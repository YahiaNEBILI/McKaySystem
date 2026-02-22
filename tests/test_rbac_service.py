"""Unit tests for RBAC service authentication behavior."""

from __future__ import annotations

from datetime import UTC
from typing import Any, Literal

from apps.backend.auth.passwords import hash_password
from services import rbac_service
from services.rbac_service import AuthContext


class _DummyConn:
    """Minimal connection double with commit counter."""

    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self) -> None:
        self.commit_count += 1

    def rollback(self) -> None:
        """No-op rollback for compatibility with pooled connection callers."""
        return


class _DummyCtx:
    """Context manager wrapper for dummy DB connection."""

    def __init__(self, conn: _DummyConn) -> None:
        self._conn = conn

    def __enter__(self) -> _DummyConn:
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False


def test_authenticate_user_creates_session(monkeypatch: Any) -> None:
    """Valid credentials should produce context and persisted session hash."""
    conn = _DummyConn()
    calls: dict[str, Any] = {}
    stored_hash = hash_password("hunter2")

    monkeypatch.setattr(rbac_service, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_by_email",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "email": "user@acme.io",
            "full_name": "Alice",
            "is_active": True,
            "is_superadmin": False,
            "password_hash": stored_hash,
        },
    )

    def _capture_upsert(*_args, **kwargs):  # type: ignore[no-untyped-def]
        session = kwargs.get("session")
        calls["session_id"] = getattr(session, "session_id", None)
        calls["session_token_hash"] = getattr(session, "session_token_hash", None)
        return {"session_id": calls["session_id"]}

    monkeypatch.setattr(rbac_service.db_rbac, "upsert_user_session", _capture_upsert)
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "touch_user_last_login",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_permissions",
        lambda *_args, **_kwargs: ["findings:read"],
    )
    monkeypatch.setattr(rbac_service, "generate_session_token", lambda: "sess-raw-token")

    result = rbac_service.authenticate_user(
        tenant_id="acme",
        workspace="prod",
        email="user@acme.io",
        password="hunter2",
    )

    assert result is not None
    context, raw_token, expires_at = result
    assert isinstance(context, AuthContext)
    assert raw_token == "sess-raw-token"
    assert expires_at.tzinfo is UTC
    assert context.user_id == "u-1"
    assert "findings:read" in context.permissions
    assert str(calls["session_id"]).startswith("ses_")
    assert len(str(calls["session_token_hash"])) == 64
    assert conn.commit_count == 1


def test_authenticate_user_rejects_bad_password(monkeypatch: Any) -> None:
    """Invalid password should return None and not commit session writes."""
    conn = _DummyConn()
    stored_hash = hash_password("hunter2")

    monkeypatch.setattr(rbac_service, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_by_email",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "email": "user@acme.io",
            "is_active": True,
            "is_superadmin": False,
            "password_hash": stored_hash,
        },
    )
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "upsert_user_session",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_permissions",
        lambda *_args, **_kwargs: [],
    )

    result = rbac_service.authenticate_user(
        tenant_id="acme",
        workspace="prod",
        email="user@acme.io",
        password="wrong",
    )

    assert result is None
    assert conn.commit_count == 0


def test_authorize_honors_superadmin_and_admin_full() -> None:
    """Authorize should allow superadmin and admin:full bypasses."""
    ctx_super = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email=None,
        full_name=None,
        is_superadmin=True,
        auth_method="session",
    )
    ctx_admin = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email=None,
        full_name=None,
        is_superadmin=False,
        auth_method="api_key",
        permissions=frozenset({"admin:full"}),
    )
    ctx_limited = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email=None,
        full_name=None,
        is_superadmin=False,
        auth_method="api_key",
        permissions=frozenset({"findings:read"}),
    )

    assert rbac_service.authorize(ctx_super, permission="users:delete") is True
    assert rbac_service.authorize(ctx_admin, permission="users:delete") is True
    assert rbac_service.authorize(ctx_limited, permission="findings:read") is True
    assert rbac_service.authorize(ctx_limited, permission="users:delete") is False


def test_authenticate_api_key_returns_context(monkeypatch: Any) -> None:
    """Valid API key should resolve to scoped auth context."""
    conn = _DummyConn()
    touched: dict[str, str] = {}

    monkeypatch.setattr(rbac_service, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_by_api_key_hash",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "email": "user@acme.io",
            "full_name": "Alice",
            "is_active": True,
            "is_superadmin": False,
            "key_id": "key_123",
        },
    )

    def _touch(*_args, **kwargs):  # type: ignore[no-untyped-def]
        touched["key_id"] = str(kwargs.get("key_id"))

    monkeypatch.setattr(rbac_service.db_rbac, "touch_api_key_last_used", _touch)
    monkeypatch.setattr(
        rbac_service.db_rbac,
        "get_user_permissions",
        lambda *_args, **_kwargs: ["findings:read", "runs:read"],
    )

    context = rbac_service.authenticate_api_key(
        tenant_id="acme",
        workspace="prod",
        api_key="raw-api-key",
    )

    assert context is not None
    assert context.auth_method == "api_key"
    assert context.key_id == "key_123"
    assert touched["key_id"] == "key_123"
    assert conn.commit_count == 1
