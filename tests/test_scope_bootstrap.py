"""Unit tests for scope bootstrap helper behavior."""

from __future__ import annotations

from typing import Any, Literal

import pytest

from apps.backend import scope_bootstrap


class _DummyConn:
    """Minimal connection double with commit tracking."""

    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self) -> None:
        """Track commit calls."""
        self.commit_count += 1

    def rollback(self) -> None:
        """No-op rollback compatibility shim."""
        return


class _DummyCtx:
    """Context manager wrapper for the dummy DB connection."""

    def __init__(self, conn: _DummyConn) -> None:
        self._conn = conn

    def __enter__(self) -> _DummyConn:
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False


def test_bootstrap_scope_admin_assigns_user_role(monkeypatch: Any) -> None:
    """Bootstrap should seed scope, upsert user, and assign role."""
    conn = _DummyConn()
    calls: dict[str, Any] = {}

    monkeypatch.setattr(scope_bootstrap, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(scope_bootstrap, "hash_password", lambda raw: f"hash:{raw}")
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "bootstrap_rbac_scope",
        lambda _conn, **kwargs: calls.__setitem__("boot", kwargs),
    )
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "get_role_by_id",
        lambda *_args, **_kwargs: {"role_id": "admin"},
    )

    def _create_user(*_args, **kwargs):  # type: ignore[no-untyped-def]
        user = kwargs["user"]
        calls["user"] = user
        return {"user_id": user.user_id}

    monkeypatch.setattr(scope_bootstrap.db_rbac, "create_user", _create_user)

    def _assign_role(*_args, **kwargs):  # type: ignore[no-untyped-def]
        assignment = kwargs["assignment"]
        calls["assignment"] = assignment
        return {"role_id": assignment.role_id}

    monkeypatch.setattr(scope_bootstrap.db_rbac, "upsert_user_workspace_role", _assign_role)
    monkeypatch.setattr(scope_bootstrap.db_rbac, "create_api_key", lambda *_args, **_kwargs: None)

    result = scope_bootstrap.bootstrap_scope_admin(
        scope_bootstrap.ScopeBootstrapRequest(
            tenant_id="acme",
            workspace="prod",
            user_id="u-admin",
            email="ADMIN@ACME.IO",
            password="secret-123",
            options=scope_bootstrap.ScopeBootstrapOptions(
                full_name="Admin User",
                role_id="admin",
                granted_by="bootstrap-test",
                is_superadmin=False,
                create_api_key=False,
            ),
        )
    )

    assert result["tenant_id"] == "acme"
    assert result["workspace"] == "prod"
    assert result["email"] == "admin@acme.io"
    assert result["api_key"] is None
    assert result["key_id"] is None
    assert calls["boot"] == {"tenant_id": "acme", "workspace": "prod"}
    assert calls["user"].password_hash == "hash:secret-123"
    assert calls["assignment"].granted_by == "bootstrap-test"
    assert conn.commit_count == 1


def test_bootstrap_scope_admin_can_issue_api_key(monkeypatch: Any) -> None:
    """Bootstrap should return raw API key when requested."""
    conn = _DummyConn()
    captured: dict[str, Any] = {}

    monkeypatch.setattr(scope_bootstrap, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(scope_bootstrap, "hash_password", lambda raw: f"hash:{raw}")
    monkeypatch.setattr(
        scope_bootstrap,
        "generate_api_key",
        lambda prefix="mck": f"{prefix}_raw_123",
    )
    monkeypatch.setattr(scope_bootstrap, "hash_api_key", lambda raw: f"hash::{raw}")
    monkeypatch.setattr(scope_bootstrap, "derive_key_id", lambda _hash: "key_abc")
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "bootstrap_rbac_scope",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "get_role_by_id",
        lambda *_args, **_kwargs: {"role_id": "admin"},
    )
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "create_user",
        lambda *_args, **_kwargs: {"user_id": "u-admin"},
    )
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "upsert_user_workspace_role",
        lambda *_args, **_kwargs: {"role_id": "admin"},
    )

    def _create_api_key(*_args, **kwargs):  # type: ignore[no-untyped-def]
        captured["api_key"] = kwargs["api_key"]
        return {"key_id": "key_abc"}

    monkeypatch.setattr(scope_bootstrap.db_rbac, "create_api_key", _create_api_key)

    result = scope_bootstrap.bootstrap_scope_admin(
        scope_bootstrap.ScopeBootstrapRequest(
            tenant_id="acme",
            workspace="prod",
            user_id="u-admin",
            email="admin@acme.io",
            password="secret-123",
            options=scope_bootstrap.ScopeBootstrapOptions(
                create_api_key=True,
                api_key_name="ops-bootstrap",
            ),
        )
    )

    assert result["api_key"] == "mck_raw_123"
    assert result["key_id"] == "key_abc"
    assert captured["api_key"].name == "ops-bootstrap"
    assert captured["api_key"].user_id == "u-admin"
    assert conn.commit_count == 1


def test_bootstrap_scope_admin_fails_when_role_missing(monkeypatch: Any) -> None:
    """Bootstrap should fail fast when target role is unavailable."""
    conn = _DummyConn()

    monkeypatch.setattr(scope_bootstrap, "db_conn", lambda: _DummyCtx(conn))
    monkeypatch.setattr(
        scope_bootstrap.db_rbac,
        "bootstrap_rbac_scope",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(scope_bootstrap.db_rbac, "get_role_by_id", lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError, match="role not found"):
        scope_bootstrap.bootstrap_scope_admin(
            scope_bootstrap.ScopeBootstrapRequest(
                tenant_id="acme",
                workspace="prod",
                user_id="u-admin",
                email="admin@acme.io",
                password="secret-123",
            )
        )

    assert conn.commit_count == 0
