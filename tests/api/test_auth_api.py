"""Tests for auth Blueprint endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from apps.flask_api import auth_middleware, flask_app
from apps.flask_api.blueprints import auth as auth_blueprint
from services.rbac_service import AuthContext


class _DummyConn:
    """Minimal context manager returned by db_conn during request tests."""

    def __enter__(self) -> _DummyConn:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False

    def commit(self) -> None:
        return


def _dummy_db_conn() -> _DummyConn:
    """Return a dummy DB context object for request tests."""
    return _DummyConn()


def _disable_runtime_guards(monkeypatch: Any) -> None:
    """Disable schema and legacy bearer gate for focused auth endpoint tests."""
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", _dummy_db_conn)


def test_auth_login_success_sets_cookie(monkeypatch: Any) -> None:
    """Login should return session token payload and set session cookie."""
    _disable_runtime_guards(monkeypatch)
    context = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email="user@acme.io",
        full_name="Alice",
        is_superadmin=False,
        auth_method="session",
        session_id="ses_123",
        permissions=frozenset({"findings:read"}),
    )
    expires_at = datetime(2026, 2, 23, 12, 0, 0, tzinfo=UTC)

    monkeypatch.setattr(
        auth_blueprint.rbac_service,
        "authenticate_user",
        lambda **_kwargs: (context, "session-token-abc", expires_at),
    )

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "secret",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("session_token") == "session-token-abc"
    assert (payload.get("user") or {}).get("user_id") == "u-1"
    cookie_header = str(resp.headers.get("Set-Cookie") or "")
    assert "session_token=session-token-abc" in cookie_header


def test_auth_login_invalid_credentials(monkeypatch: Any) -> None:
    """Login should return 401 when credential verification fails."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_blueprint.rbac_service, "authenticate_user", lambda **_kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "wrong",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 401
    assert payload.get("ok") is False
    assert payload.get("error") == "unauthorized"


def test_auth_me_requires_authenticated_context(monkeypatch: Any) -> None:
    """`/api/auth/me` should return 401 when no auth context resolves."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_session_token", lambda **_kwargs: None)

    client = flask_app.app.test_client()
    resp = client.get("/api/auth/me?tenant_id=acme&workspace=prod&session_token=missing")
    payload = resp.get_json() or {}

    assert resp.status_code == 401
    assert payload.get("ok") is False
    assert payload.get("error") == "unauthorized"


def test_auth_me_returns_current_user(monkeypatch: Any) -> None:
    """`/api/auth/me` should return serialized current principal context."""
    _disable_runtime_guards(monkeypatch)
    context = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email="user@acme.io",
        full_name="Alice",
        is_superadmin=False,
        auth_method="session",
        session_id="ses_123",
        permissions=frozenset({"findings:read", "runs:read"}),
    )
    monkeypatch.setattr(auth_middleware, "authenticate_session_token", lambda **_kwargs: context)

    client = flask_app.app.test_client()
    resp = client.get("/api/auth/me?tenant_id=acme&workspace=prod&session_token=token-xyz")
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    user = payload.get("user") or {}
    assert user.get("user_id") == "u-1"
    assert user.get("tenant_id") == "acme"
    assert user.get("workspace") == "prod"


def test_auth_logout_invalidates_session(monkeypatch: Any) -> None:
    """`/api/auth/logout` should invalidate session token and clear cookie."""
    _disable_runtime_guards(monkeypatch)
    context = AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="u-1",
        email="user@acme.io",
        full_name="Alice",
        is_superadmin=False,
        auth_method="session",
        session_id="ses_123",
    )
    calls: dict[str, Any] = {}
    monkeypatch.setattr(auth_middleware, "authenticate_session_token", lambda **_kwargs: context)

    def _logout(**kwargs: Any) -> bool:
        calls.update(kwargs)
        return True

    monkeypatch.setattr(auth_blueprint.rbac_service, "logout_session", _logout)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/auth/logout",
        json={"tenant_id": "acme", "workspace": "prod", "session_token": "token-xyz"},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("logged_out") is True
    assert calls == {
        "tenant_id": "acme",
        "workspace": "prod",
        "session_token": "token-xyz",
    }
