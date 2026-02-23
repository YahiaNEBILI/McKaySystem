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
    monkeypatch.setattr(auth_blueprint, "db_conn", _dummy_db_conn)
    auth_blueprint.clear_login_limiter_state_for_tests()


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
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        auth_blueprint.rbac_service,
        "authenticate_user",
        lambda **_kwargs: (context, "session-token-abc", expires_at),
    )
    monkeypatch.setattr(
        auth_blueprint,
        "append_audit_event",
        lambda *_args, **kwargs: captured.update({"event_type": kwargs["event"].event_type}),
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
    assert captured.get("event_type") == "auth.login.succeeded"


def test_auth_login_invalid_credentials(monkeypatch: Any) -> None:
    """Login should return 401 when credential verification fails."""
    _disable_runtime_guards(monkeypatch)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(auth_blueprint.rbac_service, "authenticate_user", lambda **_kwargs: None)
    monkeypatch.setattr(
        auth_blueprint,
        "append_audit_event",
        lambda *_args, **kwargs: captured.update({"event_type": kwargs["event"].event_type}),
    )

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
    assert captured.get("event_type") == "auth.login.failed"


def test_auth_login_rate_limited_after_repeated_failures(monkeypatch: Any) -> None:
    """`/api/auth/login` should return 429 after repeated failed attempts."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_blueprint, "_LOGIN_FAILURE_LIMIT", 2)
    monkeypatch.setattr(auth_blueprint, "_LOGIN_FAILURE_WINDOW_SECONDS", 300)
    monkeypatch.setattr(auth_blueprint.rbac_service, "authenticate_user", lambda **_kwargs: None)

    client = flask_app.app.test_client()
    first = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "wrong",
        },
    )
    second = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "wrong",
        },
    )
    payload_second = second.get_json() or {}

    assert first.status_code == 401
    assert second.status_code == 429
    assert payload_second.get("ok") is False
    assert payload_second.get("error") == "too_many_requests"
    assert str(second.headers.get("Retry-After") or "").strip() != ""


def test_auth_login_success_clears_failure_counter(monkeypatch: Any) -> None:
    """Successful login should clear prior failed-attempt limiter state."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_blueprint, "_LOGIN_FAILURE_LIMIT", 2)
    monkeypatch.setattr(auth_blueprint, "_LOGIN_FAILURE_WINDOW_SECONDS", 300)
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
    calls = {"n": 0}

    def _authenticate(**_kwargs: Any) -> tuple[AuthContext, str, datetime] | None:
        calls["n"] += 1
        if calls["n"] == 2:
            return context, "session-token-abc", expires_at
        return None

    monkeypatch.setattr(auth_blueprint.rbac_service, "authenticate_user", _authenticate)

    client = flask_app.app.test_client()
    first_fail = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "wrong",
        },
    )
    success = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "secret",
        },
    )
    second_fail = client.post(
        "/api/auth/login",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "email": "user@acme.io",
            "password": "wrong-again",
        },
    )

    assert first_fail.status_code == 401
    assert success.status_code == 200
    assert second_fail.status_code == 401


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


def test_api_preflight_allows_configured_cors_origin(monkeypatch: Any) -> None:
    """API preflight should return CORS headers for configured origins."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_API_CORS_ALLOWED_ORIGINS", ("http://localhost:3000",))
    monkeypatch.setattr(flask_app, "_API_CORS_ALLOW_CREDENTIALS", True)

    client = flask_app.app.test_client()
    resp = client.options(
        "/api/findings",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type, X-Tenant-Id, X-Workspace",
        },
    )

    assert resp.status_code == 204
    assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"


def test_api_cors_headers_omitted_for_unconfigured_origin(monkeypatch: Any) -> None:
    """API CORS headers should be omitted when request origin is not allowed."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_API_CORS_ALLOWED_ORIGINS", ("https://app.example.com",))
    monkeypatch.setattr(flask_app, "_API_CORS_ALLOW_CREDENTIALS", True)

    client = flask_app.app.test_client()
    resp = client.options(
        "/api/findings",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert resp.status_code == 200
    assert resp.headers.get("Access-Control-Allow-Origin") is None
