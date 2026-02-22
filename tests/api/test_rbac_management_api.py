"""Tests for RBAC user/api-key management endpoints."""

from __future__ import annotations

from typing import Any, Literal

from apps.backend.auth.tokens import hash_api_key
from apps.flask_api import auth_middleware, flask_app
from apps.flask_api.blueprints import api_keys as api_keys_blueprint
from apps.flask_api.blueprints import users as users_blueprint
from services.rbac_service import AuthContext

# Test fixtures intentionally mirror other API test modules.
# pylint: disable=duplicate-code


class _DummyConn:
    """Minimal context manager returned by db_conn during request tests."""

    def __enter__(self) -> _DummyConn:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False

    def commit(self) -> None:
        return


def _dummy_db_conn() -> _DummyConn:
    """Return dummy DB context object for endpoint tests."""
    return _DummyConn()


def _disable_runtime_guards(monkeypatch: Any) -> None:
    """Disable schema and legacy bearer gates for focused RBAC endpoint tests."""
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", _dummy_db_conn)
    monkeypatch.setattr(users_blueprint, "db_conn", _dummy_db_conn)
    monkeypatch.setattr(api_keys_blueprint, "db_conn", _dummy_db_conn)


def _context_with_permissions(*permissions: str) -> AuthContext:
    """Build deterministic auth context for permission-gated tests."""
    return AuthContext(
        tenant_id="acme",
        workspace="prod",
        user_id="admin-1",
        email="admin@acme.io",
        full_name="Admin",
        is_superadmin=False,
        auth_method="session",
        permissions=frozenset(permissions),
    )


def _context_without_permissions() -> AuthContext:
    """Return auth context with no permissions."""
    return _context_with_permissions()


def test_users_list_forbidden_without_permission(monkeypatch: Any) -> None:
    """`GET /api/users` should return 403 when users:read is missing."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        _context_without_permissions,
    )

    client = flask_app.app.test_client()
    resp = client.get("/api/users?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_users_list_success(monkeypatch: Any) -> None:
    """`GET /api/users` should return paged scoped users when authorized."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:read"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "list_users_page",
        lambda *_args, **_kwargs: (
            [
                {
                    "tenant_id": "acme",
                    "workspace": "prod",
                    "user_id": "u-1",
                    "email": "u-1@acme.io",
                    "full_name": "User One",
                    "external_id": None,
                    "auth_provider": "local",
                    "is_active": True,
                    "is_superadmin": False,
                    "last_login_at": None,
                    "created_at": None,
                    "updated_at": None,
                }
            ],
            1,
        ),
    )

    client = flask_app.app.test_client()
    resp = client.get("/api/users?tenant_id=acme&workspace=prod&limit=25&offset=0")
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("total") == 1
    assert isinstance(payload.get("items"), list)
    assert (payload.get("items") or [])[0].get("user_id") == "u-1"


def test_users_create_hashes_password(monkeypatch: Any) -> None:
    """`POST /api/users` should hash password before DB upsert."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:create"),
    )
    captured: dict[str, Any] = {}

    def _create_user(*_args, **kwargs):  # type: ignore[no-untyped-def]
        user = kwargs.get("user")
        captured["password_hash"] = getattr(user, "password_hash", None)
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-2",
            "email": "u-2@acme.io",
            "full_name": "User Two",
            "external_id": None,
            "auth_provider": "local",
            "is_active": True,
            "is_superadmin": False,
            "last_login_at": None,
            "created_at": None,
            "updated_at": None,
            "password_hash": captured["password_hash"],
        }

    monkeypatch.setattr(users_blueprint.db_rbac, "create_user", _create_user)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/users",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-2",
            "email": "u-2@acme.io",
            "password": "secret-123",
            "full_name": "User Two",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    user = payload.get("user") or {}
    assert user.get("user_id") == "u-2"
    assert "password_hash" not in user
    assert str(captured["password_hash"]).startswith("pbkdf2_sha256$")


def test_api_keys_create_returns_raw_key(monkeypatch: Any) -> None:
    """`POST /api/api-keys` should return raw key once and store hash."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("api_keys:create"),
    )
    monkeypatch.setattr(
        api_keys_blueprint,
        "generate_api_key",
        lambda prefix="mck": "mck_raw_secret",
    )
    captured: dict[str, Any] = {}

    def _create_api_key(*_args, **kwargs):  # type: ignore[no-untyped-def]
        api_key = kwargs.get("api_key")
        captured["key_hash"] = getattr(api_key, "key_hash", None)
        captured["key_id"] = getattr(api_key, "key_id", None)
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "key_id": captured["key_id"],
            "key_hash": captured["key_hash"],
            "key_type": "secret",
            "name": "ci",
            "description": None,
            "user_id": "u-1",
            "last_used_at": None,
            "expires_at": None,
            "is_active": True,
            "created_at": None,
        }

    monkeypatch.setattr(api_keys_blueprint.db_rbac, "create_api_key", _create_api_key)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/api-keys",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "name": "ci",
            "user_id": "u-1",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    assert payload.get("api_key") == "mck_raw_secret"
    key = payload.get("key") or {}
    assert key.get("key_id") == captured["key_id"]
    assert "key_hash" not in key
    assert captured["key_hash"] == hash_api_key("mck_raw_secret")


def test_api_keys_revoke_not_found(monkeypatch: Any) -> None:
    """`DELETE /api/api-keys/<id>` should return 404 when key is missing."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("api_keys:revoke"),
    )
    monkeypatch.setattr(
        api_keys_blueprint.db_rbac,
        "revoke_api_key",
        lambda *_args, **_kwargs: False,
    )

    client = flask_app.app.test_client()
    resp = client.delete("/api/api-keys/key_missing?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 404
    assert payload.get("ok") is False
    assert payload.get("error") == "not_found"
