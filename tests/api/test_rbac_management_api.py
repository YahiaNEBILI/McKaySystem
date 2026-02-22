"""Tests for RBAC user/api-key management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from apps.backend.auth.tokens import hash_api_key
from apps.flask_api import auth_middleware, flask_app
from apps.flask_api.blueprints import api_keys as api_keys_blueprint
from apps.flask_api.blueprints import findings as findings_blueprint
from apps.flask_api.blueprints import lifecycle as lifecycle_blueprint
from apps.flask_api.blueprints import sla_policies as sla_policies_blueprint
from apps.flask_api.blueprints import teams as teams_blueprint
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
    monkeypatch.setattr(findings_blueprint, "db_conn", _dummy_db_conn)
    monkeypatch.setattr(teams_blueprint, "db_conn", _dummy_db_conn)
    monkeypatch.setattr(sla_policies_blueprint, "db_conn", _dummy_db_conn)
    monkeypatch.setattr(lifecycle_blueprint, "db_conn", _dummy_db_conn)


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


def test_users_role_forbidden_without_permission(monkeypatch: Any) -> None:
    """`PUT /api/users/<id>/role` should return 403 without users:manage_roles."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role",
        json={"tenant_id": "acme", "workspace": "prod", "role_id": "viewer"},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_users_role_get_success(monkeypatch: Any) -> None:
    """`GET /api/users/<id>/role` should return assigned role metadata when authorized."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_user_by_id",
        lambda *_args, **_kwargs: {"user_id": "u-1", "tenant_id": "acme", "workspace": "prod"},
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_user_workspace_role",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "role_id": "viewer",
            "granted_by": "admin@acme.io",
            "granted_at": "2026-02-22T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_by_id",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "viewer",
            "name": "Viewer",
            "description": "Read only",
            "is_system": True,
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_permissions",
        lambda *_args, **_kwargs: ["findings:read", "runs:read"],
    )

    client = flask_app.app.test_client()
    resp = client.get("/api/users/u-1/role?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    role = payload.get("role") or {}
    assert role.get("role_id") == "viewer"
    assert role.get("permissions") == ["findings:read", "runs:read"]


def test_users_role_set_success(monkeypatch: Any) -> None:
    """`PUT /api/users/<id>/role` should upsert role assignment when authorized."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_user_by_id",
        lambda *_args, **_kwargs: {"user_id": "u-1", "tenant_id": "acme", "workspace": "prod"},
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_by_id",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "editor",
            "name": "Editor",
            "description": "Edit findings",
            "is_system": True,
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "upsert_user_workspace_role",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
            "granted_at": "2026-02-22T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_permissions",
        lambda *_args, **_kwargs: ["findings:read", "findings:update"],
    )
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        users_blueprint,
        "append_audit_event",
        lambda *_args, **kwargs: captured.update({"event_type": kwargs["event"].event_type}),
    )

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    role = payload.get("role") or {}
    assert role.get("role_id") == "editor"
    assert role.get("permissions") == ["findings:read", "findings:update"]
    assert captured.get("event_type") == "users.role.assigned"


def test_users_role_set_returns_not_found_for_unknown_role(monkeypatch: Any) -> None:
    """`PUT /api/users/<id>/role` should return 404 when role does not exist."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_user_by_id",
        lambda *_args, **_kwargs: {"user_id": "u-1", "tenant_id": "acme", "workspace": "prod"},
    )
    monkeypatch.setattr(users_blueprint.db_rbac, "get_role_by_id", lambda *_args, **_kwargs: None)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role",
        json={"tenant_id": "acme", "workspace": "prod", "role_id": "missing"},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 404
    assert payload.get("ok") is False
    assert payload.get("error") == "not_found"


def test_users_tenant_role_set_requires_admin_full(monkeypatch: Any) -> None:
    """`PUT /api/users/<id>/role/tenant` should require admin:full."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles"),
    )

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role/tenant",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "editor",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_users_tenant_role_set_fans_out_and_reports_skips(monkeypatch: Any) -> None:
    """Tenant-wide role assignment should fan out to existing workspaces."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles", "admin:full"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "list_tenant_workspaces",
        lambda *_args, **_kwargs: ["prod", "dev", "staging"],
    )

    def _user_by_id(*_args, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("workspace") == "staging":
            return None
        return {"user_id": "u-1", "tenant_id": "acme", "workspace": kwargs.get("workspace")}

    def _role_by_id(*_args, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("workspace") == "dev":
            return None
        return {
            "tenant_id": "acme",
            "workspace": kwargs.get("workspace"),
            "role_id": "editor",
            "name": "Editor",
            "description": "Edit findings",
            "is_system": True,
        }

    monkeypatch.setattr(users_blueprint.db_rbac, "get_user_by_id", _user_by_id)
    monkeypatch.setattr(users_blueprint.db_rbac, "get_role_by_id", _role_by_id)
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "upsert_user_workspace_role",
        lambda *_args, **kwargs: {
            "tenant_id": "acme",
            "workspace": getattr(kwargs.get("assignment"), "workspace", None),
            "user_id": "u-1",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
            "granted_at": "2026-02-22T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_permissions",
        lambda *_args, **_kwargs: ["findings:read", "findings:update"],
    )
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        users_blueprint,
        "append_audit_event",
        lambda *_args, **kwargs: captured.update({"event_type": kwargs["event"].event_type}),
    )

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role/tenant",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("target_workspaces") == ["prod", "dev", "staging"]
    summary = payload.get("summary") or {}
    assert summary.get("targeted") == 3
    assert summary.get("assigned") == 1
    assert summary.get("skipped") == 2

    items = payload.get("items") or []
    by_workspace = {str(item.get("workspace")): item for item in items}
    assert by_workspace["prod"].get("status") == "assigned"
    assert (by_workspace["prod"].get("role") or {}).get("role_id") == "editor"
    assert by_workspace["dev"].get("status") == "skipped"
    assert by_workspace["dev"].get("reason") == "role_not_found"
    assert by_workspace["staging"].get("status") == "skipped"
    assert by_workspace["staging"].get("reason") == "user_not_found"
    assert captured.get("event_type") == "users.role.assigned_tenant"


def test_users_tenant_role_set_respects_explicit_workspaces(monkeypatch: Any) -> None:
    """Tenant-wide role assignment should accept explicit workspace targets."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("users:manage_roles", "admin:full"),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "list_tenant_workspaces",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected call")),
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_user_by_id",
        lambda *_args, **kwargs: {
            "user_id": "u-1",
            "tenant_id": "acme",
            "workspace": kwargs.get("workspace"),
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_by_id",
        lambda *_args, **kwargs: {
            "tenant_id": "acme",
            "workspace": kwargs.get("workspace"),
            "role_id": "editor",
            "name": "Editor",
            "description": "Edit findings",
            "is_system": True,
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "upsert_user_workspace_role",
        lambda *_args, **kwargs: {
            "tenant_id": "acme",
            "workspace": getattr(kwargs.get("assignment"), "workspace", None),
            "user_id": "u-1",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
            "granted_at": "2026-02-22T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        users_blueprint.db_rbac,
        "get_role_permissions",
        lambda *_args, **_kwargs: ["findings:read", "findings:update"],
    )

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/users/u-1/role/tenant",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "role_id": "editor",
            "granted_by": "admin@acme.io",
            "workspaces": ["prod", "dev", "prod"],
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("target_workspaces") == ["prod", "dev"]
    summary = payload.get("summary") or {}
    assert summary.get("targeted") == 2
    assert summary.get("assigned") == 2
    assert summary.get("skipped") == 0


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


def test_findings_owner_forbidden_without_permission(monkeypatch: Any) -> None:
    """`PUT /api/findings/<fp>/owner` should return 403 without findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-1/owner",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "owner_email": "owner@acme.io",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_findings_owner_success_with_permission(monkeypatch: Any) -> None:
    """`PUT /api/findings/<fp>/owner` should succeed with findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("findings:update"),
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_finding_exists",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_ensure_finding_governance_row",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(findings_blueprint, "_audit_log_event", lambda *args, **kwargs: None)

    captured: dict[str, Any] = {}
    fetch_calls = {"n": 0}

    def _fake_fetch_governance(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None}
        return {
            "owner_id": captured.get("owner_id"),
            "owner_email": captured.get("owner_email"),
            "owner_name": captured.get("owner_name"),
            "team_id": None,
        }

    def _fake_update_owner(*_args, **kwargs):  # type: ignore[no-untyped-def]
        captured["tenant_id"] = kwargs["tenant_id"]
        captured["workspace"] = kwargs["workspace"]
        captured["fingerprint"] = kwargs["fingerprint"]
        captured["owner_id"] = kwargs["owner_id"]
        captured["owner_email"] = kwargs["owner_email"]
        captured["owner_name"] = kwargs["owner_name"]

    monkeypatch.setattr(findings_blueprint, "_fetch_governance_owner_team", _fake_fetch_governance)
    monkeypatch.setattr(findings_blueprint, "_update_finding_owner", _fake_update_owner)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-1/owner",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "owner_email": "owner@acme.io",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("owner_email") == "owner@acme.io"
    assert captured["tenant_id"] == "acme"
    assert captured["workspace"] == "prod"
    assert captured["fingerprint"] == "fp-1"
    assert captured["owner_email"] == "owner@acme.io"


def test_findings_team_forbidden_without_permission(monkeypatch: Any) -> None:
    """`PUT /api/findings/<fp>/team` should return 403 without findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-1/team",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "team-1",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_findings_team_success_with_permission(monkeypatch: Any) -> None:
    """`PUT /api/findings/<fp>/team` should succeed with findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("findings:update"),
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_finding_exists",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_ensure_finding_governance_row",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(findings_blueprint, "_team_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(findings_blueprint, "_audit_log_event", lambda *args, **kwargs: None)

    updates: dict[str, Any] = {}
    fetch_calls = {"n": 0}

    def _fake_fetch_governance(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None}
        return {
            "owner_id": None,
            "owner_email": None,
            "owner_name": None,
            "team_id": updates.get("team_id"),
        }

    def _fake_update_team(
        _conn: object,
        *,
        tenant_id: str,
        workspace: str,
        fingerprint: str,
        team_id: str | None,
    ) -> None:
        updates["tenant_id"] = tenant_id
        updates["workspace"] = workspace
        updates["fingerprint"] = fingerprint
        updates["team_id"] = team_id

    monkeypatch.setattr(findings_blueprint, "_fetch_governance_owner_team", _fake_fetch_governance)
    monkeypatch.setattr(findings_blueprint, "_update_finding_team", _fake_update_team)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-1/team",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "team-1",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("team_id") == "team-1"
    assert updates["tenant_id"] == "acme"
    assert updates["workspace"] == "prod"
    assert updates["fingerprint"] == "fp-1"
    assert updates["team_id"] == "team-1"


def test_findings_sla_extend_forbidden_without_permission(monkeypatch: Any) -> None:
    """`POST /api/findings/<fp>/sla/extend` should return 403 without findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/findings/fp-1/sla/extend",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "extend_days": 7,
            "reason": "maintenance window",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_findings_sla_extend_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/findings/<fp>/sla/extend` should succeed with findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("findings:update"),
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_finding_exists",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_fetch_finding_effective_state",
        lambda *args, **kwargs: "open",
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_ensure_finding_governance_row",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_fetch_governance_sla",
        lambda *args, **kwargs: {
            "sla_deadline": datetime(2026, 2, 20, 0, 0, tzinfo=UTC),
            "sla_paused_at": None,
            "sla_total_paused_seconds": 0,
            "sla_extension_seconds": 0,
            "sla_breached_at": None,
            "sla_extended_count": 0,
            "sla_extension_reason": None,
        },
    )
    monkeypatch.setattr(
        findings_blueprint,
        "_apply_finding_sla_extension",
        lambda *args, **kwargs: {
            "sla_deadline": datetime(2026, 2, 27, 0, 0, tzinfo=UTC),
            "sla_paused_at": None,
            "sla_total_paused_seconds": 0,
            "sla_extension_seconds": 604800,
            "sla_breached_at": None,
            "sla_extended_count": 1,
            "sla_extension_reason": "maintenance window",
        },
    )
    monkeypatch.setattr(findings_blueprint, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/findings/fp-1/sla/extend",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "extend_days": 7,
            "reason": "maintenance window",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("extend_days") == 7
    assert payload.get("sla_extended_count") == 1
