"""Tests for RBAC-governed teams, SLA policy, and lifecycle write endpoints."""

from __future__ import annotations

from typing import Any, Literal

from apps.flask_api import auth_middleware, flask_app
from apps.flask_api.blueprints import lifecycle as lifecycle_blueprint
from apps.flask_api.blueprints import sla_policies as sla_policies_blueprint
from apps.flask_api.blueprints import teams as teams_blueprint
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


def test_teams_create_forbidden_without_permission(monkeypatch: Any) -> None:
    """`POST /api/teams` should return 403 without teams:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_teams_create_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/teams` should succeed with teams:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("teams:create"),
    )
    monkeypatch.setattr(teams_blueprint, "_team_exists", lambda *args, **kwargs: False)
    monkeypatch.setattr(teams_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        teams_blueprint,
        "_fetch_team",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform",
            "description": None,
            "parent_team_id": None,
        },
    )
    monkeypatch.setattr(teams_blueprint, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    assert (payload.get("team") or {}).get("team_id") == "platform"


def test_teams_update_forbidden_without_permission(monkeypatch: Any) -> None:
    """`PUT /api/teams/<team_id>` should return 403 without teams:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/teams/platform",
        json={"tenant_id": "acme", "workspace": "prod", "name": "Platform New"},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_teams_update_success_with_permission(monkeypatch: Any) -> None:
    """`PUT /api/teams/<team_id>` should succeed with teams:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("teams:update"),
    )
    fetch_calls = {"n": 0}
    monkeypatch.setattr(teams_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(teams_blueprint, "_audit_log_event", lambda *args, **kwargs: None)

    def _fake_fetch_team(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {
                "tenant_id": "acme",
                "workspace": "prod",
                "team_id": "platform",
                "name": "Platform",
                "description": None,
                "parent_team_id": None,
            }
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform New",
            "description": None,
            "parent_team_id": None,
        }

    monkeypatch.setattr(teams_blueprint, "_fetch_team", _fake_fetch_team)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/teams/platform",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "name": "Platform New",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert (payload.get("team") or {}).get("name") == "Platform New"


def test_teams_delete_forbidden_without_permission(monkeypatch: Any) -> None:
    """`DELETE /api/teams/<team_id>` should return 403 without teams:delete."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.delete("/api/teams/platform?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_teams_delete_success_with_permission(monkeypatch: Any) -> None:
    """`DELETE /api/teams/<team_id>` should succeed with teams:delete."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("teams:delete"),
    )
    monkeypatch.setattr(teams_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(teams_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        teams_blueprint,
        "_fetch_team",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform",
            "description": None,
            "parent_team_id": None,
        },
    )

    client = flask_app.app.test_client()
    resp = client.delete("/api/teams/platform?tenant_id=acme&workspace=prod&updated_by=admin")
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("team_id") == "platform"


def test_team_member_add_forbidden_without_permission(monkeypatch: Any) -> None:
    """`POST /api/teams/<team_id>/members` should return 403 without teams:manage_members."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams/platform/members",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_team_member_add_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/teams/<team_id>/members` should succeed with teams:manage_members."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("teams:manage_members"),
    )
    monkeypatch.setattr(teams_blueprint, "_team_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(teams_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(teams_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    fetch_calls = {"n": 0}

    def _fake_fetch_member(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return None
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
            "user_name": None,
            "role": "member",
            "joined_at": None,
        }

    monkeypatch.setattr(teams_blueprint, "_fetch_team_member", _fake_fetch_member)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams/platform/members",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    assert (payload.get("member") or {}).get("user_id") == "u-1"


def test_team_member_remove_forbidden_without_permission(monkeypatch: Any) -> None:
    """`DELETE /api/teams/<team_id>/members/<user_id>` should return 403.

    Permission required: `teams:manage_members`.
    """
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.delete("/api/teams/platform/members/u-1?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_team_member_remove_success_with_permission(monkeypatch: Any) -> None:
    """`DELETE /api/teams/<team_id>/members/<user_id>` should succeed with teams:manage_members."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("teams:manage_members"),
    )
    monkeypatch.setattr(teams_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(teams_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        teams_blueprint,
        "_fetch_team_member",
        lambda *_args, **_kwargs: {
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
            "user_name": None,
            "role": "member",
            "joined_at": None,
        },
    )

    client = flask_app.app.test_client()
    resp = client.delete(
        "/api/teams/platform/members/u-1?tenant_id=acme&workspace=prod&updated_by=admin@acme.io"
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("user_id") == "u-1"


def test_sla_policy_create_forbidden_without_permission(monkeypatch: Any) -> None:
    """`POST /api/sla/policies` should return 403 without sla:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "category": "cost",
            "sla_days": 14,
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_sla_policy_create_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/sla/policies` should succeed with sla:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("sla:create"),
    )
    monkeypatch.setattr(sla_policies_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sla_policies_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    fetch_calls = {"n": 0}

    def _fake_fetch_policy(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return None
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "category": "cost",
            "sla_days": 14,
            "description": None,
        }

    monkeypatch.setattr(sla_policies_blueprint, "_fetch_sla_policy_category", _fake_fetch_policy)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "category": "cost",
            "sla_days": 14,
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    assert (payload.get("policy") or {}).get("category") == "cost"


def test_sla_policy_update_forbidden_without_permission(monkeypatch: Any) -> None:
    """`PUT /api/sla/policies/<category>` should return 403 without sla:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/sla/policies/cost",
        json={"tenant_id": "acme", "workspace": "prod", "sla_days": 10},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_sla_policy_update_success_with_permission(monkeypatch: Any) -> None:
    """`PUT /api/sla/policies/<category>` should succeed with sla:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("sla:update"),
    )
    monkeypatch.setattr(sla_policies_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sla_policies_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    fetch_calls = {"n": 0}

    def _fake_fetch_policy(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {
                "tenant_id": "acme",
                "workspace": "prod",
                "category": "cost",
                "sla_days": 14,
                "description": None,
            }
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "category": "cost",
            "sla_days": 10,
            "description": None,
        }

    monkeypatch.setattr(sla_policies_blueprint, "_fetch_sla_policy_category", _fake_fetch_policy)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/sla/policies/cost",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "sla_days": 10,
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert (payload.get("policy") or {}).get("sla_days") == 10


def test_sla_override_create_forbidden_without_permission(monkeypatch: Any) -> None:
    """`POST /api/sla/policies/overrides` should return 403 without sla:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies/overrides",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "check_id": "aws.ec2.instances.underutilized",
            "sla_days": 7,
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 403
    assert payload.get("ok") is False
    assert payload.get("error") == "forbidden"


def test_sla_override_create_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/sla/policies/overrides` should succeed with sla:create."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("sla:create"),
    )
    monkeypatch.setattr(sla_policies_blueprint, "execute_conn", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sla_policies_blueprint, "_audit_log_event", lambda *args, **kwargs: None)
    fetch_calls = {"n": 0}

    def _fake_fetch_override(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return None
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "check_id": "aws.ec2.instances.underutilized",
            "sla_days": 7,
            "reason": None,
        }

    monkeypatch.setattr(sla_policies_blueprint, "_fetch_sla_policy_override", _fake_fetch_override)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies/overrides",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "check_id": "aws.ec2.instances.underutilized",
            "sla_days": 7,
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 201
    assert payload.get("ok") is True
    assert (payload.get("override") or {}).get("check_id") == "aws.ec2.instances.underutilized"


def test_lifecycle_write_endpoints_forbidden_without_permission(monkeypatch: Any) -> None:
    """Lifecycle write endpoints should return 403 without findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)
    client = flask_app.app.test_client()

    cases = [
        (
            "/api/lifecycle/ignore",
            {"tenant_id": "acme", "workspace": "prod", "fingerprint": "fp-1"},
        ),
        (
            "/api/lifecycle/resolve",
            {"tenant_id": "acme", "workspace": "prod", "fingerprint": "fp-1"},
        ),
        (
            "/api/lifecycle/snooze",
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "fingerprint": "fp-1",
                "snooze_until": "2026-03-01T00:00:00Z",
            },
        ),
        (
            "/api/lifecycle/group/ignore",
            {"tenant_id": "acme", "workspace": "prod", "group_key": "grp-1"},
        ),
        (
            "/api/lifecycle/group/resolve",
            {"tenant_id": "acme", "workspace": "prod", "group_key": "grp-1"},
        ),
        (
            "/api/lifecycle/group/snooze",
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "group_key": "grp-1",
                "snooze_until": "2026-03-01T00:00:00Z",
            },
        ),
    ]

    for path, body in cases:
        resp = client.post(path, json=body)
        payload = resp.get_json() or {}
        assert resp.status_code == 403
        assert payload.get("ok") is False
        assert payload.get("error") == "forbidden"


def test_lifecycle_ignore_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/lifecycle/ignore` should succeed with findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("findings:update"),
    )
    monkeypatch.setattr(lifecycle_blueprint, "_finding_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(lifecycle_blueprint, "_audit_lifecycle", lambda *args, **kwargs: None)
    captured: dict[str, Any] = {}

    def _fake_upsert_state(*_args, **kwargs):  # type: ignore[no-untyped-def]
        captured["fingerprint"] = kwargs["fingerprint"]
        captured["state"] = kwargs["state"]

    monkeypatch.setattr(lifecycle_blueprint, "_upsert_state", _fake_upsert_state)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/lifecycle/ignore",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "fingerprint": "fp-1",
            "reason": "test",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert captured["fingerprint"] == "fp-1"
    assert captured["state"] == "ignored"


def test_lifecycle_group_ignore_success_with_permission(monkeypatch: Any) -> None:
    """`POST /api/lifecycle/group/ignore` should succeed with findings:update."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(
        auth_middleware,
        "authenticate_request",
        lambda: _context_with_permissions("findings:update"),
    )
    monkeypatch.setattr(lifecycle_blueprint, "_audit_lifecycle", lambda *args, **kwargs: None)
    captured: dict[str, Any] = {}

    def _fake_upsert_group_state(*_args, **kwargs):  # type: ignore[no-untyped-def]
        captured["group_key"] = kwargs["group_key"]
        captured["state"] = kwargs["state"]

    monkeypatch.setattr(lifecycle_blueprint, "_upsert_group_state", _fake_upsert_group_state)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/lifecycle/group/ignore",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "group_key": "grp-1",
            "reason": "test",
            "updated_by": "admin@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert captured["group_key"] == "grp-1"
    assert captured["state"] == "ignored"


def test_read_and_workflow_endpoints_forbidden_without_permissions(monkeypatch: Any) -> None:
    """RBAC-gated read/workflow endpoints should return 403 without permissions."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(auth_middleware, "authenticate_request", _context_without_permissions)
    client = flask_app.app.test_client()

    get_cases = [
        "/api/facets?tenant_id=acme&workspace=prod",
        "/api/groups?tenant_id=acme&workspace=prod",
        "/api/groups/grp-1?tenant_id=acme&workspace=prod",
        "/api/recommendations?tenant_id=acme&workspace=prod",
        "/api/recommendations/composite?tenant_id=acme&workspace=prod",
        "/api/remediations?tenant_id=acme&workspace=prod",
        "/api/remediations/impact?tenant_id=acme&workspace=prod",
        "/api/teams?tenant_id=acme&workspace=prod",
        "/api/teams/platform/members?tenant_id=acme&workspace=prod",
        "/api/sla/policies?tenant_id=acme&workspace=prod",
        "/api/sla/policies/overrides?tenant_id=acme&workspace=prod",
    ]
    post_cases = [
        ("/api/recommendations/estimate", {"tenant_id": "acme", "workspace": "prod"}),
        ("/api/recommendations/preview", {"tenant_id": "acme", "workspace": "prod"}),
        (
            "/api/remediations/request",
            {"tenant_id": "acme", "workspace": "prod", "fingerprint": "fp-1"},
        ),
        (
            "/api/remediations/approve",
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-1",
                "approved_by": "admin@acme.io",
            },
        ),
        (
            "/api/remediations/reject",
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-1",
                "rejected_by": "admin@acme.io",
            },
        ),
    ]

    for path in get_cases:
        resp = client.get(path)
        payload = resp.get_json() or {}
        assert resp.status_code == 403
        assert payload.get("ok") is False
        assert payload.get("error") == "forbidden"

    for path, body in post_cases:
        resp = client.post(path, json=body)
        payload = resp.get_json() or {}
        assert resp.status_code == 403
        assert payload.get("ok") is False
        assert payload.get("error") == "forbidden"
