"""Guardrails for Flask API read-model queries."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Optional

import apps.flask_api.flask_app as flask_app


class _DummyConn:
    """Minimal context manager returned by db_conn during unit tests."""

    def __enter__(self) -> "_DummyConn":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False

    def commit(self) -> None:
        return


def _disable_runtime_guards(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Disable auth/schema gates so request tests focus on SQL behavior."""
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", lambda: _DummyConn())


def test_findings_query_uses_finding_current_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings` must read from finding_current and avoid lifecycle reimplementation."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/findings?tenant_id=acme&workspace=prod&state=open")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current".lower() in sql_blob
    assert "finding_state_current" not in sql_blob
    assert "finding_group_state_current" not in sql_blob


def test_findings_query_supports_governance_filters(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings` should support governance field filters from finding_current."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get(
        "/api/findings?tenant_id=acme&workspace=prod&team_id=team-a"
        "&owner_email=owner%40acme.io&sla_status=active"
    )

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "team_id = any(%s)" in sql_blob
    assert "owner_email = any(%s)" in sql_blob
    assert "sla_status = any(%s)" in sql_blob


def test_sla_breached_query_uses_finding_current(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings/sla/breached` must query finding_current with breached status."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/findings/sla/breached?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "sla_status = 'breached'" in sql_blob


def test_findings_aging_uses_selected_age_clock(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings/aging` should use age_days_detected when age_basis=detected."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/findings/aging?tenant_id=acme&workspace=prod&age_basis=detected&min_days=14")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "age_days_detected is not null" in sql_blob
    assert "order by age_days_detected desc" in sql_blob


def test_findings_aging_rejects_invalid_age_basis(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings/aging` should return 400 for invalid age_basis values."""
    _disable_runtime_guards(monkeypatch)
    client = flask_app.app.test_client()
    resp = client.get("/api/findings/aging?tenant_id=acme&workspace=prod&age_basis=foo")
    payload = resp.get_json() or {}

    assert resp.status_code == 400
    assert payload.get("ok") is False
    assert payload.get("error") == "bad_request"


def test_teams_query_uses_scoped_team_table(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/teams` should query scoped teams rows."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/teams?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from teams t" in sql_blob
    assert "t.tenant_id = %s" in sql_blob
    assert "t.workspace = %s" in sql_blob


def test_create_team_returns_conflict_when_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`POST /api/teams` should return 409 when team_id already exists."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_team_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "platform",
            "name": "Platform",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "conflict"


def test_team_members_query_uses_scoped_member_table(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/teams/<team_id>/members` should query scoped team_members rows."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    monkeypatch.setattr(flask_app, "_team_exists", lambda *args, **kwargs: True)

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/teams/platform/members?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from team_members" in sql_blob
    assert "tenant_id = %s" in sql_blob
    assert "workspace = %s" in sql_blob
    assert "team_id = %s" in sql_blob


def test_add_team_member_returns_conflict_when_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`POST /api/teams/<team_id>/members` should return 409 on duplicate user_id."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_team_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_fetch_team_member", lambda *args, **kwargs: {"user_id": "u-1"})
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams/platform/members",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "conflict"


def test_add_team_member_rejects_invalid_role(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`POST /api/teams/<team_id>/members` should validate role enum."""
    _disable_runtime_guards(monkeypatch)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/teams/platform/members",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "user_id": "u-1",
            "user_email": "u-1@acme.io",
            "role": "admin",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 400
    assert payload.get("ok") is False
    assert payload.get("error") == "bad_request"


def test_remove_team_member_returns_not_found_when_missing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`DELETE /api/teams/<team_id>/members/<user_id>` should return 404 when member is absent."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_team_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_fetch_team_member", lambda *args, **kwargs: None)
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.delete("/api/teams/platform/members/u-404?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 404
    assert payload.get("ok") is False
    assert payload.get("error") == "not_found"


def test_sla_policies_query_uses_scoped_table(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/sla/policies` should query scoped category policy rows."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/sla/policies?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from sla_policy_category" in sql_blob
    assert "tenant_id = %s" in sql_blob
    assert "workspace = %s" in sql_blob


def test_create_sla_policy_returns_conflict_when_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`POST /api/sla/policies` should return 409 on duplicate category."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_fetch_sla_policy_category", lambda *args, **kwargs: {"category": "cost"})
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "category": "cost",
            "sla_days": 14,
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "conflict"


def test_sla_overrides_query_uses_scoped_table(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/sla/policies/overrides` should query scoped override rows."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/sla/policies/overrides?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from sla_policy_check_override" in sql_blob
    assert "tenant_id = %s" in sql_blob
    assert "workspace = %s" in sql_blob


def test_create_sla_override_returns_conflict_when_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`POST /api/sla/policies/overrides` should return 409 on duplicate check_id."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_fetch_sla_policy_override", lambda *args, **kwargs: {"check_id": "aws.ec2.test"})
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/sla/policies/overrides",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "check_id": "aws.ec2.test",
            "sla_days": 7,
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "conflict"


def test_runs_diff_latest_attributes_from_finding_current(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/runs/diff/latest` must not join finding_latest."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        captured_sql.append(sql)
        if "from runs" in sql.lower():
            return [
                {"run_id": "run-2", "run_ts": "2026-02-14T00:00:00Z"},
                {"run_id": "run-1", "run_ts": "2026-02-13T00:00:00Z"},
            ]
        return []

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)

    client = flask_app.app.test_client()
    resp = client.get("/api/runs/diff/latest?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "finding_latest" not in sql_blob
    assert sql_blob.count("finding_current") >= 2
    assert "tenant_id=%s" in sql_blob
    assert "workspace=%s" in sql_blob


def test_api_findings_sets_no_cache_headers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/findings` responses should disable intermediary caching."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(_conn: object, _sql: str, _params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        return []

    def _fake_fetch_one(_conn: object, _sql: str, _params: Optional[Sequence[Any]] = None) -> dict[str, Any]:
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/findings?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, max-age=0"
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("Expires") == "0"
    assert "authorization" in str(resp.headers.get("Vary") or "").lower()


def test_lifecycle_ignore_preserves_exact_fingerprint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Lifecycle endpoints should use the fingerprint exactly as provided by clients."""
    _disable_runtime_guards(monkeypatch)
    captured: dict[str, Any] = {}

    def _fake_upsert_state(
        _conn: object,
        *,
        tenant_id: str,
        workspace: str,
        fingerprint: str,
        state: str,
        snooze_until: Any,
        reason: Any,
        updated_by: Any,
    ) -> None:
        captured["tenant_id"] = tenant_id
        captured["workspace"] = workspace
        captured["fingerprint"] = fingerprint
        captured["state"] = state

    monkeypatch.setattr(flask_app, "_upsert_state", _fake_upsert_state)
    monkeypatch.setattr(flask_app, "_audit_lifecycle", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    body = {
        "tenant_id": "acme",
        "workspace": "prod",
        "fingerprint": "  fp-with-padding  ",
        "reason": "test",
        "updated_by": "tester",
    }
    resp = client.post("/api/lifecycle/ignore", json=body)

    assert resp.status_code == 200
    assert captured["tenant_id"] == "acme"
    assert captured["workspace"] == "prod"
    assert captured["fingerprint"] == "  fp-with-padding  "
    assert captured["state"] == "ignored"


def test_set_finding_owner_endpoint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Owner assignment endpoint should update governance fields with exact scope."""
    _disable_runtime_guards(monkeypatch)
    updates: dict[str, Any] = {}
    fetch_calls = {"n": 0}

    monkeypatch.setattr(flask_app, "_finding_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_ensure_finding_governance_row", lambda *args, **kwargs: None)

    def _fake_fetch_governance(*args, **kwargs):  # type: ignore[no-untyped-def]
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None}
        return {
            "owner_id": updates.get("owner_id"),
            "owner_email": updates.get("owner_email"),
            "owner_name": updates.get("owner_name"),
            "team_id": None,
        }

    def _fake_update_owner(
        _conn: object,
        *,
        tenant_id: str,
        workspace: str,
        fingerprint: str,
        owner_id: Any,
        owner_email: Any,
        owner_name: Any,
    ) -> None:
        updates["tenant_id"] = tenant_id
        updates["workspace"] = workspace
        updates["fingerprint"] = fingerprint
        updates["owner_id"] = owner_id
        updates["owner_email"] = owner_email
        updates["owner_name"] = owner_name

    monkeypatch.setattr(flask_app, "_fetch_governance_owner_team", _fake_fetch_governance)
    monkeypatch.setattr(flask_app, "_update_finding_owner", _fake_update_owner)
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-123/owner",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "owner_email": "owner@acme.io",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert updates["tenant_id"] == "acme"
    assert updates["workspace"] == "prod"
    assert updates["fingerprint"] == "fp-123"
    assert updates["owner_email"] == "owner@acme.io"
    assert updates["owner_id"] is None


def test_set_finding_team_requires_existing_team(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Team assignment endpoint should return 404 when team does not exist."""
    _disable_runtime_guards(monkeypatch)

    monkeypatch.setattr(flask_app, "_finding_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_ensure_finding_governance_row", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        flask_app,
        "_fetch_governance_owner_team",
        lambda *args, **kwargs: {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None},
    )
    monkeypatch.setattr(flask_app, "_team_exists", lambda *args, **kwargs: False)
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.put(
        "/api/findings/fp-123/team",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "team_id": "team-x",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 404
    assert payload.get("ok") is False
    assert payload.get("error") == "not_found"


def test_extend_finding_sla_endpoint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """SLA extension endpoint should update deadline and emit audit event."""
    _disable_runtime_guards(monkeypatch)
    captured: dict[str, Any] = {}

    before = {
        "sla_deadline": datetime(2026, 2, 20, 0, 0, tzinfo=timezone.utc),
        "sla_paused_at": None,
        "sla_total_paused_seconds": 0,
        "sla_extension_seconds": 0,
        "sla_breached_at": None,
        "sla_extended_count": 0,
        "sla_extension_reason": None,
    }
    after = {
        "sla_deadline": datetime(2026, 2, 27, 0, 0, tzinfo=timezone.utc),
        "sla_paused_at": None,
        "sla_total_paused_seconds": 0,
        "sla_extension_seconds": 604800,
        "sla_breached_at": None,
        "sla_extended_count": 1,
        "sla_extension_reason": "awaiting maintenance window",
    }

    monkeypatch.setattr(flask_app, "_finding_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_fetch_finding_effective_state", lambda *args, **kwargs: "open")
    monkeypatch.setattr(flask_app, "_ensure_finding_governance_row", lambda *args, **kwargs: None)
    monkeypatch.setattr(flask_app, "_fetch_governance_sla", lambda *args, **kwargs: before)

    def _fake_apply_extension(
        _conn: object,
        *,
        tenant_id: str,
        workspace: str,
        fingerprint: str,
        extend_days: int,
        reason: Any,
        event_ts: Any,
    ) -> dict[str, Any]:
        captured["tenant_id"] = tenant_id
        captured["workspace"] = workspace
        captured["fingerprint"] = fingerprint
        captured["extend_days"] = extend_days
        captured["reason"] = reason
        captured["event_ts"] = event_ts
        return after

    def _fake_audit(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured["audit_event_type"] = kwargs.get("event_type")
        captured["audit_category"] = kwargs.get("event_category")
        captured["audit_new_value"] = kwargs.get("new_value")

    monkeypatch.setattr(flask_app, "_apply_finding_sla_extension", _fake_apply_extension)
    monkeypatch.setattr(flask_app, "_audit_log_event", _fake_audit)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/findings/fp-123/sla/extend",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "extend_days": 7,
            "reason": "awaiting maintenance window",
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("extend_days") == 7
    assert payload.get("sla_extended_count") == 1
    assert captured["tenant_id"] == "acme"
    assert captured["workspace"] == "prod"
    assert captured["fingerprint"] == "fp-123"
    assert captured["extend_days"] == 7
    assert captured["audit_event_type"] == "finding.sla.extended"
    assert captured["audit_category"] == "sla"
    assert captured["audit_new_value"] == after


def test_extend_finding_sla_rejects_closed_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """SLA extension endpoint should reject resolved/ignored findings."""
    _disable_runtime_guards(monkeypatch)

    monkeypatch.setattr(flask_app, "_finding_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(flask_app, "_fetch_finding_effective_state", lambda *args, **kwargs: "resolved")
    monkeypatch.setattr(flask_app, "_ensure_finding_governance_row", lambda *args, **kwargs: None)
    monkeypatch.setattr(flask_app, "_audit_log_event", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/findings/fp-123/sla/extend",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "extend_days": 3,
            "updated_by": "tester@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "invalid_state"


def test_health_db_internal_error_contract(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/health/db` keeps db_unhealthy contract when internals fail."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_API_DEBUG_ERRORS", False)

    def _boom_db_conn() -> Any:
        raise RuntimeError("db down")

    monkeypatch.setattr(flask_app, "db_conn", _boom_db_conn)

    client = flask_app.app.test_client()
    resp = client.get("/api/health/db")

    assert resp.status_code == 500
    payload = resp.get_json() or {}
    assert payload.get("ok") is False
    assert payload.get("error") == "db_unhealthy"
    assert payload.get("message") == "db health check failed"


def test_runs_diff_internal_error_contract(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/runs/diff/latest` keeps `message`-style internal error payloads."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_API_DEBUG_ERRORS", False)

    def _boom_fetch_all(_conn: object, _sql: str, _params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        raise RuntimeError("boom-runs-diff")

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _boom_fetch_all)

    client = flask_app.app.test_client()
    resp = client.get("/api/runs/diff/latest?tenant_id=acme&workspace=prod")

    assert resp.status_code == 500
    payload = resp.get_json() or {}
    assert payload.get("error") == "internal_error"
    assert payload.get("message") == "boom-runs-diff"


def test_facets_internal_error_contract(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/facets` keeps `detail`-style internal error payloads."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "_API_DEBUG_ERRORS", False)

    def _boom_fetch_all(_conn: object, _sql: str, _params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
        raise RuntimeError("boom-facets")

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _boom_fetch_all)

    client = flask_app.app.test_client()
    resp = client.get("/api/facets?tenant_id=acme&workspace=prod")

    assert resp.status_code == 500
    payload = resp.get_json() or {}
    assert payload.get("error") == "internal_error"
    assert payload.get("detail") == "boom-facets"
