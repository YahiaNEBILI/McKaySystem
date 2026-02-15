"""Tests for remediation API endpoints."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import apps.flask_api.blueprints.remediations as remediations_blueprint
import apps.flask_api.flask_app as flask_app


class _DummyConn:
    """Minimal context manager returned by db_conn during unit tests."""

    def __enter__(self) -> _DummyConn:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False

    def commit(self) -> None:
        return


def _disable_runtime_guards(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Disable auth/schema guards so request tests focus on SQL behavior."""
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", lambda: _DummyConn())
    monkeypatch.setattr(remediations_blueprint, "db_conn", lambda: _DummyConn())
    monkeypatch.setattr(
        remediations_blueprint,
        "fetch_all_dict_conn",
        lambda conn, sql, params=None: flask_app.fetch_all_dict_conn(conn, sql, params),  # type: ignore[no-untyped-def]
    )
    monkeypatch.setattr(
        remediations_blueprint,
        "fetch_one_dict_conn",
        lambda conn, sql, params=None: flask_app.fetch_one_dict_conn(conn, sql, params),  # type: ignore[no-untyped-def]
    )
    monkeypatch.setattr(
        remediations_blueprint,
        "execute_conn",
        lambda conn, sql, params=None: flask_app.execute_conn(conn, sql, params),  # type: ignore[no-untyped-def]
    )


def test_remediations_list_query_is_scoped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/remediations` must query remediation_actions with tenant/workspace scope."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        _ = params
        captured_sql.append(sql)
        return []

    def _fake_fetch_one(_conn: object, sql: str, params: Sequence[Any] | None = None) -> dict[str, Any]:
        _ = params
        captured_sql.append(sql)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get(
        "/api/remediations?tenant_id=acme&workspace=prod&status=pending_approval&action_type=noop"
    )

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from remediation_actions" in sql_blob
    assert "ra.tenant_id = %s" in sql_blob
    assert "ra.workspace = %s" in sql_blob
    assert "ra.status = any(%s)" in sql_blob
    assert "ra.action_type = any(%s)" in sql_blob


def test_remediation_approve_transitions_pending_to_approved(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Approve endpoint should allow `pending_approval` -> `approved` only."""
    _disable_runtime_guards(monkeypatch)
    fetch_calls = {"n": 0}
    execute_calls: list[tuple[str, Sequence[Any] | None]] = []

    def _fake_fetch_one(_conn: object, sql: str, params: Sequence[Any] | None = None) -> dict[str, Any] | None:
        _ = sql
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-1",
                "fingerprint": "fp-1",
                "check_id": "aws.ec2.instances.underutilized",
                "action_type": "rightsize",
                "status": "pending_approval",
                "action_payload": {},
                "dry_run": True,
                "reason": None,
                "requested_by": "alice@acme.io",
                "approved_by": None,
                "rejected_by": None,
                "requested_at": "2026-02-15T10:00:00Z",
                "approved_at": None,
                "rejected_at": None,
                "updated_at": "2026-02-15T10:00:00Z",
                "version": 1,
            }
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "act-1",
            "fingerprint": "fp-1",
            "check_id": "aws.ec2.instances.underutilized",
            "action_type": "rightsize",
            "status": "approved",
            "action_payload": {},
            "dry_run": True,
            "reason": "approved for phase1",
            "requested_by": "alice@acme.io",
            "approved_by": "bob@acme.io",
            "rejected_by": None,
            "requested_at": "2026-02-15T10:00:00Z",
            "approved_at": "2026-02-15T10:05:00Z",
            "rejected_at": None,
            "updated_at": "2026-02-15T10:05:00Z",
            "version": 2,
        }

    def _fake_execute(_conn: object, sql: str, params: Sequence[Any] | None = None) -> None:
        execute_calls.append((sql, params))

    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)
    monkeypatch.setattr(flask_app, "execute_conn", _fake_execute)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/remediations/approve",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "act-1",
            "approved_by": "bob@acme.io",
            "reason": "approved for phase1",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    action = payload.get("action") or {}
    assert action.get("status") == "approved"
    assert action.get("approved_by") == "bob@acme.io"
    assert execute_calls
    _, params = execute_calls[0]
    assert params is not None
    assert params[-3:] == ("acme", "prod", "act-1")


def test_remediation_approve_rejects_invalid_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Approve endpoint should return 409 when action is not pending approval."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "act-1",
            "fingerprint": "fp-1",
            "check_id": "aws.ec2.instances.underutilized",
            "action_type": "rightsize",
            "status": "approved",
            "action_payload": {},
            "dry_run": True,
            "reason": None,
            "requested_by": "alice@acme.io",
            "approved_by": "bob@acme.io",
            "rejected_by": None,
            "requested_at": "2026-02-15T10:00:00Z",
            "approved_at": "2026-02-15T10:05:00Z",
            "rejected_at": None,
            "updated_at": "2026-02-15T10:05:00Z",
            "version": 2,
        }

    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)
    monkeypatch.setattr(flask_app, "execute_conn", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/remediations/approve",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "act-1",
            "approved_by": "bob@acme.io",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get("ok") is False
    assert payload.get("error") == "invalid_state"


def test_remediation_reject_returns_not_found(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Reject endpoint should return 404 when action is missing in scope."""
    _disable_runtime_guards(monkeypatch)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", lambda *args, **kwargs: None)
    monkeypatch.setattr(flask_app, "execute_conn", lambda *args, **kwargs: None)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/remediations/reject",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "missing-action",
            "rejected_by": "bob@acme.io",
            "reason": "out of scope",
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 404
    assert payload.get("ok") is False
    assert payload.get("error") == "not_found"
