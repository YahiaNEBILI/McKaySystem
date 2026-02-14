"""Guardrails for Flask API read-model queries."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Optional

import apps.flask_api.flask_app as flask_app


class _DummyConn:
    """Minimal context manager returned by db_conn during unit tests."""

    def __enter__(self) -> object:
        return object()

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False


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
