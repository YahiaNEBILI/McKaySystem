"""Guardrails for Flask API read-model queries."""

from __future__ import annotations

from collections.abc import Sequence
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
