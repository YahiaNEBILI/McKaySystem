"""Tests for recommendations API endpoints."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

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
    """Disable auth/schema gates so request tests focus on API SQL behavior."""
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", lambda: _DummyConn())


def test_recommendations_query_uses_finding_current(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations` must query scoped rows from finding_current."""
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
    resp = client.get("/api/recommendations?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "tenant_id = %s" in sql_blob
    assert "workspace = %s" in sql_blob
    assert "check_id = any(%s)" in sql_blob
    assert "effective_state = any(%s)" in sql_blob


def test_recommendations_response_is_enriched(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations` should return recommendation metadata and annualized savings."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": "fp-1",
                "check_id": "aws.ec2.instances.underutilized",
                "service": "ec2",
                "severity": "medium",
                "category": "rightsizing",
                "title": "EC2 instance underutilized",
                "estimated_monthly_savings": 100.5,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
            }
        ]

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 1}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/recommendations?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("total") == 1
    item = (payload.get("items") or [])[0]
    assert item.get("recommendation_type") == "rightsizing.ec2.instance"
    assert item.get("priority") == "p1"
    assert item.get("estimated_monthly_savings") == 100.5
    assert item.get("estimated_annual_savings") == 1206.0


def test_recommendations_composite_uses_finding_current(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations/composite` should aggregate scoped data from finding_current."""
    _disable_runtime_guards(monkeypatch)
    captured_sql: list[str] = []

    def _fake_fetch_all(_conn: object, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        _ = params
        captured_sql.append(sql)
        return [
            {
                "group_key": "rightsizing.ec2.instance",
                "finding_count": 2,
                "total_monthly_savings": 250.0,
                "total_annual_savings": 3000.0,
            }
        ]

    def _fake_fetch_one(_conn: object, sql: str, params: Sequence[Any] | None = None) -> dict[str, Any]:
        _ = params
        captured_sql.append(sql)
        return {"n": 1}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get(
        "/api/recommendations/composite?tenant_id=acme&workspace=prod&group_by=recommendation_type"
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("group_by") == "recommendation_type"
    assert payload.get("total") == 1
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "group by group_key" in sql_blob
    assert "aws.ec2.instances.underutilized" in sql_blob


def test_recommendations_composite_rejects_invalid_group_by(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations/composite` should return 400 for invalid group_by values."""
    _disable_runtime_guards(monkeypatch)
    client = flask_app.app.test_client()

    resp = client.get("/api/recommendations/composite?tenant_id=acme&workspace=prod&group_by=invalid")
    payload = resp.get_json() or {}

    assert resp.status_code == 400
    assert payload.get("ok") is False
    assert payload.get("error") == "bad_request"
