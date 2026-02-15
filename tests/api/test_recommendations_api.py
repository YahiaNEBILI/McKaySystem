"""Tests for recommendations API endpoints."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import apps.flask_api.flask_app as flask_app
import apps.flask_api.blueprints.recommendations as recommendations_blueprint


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
    monkeypatch.setattr(recommendations_blueprint, "db_conn", lambda: _DummyConn())
    monkeypatch.setattr(
        recommendations_blueprint,
        "fetch_all_dict_conn",
        lambda conn, sql, params=None: flask_app.fetch_all_dict_conn(conn, sql, params),  # type: ignore[no-untyped-def]
    )
    monkeypatch.setattr(
        recommendations_blueprint,
        "fetch_one_dict_conn",
        lambda conn, sql, params=None: flask_app.fetch_one_dict_conn(conn, sql, params),  # type: ignore[no-untyped-def]
    )


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
    assert "left join runs" in sql_blob


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
                "payload": {
                    "estimated": {
                        "confidence": 91,
                        "pricing_source": "snapshot",
                        "pricing_version": "aws_2026_02_01",
                    },
                    "dimensions": {
                        "instance_type": "m5.2xlarge",
                        "recommended_instance_type": "m5.xlarge",
                    },
                },
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
    assert item.get("action_type") == "rightsize"
    assert item.get("action") == "Downsize EC2 instance from m5.2xlarge to m5.xlarge based on sustained utilization."
    assert (item.get("target") or {}).get("kind") == "instance_type"
    assert (item.get("target") or {}).get("value") == "m5.xlarge"
    assert (item.get("current") or {}).get("value") == "m5.2xlarge"
    assert item.get("confidence") == 91
    assert item.get("confidence_label") == "high"
    assert item.get("pricing_source") == "snapshot"
    assert item.get("pricing_version") == "aws_2026_02_01"
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


def test_recommendations_response_uses_run_metadata_fallback(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Recommendations should read pricing metadata from run metadata when payload lacks it."""
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
                "payload": {},
                "run_meta": {"pricing_source": "snapshot", "pricing_version": "aws_2026_04_01"},
            }
        ]

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 1}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/recommendations?tenant_id=acme&workspace=prod")
    payload = resp.get_json() or {}
    item = (payload.get("items") or [])[0]

    assert resp.status_code == 200
    assert item.get("confidence") == 78
    assert item.get("pricing_source") == "snapshot"
    assert item.get("pricing_version") == "aws_2026_04_01"


def test_recommendations_response_ri_coverage_gap_is_enriched(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """RI coverage-gap recommendations should expose actionable target/current values."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": "fp-ri-gap",
                "check_id": "aws.ec2.ri.coverage.gap",
                "service": "ec2",
                "severity": "high",
                "category": "cost",
                "title": "RI coverage gap",
                "estimated_monthly_savings": 43.8,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {
                    "dimensions": {
                        "instance_type": "m5.large",
                        "uncovered_count": "2",
                        "coverage_pct": "33.33",
                        "target_coverage_pct": "90.00",
                    }
                },
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
    item = (payload.get("items") or [])[0]
    assert item.get("recommendation_type") == "commitment.ec2.ri.coverage"
    assert item.get("action_type") == "purchase"
    assert (item.get("current") or {}).get("value") == "33.33"
    assert (item.get("target") or {}).get("value") == "90.00"
    assert "m5.large" in str(item.get("action") or "")


def test_recommendations_estimate_is_scoped_and_uses_finding_current(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations/estimate` should query finding_current with scope + fingerprint filter."""
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
    resp = client.post(
        "/api/recommendations/estimate",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "fingerprints": ["fp-1", "fp-2"],
        },
    )

    assert resp.status_code == 200
    sql_blob = "\n".join(captured_sql).lower()
    assert "from finding_current" in sql_blob
    assert "tenant_id = %s" in sql_blob
    assert "workspace = %s" in sql_blob
    assert "fingerprint = any(%s)" in sql_blob
    assert "check_id = any(%s)" in sql_blob


def test_recommendations_estimate_returns_totals_and_warnings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Estimate response should include deterministic totals and risk warnings."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": "fp-1",
                "check_id": "aws.ec2.nat.gateways.idle",
                "service": "ec2",
                "severity": "high",
                "category": "cost",
                "title": "Idle NAT gateway",
                "estimated_monthly_savings": 200.0,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {
                    "estimated": {"confidence": 88},
                    "dimensions": {"pricing_version": "aws_2026_02_01"},
                },
            },
            {
                "fingerprint": "fp-2",
                "check_id": "aws.s3.governance.lifecycle.missing",
                "service": "s3",
                "severity": "medium",
                "category": "cost",
                "title": "Lifecycle missing",
                "estimated_monthly_savings": 50.0,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {
                    "estimated": {"confidence": 61},
                    "dimensions": {"pricing_version": "aws_2026_02_01"},
                },
            },
        ]

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 2}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/recommendations/estimate",
        json={
            "tenant_id": "acme",
            "workspace": "prod",
            "fingerprints": ["fp-1", "fp-missing", "fp-2"],
        },
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("mode") == "estimate"
    assert payload.get("pricing_version") == "aws_2026_02_01"
    assert payload.get("pricing_versions") == ["aws_2026_02_01"]
    assert payload.get("total") == 2
    assert payload.get("selected_count") == 2
    totals = payload.get("totals") or {}
    assert totals.get("estimated_monthly_savings") == 250.0
    assert totals.get("estimated_annual_savings") == 3000.0
    warnings = payload.get("risk_warnings") or []
    warning_codes = {str(w.get("code")) for w in warnings}
    assert "approval_required" in warning_codes
    assert "missing_or_ineligible" in warning_codes


def test_recommendations_preview_alias_points_to_estimate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/recommendations/preview` should be an alias of estimate semantics."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        return []

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.post("/api/recommendations/preview", json={"tenant_id": "acme", "workspace": "prod"})
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("ok") is True
    assert payload.get("mode") == "estimate"


def test_recommendations_estimate_pricing_version_mixed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Estimate should expose mixed pricing versions when selected items differ."""
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
                "estimated_monthly_savings": 10.0,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {"dimensions": {"pricing_version": "aws_2026_02_01"}},
            },
            {
                "fingerprint": "fp-2",
                "check_id": "aws.rds.storage.overprovisioned",
                "service": "rds",
                "severity": "medium",
                "category": "rightsizing",
                "title": "RDS storage overprovisioned",
                "estimated_monthly_savings": 20.0,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {"dimensions": {"pricing_version": "aws_2026_03_01"}},
            },
        ]

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 2}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.post("/api/recommendations/estimate", json={"tenant_id": "acme", "workspace": "prod"})
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("pricing_version") == "mixed"
    assert payload.get("pricing_versions") == ["aws_2026_02_01", "aws_2026_03_01"]


def test_recommendations_estimate_pricing_version_from_run_metadata(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Estimate should use run metadata pricing_version when payload does not provide one."""
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
                "estimated_monthly_savings": 10.0,
                "region": "us-east-1",
                "account_id": "111111111111",
                "detected_at": "2026-02-14T00:00:00Z",
                "effective_state": "open",
                "payload": {},
                "run_meta": {"pricing_version": "aws_2026_05_01"},
            }
        ]

    def _fake_fetch_one(_conn: object, _sql: str, _params: Sequence[Any] | None = None) -> dict[str, Any]:
        return {"n": 1}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.post("/api/recommendations/estimate", json={"tenant_id": "acme", "workspace": "prod"})
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get("pricing_version") == "aws_2026_05_01"
    assert payload.get("pricing_versions") == ["aws_2026_05_01"]


def test_recommendations_estimate_rejects_invalid_fingerprints_type(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Estimate endpoint should validate fingerprints payload type."""
    _disable_runtime_guards(monkeypatch)
    client = flask_app.app.test_client()

    resp = client.post(
        "/api/recommendations/estimate",
        json={"tenant_id": "acme", "workspace": "prod", "fingerprints": 123},
    )
    payload = resp.get_json() or {}

    assert resp.status_code == 400
    assert payload.get("ok") is False
    assert payload.get("error") == "bad_request"
