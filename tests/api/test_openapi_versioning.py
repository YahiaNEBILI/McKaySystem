"""Tests for OpenAPI generation and API versioned route aliases."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

import apps.flask_api.flask_app as flask_app


class _DummyConn:
    def __enter__(self) -> _DummyConn:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False

    def commit(self) -> None:
        return


def _disable_runtime_guards(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(flask_app, "_schema_gate_enabled", False)
    monkeypatch.setattr(flask_app, "_schema_gate_checked", True)
    monkeypatch.setattr(flask_app, "_API_BEARER_TOKEN", "")
    monkeypatch.setattr(flask_app, "db_conn", lambda: _DummyConn())


def test_versioned_findings_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/findings` should behave like `/api/findings`."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        _ = (sql, params)
        return []

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        _ = (sql, params)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/v1/findings?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert "items" in body
    assert body.get("total") == 0


def test_openapi_public_endpoint_contains_versioned_servers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """OpenAPI spec should expose versioned + legacy API bases."""
    _disable_runtime_guards(monkeypatch)

    client = flask_app.app.test_client()
    resp = client.get("/openapi.json")

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("openapi") == "3.0.3"
    servers = body.get("servers") or []
    urls = {str(s.get("url")) for s in servers if isinstance(s, dict)}
    assert "/api/v1" in urls
    assert "/api" in urls
    paths = body.get("paths") or {}
    assert "/findings" in paths
    assert "get" in (paths.get("/findings") or {})
    assert "/recommendations" in paths
    assert "get" in (paths.get("/recommendations") or {})
    assert "/recommendations/estimate" in paths
    assert "post" in (paths.get("/recommendations/estimate") or {})
    assert "/recommendations/preview" in paths
    assert "post" in (paths.get("/recommendations/preview") or {})
    assert "/remediations" in paths
    assert "get" in (paths.get("/remediations") or {})
    assert "/remediations/impact" in paths
    assert "get" in (paths.get("/remediations/impact") or {})
    assert "/remediations/request" in paths
    assert "post" in (paths.get("/remediations/request") or {})
    assert "/remediations/approve" in paths
    assert "post" in (paths.get("/remediations/approve") or {})


def test_versioned_recommendations_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/recommendations` should behave like `/api/recommendations`."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        _ = (sql, params)
        return []

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        _ = (sql, params)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/v1/recommendations?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("ok") is True
    assert body.get("total") == 0


def test_versioned_recommendations_estimate_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/recommendations/estimate` should behave like `/api/recommendations/estimate`."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        _ = (sql, params)
        return []

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        _ = (sql, params)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.post("/api/v1/recommendations/estimate", json={"tenant_id": "acme", "workspace": "prod"})

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("ok") is True
    assert body.get("mode") == "estimate"


def test_versioned_remediations_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/remediations` should behave like `/api/remediations`."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        _ = (sql, params)
        return []

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        _ = (sql, params)
        return {"n": 0}

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/v1/remediations?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("ok") is True
    assert body.get("total") == 0


def test_versioned_remediations_impact_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/remediations/impact` should behave like `/api/remediations/impact`."""
    _disable_runtime_guards(monkeypatch)

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        _ = (sql, params)
        return []

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        _ = (sql, params)
        return {
            "n": 0,
            "actions_count": 0,
            "resolved_count": 0,
            "persistent_count": 0,
            "pending_count": 0,
            "failed_count": 0,
            "baseline_total_monthly_savings": 0.0,
            "realized_total_monthly_savings": 0.0,
        }

    monkeypatch.setattr(flask_app, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)

    client = flask_app.app.test_client()
    resp = client.get("/api/v1/remediations/impact?tenant_id=acme&workspace=prod")

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("ok") is True
    summary = body.get("summary") or {}
    assert summary.get("actions_count") == 0


def test_versioned_remediations_request_alias_works(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`/api/v1/remediations/request` should behave like `/api/remediations/request`."""
    _disable_runtime_guards(monkeypatch)
    execute_calls: list[tuple[str, Sequence[Any] | None]] = []
    fetch_calls = {"n": 0}

    def _fake_fetch_one(
        _conn: object, _sql: str, _params: Sequence[Any] | None = None
    ) -> dict[str, Any] | None:
        fetch_calls["n"] += 1
        if fetch_calls["n"] == 1:
            return {
                "tenant_id": "acme",
                "workspace": "prod",
                "fingerprint": "fp-1",
                "check_id": "aws.ec2.instances.underutilized",
                "effective_state": "open",
                "service": "ec2",
            }
        if fetch_calls["n"] == 2:
            return None
        return {
            "tenant_id": "acme",
            "workspace": "prod",
            "action_id": "act-v1",
            "fingerprint": "fp-1",
            "check_id": "aws.ec2.instances.underutilized",
            "action_type": "rightsize",
            "status": "pending_approval",
            "action_payload": {},
            "dry_run": True,
            "reason": None,
            "requested_by": None,
            "approved_by": None,
            "rejected_by": None,
            "requested_at": "2026-02-15T10:00:00Z",
            "approved_at": None,
            "rejected_at": None,
            "updated_at": "2026-02-15T10:00:00Z",
            "version": 1,
        }

    def _fake_execute(_conn: object, sql: str, params: Sequence[Any] | None = None) -> None:
        execute_calls.append((sql, params))

    monkeypatch.setattr(flask_app, "fetch_one_dict_conn", _fake_fetch_one)
    monkeypatch.setattr(flask_app, "execute_conn", _fake_execute)

    client = flask_app.app.test_client()
    resp = client.post(
        "/api/v1/remediations/request",
        json={"tenant_id": "acme", "workspace": "prod", "fingerprint": "fp-1", "action_id": "act-v1"},
    )

    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body.get("ok") is True
    assert body.get("created") is True
    assert execute_calls


def test_versioned_openapi_alias_and_version_endpoint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Versioned aliases should exist for OpenAPI and version metadata routes."""
    _disable_runtime_guards(monkeypatch)

    client = flask_app.app.test_client()

    spec_resp = client.get("/api/v1/openapi.json")
    assert spec_resp.status_code == 200

    version_resp = client.get("/api/v1/version")
    assert version_resp.status_code == 200
    version_body = version_resp.get_json() or {}
    assert version_body.get("version") == "v1"
    assert version_body.get("prefix") == "/api/v1"
