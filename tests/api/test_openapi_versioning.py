"""Tests for OpenAPI generation and API versioned route aliases."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import apps.flask_api.flask_app as flask_app


class _DummyConn:
    def __enter__(self) -> _DummyConn:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
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
