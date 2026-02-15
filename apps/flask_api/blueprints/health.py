"""Health and metadata endpoints Blueprint.

Provides health check, OpenAPI spec, and version endpoints.
"""

from typing import Any

from flask import Blueprint, jsonify

from apps.backend.db import db_conn, fetch_one_dict_conn
from apps.flask_api.utils import _ok, _json

# Create the blueprint
health_bp = Blueprint("health", __name__)


# API version - will be set from main app
_API_VERSION: str = "v1"
_API_PREFIX: str = "/api/v1"


def init_blueprint(api_version: str, api_prefix: str) -> None:
    """Initialize blueprint with API version settings.

    Args:
        api_version: API version string (e.g., 'v1')
        api_prefix: API prefix string (e.g., '/api/v1')
    """
    global _API_VERSION, _API_PREFIX
    _API_VERSION = api_version
    _API_PREFIX = api_prefix


@health_bp.route("/health", methods=["GET"])
def health() -> Any:
    """Basic health check endpoint.

    Returns:
        JSON response with ok: true
    """
    return jsonify({"ok": True})


@health_bp.route("/api/health/db", methods=["GET"])
def api_health_db() -> Any:
    """Database health check endpoint.

    Returns:
        JSON response with database health status
    """
    with db_conn() as conn:
        row = fetch_one_dict_conn(conn, "SELECT 1 AS ok")
    return _ok({"db": bool(row and row.get("ok") == 1)})


@health_bp.route("/openapi.json", methods=["GET"])
def api_openapi_public() -> Any:
    """OpenAPI 3.0 specification (public endpoint).

    Returns:
        OpenAPI specification JSON
    """
    return _json(_build_openapi_spec())


@health_bp.route("/api/openapi.json", methods=["GET"])
def api_openapi_scoped() -> Any:
    """OpenAPI 3.0 specification under API base.

    Returns:
        OpenAPI specification JSON
    """
    return _json(_build_openapi_spec())


@health_bp.route("/api/version", methods=["GET"])
def api_version() -> Any:
    """API version metadata and supported versions.

    Returns:
        Version information JSON
    """
    return _json(
        {
            "version": _API_VERSION,
            "prefix": _API_PREFIX,
            "supported_versions": [_API_VERSION],
            "legacy_prefix": "/api",
        }
    )


def _build_openapi_spec() -> dict:
    """Build a basic OpenAPI spec for the health endpoints.

    This is a placeholder - the full implementation would introspect
    all registered routes and build a complete spec.

    Returns:
        Basic OpenAPI specification dictionary
    """
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "McKaySystem API",
            "version": _API_VERSION,
            "description": "FinOps Analyzer API",
        },
        "servers": [{"url": _API_PREFIX}],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Basic health check",
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/api/health/db": {
                "get": {
                    "summary": "Database health check",
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/api/version": {
                "get": {
                    "summary": "API version info",
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }
