"""Response helpers for Flask API.

Provides standardized HTTP response formatting for consistent API responses.
"""

from typing import Any, Dict, Optional

from flask import jsonify, request
import traceback


# Configuration - will be set when loaded into flask_app context
_API_DEBUG_ERRORS: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Set debug mode for error responses."""
    global _API_DEBUG_ERRORS
    _API_DEBUG_ERRORS = enabled


def _ok(data: Optional[Dict[str, Any]] = None, *, status: int = 200) -> Any:
    """Create a successful JSON response.

    Args:
        data: Optional dictionary to include in the response
        status: HTTP status code (default 200)

    Returns:
        Flask response tuple (json, status)
    """
    payload: Dict[str, Any] = {"ok": True}
    if data:
        payload.update(data)
    return jsonify(payload), status


def _err(
    code: str,
    message: str,
    *,
    status: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Any:
    """Create an error JSON response.

    Args:
        code: Error code (e.g., 'bad_request', 'not_found')
        message: Human-readable error message
        status: HTTP status code
        extra: Optional additional data to include

    Returns:
        Flask response tuple (json, status)
    """
    payload: Dict[str, Any] = {"ok": False, "error": code, "message": message}
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def _json(payload: Dict[str, Any], *, status: int = 200) -> Any:
    """Create a generic JSON response with explicit status code.

    Backward-compatible helper. If 'ok' is missing, it is inferred from status.
    Prefer using _ok() / _err() for new code.

    Args:
        payload: Dictionary to JSON-encode
        status: HTTP status code

    Returns:
        Flask response tuple (json, status)
    """
    if "ok" not in payload:
        payload = dict(payload)
        payload["ok"] = status < 400
    return jsonify(payload), status


def _api_internal_error_response(exc: Exception) -> Any:
    """Map API internal errors to stable, route-specific response shapes.

    Provides different error formats based on the endpoint for consistency
    with the existing API behavior.

    Args:
        exc: The exception that was raised

    Returns:
        Flask response tuple with appropriate error format
    """
    # Import here to avoid circular imports
    from flask import current_app

    exc_text = str(exc)

    # Try to get request path safely
    try:
        path = request.path if request else ""
    except RuntimeError:
        path = ""

    # Health endpoint - simple error
    if path == "/api/health/db":
        if _API_DEBUG_ERRORS:
            return _err(
                "db_unhealthy",
                "db health check failed",
                status=500,
                extra={"detail": exc_text},
            )
        return _err("db_unhealthy", "db health check failed", status=500)

    # Findings endpoint - includes traceback in debug mode
    if path == "/api/findings":
        extra = None
        if _API_DEBUG_ERRORS:
            extra = {
                "detail": exc_text,
                "traceback": traceback.format_exc(),
            }
        return _err("internal_error", "internal error", status=500, extra=extra)

    # Lifecycle and aggregate endpoints - detail in message
    if path in {
        "/api/findings/aggregates",
        "/api/facets",
        "/api/lifecycle/group/ignore",
        "/api/lifecycle/group/resolve",
        "/api/lifecycle/group/snooze",
        "/api/lifecycle/ignore",
        "/api/lifecycle/resolve",
        "/api/lifecycle/snooze",
    }:
        return jsonify({"error": "internal_error", "detail": exc_text}), 500

    # Groups and runs/diff - message in detail
    if (
        path == "/api/runs/diff/latest"
        or path == "/api/groups"
        or (path.startswith("/api/groups/"))
    ):
        return _json({"error": "internal_error", "message": exc_text}, status=500)

    # Default - generic internal error
    return _err("internal_error", "internal error", status=500)
