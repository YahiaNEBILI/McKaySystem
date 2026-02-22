"""Auth Blueprint.

Provides RBAC auth endpoints:
- login
- logout
- me
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from flask import Blueprint, Response, g, make_response, request

from apps.flask_api.auth_middleware import require_authenticated
from apps.flask_api.utils import (
    _err,
    _ok,
    _require_scope_from_json,
    _require_scope_from_query,
)
from services import rbac_service
from services.rbac_service import AuthContext

auth_bp = Blueprint("auth", __name__)

_SESSION_COOKIE_NAME = "session_token"


def _serialize_context(context: AuthContext) -> dict[str, Any]:
    """Convert an auth context into stable response payload fields."""
    return {
        "tenant_id": context.tenant_id,
        "workspace": context.workspace,
        "user_id": context.user_id,
        "email": context.email,
        "full_name": context.full_name,
        "is_superadmin": context.is_superadmin,
        "auth_method": context.auth_method,
        "session_id": context.session_id,
        "key_id": context.key_id,
        "permissions": sorted(context.permissions),
    }


def _response_with_session_cookie(
    *,
    payload: dict[str, Any],
    session_token: str,
    expires_at: datetime,
) -> Response:
    """Create an auth response and attach secure session cookie."""
    response = make_response(_ok(payload))
    response.set_cookie(
        key=_SESSION_COOKIE_NAME,
        value=session_token,
        expires=expires_at,
        httponly=True,
        secure=bool(request.is_secure),
        samesite="Lax",
        path="/",
    )
    return response


@auth_bp.route("/api/auth/login", methods=["POST"])
def api_auth_login() -> Any:
    """Authenticate user credentials and issue a scoped session token."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        if not email:
            raise ValueError("email is required")
        if not password:
            raise ValueError("password is required")

        result = rbac_service.authenticate_user(
            tenant_id=tenant_id,
            workspace=workspace,
            email=email,
            password=password,
        )
        if result is None:
            return _err("unauthorized", "invalid credentials", status=401)

        context, session_token, expires_at = result
        return _response_with_session_cookie(
            payload={
                "user": _serialize_context(context),
                "session_token": session_token,
                "expires_at": expires_at.isoformat(),
            },
            session_token=session_token,
            expires_at=expires_at,
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@auth_bp.route("/api/auth/logout", methods=["POST"])
@require_authenticated
def api_auth_logout() -> Any:
    """Invalidate current scoped session token."""
    context = getattr(g, "auth_context", None)
    if not isinstance(context, AuthContext):
        return _err("unauthorized", "authentication required", status=401)

    payload = request.get_json(silent=True) or {}
    session_token = str(
        request.cookies.get(_SESSION_COOKIE_NAME) or payload.get("session_token") or ""
    ).strip()
    if not session_token:
        return _err("bad_request", "session_token is required for logout", status=400)

    rbac_service.logout_session(
        tenant_id=context.tenant_id,
        workspace=context.workspace,
        session_token=session_token,
    )
    response = make_response(_ok({"logged_out": True}))
    response.delete_cookie(_SESSION_COOKIE_NAME, path="/")
    return response


@auth_bp.route("/api/auth/me", methods=["GET"])
@require_authenticated
def api_auth_me() -> Any:
    """Return the current authenticated principal context."""
    context = getattr(g, "auth_context", None)
    if not isinstance(context, AuthContext):
        return _err("unauthorized", "authentication required", status=401)

    try:
        tenant_id, workspace = _require_scope_from_query()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)

    if tenant_id != context.tenant_id or workspace != context.workspace:
        return _err("forbidden", "scope mismatch", status=403)
    return _ok({"user": _serialize_context(context)})
