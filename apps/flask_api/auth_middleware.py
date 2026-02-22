"""Authentication and permission middleware helpers for Flask API."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from flask import g, request
from werkzeug.exceptions import BadRequest

from apps.flask_api.utils import _err, _q, _safe_scope_from_request
from services.rbac_service import (
    AuthContext,
    authenticate_api_key,
    authenticate_session_token,
    authorize,
)

_ViewFunc = TypeVar("_ViewFunc", bound=Callable[..., Any])


def _extract_scope() -> tuple[str, str] | None:
    """Resolve tenant/workspace from headers, query params, or JSON payload."""
    tenant_id = str(
        request.headers.get("X-Tenant-Id") or request.headers.get("X-Tenant") or ""
    ).strip()
    workspace = str(request.headers.get("X-Workspace") or request.headers.get("X-WS") or "").strip()
    if tenant_id and workspace:
        return tenant_id, workspace

    tenant_id_q, workspace_q = _safe_scope_from_request()
    if tenant_id_q and workspace_q:
        return tenant_id_q, workspace_q

    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            tenant_id_p = str(payload.get("tenant_id") or payload.get("tenant") or "").strip()
            workspace_p = str(payload.get("workspace") or payload.get("ws") or "").strip()
            if tenant_id_p and workspace_p:
                return tenant_id_p, workspace_p
    except (BadRequest, TypeError, ValueError):
        return None
    return None


def _extract_bearer_token() -> str | None:
    """Extract bearer token value from Authorization header."""
    auth_header = str(request.headers.get("Authorization") or "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer ") :].strip()
    return token or None


def _extract_session_token() -> str | None:
    """Extract session token from cookie, query, or JSON payload."""
    token = str(request.cookies.get("session_token") or _q("session_token") or "").strip()
    if token:
        return token
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            token_json = str(payload.get("session_token") or "").strip()
            if token_json:
                return token_json
    except (BadRequest, TypeError, ValueError):
        return None
    return None


def authenticate_request() -> AuthContext | None:
    """Authenticate request via session cookie or API-key bearer token."""
    existing = getattr(g, "auth_context", None)
    if isinstance(existing, AuthContext):
        return existing

    scope = _extract_scope()
    if scope is None:
        return None
    tenant_id, workspace = scope

    session_token = _extract_session_token()
    if session_token:
        context = authenticate_session_token(
            tenant_id=tenant_id,
            workspace=workspace,
            session_token=session_token,
        )
        if context is not None:
            g.auth_context = context
            return context

    bearer_token = _extract_bearer_token()
    if bearer_token:
        context = authenticate_api_key(
            tenant_id=tenant_id,
            workspace=workspace,
            api_key=bearer_token,
        )
        if context is not None:
            g.auth_context = context
            return context
    return None


def require_authenticated(view_func: _ViewFunc) -> _ViewFunc:
    """Require an authenticated RBAC context for the wrapped view."""

    @wraps(view_func)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        context = authenticate_request()
        if context is None:
            return _err("unauthorized", "authentication required", status=401)
        return view_func(*args, **kwargs)

    return _wrapped  # type: ignore[return-value]


def require_permission(permission: str) -> Callable[[_ViewFunc], _ViewFunc]:
    """Require one RBAC permission for the wrapped view.

    Args:
        permission: Permission identifier (for example `findings:read`).
    """

    def _decorator(view_func: _ViewFunc) -> _ViewFunc:
        @wraps(view_func)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            context = authenticate_request()
            if context is None:
                return _err("unauthorized", "authentication required", status=401)
            if not authorize(context, permission=permission):
                return _err("forbidden", "permission denied", status=403)
            return view_func(*args, **kwargs)

        return _wrapped  # type: ignore[return-value]

    return _decorator
