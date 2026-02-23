"""Auth Blueprint.

Provides RBAC auth endpoints:
- login
- logout
- me
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

from flask import Blueprint, Response, g, make_response, request

from apps.backend.db import db_conn
from apps.flask_api.audit import AuditEvent, append_audit_event
from apps.flask_api.auth_middleware import require_authenticated
from apps.flask_api.utils import (
    _err,
    _ok,
    _require_scope_from_json,
    _require_scope_from_query,
)
from infra.config import get_settings
from services import rbac_service
from services.rbac_service import AuthContext

auth_bp = Blueprint("auth", __name__)

_SESSION_COOKIE_NAME = "session_token"
_SETTINGS = get_settings()
_LOGIN_FAILURE_LIMIT = int(_SETTINGS.api.login_failure_limit)
_LOGIN_FAILURE_WINDOW_SECONDS = int(_SETTINGS.api.login_failure_window_seconds)
_LOGIN_FAILURES_LOCK = threading.Lock()
_LOGIN_FAILURES_BY_KEY: dict[str, deque[float]] = {}


def _login_scope_and_credentials(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    """Extract required login payload fields."""
    tenant_id, workspace = _require_scope_from_json(payload)
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")
    if not email:
        raise ValueError("email is required")
    if not password:
        raise ValueError("password is required")
    return tenant_id, workspace, email, password


def _correlation_id() -> str | None:
    """Return request correlation id when provided."""
    value = str(
        request.headers.get("X-Correlation-Id")
        or request.headers.get("X-Request-Id")
        or ""
    ).strip()
    return value or None


def _client_ip() -> str:
    """Resolve stable client ip from request headers/remote addr."""
    forwarded = str(request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",", maxsplit=1)[0].strip() or "unknown"
    remote = str(request.remote_addr or "").strip()
    return remote or "unknown"


def _login_failure_key(*, tenant_id: str, workspace: str, email: str) -> str:
    """Return in-memory login-failure bucket key."""
    return f"{_client_ip()}|{tenant_id}|{workspace}|{email}"


def _prune_expired_failures(failures: deque[float], *, now_ts: float) -> None:
    """Drop login failures outside the configured rolling window."""
    window = float(_LOGIN_FAILURE_WINDOW_SECONDS)
    while failures and (now_ts - failures[0]) >= window:
        failures.popleft()


def _login_is_rate_limited(key: str) -> tuple[bool, int]:
    """Return limiter decision and retry-after seconds for one login key."""
    now_ts = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES_BY_KEY.get(key)
        if failures is None:
            return False, 0
        _prune_expired_failures(failures, now_ts=now_ts)
        if len(failures) < _LOGIN_FAILURE_LIMIT:
            if not failures:
                _LOGIN_FAILURES_BY_KEY.pop(key, None)
            return False, 0
        retry_after = max(1, int(_LOGIN_FAILURE_WINDOW_SECONDS - (now_ts - failures[0])))
        return True, retry_after


def _record_login_failure(key: str) -> int:
    """Record one failed login attempt and return retry-after when blocked."""
    now_ts = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES_BY_KEY.setdefault(key, deque())
        _prune_expired_failures(failures, now_ts=now_ts)
        failures.append(now_ts)
        if len(failures) < _LOGIN_FAILURE_LIMIT:
            return 0
        return max(1, int(_LOGIN_FAILURE_WINDOW_SECONDS - (now_ts - failures[0])))


def _clear_login_failures(key: str) -> None:
    """Clear recorded failures for a login key."""
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES_BY_KEY.pop(key, None)


def clear_login_limiter_state_for_tests() -> None:
    """Reset in-memory login limiter state (test utility)."""
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES_BY_KEY.clear()


def _rate_limited_response(*, retry_after: int) -> Response:
    """Build standard 429 response for login limiter decisions."""
    response = make_response(
        _err(
            "too_many_requests",
            "too many failed login attempts",
            status=429,
        )
    )
    response.headers["Retry-After"] = str(max(1, retry_after))
    return response


def _audit_auth_event(*, event: AuditEvent) -> None:
    """Best-effort write of auth-related audit events."""
    with db_conn() as conn:
        append_audit_event(
            conn,
            event=event,
        )
        conn.commit()


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
        samesite="None",
        path="/",
    )
    return response


@auth_bp.route("/api/auth/login", methods=["POST"])
def api_auth_login() -> Any:
    """Authenticate user credentials and issue a scoped session token."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace, email, password = _login_scope_and_credentials(payload)
        key = _login_failure_key(tenant_id=tenant_id, workspace=workspace, email=email)

        limited, retry_after = _login_is_rate_limited(key)
        if limited:
            _audit_auth_event(
                event=AuditEvent(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    entity_type="auth_principal",
                    entity_id=email,
                    event_type="auth.login.rate_limited",
                    event_category="auth",
                    previous_value=None,
                    new_value={"email": email, "limited": True},
                    actor_id=None,
                    actor_email=email,
                    actor_name=None,
                    source="/api/auth",
                    correlation_id=_correlation_id(),
                ),
            )
            return _rate_limited_response(retry_after=retry_after)

        result = rbac_service.authenticate_user(
            tenant_id=tenant_id,
            workspace=workspace,
            email=email,
            password=password,
        )
        if result is None:
            retry_after = _record_login_failure(key)
            _audit_auth_event(
                event=AuditEvent(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    entity_type="auth_principal",
                    entity_id=email,
                    event_type="auth.login.failed",
                    event_category="auth",
                    previous_value=None,
                    new_value={"email": email, "success": False},
                    actor_id=None,
                    actor_email=email,
                    actor_name=None,
                    source="/api/auth",
                    correlation_id=_correlation_id(),
                ),
            )
            if retry_after > 0:
                return _rate_limited_response(retry_after=retry_after)
            return _err("unauthorized", "invalid credentials", status=401)

        _clear_login_failures(key)
        context, session_token, expires_at = result
        _audit_auth_event(
            event=AuditEvent(
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="auth_principal",
                entity_id=context.user_id,
                event_type="auth.login.succeeded",
                event_category="auth",
                previous_value=None,
                new_value={"email": email, "success": True, "session_id": context.session_id},
                actor_id=context.user_id,
                actor_email=context.email,
                actor_name=context.full_name,
                source="/api/auth",
                correlation_id=_correlation_id(),
            ),
        )
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
    _audit_auth_event(
        event=AuditEvent(
            tenant_id=context.tenant_id,
            workspace=context.workspace,
            entity_type="auth_principal",
            entity_id=context.user_id,
            event_type="auth.logout.succeeded",
            event_category="auth",
            previous_value=None,
            new_value={"session_id": context.session_id},
            actor_id=context.user_id,
            actor_email=context.email,
            actor_name=context.full_name,
            source="/api/auth",
            correlation_id=_correlation_id(),
        ),
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
