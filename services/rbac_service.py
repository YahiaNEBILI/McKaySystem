"""RBAC authentication and authorization service layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from apps.backend import db_rbac
from apps.backend.auth.passwords import verify_password
from apps.backend.auth.tokens import (
    generate_session_token,
    hash_api_key,
    hash_session_token,
)
from apps.backend.db import db_conn

_SESSION_TTL_HOURS = 24


@dataclass(frozen=True)
# Context DTO intentionally mirrors auth/session/api-key principals.
# pylint: disable=too-many-instance-attributes
class AuthContext:
    """Resolved authentication context for one request principal."""

    tenant_id: str
    workspace: str
    user_id: str
    email: str | None
    full_name: str | None
    is_superadmin: bool
    auth_method: str
    session_id: str | None = None
    key_id: str | None = None
    permissions: frozenset[str] = frozenset()


# pylint: enable=too-many-instance-attributes


def _session_expiry_utc() -> datetime:
    """Return deterministic session expiry timestamp in UTC."""
    return datetime.now(UTC) + timedelta(hours=_SESSION_TTL_HOURS)


def _session_id_from_hash(session_token_hash: str) -> str:
    """Derive deterministic session_id from a session token hash."""
    return f"ses_{session_token_hash[:24]}"


def _build_context(
    *,
    row: dict[str, Any],
    auth_method: str,
    permissions: list[str],
) -> AuthContext:
    """Build immutable auth context from a DB row and resolved permissions."""
    return AuthContext(
        tenant_id=str(row.get("tenant_id") or ""),
        workspace=str(row.get("workspace") or ""),
        user_id=str(row.get("user_id") or ""),
        email=str(row.get("email") or "") or None,
        full_name=str(row.get("full_name") or "") or None,
        is_superadmin=bool(row.get("is_superadmin")),
        auth_method=auth_method,
        session_id=str(row.get("session_id") or "") or None,
        key_id=str(row.get("key_id") or "") or None,
        permissions=frozenset(str(p) for p in permissions if p),
    )


def authenticate_user(
    *,
    tenant_id: str,
    workspace: str,
    email: str,
    password: str,
) -> tuple[AuthContext, str, datetime] | None:
    """Authenticate a user/password and create a new scoped session.

    Args:
        tenant_id: Tenant scope.
        workspace: Workspace scope.
        email: User email.
        password: Plaintext password.

    Returns:
        Tuple of `(auth_context, raw_session_token, expires_at)` on success,
        otherwise `None`.
    """
    with db_conn() as conn:
        user = db_rbac.get_user_by_email(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            email=email,
        )
        if user is None:
            return None
        if not bool(user.get("is_active")):
            return None

        stored_hash = str(user.get("password_hash") or "")
        if not stored_hash or not verify_password(password, stored_hash):
            return None

        raw_session_token = generate_session_token()
        session_token_hash = hash_session_token(raw_session_token)
        session_id = _session_id_from_hash(session_token_hash)
        expires_at = _session_expiry_utc()

        db_rbac.upsert_user_session(
            conn,
            session=db_rbac.SessionUpsert(
                tenant_id=tenant_id,
                workspace=workspace,
                session_id=session_id,
                session_token_hash=session_token_hash,
                user_id=str(user.get("user_id") or ""),
                expires_at=expires_at,
            ),
        )
        db_rbac.touch_user_last_login(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            user_id=str(user.get("user_id") or ""),
        )
        permissions = db_rbac.get_user_permissions(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            user_id=str(user.get("user_id") or ""),
        )
        conn.commit()
    context = _build_context(
        row={**user, "session_id": session_id},
        auth_method="session",
        permissions=permissions,
    )
    return context, raw_session_token, expires_at


def authenticate_api_key(
    *,
    tenant_id: str,
    workspace: str,
    api_key: str,
) -> AuthContext | None:
    """Authenticate a scoped API key and return auth context when valid."""
    key_hash = hash_api_key(api_key)
    with db_conn() as conn:
        user = db_rbac.get_user_by_api_key_hash(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            key_hash=key_hash,
        )
        if user is None:
            return None
        key_id = str(user.get("key_id") or "")
        if key_id:
            db_rbac.touch_api_key_last_used(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                key_id=key_id,
            )
        permissions = db_rbac.get_user_permissions(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            user_id=str(user.get("user_id") or ""),
        )
        conn.commit()
    return _build_context(row=user, auth_method="api_key", permissions=permissions)


def authenticate_session_token(
    *,
    tenant_id: str,
    workspace: str,
    session_token: str,
) -> AuthContext | None:
    """Authenticate a scoped session token and return auth context when valid."""
    token_hash = hash_session_token(session_token)
    with db_conn() as conn:
        user = db_rbac.get_user_by_session_hash(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            session_token_hash=token_hash,
        )
        if user is None:
            return None
        permissions = db_rbac.get_user_permissions(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            user_id=str(user.get("user_id") or ""),
        )
    return _build_context(row=user, auth_method="session", permissions=permissions)


def logout_session(
    *,
    tenant_id: str,
    workspace: str,
    session_token: str,
) -> bool:
    """Invalidate one scoped session token."""
    token_hash = hash_session_token(session_token)
    with db_conn() as conn:
        removed = db_rbac.delete_session_by_hash(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            session_token_hash=token_hash,
        )
        conn.commit()
        return removed


def authorize(ctx: AuthContext, *, permission: str) -> bool:
    """Return True when the auth context is allowed for a permission."""
    if ctx.is_superadmin:
        return True
    if "admin:full" in ctx.permissions:
        return True
    return permission in ctx.permissions
