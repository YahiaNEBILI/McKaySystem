"""Users Blueprint.

Provides RBAC-managed user endpoints:
- list users
- create user
- get user
- update user
- deactivate user
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from flask import Blueprint, g, request

from apps.backend import db_rbac
from apps.backend.auth.passwords import hash_password
from apps.backend.db import db_conn
from apps.flask_api import auth_middleware
from apps.flask_api.audit import AuditEvent, append_audit_event
from apps.flask_api.auth_middleware import require_permission
from apps.flask_api.utils import (
    _coerce_optional_text,
    _err,
    _ok,
    _parse_bool,
    _parse_int,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)
from services.rbac_service import AuthContext

users_bp = Blueprint("users", __name__)
# CRUD endpoint patterns intentionally mirror related RBAC blueprints.
# pylint: disable=duplicate-code


def _public_user(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return public user payload without password hashes."""
    if row is None:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "workspace": row.get("workspace"),
        "user_id": row.get("user_id"),
        "email": row.get("email"),
        "full_name": row.get("full_name"),
        "external_id": row.get("external_id"),
        "auth_provider": row.get("auth_provider"),
        "is_active": bool(row.get("is_active")),
        "is_superadmin": bool(row.get("is_superadmin")),
        "last_login_at": row.get("last_login_at"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "role_id": row.get("role_id"),
        "role_name": row.get("role_name"),
    }


def _public_role(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return public role payload with deterministic permissions list."""
    if row is None:
        return None
    permissions_raw = row.get("permissions")
    permissions = (
        [str(item) for item in permissions_raw]
        if isinstance(permissions_raw, Sequence)
        and not isinstance(permissions_raw, (str, bytes, bytearray))
        else []
    )
    return {
        "tenant_id": row.get("tenant_id"),
        "workspace": row.get("workspace"),
        "role_id": row.get("role_id"),
        "name": row.get("name"),
        "description": row.get("description"),
        "is_system": bool(row.get("is_system")),
        "permissions": permissions,
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def _password_hash_from_payload(payload: dict[str, Any], *, allow_missing: bool) -> str | None:
    """Resolve password hash from payload data.

    Args:
        payload: Request payload.
        allow_missing: When true, missing password key returns None.
    """
    if "password" not in payload:
        if allow_missing:
            return None
        raise ValueError("password is required")
    password_raw = payload.get("password")
    if password_raw is None:
        return None
    password_text = str(password_raw)
    if not password_text:
        raise ValueError("password must not be empty when provided")
    return hash_password(password_text)


def _user_upsert_from_create_payload(
    *,
    payload: dict[str, Any],
    tenant_id: str,
    workspace: str,
) -> db_rbac.UserUpsert:
    """Build validated user upsert payload from create request JSON."""
    user_id = _coerce_optional_text(payload.get("user_id"))
    email = _coerce_optional_text(payload.get("email"))
    if not user_id:
        raise ValueError("user_id is required")
    if not email:
        raise ValueError("email is required")
    return db_rbac.UserUpsert(
        tenant_id=tenant_id,
        workspace=workspace,
        user_id=user_id,
        email=email,
        password_hash=_password_hash_from_payload(payload, allow_missing=True),
        full_name=_coerce_optional_text(payload.get("full_name")),
        external_id=_coerce_optional_text(payload.get("external_id")),
        auth_provider=_coerce_optional_text(payload.get("auth_provider")) or "local",
        is_active=_parse_bool(payload.get("is_active"), field_name="is_active", default=True),
        is_superadmin=_parse_bool(
            payload.get("is_superadmin"),
            field_name="is_superadmin",
            default=False,
        ),
    )


def _user_upsert_from_update_payload(
    *,
    payload: dict[str, Any],
    tenant_id: str,
    workspace: str,
    user_id: str,
    existing: dict[str, Any],
) -> db_rbac.UserUpsert:
    """Build merged user upsert payload from update request JSON."""
    email = _coerce_optional_text(payload.get("email")) or str(existing.get("email") or "")
    if not email:
        raise ValueError("email is required")

    password_hash: str | None
    if "password" in payload:
        password_hash = _password_hash_from_payload(payload, allow_missing=True)
    else:
        current_hash = existing.get("password_hash")
        password_hash = str(current_hash) if current_hash is not None else None

    full_name = (
        _coerce_optional_text(payload.get("full_name"))
        if "full_name" in payload
        else existing.get("full_name")
    )
    external_id = (
        _coerce_optional_text(payload.get("external_id"))
        if "external_id" in payload
        else existing.get("external_id")
    )
    auth_provider = (
        _coerce_optional_text(payload.get("auth_provider"))
        if "auth_provider" in payload
        else str(existing.get("auth_provider") or "local")
    ) or "local"
    is_active = (
        _parse_bool(payload.get("is_active"), field_name="is_active", default=True)
        if "is_active" in payload
        else bool(existing.get("is_active"))
    )
    is_superadmin = (
        _parse_bool(payload.get("is_superadmin"), field_name="is_superadmin", default=False)
        if "is_superadmin" in payload
        else bool(existing.get("is_superadmin"))
    )
    return db_rbac.UserUpsert(
        tenant_id=tenant_id,
        workspace=workspace,
        user_id=user_id,
        email=email,
        password_hash=password_hash,
        full_name=str(full_name) if full_name is not None else None,
        external_id=str(external_id) if external_id is not None else None,
        auth_provider=auth_provider,
        is_active=is_active,
        is_superadmin=is_superadmin,
    )


def _optional_workspace_list(payload: dict[str, Any]) -> list[str] | None:
    """Normalize optional tenant fan-out workspace list from request payload.

    Args:
        payload: Request payload.

    Returns:
        Ordered de-duplicated workspace list, or None when not provided.

    Raises:
        ValueError: If workspaces field has an invalid shape or empty values.
    """
    raw = payload.get("workspaces")
    if raw is None:
        return None
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        raise ValueError("workspaces must be a non-empty array of workspace names")

    seen: set[str] = set()
    items: list[str] = []
    for value in raw:
        text = _coerce_optional_text(value)
        if not text:
            raise ValueError("workspaces must not contain empty values")
        if text in seen:
            continue
        seen.add(text)
        items.append(text)
    if not items:
        raise ValueError("workspaces must be a non-empty array of workspace names")
    return items


@dataclass(frozen=True)
class _TenantRoleAssignmentRequest:
    """Input payload for tenant-wide workspace role assignment fan-out."""

    tenant_id: str
    user_id: str
    role_id: str
    granted_by: str | None


def _tenant_role_request_from_payload(
    *,
    payload: dict[str, Any],
    user_id: str,
) -> tuple[str, str, list[str] | None, _TenantRoleAssignmentRequest]:
    """Build normalized tenant fan-out role assignment request."""
    tenant_id, workspace = _require_scope_from_json(payload)
    uid = _coerce_optional_text(user_id)
    if not uid:
        raise ValueError("user_id is required")
    role_id = _coerce_optional_text(payload.get("role_id"))
    if not role_id:
        raise ValueError("role_id is required")
    granted_by = _coerce_optional_text(payload.get("granted_by"))
    workspaces = _optional_workspace_list(payload)
    return (
        tenant_id,
        workspace,
        workspaces,
        _TenantRoleAssignmentRequest(
            tenant_id=tenant_id,
            user_id=uid,
            role_id=role_id,
            granted_by=granted_by,
        ),
    )


def _correlation_id() -> str | None:
    """Return request correlation id when present."""
    value = str(
        request.headers.get("X-Correlation-Id")
        or request.headers.get("X-Request-Id")
        or ""
    ).strip()
    return value or None


def _resolved_auth_context() -> AuthContext | None:
    """Return authenticated RBAC context for current request."""
    auth_context = getattr(g, "auth_context", None)
    if isinstance(auth_context, AuthContext):
        return auth_context
    candidate = auth_middleware.authenticate_request()
    return candidate if isinstance(candidate, AuthContext) else None


def _assign_workspace_role_for_tenant_scope(
    conn: Any,
    *,
    workspace: str,
        assignment_request: _TenantRoleAssignmentRequest,
        role_permissions_cache: dict[str, list[str]],
) -> tuple[dict[str, Any], bool]:
    """Assign one role for one workspace and return item payload + applied flag.

    Args:
        conn: Open database connection.
        workspace: Target workspace.
        assignment_request: Tenant-wide assignment payload.
        role_permissions_cache: Per-workspace permissions cache.

    Returns:
        Tuple of `(item, applied)` where `applied=True` means role assignment
        was created/updated for the workspace.
    """
    user = db_rbac.get_user_by_id(
        conn,
        tenant_id=assignment_request.tenant_id,
        workspace=workspace,
        user_id=assignment_request.user_id,
    )
    if user is None:
        return {
            "workspace": workspace,
            "status": "skipped",
            "reason": "user_not_found",
        }, False

    role = db_rbac.get_role_by_id(
        conn,
        tenant_id=assignment_request.tenant_id,
        workspace=workspace,
        role_id=assignment_request.role_id,
    )
    if role is None:
        return {
            "workspace": workspace,
            "status": "skipped",
            "reason": "role_not_found",
        }, False

    assignment = db_rbac.upsert_user_workspace_role(
        conn,
        assignment=db_rbac.UserWorkspaceRoleUpsert(
            tenant_id=assignment_request.tenant_id,
            workspace=workspace,
            user_id=assignment_request.user_id,
            role_id=assignment_request.role_id,
            granted_by=assignment_request.granted_by,
        ),
    )
    if workspace not in role_permissions_cache:
        role_permissions_cache[workspace] = db_rbac.get_role_permissions(
            conn,
            tenant_id=assignment_request.tenant_id,
            workspace=workspace,
            role_id=assignment_request.role_id,
        )
    return {
        "workspace": workspace,
        "status": "assigned",
        "role": {
            "role_id": assignment_request.role_id,
            "name": role.get("name"),
            "description": role.get("description"),
            "is_system": bool(role.get("is_system")),
            "granted_by": (assignment or {}).get("granted_by"),
            "granted_at": (assignment or {}).get("granted_at"),
            "permissions": role_permissions_cache[workspace],
        },
    }, True


def _apply_tenant_role_fanout(
    conn: Any,
    *,
    workspaces: list[str],
    assignment_request: _TenantRoleAssignmentRequest,
) -> tuple[list[dict[str, Any]], int]:
    """Apply tenant role assignment across workspaces and return summary tuple."""
    items: list[dict[str, Any]] = []
    assigned_count = 0
    role_permissions_cache: dict[str, list[str]] = {}
    for target_workspace in workspaces:
        item, applied = _assign_workspace_role_for_tenant_scope(
            conn,
            workspace=target_workspace,
            assignment_request=assignment_request,
            role_permissions_cache=role_permissions_cache,
        )
        items.append(item)
        if applied:
            assigned_count += 1
    return items, assigned_count


def _workspace_outcomes(items: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Return assigned/skipped workspace identifiers from fan-out results."""
    assigned = [
        str(item.get("workspace"))
        for item in items
        if item.get("status") == "assigned" and item.get("workspace")
    ]
    skipped = [
        str(item.get("workspace"))
        for item in items
        if item.get("status") == "skipped" and item.get("workspace")
    ]
    return assigned, skipped


@users_bp.route("/api/users", methods=["GET"])
@require_permission("users:read")
def api_users_list() -> Any:
    """List users in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        query_text = _coerce_optional_text(_q("q"))
        include_inactive = _parse_bool(
            _q("include_inactive"),
            field_name="include_inactive",
            default=False,
        )

        with db_conn() as conn:
            rows, total = db_rbac.list_users_page(
                conn,
                query=db_rbac.UserListQuery(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    limit=limit,
                    offset=offset,
                    query=query_text,
                    include_inactive=include_inactive,
                ),
            )
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": total,
                "items": [_public_user(row) for row in rows],
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>/role/tenant", methods=["PUT"])
@require_permission("users:manage_roles")
def api_users_set_tenant_role(user_id: str) -> Any:
    """Assign one role to a user across existing tenant workspaces."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace, workspaces, assignment_request = _tenant_role_request_from_payload(
            payload=payload,
            user_id=user_id,
        )

        auth_context = _resolved_auth_context()
        if not isinstance(auth_context, AuthContext):
            return _err("unauthorized", "authentication required", status=401)
        if not auth_context.is_superadmin and "admin:full" not in auth_context.permissions:
            return _err(
                "forbidden",
                "tenant-wide role assignment requires admin:full",
                status=403,
            )

        with db_conn() as conn:
            if workspaces is None:
                workspaces = db_rbac.list_tenant_workspaces(
                    conn,
                    tenant_id=tenant_id,
                    anchor_workspace=workspace,
                )
            if not workspaces:
                return _err("not_found", "no workspaces found for tenant scope", status=404)

            items, assigned_count = _apply_tenant_role_fanout(
                conn,
                workspaces=workspaces,
                assignment_request=assignment_request,
            )
            assigned_workspaces, skipped_workspaces = _workspace_outcomes(items)
            append_audit_event(
                conn,
                event=AuditEvent(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    entity_type="user_role_assignment",
                    entity_id=assignment_request.user_id,
                    event_type="users.role.assigned_tenant",
                    event_category="rbac",
                    previous_value=None,
                    new_value={
                        "mode": "tenant_existing_workspaces",
                        "role_id": assignment_request.role_id,
                        "targeted": len(workspaces),
                        "assigned": assigned_count,
                        "skipped": len(workspaces) - assigned_count,
                        "assigned_workspaces": assigned_workspaces,
                        "skipped_workspaces": skipped_workspaces,
                    },
                    actor_id=auth_context.user_id,
                    actor_email=auth_context.email,
                    actor_name=auth_context.full_name,
                    source="/api/users/<user_id>/role/tenant",
                    correlation_id=_correlation_id(),
                ),
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "user_id": assignment_request.user_id,
                "role_id": assignment_request.role_id,
                "mode": "tenant_existing_workspaces",
                "anchor_workspace": workspace,
                "target_workspaces": workspaces,
                "summary": {
                    "targeted": len(workspaces),
                    "assigned": assigned_count,
                    "skipped": len(workspaces) - assigned_count,
                },
                "items": items,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users", methods=["POST"])
@require_permission("users:create")
def api_users_create() -> Any:
    """Create a user in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        user_upsert = _user_upsert_from_create_payload(
            payload=payload,
            tenant_id=tenant_id,
            workspace=workspace,
        )

        with db_conn() as conn:
            row = db_rbac.create_user(
                conn,
                user=user_upsert,
            )
            conn.commit()
        return _ok({"user": _public_user(row)}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/roles", methods=["GET"])
@require_permission("users:manage_roles")
def api_users_roles_catalog() -> Any:
    """List available scoped roles for role assignment UI."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            rows = db_rbac.list_roles(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
            )
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "total": len(rows),
                "items": [_public_role(row) for row in rows],
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>", methods=["GET"])
@require_permission("users:read")
def api_users_get(user_id: str) -> Any:
    """Get one scoped user."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        uid = _coerce_optional_text(user_id)
        if not uid:
            raise ValueError("user_id is required")
        with db_conn() as conn:
            row = db_rbac.get_user_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
            )
        if row is None:
            return _err("not_found", "user not found", status=404)
        return _ok({"user": _public_user(row)})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>", methods=["PUT"])
@require_permission("users:update")
def api_users_update(user_id: str) -> Any:
    """Update one scoped user via idempotent upsert semantics."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        uid = _coerce_optional_text(user_id)
        if not uid:
            raise ValueError("user_id is required")

        with db_conn() as conn:
            existing = db_rbac.get_user_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
            )
            if existing is None:
                return _err("not_found", "user not found", status=404)
            user_upsert = _user_upsert_from_update_payload(
                payload=payload,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
                existing=existing,
            )
            row = db_rbac.create_user(
                conn,
                user=user_upsert,
            )
            conn.commit()
        return _ok({"user": _public_user(row)})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>", methods=["DELETE"])
@require_permission("users:delete")
def api_users_delete(user_id: str) -> Any:
    """Deactivate one scoped user."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        uid = _coerce_optional_text(user_id)
        if not uid:
            raise ValueError("user_id is required")
        with db_conn() as conn:
            changed = db_rbac.set_user_active(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
                is_active=False,
            )
            conn.commit()
        if not changed:
            return _err("not_found", "user not found", status=404)
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "user_id": uid,
                "deactivated": True,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>/role", methods=["GET"])
@require_permission("users:manage_roles")
def api_users_get_role(user_id: str) -> Any:
    """Return one scoped user's workspace role assignment."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        uid = _coerce_optional_text(user_id)
        if not uid:
            raise ValueError("user_id is required")

        with db_conn() as conn:
            user = db_rbac.get_user_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
            )
            if user is None:
                return _err("not_found", "user not found", status=404)

            assignment = db_rbac.get_user_workspace_role(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
            )
            if assignment is None:
                return _ok(
                    {
                        "tenant_id": tenant_id,
                        "workspace": workspace,
                        "user_id": uid,
                        "role": None,
                    }
                )

            role_id = str(assignment.get("role_id") or "")
            role = db_rbac.get_role_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                role_id=role_id,
            )
            permissions = db_rbac.get_role_permissions(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                role_id=role_id,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "user_id": uid,
                "role": {
                    "role_id": role_id,
                    "name": (role or {}).get("name"),
                    "description": (role or {}).get("description"),
                    "is_system": bool((role or {}).get("is_system")),
                    "granted_by": assignment.get("granted_by"),
                    "granted_at": assignment.get("granted_at"),
                    "permissions": permissions,
                },
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@users_bp.route("/api/users/<user_id>/role", methods=["PUT"])
@require_permission("users:manage_roles")
def api_users_set_role(user_id: str) -> Any:
    """Assign one workspace role to a user in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        uid = _coerce_optional_text(user_id)
        if not uid:
            raise ValueError("user_id is required")

        role_id = _coerce_optional_text(payload.get("role_id"))
        if not role_id:
            raise ValueError("role_id is required")
        granted_by = _coerce_optional_text(payload.get("granted_by"))
        auth_context = _resolved_auth_context()
        if not isinstance(auth_context, AuthContext):
            return _err("unauthorized", "authentication required", status=401)

        with db_conn() as conn:
            user = db_rbac.get_user_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=uid,
            )
            if user is None:
                return _err("not_found", "user not found", status=404)

            role = db_rbac.get_role_by_id(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                role_id=role_id,
            )
            if role is None:
                return _err("not_found", "role not found", status=404)

            assignment = db_rbac.upsert_user_workspace_role(
                conn,
                assignment=db_rbac.UserWorkspaceRoleUpsert(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    user_id=uid,
                    role_id=role_id,
                    granted_by=granted_by,
                ),
            )
            permissions = db_rbac.get_role_permissions(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                role_id=role_id,
            )
            append_audit_event(
                conn,
                event=AuditEvent(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    entity_type="user_role_assignment",
                    entity_id=uid,
                    event_type="users.role.assigned",
                    event_category="rbac",
                    previous_value=None,
                    new_value={
                        "role_id": role_id,
                        "granted_by": (assignment or {}).get("granted_by"),
                    },
                    actor_id=auth_context.user_id,
                    actor_email=auth_context.email,
                    actor_name=auth_context.full_name,
                    source="/api/users/<user_id>/role",
                    correlation_id=_correlation_id(),
                ),
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "user_id": uid,
                "role": {
                    "role_id": role_id,
                    "name": role.get("name"),
                    "description": role.get("description"),
                    "is_system": bool(role.get("is_system")),
                    "granted_by": (assignment or {}).get("granted_by"),
                    "granted_at": (assignment or {}).get("granted_at"),
                    "permissions": permissions,
                },
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
