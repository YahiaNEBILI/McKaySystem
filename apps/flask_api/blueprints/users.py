"""Users Blueprint.

Provides RBAC-managed user endpoints:
- list users
- create user
- get user
- update user
- deactivate user
"""

from __future__ import annotations

from typing import Any

from flask import Blueprint, request

from apps.backend import db_rbac
from apps.backend.auth.passwords import hash_password
from apps.backend.db import db_conn
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
