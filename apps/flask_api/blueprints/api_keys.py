"""API Keys Blueprint.

Provides RBAC-managed API key endpoints:
- list keys
- create key
- revoke key
"""

from __future__ import annotations

from typing import Any

from flask import Blueprint, request

from apps.backend import db_rbac
from apps.backend.auth.tokens import derive_key_id, generate_api_key, hash_api_key
from apps.backend.db import db_conn
from apps.flask_api.auth_middleware import require_permission
from apps.flask_api.utils import (
    _coerce_optional_text,
    _err,
    _ok,
    _parse_bool,
    _parse_iso8601_dt,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)

api_keys_bp = Blueprint("api_keys", __name__)
# CRUD endpoint patterns intentionally mirror related RBAC blueprints.
# pylint: disable=duplicate-code


def _public_key(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return API key payload excluding stored key hash."""
    if row is None:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "workspace": row.get("workspace"),
        "key_id": row.get("key_id"),
        "key_type": row.get("key_type"),
        "name": row.get("name"),
        "description": row.get("description"),
        "user_id": row.get("user_id"),
        "last_used_at": row.get("last_used_at"),
        "expires_at": row.get("expires_at"),
        "is_active": bool(row.get("is_active")),
        "created_at": row.get("created_at"),
    }


@api_keys_bp.route("/api/api-keys", methods=["GET"])
@require_permission("api_keys:read")
def api_keys_list() -> Any:
    """List scoped API keys."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        user_id = _coerce_optional_text(_q("user_id"))
        include_inactive = _parse_bool(
            _q("include_inactive"),
            field_name="include_inactive",
            default=False,
        )
        with db_conn() as conn:
            rows = db_rbac.list_api_keys(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                user_id=user_id,
                include_inactive=include_inactive,
            )
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "items": [_public_key(row) for row in rows],
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@api_keys_bp.route("/api/api-keys", methods=["POST"])
@require_permission("api_keys:create")
def api_keys_create() -> Any:
    """Create one scoped API key and return plaintext token once."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        name = _coerce_optional_text(payload.get("name"))
        if not name:
            raise ValueError("name is required")
        description = _coerce_optional_text(payload.get("description"))
        user_id = _coerce_optional_text(payload.get("user_id"))
        raw_key = generate_api_key(prefix="mck")
        key_hash = hash_api_key(raw_key)
        key_id = derive_key_id(key_hash)
        expires_at = _parse_iso8601_dt(payload.get("expires_at"), field_name="expires_at")

        with db_conn() as conn:
            row = db_rbac.create_api_key(
                conn,
                api_key=db_rbac.ApiKeyUpsert(
                    tenant_id=tenant_id,
                    workspace=workspace,
                    key_id=key_id,
                    key_hash=key_hash,
                    key_type="secret",
                    name=name,
                    description=description,
                    user_id=user_id,
                    expires_at=expires_at,
                ),
            )
            conn.commit()
        return _ok({"api_key": raw_key, "key": _public_key(row)}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@api_keys_bp.route("/api/api-keys/<key_id>", methods=["DELETE"])
@require_permission("api_keys:revoke")
def api_keys_revoke(key_id: str) -> Any:
    """Revoke one scoped API key."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        kid = _coerce_optional_text(key_id)
        if not kid:
            raise ValueError("key_id is required")
        with db_conn() as conn:
            changed = db_rbac.revoke_api_key(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                key_id=kid,
            )
            conn.commit()
        if not changed:
            return _err("not_found", "api key not found", status=404)
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "key_id": kid,
                "revoked": True,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
