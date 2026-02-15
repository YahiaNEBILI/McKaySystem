"""SLA Policies Blueprint.

Provides endpoints for managing SLA policies and overrides.
"""

import json
from typing import Any, Dict, List, Optional

from flask import Blueprint, request

from apps.backend.db import db_conn, fetch_one_dict_conn, fetch_all_dict_conn, execute_conn
from apps.flask_api.utils import (
    _ok,
    _err,
    _q,
    _require_scope_from_query,
    _require_scope_from_json,
    _parse_int,
    _parse_csv_list,
    _coerce_optional_text,
    _coerce_positive_int,
    _MISSING,
    _payload_optional_text,
)


# Create the blueprint
sla_policies_bp = Blueprint("sla_policies", __name__)


# --------------------
# Helper functions
# --------------------


def _fetch_sla_policy_category(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    category: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one category SLA policy row by scope + category."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          category,
          sla_days,
          description,
          created_at,
          updated_at
        FROM sla_policy_category
        WHERE tenant_id = %s AND workspace = %s AND category = %s
        """,
        (tenant_id, workspace, category),
    )


def _fetch_sla_policy_override(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    check_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one check SLA override row by scope + check_id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          check_id,
          sla_days,
          reason,
          created_at,
          updated_at
        FROM sla_policy_check_override
        WHERE tenant_id = %s AND workspace = %s AND check_id = %s
        """,
        (tenant_id, workspace, check_id),
    )


def _audit_log_event(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    entity_type: str,
    entity_id: str,
    fingerprint: Optional[str],
    event_type: str,
    event_category: str,
    previous_value: Optional[Dict[str, Any]],
    new_value: Optional[Dict[str, Any]],
    actor_id: Optional[str],
    actor_email: Optional[str],
    actor_name: Optional[str],
    source: str,
    run_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    """Best-effort append-only write to audit_log, isolated by savepoint."""
    try:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
    except RuntimeError:
        ip_address = None
        user_agent = ""

    params = (
        tenant_id,
        workspace,
        entity_type,
        entity_id,
        fingerprint,
        event_type,
        event_category,
        (json.dumps(previous_value, separators=(",", ":")) if previous_value is not None else None),
        (json.dumps(new_value, separators=(",", ":")) if new_value is not None else None),
        actor_id,
        actor_email,
        actor_name,
        source,
        ip_address,
        user_agent,
        run_id,
        correlation_id,
    )

    with conn.cursor() as cur:
        try:
            cur.execute("SAVEPOINT mckay_audit_log_1")
            cur.execute(
                """
                INSERT INTO audit_log
                  (tenant_id, workspace, entity_type, entity_id, fingerprint,
                   event_type, event_category, previous_value, new_value,
                   actor_id, actor_email, actor_name, source,
                   ip_address, user_agent, run_id, correlation_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT mckay_audit_log_1")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT mckay_audit_log_1")


# --------------------
# SLA Policy Category endpoints
# --------------------


@sla_policies_bp.route("/api/sla/policies", methods=["GET"])
def api_sla_policies() -> Any:
    """List category SLA policies in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 200)
        offset: Results offset (default 0)

    Returns:
        Paginated list of SLA policies
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                """
                SELECT
                  tenant_id,
                  workspace,
                  category,
                  sla_days,
                  description,
                  created_at,
                  updated_at
                FROM sla_policy_category
                WHERE tenant_id = %s AND workspace = %s
                ORDER BY category ASC
                LIMIT %s OFFSET %s
                """,
                (tenant_id, workspace, limit, offset),
            )
            count_row = fetch_one_dict_conn(
                conn,
                """
                SELECT COUNT(*)::bigint AS n
                FROM sla_policy_category
                WHERE tenant_id = %s AND workspace = %s
                """,
                (tenant_id, workspace),
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@sla_policies_bp.route("/api/sla/policies", methods=["POST"])
def api_create_sla_policy() -> Any:
    """Create a category SLA policy in tenant/workspace scope.

    JSON body:
        tenant_id, workspace, category (required): Policy scope and category
        sla_days (required): Number of days for SLA
        description: Optional description
        updated_by: Optional actor identifier

    Returns:
        Created policy object
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        category = _coerce_optional_text(payload.get("category"))
        sla_days = _coerce_positive_int(payload.get("sla_days"), field_name="sla_days")
        description_v = _payload_optional_text(payload, "description")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not category:
            raise ValueError("category is required")
        description = None if description_v is _MISSING else description_v

        with db_conn() as conn:
            if _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=category):
                return _err("conflict", f"sla policy already exists for category: {category}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO sla_policy_category
                  (tenant_id, workspace, category, sla_days, description, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, category, sla_days, description),
            )
            policy = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=category)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_category",
                entity_id=category,
                fingerprint=None,
                event_type="sla.policy.created",
                event_category="configuration",
                previous_value=None,
                new_value=policy,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "policy": policy}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@sla_policies_bp.route("/api/sla/policies/<category>", methods=["PUT"])
def api_update_sla_policy(category: str) -> Any:
    """Update one category SLA policy in tenant/workspace scope.

    JSON body:
        tenant_id, workspace (required): Policy scope
        sla_days: New SLA days (optional)
        description: New description (optional)
        updated_by: Optional actor identifier

    Returns:
        Updated policy object
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        cat = _coerce_optional_text(category)
        if not cat:
            raise ValueError("category is required")

        sla_days_raw = payload.get("sla_days")
        description_v = _payload_optional_text(payload, "description")
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        if sla_days_raw is None and description_v is _MISSING:
            raise ValueError("at least one of sla_days, description must be provided")

        with db_conn() as conn:
            before = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=cat)
            if before is None:
                return _err("not_found", "sla policy not found", status=404)

            sla_days = int(before.get("sla_days") or 0)
            if sla_days_raw is not None:
                sla_days = _coerce_positive_int(sla_days_raw, field_name="sla_days")
            description = before.get("description") if description_v is _MISSING else description_v

            execute_conn(
                conn,
                """
                UPDATE sla_policy_category
                SET
                  sla_days = %s,
                  description = %s,
                  updated_at = now()
                WHERE tenant_id = %s AND workspace = %s AND category = %s
                """,
                (sla_days, description, tenant_id, workspace, cat),
            )
            after = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=cat)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_category",
                entity_id=cat,
                fingerprint=None,
                event_type="sla.policy.updated",
                event_category="configuration",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "policy": after})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


# --------------------
# SLA Policy Override endpoints
# --------------------


@sla_policies_bp.route("/api/sla/policies/overrides", methods=["GET"])
def api_sla_overrides() -> Any:
    """List check-level SLA overrides in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 200)
        offset: Results offset (default 0)
        check_id: Filter by check_id

    Returns:
        Paginated list of SLA overrides
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        check_ids = _parse_csv_list(_q("check_id"))

        where = ["tenant_id = %s", "workspace = %s"]
        params: List[Any] = [tenant_id, workspace]
        if check_ids:
            where.append("check_id = ANY(%s)")
            params.append(check_ids)

        where_sql = " AND ".join(where)

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  tenant_id,
                  workspace,
                  check_id,
                  sla_days,
                  reason,
                  created_at,
                  updated_at
                FROM sla_policy_check_override
                WHERE {where_sql}
                ORDER BY check_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM sla_policy_check_override WHERE {where_sql}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@sla_policies_bp.route("/api/sla/policies/overrides", methods=["POST"])
def api_create_sla_override() -> Any:
    """Create a check-level SLA override in tenant/workspace scope.

    JSON body:
        tenant_id, workspace, check_id (required): Override scope and check_id
        sla_days (required): Number of days for SLA override
        reason: Optional reason for override
        updated_by: Optional actor identifier

    Returns:
        Created override object
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        check_id = _coerce_optional_text(payload.get("check_id"))
        sla_days = _coerce_positive_int(payload.get("sla_days"), field_name="sla_days")
        reason_v = _payload_optional_text(payload, "reason")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not check_id:
            raise ValueError("check_id is required")
        reason = None if reason_v is _MISSING else reason_v

        with db_conn() as conn:
            if _fetch_sla_policy_override(conn, tenant_id=tenant_id, workspace=workspace, check_id=check_id):
                return _err("conflict", f"sla override already exists for check_id: {check_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO sla_policy_check_override
                  (tenant_id, workspace, check_id, sla_days, reason, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, check_id, sla_days, reason),
            )
            override = _fetch_sla_policy_override(conn, tenant_id=tenant_id, workspace=workspace, check_id=check_id)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_check_override",
                entity_id=check_id,
                fingerprint=None,
                event_type="sla.override.created",
                event_category="configuration",
                previous_value=None,
                new_value=override,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "override": override}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
