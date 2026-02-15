"""Remediations Blueprint.

Provides remediation action endpoints:
- list actions
- approve action
- reject action
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from flask import Blueprint, request

from apps.backend.db import db_conn, execute_conn, fetch_all_dict_conn, fetch_one_dict_conn
from apps.flask_api.utils import (
    _err,
    _ok,
    _parse_csv_list,
    _parse_int,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)

if TYPE_CHECKING:
    from psycopg2 import Error as PsycopgError  # type: ignore
else:
    try:
        from psycopg2 import Error as _PsycopgError  # type: ignore
    except ImportError:  # pragma: no cover
        class _PsycopgError(Exception):
            """Fallback psycopg error type when psycopg2 import is unavailable."""

    PsycopgError = _PsycopgError


remediations_bp = Blueprint("remediations", __name__)

_PENDING_APPROVAL = "pending_approval"
_APPROVED = "approved"
_REJECTED = "rejected"


def _utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _normalize_action_payload(value: Any) -> dict[str, Any]:
    """Normalize JSON payload to a dictionary."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _serialize_action(row: dict[str, Any]) -> dict[str, Any]:
    """Convert DB row to stable API payload."""
    return {
        "action_id": row.get("action_id"),
        "fingerprint": row.get("fingerprint"),
        "check_id": row.get("check_id"),
        "action_type": row.get("action_type"),
        "status": row.get("status"),
        "dry_run": bool(row.get("dry_run")),
        "reason": row.get("reason"),
        "requested_by": row.get("requested_by"),
        "approved_by": row.get("approved_by"),
        "rejected_by": row.get("rejected_by"),
        "requested_at": row.get("requested_at"),
        "approved_at": row.get("approved_at"),
        "rejected_at": row.get("rejected_at"),
        "updated_at": row.get("updated_at"),
        "version": int(row.get("version") or 0),
        "action_payload": _normalize_action_payload(row.get("action_payload")),
    }


def _audit_log_event(
    conn: Any,
    *,
    event: dict[str, Any],
    actor_id: str | None,
) -> None:
    """Best-effort write to audit_log for remediation lifecycle events."""
    tenant_id = str(event.get("tenant_id") or "")
    workspace = str(event.get("workspace") or "")
    action_id = str(event.get("action_id") or "")
    event_type = str(event.get("event_type") or "")
    previous_value = event.get("previous_value")
    new_value = event.get("new_value")

    try:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
    except RuntimeError:
        ip_address = None
        user_agent = ""

    params = (
        tenant_id,
        workspace,
        "remediation_action",
        action_id,
        None,
        event_type,
        "remediation",
        json.dumps(previous_value, separators=(",", ":")) if previous_value is not None else None,
        json.dumps(new_value, separators=(",", ":")) if new_value is not None else None,
        actor_id,
        actor_id,
        None,
        "api",
        ip_address,
        user_agent,
        None,
        None,
    )

    try:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT remediation_audit_1")
            cur.execute(
                """
                INSERT INTO audit_log
                  (tenant_id, workspace, entity_type, entity_id, fingerprint,
                   event_type, event_category, previous_value, new_value,
                   actor_id, actor_email, actor_name, source, ip_address, user_agent,
                   run_id, correlation_id, created_at)
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,now())
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT remediation_audit_1")
            return
    except (PsycopgError, RuntimeError, TypeError, ValueError, AttributeError):
        try:
            with conn.cursor() as cur:
                cur.execute("ROLLBACK TO SAVEPOINT remediation_audit_1")
        except (PsycopgError, RuntimeError, TypeError, ValueError, AttributeError):
            pass


def _where_clause(
    tenant_id: str,
    workspace: str,
    filters: dict[str, list[str] | None],
) -> tuple[list[str], list[Any]]:
    """Build list endpoint WHERE clauses and bind params."""
    where = ["ra.tenant_id = %s", "ra.workspace = %s"]
    params: list[Any] = [tenant_id, workspace]

    def _add_any(column: str, values: list[str] | None) -> None:
        if not values:
            return
        where.append(f"ra.{column} = ANY(%s)")
        params.append(values)

    _add_any("status", filters.get("status"))
    _add_any("action_type", filters.get("action_type"))
    _add_any("check_id", filters.get("check_id"))
    _add_any("fingerprint", filters.get("fingerprint"))
    return where, params


def _fetch_action_for_update(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action_id: str,
) -> dict[str, Any] | None:
    """Fetch one remediation action row with row lock."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id, workspace, action_id, fingerprint, check_id, action_type,
          status, action_payload, dry_run, reason,
          requested_by, approved_by, rejected_by,
          requested_at, approved_at, rejected_at, updated_at, version
        FROM remediation_actions
        WHERE tenant_id = %s AND workspace = %s AND action_id = %s
        FOR UPDATE
        """,
        (tenant_id, workspace, action_id),
    )


def _fetch_action(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action_id: str,
) -> dict[str, Any] | None:
    """Fetch one remediation action row without locking."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id, workspace, action_id, fingerprint, check_id, action_type,
          status, action_payload, dry_run, reason,
          requested_by, approved_by, rejected_by,
          requested_at, approved_at, rejected_at, updated_at, version
        FROM remediation_actions
        WHERE tenant_id = %s AND workspace = %s AND action_id = %s
        """,
        (tenant_id, workspace, action_id),
    )


def _require_action_id(payload: dict[str, Any]) -> str:
    """Extract required action_id from request JSON."""
    action_id = str(payload.get("action_id") or "").strip()
    if not action_id:
        raise ValueError("action_id is required")
    return action_id


def _require_actor(payload: dict[str, Any], *, field_name: str) -> str:
    """Extract required actor identity from request JSON."""
    actor = str(payload.get(field_name) or "").strip()
    if not actor:
        raise ValueError(f"{field_name} is required")
    return actor


def _list_filters_from_query() -> dict[str, list[str] | None]:
    """Build list filters from query params."""
    return {
        "status": _parse_csv_list(_q("status")),
        "action_type": _parse_csv_list(_q("action_type")),
        "check_id": _parse_csv_list(_q("check_id")),
        "fingerprint": _parse_csv_list(_q("fingerprint")),
    }


def _query_actions(
    *,
    tenant_id: str,
    workspace: str,
    filters: dict[str, list[str] | None],
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    """Query action rows with count for paginated list endpoint."""
    where, params = _where_clause(tenant_id, workspace, filters)

    sql = f"""
        SELECT
          ra.tenant_id, ra.workspace, ra.action_id, ra.fingerprint,
          ra.check_id, ra.action_type, ra.status,
          ra.action_payload, ra.dry_run, ra.reason,
          ra.requested_by, ra.approved_by, ra.rejected_by,
          ra.requested_at, ra.approved_at, ra.rejected_at, ra.updated_at, ra.version
        FROM remediation_actions ra
        WHERE {' AND '.join(where)}
        ORDER BY ra.requested_at DESC, ra.action_id
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT COUNT(*) AS n FROM remediation_actions ra WHERE {' AND '.join(where)}"
    params_page = params + [limit, offset]

    with db_conn() as conn:
        rows = fetch_all_dict_conn(conn, sql, params_page)
        count_row = fetch_one_dict_conn(conn, count_sql, params)
    return rows, int((count_row or {}).get("n") or 0)


@remediations_bp.route("/api/remediations", methods=["GET"])
def api_remediations_list() -> Any:
    """List remediation actions for a scoped tenant/workspace."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        rows, total = _query_actions(
            tenant_id=tenant_id,
            workspace=workspace,
            filters=_list_filters_from_query(),
            limit=limit,
            offset=offset,
        )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": total,
                "items": [_serialize_action(row) for row in rows],
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@remediations_bp.route("/api/remediations/approve", methods=["POST"])
def api_remediations_approve() -> Any:
    """Approve one remediation action currently pending approval."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        action_id = _require_action_id(payload)
        approved_by = _require_actor(payload, field_name="approved_by")
        reason_raw = payload.get("reason")
        reason = str(reason_raw).strip() if reason_raw is not None else None

        with db_conn() as conn:
            row = _fetch_action_for_update(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action_id=action_id,
            )
            if row is None:
                return _err("not_found", "remediation action not found", status=404)
            if str(row.get("status") or "") != _PENDING_APPROVAL:
                return _err(
                    "invalid_state",
                    f"action must be in '{_PENDING_APPROVAL}' state",
                    status=409,
                )

            execute_conn(
                conn,
                """
                UPDATE remediation_actions
                SET
                  status = %s,
                  approved_by = %s,
                  approved_at = %s,
                  reason = COALESCE(%s, reason),
                  updated_at = %s,
                  version = version + 1
                WHERE tenant_id = %s AND workspace = %s AND action_id = %s
                """,
                (
                    _APPROVED,
                    approved_by,
                    _utc_now(),
                    reason,
                    _utc_now(),
                    tenant_id,
                    workspace,
                    action_id,
                ),
            )
            updated = _fetch_action(
                conn, tenant_id=tenant_id, workspace=workspace, action_id=action_id
            )
            _audit_log_event(
                conn,
                event={
                    "tenant_id": tenant_id,
                    "workspace": workspace,
                    "action_id": action_id,
                    "event_type": "remediation.approved",
                    "previous_value": _serialize_action(row),
                    "new_value": _serialize_action(updated) if updated is not None else None,
                },
                actor_id=approved_by,
            )
            conn.commit()

        return _ok({"action": _serialize_action(updated) if updated is not None else None})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@remediations_bp.route("/api/remediations/reject", methods=["POST"])
def api_remediations_reject() -> Any:
    """Reject one remediation action currently pending approval."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        action_id = _require_action_id(payload)
        rejected_by = _require_actor(payload, field_name="rejected_by")
        reason_raw = payload.get("reason")
        reason = str(reason_raw).strip() if reason_raw is not None else None

        with db_conn() as conn:
            row = _fetch_action_for_update(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action_id=action_id,
            )
            if row is None:
                return _err("not_found", "remediation action not found", status=404)
            if str(row.get("status") or "") != _PENDING_APPROVAL:
                return _err(
                    "invalid_state",
                    f"action must be in '{_PENDING_APPROVAL}' state",
                    status=409,
                )

            execute_conn(
                conn,
                """
                UPDATE remediation_actions
                SET
                  status = %s,
                  rejected_by = %s,
                  rejected_at = %s,
                  reason = COALESCE(%s, reason),
                  updated_at = %s,
                  version = version + 1
                WHERE tenant_id = %s AND workspace = %s AND action_id = %s
                """,
                (
                    _REJECTED,
                    rejected_by,
                    _utc_now(),
                    reason,
                    _utc_now(),
                    tenant_id,
                    workspace,
                    action_id,
                ),
            )
            updated = _fetch_action(
                conn, tenant_id=tenant_id, workspace=workspace, action_id=action_id
            )
            _audit_log_event(
                conn,
                event={
                    "tenant_id": tenant_id,
                    "workspace": workspace,
                    "action_id": action_id,
                    "event_type": "remediation.rejected",
                    "previous_value": _serialize_action(row),
                    "new_value": _serialize_action(updated) if updated is not None else None,
                },
                actor_id=rejected_by,
            )
            conn.commit()

        return _ok({"action": _serialize_action(updated) if updated is not None else None})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
