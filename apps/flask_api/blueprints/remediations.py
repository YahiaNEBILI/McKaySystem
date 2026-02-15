"""Remediations Blueprint.

Provides remediation action endpoints:
- request action
- list actions
- approve action
- reject action
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from flask import Blueprint, request

from apps.backend.db import db_conn, execute_conn, fetch_all_dict_conn, fetch_one_dict_conn
from apps.flask_api.blueprints import recommendations as recommendations_module
from apps.flask_api.utils import (
    _err,
    _ok,
    _parse_csv_list,
    _parse_int,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)
from services.remediation.impact import refresh_scope_action_impacts
from services.remediation.payload import normalize_action_payload

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
_TERMINAL_FINDING_STATES = {"resolved", "ignored"}


@dataclass(frozen=True)
class _RequestCreateInput:
    """Normalized input for remediation action creation."""

    tenant_id: str
    workspace: str
    fingerprint: str
    requested_by: str | None
    reason: str | None
    payload: dict[str, Any]


class _RequestError(ValueError):
    """Structured API error for remediation request endpoint."""

    def __init__(self, *, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _normalize_action_payload(value: Any) -> dict[str, Any]:
    """Normalize JSON payload to a dictionary."""
    return normalize_action_payload(value)


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


def _normalize_bool(value: Any, *, field_name: str, default: bool) -> bool:
    """Parse an optional boolean-like value from payload."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
    raise ValueError(f"{field_name} must be a boolean")


def _stable_action_id(
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    action_type: str,
    dry_run: bool,
) -> str:
    """Deterministically build an action_id."""
    seed = f"{tenant_id}|{workspace}|{fingerprint}|{action_type}|{int(dry_run)}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"act_{digest[:24]}"


def _recommendation_rule_for_check_id(check_id: str) -> dict[str, Any]:
    """Best-effort load recommendation rule metadata by check_id."""
    if not check_id:
        return {}

    rules = getattr(recommendations_module, "_RECOMMENDATION_RULES", {})
    default_rule = getattr(recommendations_module, "_RECOMMENDATION_DEFAULT_RULE", {})
    if not isinstance(rules, dict):
        rules = {}
    if not isinstance(default_rule, dict):
        default_rule = {}
    rule = rules.get(check_id, default_rule)
    if not isinstance(rule, dict):
        return {}
    return dict(rule)


def _fetch_finding_for_request(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
) -> dict[str, Any] | None:
    """Fetch recommendation-relevant finding fields from read model."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id, workspace, fingerprint, check_id, effective_state, service
        FROM finding_current
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint),
    )


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


def _resolve_request_action_type(payload: dict[str, Any], *, check_id: str) -> str:
    """Resolve action_type from request override or recommendation rule defaults."""
    explicit = str(payload.get("action_type") or "").strip().lower()
    if explicit:
        return explicit
    rule = _recommendation_rule_for_check_id(check_id)
    rule_action = str(rule.get("action_type") or "").strip().lower()
    if rule_action:
        return rule_action
    raise ValueError("action_type is required")


def _build_action_payload(
    *,
    payload: dict[str, Any],
    check_id: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Build deterministic action_payload JSON for storage."""
    out = _normalize_action_payload(payload.get("action_payload"))
    out.setdefault("fingerprint", fingerprint)
    out.setdefault("check_id", check_id)
    rule = _recommendation_rule_for_check_id(check_id)
    recommendation_type = str(rule.get("recommendation_type") or "").strip()
    if recommendation_type:
        out.setdefault("recommendation_type", recommendation_type)
    return out


def _resolve_initial_status(
    *,
    payload: dict[str, Any],
    check_id: str,
) -> tuple[str, str | None, datetime | None]:
    """Resolve initial action status and approval metadata."""
    rule = _recommendation_rule_for_check_id(check_id)
    requires_approval = bool(rule.get("requires_approval", False))
    auto_approve = _normalize_bool(
        payload.get("auto_approve"),
        field_name="auto_approve",
        default=False,
    )

    if auto_approve and requires_approval:
        raise ValueError("auto_approve is not allowed for actions that require approval")

    if auto_approve:
        actor = _require_actor(payload, field_name="requested_by")
        return _APPROVED, actor, _utc_now()
    return _PENDING_APPROVAL, None, None


def _insert_action(conn: Any, *, action: dict[str, Any]) -> None:
    """Insert remediation action idempotently."""
    now = _utc_now()
    execute_conn(
        conn,
        """
        INSERT INTO remediation_actions (
          tenant_id, workspace, action_id,
          fingerprint, check_id, action_type,
          action_payload, dry_run, status, reason,
          requested_by, approved_by, rejected_by,
          requested_at, approved_at, rejected_at, updated_at, version
        ) VALUES (
          %s, %s, %s,
          %s, %s, %s,
          %s::jsonb, %s, %s, %s,
          %s, %s, NULL,
          %s, %s, NULL, %s, 1
        )
        ON CONFLICT (tenant_id, workspace, action_id) DO NOTHING
        """,
        (
            action["tenant_id"],
            action["workspace"],
            action["action_id"],
            action["fingerprint"],
            action["check_id"],
            action["action_type"],
            json.dumps(action["action_payload"], separators=(",", ":")),
            action["dry_run"],
            action["status"],
            action["reason"],
            action["requested_by"],
            action["approved_by"],
            now,
            action["approved_at"],
            now,
        ),
    )


def _optional_text(value: Any) -> str | None:
    """Normalize optional payload text to stripped string or None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_request_create_input(payload: dict[str, Any]) -> _RequestCreateInput:
    """Normalize and validate request payload for action creation."""
    tenant_id, workspace = _require_scope_from_json(payload)
    fingerprint = str(payload.get("fingerprint") or "").strip()
    if not fingerprint:
        raise ValueError("fingerprint is required")
    return _RequestCreateInput(
        tenant_id=tenant_id,
        workspace=workspace,
        fingerprint=fingerprint,
        requested_by=_optional_text(payload.get("requested_by")),
        reason=_optional_text(payload.get("reason")),
        payload=payload,
    )


def _require_actionable_finding(
    conn: Any,
    *,
    request_data: _RequestCreateInput,
) -> dict[str, Any]:
    """Load finding row and enforce request eligibility constraints."""
    finding = _fetch_finding_for_request(
        conn,
        tenant_id=request_data.tenant_id,
        workspace=request_data.workspace,
        fingerprint=request_data.fingerprint,
    )
    if finding is None:
        raise _RequestError(code="not_found", message="finding not found", status=404)

    effective_state = str(finding.get("effective_state") or "").strip().lower()
    if effective_state in _TERMINAL_FINDING_STATES:
        raise _RequestError(code="invalid_state", message="finding is not actionable", status=409)
    return finding


def _resolve_action_identity(
    *,
    request_data: _RequestCreateInput,
    check_id: str,
) -> tuple[str, str, bool]:
    """Resolve action_type, dry_run and action_id deterministically."""
    action_type = _resolve_request_action_type(request_data.payload, check_id=check_id)
    dry_run = _normalize_bool(
        request_data.payload.get("dry_run"),
        field_name="dry_run",
        default=True,
    )
    action_id_raw = str(request_data.payload.get("action_id") or "").strip()
    action_id = action_id_raw or _stable_action_id(
        tenant_id=request_data.tenant_id,
        workspace=request_data.workspace,
        fingerprint=request_data.fingerprint,
        action_type=action_type,
        dry_run=dry_run,
    )
    return action_type, action_id, dry_run


def _request_action_for_finding(
    conn: Any,
    *,
    request_data: _RequestCreateInput,
) -> tuple[dict[str, Any], bool, bool]:
    """Create or fetch an idempotent remediation action for one finding."""
    finding = _require_actionable_finding(conn, request_data=request_data)
    check_id = str(finding.get("check_id") or "").strip()
    action_type, action_id, dry_run = _resolve_action_identity(
        request_data=request_data,
        check_id=check_id,
    )

    existing = _fetch_action(
        conn,
        tenant_id=request_data.tenant_id,
        workspace=request_data.workspace,
        action_id=action_id,
    )
    if existing is not None:
        if (
            str(existing.get("fingerprint") or "") != request_data.fingerprint
            or str(existing.get("action_type") or "") != action_type
        ):
            raise _RequestError(
                code="conflict",
                message="action_id already exists with different payload",
                status=409,
            )
        return existing, False, True

    status, approved_by, approved_at = _resolve_initial_status(
        payload=request_data.payload,
        check_id=check_id,
    )
    action_payload = _build_action_payload(
        payload=request_data.payload,
        check_id=check_id,
        fingerprint=request_data.fingerprint,
    )
    _insert_action(
        conn,
        action={
            "tenant_id": request_data.tenant_id,
            "workspace": request_data.workspace,
            "action_id": action_id,
            "fingerprint": request_data.fingerprint,
            "check_id": check_id,
            "action_type": action_type,
            "action_payload": action_payload,
            "dry_run": dry_run,
            "status": status,
            "reason": request_data.reason,
            "requested_by": request_data.requested_by,
            "approved_by": approved_by,
            "approved_at": approved_at,
        },
    )
    created = _fetch_action(
        conn,
        tenant_id=request_data.tenant_id,
        workspace=request_data.workspace,
        action_id=action_id,
    )
    if created is None:
        raise ValueError("failed to create remediation action")
    return created, True, False


@remediations_bp.route("/api/remediations/request", methods=["POST"])
def api_remediations_request() -> Any:
    """Create (idempotently) a remediation action from a finding fingerprint."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        request_data = _parse_request_create_input(payload)
        with db_conn() as conn:
            action, created, idempotent = _request_action_for_finding(
                conn,
                request_data=request_data,
            )
            if created:
                _audit_log_event(
                    conn,
                    event={
                        "tenant_id": request_data.tenant_id,
                        "workspace": request_data.workspace,
                        "action_id": action.get("action_id"),
                        "event_type": "remediation.requested",
                        "previous_value": None,
                        "new_value": _serialize_action(action),
                    },
                    actor_id=request_data.requested_by,
                )
                conn.commit()
        response_payload: dict[str, Any] = {
            "action": _serialize_action(action),
            "created": created,
        }
        if idempotent:
            response_payload["idempotent"] = True
        return _ok(response_payload)
    except _RequestError as exc:
        return _err(exc.code, exc.message, status=exc.status)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


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


def _impact_filters_from_query() -> dict[str, list[str] | None]:
    """Build remediation impact filters from query params."""
    return {
        "action_status": _parse_csv_list(_q("action_status")),
        "verification_status": _parse_csv_list(_q("verification_status")),
        "action_type": _parse_csv_list(_q("action_type")),
        "check_id": _parse_csv_list(_q("check_id")),
        "fingerprint": _parse_csv_list(_q("fingerprint")),
        "action_id": _parse_csv_list(_q("action_id")),
    }


def _impact_where_clause(
    tenant_id: str,
    workspace: str,
    filters: dict[str, list[str] | None],
) -> tuple[list[str], list[Any]]:
    """Build scoped WHERE clause for remediation impact listing."""
    where = ["ri.tenant_id = %s", "ri.workspace = %s"]
    params: list[Any] = [tenant_id, workspace]

    def _add_any(column: str, values: list[str] | None) -> None:
        if not values:
            return
        where.append(f"ri.{column} = ANY(%s)")
        params.append(values)

    _add_any("action_status", filters.get("action_status"))
    _add_any("verification_status", filters.get("verification_status"))
    _add_any("action_type", filters.get("action_type"))
    _add_any("check_id", filters.get("check_id"))
    _add_any("fingerprint", filters.get("fingerprint"))
    _add_any("action_id", filters.get("action_id"))
    return where, params


def _query_impact_rows(
    *,
    tenant_id: str,
    workspace: str,
    filters: dict[str, list[str] | None],
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    """Query remediation impact list, summary and total count."""
    where, params = _impact_where_clause(tenant_id, workspace, filters)
    list_sql = f"""
        SELECT
          ri.tenant_id, ri.workspace, ri.action_id, ri.fingerprint, ri.check_id, ri.action_type,
          ri.action_status, ri.verification_status,
          ri.baseline_estimated_monthly_savings, ri.current_estimated_monthly_savings,
          ri.realized_monthly_savings, ri.realization_rate_pct,
          ri.latest_run_id, ri.latest_run_ts, ri.present_in_latest,
          ri.finalized_at, ri.computed_at, ri.version
        FROM remediation_impact ri
        WHERE {' AND '.join(where)}
        ORDER BY ri.computed_at DESC, ri.action_id
        LIMIT %s OFFSET %s
    """
    count_sql = f"""
        SELECT COUNT(*) AS n
        FROM remediation_impact ri
        WHERE {' AND '.join(where)}
    """
    summary_sql = f"""
        SELECT
          COUNT(*)::bigint AS actions_count,
          SUM(CASE WHEN ri.verification_status = 'verified_resolved' THEN 1 ELSE 0 END)::bigint AS resolved_count,
          SUM(CASE WHEN ri.verification_status = 'verified_persistent' THEN 1 ELSE 0 END)::bigint AS persistent_count,
          SUM(CASE WHEN ri.verification_status = 'pending_post_run' THEN 1 ELSE 0 END)::bigint AS pending_count,
          SUM(CASE WHEN ri.verification_status = 'execution_failed' THEN 1 ELSE 0 END)::bigint AS failed_count,
          COALESCE(SUM(ri.baseline_estimated_monthly_savings), 0)::double precision AS baseline_total_monthly_savings,
          COALESCE(SUM(ri.realized_monthly_savings), 0)::double precision AS realized_total_monthly_savings
        FROM remediation_impact ri
        WHERE {' AND '.join(where)}
    """
    with db_conn() as conn:
        rows = fetch_all_dict_conn(conn, list_sql, params + [limit, offset])
        count_row = fetch_one_dict_conn(conn, count_sql, params)
        summary = fetch_one_dict_conn(conn, summary_sql, params) or {}
    return rows, summary, int((count_row or {}).get("n") or 0)


def _impact_summary_payload(summary: dict[str, Any]) -> dict[str, Any]:
    """Normalize remediation impact summary counters and ROI percentages."""
    baseline_total = float(summary.get("baseline_total_monthly_savings") or 0.0)
    realized_total = float(summary.get("realized_total_monthly_savings") or 0.0)
    realization_rate_pct = None
    if baseline_total > 0:
        realization_rate_pct = (realized_total / baseline_total) * 100.0
    return {
        "actions_count": int(summary.get("actions_count") or 0),
        "resolved_count": int(summary.get("resolved_count") or 0),
        "persistent_count": int(summary.get("persistent_count") or 0),
        "pending_count": int(summary.get("pending_count") or 0),
        "failed_count": int(summary.get("failed_count") or 0),
        "baseline_total_monthly_savings": baseline_total,
        "realized_total_monthly_savings": realized_total,
        "realization_rate_pct": realization_rate_pct,
    }


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


@remediations_bp.route("/api/remediations/impact", methods=["GET"])
def api_remediations_impact() -> Any:
    """List closed-loop remediation impact with aggregate realized ROI metrics."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        refresh = _normalize_bool(
            _q("refresh"),
            field_name="refresh",
            default=False,
        )
        refresh_limit = _parse_int(_q("refresh_limit"), default=500, min_v=1, max_v=5000)
        filters = _impact_filters_from_query()

        refreshed = 0
        if refresh:
            with db_conn() as conn:
                refreshed = refresh_scope_action_impacts(
                    conn,
                    tenant_id=tenant_id,
                    workspace=workspace,
                    limit=refresh_limit,
                )
                conn.commit()

        rows, summary, total = _query_impact_rows(
            tenant_id=tenant_id,
            workspace=workspace,
            filters=filters,
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
                "refreshed": refreshed,
                "summary": _impact_summary_payload(summary),
                "items": rows,
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
