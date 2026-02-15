"""Findings Blueprint.

Provides finding query and management endpoints.
"""

from typing import Any, Dict, List, Optional

from flask import Blueprint

from apps.backend.db import db_conn, fetch_one_dict_conn, fetch_all_dict_conn, execute_conn
from apps.flask_api.utils import (
    _ok,
    _err,
    _json,
    _q,
    _require_scope_from_query,
    _require_scope_from_json,
    _parse_int,
    _parse_csv_list,
    _parse_iso8601_dt,
    _coerce_optional_text,
    _payload_optional_text,
    _coerce_positive_int,
    _coerce_non_negative_int,
)


# Create the blueprint
findings_bp = Blueprint("findings", __name__)


def _add_any_filter(where: List[str], params: List[Any], field: str, values: Optional[List[str]]) -> None:
    """Add ANY filter to WHERE clause."""
    if not values:
        return
    where.append(f"{field} = ANY(%s)")
    params.append(values)


@findings_bp.route("/api/findings", methods=["GET"])
def api_findings() -> Any:
    """Query findings with filters and pagination.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100, max 1000)
        offset: Results offset (default 0)
        state: Filter by effective_state (comma-separated)
        severity: Filter by severity (comma-separated)
        service: Filter by service (comma-separated)
        check_id: Filter by check_id (comma-separated)
        category: Filter by category (comma-separated)
        region: Filter by region (comma-separated)
        account_id: Filter by account_id (comma-separated)
        team_id: Filter by team_id (comma-separated)
        owner_email: Filter by owner_email (comma-separated)
        sla_status: Filter by sla_status (comma-separated)
        q: Substring match on title
        order: Sort order (savings_desc or detected_desc)

    Returns:
        Paginated list of findings
    """
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        # Filters
        effective_states = _parse_csv_list(_q("state"))
        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        sla_statuses = _parse_csv_list(_q("sla_status"))
        query_str = _q("q")

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "detected_desc"}:
            raise ValueError("order must be 'savings_desc' or 'detected_desc'")

        where = ["tenant_id = %s", "workspace = %s"]
        params: List[Any] = [tenant_id, workspace]

        _add_any_filter(where, params, "effective_state", effective_states)
        _add_any_filter(where, params, "severity", severities)
        _add_any_filter(where, params, "service", services)
        _add_any_filter(where, params, "check_id", check_ids)
        _add_any_filter(where, params, "category", categories)
        _add_any_filter(where, params, "region", regions)
        _add_any_filter(where, params, "account_id", account_ids)
        _add_any_filter(where, params, "team_id", team_ids)
        _add_any_filter(where, params, "owner_email", owner_emails)
        _add_any_filter(where, params, "sla_status", sla_statuses)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        order_sql = (
            "estimated_monthly_savings DESC NULLS LAST, detected_at DESC"
            if order == "savings_desc"
            else "detected_at DESC"
        )

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
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


@findings_bp.route("/api/findings/sla/breached", methods=["GET"])
def api_findings_sla_breached() -> Any:
    """List findings currently in breached SLA state.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100, max 1000)
        offset: Results offset (default 0)
        severity, service, check_id, category, region, account_id, team_id, owner_email: Filters

    Returns:
        Paginated list of SLA-breached findings
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        query_str = _q("q")

        where = ["tenant_id = %s", "workspace = %s", "sla_status = 'breached'"]
        params: List[Any] = [tenant_id, workspace]

        _add_any_filter(where, params, "severity", severities)
        _add_any_filter(where, params, "service", services)
        _add_any_filter(where, params, "check_id", check_ids)
        _add_any_filter(where, params, "category", categories)
        _add_any_filter(where, params, "region", regions)
        _add_any_filter(where, params, "account_id", account_ids)
        _add_any_filter(where, params, "team_id", team_ids)
        _add_any_filter(where, params, "owner_email", owner_emails)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_extension_seconds, sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY sla_deadline ASC NULLS LAST, detected_at DESC
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
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


@findings_bp.route("/api/findings/aging", methods=["GET"])
def api_findings_aging() -> Any:
    """List findings filtered by aging clock (open or detected age).

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100, max 1000)
        offset: Results offset (default 0)
        age_basis: 'open' or 'detected' (default 'open')
        min_days: Minimum age in days (default 0)
        max_days: Maximum age in days
        state, severity, service, check_id, category, region, account_id, team_id, owner_email, sla_status: Filters
        q: Substring match on title

    Returns:
        Paginated list of aging findings
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        age_basis = (_q("age_basis", "open") or "open").strip().lower()
        if age_basis not in {"open", "detected"}:
            raise ValueError("age_basis must be 'open' or 'detected'")
        age_col = "age_days_open" if age_basis == "open" else "age_days_detected"

        min_days = _parse_int(_q("min_days"), default=0, min_v=0, max_v=36500)
        max_days_raw = _q("max_days")
        max_days: Optional[int] = None
        if max_days_raw is not None and max_days_raw != "":
            max_days = _parse_int(max_days_raw, default=0, min_v=0, max_v=36500)
            if max_days < min_days:
                raise ValueError("max_days must be >= min_days")

        effective_states = _parse_csv_list(_q("state"))
        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        sla_statuses = _parse_csv_list(_q("sla_status"))
        query_str = _q("q")

        where = ["tenant_id = %s", "workspace = %s", f"{age_col} IS NOT NULL", f"{age_col} >= %s"]
        params: List[Any] = [tenant_id, workspace, min_days]

        if max_days is not None:
            where.append(f"{age_col} <= %s")
            params.append(max_days)

        _add_any_filter(where, params, "effective_state", effective_states)
        _add_any_filter(where, params, "severity", severities)
        _add_any_filter(where, params, "service", services)
        _add_any_filter(where, params, "check_id", check_ids)
        _add_any_filter(where, params, "category", categories)
        _add_any_filter(where, params, "region", regions)
        _add_any_filter(where, params, "account_id", account_ids)
        _add_any_filter(where, params, "team_id", team_ids)
        _add_any_filter(where, params, "owner_email", owner_emails)
        _add_any_filter(where, params, "sla_status", sla_statuses)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_extension_seconds, sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              {age_col} AS age_days,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY {age_col} DESC, detected_at DESC
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
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


@findings_bp.route("/api/findings/aggregates", methods=["GET"])
def api_findings_aggregates() -> Any:
    """Get aggregated statistics about findings.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier

    Returns:
        Aggregated statistics
    """
    try:
        tenant_id, workspace = _require_scope_from_query()

        with db_conn() as conn:
            # Count by severity
            by_severity = fetch_all_dict_conn(
                conn,
                """
                SELECT severity, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY severity
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )

            # Count by service
            by_service = fetch_all_dict_conn(
                conn,
                """
                SELECT service, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY service
                ORDER BY count DESC
                LIMIT 20
                """,
                (tenant_id, workspace),
            )

            # Count by category
            by_category = fetch_all_dict_conn(
                conn,
                """
                SELECT category, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY category
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )

            # Count by state
            by_state = fetch_all_dict_conn(
                conn,
                """
                SELECT effective_state AS state, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY effective_state
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )

            # Count by account
            by_account = fetch_all_dict_conn(
                conn,
                """
                SELECT account_id, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY account_id
                ORDER BY count DESC
                LIMIT 20
                """,
                (tenant_id, workspace),
            )

            # Total count
            total_row = fetch_one_dict_conn(
                conn,
                "SELECT COUNT(*)::bigint AS n FROM finding_current WHERE tenant_id = %s AND workspace = %s",
                (tenant_id, workspace),
            )

            # Sum of potential savings
            savings_row = fetch_one_dict_conn(
                conn,
                """
                SELECT SUM(estimated_monthly_savings) AS total_savings
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s AND estimated_monthly_savings IS NOT NULL
                """,
                (tenant_id, workspace),
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "total": int(total_row.get("n") or 0) if total_row else 0,
                "total_monthly_savings": float(savings_row.get("total_savings") or 0) if savings_row else 0,
                "by_severity": by_severity,
                "by_service": by_service,
                "by_category": by_category,
                "by_state": by_state,
                "by_account": by_account,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
