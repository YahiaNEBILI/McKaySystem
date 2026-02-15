"""Groups Blueprint.

Provides finding group endpoints for grouped findings.
"""

from typing import Any, Dict, List, Optional

from flask import Blueprint

from apps.backend.db import db_conn, fetch_one_dict_conn, fetch_all_dict_conn
from apps.flask_api.utils import (
    _ok,
    _json,
    _q,
    _require_scope_from_query,
    _parse_int,
    _parse_csv_list,
)


# Create the blueprint
groups_bp = Blueprint("groups", __name__)


def _add_any_filter(where: List[str], params: List[Any], field: str, values: Optional[List[str]]) -> None:
    """Add ANY filter to WHERE clause."""
    if not values:
        return
    where.append(f"{field} = ANY(%s)")
    params.append(values)


@groups_bp.route("/api/groups", methods=["GET"])
def api_groups() -> Any:
    """List grouped finding types.

    Groups are defined by finding_current.group_key (populated at ingest).

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100)
        offset: Results offset (default 0)
        state, category, service, check_id, severity: Filters
        q: Substring match on title
        order: Sort order (savings_desc or count_desc)

    Returns:
        Paginated list of groups
    """
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        effective_states = _parse_csv_list(_q("state"))
        categories = _parse_csv_list(_q("category"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        severities = _parse_csv_list(_q("severity"))
        q = _q("q")

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "count_desc"}:
            raise ValueError("order must be 'savings_desc' or 'count_desc'")

        where = ["tenant_id = %s", "workspace = %s", "group_key IS NOT NULL"]
        params: List[Any] = [tenant_id, workspace]

        _add_any_filter(where, params, "effective_state", effective_states)
        _add_any_filter(where, params, "category", categories)
        _add_any_filter(where, params, "service", services)
        _add_any_filter(where, params, "check_id", check_ids)
        _add_any_filter(where, params, "severity", severities)

        if q:
            where.append("COALESCE(title, '') ILIKE %s")
            params.append(f"%{q}%")

        order_sql = "total_savings DESC NULLS LAST"
        if order == "count_desc":
            order_sql = "finding_count DESC"

        sql = f"""
            SELECT
              group_key,
              MIN(title) AS title,
              MIN(check_id) AS check_id,
              MIN(service) AS service,
              MIN(category) AS category,
              COUNT(*)::bigint AS finding_count,
              SUM(COALESCE(estimated_monthly_savings, 0))::double precision AS total_savings,
              MAX(
                CASE lower(COALESCE(severity,''))
                  WHEN 'critical' THEN 4
                  WHEN 'high' THEN 3
                  WHEN 'medium' THEN 2
                  WHEN 'low' THEN 1
                  ELSE 0
                END
              )::int AS max_severity_rank
            FROM finding_current
            WHERE {' AND '.join(where)}
            GROUP BY group_key
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            groups = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(DISTINCT group_key) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )
            total = int(count_row["n"] or 0) if count_row else 0

        # Map rank back to a label
        for g in groups:
            rank = int(g.get("max_severity_rank") or 0)
            g["max_severity"] = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(rank, "unknown")

        return _json({"items": groups, "total": total, "limit": limit, "offset": offset})

    except ValueError as exc:
        return _json({"error": "bad_request", "message": str(exc)}, status=400)


@groups_bp.route("/api/groups/<group_key>", methods=["GET"])
def api_group_detail(group_key: str) -> Any:
    """Get one group summary + member findings (paginated).

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100)
        offset: Results offset (default 0)
        state: Filter by effective_state
        q: Substring match on title

    Returns:
        Group summary with paginated member findings
    """
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        effective_states = _parse_csv_list(_q("state"))
        q = _q("q")

        where = ["tenant_id = %s", "workspace = %s", "group_key = %s"]
        params: List[Any] = [tenant_id, workspace, group_key]

        if effective_states:
            where.append("effective_state = ANY(%s)")
            params.append(effective_states)

        if q:
            where.append("COALESCE(title, '') ILIKE %s")
            params.append(f"%{q}%")

        with db_conn() as conn:
            summary = fetch_one_dict_conn(
                conn,
                f"""
                SELECT
                  group_key,
                  MIN(title) AS title,
                  MIN(check_id) AS check_id,
                  MIN(service) AS service,
                  MIN(category) AS category,
                  COUNT(*)::bigint AS finding_count,
                  SUM(COALESCE(estimated_monthly_savings, 0))::double precision AS total_savings
                FROM finding_current
                WHERE {' AND '.join(where)}
                GROUP BY group_key
                """,
                params,
            )

            if not summary:
                return _json({"error": "not_found", "message": "group not found"}, status=404)

            members_sql = f"""
                SELECT
                  tenant_id, workspace, fingerprint, run_id,
                  check_id, service, severity, title,
                  estimated_monthly_savings, region, account_id,
                  category, group_key,
                  detected_at, state, snooze_until, reason, effective_state,
                  payload
                FROM finding_current
                WHERE {' AND '.join(where)}
                ORDER BY estimated_monthly_savings DESC NULLS LAST, detected_at DESC
                LIMIT %s OFFSET %s
            """
            members = fetch_all_dict_conn(conn, members_sql, params + [limit, offset])
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )
            total = int(count_row["n"] or 0) if count_row else 0

        return _json({"group": summary, "items": members, "total": total, "limit": limit, "offset": offset})

    except ValueError as exc:
        return _json({"error": "bad_request", "message": str(exc)}, status=400)
