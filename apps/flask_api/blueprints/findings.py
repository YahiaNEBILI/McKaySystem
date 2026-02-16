"""Findings Blueprint.

Provides finding query and management endpoints.
"""

import json
from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, request

from apps.backend.db import db_conn, execute_conn, fetch_all_dict_conn, fetch_one_dict_conn
from apps.flask_api.utils import (
    _MISSING,
    _coerce_optional_text,
    _coerce_positive_int,
    _err,
    _ok,
    _parse_csv_list,
    _parse_int,
    _payload_optional_text,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)

# Create the blueprint
findings_bp = Blueprint("findings", __name__)


def _add_any_filter(where: list[str], params: list[Any], field: str, values: list[str] | None) -> None:
    """Add ANY filter to WHERE clause."""
    if not values:
        return
    where.append(f"{field} = ANY(%s)")
    params.append(values)


def _audit_log_event(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    entity_type: str,
    entity_id: str,
    fingerprint: str | None,
    event_type: str,
    event_category: str,
    previous_value: dict[str, Any] | None,
    new_value: dict[str, Any] | None,
    actor_id: str | None,
    actor_email: str | None,
    actor_name: str | None,
    source: str,
    run_id: str | None = None,
    correlation_id: str | None = None,
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


def _finding_exists(conn: Any, *, tenant_id: str, workspace: str, fingerprint: str) -> bool:
    """Check whether a finding exists in scope."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM finding_latest
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint),
    )
    return bool(row and row.get("ok") == 1)


def _team_exists(conn: Any, *, tenant_id: str, workspace: str, team_id: str) -> bool:
    """Check whether a team exists in scope."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM teams
        WHERE tenant_id = %s AND workspace = %s AND team_id = %s
        LIMIT 1
        """,
        (tenant_id, workspace, team_id),
    )
    return bool(row and row.get("ok") == 1)


def _ensure_finding_governance_row(conn: Any, *, tenant_id: str, workspace: str, fingerprint: str) -> None:
    """Ensure a governance row exists for the finding."""
    execute_conn(
        conn,
        """
        INSERT INTO finding_governance (
          tenant_id,
          workspace,
          fingerprint,
          first_detected_at,
          first_opened_at,
          sla_deadline,
          created_at,
          updated_at
        )
        SELECT
          fc.tenant_id,
          fc.workspace,
          fc.fingerprint,
          COALESCE(fc.detected_at, now()),
          CASE WHEN fc.effective_state = 'open' THEN now() ELSE NULL END,
          CASE
            WHEN fc.effective_state = 'open' AND COALESCE(spo.sla_days, spc.sla_days) IS NOT NULL
            THEN now() + (COALESCE(spo.sla_days, spc.sla_days) * INTERVAL '1 day')
            ELSE NULL
          END,
          now(),
          now()
        FROM finding_current fc
        LEFT JOIN sla_policy_check_override spo
          ON spo.tenant_id = fc.tenant_id
          AND spo.workspace = fc.workspace
          AND spo.check_id = fc.check_id
        LEFT JOIN sla_policy_category spc
          ON spc.tenant_id = fc.tenant_id
          AND spc.workspace = fc.workspace
          AND spc.category = fc.category
        WHERE fc.tenant_id = %s
          AND fc.workspace = %s
          AND fc.fingerprint = %s
        ON CONFLICT (tenant_id, workspace, fingerprint) DO NOTHING
        """,
        (tenant_id, workspace, fingerprint),
    )


def _fetch_governance_owner_team(
    conn: Any, *, tenant_id: str, workspace: str, fingerprint: str
) -> dict[str, Any] | None:
    """Fetch owner/team governance fields for one finding."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT owner_id, owner_email, owner_name, team_id
        FROM finding_governance
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    )


def _update_finding_owner(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    owner_id: str | None,
    owner_email: str | None,
    owner_name: str | None,
) -> None:
    """Update owner fields for one finding governance row."""
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET owner_id = %s,
            owner_email = %s,
            owner_name = %s,
            updated_at = now()
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (owner_id, owner_email, owner_name, tenant_id, workspace, fingerprint),
    )


def _update_finding_team(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    team_id: str | None,
) -> None:
    """Update team assignment for one finding governance row."""
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET team_id = %s,
            updated_at = now()
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (team_id, tenant_id, workspace, fingerprint),
    )


def _fetch_finding_effective_state(
    conn: Any, *, tenant_id: str, workspace: str, fingerprint: str
) -> str | None:
    """Fetch effective finding lifecycle state from read model."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT effective_state
        FROM finding_current
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    )
    if not row:
        return None
    state = row.get("effective_state")
    if state is None:
        return None
    return str(state)


def _fetch_governance_sla(
    conn: Any, *, tenant_id: str, workspace: str, fingerprint: str
) -> dict[str, Any] | None:
    """Fetch SLA governance fields for one finding."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          sla_deadline,
          sla_paused_at,
          sla_total_paused_seconds,
          sla_extension_seconds,
          sla_breached_at,
          sla_extended_count,
          sla_extension_reason
        FROM finding_governance
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    )


def _apply_finding_sla_extension(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    extend_days: int,
    reason: str | None,
    event_ts: datetime,
) -> dict[str, Any]:
    """Apply SLA extension and return resulting SLA governance fields."""
    extension_seconds = int(extend_days) * 86400
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET sla_extension_seconds = COALESCE(sla_extension_seconds, 0) + %s,
            sla_extended_count = COALESCE(sla_extended_count, 0) + 1,
            sla_extension_reason = %s,
            sla_deadline = CASE
              WHEN sla_deadline IS NULL THEN NULL
              ELSE sla_deadline + (%s * INTERVAL '1 second')
            END,
            sla_breached_at = CASE
              WHEN sla_deadline IS NULL THEN NULL
              WHEN (sla_deadline + (%s * INTERVAL '1 second')) < %s
                THEN COALESCE(sla_breached_at, %s)
              ELSE NULL
            END,
            updated_at = now()
        WHERE tenant_id = %s
          AND workspace = %s
          AND fingerprint = %s
        """,
        (
            extension_seconds,
            reason,
            extension_seconds,
            extension_seconds,
            event_ts,
            event_ts,
            tenant_id,
            workspace,
            fingerprint,
        ),
    )
    after = _fetch_governance_sla(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
    return after or {}


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
        params: list[Any] = [tenant_id, workspace]

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
        params: list[Any] = [tenant_id, workspace]

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
        max_days: int | None = None
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
        params: list[Any] = [tenant_id, workspace, min_days]

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


@findings_bp.route("/api/findings/<fingerprint>/owner", methods=["PUT"])
def api_finding_set_owner(fingerprint: str) -> Any:
    """Assign or clear finding owner governance fields."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)

        owner_id_in = _payload_optional_text(payload, "owner_id")
        owner_email_in = _payload_optional_text(payload, "owner_email")
        owner_name_in = _payload_optional_text(payload, "owner_name")
        if owner_id_in is _MISSING and owner_email_in is _MISSING and owner_name_in is _MISSING:
            raise ValueError("at least one of owner_id, owner_email, owner_name must be provided")

        updated_by = _coerce_optional_text(payload.get("updated_by"))

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint):
                return _err("not_found", "finding not found", status=404)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            before = _fetch_governance_owner_team(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            ) or {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None}

            owner_id = before.get("owner_id") if owner_id_in is _MISSING else owner_id_in
            owner_email = before.get("owner_email") if owner_email_in is _MISSING else owner_email_in
            owner_name = before.get("owner_name") if owner_name_in is _MISSING else owner_name_in

            _update_finding_owner(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                owner_id=owner_id,
                owner_email=owner_email,
                owner_name=owner_name,
            )
            after = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fingerprint,
                fingerprint=fingerprint,
                event_type="finding.owner.updated",
                event_category="governance",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fingerprint,
                "owner_id": (after or {}).get("owner_id"),
                "owner_email": (after or {}).get("owner_email"),
                "owner_name": (after or {}).get("owner_name"),
                "team_id": (after or {}).get("team_id"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@findings_bp.route("/api/findings/<fingerprint>/team", methods=["PUT"])
def api_finding_set_team(fingerprint: str) -> Any:
    """Assign or clear finding team governance field."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)

        team_id_in = _payload_optional_text(payload, "team_id")
        if team_id_in is _MISSING:
            raise ValueError("team_id key is required")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint):
                return _err("not_found", "finding not found", status=404)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            before = _fetch_governance_owner_team(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            ) or {"owner_id": None, "owner_email": None, "owner_name": None, "team_id": None}

            if team_id_in is not None and not _team_exists(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=team_id_in
            ):
                return _err("not_found", "team not found", status=404)

            _update_finding_team(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                team_id=team_id_in,
            )
            after = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fingerprint,
                fingerprint=fingerprint,
                event_type="finding.team.updated",
                event_category="governance",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fingerprint,
                "owner_id": (after or {}).get("owner_id"),
                "owner_email": (after or {}).get("owner_email"),
                "owner_name": (after or {}).get("owner_name"),
                "team_id": (after or {}).get("team_id"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@findings_bp.route("/api/findings/<fingerprint>/sla/extend", methods=["POST"])
def api_finding_extend_sla(fingerprint: str) -> Any:
    """Extend finding SLA by a positive day count."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        extend_days = _coerce_positive_int(payload.get("extend_days"), field_name="extend_days")
        reason = _coerce_optional_text(payload.get("reason"))
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        event_ts = datetime.now(UTC)

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint):
                return _err("not_found", "finding not found", status=404)

            effective_state = _fetch_finding_effective_state(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            )
            if effective_state in {"resolved", "ignored"}:
                return _err("invalid_state", "cannot extend SLA for closed findings", status=409)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            before = _fetch_governance_sla(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint)
            if not before or before.get("sla_deadline") is None:
                return _err("bad_request", "no SLA policy resolved for finding", status=400)

            after = _apply_finding_sla_extension(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                extend_days=extend_days,
                reason=reason,
                event_ts=event_ts,
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fingerprint,
                fingerprint=fingerprint,
                event_type="finding.sla.extended",
                event_category="sla",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fingerprint,
                "extend_days": extend_days,
                "sla_deadline": after.get("sla_deadline"),
                "sla_paused_at": after.get("sla_paused_at"),
                "sla_total_paused_seconds": after.get("sla_total_paused_seconds"),
                "sla_extension_seconds": after.get("sla_extension_seconds"),
                "sla_breached_at": after.get("sla_breached_at"),
                "sla_extended_count": after.get("sla_extended_count"),
                "sla_extension_reason": after.get("sla_extension_reason"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
