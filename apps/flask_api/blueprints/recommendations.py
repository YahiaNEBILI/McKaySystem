"""Recommendations Blueprint.

Provides recommendation endpoints for FinOps optimization opportunities.
"""

from typing import Any

from flask import Blueprint, request

from apps.backend.db import db_conn, fetch_all_dict_conn, fetch_one_dict_conn
from apps.flask_api.utils import (
    _coerce_non_negative_int,
    _coerce_optional_float,
    _coerce_optional_text,
    _coerce_positive_int,
    _coerce_text_list,
    _err,
    _ok,
    _parse_csv_list,
    _parse_int,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)
from apps.flask_api.utils.payload import (
    _as_float,
    _payload_dict,
    _payload_estimated_confidence,
    _payload_pricing_source,
    _payload_pricing_version,
    _run_meta_pricing_source,
    _run_meta_pricing_version,
)

# Create the blueprint
recommendations_bp = Blueprint("recommendations", __name__)


# Recommendation rules - mapping check_ids to recommendation metadata
_RECOMMENDATION_RULES: dict[str, dict[str, Any]] = {
    "aws.ec2.instances.underutilized": {
        "recommendation_type": "rightsizing.ec2.instance",
        "action": "Downsize EC2 instance to a smaller family/size based on sustained utilization.",
        "priority": "p1",
        "action_type": "rightsize",
        "target_kind": "instance_type",
        "target_value": "smaller_same_family",
        "current_kind": "instance_type",
        "current_value": "current",
        "confidence": 78,
        "pricing_source": "finding_estimate",
        "requires_approval": False,
    },
    "aws.ec2.ri.coverage.gap": {
        "recommendation_type": "commitment.ec2.ri.coverage",
        "action": "Increase EC2 Reserved Instance coverage for steady-state usage.",
        "priority": "p1",
        "action_type": "purchase",
        "target_kind": "coverage_pct",
        "target_value": "90",
        "current_kind": "coverage_pct",
        "current_value": "current",
        "confidence": 66,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.ec2.ri.utilization.low": {
        "recommendation_type": "commitment.ec2.ri.utilization",
        "action": "Optimize underutilized EC2 Reserved Instance commitments.",
        "priority": "p1",
        "action_type": "tune",
        "target_kind": "utilization_pct",
        "target_value": ">=80",
        "current_kind": "utilization_pct",
        "current_value": "current",
        "confidence": 60,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.ec2.savings.plans.coverage.gap": {
        "recommendation_type": "commitment.ec2.savings_plan.coverage",
        "action": "Increase EC2 Savings Plan commitment for steady-state demand.",
        "priority": "p1",
        "action_type": "purchase",
        "target_kind": "commitment_usd_per_hour",
        "target_value": "match_demand",
        "current_kind": "commitment_usd_per_hour",
        "current_value": "current",
        "confidence": 66,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.ec2.savings.plans.utilization.low": {
        "recommendation_type": "commitment.ec2.savings_plan.utilization",
        "action": "Optimize underutilized EC2 Savings Plan commitments.",
        "priority": "p1",
        "action_type": "tune",
        "target_kind": "utilization_pct",
        "target_value": ">=80",
        "current_kind": "utilization_pct",
        "current_value": "current",
        "confidence": 60,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.rds.storage.overprovisioned": {
        "recommendation_type": "rightsizing.rds.storage",
        "action": "Reduce allocated RDS storage to match observed baseline plus safety headroom.",
        "priority": "p1",
        "action_type": "rightsize",
        "target_kind": "storage",
        "target_value": "lower_allocated_gb",
        "current_kind": "storage",
        "current_value": "current",
        "confidence": 74,
        "pricing_source": "finding_estimate",
        "requires_approval": False,
    },
    "aws.ec2.nat.gateways.idle": {
        "recommendation_type": "cleanup.nat.gateway",
        "action": "Delete idle NAT Gateway after dependency validation to remove fixed hourly cost.",
        "priority": "p1",
        "action_type": "terminate",
        "target_kind": "resource",
        "target_value": "delete",
        "current_kind": "resource",
        "current_value": "current",
        "confidence": 90,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.s3.governance.lifecycle.missing": {
        "recommendation_type": "storage.lifecycle.s3",
        "action": "Add S3 lifecycle transitions/expiration for cold or stale data classes.",
        "priority": "p2",
        "action_type": "enable",
        "target_kind": "feature",
        "target_value": "s3_lifecycle",
        "current_kind": "feature",
        "current_value": "missing",
        "confidence": 65,
        "pricing_source": "finding_estimate",
        "requires_approval": False,
    },
    "aws.lambda.functions.unused": {
        "recommendation_type": "cleanup.lambda.function",
        "action": "Disable triggers or remove unused Lambda functions after owner confirmation.",
        "priority": "p1",
        "action_type": "terminate",
        "target_kind": "resource",
        "target_value": "delete_or_disable",
        "current_kind": "resource",
        "current_value": "current",
        "confidence": 70,
        "pricing_source": "finding_estimate",
        "requires_approval": True,
    },
    "aws.lambda.functions.memory.overprovisioned": {
        "recommendation_type": "rightsizing.lambda.memory",
        "action": "Lower Lambda memory configuration based on p95 memory usage and latency guardrails.",
        "priority": "p1",
        "action_type": "tune",
        "target_kind": "memory_mb",
        "target_value": "lower_memory",
        "current_kind": "memory_mb",
        "current_value": "current",
        "confidence": 72,
        "pricing_source": "finding_estimate",
        "requires_approval": False,
    },
}

_RECOMMENDATION_CHECK_IDS = sorted(_RECOMMENDATION_RULES)
_RECOMMENDATION_DEFAULT_RULE: dict[str, Any] = {
    "recommendation_type": "other",
    "action": "Review finding details and define a remediation plan.",
    "priority": "p2",
    "action_type": "tune",
    "target_kind": "generic",
    "target_value": "review",
    "current_kind": "generic",
    "current_value": "current",
    "confidence": 50,
    "pricing_source": "finding_estimate",
    "requires_approval": False,
}


def _build_recommendations_where_from_values(
    tenant_id: str,
    workspace: str,
    *,
    effective_states: list[str] | None,
    severities: list[str] | None,
    services: list[str] | None,
    check_ids: list[str] | None,
    categories: list[str] | None,
    regions: list[str] | None,
    account_ids: list[str] | None,
    query_str: str | None,
    min_savings: float | None,
    fingerprints: list[str] | None = None,
) -> tuple[list[str], list[Any]]:
    """Build scoped SQL filters for recommendations endpoints."""
    where = ["fc.tenant_id = %s", "fc.workspace = %s", "fc.check_id = ANY(%s)"]
    params: list[Any] = [tenant_id, workspace, _RECOMMENDATION_CHECK_IDS]

    def _add_any(field: str, values: list[str] | None) -> None:
        if not values:
            return
        where.append(f"fc.{field} = ANY(%s)")
        params.append(values)

    _add_any("effective_state", effective_states)
    _add_any("severity", severities)
    _add_any("service", services)
    _add_any("check_id", check_ids)
    _add_any("category", categories)
    _add_any("region", regions)
    _add_any("account_id", account_ids)
    _add_any("fingerprint", fingerprints)

    if query_str:
        where.append("fc.title ILIKE %s")
        params.append(f"%{query_str}%")

    if min_savings is not None:
        where.append("COALESCE(fc.estimated_monthly_savings, 0) >= %s")
        params.append(min_savings)

    return where, params


def _build_recommendations_where(tenant_id: str, workspace: str) -> tuple[list[str], list[Any]]:
    """Build scoped SQL filters for recommendations endpoints from query params."""
    min_savings_raw = _q("min_savings")
    min_savings: float | None = None
    if min_savings_raw is not None:
        try:
            min_savings = float(min_savings_raw)
        except ValueError as exc:
            raise ValueError(f"Invalid min_savings: {min_savings_raw}") from exc
    return _build_recommendations_where_from_values(
        tenant_id,
        workspace,
        effective_states=_parse_csv_list(_q("state", "open")),
        severities=_parse_csv_list(_q("severity")),
        services=_parse_csv_list(_q("service")),
        check_ids=_parse_csv_list(_q("check_id")),
        categories=_parse_csv_list(_q("category")),
        regions=_parse_csv_list(_q("region")),
        account_ids=_parse_csv_list(_q("account_id")),
        query_str=_q("q"),
        min_savings=min_savings,
    )


def _recommendation_type_case_sql() -> str:
    """Return SQL CASE expression that maps check_id to recommendation_type."""
    clauses: list[str] = []
    for check_id in _RECOMMENDATION_CHECK_IDS:
        rec_type = _RECOMMENDATION_RULES[check_id]["recommendation_type"]
        clauses.append(f"WHEN check_id = '{check_id}' THEN '{rec_type}'")
    return "CASE " + " ".join(clauses) + " ELSE 'other' END"


def _build_estimate_risk_warnings(
    *,
    items: list[dict[str, Any]],
    requested_fingerprints: list[str] | None,
) -> list[dict[str, Any]]:
    """Build deterministic risk warnings for estimate responses."""
    warnings: list[dict[str, Any]] = []
    requires_approval_count = sum(1 for item in items if bool(item.get("requires_approval")))
    if requires_approval_count:
        warnings.append(
            {
                "code": "approval_required",
                "severity": "medium",
                "count": requires_approval_count,
                "message": "Some recommendations require manual approval before execution.",
            }
        )

    low_confidence_count = sum(1 for item in items if int(item.get("confidence") or 0) < 60)
    if low_confidence_count:
        warnings.append(
            {
                "code": "low_confidence",
                "severity": "low",
                "count": low_confidence_count,
                "message": "Some estimates have low confidence and should be manually validated.",
            }
        )

    if requested_fingerprints is not None:
        found = {str(item.get("fingerprint") or "") for item in items}
        missing = [fp for fp in requested_fingerprints if fp not in found]
        if missing:
            warnings.append(
                {
                    "code": "missing_or_ineligible",
                    "severity": "low",
                    "count": len(missing),
                    "message": "Some requested fingerprints are missing or not recommendation-eligible.",
                    "fingerprints": missing,
                }
            )
    return warnings


def _build_recommendation_item(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a finding_current row to a recommendation item payload."""
    check_id = str(row.get("check_id") or "")
    rule = _RECOMMENDATION_RULES.get(check_id, _RECOMMENDATION_DEFAULT_RULE)
    payload = _payload_dict(row.get("payload"))
    run_meta = _payload_dict(row.get("run_meta"))
    dimensions = payload.get("dimensions")
    if not isinstance(dimensions, dict):
        dimensions = {}

    monthly_savings = _as_float(row.get("estimated_monthly_savings"), default=0.0)
    annual_savings = round(monthly_savings * 12.0, 2)
    confidence = _payload_estimated_confidence(payload)
    if confidence is None:
        confidence = int(rule.get("confidence") or 0)
    pricing_source = _payload_pricing_source(payload)
    if not pricing_source:
        pricing_source = _run_meta_pricing_source(run_meta)
    if not pricing_source:
        pricing_source = str(rule["pricing_source"])

    pricing_version = _payload_pricing_version(payload)
    if not pricing_version:
        pricing_version_raw = dimensions.get("pricing_version")
        pricing_version = str(pricing_version_raw).strip() if pricing_version_raw is not None else None
    if not pricing_version:
        pricing_version = _run_meta_pricing_version(run_meta)

    action = str(rule["action"])
    target_kind = str(rule["target_kind"])
    target_value = str(rule["target_value"])
    current_kind = str(rule["current_kind"])
    current_value = str(rule["current_value"])

    if check_id == "aws.ec2.instances.underutilized":
        current_instance_type = str(dimensions.get("instance_type") or "").strip()
        target_instance_type = str(dimensions.get("recommended_instance_type") or "").strip()
        if current_instance_type:
            current_value = current_instance_type
        if target_instance_type:
            target_value = target_instance_type
        if current_instance_type and target_instance_type:
            action = (
                f"Downsize EC2 instance from {current_instance_type} to {target_instance_type} "
                "based on sustained utilization."
            )

    if check_id == "aws.rds.storage.overprovisioned":
        allocated_gb = str(dimensions.get("allocated_gb") or "").strip()
        estimated_used_gb = str(dimensions.get("estimated_used_gb") or "").strip()
        if allocated_gb:
            current_value = f"{allocated_gb}gb"
        if estimated_used_gb:
            target_value = f"{estimated_used_gb}gb"
        if allocated_gb and estimated_used_gb:
            action = (
                f"Reduce allocated RDS storage from {allocated_gb} GB toward observed baseline "
                f"({estimated_used_gb} GB) after validating growth headroom."
            )

    if check_id == "aws.ec2.ri.coverage.gap":
        instance_type = str(dimensions.get("instance_type") or "").strip()
        uncovered = str(dimensions.get("uncovered_count") or "").strip()
        coverage_pct = str(dimensions.get("coverage_pct") or "").strip()
        target_coverage_pct = str(dimensions.get("target_coverage_pct") or "").strip()
        if coverage_pct:
            current_value = coverage_pct
        if target_coverage_pct:
            target_value = target_coverage_pct
        if instance_type and uncovered:
            action = (
                f"Increase RI coverage for {instance_type} by about {uncovered} instance(s) "
                "after validating baseline demand."
            )

    if check_id == "aws.ec2.ri.utilization.low":
        instance_type = str(dimensions.get("instance_type") or "").strip()
        unused = str(dimensions.get("unused_count") or "").strip()
        utilization_pct = str(dimensions.get("utilization_pct") or "").strip()
        target_utilization_pct = str(dimensions.get("target_utilization_pct") or "").strip()
        if utilization_pct:
            current_value = utilization_pct
        if target_utilization_pct:
            target_value = target_utilization_pct
        if instance_type and unused:
            action = (
                f"Reduce unused RI commitments for {instance_type} (~{unused} unit(s)) via "
                "modification/exchange/reallocation."
            )

    if check_id == "aws.ec2.savings.plans.coverage.gap":
        demand_hourly = str(dimensions.get("estimated_demand_usd_per_hour") or "").strip()
        committed_hourly = str(dimensions.get("committed_usd_per_hour") or "").strip()
        uncovered_hourly = str(dimensions.get("uncovered_usd_per_hour") or "").strip()
        if committed_hourly:
            current_value = committed_hourly
        if demand_hourly:
            target_value = demand_hourly
        if uncovered_hourly:
            action = (
                f"Increase Savings Plan commitment by about ${uncovered_hourly}/hr "
                "after validating steady-state demand."
            )

    if check_id == "aws.ec2.savings.plans.utilization.low":
        utilization_pct = str(dimensions.get("utilization_pct") or "").strip()
        target_utilization_pct = str(dimensions.get("target_utilization_pct") or "").strip()
        unused_hourly = str(dimensions.get("unused_usd_per_hour") or "").strip()
        if utilization_pct:
            current_value = utilization_pct
        if target_utilization_pct:
            target_value = target_utilization_pct
        if unused_hourly:
            action = (
                f"Reduce underused Savings Plan commitment (about ${unused_hourly}/hr appears unused) "
                "through workload alignment and commitment planning."
            )

    return {
        "fingerprint": row.get("fingerprint"),
        "check_id": check_id,
        "service": row.get("service"),
        "severity": row.get("severity"),
        "category": row.get("category"),
        "title": row.get("title"),
        "recommendation_type": rule["recommendation_type"],
        "action": action,
        "priority": rule["priority"],
        "action_type": rule["action_type"],
        "target": {
            "kind": target_kind,
            "value": target_value,
        },
        "current": {
            "kind": current_kind,
            "value": current_value,
        },
        "estimated_monthly_savings": monthly_savings,
        "estimated_annual_savings": annual_savings,
        "confidence": confidence,
        "confidence_label": "high" if confidence >= 80 else ("medium" if confidence >= 60 else "low"),
        "pricing_source": pricing_source,
        "pricing_version": pricing_version,
        "requires_approval": bool(rule.get("requires_approval")),
        "region": row.get("region"),
        "account_id": row.get("account_id"),
        "detected_at": row.get("detected_at"),
        "effective_state": row.get("effective_state"),
    }


@recommendations_bp.route("/api/recommendations", methods=["GET"])
def api_recommendations() -> Any:
    """List actionable recommendations derived from current scoped findings.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100)
        offset: Results offset (default 0)
        state, severity, service, check_id, category, region, account_id: Filters
        q: Substring match on title
        min_savings: Minimum monthly savings filter
        order: Sort order (savings_desc or detected_desc)

    Returns:
        Paginated list of recommendations
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "detected_desc"}:
            raise ValueError("order must be 'savings_desc' or 'detected_desc'")

        where, params = _build_recommendations_where(tenant_id, workspace)
        order_sql = (
            "estimated_monthly_savings DESC NULLS LAST, detected_at DESC, fingerprint"
            if order == "savings_desc"
            else "detected_at DESC, fingerprint"
        )

        sql = f"""
            SELECT
              fc.tenant_id, fc.workspace, fc.fingerprint, fc.check_id, fc.service, fc.severity,
              fc.category, fc.title, fc.estimated_monthly_savings, fc.region, fc.account_id,
              fc.detected_at, fc.effective_state, fc.payload,
              to_jsonb(r) AS run_meta
            FROM finding_current fc
            LEFT JOIN runs r
              ON r.tenant_id = fc.tenant_id
             AND r.workspace = fc.workspace
             AND r.run_id = fc.run_id
            WHERE {' AND '.join(where)}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current fc WHERE {' AND '.join(where)}",
                params,
            )

        items = [_build_recommendation_item(row) for row in rows]
        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": items,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@recommendations_bp.route("/api/recommendations/composite", methods=["GET"])
def api_recommendations_composite() -> Any:
    """Aggregate recommendation opportunities for portfolio-level prioritization.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100)
        offset: Results offset (default 0)
        group_by: Grouping key (recommendation_type, service, check_id, category, region)
        order: Sort order (savings_desc or count_desc)

    Returns:
        Aggregated recommendations by group
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        group_by = (_q("group_by", "recommendation_type") or "recommendation_type").strip().lower()
        group_expr_map = {
            "recommendation_type": _recommendation_type_case_sql(),
            "service": "COALESCE(service, 'unknown')",
            "check_id": "check_id",
            "category": "COALESCE(category, 'unknown')",
            "region": "COALESCE(region, 'unknown')",
        }
        group_expr = group_expr_map.get(group_by)
        if not group_expr:
            raise ValueError("group_by must be one of: recommendation_type, service, check_id, category, region")

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "count_desc"}:
            raise ValueError("order must be 'savings_desc' or 'count_desc'")
        order_sql = "total_monthly_savings DESC NULLS LAST, finding_count DESC, group_key"
        if order == "count_desc":
            order_sql = "finding_count DESC, total_monthly_savings DESC NULLS LAST, group_key"

        where, params = _build_recommendations_where(tenant_id, workspace)
        sql = f"""
            SELECT
              {group_expr} AS group_key,
              COUNT(*)::bigint AS finding_count,
              SUM(COALESCE(estimated_monthly_savings, 0))::double precision AS total_monthly_savings,
              (SUM(COALESCE(estimated_monthly_savings, 0)) * 12.0)::double precision AS total_annual_savings
            FROM finding_current fc
            WHERE {' AND '.join(where)}
            GROUP BY group_key
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        count_sql = f"""
            SELECT COUNT(*) AS n
            FROM (
              SELECT {group_expr} AS group_key
              FROM finding_current fc
              WHERE {' AND '.join(where)}
              GROUP BY group_key
            ) grouped
        """

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(conn, count_sql, params)

        items = []
        for row in rows:
            items.append({
                "group_key": row.get("group_key"),
                "finding_count": int(row.get("finding_count") or 0),
                "total_monthly_savings": _as_float(row.get("total_monthly_savings"), default=0.0),
                "total_annual_savings": _as_float(row.get("total_annual_savings"), default=0.0),
            })

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "group_by": group_by,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": items,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@recommendations_bp.route("/api/recommendations/estimate", methods=["POST"])
@recommendations_bp.route("/api/recommendations/preview", methods=["POST"])
def api_recommendations_estimate() -> Any:
    """Estimate cost/savings for a set of recommendations.

    JSON body:
        tenant_id, workspace, fingerprints: List of finding fingerprints to estimate
        limit, offset, order, state, severity, service, check_id, category, region, account_id, q, min_savings: Optional filters

    Returns:
        Cost/savings estimate for the recommendations
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)

        requested_fingerprints = _coerce_text_list(payload.get("fingerprints"), field_name="fingerprints")

        if "limit" in payload:
            limit = _coerce_positive_int(payload.get("limit"), field_name="limit")
            limit = min(limit, 1000)
        elif requested_fingerprints:
            limit = min(max(1, len(requested_fingerprints)), 1000)
        else:
            limit = 200

        if "offset" in payload:
            offset = _coerce_non_negative_int(payload.get("offset"), field_name="offset")
            offset = min(offset, 5_000_000)
        else:
            offset = 0

        order = str(payload.get("order") or "savings_desc").strip().lower()
        if order not in {"savings_desc", "detected_desc"}:
            raise ValueError("order must be 'savings_desc' or 'detected_desc'")

        where, params = _build_recommendations_where_from_values(
            tenant_id,
            workspace,
            effective_states=_coerce_text_list(payload.get("state", ["open"]), field_name="state"),
            severities=_coerce_text_list(payload.get("severity"), field_name="severity"),
            services=_coerce_text_list(payload.get("service"), field_name="service"),
            check_ids=_coerce_text_list(payload.get("check_id"), field_name="check_id"),
            categories=_coerce_text_list(payload.get("category"), field_name="category"),
            regions=_coerce_text_list(payload.get("region"), field_name="region"),
            account_ids=_coerce_text_list(payload.get("account_id"), field_name="account_id"),
            query_str=_coerce_optional_text(payload.get("q")),
            min_savings=_coerce_optional_float(payload.get("min_savings"), field_name="min_savings"),
            fingerprints=requested_fingerprints,
        )
        order_sql = (
            "estimated_monthly_savings DESC NULLS LAST, detected_at DESC, fingerprint"
            if order == "savings_desc"
            else "detected_at DESC, fingerprint"
        )

        sql = f"""
            SELECT
              fc.tenant_id, fc.workspace, fc.fingerprint, fc.check_id, fc.service, fc.severity,
              fc.category, fc.title, fc.estimated_monthly_savings, fc.region, fc.account_id,
              fc.detected_at, fc.effective_state, fc.payload,
              to_jsonb(r) AS run_meta
            FROM finding_current fc
            LEFT JOIN runs r
              ON r.tenant_id = fc.tenant_id
             AND r.workspace = fc.workspace
             AND r.run_id = fc.run_id
            WHERE {' AND '.join(where)}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current fc WHERE {' AND '.join(where)}",
                params,
            )

        items = [_build_recommendation_item(row) for row in rows]
        total_monthly_savings = round(sum(_as_float(item.get("estimated_monthly_savings")) for item in items), 2)
        total_annual_savings = round(total_monthly_savings * 12.0, 2)
        pricing_versions = sorted(
            {
                str(item.get("pricing_version")).strip()
                for item in items
                if str(item.get("pricing_version") or "").strip()
            }
        )
        pricing_version = "unknown"
        if len(pricing_versions) == 1:
            pricing_version = pricing_versions[0]
        elif len(pricing_versions) > 1:
            pricing_version = "mixed"

        avg_confidence = round(
            sum(int(item.get("confidence") or 0) for item in items) / max(1, len(items)),
            2,
        )
        risk_warnings = _build_estimate_risk_warnings(
            items=items,
            requested_fingerprints=requested_fingerprints,
        )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "mode": "estimate",
                "pricing_version": pricing_version,
                "pricing_versions": pricing_versions,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "selected_count": len(items),
                "totals": {
                    "estimated_monthly_savings": total_monthly_savings,
                    "estimated_annual_savings": total_annual_savings,
                    "average_confidence": avg_confidence,
                },
                "risk_warnings": risk_warnings,
                "items": items,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
