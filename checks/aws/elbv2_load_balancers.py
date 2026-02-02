"""checks/aws/elbv2_load_balancers.py

ALB/NLB (ELBv2) cost + hygiene checker.

Signals (cost / optimization)
----------------------------
1) Idle load balancers (best-effort via CloudWatch)
   - ALB: low p95 daily RequestCount over a lookback window.
   - NLB: low p95 daily NewFlowCount over a lookback window.

2) Orphaned / misconfigured load balancers (best-effort)
   - No listeners.
   - Has listeners but no registered targets in referenced target groups.

Signals (governance / reliability)
---------------------------------
3) Target groups with no healthy targets (best-effort)
   - All targets are unhealthy or the target group has zero targets.

Notes
-----
- Uses ELBv2 APIs for inventory (DescribeLoadBalancers / DescribeListeners /
  DescribeTargetGroups / DescribeTargetHealth / DescribeTags).
- Uses CloudWatch metrics to estimate utilization. These are directional signals.
- Estimates use PricingService only for hourly baseline where possible; LCU usage
  is not estimated here (CUR enrichment is expected downstream).
- This checker runs in the region configured by ``ctx.services.elbv2``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, cast

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    is_suppressed,
    money,
    normalize_tags,
    now_utc,
    safe_float,
    safe_region_from_client,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class ElbV2LoadBalancersConfig:
    """Configuration knobs for :class:`ElbV2LoadBalancersChecker`."""

    lookback_days: int = 14
    min_daily_datapoints: int = 7

    # Idle thresholds (p95 daily).
    idle_p95_daily_requests_threshold: float = 1.0
    idle_p95_daily_new_flows_threshold: float = 1.0

    # Ignore very new LBs for orphan/idle.
    min_age_days: int = 2

    # Tag-based suppression keys (lowercased).
    suppress_tag_keys: Tuple[str, ...] = ("finops:ignore", "do-not-delete", "keep")

    # Safety valve.
    max_findings_per_type: int = 50_000


# -----------------------------
# Pricing (best-effort)
# -----------------------------


_FALLBACK_ALB_HOURLY_USD: float = 0.025
_FALLBACK_NLB_HOURLY_USD: float = 0.0225


def _pricing_service(ctx: RunContext) -> Any:
    return getattr(getattr(ctx, "services", None), "pricing", None)


def _resolve_lb_hourly_pricing(ctx: RunContext, *, region: str, lb_type: str) -> Tuple[float, str, int]:
    """Best-effort hourly price for ALB/NLB.

    Returns: (usd_per_hour, notes, confidence_0_100)
    """
    fallback = _FALLBACK_ALB_HOURLY_USD if lb_type == "application" else _FALLBACK_NLB_HOURLY_USD
    pricing = _pricing_service(ctx)
    if pricing is None:
        return fallback, "PricingService unavailable; using fallback pricing.", 30

    location = ""
    try:
        location = str(pricing.location_for_region(region) or "")
    except Exception:
        location = ""
    if not location:
        return fallback, "Pricing region mapping missing; using fallback pricing.", 30

    # ELB pricing is in AmazonEC2 pricing catalog.
    # Attributes vary; try a few reasonable filter sets.
    attempts: List[List[Dict[str, str]]] = []
    if lb_type == "application":
        attempts = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Load Balancer"},
                {"Field": "group", "Value": "Application Load Balancer"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "usagetype", "Value": "LoadBalancerUsage"},
            ],
        ]
    else:
        attempts = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Load Balancer"},
                {"Field": "group", "Value": "Network Load Balancer"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "usagetype", "Value": "NetworkLoadBalancerUsage"},
            ],
        ]

    hourly: Optional[float] = None
    for filters in attempts:
        try:
            quote = pricing.get_on_demand_unit_price(service_code="AmazonEC2", filters=filters, unit="Hrs")
        except Exception:
            quote = None
        if quote is None:
            continue
        try:
            hourly = float(getattr(quote, "unit_price", None) or getattr(quote, "price", None) or 0.0)
        except Exception:
            hourly = None
        if hourly and hourly > 0.0:
            return float(hourly), "on-demand hourly price resolved via PricingService", 60

    return float(fallback), "using fallback pricing", 30


# -----------------------------
# Pagination helpers
# -----------------------------


def _paginate_items(
    client: BaseClient,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    params = dict(params or {})

    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**params):
                for item in page.get(result_key, []) or []:
                    if isinstance(item, dict):
                        yield item
            return
        except Exception:
            pass

    next_marker: Optional[str] = None
    while True:
        call = getattr(client, operation, None)
        if call is None:
            raise AttributeError(f"client has no operation {operation}")
        req = dict(params)
        if next_marker:
            req["Marker"] = next_marker
        resp = call(**req) if req else call()
        for item in resp.get(result_key, []) or []:
            if isinstance(item, dict):
                yield item
        next_marker = cast(Optional[str], resp.get("NextMarker") or resp.get("Marker"))
        if not next_marker:
            break


def _chunk(seq: Sequence[str], size: int) -> Iterator[List[str]]:
    i = 0
    while i < len(seq):
        yield list(seq[i : i + size])
        i += size


# -----------------------------
# CloudWatch batching
# -----------------------------


def _lb_metric_dimension_value(lb_arn: str) -> str:
    """Extract CloudWatch 'LoadBalancer' dimension value from an LB ARN."""
    marker = "loadbalancer/"
    if marker not in lb_arn:
        return lb_arn
    return lb_arn.split(marker, 1)[1]


def _p95(values: Sequence[float]) -> float:
    vals = [safe_float(v) for v in values if safe_float(v) is not None]
    vals2 = [v for v in vals if v is not None]
    if not vals2:
        return 0.0
    vals2.sort()
    idx = int(0.95 * (len(vals2) - 1))
    return float(vals2[idx])


class _ElbCloudWatch:
    """Batch CloudWatch fetcher for ELBv2 utilization."""

    def __init__(self, cw: Any) -> None:
        self._cw = cw

    def daily_metric(
        self,
        *,
        namespace: str,
        metric_name: str,
        lb_dimension_values: Sequence[str],
        start: datetime,
        end: datetime,
    ) -> Dict[str, List[float]]:
        period = 86400
        stat = "Sum"

        out: Dict[str, List[float]] = {v: [] for v in lb_dimension_values}
        if not lb_dimension_values:
            return out

        # get_metric_data supports up to 500 MetricDataQueries.
        # We issue one query per load balancer.
        for batch in _chunk(list(lb_dimension_values), 450):
            queries: List[Dict[str, Any]] = []
            id_to_dim: Dict[str, str] = {}
            for i, dim_val in enumerate(batch):
                qid = f"m{i}"
                id_to_dim[qid] = dim_val
                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                            },
                            "Period": period,
                            "Stat": stat,
                        },
                        "ReturnData": True,
                    }
                )

            try:
                resp = self._cw.get_metric_data(
                    MetricDataQueries=queries,
                    StartTime=start,
                    EndTime=end,
                    ScanBy="TimestampAscending",
                )
            except Exception:
                continue

            for r in resp.get("MetricDataResults", []) or []:
                rid = str(r.get("Id") or "")
                dim_val = id_to_dim.get(rid)
                if not dim_val:
                    continue
                vals = r.get("Values", []) or []
                if isinstance(vals, list):
                    out[dim_val].extend([safe_float(v) or 0.0 for v in vals])

        return out


# -----------------------------
# Checker
# -----------------------------


class ElbV2LoadBalancersChecker:
    """ALB/NLB (ELBv2) checker."""

    checker_id = "aws.elbv2.load_balancers"

    _CHECK_NAME = "ALB/NLB load balancers"

    def __init__(
        self,
        *,
        account_id: str,
        billing_account_id: Optional[str] = None,
        partition: str = "aws",
        cfg: Optional[ElbV2LoadBalancersConfig] = None,
    ) -> None:
        self._account = AwsAccountContext(
            account_id=str(account_id or ""),
            billing_account_id=str(billing_account_id) if billing_account_id else None,
            partition=str(partition or "aws"),
        )
        self._cfg = cfg or ElbV2LoadBalancersConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        cfg = self._cfg

        services = getattr(ctx, "services", None)
        if services is None:
            raise RuntimeError("RunContext.services is required")

        elbv2 = getattr(services, "elbv2", None)
        if elbv2 is None:
            raise RuntimeError("ElbV2LoadBalancersChecker requires ctx.services.elbv2")

        cw = getattr(services, "cloudwatch", None)
        region = safe_region_from_client(elbv2) or str(getattr(services, "region", "") or "")
        if not region:
            region = "unknown"

        # Inventory
        try:
            lbs = list(_paginate_items(elbv2, "describe_load_balancers", "LoadBalancers"))
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            yield FindingDraft(
                check_id="aws.elbv2.load_balancers.access_error",
                check_name=self._CHECK_NAME,
                category="governance",
                status="unknown",
                severity=Severity(level="medium", score=55),
                title="Unable to list load balancers",
                scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                message=f"Unable to list ELBv2 load balancers ({code or type(exc).__name__}).",
                issue_key={"check_id": "aws.elbv2.load_balancers.access_error", "region": region},
            )
            return

        if not lbs:
            return

        # Tags (DescribeTags: max 20 ARNs per call)
        lb_arns = [str(lb.get("LoadBalancerArn") or "") for lb in lbs if lb.get("LoadBalancerArn")]
        tags_by_arn: Dict[str, Dict[str, str]] = {}
        for batch in _chunk(lb_arns, 20):
            try:
                resp = elbv2.describe_tags(ResourceArns=batch)
            except Exception:
                continue
            for td in resp.get("TagDescriptions", []) or []:
                arn = str(td.get("ResourceArn") or "")
                tags_by_arn[arn] = normalize_tags(td.get("Tags", []) or [])

        now = now_utc()
        min_age = timedelta(days=int(cfg.min_age_days))
        start = now - timedelta(days=int(cfg.lookback_days))
        end = now

        cw_fetcher = _ElbCloudWatch(cw) if cw is not None else None

        # Build CloudWatch series for ALB and NLB separately.
        alb_dims: List[str] = []
        nlb_dims: List[str] = []
        dim_by_arn: Dict[str, str] = {}

        for lb in lbs:
            arn = str(lb.get("LoadBalancerArn") or "")
            if not arn:
                continue
            dim_val = _lb_metric_dimension_value(arn)
            dim_by_arn[arn] = dim_val
            lb_type = str(lb.get("Type") or "")
            if lb_type == "application":
                alb_dims.append(dim_val)
            elif lb_type == "network":
                nlb_dims.append(dim_val)

        alb_series: Dict[str, List[float]] = {}
        nlb_series: Dict[str, List[float]] = {}
        if cw_fetcher is not None and cfg.lookback_days > 0:
            alb_series = cw_fetcher.daily_metric(
                namespace="AWS/ApplicationELB",
                metric_name="RequestCount",
                lb_dimension_values=alb_dims,
                start=start,
                end=end,
            )
            nlb_series = cw_fetcher.daily_metric(
                namespace="AWS/NetworkELB",
                metric_name="NewFlowCount",
                lb_dimension_values=nlb_dims,
                start=start,
                end=end,
            )

        emitted: Dict[str, int] = {
            "idle": 0,
            "orphan_no_listeners": 0,
            "orphan_no_targets": 0,
            "no_healthy_targets": 0,
        }

        # Pre-fetch listeners and target groups (maps keyed by LB ARN)
        listeners_by_lb: Dict[str, List[Dict[str, Any]]] = {}
        for lb_arn in lb_arns:
            try:
                listeners = list(
                    _paginate_items(
                        elbv2,
                        "describe_listeners",
                        "Listeners",
                        params={"LoadBalancerArn": lb_arn},
                    )
                )
            except Exception:
                listeners = []
            listeners_by_lb[lb_arn] = listeners

        tgs_by_lb: Dict[str, List[Dict[str, Any]]] = {}
        for lb_arn in lb_arns:
            try:
                tgs = list(
                    _paginate_items(
                        elbv2,
                        "describe_target_groups",
                        "TargetGroups",
                        params={"LoadBalancerArn": lb_arn},
                    )
                )
            except Exception:
                tgs = []
            tgs_by_lb[lb_arn] = tgs

        # Helper: resolve referenced TG ARNs from listener actions
        def _listener_tg_arns(listener: Mapping[str, Any]) -> Set[str]:
            out: Set[str] = set()
            for act in listener.get("DefaultActions", []) or []:
                if not isinstance(act, dict):
                    continue
                if str(act.get("Type") or "") != "forward":
                    continue
                tg_arn = act.get("TargetGroupArn")
                if tg_arn:
                    out.add(str(tg_arn))
                fwd = act.get("ForwardConfig")
                if isinstance(fwd, dict):
                    for tg in fwd.get("TargetGroups", []) or []:
                        if isinstance(tg, dict) and tg.get("TargetGroupArn"):
                            out.add(str(tg.get("TargetGroupArn")))
            return out

        # Main evaluation loop
        for lb in lbs:
            arn = str(lb.get("LoadBalancerArn") or "")
            if not arn:
                continue

            tags = tags_by_arn.get(arn, {})
            if is_suppressed(tags, suppress_keys=set(cfg.suppress_tag_keys)):
                continue

            created: Optional[datetime] = lb.get("CreatedTime") if isinstance(lb.get("CreatedTime"), datetime) else None
            if created is not None and (now - created) < min_age:
                # too new
                continue

            lb_type = str(lb.get("Type") or "")
            scheme = str(lb.get("Scheme") or "")
            lb_name = str(lb.get("LoadBalancerName") or "")
            dim_val = dim_by_arn.get(arn, arn)

            # Pricing (hourly baseline only)
            hourly_usd, pricing_notes, pricing_conf = _resolve_lb_hourly_pricing(ctx, region=region, lb_type=lb_type)
            monthly_cost = money(hourly_usd * 24.0 * 30.0)

            scope = build_scope(ctx, account=self._account, region=region, service="elbv2", resource_id=lb_name)

            listeners = listeners_by_lb.get(arn, [])
            if not listeners:
                if emitted["orphan_no_listeners"] < cfg.max_findings_per_type:
                    emitted["orphan_no_listeners"] += 1
                    yield FindingDraft(
                        check_id="aws.elbv2.load_balancers.no_listeners",
                        check_name=self._CHECK_NAME,
                        category="cost",
                        status="fail",
                        severity=Severity(level="high", score=75),
                        title="Load balancer has no listeners",
                        scope=scope,
                        message=(
                            f"Load balancer '{lb_name}' ({lb_type}, {scheme}) has no listeners. "
                            "It may be unused or misconfigured."
                        ),
                        recommendation="Delete the load balancer if it is no longer needed.",
                        estimated_monthly_cost=monthly_cost,
                        estimate_confidence=pricing_conf,
                        estimate_notes=pricing_notes,
                        tags=tags,
                        issue_key={"check_id": "aws.elbv2.load_balancers.no_listeners", "lb_arn": arn},
                        dimensions={"lb_type": lb_type, "scheme": scheme},
                    )
                continue

            # Idle detection (best-effort)
            p95_val = 0.0
            if lb_type == "application":
                p95_val = _p95(alb_series.get(dim_val, []))
                is_idle = p95_val <= float(cfg.idle_p95_daily_requests_threshold)
            elif lb_type == "network":
                p95_val = _p95(nlb_series.get(dim_val, []))
                is_idle = p95_val <= float(cfg.idle_p95_daily_new_flows_threshold)
            else:
                is_idle = False

            if is_idle and emitted["idle"] < cfg.max_findings_per_type:
                emitted["idle"] += 1
                metric = "RequestCount" if lb_type == "application" else "NewFlowCount"
                yield FindingDraft(
                    check_id="aws.elbv2.load_balancers.idle",
                    check_name=self._CHECK_NAME,
                    category="cost",
                    status="fail",
                    severity=Severity(level="medium", score=60),
                    title="Idle load balancer",
                    scope=scope,
                    message=(
                        f"Load balancer '{lb_name}' ({lb_type}, {scheme}) appears idle: "
                        f"p95 daily {metric} ≈ {p95_val:.2f} over last {cfg.lookback_days} days."
                    ),
                    recommendation="Confirm usage with application owners, then delete the load balancer if unused.",
                    estimated_monthly_savings=monthly_cost,
                    estimate_confidence=pricing_conf,
                    estimate_notes=pricing_notes,
                    tags=tags,
                    issue_key={"check_id": "aws.elbv2.load_balancers.idle", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )

            # Orphaned targets / unhealthy targets (best-effort)
            # Determine referenced TGs from listener actions and inspect target health.
            referenced_tgs: Set[str] = set()
            for l in listeners:
                referenced_tgs |= _listener_tg_arns(l)

            if not referenced_tgs:
                # No forward target groups referenced.
                continue

            # Target groups inventory for the LB
            tg_by_arn: Dict[str, Dict[str, Any]] = {str(tg.get("TargetGroupArn") or ""): tg for tg in tgs_by_lb.get(arn, [])}

            any_targets = False
            any_healthy = False
            for tg_arn in referenced_tgs:
                tg = tg_by_arn.get(tg_arn)
                if not tg:
                    continue
                target_type = str(tg.get("TargetType") or "")

                # Lambda target groups can look empty in target health API; skip to avoid false positives.
                if target_type == "lambda":
                    continue

                try:
                    th = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                except Exception:
                    continue

                desc = th.get("TargetHealthDescriptions", []) or []
                if desc:
                    any_targets = True
                for d in desc:
                    st = str(((d or {}).get("TargetHealth") or {}).get("State") or "")
                    if st == "healthy":
                        any_healthy = True

            if not any_targets and emitted["orphan_no_targets"] < cfg.max_findings_per_type:
                emitted["orphan_no_targets"] += 1
                yield FindingDraft(
                    check_id="aws.elbv2.load_balancers.no_registered_targets",
                    check_name=self._CHECK_NAME,
                    category="cost",
                    status="fail",
                    severity=Severity(level="high", score=75),
                    title="Load balancer has no registered targets",
                    scope=scope,
                    message=(
                        f"Load balancer '{lb_name}' references target groups but no targets are registered "
                        "(best-effort). It may be unused or misconfigured."
                    ),
                    recommendation="Register targets or delete the load balancer if it is no longer needed.",
                    estimated_monthly_savings=monthly_cost,
                    estimate_confidence=pricing_conf,
                    estimate_notes=pricing_notes,
                    tags=tags,
                    issue_key={"check_id": "aws.elbv2.load_balancers.no_registered_targets", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )

            if any_targets and not any_healthy and emitted["no_healthy_targets"] < cfg.max_findings_per_type:
                emitted["no_healthy_targets"] += 1
                yield FindingDraft(
                    check_id="aws.elbv2.load_balancers.no_healthy_targets",
                    check_name=self._CHECK_NAME,
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=75),
                    title="Load balancer has no healthy targets",
                    scope=scope,
                    message=(
                        f"Load balancer '{lb_name}' has registered targets but none are healthy (best-effort). "
                        "This may indicate misconfiguration or downtime."
                    ),
                    recommendation="Investigate target group health checks, security groups, and target configuration.",
                    tags=tags,
                    issue_key={"check_id": "aws.elbv2.load_balancers.no_healthy_targets", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )


@register_checker("checks.aws.elbv2_load_balancers:ElbV2LoadBalancersChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("account_id") or "")
    billing_id = str(bootstrap.get("billing_account_id") or "") or None
    partition = str(bootstrap.get("partition") or "aws")

    # Config defaults for now; could be wired to bootstrap later.
    cfg = ElbV2LoadBalancersConfig()
    return ElbV2LoadBalancersChecker(
        account_id=account_id,
        billing_account_id=billing_id,
        partition=partition,
        cfg=cfg,
    )
