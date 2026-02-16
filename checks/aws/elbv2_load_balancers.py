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

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from checks.aws._common import (
    AwsAccountContext,
    PricingResolver,
    build_scope,
    get_logger,
    is_suppressed,
    money,
    normalize_tags,
    now_utc,
    paginate_items,
    percentile,
    safe_float,
    safe_region_from_client,
)
from checks.aws.defaults import (
    ELBV2_FALLBACK_ALB_HOURLY_USD,
    ELBV2_FALLBACK_NLB_HOURLY_USD,
    ELBV2_IDLE_P95_DAILY_NEW_FLOWS_THRESHOLD,
    ELBV2_IDLE_P95_DAILY_REQUESTS_THRESHOLD,
    ELBV2_LOOKBACK_DAYS,
    ELBV2_MAX_FINDINGS_PER_TYPE,
    ELBV2_MIN_AGE_DAYS,
    ELBV2_MIN_DAILY_DATAPOINTS,
    ELBV2_SUPPRESS_TAG_KEYS,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class ElbV2LoadBalancersConfig:
    """Configuration knobs for :class:`ElbV2LoadBalancersChecker`."""

    lookback_days: int = ELBV2_LOOKBACK_DAYS
    min_daily_datapoints: int = ELBV2_MIN_DAILY_DATAPOINTS

    # Idle thresholds (p95 daily).
    idle_p95_daily_requests_threshold: float = ELBV2_IDLE_P95_DAILY_REQUESTS_THRESHOLD
    idle_p95_daily_new_flows_threshold: float = ELBV2_IDLE_P95_DAILY_NEW_FLOWS_THRESHOLD

    # Ignore very new LBs for orphan/idle.
    min_age_days: int = ELBV2_MIN_AGE_DAYS

    # Tag-based suppression keys (lowercased).
    suppress_tag_keys: tuple[str, ...] = ELBV2_SUPPRESS_TAG_KEYS

    # Safety valve.
    max_findings_per_type: int = ELBV2_MAX_FINDINGS_PER_TYPE


# -----------------------------
# Pricing (best-effort)
# -----------------------------


_FALLBACK_ALB_HOURLY_USD: float = ELBV2_FALLBACK_ALB_HOURLY_USD
_FALLBACK_NLB_HOURLY_USD: float = ELBV2_FALLBACK_NLB_HOURLY_USD


def _resolve_lb_hourly_pricing(ctx: RunContext, *, region: str, lb_type: str) -> tuple[float, str, int]:
    """Best-effort hourly price for ALB/NLB.

    Returns: (usd_per_hour, notes, confidence_0_100)
    """
    return PricingResolver(ctx).resolve_elb_hourly_price(
        region=region,
        lb_type=lb_type,
        fallback_alb_hourly_usd=_FALLBACK_ALB_HOURLY_USD,
        fallback_nlb_hourly_usd=_FALLBACK_NLB_HOURLY_USD,
        call_exceptions=(ClientError, BotoCoreError, AttributeError, TypeError, ValueError),
    )


# -----------------------------
# Error helpers
# -----------------------------


def _client_error_code(exc: ClientError) -> str:
    try:
        return str(exc.response.get("Error", {}).get("Code") or "")
    except (AttributeError, TypeError, ValueError):
        return ""


def _is_access_denied(exc: ClientError) -> bool:
    return _client_error_code(exc) in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }


def _chunk(seq: Sequence[str], size: int) -> Iterator[list[str]]:
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
    p95_value = percentile(vals2, 95.0, method="floor")
    if p95_value is None:
        return 0.0
    return float(p95_value)


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
    ) -> dict[str, list[float]]:
        period = 86400
        stat = "Sum"

        out: dict[str, list[float]] = {v: [] for v in lb_dimension_values}
        if not lb_dimension_values:
            return out

        # get_metric_data supports up to 500 MetricDataQueries.
        # We issue one query per load balancer.
        for batch in _chunk(list(lb_dimension_values), 450):
            queries: list[dict[str, Any]] = []
            id_to_dim: dict[str, str] = {}
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
            except (ClientError, BotoCoreError):
                raise

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
# Logger for this module
_LOGGER = get_logger("elbv2_load_balancers")


class ElbV2LoadBalancersChecker:
    """ALB/NLB (ELBv2) checker."""

    checker_id = "aws.elbv2.load.balancers"

    _CHECK_NAME = "ALB/NLB load balancers"

    def __init__(
        self,
        *,
        account_id: str,
        billing_account_id: str | None = None,
        partition: str = "aws",
        cfg: ElbV2LoadBalancersConfig | None = None,
    ) -> None:
        self._account = AwsAccountContext(
            account_id=str(account_id or ""),
            billing_account_id=str(billing_account_id) if billing_account_id else None,
            partition=str(partition or "aws"),
        )
        self._cfg = cfg or ElbV2LoadBalancersConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting ELBv2 load balancers check")
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
        _LOGGER.debug("ELBv2 check running", extra={"region": region})

        # Inventory
        try:
            lbs = list(
                paginate_items(
                    elbv2,
                    "describe_load_balancers",
                    "LoadBalancers",
                    paginator_fallback_exceptions=(AttributeError, KeyError, TypeError, ValueError),
                    request_token_key="Marker",
                    response_token_keys=("NextMarker", "Marker"),
                )
            )
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            yield FindingDraft(
                check_id="aws.elbv2.load.balancers.access.error",
                check_name=self._CHECK_NAME,
                category="governance",
                status="unknown",
                severity=Severity(level="medium", score=55),
                title="Unable to list load balancers",
                scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                message=f"Unable to list ELBv2 load balancers ({code or type(exc).__name__}).",
                issue_key={"check_id": "aws.elbv2.load.balancers.access.error", "region": region},
            )
            return

        if not lbs:
            return
        _LOGGER.info("Listed ELBv2 load balancers", extra={"count": len(lbs), "region": region})
        # Tags (DescribeTags: max 20 ARNs per call)
        lb_arns = [str(lb.get("LoadBalancerArn") or "") for lb in lbs if lb.get("LoadBalancerArn")]

        # Track IAM gaps once per operation (do not spam per resource).
        iam_denied: set[str] = set()

        tags_by_arn: dict[str, dict[str, str]] = {}
        for batch in _chunk(lb_arns, 20):
            try:
                resp = elbv2.describe_tags(ResourceArns=batch)
            except ClientError as exc:
                if _is_access_denied(exc) and "elbv2:DescribeTags" not in iam_denied:
                    iam_denied.add("elbv2:DescribeTags")
                    yield FindingDraft(
                        check_id="aws.elbv2.load.balancers.missing.permission",
                        check_name=self._CHECK_NAME,
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title="Missing ELB permission for tags",
                        scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                        message="Access denied on elbv2:DescribeTags. Suppression tags may not be applied.",
                        recommendation="Grant elasticloadbalancing:DescribeTags to the scanner role.",
                        issue_key={"check_id": "aws.elbv2.load.balancers.missing.permission", "op": "DescribeTags", "region": region},
                    )
                    continue
                raise
            except BotoCoreError:
                raise

            for td in resp.get("TagDescriptions", []) or []:
                arn = str(td.get("ResourceArn") or "")
                tags_by_arn[arn] = normalize_tags(td.get("Tags", []) or [])

        now = now_utc()
        min_age = timedelta(days=int(cfg.min_age_days))
        start = now - timedelta(days=int(cfg.lookback_days))
        end = now

        cw_fetcher = _ElbCloudWatch(cw) if cw is not None else None

        # Build CloudWatch series for ALB and NLB separately.
        alb_dims: list[str] = []
        nlb_dims: list[str] = []
        dim_by_arn: dict[str, str] = {}

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

        alb_series: dict[str, list[float]] = {}
        nlb_series: dict[str, list[float]] = {}
        if cw_fetcher is not None and cfg.lookback_days > 0:
            try:
                alb_series = cw_fetcher.daily_metric(
                    namespace="AWS/ApplicationELB",
                    metric_name="RequestCount",
                    lb_dimension_values=alb_dims,
                    start=start,
                    end=end,
                )
            except ClientError as exc:
                if _is_access_denied(exc) and "cloudwatch:GetMetricData" not in iam_denied:
                    iam_denied.add("cloudwatch:GetMetricData")
                    yield FindingDraft(
                        check_id="aws.elbv2.load.balancers.missing.permission",
                        check_name=self._CHECK_NAME,
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title="Missing CloudWatch permission for ELB metrics",
                        scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                        message="Access denied on cloudwatch:GetMetricData. Idle detection will be skipped.",
                        recommendation="Grant cloudwatch:GetMetricData to the scanner role.",
                        issue_key={"check_id": "aws.elbv2.load.balancers.missing.permission", "op": "GetMetricData", "region": region},
                    )
                else:
                    raise

            try:
                nlb_series = cw_fetcher.daily_metric(
                    namespace="AWS/NetworkELB",
                    metric_name="NewFlowCount",
                    lb_dimension_values=nlb_dims,
                    start=start,
                    end=end,
                )
            except ClientError as exc:
                if _is_access_denied(exc) and "cloudwatch:GetMetricData" not in iam_denied:
                    iam_denied.add("cloudwatch:GetMetricData")
                    yield FindingDraft(
                        check_id="aws.elbv2.load.balancers.missing.permission",
                        check_name=self._CHECK_NAME,
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title="Missing CloudWatch permission for ELB metrics",
                        scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                        message="Access denied on cloudwatch:GetMetricData. Idle detection will be skipped.",
                        recommendation="Grant cloudwatch:GetMetricData to the scanner role.",
                        issue_key={"check_id": "aws.elbv2.load.balancers.missing.permission", "op": "GetMetricData", "region": region},
                    )
                else:
                    raise

        emitted: dict[str, int] = {
            "idle": 0,
            "orphan_no_listeners": 0,
            "orphan_no_targets": 0,
            "no_healthy_targets": 0,
        }

        # Pre-fetch listeners and target groups (maps keyed by LB ARN)
        listeners_by_lb: dict[str, list[dict[str, Any]]] = {}
        for lb_arn in lb_arns:
            try:
                listeners = list(
                    paginate_items(
                        elbv2,
                        "describe_listeners",
                        "Listeners",
                        params={"LoadBalancerArn": lb_arn},
                        paginator_fallback_exceptions=(AttributeError, KeyError, TypeError, ValueError),
                        request_token_key="Marker",
                        response_token_keys=("NextMarker", "Marker"),
                    )
                )
            except ClientError as exc:
                if _is_access_denied(exc) and "elbv2:DescribeListeners" not in iam_denied:
                    iam_denied.add("elbv2:DescribeListeners")
                    yield FindingDraft(
                        check_id="aws.elbv2.load.balancers.missing.permission",
                        check_name=self._CHECK_NAME,
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title="Missing ELB permission for listeners",
                        scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                        message="Access denied on elbv2:DescribeListeners. Listener-based checks may be incomplete.",
                        recommendation="Grant elasticloadbalancing:DescribeListeners to the scanner role.",
                        issue_key={"check_id": "aws.elbv2.load.balancers.missing.permission", "op": "DescribeListeners", "region": region},
                    )
                    listeners = []
                else:
                    raise
            except BotoCoreError:
                raise
            listeners_by_lb[lb_arn] = listeners

        tgs_by_lb: dict[str, list[dict[str, Any]]] = {}
        for lb_arn in lb_arns:
            try:
                tgs = list(
                    paginate_items(
                        elbv2,
                        "describe_target_groups",
                        "TargetGroups",
                        params={"LoadBalancerArn": lb_arn},
                        paginator_fallback_exceptions=(AttributeError, KeyError, TypeError, ValueError),
                        request_token_key="Marker",
                        response_token_keys=("NextMarker", "Marker"),
                    )
                )
            except ClientError as exc:
                if _is_access_denied(exc) and "elbv2:DescribeTargetGroups" not in iam_denied:
                    iam_denied.add("elbv2:DescribeTargetGroups")
                    yield FindingDraft(
                        check_id="aws.elbv2.load.balancers.missing.permission",
                        check_name=self._CHECK_NAME,
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title="Missing ELB permission for target groups",
                        scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                        message="Access denied on elbv2:DescribeTargetGroups. Target-group checks may be incomplete.",
                        recommendation="Grant elasticloadbalancing:DescribeTargetGroups to the scanner role.",
                        issue_key={"check_id": "aws.elbv2.load.balancers.missing.permission", "op": "DescribeTargetGroups", "region": region},
                    )
                    tgs = []
                else:
                    raise
            except BotoCoreError:
                raise
            tgs_by_lb[lb_arn] = tgs

        # Helper: resolve referenced TG ARNs from listener actions
        def _listener_tg_arns(listener: Mapping[str, Any]) -> set[str]:
            out: set[str] = set()
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

            created: datetime | None = lb.get("CreatedTime") if isinstance(lb.get("CreatedTime"), datetime) else None
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
                        check_id="aws.elbv2.load.balancers.no.listeners",
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
                        issue_key={"check_id": "aws.elbv2.load.balancers.no.listeners", "lb_arn": arn},
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
                    check_id="aws.elbv2.load.balancers.idle",
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
                    issue_key={"check_id": "aws.elbv2.load.balancers.idle", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )

            # Orphaned targets / unhealthy targets (best-effort)
            # Determine referenced TGs from listener actions and inspect target health.
            referenced_tgs: set[str] = set()
            for listener in listeners:
                referenced_tgs |= _listener_tg_arns(listener)

            if not referenced_tgs:
                # No forward target groups referenced.
                continue

            # Target groups inventory for the LB
            tg_by_arn: dict[str, dict[str, Any]] = {str(tg.get("TargetGroupArn") or ""): tg for tg in tgs_by_lb.get(arn, [])}

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
                except ClientError as exc:
                    code = _client_error_code(exc)
                    if code == "TargetGroupNotFound":
                        # Resource changed during scan.
                        continue
                    if _is_access_denied(exc) and "elbv2:DescribeTargetHealth" not in iam_denied:
                        iam_denied.add("elbv2:DescribeTargetHealth")
                        yield FindingDraft(
                            check_id="aws.elbv2.load.balancers.missing.permission",
                            check_name=self._CHECK_NAME,
                            category="governance",
                            status="info",
                            severity=Severity(level="low", score=20),
                            title="Missing ELB permission for target health",
                            scope=build_scope(ctx, account=self._account, region=region, service="elbv2"),
                            message=(
                                "Access denied on elbv2:DescribeTargetHealth. "
                                "Target health checks may be incomplete."
                            ),
                            recommendation="Grant elasticloadbalancing:DescribeTargetHealth to the scanner role.",
                            issue_key={
                                "check_id": "aws.elbv2.load.balancers.missing.permission",
                                "op": "DescribeTargetHealth",
                                "region": region,
                            },
                        )
                        continue
                    raise
                except BotoCoreError:
                    raise

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
                    check_id="aws.elbv2.load.balancers.no.registered.targets",
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
                    issue_key={"check_id": "aws.elbv2.load.balancers.no.registered.targets", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )

            if any_targets and not any_healthy and emitted["no_healthy_targets"] < cfg.max_findings_per_type:
                emitted["no_healthy_targets"] += 1
                yield FindingDraft(
                    check_id="aws.elbv2.load.balancers.no.healthy.targets",
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
                    issue_key={"check_id": "aws.elbv2.load.balancers.no.healthy.targets", "lb_arn": arn},
                    dimensions={"lb_type": lb_type, "scheme": scheme},
                )


@register_checker("checks.aws.elbv2_load_balancers:ElbV2LoadBalancersChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("aws_account_id") or "")
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
