"""checks/aws/cloudwatch_metrics_logs_cost.py

CloudWatch Metrics & Logs cost/hygiene checker.

This checker intentionally focuses on **signals** (facts) that can later be
interpreted by correlation rules.

Signals (cost / hygiene):
1) CloudWatch Logs log groups with no retention policy ("Never expire")
2) CloudWatch Logs metric filters that create custom metrics
3) CloudWatch alarms count (account/region signal)

Design notes
------------
- Avoids per-resource CloudWatch metric reads (expensive).
- Uses paginator-based inventory to stay O(n) and resilient.
- Emits informational findings on AccessDenied to avoid hiding IAM gaps.
- Keeps estimates best-effort (PricingService if present, conservative fallbacks otherwise).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from botocore.exceptions import BotoCoreError, ClientError

import checks.aws._common as common
from checks.aws._common import AwsAccountContext, build_scope, get_logger
from checks.aws.defaults import (
    CLOUDWATCH_ALARMS_COUNT_WARN_THRESHOLD,
    CLOUDWATCH_FALLBACK_USD_PER_ALARM_MONTH,
    CLOUDWATCH_FALLBACK_USD_PER_CUSTOM_METRIC_MONTH,
    CLOUDWATCH_MAX_CUSTOM_METRIC_FINDINGS,
    CLOUDWATCH_MIN_CUSTOM_METRICS_FOR_SIGNAL,
    CLOUDWATCH_REQUIRE_RETENTION_POLICY,
    CLOUDWATCH_SUPPRESS_TAG_KEYS,
    CLOUDWATCH_SUPPRESS_TAG_VALUES,
    CLOUDWATCH_SUPPRESS_VALUE_PREFIXES,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

# Logger for this module
_LOGGER = get_logger("cloudwatch_metrics_logs_cost")


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class CloudWatchMetricsLogsCostConfig:
    """Configuration for CloudWatch Metrics & Logs cost checker."""

    # Log groups
    require_retention_policy: bool = CLOUDWATCH_REQUIRE_RETENTION_POLICY
    suppress_tag_keys: Tuple[str, ...] = CLOUDWATCH_SUPPRESS_TAG_KEYS
    suppress_tag_values: Tuple[str, ...] = CLOUDWATCH_SUPPRESS_TAG_VALUES
    suppress_value_prefixes: Tuple[str, ...] = CLOUDWATCH_SUPPRESS_VALUE_PREFIXES

    # Custom metrics
    min_custom_metrics_for_signal: int = CLOUDWATCH_MIN_CUSTOM_METRICS_FOR_SIGNAL
    max_custom_metric_findings: int = CLOUDWATCH_MAX_CUSTOM_METRIC_FINDINGS

    # Alarms
    alarms_count_warn_threshold: int = CLOUDWATCH_ALARMS_COUNT_WARN_THRESHOLD


# -----------------------------
# Pricing (best-effort)
# -----------------------------


_FALLBACK_USD_PER_CUSTOM_METRIC_MONTH: float = CLOUDWATCH_FALLBACK_USD_PER_CUSTOM_METRIC_MONTH
_FALLBACK_USD_PER_ALARM_MONTH: float = CLOUDWATCH_FALLBACK_USD_PER_ALARM_MONTH


def _pricing_service(ctx: RunContext) -> Any:
    return getattr(getattr(ctx, "services", None), "pricing", None)


def _resolve_custom_metric_price_usd_per_month(ctx: RunContext, *, region: str) -> tuple[float, str, int]:
    """Resolve custom metric unit price (USD per metric-month) best-effort."""

    pricing = _pricing_service(ctx)
    if pricing is None:
        return (
            _FALLBACK_USD_PER_CUSTOM_METRIC_MONTH,
            "PricingService unavailable; using fallback pricing.",
            30,
        )

    location_for_region = getattr(pricing, "location_for_region", None)
    get_price = getattr(pricing, "get_on_demand_unit_price", None)
    if not callable(location_for_region) or not callable(get_price):
        return (
            _FALLBACK_USD_PER_CUSTOM_METRIC_MONTH,
            "PricingService missing expected methods; using fallback pricing.",
            30,
        )

    location = ""
    try:
        location = str(location_for_region(region) or "")
    except (TypeError, ValueError, AttributeError):
        location = ""

    if not location:
        return (
            _FALLBACK_USD_PER_CUSTOM_METRIC_MONTH,
            "Pricing region mapping missing; using fallback pricing.",
            30,
        )

    attempts: List[List[Dict[str, str]]] = [
        [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "Metric"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "group", "Value": "AWS-CustomMetrics"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "usagetype", "Value": "CW:Metric"},
        ],
    ]

    for filters in attempts:
        try:
            quote = get_price(service_code="AmazonCloudWatch", filters=filters, unit="Each")
            unit_price = float(getattr(quote, "unit_price_usd", getattr(quote, "unit_price", 0.0)))
            if unit_price > 0.0:
                return (unit_price, "PricingService resolved custom metric unit price.", 70)
        except (ClientError, BotoCoreError, TypeError, ValueError):
            continue

    return (
        _FALLBACK_USD_PER_CUSTOM_METRIC_MONTH,
        "Pricing lookup failed; using fallback pricing.",
        30,
    )


def _resolve_alarm_price_usd_per_month(ctx: RunContext, *, region: str) -> tuple[float, str, int]:
    """Resolve alarm unit price (USD per alarm-month) best-effort."""

    pricing = _pricing_service(ctx)
    if pricing is None:
        return (
            _FALLBACK_USD_PER_ALARM_MONTH,
            "PricingService unavailable; using fallback pricing.",
            30,
        )

    location_for_region = getattr(pricing, "location_for_region", None)
    get_price = getattr(pricing, "get_on_demand_unit_price", None)
    if not callable(location_for_region) or not callable(get_price):
        return (
            _FALLBACK_USD_PER_ALARM_MONTH,
            "PricingService missing expected methods; using fallback pricing.",
            30,
        )

    try:
        location = str(location_for_region(region) or "")
    except (TypeError, ValueError, AttributeError):
        location = ""

    if not location:
        return (
            _FALLBACK_USD_PER_ALARM_MONTH,
            "Pricing region mapping missing; using fallback pricing.",
            30,
        )

    attempts: List[List[Dict[str, str]]] = [
        [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "Alarm"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "group", "Value": "AWS-Alarms"},
        ],
    ]

    for filters in attempts:
        try:
            quote = get_price(service_code="AmazonCloudWatch", filters=filters, unit="Each")
            unit_price = float(getattr(quote, "unit_price_usd", getattr(quote, "unit_price", 0.0)))
            if unit_price > 0.0:
                return (unit_price, "PricingService resolved alarm unit price.", 70)
        except (ClientError, BotoCoreError, TypeError, ValueError):
            continue

    return (
        _FALLBACK_USD_PER_ALARM_MONTH,
        "Pricing lookup failed; using fallback pricing.",
        30,
    )


# -----------------------------
# Helpers
# -----------------------------


def _is_access_denied(exc: ClientError) -> bool:
    try:
        code = str(exc.response.get("Error", {}).get("Code", ""))
    except (TypeError, ValueError, AttributeError):
        return False
    return code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }


def _paginate(
    client: Any,
    op_name: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield items from a paginator, raising errors to the caller."""

    paginator = client.get_paginator(op_name)
    for page in paginator.paginate(**(params or {})):
        items = page.get(result_key, [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, Mapping):
                    yield dict(item)


def _safe_str(value: Any) -> str:
    return str(value or "")


# -----------------------------
# Checker
# -----------------------------


class CloudWatchMetricsLogsCostChecker(Checker):
    """CloudWatch Logs retention + custom metrics + alarms count signals."""

    checker_id = "aws.cloudwatch.metrics.logs.cost"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: Optional[CloudWatchMetricsLogsCostConfig] = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or CloudWatchMetricsLogsCostConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting CloudWatch metrics and logs cost check")
        services = getattr(ctx, "services", None)
        if services is None:
            return []

        logs = getattr(services, "logs", None)
        cw = getattr(services, "cloudwatch", None)
        region = str(
            getattr(services, "region", "")
            or common.safe_region_from_client(logs)
            or common.safe_region_from_client(cw)
        )
        _LOGGER.debug("CloudWatch check running", extra={"region": region})

        findings: List[FindingDraft] = []

        # Logs inventory is shared by multiple signals; fetch once.
        log_groups: Optional[List[Dict[str, Any]]] = None
        if logs is not None:
            try:
                log_groups = list(_paginate(logs, "describe_log_groups", "logGroups"))
            except ClientError as exc:
                if _is_access_denied(exc):
                    findings.append(
                        self._access_error(
                            ctx,
                            region=region,
                            service="logs",
                            action="logs:DescribeLogGroups",
                            exc=exc,
                        )
                    )
                    log_groups = None
                else:
                    raise

        if logs is not None and log_groups is not None:
            findings.extend(
                self._log_group_retention_findings(ctx, logs=logs, region=region, log_groups=log_groups)
            )
            findings.extend(
                self._custom_metrics_from_metric_filters_findings(
                    ctx, logs=logs, region=region, log_groups=log_groups
                )
            )

        if cw is not None:
            findings.extend(self._alarms_count_findings(ctx, cloudwatch=cw, region=region))

        return findings

    # -------------------------
    # Access errors
    # -------------------------

    def _access_error(self, ctx: Any, *, region: str, service: str, action: str, exc: ClientError) -> FindingDraft:
        code = ""
        try:
            code = str(exc.response.get("Error", {}).get("Code", ""))
        except (TypeError, ValueError, AttributeError):
            code = ""

        scope = build_scope(
            ctx,
            account=self._account,
            region=region,
            service=service,
            resource_type="account",
            resource_id=self._account.account_id,
            resource_arn="",
        )

        return FindingDraft(
            check_id="aws.cloudwatch.access.error",
            check_name="CloudWatch access error",
            category="governance",
            status="info",
            severity=Severity(level="info", score=0),
            title="CloudWatch permissions missing for cost/hygiene checks",
            scope=scope,
            message=f"Access denied calling {action} on service '{service}' in region '{region}'. ErrorCode={code}",
            recommendation=(
                "Grant logs:DescribeLogGroups, logs:ListTagsLogGroup, logs:DescribeMetricFilters, "
                "cloudwatch:DescribeAlarms (and optionally pricing:GetProducts for estimates)."
            ),
            estimated_monthly_cost=0.0,
            estimated_monthly_savings=0.0,
            estimate_confidence=0,
            estimate_notes="Informational finding emitted when permissions are missing.",
        ).with_issue(
            check="access_error",
            account_id=self._account.account_id,
            region=region,
            service=service,
            action=action,
        )

    # -------------------------
    # Logs retention
    # -------------------------

    def _log_group_retention_findings(
        self,
        ctx: RunContext,
        *,
        logs: Any,
        region: str,
        log_groups: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg
        if not cfg.require_retention_policy:
            return []

        findings: List[FindingDraft] = []
        for g in log_groups:
            name = _safe_str(g.get("logGroupName"))
            if not name:
                continue
            retention = g.get("retentionInDays")
            if retention is not None:
                continue

            tags = self._log_group_tags_best_effort(logs, region=region, log_group_name=name)
            if common.is_suppressed(
                tags,
                suppress_keys=set(cfg.suppress_tag_keys),
                suppress_values=set(cfg.suppress_tag_values),
                value_prefixes=cfg.suppress_value_prefixes,
            ):
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="logs",
                resource_type="log_group",
                resource_id=name,
                resource_arn=_safe_str(g.get("arn")),
            )

            findings.append(
                FindingDraft(
                    check_id="aws.logs.log.groups.retention.missing",
                    check_name="CloudWatch Logs retention policy",
                    category="governance",
                    status="fail",
                    severity=Severity(level="medium", score=450),
                    title="Log group has no retention policy (never expires)",
                    scope=scope,
                    message=(
                        "This log group has no retention policy configured. Logs will be retained indefinitely "
                        "and can grow unbounded, increasing CloudWatch Logs storage costs."
                    ),
                    recommendation=(
                        "Set an appropriate retention period (e.g., 14/30/90 days) based on compliance and debugging needs."
                    ),
                    remediation="In CloudWatch Logs -> Log groups -> select the group -> Actions -> Edit retention setting.",
                    tags=common.normalize_tags(tags),
                    estimate_notes=(
                        "CloudWatch Logs ingestion/storage costs depend on volume; this checker emits a governance signal only."
                    ),
                    estimate_confidence=10,
                ).with_issue(
                    log_group=name,
                    account_id=self._account.account_id,
                    region=region,
                    reason="retention_missing",
                )
            )

        return findings

    def _log_group_tags_best_effort(self, logs: Any, *, region: str, log_group_name: str) -> Mapping[str, str]:
        """Return normalized tags for a log group best-effort.

        Tag read is optional and can be denied even if DescribeLogGroups is allowed.
        In that case, return an empty map (do not emit a second access finding).
        """
        try:
            resp = logs.list_tags_log_group(logGroupName=log_group_name)
            tags = resp.get("tags", {})
            return common.normalize_tags(tags)
        except ClientError as exc:
            if _is_access_denied(exc):
                return {}
            raise
        except BotoCoreError:
            return {}

    # -------------------------
    # Metric filters -> custom metrics
    # -------------------------

    def _custom_metrics_from_metric_filters_findings(
        self,
        ctx: RunContext,
        *,
        logs: Any,
        region: str,
        log_groups: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg

        by_metric: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for g in log_groups:
            name = _safe_str(g.get("logGroupName"))
            if not name:
                continue

            try:
                filters = list(
                    _paginate(logs, "describe_metric_filters", "metricFilters", params={"logGroupName": name})
                )
            except ClientError as exc:
                if _is_access_denied(exc):
                    return [
                        self._access_error(
                            ctx,
                            region=region,
                            service="logs",
                            action="logs:DescribeMetricFilters",
                            exc=exc,
                        )
                    ]
                raise

            for mf in filters:
                metric_transformations = mf.get("metricTransformations")
                if not isinstance(metric_transformations, list):
                    continue
                for mt in metric_transformations:
                    if not isinstance(mt, Mapping):
                        continue
                    namespace = _safe_str(mt.get("metricNamespace")).strip()
                    metric_name = _safe_str(mt.get("metricName")).strip()
                    if not namespace or not metric_name:
                        continue
                    key = (namespace, metric_name)
                    agg = by_metric.setdefault(key, {"count": 0, "log_groups": set()})
                    agg["count"] = int(agg.get("count", 0)) + 1
                    group_set = agg.get("log_groups")
                    if isinstance(group_set, set):
                        group_set.add(name)

        if len(by_metric) < cfg.min_custom_metrics_for_signal:
            return []

        unit_price, notes, confidence = _resolve_custom_metric_price_usd_per_month(ctx, region=region)

        findings: List[FindingDraft] = []
        emitted = 0
        for (namespace, metric_name), meta in sorted(by_metric.items()):
            if emitted >= cfg.max_custom_metric_findings:
                break

            created_by_filters = int(meta.get("count", 0))
            lg = meta.get("log_groups")
            lg_count = len(lg) if isinstance(lg, set) else 0

            est_cost = common.money(unit_price)

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="cloudwatch",
                resource_type="custom_metric",
                resource_id=f"{namespace}:{metric_name}",
                resource_arn="",
            )

            findings.append(
                FindingDraft(
                    check_id="aws.cloudwatch.custom.metrics.from.log.filters",
                    check_name="CloudWatch custom metrics created by log metric filters",
                    category="waste",
                    status="info",
                    severity=Severity(level="low", score=150),
                    title="Custom metric created by CloudWatch Logs metric filters",
                    scope=scope,
                    message=(
                        "CloudWatch Logs metric filters create custom CloudWatch metrics. "
                        "Unused or excessive custom metrics can drive recurring monthly charges."
                    ),
                    recommendation=(
                        "Review whether this metric is still needed. Remove unused metric filters, "
                        "or consolidate metrics when possible."
                    ),
                    estimated_monthly_cost=est_cost,
                    estimated_monthly_savings=est_cost,
                    estimate_confidence=confidence,
                    estimate_notes=notes,
                    dimensions={
                        "namespace": namespace,
                        "metric_name": metric_name,
                        "created_by_filters": str(created_by_filters),
                        "log_groups_count": str(lg_count),
                    },
                ).with_issue(
                    namespace=namespace,
                    metric_name=metric_name,
                    account_id=self._account.account_id,
                    region=region,
                    reason="custom_metric_from_log_filter",
                )
            )
            emitted += 1

        return findings

    # -------------------------
    # Alarm count signal
    # -------------------------

    def _alarms_count_findings(self, ctx: RunContext, *, cloudwatch: Any, region: str) -> List[FindingDraft]:
        cfg = self._cfg
        try:
            alarms = list(_paginate(cloudwatch, "describe_alarms", "MetricAlarms"))
        except ClientError as exc:
            if _is_access_denied(exc):
                return [
                    self._access_error(
                        ctx,
                        region=region,
                        service="cloudwatch",
                        action="cloudwatch:DescribeAlarms",
                        exc=exc,
                    )
                ]
            raise

        alarm_count = len(alarms)
        if alarm_count < cfg.alarms_count_warn_threshold:
            return []

        unit_price, notes, confidence = _resolve_alarm_price_usd_per_month(ctx, region=region)
        est_cost = common.money(float(alarm_count) * float(unit_price))

        scope = build_scope(
            ctx,
            account=self._account,
            region=region,
            service="cloudwatch",
            resource_type="account",
            resource_id=self._account.account_id,
            resource_arn="",
        )

        return [
            FindingDraft(
                check_id="aws.cloudwatch.alarms.high.count",
                check_name="CloudWatch alarms count",
                category="waste",
                status="info",
                severity=Severity(level="low", score=200),
                title="High number of CloudWatch alarms in region",
                scope=scope,
                message=(
                    f"This account has {alarm_count} metric alarms in region '{region}'. "
                    "A high alarm count may indicate stale monitoring configurations and can increase recurring costs."
                ),
                recommendation="Review alarms for deprecated services/environments and remove or consolidate unused alarms.",
                estimated_monthly_cost=est_cost,
                estimated_monthly_savings=est_cost,
                estimate_confidence=confidence,
                estimate_notes=notes,
                dimensions={"alarm_count": str(alarm_count)},
            ).with_issue(
                account_id=self._account.account_id,
                region=region,
                reason="high_alarm_count",
                alarm_count=str(alarm_count),
            )
        ]


SPEC = "checks.aws.cloudwatch_metrics_logs_cost:CloudWatchMetricsLogsCostChecker"


@register_checker(SPEC)
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> CloudWatchMetricsLogsCostChecker:
    account_id = _safe_str(bootstrap.get("aws_account_id")).strip()
    billing_id = _safe_str(bootstrap.get("aws_billing_account_id")).strip() or account_id
    if not account_id:
        raise ValueError("bootstrap missing aws_account_id")

    return CloudWatchMetricsLogsCostChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_id),
    )
