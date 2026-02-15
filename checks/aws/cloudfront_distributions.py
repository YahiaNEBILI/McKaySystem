"""CloudFront distributions optimization and caching checker.

Signals:
1) Unused distributions (low request volume over a lookback window)
2) Default behavior with caching disabled

Design notes:
- CloudFront inventory is global and this checker runs once per run (`is_regional = False`).
- Request-volume signal is best-effort and uses CloudWatch metric `AWS/CloudFront::Requests`
  with dimensions `DistributionId` and `Region=Global`.
- Caching signal is configuration-based and detects:
  - Managed policy `CachingDisabled`
  - Legacy behavior where MinTTL/DefaultTTL/MaxTTL are all zero.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

import checks.aws._common as common
from checks.aws._common import AwsAccountContext, build_scope, get_logger
from checks.aws.defaults import (
    CLOUDFRONT_IDLE_P95_DAILY_REQUESTS_THRESHOLD,
    CLOUDFRONT_LOOKBACK_DAYS,
    CLOUDFRONT_MAX_FINDINGS_PER_TYPE,
    CLOUDFRONT_MIN_AGE_DAYS,
    CLOUDFRONT_MIN_DAILY_DATAPOINTS,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

_LOGGER = get_logger("cloudfront_distributions")

_MANAGED_CACHING_DISABLED_POLICY_ID = "413f160f-4f18-4c0b-95c7-bf7f44e8f58b"
_CLOUDFRONT_METRICS_REGION = "Global"
_CLOUDFRONT_SCOPE_REGION = "global"


@dataclass(frozen=True)
class CloudFrontDistributionsConfig:
    """Configuration knobs for the CloudFront distributions checker."""

    lookback_days: int = CLOUDFRONT_LOOKBACK_DAYS
    min_daily_datapoints: int = CLOUDFRONT_MIN_DAILY_DATAPOINTS
    idle_p95_daily_requests_threshold: float = CLOUDFRONT_IDLE_P95_DAILY_REQUESTS_THRESHOLD
    min_age_days: int = CLOUDFRONT_MIN_AGE_DAYS
    max_findings_per_type: int = CLOUDFRONT_MAX_FINDINGS_PER_TYPE


def _client_error_code(exc: ClientError) -> str:
    """Return normalized AWS error code from a ClientError."""
    try:
        return str(exc.response.get("Error", {}).get("Code") or "")
    except (AttributeError, TypeError, ValueError):
        return ""


def _is_access_denied(exc: ClientError) -> bool:
    """True when the AWS error code indicates missing permissions."""
    return _client_error_code(exc) in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }


def _chunk(values: Sequence[str], chunk_size: int) -> Iterator[list[str]]:
    """Yield deterministic chunks from a sequence."""
    idx = 0
    while idx < len(values):
        yield list(values[idx : idx + chunk_size])
        idx += chunk_size


def _distribution_age_days(summary: Mapping[str, Any], *, now: datetime) -> int | None:
    """Return distribution age in full days or None when unavailable."""
    last_modified = summary.get("LastModifiedTime")
    if not isinstance(last_modified, datetime):
        return None
    last_modified_utc = common.utc(last_modified)
    if last_modified_utc is None:
        return None
    delta = now - last_modified_utc
    if delta.total_seconds() < 0:
        return 0
    return int(delta.days)


def _distribution_enabled(summary: Mapping[str, Any]) -> bool:
    """Return True if distribution is enabled."""
    return bool(summary.get("Enabled", False))


def _distribution_id(summary: Mapping[str, Any]) -> str:
    """Normalized distribution ID."""
    return str(summary.get("Id") or "").strip()


def _distribution_arn(summary: Mapping[str, Any]) -> str:
    """Normalized distribution ARN."""
    return str(summary.get("ARN") or "").strip()


def _distribution_domain(summary: Mapping[str, Any]) -> str:
    """Normalized distribution domain name."""
    return str(summary.get("DomainName") or "").strip()


def _default_behavior_cache_disabled_reason(summary: Mapping[str, Any]) -> str:
    """Return reason when default cache behavior appears disabled, else empty."""
    behavior = summary.get("DefaultCacheBehavior")
    if not isinstance(behavior, Mapping):
        return ""

    cache_policy_id = str(behavior.get("CachePolicyId") or "").strip()
    if cache_policy_id == _MANAGED_CACHING_DISABLED_POLICY_ID:
        return "managed_policy_caching_disabled"
    if cache_policy_id:
        return ""

    ttl_keys = ("MinTTL", "DefaultTTL", "MaxTTL")
    if not all(key in behavior for key in ttl_keys):
        return ""
    ttl_values = [common.safe_float(behavior.get(key), default=1.0) for key in ttl_keys]
    if all(ttl <= 0.0 for ttl in ttl_values):
        return "legacy_ttl_zero"
    return ""


def _p95(values: Sequence[float]) -> float:
    """Compute p95 with deterministic floor percentile."""
    p95_value = common.percentile(values, 95.0, method="floor")
    if p95_value is None:
        return 0.0
    return float(p95_value)


class _CloudFrontCloudWatch:
    """Batch CloudWatch fetcher for CloudFront daily request counts."""

    def __init__(self, cloudwatch: Any) -> None:
        self._cloudwatch = cloudwatch

    def daily_requests(
        self,
        *,
        distribution_ids: Sequence[str],
        start: datetime,
        end: datetime,
    ) -> dict[str, list[float]]:
        """Fetch daily request count series for distributions."""
        out: dict[str, list[float]] = {dist_id: [] for dist_id in distribution_ids}
        if not distribution_ids:
            return out

        for batch in _chunk(list(distribution_ids), 450):
            queries: list[dict[str, Any]] = []
            id_to_distribution: dict[str, str] = {}
            for idx, dist_id in enumerate(batch):
                query_id = f"m{idx}"
                id_to_distribution[query_id] = dist_id
                queries.append(
                    {
                        "Id": query_id,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/CloudFront",
                                "MetricName": "Requests",
                                "Dimensions": [
                                    {"Name": "DistributionId", "Value": dist_id},
                                    {"Name": "Region", "Value": _CLOUDFRONT_METRICS_REGION},
                                ],
                            },
                            "Period": 86_400,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                )

            response = self._cloudwatch.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampAscending",
            )
            metric_data = response.get("MetricDataResults", [])
            if not isinstance(metric_data, list):
                continue
            for row in metric_data:
                if not isinstance(row, Mapping):
                    continue
                query_id = str(row.get("Id") or "")
                mapped_dist_id = id_to_distribution.get(query_id)
                if not mapped_dist_id:
                    continue
                values = row.get("Values", [])
                if not isinstance(values, list):
                    continue
                out[mapped_dist_id].extend(common.safe_float(value) for value in values)

        return out


class CloudFrontDistributionsChecker(Checker):
    """CloudFront distribution checker for usage and caching signals."""

    checker_id = "aws.cloudfront.distributions.audit"
    is_regional = False

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: CloudFrontDistributionsConfig | None = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or CloudFrontDistributionsConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        """Run the checker and emit findings."""
        _LOGGER.info("Starting CloudFront distributions check")
        services = getattr(ctx, "services", None)
        if services is None:
            return []
        cloudfront = getattr(services, "cloudfront", None)
        if cloudfront is None:
            return []

        findings: list[FindingDraft] = []
        try:
            distributions = self._list_distributions(cloudfront)
        except ClientError as exc:
            if _is_access_denied(exc):
                return [
                    self._access_error(
                        ctx,
                        action="cloudfront:ListDistributions",
                        service="cloudfront",
                        error_code=_client_error_code(exc),
                    )
                ]
            raise

        if not distributions:
            return []
        _LOGGER.debug("CloudFront distributions listed", extra={"count": len(distributions)})

        distributions = sorted(distributions, key=_distribution_id)
        now = common.now_utc()
        usage_candidates: list[str] = []
        for summary in distributions:
            dist_id = _distribution_id(summary)
            if not dist_id or not _distribution_enabled(summary):
                continue
            age_days = _distribution_age_days(summary, now=now)
            if age_days is not None and age_days < int(self._cfg.min_age_days):
                continue
            usage_candidates.append(dist_id)

        requests_by_distribution: dict[str, list[float]] = {}
        cloudwatch = getattr(services, "cloudwatch", None)
        if cloudwatch is not None and usage_candidates and int(self._cfg.lookback_days) > 0:
            start = now - timedelta(days=int(self._cfg.lookback_days))
            end = now
            try:
                requests_by_distribution = _CloudFrontCloudWatch(cloudwatch).daily_requests(
                    distribution_ids=usage_candidates,
                    start=start,
                    end=end,
                )
            except ClientError as exc:
                if _is_access_denied(exc):
                    findings.append(
                        self._missing_permission(
                            ctx,
                            action="cloudwatch:GetMetricData",
                            service="cloudwatch",
                            error_code=_client_error_code(exc),
                        )
                    )
                    requests_by_distribution = {}
                else:
                    raise

        emitted_unused = 0
        emitted_cache_disabled = 0
        for summary in distributions:
            dist_id = _distribution_id(summary)
            if not dist_id or not _distribution_enabled(summary):
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=_CLOUDFRONT_SCOPE_REGION,
                service="cloudfront",
                resource_type="distribution",
                resource_id=dist_id,
                resource_arn=_distribution_arn(summary),
            )
            domain_name = _distribution_domain(summary)

            if emitted_cache_disabled < int(self._cfg.max_findings_per_type):
                cache_disabled_reason = _default_behavior_cache_disabled_reason(summary)
                if cache_disabled_reason:
                    findings.append(
                        FindingDraft(
                            check_id="aws.cloudfront.distributions.caching.disabled",
                            check_name="CloudFront distribution caching configuration",
                            category="waste",
                            status="fail",
                            severity=Severity(level="medium", score=520),
                            title="CloudFront default cache behavior has caching disabled",
                            scope=scope,
                            message=(
                                "The default behavior appears to disable edge caching, "
                                "which can increase origin load and transfer/request charges."
                            ),
                            recommendation=(
                                "Enable caching for cacheable paths using an appropriate "
                                "cache policy and TTL values."
                            ),
                            dimensions={
                                "distribution_domain": domain_name,
                                "caching_disabled_reason": cache_disabled_reason,
                            },
                        ).with_issue(
                            distribution_id=dist_id,
                            reason=cache_disabled_reason,
                        )
                    )
                    emitted_cache_disabled += 1

            if emitted_unused >= int(self._cfg.max_findings_per_type):
                continue
            series = requests_by_distribution.get(dist_id, [])
            if len(series) < int(self._cfg.min_daily_datapoints):
                continue
            p95_daily_requests = _p95(series)
            if p95_daily_requests > float(self._cfg.idle_p95_daily_requests_threshold):
                continue

            findings.append(
                FindingDraft(
                    check_id="aws.cloudfront.distributions.unused",
                    check_name="CloudFront distribution utilization",
                    category="waste",
                    status="fail",
                    severity=Severity(level="medium", score=560),
                    title="CloudFront distribution appears unused",
                    scope=scope,
                    message=(
                        f"Distribution '{dist_id}' has low request volume (p95 daily Requests="
                        f"{p95_daily_requests:.2f}) over the last {int(self._cfg.lookback_days)} days."
                    ),
                    recommendation=(
                        "Validate with application owners. Disable or delete the distribution "
                        "if it is no longer needed."
                    ),
                    estimated_monthly_savings=0.0,
                    estimate_confidence=30,
                    estimate_notes=(
                        "CloudFront has usage-based pricing; this signal indicates likely "
                        "unused configuration rather than a fixed monthly baseline."
                    ),
                    dimensions={
                        "distribution_domain": domain_name,
                        "p95_daily_requests": f"{p95_daily_requests:.2f}",
                    },
                ).with_issue(
                    distribution_id=dist_id,
                    reason="low_request_volume",
                )
            )
            emitted_unused += 1

        return findings

    def _list_distributions(self, cloudfront: Any) -> list[dict[str, Any]]:
        """Return distribution summaries from CloudFront with paginator/fallback support."""
        if hasattr(cloudfront, "get_paginator"):
            paginator = cloudfront.get_paginator("list_distributions")
            output: list[dict[str, Any]] = []
            for page in paginator.paginate():
                output.extend(self._extract_distribution_items(page))
            return output

        output = []
        marker = ""
        while True:
            kwargs = {"Marker": marker} if marker else {}
            page = cloudfront.list_distributions(**kwargs)
            output.extend(self._extract_distribution_items(page))

            distribution_list = (
                page.get("DistributionList", {}) if isinstance(page, Mapping) else {}
            )
            if not isinstance(distribution_list, Mapping):
                break
            is_truncated = bool(distribution_list.get("IsTruncated", False))
            marker = str(distribution_list.get("NextMarker") or "").strip()
            if not is_truncated or not marker:
                break

        return output

    @staticmethod
    def _extract_distribution_items(page: Any) -> list[dict[str, Any]]:
        """Extract `DistributionList.Items` from a page payload."""
        if not isinstance(page, Mapping):
            return []
        distribution_list = page.get("DistributionList", {})
        if not isinstance(distribution_list, Mapping):
            return []
        items = distribution_list.get("Items", [])
        if not isinstance(items, list):
            return []

        output: list[dict[str, Any]] = []
        for item in items:
            if isinstance(item, Mapping):
                output.append(dict(item))
        return output

    def _access_error(
        self,
        ctx: RunContext,
        *,
        action: str,
        service: str,
        error_code: str,
    ) -> FindingDraft:
        """Build an informational access error finding."""
        scope = build_scope(
            ctx,
            account=self._account,
            region=_CLOUDFRONT_SCOPE_REGION,
            service=service,
            resource_type="account",
            resource_id=self._account.account_id,
            resource_arn="",
        )
        return FindingDraft(
            check_id="aws.cloudfront.distributions.access.error",
            check_name="CloudFront access error",
            category="governance",
            status="info",
            severity=Severity(level="low", score=100),
            title="CloudFront permissions missing for distribution checks",
            scope=scope,
            message=(
                f"Access denied calling {action} in CloudFront checks. "
                f"ErrorCode={error_code or 'unknown'}."
            ),
            recommendation=(
                "Grant cloudfront:ListDistributions and cloudwatch:GetMetricData "
                "to the scanner role."
            ),
            estimate_confidence=0,
            estimate_notes="Informational finding emitted when required permissions are missing.",
        ).with_issue(
            account_id=self._account.account_id,
            action=action,
            service=service,
        )

    def _missing_permission(
        self,
        ctx: RunContext,
        *,
        action: str,
        service: str,
        error_code: str,
    ) -> FindingDraft:
        """Build an informational finding for a non-fatal missing permission."""
        scope = build_scope(
            ctx,
            account=self._account,
            region=_CLOUDFRONT_SCOPE_REGION,
            service="cloudfront",
            resource_type="account",
            resource_id=self._account.account_id,
            resource_arn="",
        )
        return FindingDraft(
            check_id="aws.cloudfront.distributions.missing.permission",
            check_name="CloudFront permissions",
            category="governance",
            status="info",
            severity=Severity(level="low", score=120),
            title="Missing permission for full CloudFront analysis",
            scope=scope,
            message=(
                f"Access denied calling {action} on service '{service}'. "
                "Usage-based unused-distribution detection may be incomplete."
            ),
            recommendation=(
                "Grant cloudwatch:GetMetricData to enable CloudFront utilization signals."
            ),
            estimate_confidence=0,
            estimate_notes=f"ErrorCode={error_code or 'unknown'}",
        ).with_issue(
            account_id=self._account.account_id,
            action=action,
            service=service,
        )


SPEC = "checks.aws.cloudfront_distributions:CloudFrontDistributionsChecker"


@register_checker(SPEC)
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    """Instantiate checker from bootstrap/runtime context."""
    _ = ctx
    account_id = str(bootstrap.get("aws_account_id") or "").strip()
    if not account_id:
        raise ValueError("bootstrap missing aws_account_id")
    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id).strip()

    return CloudFrontDistributionsChecker(
        account=AwsAccountContext(
            account_id=account_id,
            billing_account_id=billing_account_id,
        ),
    )
