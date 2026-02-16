"""Unit tests for the CloudFront distributions checker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

from botocore.exceptions import ClientError

from checks.aws.cloudfront_distributions import (
    CloudFrontDistributionsChecker,
    CloudFrontDistributionsConfig,
)
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    """Simple paginator fake with fixed pages."""

    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = list(pages)

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeCloudFront:
    """CloudFront fake exposing list_distributions paginator."""

    def __init__(self, *, pages: list[Mapping[str, Any]]) -> None:
        self._pages = list(pages)

    def get_paginator(self, op_name: str) -> FakePaginator:
        if op_name != "list_distributions":
            raise KeyError(op_name)
        return FakePaginator(self._pages)


class FakeCloudFrontAccessDenied:
    """CloudFront fake that always raises access denied."""

    def get_paginator(self, _op_name: str) -> FakePaginator:
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="ListDistributions",
        )


class FakeCloudWatch:
    """CloudWatch fake for GetMetricData keyed by DistributionId."""

    def __init__(
        self,
        *,
        requests_by_distribution: dict[str, list[float]] | None = None,
        raise_access_denied: bool = False,
    ) -> None:
        self._requests_by_distribution = dict(requests_by_distribution or {})
        self._raise_access_denied = bool(raise_access_denied)

    def get_metric_data(
        self,
        *,
        MetricDataQueries: list[Mapping[str, Any]],
        **_kwargs: Any,
    ) -> Mapping[str, Any]:
        if self._raise_access_denied:
            raise ClientError(
                error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
                operation_name="GetMetricData",
            )

        out: list[dict[str, Any]] = []
        for query in MetricDataQueries:
            query_id = str(query.get("Id") or "")
            metric = ((query.get("MetricStat") or {}).get("Metric") or {})
            dimensions = metric.get("Dimensions", [])
            distribution_id = ""
            if isinstance(dimensions, list):
                for dim in dimensions:
                    if not isinstance(dim, Mapping):
                        continue
                    if str(dim.get("Name") or "") == "DistributionId":
                        distribution_id = str(dim.get("Value") or "")
                        break
            values = list(self._requests_by_distribution.get(distribution_id, []))
            out.append({"Id": query_id, "Values": values})
        return {"MetricDataResults": out}


def _mk_ctx(*, cloudfront: Any, cloudwatch: Any) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(cloudfront=cloudfront, cloudwatch=cloudwatch),
        ),
    )


def _distribution(
    *,
    dist_id: str,
    now: datetime,
    enabled: bool = True,
    cache_policy_id: str = "658327ea-f89d-4fab-a63d-7e88639e58f6",
) -> dict[str, Any]:
    return {
        "Id": dist_id,
        "ARN": f"arn:aws:cloudfront::123456789012:distribution/{dist_id}",
        "DomainName": f"{dist_id}.cloudfront.net",
        "Enabled": enabled,
        "LastModifiedTime": now - timedelta(days=30),
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin-1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": cache_policy_id,
        },
    }


def test_unused_distribution_emits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import checks.aws.cloudfront_distributions as mod

    now = datetime(2026, 2, 15, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(mod.common, "now_utc", lambda: now)

    dist = _distribution(dist_id="D_UNUSED", now=now)
    cloudfront = FakeCloudFront(pages=[{"DistributionList": {"Items": [dist]}}])
    cloudwatch = FakeCloudWatch(requests_by_distribution={"D_UNUSED": [0.0] * 14})
    ctx = _mk_ctx(cloudfront=cloudfront, cloudwatch=cloudwatch)

    cfg = CloudFrontDistributionsConfig(
        lookback_days=14,
        min_daily_datapoints=7,
        idle_p95_daily_requests_threshold=1.0,
        min_age_days=7,
    )
    checker = CloudFrontDistributionsChecker(
        account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws"),
        cfg=cfg,
    )
    findings = list(checker.run(ctx))

    hits = [
        finding for finding in findings if finding.check_id == "aws.cloudfront.distributions.unused"
    ]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "D_UNUSED"


def test_caching_disabled_policy_emits() -> None:
    now = datetime(2026, 2, 15, 12, 0, tzinfo=UTC)
    dist = _distribution(
        dist_id="D_CACHE_DISABLED",
        now=now,
        cache_policy_id="413f160f-4f18-4c0b-95c7-bf7f44e8f58b",
    )
    cloudfront = FakeCloudFront(pages=[{"DistributionList": {"Items": [dist]}}])
    ctx = _mk_ctx(cloudfront=cloudfront, cloudwatch=None)

    checker = CloudFrontDistributionsChecker(
        account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws")
    )
    findings = list(checker.run(ctx))

    hits = [
        finding for finding in findings if finding.check_id == "aws.cloudfront.distributions.caching.disabled"
    ]
    assert len(hits) == 1
    assert hits[0].issue_key.get("reason") == "managed_policy_caching_disabled"


def test_list_distributions_access_denied_emits_info() -> None:
    ctx = _mk_ctx(cloudfront=FakeCloudFrontAccessDenied(), cloudwatch=None)
    checker = CloudFrontDistributionsChecker(
        account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws")
    )

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.cloudfront.distributions.access.error"
    assert findings[0].status == "info"


def test_cloudwatch_access_denied_emits_missing_permission() -> None:
    now = datetime(2026, 2, 15, 12, 0, tzinfo=UTC)
    dist = _distribution(dist_id="D_ONE", now=now)

    cloudfront = FakeCloudFront(pages=[{"DistributionList": {"Items": [dist]}}])
    cloudwatch = FakeCloudWatch(raise_access_denied=True)
    ctx = _mk_ctx(cloudfront=cloudfront, cloudwatch=cloudwatch)

    checker = CloudFrontDistributionsChecker(
        account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws")
    )
    findings = list(checker.run(ctx))

    hits = [
        finding
        for finding in findings
        if finding.check_id == "aws.cloudfront.distributions.missing.permission"
    ]
    assert len(hits) == 1
    assert hits[0].status == "info"
