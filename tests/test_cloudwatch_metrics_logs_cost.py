"""Unit tests for the CloudWatch Metrics & Logs cost checker."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

import pytest
from botocore.exceptions import ClientError

from checks.aws.cloudwatch_metrics_logs_cost import (
    CloudWatchMetricsLogsCostChecker,
    CloudWatchMetricsLogsCostConfig,
)
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeLogs:
    """Minimal CloudWatch Logs fake."""

    def __init__(
        self,
        *,
        region: str,
        pages_by_op: Dict[str, List[Mapping[str, Any]]],
        tags_by_group: Optional[Dict[str, Mapping[str, str]]] = None,
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op
        self._tags_by_group = tags_by_group or {}

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeLogs has no paginator pages configured for {op_name}")
        return FakePaginator(pages)

    def list_tags_log_group(self, *, logGroupName: str) -> Mapping[str, Any]:
        return {"tags": dict(self._tags_by_group.get(logGroupName, {}))}


class FakeLogsAccessDenied(FakeLogs):
    def get_paginator(self, op_name: str) -> FakePaginator:  # pylint: disable=unused-argument
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetPaginator",
        )


class FakePriceQuote:
    def __init__(self, unit_price_usd: float) -> None:
        self.unit_price_usd = unit_price_usd


class FakePricing:
    def location_for_region(self, region: str) -> str:
        assert region
        return "EU (Paris)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        assert service_code == "AmazonCloudWatch"
        assert filters
        assert unit == "Each"
        return FakePriceQuote(0.25)


def _mk_ctx(*, logs: Any, pricing: Any = None, region: str = "eu-west-3") -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(region=region, logs=logs, cloudwatch=None, pricing=pricing),
        ),
    )


def test_log_group_retention_missing_emits() -> None:
    logs = FakeLogs(
        region="eu-west-3",
        pages_by_op={
            "describe_log_groups": [
                {
                    "logGroups": [
                        {"logGroupName": "/aws/lambda/fn-a", "arn": "arn:aws:logs:eu-west-3:123:log-group:/aws/lambda/fn-a"},
                        {"logGroupName": "/aws/lambda/fn-b", "retentionInDays": 14},
                    ]
                }
            ],
            "describe_metric_filters": [{"metricFilters": []}],
        },
    )

    checker = CloudWatchMetricsLogsCostChecker(account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws"))
    ctx = _mk_ctx(logs=logs)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.logs.log.groups.retention.missing"]
    assert len(hits) == 1
    assert hits[0].scope.service == "logs"
    assert hits[0].issue_key.get("log_group") == "/aws/lambda/fn-a"


def test_metric_filters_custom_metrics_emits_with_pricing() -> None:
    logs = FakeLogs(
        region="eu-west-3",
        pages_by_op={
            "describe_log_groups": [{"logGroups": [{"logGroupName": "lg-1"}]}],
            "describe_metric_filters": [
                {
                    "metricFilters": [
                        {
                            "filterName": "f1",
                            "metricTransformations": [
                                {"metricNamespace": "MyApp", "metricName": "Errors"},
                                {"metricNamespace": "MyApp", "metricName": "Latency"},
                            ],
                        }
                    ]
                }
            ],
        },
    )

    cfg = CloudWatchMetricsLogsCostConfig(min_custom_metrics_for_signal=1)
    checker = CloudWatchMetricsLogsCostChecker(
        account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws"),
        cfg=cfg,
    )
    ctx = _mk_ctx(logs=logs, pricing=FakePricing())
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.cloudwatch.custom.metrics.from.log.filters"]
    assert len(hits) == 2
    assert all(f.estimated_monthly_cost == pytest.approx(0.25) for f in hits)
    assert {f.dimensions.get("metric_name") for f in hits} == {"Errors", "Latency"}


def test_access_denied_emits_info_finding() -> None:
    logs = FakeLogsAccessDenied(region="eu-west-3", pages_by_op={})
    checker = CloudWatchMetricsLogsCostChecker(account=SimpleNamespace(account_id="123", billing_account_id="123", partition="aws"))
    ctx = _mk_ctx(logs=logs)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.cloudwatch.access.error"]
    assert len(hits) == 1
    assert hits[0].status == "info"
