"""Unit tests for the Lambda functions analyzer checker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import SimpleNamespace
from typing import Any, cast

from botocore.exceptions import ClientError

from checks.aws._common import AwsAccountContext
from checks.aws.lambda_functions_analyzer import (
    LambdaFunctionsAnalyzerChecker,
    LambdaFunctionsAnalyzerConfig,
)
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    """Simple paginator fake for unit tests."""

    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        """Yield configured pages."""

        yield from self._pages


class FakeLambda:
    """Lambda client fake with list_functions paginator support."""

    def __init__(self, *, region: str, pages_by_op: dict[str, list[Mapping[str, Any]]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op

    def get_paginator(self, op_name: str) -> FakePaginator:
        """Return a fake paginator for the given operation."""

        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeLambda has no paginator pages configured for {op_name}")
        return FakePaginator(pages)


class FakeLambdaAccessDenied(FakeLambda):
    """Lambda fake that raises an access denied error."""

    def get_paginator(self, op_name: str) -> FakePaginator:  # pylint: disable=unused-argument
        """Raise a synthetic access denied error."""

        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetPaginator",
        )


class FakeCloudWatch:
    """CloudWatch fake for GetMetricData used by the checker."""

    def __init__(
        self,
        *,
        invocations_by_function: dict[str, list[float]],
        duration_by_function: dict[str, list[float]],
    ) -> None:
        self._invocations_by_function = invocations_by_function
        self._duration_by_function = duration_by_function

    def get_metric_data(self, *, MetricDataQueries: list[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:
        """Return synthetic metric data for requested query IDs."""

        rows: list[dict[str, Any]] = []
        for query in MetricDataQueries:
            query_id = str(query.get("Id") or "")
            metric = (query.get("MetricStat") or {}).get("Metric") or {}
            name = str(metric.get("MetricName") or "")
            dimensions = metric.get("Dimensions") or []
            function_name = ""
            if isinstance(dimensions, list) and dimensions:
                function_name = str((dimensions[0] or {}).get("Value") or "")

            if name == "Invocations":
                values = list(self._invocations_by_function.get(function_name, []))
            else:
                values = list(self._duration_by_function.get(function_name, []))

            rows.append({"Id": query_id, "Values": values})

        return {"MetricDataResults": rows}


class FakeCloudWatchAccessDenied(FakeCloudWatch):
    """CloudWatch fake that raises access denied."""

    def get_metric_data(self, *, MetricDataQueries: list[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:  # pylint: disable=unused-argument
        """Raise a synthetic access denied error."""

        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetMetricData",
        )


class FakePriceQuote:
    """Simple pricing quote fake."""

    def __init__(self, unit_price_usd: float) -> None:
        self.unit_price_usd = unit_price_usd


class FakePricing:
    """Pricing service fake used by cost estimation."""

    def location_for_region(self, region: str) -> str:
        """Return a deterministic region location string."""

        assert region
        return "US East (N. Virginia)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        """Return a stable synthetic Lambda GB-second unit price."""

        assert service_code == "AWSLambda"
        assert filters
        assert unit
        return FakePriceQuote(0.00002)


def _mk_ctx(
    *,
    lambda_client: Any,
    cloudwatch: Any | None = None,
    pricing: Any | None = None,
    region: str = "us-east-1",
) -> RunContext:
    """Create a lightweight RunContext stub for checker unit tests."""

    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(
                region=region,
                lambda_client=lambda_client,
                cloudwatch=cloudwatch,
                pricing=pricing,
            ),
        ),
    )


def _checker() -> LambdaFunctionsAnalyzerChecker:
    """Build checker instance with deterministic account context."""

    return LambdaFunctionsAnalyzerChecker(
        account=AwsAccountContext(account_id="123456789012", billing_account_id="123456789012"),
    )


def test_idle_lambda_emits_unused() -> None:
    """Idle Lambda functions should emit aws.lambda.functions.unused findings."""

    lambda_client = FakeLambda(
        region="us-east-1",
        pages_by_op={
            "list_functions": [
                {
                    "Functions": [
                        {
                            "FunctionName": "fn-idle",
                            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn-idle",
                            "Runtime": "python3.11",
                            "MemorySize": 1024,
                            "Timeout": 30,
                        }
                    ]
                }
            ]
        },
    )
    cloudwatch = FakeCloudWatch(
        invocations_by_function={"fn-idle": [0.0] * 14},
        duration_by_function={"fn-idle": [75.0] * 14},
    )

    findings = list(_checker().run(_mk_ctx(lambda_client=lambda_client, cloudwatch=cloudwatch)))
    hits = [item for item in findings if item.check_id == "aws.lambda.functions.unused"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "fn-idle"
    assert hits[0].issue_key.get("signal") == "idle"


def test_memory_overprovisioned_emits() -> None:
    """High-memory/low-duration functions should emit overprovisioned-memory findings."""

    lambda_client = FakeLambda(
        region="us-east-1",
        pages_by_op={
            "list_functions": [
                {
                    "Functions": [
                        {
                            "FunctionName": "fn-overprov",
                            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn-overprov",
                            "Runtime": "python3.11",
                            "MemorySize": 2048,
                            "Timeout": 30,
                        }
                    ]
                }
            ]
        },
    )
    cloudwatch = FakeCloudWatch(
        invocations_by_function={"fn-overprov": [12000.0] * 14},
        duration_by_function={"fn-overprov": [60.0] * 14},
    )

    checker = LambdaFunctionsAnalyzerChecker(
        account=AwsAccountContext(account_id="123456789012", billing_account_id="123456789012"),
        cfg=LambdaFunctionsAnalyzerConfig(idle_p95_daily_invocations_threshold=1.0),
    )
    findings = list(checker.run(_mk_ctx(lambda_client=lambda_client, cloudwatch=cloudwatch, pricing=FakePricing())))

    hits = [item for item in findings if item.check_id == "aws.lambda.functions.memory.overprovisioned"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "fn-overprov"
    assert hits[0].dimensions.get("suggested_memory_mb") == "1024"
    assert (hits[0].estimated_monthly_savings or 0.0) > 0.0
    assert not any(item.check_id == "aws.lambda.functions.unused" for item in findings)


def test_list_functions_access_denied_emits_info() -> None:
    """Missing list permission should emit an informational access-error finding."""

    lambda_client = FakeLambdaAccessDenied(region="us-east-1", pages_by_op={})
    findings = list(_checker().run(_mk_ctx(lambda_client=lambda_client, cloudwatch=None)))

    hits = [item for item in findings if item.check_id == "aws.lambda.functions.access.error"]
    assert len(hits) == 1
    assert hits[0].status == "info"


def test_cloudwatch_access_denied_emits_missing_permission() -> None:
    """When CloudWatch metric access is denied, checker should emit missing-permission info finding."""

    lambda_client = FakeLambda(
        region="us-east-1",
        pages_by_op={
            "list_functions": [
                {
                    "Functions": [
                        {
                            "FunctionName": "fn-a",
                            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn-a",
                            "Runtime": "python3.11",
                            "MemorySize": 1024,
                            "Timeout": 30,
                        }
                    ]
                }
            ]
        },
    )
    cloudwatch = FakeCloudWatchAccessDenied(invocations_by_function={}, duration_by_function={})

    findings = list(_checker().run(_mk_ctx(lambda_client=lambda_client, cloudwatch=cloudwatch)))
    permission_hits = [item for item in findings if item.check_id == "aws.lambda.functions.missing.permission"]
    assert len(permission_hits) == 1
    assert permission_hits[0].issue_key.get("operation") == "cloudwatch:GetMetricData"
    assert not any(item.check_id == "aws.lambda.functions.unused" for item in findings)
    assert not any(item.check_id == "aws.lambda.functions.memory.overprovisioned" for item in findings)


def test_determinism_shuffled_inventory() -> None:
    """Shuffled inventory input order should produce equivalent finding signatures."""

    fn_a = {
        "FunctionName": "fn-a",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn-a",
        "Runtime": "python3.11",
        "MemorySize": 2048,
        "Timeout": 30,
    }
    fn_b = {
        "FunctionName": "fn-b",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn-b",
        "Runtime": "python3.11",
        "MemorySize": 1024,
        "Timeout": 30,
    }

    cw = FakeCloudWatch(
        invocations_by_function={"fn-a": [100.0] * 14, "fn-b": [0.0] * 14},
        duration_by_function={"fn-a": [70.0] * 14, "fn-b": [50.0] * 14},
    )
    checker = _checker()

    ctx1 = _mk_ctx(
        lambda_client=FakeLambda(
            region="us-east-1",
            pages_by_op={"list_functions": [{"Functions": [fn_a, fn_b]}]},
        ),
        cloudwatch=cw,
    )
    ctx2 = _mk_ctx(
        lambda_client=FakeLambda(
            region="us-east-1",
            pages_by_op={"list_functions": [{"Functions": [fn_b, fn_a]}]},
        ),
        cloudwatch=cw,
    )

    findings_1 = list(checker.run(ctx1))
    findings_2 = list(checker.run(ctx2))

    def _signature(findings: list[Any]) -> list[Any]:
        return sorted(
            [
                (
                    item.check_id,
                    item.scope.resource_id,
                    tuple(sorted((item.issue_key or {}).items())),
                )
                for item in findings
            ],
            key=lambda row: (row[0], row[1], row[2]),
        )

    assert _signature(findings_1) == _signature(findings_2)
