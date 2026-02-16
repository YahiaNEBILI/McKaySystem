"""
checks/aws/lambda_functions_analyzer.py

AWS Lambda analyzer checker.

Signals:
1) Idle/unused Lambda functions (very low invocation volume)
2) Potentially overprovisioned Lambda memory (heuristic)

Design notes
------------
- Uses Lambda inventory + CloudWatch metrics (Invocations, Duration).
- Emits informational findings for IAM permission gaps.
- Keeps output deterministic by sorting functions and avoiding unstable keys.
- Memory overprovisioning is heuristic and intentionally conservative.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, OperationNotPageableError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    get_logger,
    money,
    now_utc,
    paginate_items,
    percentile,
    safe_region_from_client,
)
from checks.aws.defaults import (
    LAMBDA_FALLBACK_GB_SECOND_USD,
    LAMBDA_IDLE_P95_DAILY_INVOCATIONS_THRESHOLD,
    LAMBDA_LOOKBACK_DAYS,
    LAMBDA_MAX_FINDINGS_PER_TYPE,
    LAMBDA_MEMORY_OVERPROV_DURATION_SLOWDOWN_FACTOR,
    LAMBDA_MEMORY_OVERPROV_MAX_DURATION_TO_TIMEOUT_RATIO,
    LAMBDA_MEMORY_OVERPROV_MAX_P95_DURATION_MS,
    LAMBDA_MEMORY_OVERPROV_MIN_ALLOCATED_MB,
    LAMBDA_MEMORY_OVERPROV_MIN_INVOCATIONS,
    LAMBDA_MEMORY_OVERPROV_TARGET_MEMORY_RATIO,
    LAMBDA_MIN_DAILY_DATAPOINTS,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

_LOGGER = get_logger("lambda_functions_analyzer")


@dataclass(frozen=True)
class LambdaFunctionsAnalyzerConfig:
    """Configuration knobs for Lambda analyzer checker."""

    lookback_days: int = LAMBDA_LOOKBACK_DAYS
    min_daily_datapoints: int = LAMBDA_MIN_DAILY_DATAPOINTS
    idle_p95_daily_invocations_threshold: float = LAMBDA_IDLE_P95_DAILY_INVOCATIONS_THRESHOLD

    memory_overprov_min_allocated_mb: int = LAMBDA_MEMORY_OVERPROV_MIN_ALLOCATED_MB
    memory_overprov_max_p95_duration_ms: float = LAMBDA_MEMORY_OVERPROV_MAX_P95_DURATION_MS
    memory_overprov_max_duration_to_timeout_ratio: float = LAMBDA_MEMORY_OVERPROV_MAX_DURATION_TO_TIMEOUT_RATIO
    memory_overprov_min_invocations: int = LAMBDA_MEMORY_OVERPROV_MIN_INVOCATIONS
    memory_overprov_target_memory_ratio: float = LAMBDA_MEMORY_OVERPROV_TARGET_MEMORY_RATIO
    memory_overprov_duration_slowdown_factor: float = LAMBDA_MEMORY_OVERPROV_DURATION_SLOWDOWN_FACTOR

    max_findings_per_type: int = LAMBDA_MAX_FINDINGS_PER_TYPE


def _safe_str(value: Any) -> str:
    """Return a safe string representation."""

    return str(value or "")


def _safe_int(value: Any, *, default: int = 0) -> int:
    """Best-effort integer conversion."""

    if isinstance(value, bool):
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    """Best-effort float conversion."""

    if isinstance(value, bool):
        return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _is_access_denied(exc: ClientError) -> bool:
    """Return True when a ClientError is access-denied shaped."""

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


def _p95(values: Sequence[float]) -> float:
    """Compute a floor-index p95 from numeric values."""

    numbers: list[float] = []
    for value in values:
        as_float = _safe_float(value, default=-1.0)
        if as_float >= 0.0:
            numbers.append(as_float)
    p95_value = percentile(numbers, 95.0, method="floor")
    if p95_value is None:
        return 0.0
    return float(p95_value)


def _estimate_compute_cost_usd(
    *,
    monthly_invocations: float,
    duration_seconds: float,
    memory_mb: int,
    usd_per_gb_second: float,
) -> float:
    """Estimate Lambda compute cost from invocations * duration * memory."""

    if monthly_invocations <= 0.0 or duration_seconds <= 0.0 or memory_mb <= 0 or usd_per_gb_second <= 0.0:
        return 0.0
    gb_seconds = float(monthly_invocations) * float(duration_seconds) * (float(memory_mb) / 1024.0)
    return money(gb_seconds * float(usd_per_gb_second))


def _resolve_lambda_gb_second_price(ctx: RunContext, *, region: str) -> tuple[float, str, int]:
    """Resolve Lambda compute price (USD per GB-second) best-effort."""

    fallback = float(LAMBDA_FALLBACK_GB_SECOND_USD)
    pricing = getattr(getattr(ctx, "services", None), "pricing", None)
    if pricing is None:
        return fallback, "PricingService unavailable; using fallback Lambda compute price.", 30

    location_for_region = getattr(pricing, "location_for_region", None)
    get_price = getattr(pricing, "get_on_demand_unit_price", None)
    if not callable(location_for_region) or not callable(get_price):
        return fallback, "PricingService missing expected methods; using fallback Lambda compute price.", 30

    try:
        location = str(location_for_region(region) or "")
    except (AttributeError, TypeError, ValueError):
        location = ""
    if not location:
        return fallback, "Pricing region mapping missing; using fallback Lambda compute price.", 30

    attempts: list[tuple[str, list[dict[str, str]]]] = [
        (
            "Lambda-GB-Second",
            [
                {"Field": "location", "Value": location},
                {"Field": "group", "Value": "AWS-Lambda-Duration"},
            ],
        ),
        (
            "GB-Second",
            [
                {"Field": "location", "Value": location},
                {"Field": "usagetype", "Value": "Lambda-GB-Second"},
            ],
        ),
        (
            "Seconds",
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Serverless"},
            ],
        ),
    ]

    for unit, filters in attempts:
        try:
            quote = get_price(service_code="AWSLambda", filters=filters, unit=unit)
        except (ClientError, BotoCoreError, TypeError, ValueError):
            continue

        for attr in ("unit_price_usd", "unit_price", "price"):
            try:
                raw_price = getattr(quote, attr, None)
                if raw_price is None:
                    continue
                unit_price = float(raw_price)
            except (AttributeError, TypeError, ValueError):
                continue
            if unit_price > 0.0:
                return unit_price, "PricingService resolved Lambda compute unit price.", 70

    return fallback, "Pricing lookup failed; using fallback Lambda compute price.", 30


class _LambdaCloudWatchMetrics:
    """Batch CloudWatch metric fetcher for Lambda invocations and duration."""

    def __init__(self, cloudwatch: Any) -> None:
        self._cloudwatch = cloudwatch

    def daily_invocations_and_duration(
        self,
        *,
        function_names: Sequence[str],
        start: Any,
        end: Any,
    ) -> dict[str, dict[str, list[float]]]:
        """Return daily metric series by function name.

        Shape:
        {
          "fn-a": {"invocations": [..], "duration_ms": [..]},
        }
        """

        out: dict[str, dict[str, list[float]]] = {
            fn: {"invocations": [], "duration_ms": []}
            for fn in function_names
        }
        if not function_names:
            return out

        # CloudWatch GetMetricData limit: 500 queries per request.
        # We emit two queries per function => 200 functions/request for headroom.
        batch_size = 200
        for i in range(0, len(function_names), batch_size):
            batch = [name for name in function_names[i:i + batch_size] if name]
            if not batch:
                continue

            queries: list[dict[str, Any]] = []
            id_to_key: dict[str, tuple[str, str]] = {}
            for idx, fn_name in enumerate(batch):
                inv_id = f"i{idx}"
                dur_id = f"d{idx}"
                dimensions = [{"Name": "FunctionName", "Value": fn_name}]
                queries.append(
                    {
                        "Id": inv_id,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": "Invocations",
                                "Dimensions": dimensions,
                            },
                            "Period": 86400,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                )
                queries.append(
                    {
                        "Id": dur_id,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": "Duration",
                                "Dimensions": dimensions,
                            },
                            "Period": 86400,
                            "Stat": "p95",
                        },
                        "ReturnData": True,
                    }
                )
                id_to_key[inv_id] = (fn_name, "invocations")
                id_to_key[dur_id] = (fn_name, "duration_ms")

            next_token: str | None = None
            while True:
                request: dict[str, Any] = {
                    "MetricDataQueries": queries,
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampAscending",
                }
                if next_token:
                    request["NextToken"] = next_token
                response = self._cloudwatch.get_metric_data(**request)

                for row in response.get("MetricDataResults", []) or []:
                    query_id = _safe_str(row.get("Id"))
                    if not query_id:
                        continue
                    mapped = id_to_key.get(query_id)
                    if mapped is None:
                        continue
                    fn_name, metric_key = mapped
                    values = row.get("Values", []) or []
                    series = out.setdefault(fn_name, {}).setdefault(metric_key, [])
                    for value in values:
                        as_float = _safe_float(value, default=-1.0)
                        if as_float >= 0.0:
                            series.append(as_float)

                next_token_raw = response.get("NextToken")
                next_token = str(next_token_raw) if next_token_raw else None
                if not next_token:
                    break

        return out


class LambdaFunctionsAnalyzerChecker(Checker):
    """Detect idle Lambda functions and memory-overprovisioning candidates."""

    checker_id = "aws.lambda.functions.analyzer"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: LambdaFunctionsAnalyzerConfig | None = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or LambdaFunctionsAnalyzerConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        """Run the checker and emit findings."""

        _LOGGER.info("Starting Lambda functions analyzer check")
        services = getattr(ctx, "services", None)
        if services is None:
            _LOGGER.warning("Lambda analyzer skipped: services are missing in context")
            return []

        lambda_client = getattr(services, "lambda_client", None)
        cloudwatch = getattr(services, "cloudwatch", None)
        if lambda_client is None:
            _LOGGER.warning("Lambda analyzer skipped: lambda_client is unavailable")
            return []

        region = str(
            getattr(services, "region", "")
            or safe_region_from_client(lambda_client)
            or safe_region_from_client(cloudwatch)
        )
        _LOGGER.debug("Lambda analyzer running", extra={"region": region})

        try:
            raw_functions = list(
                paginate_items(
                    lambda_client,
                    "list_functions",
                    "Functions",
                    paginator_fallback_exceptions=(
                        OperationNotPageableError,
                        AttributeError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ),
                )
            )
        except ClientError as exc:
            if _is_access_denied(exc):
                _LOGGER.warning("Access denied while listing Lambda functions", extra={"region": region})
                return [self._access_error(ctx, region=region, operation="lambda:ListFunctions", exc=exc)]
            raise

        _LOGGER.info("Listed Lambda functions", extra={"count": len(raw_functions), "region": region})
        functions = self._normalize_functions(raw_functions)
        if not functions:
            _LOGGER.info("No Lambda functions eligible for analysis", extra={"region": region})
            return []

        findings: list[FindingDraft] = []
        metrics: dict[str, dict[str, list[float]]] = {
            fn["function_name"]: {"invocations": [], "duration_ms": []} for fn in functions
        }

        if cloudwatch is not None:
            end = now_utc()
            start = end - timedelta(days=max(1, int(self._cfg.lookback_days)))
            try:
                fetcher = _LambdaCloudWatchMetrics(cloudwatch)
                metrics = fetcher.daily_invocations_and_duration(
                    function_names=[fn["function_name"] for fn in functions],
                    start=start,
                    end=end,
                )
            except ClientError as exc:
                if _is_access_denied(exc):
                    _LOGGER.warning(
                        "Access denied while fetching Lambda CloudWatch metrics",
                        extra={"region": region},
                    )
                    findings.append(
                        self._missing_permission(
                            ctx,
                            region=region,
                            operation="cloudwatch:GetMetricData",
                            message=(
                                "CloudWatch GetMetricData is required to evaluate Lambda idle and "
                                "memory-overprovisioning signals."
                            ),
                        )
                    )
                else:
                    _LOGGER.warning(
                        "CloudWatch ClientError while fetching Lambda metrics",
                        extra={"region": region},
                    )
                    findings.append(self._cloudwatch_error(ctx, region=region, operation="get_metric_data", exc=exc))
            except BotoCoreError as exc:
                _LOGGER.warning(
                    "CloudWatch BotoCoreError while fetching Lambda metrics",
                    extra={"region": region},
                )
                findings.append(self._cloudwatch_error(ctx, region=region, operation="get_metric_data", exc=exc))

        usd_per_gb_second, price_notes, price_conf = _resolve_lambda_gb_second_price(ctx, region=region)
        emitted: dict[str, int] = {"idle": 0, "memory_overprovisioned": 0}
        for fn in functions:
            function_name = fn["function_name"]
            function_arn = fn["function_arn"]
            runtime = fn["runtime"]
            memory_mb = fn["memory_mb"]
            timeout_seconds = fn["timeout_seconds"]

            function_metrics = metrics.get(function_name, {})
            invocations = list(function_metrics.get("invocations", []) or [])
            duration_ms = list(function_metrics.get("duration_ms", []) or [])

            idle_signal = self._is_idle(invocations)
            if idle_signal and emitted["idle"] < self._cfg.max_findings_per_type:
                emitted["idle"] += 1
                findings.append(
                    self._idle_finding(
                        ctx,
                        region=region,
                        function_name=function_name,
                        function_arn=function_arn,
                        runtime=runtime,
                        memory_mb=memory_mb,
                        p95_daily_invocations=_p95(invocations),
                    )
                )
                continue

            if emitted["memory_overprovisioned"] >= self._cfg.max_findings_per_type:
                continue

            overprov = self._memory_overprovisioned_candidate(
                invocations=invocations,
                duration_ms=duration_ms,
                memory_mb=memory_mb,
                timeout_seconds=timeout_seconds,
            )
            if overprov is None:
                continue

            emitted["memory_overprovisioned"] += 1
            findings.append(
                self._memory_overprovisioned_finding(
                    ctx,
                    region=region,
                    function_name=function_name,
                    function_arn=function_arn,
                    runtime=runtime,
                    memory_mb=memory_mb,
                    timeout_seconds=timeout_seconds,
                    p95_duration_ms=overprov["p95_duration_ms"],
                    p95_daily_invocations=overprov["p95_daily_invocations"],
                    monthly_invocations=overprov["monthly_invocations"],
                    usd_per_gb_second=usd_per_gb_second,
                    price_notes=price_notes,
                    price_conf=price_conf,
                )
            )

        _LOGGER.info(
            "Lambda analyzer completed",
            extra={
                "region": region,
                "functions": len(functions),
                "findings": len(findings),
                "idle_findings": emitted["idle"],
                "memory_overprovisioned_findings": emitted["memory_overprovisioned"],
            },
        )
        return findings

    def _normalize_functions(self, functions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Normalize Lambda list_functions records into deterministic internal shape."""

        normalized: list[dict[str, Any]] = []
        for raw in functions:
            function_name = _safe_str(raw.get("FunctionName")).strip()
            if not function_name:
                continue

            state = _safe_str(raw.get("State")).strip().lower()
            if state and state not in {"active", "inactive"}:
                continue

            normalized.append(
                {
                    "function_name": function_name,
                    "function_arn": _safe_str(raw.get("FunctionArn")).strip(),
                    "runtime": _safe_str(raw.get("Runtime")).strip(),
                    "memory_mb": _safe_int(raw.get("MemorySize"), default=0),
                    "timeout_seconds": _safe_int(raw.get("Timeout"), default=0),
                }
            )

        normalized.sort(key=lambda item: (item["function_name"], item["function_arn"]))
        return normalized

    def _is_idle(self, invocations: Sequence[float]) -> bool:
        """Return True when invocation series indicates an idle/unused function."""

        if len(invocations) < int(self._cfg.min_daily_datapoints):
            return False
        return _p95(invocations) <= float(self._cfg.idle_p95_daily_invocations_threshold)

    def _memory_overprovisioned_candidate(
        self,
        *,
        invocations: Sequence[float],
        duration_ms: Sequence[float],
        memory_mb: int,
        timeout_seconds: int,
    ) -> dict[str, float] | None:
        """Return candidate metrics when the function meets overprovisioning heuristics."""

        if len(invocations) < int(self._cfg.min_daily_datapoints):
            return None
        if len(duration_ms) < int(self._cfg.min_daily_datapoints):
            return None
        if memory_mb < int(self._cfg.memory_overprov_min_allocated_mb):
            return None

        p95_duration_ms = _p95(duration_ms)
        if p95_duration_ms <= 0.0:
            return None
        if p95_duration_ms > float(self._cfg.memory_overprov_max_p95_duration_ms):
            return None

        if timeout_seconds > 0:
            duration_to_timeout = (p95_duration_ms / 1000.0) / float(timeout_seconds)
            if duration_to_timeout > float(self._cfg.memory_overprov_max_duration_to_timeout_ratio):
                return None

        inv_total = 0.0
        for value in invocations:
            inv_total += max(0.0, _safe_float(value, default=0.0))
        if inv_total < float(self._cfg.memory_overprov_min_invocations):
            return None

        days_observed = float(max(1, len(invocations)))
        monthly_invocations = (inv_total / days_observed) * 30.0
        return {
            "p95_duration_ms": p95_duration_ms,
            "p95_daily_invocations": _p95(invocations),
            "monthly_invocations": monthly_invocations,
        }

    def _access_error(self, ctx: RunContext, *, region: str, operation: str, exc: ClientError) -> FindingDraft:
        """Build a permission finding for ListFunctions failures."""

        code = ""
        try:
            code = str(exc.response.get("Error", {}).get("Code", ""))
        except (TypeError, ValueError, AttributeError):
            code = ""
        return FindingDraft(
            check_id="aws.lambda.functions.access.error",
            check_name="Lambda access error",
            category="governance",
            status="info",
            severity=Severity(level="info", score=100),
            title="Lambda permissions missing for analyzer checks",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="lambda",
                resource_type="account",
                resource_id=self._account.account_id,
                resource_arn="",
            ),
            message=f"Access denied calling {operation} in region '{region}'. ErrorCode={code}.",
            recommendation="Grant lambda:ListFunctions and cloudwatch:GetMetricData for Lambda analyzer signals.",
            estimate_notes="Informational finding emitted when permissions are missing.",
            estimate_confidence=0,
        ).with_issue(operation=operation, region=region)

    def _cloudwatch_error(self, ctx: RunContext, *, region: str, operation: str, exc: Exception) -> FindingDraft:
        """Build an informational CloudWatch error finding."""

        return FindingDraft(
            check_id="aws.lambda.functions.cloudwatch.error",
            check_name="Lambda analyzer CloudWatch error",
            category="governance",
            status="info",
            severity=Severity(level="info", score=120),
            title=f"Unable to evaluate Lambda metrics ({operation})",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="cloudwatch",
                resource_type="metric",
                resource_id=self._account.account_id,
                resource_arn="",
            ),
            message=str(exc),
            recommendation="Validate CloudWatch metric permissions and retry the scan.",
            estimate_notes="Informational finding emitted when CloudWatch metric reads fail.",
            estimate_confidence=0,
        ).with_issue(operation=operation, region=region)

    def _missing_permission(
        self,
        ctx: RunContext,
        *,
        region: str,
        operation: str,
        message: str,
    ) -> FindingDraft:
        """Build an informational missing-permission finding."""

        return FindingDraft(
            check_id="aws.lambda.functions.missing.permission",
            check_name="Lambda analyzer missing permission",
            category="governance",
            status="info",
            severity=Severity(level="info", score=110),
            title=f"Missing permission to evaluate Lambda analyzer ({operation})",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="cloudwatch",
                resource_type="permission",
                resource_id=self._account.account_id,
                resource_arn="",
            ),
            message=message,
            recommendation="Grant the missing permission(s) and re-run the scan.",
            estimate_notes="Informational finding emitted when required metric permissions are missing.",
            estimate_confidence=0,
        ).with_issue(operation=operation, region=region)

    def _idle_finding(
        self,
        ctx: RunContext,
        *,
        region: str,
        function_name: str,
        function_arn: str,
        runtime: str,
        memory_mb: int,
        p95_daily_invocations: float,
    ) -> FindingDraft:
        """Build an idle/unused Lambda finding."""

        return FindingDraft(
            check_id="aws.lambda.functions.unused",
            check_name="Lambda function unused/idle",
            category="cost",
            status="fail",
            severity=Severity(level="low", score=320),
            title=f"Lambda function {function_name} appears idle",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="lambda",
                resource_type="function",
                resource_id=function_name,
                resource_arn=function_arn,
            ),
            message=(
                f"Over the last {int(self._cfg.lookback_days)} days, this function's p95 daily invocations is "
                f"{p95_daily_invocations:.2f}."
            ),
            recommendation=(
                "Confirm business usage. Remove, disable event sources, or consolidate this function if no longer needed."
            ),
            dimensions={
                "runtime": runtime,
                "memory_mb": str(memory_mb),
                "p95_daily_invocations": f"{p95_daily_invocations:.2f}",
                "lookback_days": str(int(self._cfg.lookback_days)),
            },
            estimate_notes="Usage signal only; cost estimate intentionally omitted.",
            estimate_confidence=20,
            issue_key={"function_name": function_name, "signal": "idle"},
        )

    def _memory_overprovisioned_finding(
        self,
        ctx: RunContext,
        *,
        region: str,
        function_name: str,
        function_arn: str,
        runtime: str,
        memory_mb: int,
        timeout_seconds: int,
        p95_duration_ms: float,
        p95_daily_invocations: float,
        monthly_invocations: float,
        usd_per_gb_second: float,
        price_notes: str,
        price_conf: int,
    ) -> FindingDraft:
        """Build a memory overprovisioning candidate finding."""

        target_memory_mb = max(128, int(float(memory_mb) * float(self._cfg.memory_overprov_target_memory_ratio)))
        current_duration_seconds = p95_duration_ms / 1000.0
        projected_duration_seconds = current_duration_seconds * float(self._cfg.memory_overprov_duration_slowdown_factor)

        estimated_current_cost = _estimate_compute_cost_usd(
            monthly_invocations=monthly_invocations,
            duration_seconds=current_duration_seconds,
            memory_mb=memory_mb,
            usd_per_gb_second=usd_per_gb_second,
        )
        estimated_projected_cost = _estimate_compute_cost_usd(
            monthly_invocations=monthly_invocations,
            duration_seconds=projected_duration_seconds,
            memory_mb=target_memory_mb,
            usd_per_gb_second=usd_per_gb_second,
        )
        estimated_savings = money(max(0.0, estimated_current_cost - estimated_projected_cost))

        confidence = max(20, min(int(price_conf), 55))
        notes = (
            f"{price_notes} Heuristic assumes memory can be reduced to ~{target_memory_mb} MB and duration may "
            f"increase by {int((self._cfg.memory_overprov_duration_slowdown_factor - 1.0) * 100)}%."
        )

        return FindingDraft(
            check_id="aws.lambda.functions.memory.overprovisioned",
            check_name="Lambda memory potentially overprovisioned",
            category="cost",
            status="fail",
            severity=Severity(level="medium", score=560),
            title=f"Lambda function {function_name} may be overprovisioned for memory",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="lambda",
                resource_type="function",
                resource_id=function_name,
                resource_arn=function_arn,
            ),
            message=(
                f"Configured memory is {memory_mb} MB, while observed p95 duration is {p95_duration_ms:.1f} ms "
                f"with p95 daily invocations {p95_daily_invocations:.1f}."
            ),
            recommendation=(
                "Run Lambda Power Tuning or staged canary tests at lower memory settings to validate a cheaper "
                "configuration while preserving latency/error objectives."
            ),
            estimated_monthly_cost=estimated_current_cost,
            estimated_monthly_savings=estimated_savings,
            estimate_confidence=confidence,
            estimate_notes=notes,
            dimensions={
                "runtime": runtime,
                "memory_mb": str(memory_mb),
                "suggested_memory_mb": str(target_memory_mb),
                "timeout_seconds": str(timeout_seconds),
                "p95_duration_ms": f"{p95_duration_ms:.2f}",
                "p95_daily_invocations": f"{p95_daily_invocations:.2f}",
                "estimated_monthly_invocations": f"{monthly_invocations:.2f}",
            },
            issue_key={"function_name": function_name, "signal": "memory_overprovisioned"},
        )


SPEC = "checks.aws.lambda_functions_analyzer:LambdaFunctionsAnalyzerChecker"


@register_checker(SPEC)
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> LambdaFunctionsAnalyzerChecker:
    """Instantiate checker from runner bootstrap."""

    account_id = _safe_str(bootstrap.get("aws_account_id") or bootstrap.get("account_id")).strip()
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for LambdaFunctionsAnalyzerChecker)")

    billing_id = _safe_str(
        bootstrap.get("aws_billing_account_id")
        or bootstrap.get("billing_account_id")
        or account_id
    ).strip()
    return LambdaFunctionsAnalyzerChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_id),
    )
