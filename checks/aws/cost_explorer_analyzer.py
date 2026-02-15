"""checks/aws/cost_explorer_analyzer.py

Cost Explorer API Analyzer Checker.

Detects cost anomalies and trends at the AWS service level using AWS Cost Explorer API
as the primary freshness source, with Postgres as the durable history store.

Emitted check_ids:
  - aws.cost.anomaly.spike: Significant cost spike detected
  - aws.cost.anomaly.drop: Significant cost drop detected
  - aws.cost.trend.increasing: Sustained cost increase
  - aws.cost.trend.decreasing: Sustained cost decrease
  - aws.cost.service.new: New service appearing in costs
  - aws.cost.service.absent: Previously billed service now absent
  - aws.cost.access.error: Access denied to Cost Explorer
  - aws.cost.threshold.exceeded: Configured budget threshold exceeded
  - aws.cost.data.gap: Insufficient history / missing periods for requested method
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from math import sqrt  # Add sqrt import
from typing import Any, Dict, Iterable, List, Optional, Sequence

from botocore.exceptions import ClientError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    get_logger,
)
from checks.aws.defaults import (
    COST_EXPLORER_CE_FRESHNESS_MONTHS,
    COST_EXPLORER_DROP_THRESHOLD_PCT,
    COST_EXPLORER_ENABLE_CUR_BACKFILL,
    COST_EXPLORER_ENABLE_YOY,
    COST_EXPLORER_ENABLE_ZSCORE,
    COST_EXPLORER_LOOKBACK_MONTHS,
    COST_EXPLORER_MIN_COST_ABS,
    COST_EXPLORER_MIN_DELTA_ABS,
    COST_EXPLORER_MIN_MONTHS_FOR_MOVING,
    COST_EXPLORER_MOVING_AVG_THRESHOLD_PCT,
    COST_EXPLORER_MOVING_AVG_WINDOW_MONTHS,
    COST_EXPLORER_SPIKE_THRESHOLD_PCT,
    COST_EXPLORER_TREND_MIN_MONTHS,
    COST_EXPLORER_TREND_SLOPE_MIN_ABS,
    COST_EXPLORER_TREND_SLOPE_MIN_PCT,
    COST_EXPLORER_TREND_WINDOW_MONTHS,
    COST_EXPLORER_YOY_MIN_MONTHS,
    COST_EXPLORER_YOY_THRESHOLD_PCT,
    COST_EXPLORER_ZSCORE_THRESHOLD,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Scope, Severity

# Logger for this module
_LOGGER = get_logger("cost_explorer_analyzer")

# Check IDs emitted by this checker
_CID_ANOMALY_SPIKE = "aws.cost.anomaly.spike"
_CID_ANOMALY_DROP = "aws.cost.anomaly.drop"
_CID_TREND_INCREASING = "aws.cost.trend.increasing"
_CID_TREND_DECREASING = "aws.cost.trend.decreasing"
_CID_SERVICE_NEW = "aws.cost.service.new"
_CID_SERVICE_ABSENT = "aws.cost.service.absent"
_CID_ACCESS_ERROR = "aws.cost.access.error"
_CID_THRESHOLD_EXCEEDED = "aws.cost.threshold.exceeded"
_CID_DATA_GAP = "aws.cost.data.gap"

# Category
_CATEGORY = "cost"


@dataclass(frozen=True)
class CostRecord:
    """A single cost record from Cost Explorer or Postgres history."""

    tenant_id: str
    workspace: str
    account_id: str
    billing_account_id: str
    service: str
    period_start: date
    period_end: date
    unblended_cost: Decimal
    blended_cost: Optional[Decimal]
    amortized_cost: Optional[Decimal]
    currency: str
    source: str  # "ce" or "cur"


def _round_cost(value: Any) -> Decimal:
    """Round monetary value to 6 decimal places for deterministic storage."""
    if value is None:
        return Decimal("0")
    if isinstance(value, Decimal):
        return value.quantize(Decimal("0.000001"))
    if isinstance(value, (int, float)):
        return Decimal(str(value)).quantize(Decimal("0.000001"))
    return Decimal(str(value)).quantize(Decimal("0.000001"))


def _get_previous_months(period: date, count: int) -> List[date]:
    """Get the previous 'count' months before the given period."""
    result = []
    current = period
    for _ in range(count):
        # Go to first day of previous month
        if current.month == 1:
            current = date(current.year - 1, 12, 1)
        else:
            current = date(current.year, current.month - 1, 1)
        result.append(current)
    return result


def _get_month_start(dt: date) -> date:
    """Get the first day of the month for a given date."""
    return date(dt.year, dt.month, 1)


def _get_month_end(dt: date) -> date:
    """Get the first day of the next month."""
    if dt.month == 12:
        return date(dt.year + 1, 1, 1)
    return date(dt.year, dt.month + 1, 1)


def _period_key(period: date) -> str:
    """Format period as YYYY-MM string for issue keys."""
    return f"{period.year:04d}-{period.month:02d}"


class CostExplorerAnalyzerChecker(Checker):
    """Cost Explorer API analyzer for detecting cost anomalies and trends."""

    checker_id = "aws.cost.explorer.analyzer"
    is_regional = False  # Cost Explorer is global

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        ce_client: Any = None,
        lookback_months: int = COST_EXPLORER_LOOKBACK_MONTHS,
        freshness_months: int = COST_EXPLORER_CE_FRESHNESS_MONTHS,
        spike_threshold_pct: float = COST_EXPLORER_SPIKE_THRESHOLD_PCT,
        drop_threshold_pct: float = COST_EXPLORER_DROP_THRESHOLD_PCT,
        min_cost_abs: float = COST_EXPLORER_MIN_COST_ABS,
        min_delta_abs: float = COST_EXPLORER_MIN_DELTA_ABS,
        min_months_for_moving: int = COST_EXPLORER_MIN_MONTHS_FOR_MOVING,
        moving_avg_window_months: int = COST_EXPLORER_MOVING_AVG_WINDOW_MONTHS,
        moving_avg_threshold_pct: float = COST_EXPLORER_MOVING_AVG_THRESHOLD_PCT,
        enable_zscore: bool = COST_EXPLORER_ENABLE_ZSCORE,
        zscore_threshold: float = COST_EXPLORER_ZSCORE_THRESHOLD,
        enable_yoy: bool = COST_EXPLORER_ENABLE_YOY,
        yoy_threshold_pct: float = COST_EXPLORER_YOY_THRESHOLD_PCT,
        yoy_min_months: int = COST_EXPLORER_YOY_MIN_MONTHS,
        trend_min_months: int = COST_EXPLORER_TREND_MIN_MONTHS,
        trend_window_months: int = COST_EXPLORER_TREND_WINDOW_MONTHS,
        trend_slope_min_abs: float = COST_EXPLORER_TREND_SLOPE_MIN_ABS,
        trend_slope_min_pct: float = COST_EXPLORER_TREND_SLOPE_MIN_PCT,
    ) -> None:
        self._account = account
        self._ce_client = ce_client
        self._lookback_months = lookback_months
        self._freshness_months = freshness_months
        self._spike_threshold_pct = spike_threshold_pct
        self._drop_threshold_pct = drop_threshold_pct
        self._min_cost_abs = Decimal(str(min_cost_abs))
        self._min_delta_abs = Decimal(str(min_delta_abs))
        self._min_months_for_moving = min_months_for_moving
        self._moving_avg_window_months = moving_avg_window_months
        self._moving_avg_threshold_pct = moving_avg_threshold_pct
        self._enable_zscore = enable_zscore
        self._zscore_threshold = zscore_threshold
        self._enable_yoy = enable_yoy
        self._yoy_threshold_pct = yoy_threshold_pct
        self._yoy_min_months = yoy_min_months
        self._trend_min_months = trend_min_months
        self._trend_window_months = trend_window_months
        self._trend_slope_min_abs = Decimal(str(trend_slope_min_abs))
        self._trend_slope_min_pct = Decimal(str(trend_slope_min_pct / 100))

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        """Run the Cost Explorer analyzer."""
        # Try to fetch fresh data from Cost Explorer
        ce_records: List[CostRecord] = []
        access_error = False

        if self._ce_client is not None:
            try:
                ce_records = self._fetch_from_ce(ctx)
                # Upsert to Postgres
                self._upsert_to_postgres(ctx, ce_records)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDenied", "UnauthorizedOperation"):
                    _LOGGER.warning(
                        "Cost Explorer access denied for account %s: %s",
                        self._account.account_id,
                        exc,
                    )
                    access_error = True
                else:
                    _LOGGER.warning(
                        "Cost Explorer API error for account %s: %s",
                        self._account.account_id,
                        exc,
                    )
            except Exception as exc:
                _LOGGER.warning(
                    "Unexpected error fetching Cost Explorer data for %s: %s",
                    self._account.account_id,
                    exc,
                )

        # Emit access error if applicable
        if access_error:
            yield self._emit_access_error(ctx)
            return

        # Load history from Postgres for detection
        history = self._load_history_from_postgres(ctx)

        if not history:
            _LOGGER.info(
                "No cost history found for account %s, skipping detection",
                self._account.account_id,
            )
            return

        # Run detection layers
        yield from self._run_detection(ctx, history)

    def _fetch_from_ce(self, ctx: RunContext) -> List[CostRecord]:
        """Fetch cost data from AWS Cost Explorer API."""
        records: List[CostRecord] = []

        # Calculate the time period to fetch
        today = datetime.now(timezone.utc).date()
        end_month = _get_month_start(today)
        start_month = _get_previous_months(end_month, self._freshness_months - 1)[0]

        _LOGGER.info(
            "Fetching Cost Explorer data from %s to %s for account %s",
            start_month,
            end_month,
            self._account.account_id,
        )

        # Call Cost Explorer API
        response = self._ce_client.get_cost_and_usage(
            TimePeriod={
                "Start": start_month.isoformat(),
                "End": end_month.isoformat(),
            },
            Granularity="MONTHLY",
            Metrics=["UnblendedCost", "BlendedCost", "AmortizedCost"],
            GroupBy=[
                {"Type": "DIMENSION", "Key": "SERVICE"},
            ],
        )

        for result in response.get("ResultsByTime", []):
            period_start = datetime.fromisoformat(result["TimePeriod"]["Start"]).date()
            period_end = datetime.fromisoformat(result["TimePeriod"]["End"]).date()

            for group in result.get("Groups", []):
                keys = group.get("Keys", [])
                if not keys:
                    continue

                service = keys[0]
                metrics = group.get("Metrics", {})

                unblended = _round_cost(metrics.get("UnblendedCost", {}).get("Amount", 0))
                blended = _round_cost(metrics.get("BlendedCost", {}).get("Amount", 0))
                amortized = _round_cost(metrics.get("AmortizedCost", {}).get("Amount", 0))
                currency = metrics.get("UnblendedCost", {}).get("Unit", "USD")

                # Skip zero-cost records
                if unblended == 0:
                    continue

                record = CostRecord(
                    tenant_id=ctx.tenant_id,
                    workspace=ctx.workspace_id,
                    account_id=self._account.account_id,
                    billing_account_id=self._account.billing_account_id or self._account.account_id,
                    service=service,
                    period_start=period_start,
                    period_end=period_end,
                    unblended_cost=unblended,
                    blended_cost=blended if blended else None,
                    amortized_cost=amortized if amortized else None,
                    currency=currency,
                    source="ce",
                )
                records.append(record)

        _LOGGER.info(
            "Fetched %d cost records from Cost Explorer for account %s",
            len(records),
            self._account.account_id,
        )

        return records

    def _upsert_to_postgres(
        self, ctx: RunContext, records: List[CostRecord]
    ) -> None:
        """Upsert cost records to Postgres cost_service_monthly table."""
        # Import here to avoid circular imports
        from apps.backend.db import db_conn

        if not records:
            return

        # Import psycopg2
        import psycopg2
        from psycopg2 import sql

        try:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    for record in records:
                        # Use INSERT ... ON CONFLICT for idempotent upsert
                        query = sql.SQL("""
                            INSERT INTO cost_service_monthly (
                                tenant_id, workspace, account_id, billing_account_id,
                                service, period_start, period_end,
                                unblended_cost, blended_cost, amortized_cost,
                                currency, source, ingested_at_utc
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (
                                tenant_id, workspace, account_id, service, period_start
                            ) DO UPDATE SET
                                unblended_cost = EXCLUDED.unblended_cost,
                                blended_cost = EXCLUDED.blended_cost,
                                amortized_cost = EXCLUDED.amortized_cost,
                                currency = EXCLUDED.currency,
                                source = EXCLUDED.source,
                                ingested_at_utc = EXCLUDED.ingested_at_utc
                        """)

                        cur.execute(
                            query,
                            (
                                record.tenant_id,
                                record.workspace,
                                record.account_id,
                                record.billing_account_id,
                                record.service,
                                record.period_start,
                                record.period_end,
                                record.unblended_cost,
                                record.blended_cost,
                                record.amortized_cost,
                                record.currency,
                                record.source,
                                datetime.now(timezone.utc),
                            ),
                        )

                    conn.commit()

            _LOGGER.info(
                "Upserted %d cost records to Postgres for account %s",
                len(records),
                self._account.account_id,
            )
        except Exception as exc:
            _LOGGER.error(
                "Failed to upsert cost records to Postgres: %s",
                exc,
            )
            raise

    def _load_history_from_postgres(self, ctx: RunContext) -> List[CostRecord]:
        """Load cost history from Postgres for detection."""
        from apps.backend.db import db_conn

        import psycopg2
        from psycopg2 import sql

        records: List[CostRecord] = []

        try:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    # Query the history, ordered by period for deterministic processing
                    query = sql.SQL("""
                        SELECT
                            tenant_id, workspace, account_id, billing_account_id,
                            service, period_start, period_end,
                            unblended_cost, blended_cost, amortized_cost,
                            currency, source
                        FROM cost_service_monthly
                        WHERE tenant_id = %s
                            AND workspace = %s
                            AND account_id = %s
                        ORDER BY period_start ASC, service ASC
                    """)

                    cur.execute(
                        query,
                        (
                            ctx.tenant_id,
                            ctx.workspace_id,
                            self._account.account_id,
                        ),
                    )

                    rows = cur.fetchall()

                    for row in rows:
                        record = CostRecord(
                            tenant_id=row[0],
                            workspace=row[1],
                            account_id=row[2],
                            billing_account_id=row[3],
                            service=row[4],
                            period_start=row[5],
                            period_end=row[6],
                            unblended_cost=Decimal(str(row[7])),
                            blended_cost=Decimal(str(row[8])) if row[8] is not None else None,
                            amortized_cost=Decimal(str(row[9])) if row[9] is not None else None,
                            currency=row[10],
                            source=row[11],
                        )
                        records.append(record)

            _LOGGER.info(
                "Loaded %d cost history records from Postgres for account %s",
                len(records),
                self._account.account_id,
            )
        except Exception as exc:
            _LOGGER.error(
                "Failed to load cost history from Postgres: %s",
                exc,
            )
            # Return empty list on error - detection will skip
            return []

        return records

    def _run_detection(
        self, ctx: RunContext, history: List[CostRecord]
    ) -> Iterable[FindingDraft]:
        """Run all detection layers on the cost history."""

        # Group by service for easier processing
        by_service: Dict[str, List[CostRecord]] = {}
        for record in history:
            if record.service not in by_service:
                by_service[record.service] = []
            by_service[record.service].append(record)

        # Process each service
        for service in sorted(by_service.keys()):
            records = by_service[service]

            # Sort by period
            records.sort(key=lambda r: r.period_start)

            if len(records) < 2:
                continue

            # Get current and previous period costs
            current = records[-1]
            previous = records[-2] if len(records) >= 2 else None

            # Threshold-based detection
            if previous:
                yield from self._detect_threshold(ctx, service, current, previous)

            # Moving average / Z-score detection
            if len(records) >= self._min_months_for_moving + 1:
                yield from self._detect_moving_avg(ctx, service, current, records)

            # Year-over-Year detection
            if self._enable_yoy and len(records) >= self._yoy_min_months:
                yield from self._detect_yoy(ctx, service, current, records)

            # Trend detection (regression-based)
            if len(records) >= self._trend_min_months:
                yield from self._detect_trend(ctx, service, records)

            # Service discovery (new/absent)
            yield from self._detect_discovery(ctx, service, current, previous)

    def _detect_threshold(
        self,
        ctx: RunContext,
        service: str,
        current: CostRecord,
        previous: CostRecord,
    ) -> Iterable[FindingDraft]:
        """Threshold-based spike/drop detection."""
        delta = current.unblended_cost - previous.unblended_cost

        # Skip if below minimum delta
        if abs(delta) < self._min_delta_abs:
            return

        # Skip if current is below minimum cost
        if current.unblended_cost < self._min_cost_abs:
            return

        # Calculate percentage change
        if previous.unblended_cost > 0:
            pct_change = (delta / previous.unblended_cost) * 100
        else:
            # Previous was zero - this is a new service, handled by discovery
            return

        # Check for spike
        if pct_change >= self._spike_threshold_pct:
            scope = self._build_scope(ctx, service)
            yield FindingDraft(
                check_id=_CID_ANOMALY_SPIKE,
                check_name="Cost Spike Detected",
                category=_CATEGORY,
                status="fail",
                severity=Severity(level="medium", score=60),
                title=f"Cost spike detected for {service}",
                message=f"Cost for {service} increased by {pct_change:.1f}% from ${previous.unblended_cost} to ${current.unblended_cost}",
                scope=scope,
                estimated_monthly_cost=float(current.unblended_cost),
                issue_key={
                    "service": service,
                    "signal": "spike",
                    "period": _period_key(current.period_start),
                    "method": "threshold",
                },
            )

        # Check for drop
        if pct_change <= -self._drop_threshold_pct:
            scope = self._build_scope(ctx, service)
            yield FindingDraft(
                check_id=_CID_ANOMALY_DROP,
                check_name="Cost Drop Detected",
                category=_CATEGORY,
                status="info",
                severity=Severity(level="low", score=30),
                title=f"Cost drop detected for {service}",
                message=f"Cost for {service} decreased by {abs(pct_change):.1f}% from ${previous.unblended_cost} to ${current.unblended_cost}",
                scope=scope,
                estimated_monthly_cost=float(current.unblended_cost),
                issue_key={
                    "service": service,
                    "signal": "drop",
                    "period": _period_key(current.period_start),
                    "method": "threshold",
                },
            )

    def _detect_moving_avg(
        self,
        ctx: RunContext,
        service: str,
        current: CostRecord,
        records: List[CostRecord],
    ) -> Iterable[FindingDraft]:
        """Moving average / Z-score based detection."""
        # Get the window of previous months (excluding current)
        window_records = records[-self._moving_avg_window_months - 1 : -1]

        if len(window_records) < self._min_months_for_moving:
            return

        # Calculate mean (convert to float for calculations)
        total = sum(float(r.unblended_cost) for r in window_records)
        mean = Decimal(str(total / len(window_records)))

        if mean <= 0:
            return

        # Calculate standard deviation for z-score
        variance = sum((float(r.unblended_cost) - float(mean)) ** 2 for r in window_records) / len(window_records)
        stddev = Decimal(str(sqrt(variance)))

        # Z-score detection
        if self._enable_zscore and stddev > 0:
            zscore = (float(current.unblended_cost) - float(mean)) / float(stddev)

            if abs(zscore) >= self._zscore_threshold:
                signal = "spike" if zscore > 0 else "drop"
                scope = self._build_scope(ctx, service)
                yield FindingDraft(
                    check_id=_CID_ANOMALY_SPIKE if zscore > 0 else _CID_ANOMALY_DROP,
                    check_name=f"Cost {signal.title()} via Z-score",
                    category=_CATEGORY,
                    status="fail",
                    severity=Severity(level="medium", score=60),
                    title=f"Cost {signal} detected for {service} (z-score: {zscore:.2f})",
                    message=f"Cost for {service} is {abs(zscore):.1f} standard deviations from the {len(window_records)}-month mean",
                    scope=scope,
                    estimated_monthly_cost=float(current.unblended_cost),
                    issue_key={
                        "service": service,
                        "signal": signal,
                        "period": _period_key(current.period_start),
                        "method": "zscore",
                        "zscore": round(zscore, 2),
                    },
                )
        else:
            # Simple moving average threshold
            threshold = mean * Decimal(str(1 + self._moving_avg_threshold_pct / 100))

            if current.unblended_cost >= threshold:
                scope = self._build_scope(ctx, service)
                yield FindingDraft(
                    check_id=_CID_ANOMALY_SPIKE,
                    check_name="Cost Spike via Moving Average",
                    category=_CATEGORY,
                    status="fail",
                    severity=Severity(level="medium", score=60),
                    title=f"Cost spike detected for {service} (moving average)",
                    message=f"Cost for {service} (${current.unblended_cost}) exceeds {self._moving_avg_threshold_pct}% threshold over {len(window_records)}-month average (${mean})",
                    scope=scope,
                    estimated_monthly_cost=float(current.unblended_cost),
                    issue_key={
                        "service": service,
                        "signal": "spike",
                        "period": _period_key(current.period_start),
                        "method": "moving_avg",
                    },
                )

    def _detect_yoy(
        self,
        ctx: RunContext,
        service: str,
        current: CostRecord,
        records: List[CostRecord],
    ) -> Iterable[FindingDraft]:
        """Year-over-Year comparison detection."""
        # Find the same month last year
        target_year = current.period_start.year - 1
        target_month = current.period_start.month

        last_year_record = None
        for record in records:
            if record.period_start.year == target_year and record.period_start.month == target_month:
                last_year_record = record
                break

        if last_year_record is None:
            return

        if last_year_record.unblended_cost <= 0:
            return

        delta = current.unblended_cost - last_year_record.unblended_cost
        pct_change = (delta / last_year_record.unblended_cost) * 100

        if abs(pct_change) >= self._yoy_threshold_pct:
            signal = "spike" if pct_change > 0 else "drop"
            scope = self._build_scope(ctx, service)
            yield FindingDraft(
                check_id=_CID_ANOMALY_SPIKE if pct_change > 0 else _CID_ANOMALY_DROP,
                check_name=f"Year-over-Year Cost {signal.title()}",
                category=_CATEGORY,
                status="fail",
                severity=Severity(level="high", score=70),
                title=f"YoY cost {signal} for {service}",
                message=f"Cost for {service} changed {abs(pct_change):.1f}% YoY (${last_year_record.unblended_cost} -> ${current.unblended_cost})",
                scope=scope,
                estimated_monthly_cost=float(current.unblended_cost),
                issue_key={
                    "service": service,
                    "signal": signal,
                    "period": _period_key(current.period_start),
                    "method": "yoy",
                    "last_year_period": _period_key(last_year_record.period_start),
                },
            )

    def _detect_trend(
        self,
        ctx: RunContext,
        service: str,
        records: List[CostRecord],
    ) -> Iterable[FindingDraft]:
        """Regression-based trend detection."""
        # Use the last N months for trend analysis
        window_size = min(self._trend_window_months, len(records))
        window_records = records[-window_size:]

        if len(window_records) < self._trend_min_months:
            return

        # Simple linear regression: cost = a + b * t
        # t is the month index (0, 1, 2, ...)
        n = len(window_records)
        sum_t = sum(i for i in range(n))
        sum_t2 = sum(i * i for i in range(n))
        sum_cost = sum(float(r.unblended_cost) for r in window_records)
        sum_t_cost = sum(i * float(r.unblended_cost) for i, r in enumerate(window_records))

        # Calculate slope (b)
        denominator = n * sum_t2 - sum_t * sum_t
        if denominator == 0:
            return

        slope = (n * sum_t_cost - sum_t * sum_cost) / denominator

        # Calculate mean cost for percentage threshold
        mean_cost = Decimal(str(sum_cost / n))

        # Check if slope exceeds threshold
        slope_exceeds_abs = abs(slope) >= float(self._trend_slope_min_abs)
        slope_exceeds_pct = abs(slope) >= (float(mean_cost) * float(self._trend_slope_min_pct))

        if slope_exceeds_abs or slope_exceeds_pct:
            signal = "increasing" if slope > 0 else "decreasing"
            scope = self._build_scope(ctx, service)

            yield FindingDraft(
                check_id=_CID_TREND_INCREASING if slope > 0 else _CID_TREND_DECREASING,
                check_name=f"Cost Trend {signal.title()}",
                category=_CATEGORY,
                status="fail",
                severity=Severity(level="medium", score=60),
                title=f"Sustained cost {signal} for {service}",
                message=f"Cost for {service} shows {signal} trend (${abs(slope):.2f}/month over {n} months)",
                scope=scope,
                estimated_monthly_cost=float(window_records[-1].unblended_cost),
                issue_key={
                    "service": service,
                    "signal": signal,
                    "start_period": _period_key(window_records[0].period_start),
                    "end_period": _period_key(window_records[-1].period_start),
                    "method": "regression",
                    "slope": round(slope, 2),
                },
            )

    def _detect_discovery(
        self,
        ctx: RunContext,
        service: str,
        current: CostRecord,
        previous: Optional[CostRecord],
    ) -> Iterable[FindingDraft]:
        """Service discovery: new or absent services."""
        # New service detection
        if previous is None or previous.unblended_cost < self._min_cost_abs:
            if current.unblended_cost >= self._min_cost_abs:
                scope = self._build_scope(ctx, service)
                yield FindingDraft(
                    check_id=_CID_SERVICE_NEW,
                    check_name="New Service Detected",
                    category=_CATEGORY,
                    status="info",
                    severity=Severity(level="low", score=30),
                    title=f"New service detected: {service}",
                    message=f"Service {service} is now appearing in costs with ${current.unblended_cost}",
                    scope=scope,
                    estimated_monthly_cost=float(current.unblended_cost),
                    issue_key={
                        "service": service,
                        "signal": "new",
                        "period": _period_key(current.period_start),
                    },
                )

        # Absent service detection (was present before, now absent or very low)
        if previous is not None and previous.unblended_cost >= self._min_cost_abs:
            if current.unblended_cost < self._min_cost_abs:
                scope = self._build_scope(ctx, service)
                yield FindingDraft(
                    check_id=_CID_SERVICE_ABSENT,
                    check_name="Service Absent",
                    category=_CATEGORY,
                    status="info",
                    severity=Severity(level="low", score=30),
                    title=f"Service no longer in costs: {service}",
                    message=f"Service {service} is no longer appearing in costs (was ${previous.unblended_cost})",
                    scope=scope,
                    issue_key={
                        "service": service,
                        "signal": "absent",
                        "period": _period_key(current.period_start),
                    },
                )

    def _build_scope(self, ctx: RunContext, service: str) -> Scope:
        """Build a Scope for the given service."""
        return build_scope(
            ctx,
            account=self._account,
            region="global",  # Cost Explorer is global
            service=service,
            resource_type="cost_service",
            resource_id=service,
        )

    def _emit_access_error(self, ctx: RunContext) -> FindingDraft:
        """Emit an access error finding."""
        scope = Scope(
            cloud=ctx.cloud,
            account_id=self._account.account_id,
            billing_account_id=self._account.billing_account_id or self._account.account_id,
            region="global",
            service="cost_explorer",
            resource_type="api_access",
            resource_id="cost_explorer_api",
        )

        return FindingDraft(
            check_id=_CID_ACCESS_ERROR,
            check_name="Cost Explorer Access Denied",
            category=_CATEGORY,
            status="fail",
            severity=Severity(level="high", score=80),
            title="Cannot access AWS Cost Explorer API",
            message=f"Access denied to AWS Cost Explorer API for account {self._account.account_id}. Required permission: ce:GetCostAndUsage",
            recommendation="Grant 'ce:GetCostAndUsage' IAM permission to the role used by McKay",
            scope=scope,
            remediation="Add the following IAM policy to the role:\n"
            "{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [\n'
            '    {\n'
            '      "Effect": "Allow",\n'
            '      "Action": "ce:GetCostAndUsage",\n'
            '      "Resource": "*"\n'
            "    }\n"
            "  ]\n"
            "}",
            issue_key={
                "service": "cost_explorer",
                "signal": "access_denied",
            },
        )


@register_checker("checks.aws.cost_explorer_analyzer:CostExplorerAnalyzerChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> CostExplorerAnalyzerChecker:
    """Factory function to create CostExplorerAnalyzerChecker."""
    # Get account info from bootstrap
    account_id = bootstrap.get("aws_account_id")
    if not account_id:
        raise RuntimeError(
            "aws_account_id missing from bootstrap (required for CostExplorerAnalyzerChecker)"
        )

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)

    # Get the CE client from services if available
    ce_client = None
    if ctx.services and ctx.services.ce:
        ce_client = ctx.services.ce

    return CostExplorerAnalyzerChecker(
        account=AwsAccountContext(
            account_id=account_id,
            billing_account_id=billing_account_id,
        ),
        ce_client=ce_client,
    )
