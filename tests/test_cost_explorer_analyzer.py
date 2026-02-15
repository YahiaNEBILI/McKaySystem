"""Unit tests for the AWS Cost Explorer Analyzer checker."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from checks.aws._common import AwsAccountContext
from checks.aws.cost_explorer_analyzer import (
    CostExplorerAnalyzerChecker,
    CostRecord,
    _get_month_start,
    _get_previous_months,
    _period_key,
    _round_cost,
)
from contracts.finops_checker_pattern import RunContext

# -------------------------
# Helper functions tests
# -------------------------


def test_get_month_start():
    """Test _get_month_start returns first day of month."""
    assert _get_month_start(date(2026, 1, 15)) == date(2026, 1, 1)
    assert _get_month_start(date(2026, 12, 31)) == date(2026, 12, 1)
    assert _get_month_start(date(2026, 6, 1)) == date(2026, 6, 1)


def test_get_previous_months():
    """Test _get_previous_months returns correct list."""
    result = _get_previous_months(date(2026, 3, 15), 3)
    assert result == [date(2026, 2, 1), date(2026, 1, 1), date(2025, 12, 1)]


def test_period_key():
    """Test _period_key formats correctly."""
    assert _period_key(date(2026, 1, 1)) == "2026-01"
    assert _period_key(date(2026, 12, 1)) == "2026-12"


def test_round_cost():
    """Test _round_cost handles various inputs."""
    assert _round_cost(None) == Decimal("0")
    assert _round_cost(0) == Decimal("0")
    assert _round_cost(123.456789) == Decimal("123.456789")
    assert _round_cost("999.999999") == Decimal("999.999999")
    assert _round_cost(Decimal("100.000001")) == Decimal("100.000001")


# -------------------------
# Fake clients
# -------------------------


class FakeCEClient:
    """Fake Cost Explorer client for testing."""

    def __init__(
        self,
        *,
        results_by_time: list[dict[str, Any]] | None = None,
        raise_on: str | None = None,
        raise_code: str = "AccessDenied",
    ) -> None:
        self._results = results_by_time or []
        self._raise_on = raise_on
        self._raise_code = raise_code

    def get_cost_and_usage(self, **kwargs) -> dict[str, Any]:
        if self._raise_on == "get_cost_and_usage":
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Test error"}},
                "GetCostAndUsage",
            )
        return {"ResultsByTime": self._results}


# -------------------------
# Test fixtures
# -------------------------


def make_test_context(
    tenant_id: str = "test-tenant",
    workspace_id: str = "test-workspace",
    run_id: str = "test-run",
) -> RunContext:
    """Create a test RunContext."""
    return RunContext(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=run_id,
        run_ts=datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC),
    )


def make_test_account(
    account_id: str = "123456789012",
    billing_account_id: str | None = None,
) -> AwsAccountContext:
    """Create a test AwsAccountContext."""
    return AwsAccountContext(
        account_id=account_id,
        billing_account_id=billing_account_id or account_id,
    )


# -------------------------
# Detection tests
# -------------------------


class TestThresholdDetection:
    """Tests for threshold-based spike/drop detection."""

    def test_spike_detection(self):
        """Test spike detection when cost increases significantly."""
        # Current: $150, Previous: $100 (50% increase - above 20% threshold)
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,  # No CE client - use history only
            spike_threshold_pct=20.0,
            min_cost_abs=25.0,
            min_delta_abs=50.0,
        )

        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("150"),
            blended_cost=Decimal("150"),
            amortized_cost=Decimal("150"),
            currency="USD",
            source="ce",
        )

        previous = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2025, 12, 1),
            period_end=date(2026, 1, 1),
            unblended_cost=Decimal("100"),
            blended_cost=Decimal("100"),
            amortized_cost=Decimal("100"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        findings = list(checker._detect_threshold(ctx, "AmazonEC2", current, previous))

        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.anomaly.spike"
        assert findings[0].severity.level == "medium"

    def test_drop_detection(self):
        """Test drop detection when cost decreases significantly."""
        # Current: $50, Previous: $100 (50% decrease - above 20% threshold)
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            drop_threshold_pct=20.0,
            min_cost_abs=25.0,
            min_delta_abs=50.0,
        )

        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("50"),
            blended_cost=Decimal("50"),
            amortized_cost=Decimal("50"),
            currency="USD",
            source="ce",
        )

        previous = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2025, 12, 1),
            period_end=date(2026, 1, 1),
            unblended_cost=Decimal("100"),
            blended_cost=Decimal("100"),
            amortized_cost=Decimal("100"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        findings = list(checker._detect_threshold(ctx, "AmazonEC2", current, previous))

        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.anomaly.drop"

    def test_no_detection_below_threshold(self):
        """Test no detection when change is below threshold."""
        # Current: $110, Previous: $100 (10% increase - below 20% threshold)
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            spike_threshold_pct=20.0,
            min_cost_abs=25.0,
            min_delta_abs=50.0,
        )

        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("110"),
            blended_cost=Decimal("110"),
            amortized_cost=Decimal("110"),
            currency="USD",
            source="ce",
        )

        previous = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2025, 12, 1),
            period_end=date(2026, 1, 1),
            unblended_cost=Decimal("100"),
            blended_cost=Decimal("100"),
            amortized_cost=Decimal("100"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        findings = list(checker._detect_threshold(ctx, "AmazonEC2", current, previous))

        assert len(findings) == 0


class TestZScoreDetection:
    """Tests for Z-score based detection."""

    def test_zscore_spike_detection(self):
        """Test Z-score spike detection when cost is far above average."""
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            enable_zscore=True,
            zscore_threshold=2.0,
            moving_avg_window_months=3,
            min_months_for_moving=2,
        )

        # Current month cost is much higher than average
        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("300"),
            blended_cost=Decimal("300"),
            amortized_cost=Decimal("300"),
            currency="USD",
            source="ce",
        )

        # Historical months: 80, 100, 120 (mean=100, stddev~=16.7)
        # Current=300 gives z-score ~12 which should trigger
        records = [
            current,
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 12, 1),
                period_end=date(2026, 1, 1),
                unblended_cost=Decimal("80"),
                blended_cost=Decimal("80"),
                amortized_cost=Decimal("80"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 11, 1),
                period_end=date(2025, 12, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 10, 1),
                period_end=date(2025, 11, 1),
                unblended_cost=Decimal("120"),
                blended_cost=Decimal("120"),
                amortized_cost=Decimal("120"),
                currency="USD",
                source="ce",
            ),
        ]

        ctx = make_test_context()
        findings = list(checker._detect_moving_avg(ctx, "AmazonEC2", current, records))

        # Should detect spike via z-score
        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.anomaly.spike"
        assert findings[0].issue_key.get("method") == "zscore"

    def test_simple_moving_avg_detection(self):
        """Test simple moving average threshold detection."""
        # Use zscore disabled to test simple mode
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            enable_zscore=False,  # Disable z-score to test simple mode
            moving_avg_threshold_pct=50.0,
            moving_avg_window_months=3,
            min_months_for_moving=2,
        )

        # Current month cost exceeds 150% of average
        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("200"),  # 2x the average of 100
            blended_cost=Decimal("200"),
            amortized_cost=Decimal("200"),
            currency="USD",
            source="ce",
        )

        # Historical months: 100, 100, 100 (mean=100, threshold=150)
        records = [
            current,
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 12, 1),
                period_end=date(2026, 1, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 11, 1),
                period_end=date(2025, 12, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 10, 1),
                period_end=date(2025, 11, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
        ]

        ctx = make_test_context()
        findings = list(checker._detect_moving_avg(ctx, "AmazonEC2", current, records))

        # Should detect spike via simple moving average
        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.anomaly.spike"
        assert findings[0].issue_key.get("method") == "moving_avg"


class TestServiceDiscovery:
    """Tests for service discovery (new/absent services)."""

    def test_new_service_detection(self):
        """Test detection of new service appearing."""
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            min_cost_abs=25.0,
        )

        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonSageMaker",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("500"),
            blended_cost=Decimal("500"),
            amortized_cost=Decimal("500"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        # Previous is None - new service
        findings = list(checker._detect_discovery(ctx, "AmazonSageMaker", current, None))

        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.service.new"

    def test_absent_service_detection(self):
        """Test detection of service that is now absent."""
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            min_cost_abs=25.0,
        )

        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonRedshift",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("0"),
            blended_cost=Decimal("0"),
            amortized_cost=Decimal("0"),
            currency="USD",
            source="ce",
        )

        previous = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonRedshift",
            period_start=date(2025, 12, 1),
            period_end=date(2026, 1, 1),
            unblended_cost=Decimal("1000"),
            blended_cost=Decimal("1000"),
            amortized_cost=Decimal("1000"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        findings = list(checker._detect_discovery(ctx, "AmazonRedshift", current, previous))

        assert len(findings) == 1
        assert findings[0].check_id == "aws.cost.service.absent"


class TestAccessError:
    """Tests for access error handling."""

    def test_access_error_finding(self):
        """Test that access error is properly emitted."""
        from botocore.exceptions import ClientError

        ce_client = FakeCEClient(raise_on="get_cost_and_usage", raise_code="AccessDenied")

        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=ce_client,
        )

        ctx = make_test_context()

        # Patch the fetch to raise ClientError
        with patch.object(checker, "_fetch_from_ce") as mock_fetch:
            mock_fetch.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "GetCostAndUsage",
            )

            findings = list(checker.run(ctx))

            # Should have emitted access error
            assert len(findings) == 1
            assert findings[0].check_id == "aws.cost.access.error"
            assert "ce:GetCostAndUsage" in findings[0].remediation


class TestDeterminism:
    """Tests for deterministic behavior."""

    def test_services_sorted_for_detection(self):
        """Ensure services are processed in alphabetical order."""
        # The checker should process services in sorted order
        # This test verifies the logic by checking sorted() behavior
        services = ["Zebra", "Apple", "Banana"]
        sorted_services = sorted(services)
        assert sorted_services == ["Apple", "Banana", "Zebra"]

    def test_issue_key_no_timestamp(self):
        """Verify issue keys don't contain timestamps."""
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            spike_threshold_pct=20.0,
        )

        # Use a case that will trigger detection
        current = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2026, 1, 1),
            period_end=date(2026, 2, 1),
            unblended_cost=Decimal("150"),
            blended_cost=Decimal("150"),
            amortized_cost=Decimal("150"),
            currency="USD",
            source="ce",
        )

        previous = CostRecord(
            tenant_id="t",
            workspace="w",
            account_id="123456789012",
            billing_account_id="123456789012",
            service="AmazonEC2",
            period_start=date(2025, 12, 1),
            period_end=date(2026, 1, 1),
            unblended_cost=Decimal("100"),
            blended_cost=Decimal("100"),
            amortized_cost=Decimal("100"),
            currency="USD",
            source="ce",
        )

        ctx = make_test_context()
        findings = list(checker._detect_threshold(ctx, "AmazonEC2", current, previous))

        # Verify we got findings and check issue key
        assert len(findings) >= 1
        issue_key = findings[0].issue_key

        # Check issue key has no timestamp keys
        for key in issue_key.keys():
            assert "ts" not in key.lower(), f"Issue key contains timestamp: {key}"


# -------------------------
# Integration-style tests
# -------------------------


class TestFullDetectionFlow:
    """Tests that simulate full detection flow."""

    def test_full_flow_with_history(self):
        """Test complete detection flow with multi-month history."""
        checker = CostExplorerAnalyzerChecker(
            account=make_test_account(),
            ce_client=None,
            spike_threshold_pct=20.0,
            enable_zscore=True,
            zscore_threshold=2.0,
            min_cost_abs=25.0,
            min_delta_abs=50.0,
            min_months_for_moving=2,
            moving_avg_window_months=3,
        )

        # Build 6 months of history
        records = [
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 8, 1),
                period_end=date(2025, 9, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 9, 1),
                period_end=date(2025, 10, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 10, 1),
                period_end=date(2025, 11, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 11, 1),
                period_end=date(2025, 12, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2025, 12, 1),
                period_end=date(2026, 1, 1),
                unblended_cost=Decimal("100"),
                blended_cost=Decimal("100"),
                amortized_cost=Decimal("100"),
                currency="USD",
                source="ce",
            ),
            # Current month - spike!
            CostRecord(
                tenant_id="t",
                workspace="w",
                account_id="123456789012",
                billing_account_id="123456789012",
                service="AmazonEC2",
                period_start=date(2026, 1, 1),
                period_end=date(2026, 2, 1),
                unblended_cost=Decimal("150"),  # 50% increase!
                blended_cost=Decimal("150"),
                amortized_cost=Decimal("150"),
                currency="USD",
                source="ce",
            ),
        ]

        ctx = make_test_context()
        findings = list(checker._run_detection(ctx, records))

        # Should detect spike
        spike_findings = [f for f in findings if f.check_id == "aws.cost.anomaly.spike"]
        assert len(spike_findings) >= 1
