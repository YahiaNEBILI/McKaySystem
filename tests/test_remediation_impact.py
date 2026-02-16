"""Unit tests for remediation impact derivation logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from services.remediation.impact import _derive_metrics, _MetricInputs


def test_derive_metrics_marks_completed_resolved_when_absent() -> None:
    """Completed actions should be fully realized once absent in a post-action run."""
    finalized_at = datetime.now(UTC)
    latest_run_ts = finalized_at + timedelta(hours=2)
    metrics = _derive_metrics(
        _MetricInputs(
            action_status="completed",
            baseline_estimated=120.0,
            current_estimated=None,
            present_in_latest=False,
            latest_run_ts=latest_run_ts,
            finalized_at=finalized_at,
        )
    )

    assert metrics.verification_status == "verified_resolved"
    assert metrics.realized_monthly_savings == 120.0
    assert metrics.realization_rate_pct == 100.0


def test_derive_metrics_marks_completed_persistent_with_partial_realization() -> None:
    """Completed actions should compute partial realization when finding persists."""
    finalized_at = datetime.now(UTC)
    latest_run_ts = finalized_at + timedelta(hours=1)
    metrics = _derive_metrics(
        _MetricInputs(
            action_status="completed",
            baseline_estimated=200.0,
            current_estimated=50.0,
            present_in_latest=True,
            latest_run_ts=latest_run_ts,
            finalized_at=finalized_at,
        )
    )

    assert metrics.verification_status == "verified_persistent"
    assert metrics.realized_monthly_savings == 150.0
    assert metrics.realization_rate_pct == 75.0


def test_derive_metrics_waits_for_post_action_run() -> None:
    """Completed actions should stay pending when no post-action ready run exists yet."""
    finalized_at = datetime.now(UTC)
    metrics = _derive_metrics(
        _MetricInputs(
            action_status="completed",
            baseline_estimated=80.0,
            current_estimated=None,
            present_in_latest=None,
            latest_run_ts=finalized_at,
            finalized_at=finalized_at,
        )
    )

    assert metrics.verification_status == "pending_post_run"
    assert metrics.realized_monthly_savings == 0.0
    assert metrics.realization_rate_pct == 0.0


def test_derive_metrics_failed_action_is_execution_failed() -> None:
    """Failed executions should report execution_failed with zero realized savings."""
    finalized_at = datetime.now(UTC)
    latest_run_ts = finalized_at + timedelta(hours=1)
    metrics = _derive_metrics(
        _MetricInputs(
            action_status="failed",
            baseline_estimated=100.0,
            current_estimated=100.0,
            present_in_latest=True,
            latest_run_ts=latest_run_ts,
            finalized_at=finalized_at,
        )
    )

    assert metrics.verification_status == "execution_failed"
    assert metrics.realized_monthly_savings == 0.0
    assert metrics.realization_rate_pct == 0.0
