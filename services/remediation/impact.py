"""Closed-loop remediation impact tracking primitives.

This module computes deterministic remediation impact snapshots from:
- `remediation_actions` execution state
- `runs` latest ready run metadata
- `finding_presence` historical membership/savings
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from apps.backend.db import execute_conn, fetch_all_dict_conn, fetch_one_dict_conn

_STATUS_COMPLETED = "completed"
_STATUS_FAILED = "failed"

_VERIFY_PENDING = "pending_post_run"
_VERIFY_RESOLVED = "verified_resolved"
_VERIFY_PERSISTENT = "verified_persistent"
_VERIFY_FAILED = "execution_failed"


@dataclass(frozen=True)
class ImpactMetrics:
    """Derived remediation impact metrics for one action.

    Args:
        verification_status: Verification lifecycle for the action impact.
        realized_monthly_savings: Realized monthly savings (USD).
        realization_rate_pct: Realization rate percentage when baseline > 0.
    """

    verification_status: str
    realized_monthly_savings: float
    realization_rate_pct: float | None


@dataclass(frozen=True)
class _LatestRun:
    """Latest ready run metadata for one tenant/workspace scope."""

    run_id: str
    run_ts: datetime


@dataclass(frozen=True)
class _MetricInputs:
    """Inputs for deterministic remediation impact metric derivation."""

    action_status: str
    baseline_estimated: float
    current_estimated: float | None
    present_in_latest: bool | None
    latest_run_ts: datetime | None
    finalized_at: datetime


def _coerce_dt(value: Any) -> datetime | None:
    """Coerce datetime-like values to UTC-aware datetime."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _coerce_float(value: Any) -> float:
    """Coerce value to float with deterministic fallback to zero."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _derive_metrics(inputs: _MetricInputs) -> ImpactMetrics:
    """Derive verification status and realized savings for one action."""
    baseline = max(0.0, inputs.baseline_estimated)
    current = max(0.0, inputs.current_estimated or 0.0)
    status_norm = str(inputs.action_status or "").strip().lower()
    failed_or_pending = _VERIFY_FAILED if status_norm == _STATUS_FAILED else _VERIFY_PENDING

    if status_norm != _STATUS_COMPLETED:
        return ImpactMetrics(
            verification_status=failed_or_pending,
            realized_monthly_savings=0.0,
            realization_rate_pct=(0.0 if baseline > 0 else None),
        )

    if inputs.latest_run_ts is None or inputs.latest_run_ts <= inputs.finalized_at:
        return ImpactMetrics(
            verification_status=_VERIFY_PENDING,
            realized_monthly_savings=0.0,
            realization_rate_pct=(0.0 if baseline > 0 else None),
        )

    if inputs.present_in_latest:
        realized = max(0.0, baseline - current)
        return ImpactMetrics(
            verification_status=_VERIFY_PERSISTENT,
            realized_monthly_savings=realized,
            realization_rate_pct=((realized / baseline) * 100.0 if baseline > 0 else None),
        )

    realized = baseline
    return ImpactMetrics(
        verification_status=_VERIFY_RESOLVED,
        realized_monthly_savings=realized,
        realization_rate_pct=((realized / baseline) * 100.0 if baseline > 0 else None),
    )


def _load_action(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action_id: str,
) -> dict[str, Any] | None:
    """Load one remediation action row by scoped primary key."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id, workspace, action_id, fingerprint, check_id, action_type, status, updated_at
        FROM remediation_actions
        WHERE tenant_id = %s AND workspace = %s AND action_id = %s
        """,
        (tenant_id, workspace, action_id),
    )


def _latest_ready_run(conn: Any, *, tenant_id: str, workspace: str) -> _LatestRun | None:
    """Return latest ready run metadata for a tenant/workspace."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT run_id, run_ts
        FROM runs
        WHERE tenant_id = %s AND workspace = %s AND status = 'ready'
        ORDER BY run_ts DESC, run_id DESC
        LIMIT 1
        """,
        (tenant_id, workspace),
    )
    if row is None:
        return None
    run_id = str(row.get("run_id") or "").strip()
    run_ts = _coerce_dt(row.get("run_ts"))
    if not run_id or run_ts is None:
        return None
    return _LatestRun(run_id=run_id, run_ts=run_ts)


def _baseline_estimated_before_finalized(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    finalized_at: datetime,
) -> float:
    """Resolve baseline monthly savings from latest presence snapshot before finalization."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT fp.estimated_monthly_savings
        FROM finding_presence fp
        JOIN runs r
          ON r.tenant_id = fp.tenant_id
         AND r.workspace = fp.workspace
         AND r.run_id = fp.run_id
        WHERE fp.tenant_id = %s
          AND fp.workspace = %s
          AND fp.fingerprint = %s
          AND r.status = 'ready'
          AND r.run_ts <= %s
        ORDER BY r.run_ts DESC, fp.run_id DESC
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint, finalized_at),
    )
    if row is not None:
        return _coerce_float(row.get("estimated_monthly_savings"))

    fallback = fetch_one_dict_conn(
        conn,
        """
        SELECT fp.estimated_monthly_savings
        FROM finding_presence fp
        JOIN runs r
          ON r.tenant_id = fp.tenant_id
         AND r.workspace = fp.workspace
         AND r.run_id = fp.run_id
        WHERE fp.tenant_id = %s
          AND fp.workspace = %s
          AND fp.fingerprint = %s
          AND r.status = 'ready'
        ORDER BY r.run_ts DESC, fp.run_id DESC
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint),
    )
    return _coerce_float((fallback or {}).get("estimated_monthly_savings"))


def _latest_presence_for_run(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    run_id: str,
) -> tuple[bool, float | None]:
    """Return (present_in_latest, current_estimated_monthly_savings) for one latest run."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT estimated_monthly_savings
        FROM finding_presence
        WHERE tenant_id = %s
          AND workspace = %s
          AND run_id = %s
          AND fingerprint = %s
        LIMIT 1
        """,
        (tenant_id, workspace, run_id, fingerprint),
    )
    if row is None:
        return False, None
    return True, _coerce_float(row.get("estimated_monthly_savings"))


def _build_impact_payload(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Build normalized remediation impact payload for one action row."""
    fingerprint = str(action.get("fingerprint") or "").strip()
    action_status = str(action.get("status") or "").strip().lower()
    finalized_at = _coerce_dt(action.get("updated_at")) or datetime.now(UTC)

    latest_run = _latest_ready_run(conn, tenant_id=tenant_id, workspace=workspace)
    latest_run_id = latest_run.run_id if latest_run is not None else None
    latest_run_ts = latest_run.run_ts if latest_run is not None else None

    baseline = _baseline_estimated_before_finalized(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        fingerprint=fingerprint,
        finalized_at=finalized_at,
    )

    present_in_latest: bool | None = None
    current_estimated: float | None = None
    if latest_run_id:
        present_in_latest, current_estimated = _latest_presence_for_run(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            fingerprint=fingerprint,
            run_id=latest_run_id,
        )

    metrics = _derive_metrics(
        _MetricInputs(
            action_status=action_status,
            baseline_estimated=baseline,
            current_estimated=current_estimated,
            present_in_latest=present_in_latest,
            latest_run_ts=latest_run_ts,
            finalized_at=finalized_at,
        )
    )
    return {
        "fingerprint": fingerprint,
        "check_id": str(action.get("check_id") or "").strip(),
        "action_type": str(action.get("action_type") or "").strip(),
        "action_status": action_status,
        "finalized_at": finalized_at,
        "latest_run_id": latest_run_id,
        "latest_run_ts": latest_run_ts,
        "present_in_latest": present_in_latest,
        "baseline_estimated": baseline,
        "current_estimated": current_estimated,
        "metrics": metrics,
    }


def upsert_action_impact(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action_id: str,
) -> bool:
    """Compute and upsert remediation impact snapshot for one action.

    Args:
        conn: Active database connection.
        tenant_id: Tenant scope.
        workspace: Workspace scope.
        action_id: Remediation action identifier.

    Returns:
        True when an impact row was written, else False.
    """
    action = _load_action(conn, tenant_id=tenant_id, workspace=workspace, action_id=action_id)
    if action is None:
        return False

    payload = _build_impact_payload(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        action=action,
    )

    execute_conn(
        conn,
        """
        INSERT INTO remediation_impact (
          tenant_id, workspace, action_id,
          fingerprint, check_id, action_type, action_status, verification_status,
          baseline_estimated_monthly_savings, current_estimated_monthly_savings,
          realized_monthly_savings, realization_rate_pct,
          latest_run_id, latest_run_ts, present_in_latest,
          finalized_at, computed_at, version
        )
        VALUES (
          %s, %s, %s,
          %s, %s, %s, %s, %s,
          %s, %s,
          %s, %s,
          %s, %s, %s,
          %s, now(), 1
        )
        ON CONFLICT (tenant_id, workspace, action_id)
        DO UPDATE SET
          fingerprint = EXCLUDED.fingerprint,
          check_id = EXCLUDED.check_id,
          action_type = EXCLUDED.action_type,
          action_status = EXCLUDED.action_status,
          verification_status = EXCLUDED.verification_status,
          baseline_estimated_monthly_savings = EXCLUDED.baseline_estimated_monthly_savings,
          current_estimated_monthly_savings = EXCLUDED.current_estimated_monthly_savings,
          realized_monthly_savings = EXCLUDED.realized_monthly_savings,
          realization_rate_pct = EXCLUDED.realization_rate_pct,
          latest_run_id = EXCLUDED.latest_run_id,
          latest_run_ts = EXCLUDED.latest_run_ts,
          present_in_latest = EXCLUDED.present_in_latest,
          finalized_at = EXCLUDED.finalized_at,
          computed_at = now(),
          version = remediation_impact.version + 1
        """,
        (
            tenant_id,
            workspace,
            action_id,
            payload["fingerprint"],
            payload["check_id"],
            payload["action_type"],
            payload["action_status"],
            payload["metrics"].verification_status,
            payload["baseline_estimated"],
            payload["current_estimated"],
            payload["metrics"].realized_monthly_savings,
            payload["metrics"].realization_rate_pct,
            payload["latest_run_id"],
            payload["latest_run_ts"],
            payload["present_in_latest"],
            payload["finalized_at"],
        ),
    )
    return True


def refresh_scope_action_impacts(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    limit: int = 500,
) -> int:
    """Backfill/update impact rows for recent completed/failed remediation actions."""
    rows = fetch_all_dict_conn(
        conn,
        """
        SELECT action_id
        FROM remediation_actions
        WHERE tenant_id = %s
          AND workspace = %s
          AND status = ANY(%s)
        ORDER BY updated_at DESC, action_id
        LIMIT %s
        """,
        (tenant_id, workspace, [_STATUS_COMPLETED, _STATUS_FAILED], max(1, int(limit))),
    )

    written = 0
    for row in rows:
        action_id = str(row.get("action_id") or "").strip()
        if not action_id:
            continue
        if upsert_action_impact(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            action_id=action_id,
        ):
            written += 1
    return written
