"""
RDS Snapshots Cleanup Checker
=============================

This module implements an infra-native FinOps checker that analyzes Amazon RDS
DB snapshots and Aurora cluster snapshots to detect two classes of issues:

1. **Orphaned snapshots**
   Snapshots whose source DB instance or DB cluster no longer exists in the
   current region. These snapshots typically accumulate over time and represent
   pure waste. Orphan detection is evaluated for *all* snapshots (manual or
   automated). If a snapshot is identified as orphaned, only the orphaned
   finding is emitted (no duplicate findings).

2. **Old manual snapshots**
   Manual snapshots that exceed a configurable retention threshold (default:
   30 days). These snapshots often remain after migrations, upgrades, or
   operational tasks. Old snapshot detection applies only to non-orphaned
   snapshots whose type begins with ``"manual"``.

The checker also includes several production-grade behaviors:

- **Tag-based suppression**
  Snapshots tagged with keys or values indicating intentional retention
  (e.g., ``retain``, ``legal-hold``, ``backup-policy``, ``suppress``,
  ``downgrade``) are ignored entirely. This prevents false positives for
  compliance, DR, or operational workflows.

- **Cross-region false-positive guards**
  RDS snapshot copies may reference source identifiers that do not exist in
  the current region. The checker inspects both ``SourceRegion`` and the
  snapshot ARN to avoid incorrectly flagging these snapshots as orphaned.

- **Cost estimation**
  For DB snapshots, approximate monthly storage cost is estimated using
  ``AllocatedStorage`` and a configurable USD/GB-month price (default: 0.095).
  Aurora cluster snapshots generally do not expose reliable size information,
  so their cost is marked as unknown.

- **Graceful degradation**
  If the checker lacks permissions to list RDS instances, clusters, or
  snapshots, it emits a single informational finding describing the access
  error and stops cleanly.

- **Contract alignment**
  All findings are emitted as ``FindingDraft`` objects compatible with the
  FinOps engine contract:
    - deterministic scope and issue keys
    - stable fingerprint generation
    - consistent severity, category, and metadata fields

This checker is intended to be used by the FinOps engine runner and is
registered via ``@register_checker`` for automatic discovery.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Optional, Set, Tuple

from botocore.exceptions import ClientError

from checks.aws._common import (
    build_scope,
    AwsAccountContext,
    arn_region,
    is_suppressed,
    money,
    now_utc,
    safe_float,
    safe_region_from_client,
    utc,
    normalize_tags,
)
from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Scope, Severity


SUPPRESS_TAG_KEYS = {"retain", "legal-hold", "backup-policy"}


 


def _resolve_rds_snapshot_storage_price_usd_per_gb_month(
    ctx: Any, region: str, default_price: float
) -> tuple[float, str, int]:
    """
    Returns: (usd_per_gb_month, notes, confidence)
    """
    pricing = getattr(getattr(ctx, "services", None), "pricing", None)
    if pricing is None:
        return (default_price, "PricingService unavailable; using default price.", 30)

    try:
        quote = pricing.rds_backup_storage_gb_month(region=region)
    except Exception:
        quote = None

    if quote is None:
        return (default_price, "Pricing lookup failed/unknown; using default price.", 30)

    return (
        float(quote.unit_price_usd),
        f"PricingService {quote.source} as_of={quote.as_of.isoformat()} unit={quote.unit}",
        60 if quote.source == "cache" else 70,
    )


class RDSSnapshotsCleanupChecker:
    """Detect orphaned RDS snapshots and old manual RDS snapshots."""

    checker_id = "aws.rds.snapshots.cleanup"

    def _extract_tags(self, snap: dict) -> dict[str, str]:
        return normalize_tags(snap.get("TagList", []) or [])

    def _should_suppress(self, tags: dict[str, str]) -> bool:
        return is_suppressed(tags, suppress_keys=SUPPRESS_TAG_KEYS, suppress_values=SUPPRESS_TAG_KEYS)

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        stale_days: int = 30,
        snapshot_gb_month_price_usd: float = 0.095,
    ) -> None:
        self._account = account
        self._stale_days = stale_days
        self._snapshot_gb_month_price_usd = snapshot_gb_month_price_usd

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "rds", None):
            raise RuntimeError("RDSSnapshotsCleanupChecker requires ctx.services.rds")

        rds = ctx.services.rds
        region = safe_region_from_client(rds)
        cutoff = now_utc() - timedelta(days=self._stale_days)

        # Resolve pricing once per run/region (fast + cached).
        usd_per_gb_month, pricing_notes, pricing_conf = _resolve_rds_snapshot_storage_price_usd_per_gb_month(
            ctx,
            region,
            default_price=float(self._snapshot_gb_month_price_usd),
        )

        # Inventory (best effort). If we can't list sources, emit a single INFO finding and stop.
        try:
            instances = self._list_db_instances(rds)
            clusters = self._list_db_clusters(rds)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "describe_db_instances/describe_db_clusters", exc)
            return

        # DB snapshots
        try:
            for snap in self._list_db_snapshots(rds):
                yield from self._evaluate_db_snapshot(
                    ctx,
                    snap,
                    instances,
                    cutoff,
                    region,
                    usd_per_gb_month,
                    pricing_notes,
                    pricing_conf,
                )
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "describe_db_snapshots", exc)
            return

        # Cluster snapshots (Aurora)
        try:
            for snap in self._list_cluster_snapshots(rds):
                yield from self._evaluate_cluster_snapshot(
                    ctx,
                    snap,
                    clusters,
                    cutoff,
                    region,
                    usd_per_gb_month,
                    pricing_notes,
                    pricing_conf,
                )
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "describe_db_cluster_snapshots", exc)
            return

    # ---------- evaluation ----------

    def _evaluate_db_snapshot(
        self,
        ctx,
        snap: dict,
        instances: Set[str],
        cutoff: datetime,
        region: str,
        usd_per_gb_month: float,
        pricing_notes: str,
        pricing_conf: int,
    ) -> Iterable[FindingDraft]:
        sid = str(snap.get("DBSnapshotIdentifier") or "")
        snapshot_type = str(snap.get("SnapshotType") or "").lower()
        created = utc(snap.get("SnapshotCreateTime"))
        arn = self._snapshot_arn(snap, "db")

        tags = self._extract_tags(snap)
        if self._should_suppress(tags):
            return iter(())  # ignore this snapshot entirely

        # Orphan detection first (ALL snapshots) with false-positive guards.
        if self._is_cross_region_snapshot(snap, region, arn):
            is_orphan = False
        else:
            src_instance = snap.get("DBInstanceIdentifier")
            is_orphan = bool(src_instance and str(src_instance) not in instances)

        if is_orphan:
            est = self._estimate_snapshot_cost_usd(
                snap,
                kind="db",
                usd_per_gb_month=usd_per_gb_month,
                pricing_notes=pricing_notes,
                pricing_conf=pricing_conf,
            )
            yield self._orphan_finding(ctx, sid, created, region, "rds_db_snapshot", arn, est, tags)
            return

        # Old manual applies only to non-orphaned manual-ish snapshots.
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        est = self._estimate_snapshot_cost_usd(
            snap,
            kind="db",
            usd_per_gb_month=usd_per_gb_month,
            pricing_notes=pricing_notes,
            pricing_conf=pricing_conf,
        )
        yield self._old_manual_finding(ctx, sid, created, region, "rds_db_snapshot", arn, est, tags)

    def _evaluate_cluster_snapshot(
        self,
        ctx,
        snap: dict,
        clusters: Set[str],
        cutoff: datetime,
        region: str,
        usd_per_gb_month: float,
        pricing_notes: str,
        pricing_conf: int,
    ) -> Iterable[FindingDraft]:
        sid = str(snap.get("DBClusterSnapshotIdentifier") or "")
        snapshot_type = str(snap.get("SnapshotType") or "").lower()
        created = utc(snap.get("SnapshotCreateTime"))
        arn = self._snapshot_arn(snap, "cluster")

        tags = self._extract_tags(snap)
        if self._should_suppress(tags):
            return iter(())

        # Orphan detection first (ALL snapshots) with false-positive guards.
        if self._is_cross_region_snapshot(snap, region, arn):
            is_orphan = False
        else:
            src_cluster = snap.get("DBClusterIdentifier")
            is_orphan = bool(src_cluster and str(src_cluster) not in clusters)

        if is_orphan:
            est = self._estimate_snapshot_cost_usd(
                snap,
                kind="cluster",
                usd_per_gb_month=usd_per_gb_month,
                pricing_notes=pricing_notes,
                pricing_conf=pricing_conf,
            )
            yield self._orphan_finding(ctx, sid, created, region, "rds_cluster_snapshot", arn, est, tags)
            return

        # Old manual applies only to non-orphaned manual-ish snapshots.
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        est = self._estimate_snapshot_cost_usd(
            snap,
            kind="cluster",
            usd_per_gb_month=usd_per_gb_month,
            pricing_notes=pricing_notes,
            pricing_conf=pricing_conf,
        )
        yield self._old_manual_finding(ctx, sid, created, region, "rds_cluster_snapshot", arn, est, tags)

    # ---------- estimation ----------

    def _estimate_snapshot_cost_usd(
        self,
        snap: dict,
        *,
        kind: str,
        usd_per_gb_month: float,
        pricing_notes: str,
        pricing_conf: int,
    ) -> Tuple[Optional[float], Optional[float], Optional[int], str]:
        """Return (estimated_monthly_cost, estimated_monthly_savings, confidence, notes).

        We estimate storage cost for snapshots as:
            allocated_storage_gb * usd_per_gb_month
        """
        size_gb = safe_float(snap.get("AllocatedStorage"), default=0.0)
        if size_gb <= 0.0:
            # Unknown sizing for many Aurora snapshots; avoid misleading 0.
            return (None, None, 10, f"Snapshot size unavailable for {kind} snapshot; cost not estimated.")

        est_cost = float(size_gb) * float(usd_per_gb_month)
        if est_cost <= 0.0:
            return (None, None, 10, f"Estimated cost <= 0 for {kind} snapshot; check pricing inputs.")

        cost_usd = money(est_cost)

        # Base heuristic confidence is 50 (we only know storage, not requests/backup deltas).
        confidence = 50

        notes = (
            f"{pricing_notes}; "
            f"Estimated using AllocatedStorage={size_gb:.0f}GB and ${usd_per_gb_month}/GB-month."
        )
        # Potential savings assumes deletion of the snapshot.
        return (cost_usd, cost_usd, confidence, notes)

    # ---------- findings ----------

    def _access_error_finding(self, ctx, region: str, operation: str, exc: ClientError) -> FindingDraft:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return FindingDraft(
            check_id="aws.rds.snapshots.access_error",
            check_name="RDS snapshots access error",
            category="inventory",
            status="info",
            severity=Severity(level="low", score=10),
            title="Unable to list RDS snapshot inventory",
            message=f"Failed to call {operation} ({code}). Some snapshot checks were skipped.",
            recommendation="Grant rds:Describe* permissions to the scanner role and retry.",
            scope=self._base_scope(ctx, region=region, resource_type="rds_inventory", resource_id=operation, resource_arn=""),
            issue_key={"rule": "access_error", "operation": operation, "error": code},
            estimated_monthly_savings=None,
            estimated_monthly_cost=None,
            estimate_confidence=0,
            estimate_notes="",
        )

    def _orphan_finding(
        self,
        ctx,
        snapshot_id: str,
        created: Optional[datetime],
        region: str,
        resource_type: str,
        resource_arn: str,
        est: Tuple[Optional[float], Optional[float], Optional[int], str],
        tags: dict[str, str],
    ) -> FindingDraft:
        (est_cost, est_save, conf, notes) = est
        created_str = created.date().isoformat() if created else "unknown date"
        return FindingDraft(
            check_id="aws.rds.snapshots.orphaned",
            check_name="Orphaned RDS snapshot",
            category="waste",
            status="fail",
            severity=Severity(level="medium", score=70),
            title="RDS snapshot is orphaned",
            message=f"Snapshot '{snapshot_id}' appears orphaned (created {created_str}).",
            recommendation="Review and delete orphaned snapshots if they are no longer required.",
            scope=self._base_scope(ctx, region=region, resource_type=resource_type, resource_id=snapshot_id, resource_arn=resource_arn),
            issue_key={"rule": "orphaned", "snapshot_id": snapshot_id, "resource_type": resource_type},
            estimated_monthly_cost=est_cost,
            estimated_monthly_savings=est_save,
            estimate_confidence=conf,
            estimate_notes=notes,
            tags=tags,
        )

    def _old_manual_finding(
        self,
        ctx,
        snapshot_id: str,
        created: datetime,
        region: str,
        resource_type: str,
        resource_arn: str,
        est: Tuple[Optional[float], Optional[float], Optional[int], str],
        tags: dict[str, str],
    ) -> FindingDraft:
        (est_cost, est_save, conf, notes) = est
        return FindingDraft(
            check_id="aws.rds.snapshots.manual_old",
            check_name="Old manual RDS snapshot",
            category="waste",
            status="fail",
            severity=Severity(level="low", score=60),
            title="Manual RDS snapshot is old",
            message=(
                f"Manual snapshot '{snapshot_id}' was created on {created.date().isoformat()} "
                f"and exceeds retention ({self._stale_days}d)."
            ),
            recommendation="Delete old manual snapshots if they are no longer required.",
            scope=self._base_scope(ctx, region=region, resource_type=resource_type, resource_id=snapshot_id, resource_arn=resource_arn),
            issue_key={"rule": "manual_old", "snapshot_id": snapshot_id, "resource_type": resource_type, "stale_days": self._stale_days},
            estimated_monthly_cost=est_cost,
            estimated_monthly_savings=est_save,
            estimate_confidence=conf,
            estimate_notes=notes,
            tags=tags,
        )

    # ---------- scope / identity helpers ----------

    def _base_scope(self, ctx, *, region: str, resource_type: str, resource_id: str, resource_arn: str) -> Scope:
        account_id = self._account.account_id
        billing_account_id = self._account.billing_account_id or account_id
        return build_scope(
            ctx,
            account=self._account,
            region=region,
            service="AmazonRDS",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            billing_account_id=billing_account_id,
        )

    def _snapshot_arn(self, snap: dict, kind: str) -> str:
        arn = snap.get("DBSnapshotArn") if kind == "db" else snap.get("DBClusterSnapshotArn")
        return str(arn or "")

    def _is_cross_region_snapshot(self, snap: dict, current_region: str, snapshot_arn: str) -> bool:
        source_region = str(snap.get("SourceRegion") or "")
        if source_region and current_region and source_region != current_region:
            return True
        arn_reg = arn_region(snapshot_arn) if snapshot_arn else ""
        if arn_reg and current_region and arn_reg != current_region:
            return True
        return False

    # ---------- AWS listing helpers ----------

    def _list_db_instances(self, rds) -> Set[str]:
        ids: Set[str] = set()
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                ident = db.get("DBInstanceIdentifier")
                if ident:
                    ids.add(str(ident))
        return ids

    def _list_db_clusters(self, rds) -> Set[str]:
        ids: Set[str] = set()
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for c in page.get("DBClusters", []):
                ident = c.get("DBClusterIdentifier")
                if ident:
                    ids.add(str(ident))
        return ids

    def _list_db_snapshots(self, rds):
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate():
            for snap in page.get("DBSnapshots", []):
                yield snap

    def _list_cluster_snapshots(self, rds):
        paginator = rds.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate():
            for snap in page.get("DBClusterSnapshots", []):
                yield snap


@register_checker("checks.aws.rds_snapshots_cleanup:RDSSnapshotsCleanupChecker")
def _factory(ctx, bootstrap):
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for RDSSnapshotsCleanupChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    stale_days = int(bootstrap.get("rds_snapshot_stale_days", 30))
    price = safe_float(bootstrap.get("rds_snapshot_gb_month_price_usd", 0.095), default=0.095)
    partition = str(bootstrap.get("aws_partition") or "aws")

    account = AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id, partition=partition)
    return RDSSnapshotsCleanupChecker(account=account, stale_days=stale_days, snapshot_gb_month_price_usd=price)
