from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional, Set, Tuple

from botocore.exceptions import ClientError

from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Scope, Severity


SUPPRESS_TAG_KEYS = { "retain", "legal-hold", "backup-policy", "suppress", "downgrade", }


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_region_from_client(rds_client) -> str:
    try:
        return str(getattr(getattr(rds_client, "meta", None), "region_name", "") or "")
    except Exception:  # pragma: no cover
        return ""


def _arn_region(arn: str) -> str:
    # arn:partition:service:region:account:resource...
    try:
        parts = arn.split(":")
        if len(parts) >= 4 and parts[0] == "arn":
            return parts[3] or ""
    except Exception:  # pragma: no cover
        return ""
    return ""


def _fmt_money_usd(amount: float) -> str:
    # Wire-format money as string (decimal-friendly downstream).
    return f"{amount:.2f}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Best-effort float conversion, mypy/pylance-friendly."""
    try:
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return default


class RDSSnapshotsCleanupChecker:
    """Detect orphaned RDS snapshots and old manual RDS snapshots.

    Rules:
    - Orphan detection is evaluated first for ALL snapshots.
    - If orphaned -> emit only the orphaned finding (no duplicates).
    - Old snapshot detection applies ONLY to non-orphaned snapshots whose type startswith "manual".
    - Cost estimation is approximate and emitted in structured fields:
        * estimated_monthly_cost
        * estimated_monthly_savings
      (never embedded in message)
    """

    checker_id = "aws.rds.snapshots.cleanup"

    def _extract_tags(self, snap: dict) -> dict[str, str]:
        tags = {}
        for t in snap.get("TagList", []) or []:
            key = str(t.get("Key") or "").strip().lower()
            val = str(t.get("Value") or "").strip().lower()
            if key:
                tags[key] = val
        return tags


    def _should_suppress(self, tags: dict[str, str]) -> bool:
        # If tag key exists with any value → suppress
        for k in tags:
            if k in SUPPRESS_TAG_KEYS:
                return True
        # If tag value matches suppression keywords
        for v in tags.values():
            if v in SUPPRESS_TAG_KEYS:
                return True
        return False

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
        region = _safe_region_from_client(rds)
        cutoff = _now_utc() - timedelta(days=self._stale_days)

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
                yield from self._evaluate_db_snapshot(ctx, snap, instances, cutoff, region)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "describe_db_snapshots", exc)
            return

        # Cluster snapshots (Aurora)
        try:
            for snap in self._list_cluster_snapshots(rds):
                yield from self._evaluate_cluster_snapshot(ctx, snap, clusters, cutoff, region)
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
    ) -> Iterable[FindingDraft]:
        sid = str(snap.get("DBSnapshotIdentifier") or "")
        snapshot_type = str(snap.get("SnapshotType") or "").lower()
        created = _utc(snap.get("SnapshotCreateTime"))
        arn = self._snapshot_arn(snap, "db")

        tags = self._extract_tags(snap)
        if self._should_suppress(tags):
            return  # ignore this snapshot entirely

        # Orphan detection first (ALL snapshots) with false-positive guards.
        if self._is_cross_region_snapshot(snap, region, arn):
            is_orphan = False
        else:
            src_instance = snap.get("DBInstanceIdentifier")
            is_orphan = bool(src_instance and str(src_instance) not in instances)

        if is_orphan:
            est = self._estimate_snapshot_cost_usd(snap, kind="db")
            yield self._orphan_finding(ctx, sid, created, region, "rds_db_snapshot", arn, est, tags)
            return

        # Old manual applies only to non-orphaned manual-ish snapshots.
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        est = self._estimate_snapshot_cost_usd(snap, kind="db")
        yield self._old_manual_finding(ctx, sid, created, region, "rds_db_snapshot", arn, est, tags)

    def _evaluate_cluster_snapshot(
        self,
        ctx,
        snap: dict,
        clusters: Set[str],
        cutoff: datetime,
        region: str,
    ) -> Iterable[FindingDraft]:
        sid = str(snap.get("DBClusterSnapshotIdentifier") or "")
        snapshot_type = str(snap.get("SnapshotType") or "").lower()
        created = _utc(snap.get("SnapshotCreateTime"))
        arn = self._snapshot_arn(snap, "cluster")

        tags = self._extract_tags(snap)
        if self._should_suppress(tags):
            return

        # Orphan detection first (ALL snapshots) with false-positive guards.
        if self._is_cross_region_snapshot(snap, region, arn):
            is_orphan = False
        else:
            src_cluster = snap.get("DBClusterIdentifier")
            is_orphan = bool(src_cluster and str(src_cluster) not in clusters)

        if is_orphan:
            est = self._estimate_snapshot_cost_usd(snap, kind="cluster")
            yield self._orphan_finding(ctx, sid, created, region, "rds_cluster_snapshot", arn, est, tags)
            return

        # Old manual applies only to non-orphaned manual-ish snapshots.
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        est = self._estimate_snapshot_cost_usd(snap, kind="cluster")
        yield self._old_manual_finding(ctx, sid, created, region, "rds_cluster_snapshot", arn, est, tags)

    # ---------- estimation ----------

    def _estimate_snapshot_cost_usd(self, snap: dict, *, kind: str) -> Tuple[Optional[str], Optional[str], Optional[int], str]:
        """Return (estimated_monthly_cost, estimated_monthly_savings, confidence, notes).

        We estimate storage cost for snapshots as:
            allocated_storage_gb * price_per_gb_month

        - For DB snapshots, AWS typically provides AllocatedStorage.
        - For cluster snapshots (Aurora), AllocatedStorage is often missing; if missing -> unknown.
        """
        size_gb = _safe_float(snap.get("AllocatedStorage"), default=0.0)
        if size_gb <= 0.0:
            # Unknown sizing for many Aurora snapshots; avoid misleading 0.
            return (None, None, 10, f"Snapshot size unavailable for {kind} snapshot; cost not estimated.")

        est_cost = float(size_gb) * float(self._snapshot_gb_month_price_usd)
        if est_cost <= 0.0:
            return (None, None, 10, f"Estimated cost <= 0 for {kind} snapshot; check pricing inputs.")
        # Potential savings assumes deletion of the snapshot.
        money = _fmt_money_usd(est_cost)
        return (money, money, 50, f"Estimated using AllocatedStorage={size_gb:.0f}GB and ${self._snapshot_gb_month_price_usd}/GB-month.")

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
        est: Tuple[Optional[str], Optional[str], Optional[int], str],
        tags: dict[str, str]
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
        est: Tuple[Optional[str], Optional[str], Optional[int], str],
        tags: dict[str, str]
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
        return Scope(
            cloud=ctx.cloud,
            provider_partition=self._account.partition,
            billing_account_id=billing_account_id,
            account_id=account_id,
            region=region,
            service="AmazonRDS",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
        )

    def _snapshot_arn(self, snap: dict, kind: str) -> str:
        # Prefer ARN directly from AWS response.
        arn = snap.get("DBSnapshotArn") if kind == "db" else snap.get("DBClusterSnapshotArn")
        return str(arn or "")

    def _is_cross_region_snapshot(self, snap: dict, current_region: str, snapshot_arn: str) -> bool:
        # Guards to reduce false positives:
        # - Cross-region snapshot copies can reference identifiers that don't exist in this region.
        source_region = str(snap.get("SourceRegion") or "")
        if source_region and current_region and source_region != current_region:
            return True
        arn_region = _arn_region(snapshot_arn) if snapshot_arn else ""
        if arn_region and current_region and arn_region != current_region:
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
    price = _safe_float(bootstrap.get("rds_snapshot_gb_month_price_usd", 0.095), default=0.095)
    partition = str(bootstrap.get("aws_partition") or "aws")

    account = AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id, partition=partition)
    return RDSSnapshotsCleanupChecker(account=account, stale_days=stale_days, snapshot_gb_month_price_usd=price)
