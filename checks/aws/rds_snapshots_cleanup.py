from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Set

from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity
from checks.registry import register_checker


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None


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


class RDSSnapshotsCleanupChecker:
    """Detect old manual RDS snapshots and orphaned RDS snapshots.

    Rules:
    - Orphaned snapshots always win (no duplicate findings)
    - Orphan detection applies to ALL snapshots (manual or not)
    - Old snapshot detection applies ONLY to non-orphaned manual snapshots
    """

    checker_id = "aws.rds.snapshots.cleanup"

    def __init__(self, *, account: AwsAccountContext, stale_days: int = 30) -> None:
        self._account = account
        self._stale_days = stale_days

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "rds", None):
            raise RuntimeError("RDSSnapshotsCleanupChecker requires ctx.services.rds")

        rds = ctx.services.rds
        region = _safe_region_from_client(rds)

        now = _now_utc()
        cutoff = now - timedelta(days=self._stale_days)

        # Inventory (best effort). If we can't list sources, emit a single INFO finding.
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

        src_instance = snap.get("DBInstanceIdentifier")
        is_orphan = bool(src_instance and src_instance not in instances)

        # Orphan wins (no duplicate findings).
        if is_orphan:
            yield self._orphan_finding(ctx, sid, created, region, resource_type="rds_db_snapshot")
            return

        # Old manual applies only to non-orphaned manual-ish snapshots
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        yield self._old_manual_finding(ctx, sid, created, region, resource_type="rds_db_snapshot")

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

        src_cluster = snap.get("DBClusterIdentifier")
        is_orphan = bool(src_cluster and src_cluster not in clusters)

        # Orphan wins (no duplicate findings).
        if is_orphan:
            yield self._orphan_finding(ctx, sid, created, region, resource_type="rds_cluster_snapshot")
            return

        # Old manual applies only to non-orphaned manual-ish snapshots
        if not snapshot_type.startswith("manual"):
            return
        if not created or created > cutoff:
            return

        yield self._old_manual_finding(ctx, sid, created, region, resource_type="rds_cluster_snapshot")

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
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type="rds_inventory",
                resource_id=operation,
                resource_arn="",
            ),
            issue_key={"operation": operation, "error": code},
            estimated_monthly_savings="",
            estimate_confidence=0,
        )

    def _orphan_finding(
        self,
        ctx,
        snapshot_id: str,
        created: Optional[datetime],
        region: str,
        resource_type: str,
    ) -> FindingDraft:
        created_str = created.isoformat().replace("+00:00", "Z") if created else "unknown time"
        return FindingDraft(
            check_id="aws.rds.snapshots.orphaned",
            check_name="Orphaned RDS snapshot",
            category="cost_optimization",
            status="fail",
            severity=Severity(level="medium", score=60),
            title="RDS snapshot is orphaned",
            message=f"Snapshot '{snapshot_id}' appears orphaned (created {created_str}).",
            recommendation="Review and delete orphaned snapshots if they are no longer required.",
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type=resource_type,
                resource_id=snapshot_id,
                resource_arn="",
            ),
            issue_key={"orphaned": True},
            estimated_monthly_savings="",
            estimate_confidence=0,
        )

    def _old_manual_finding(
        self,
        ctx,
        snapshot_id: str,
        created: datetime,
        region: str,
        resource_type: str,
    ) -> FindingDraft:
        return FindingDraft(
            check_id="aws.rds.snapshots.manual_old",
            check_name="Old manual RDS snapshot",
            category="cost_optimization",
            status="fail",
            severity=Severity(level="low", score=30),
            title="Manual RDS snapshot is old",
            message=(
                f"Manual snapshot '{snapshot_id}' was created on "
                f"{created.date().isoformat()} and exceeds retention ({self._stale_days}d)."
            ),
            recommendation="Delete old manual snapshots if they are no longer required.",
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type=resource_type,
                resource_id=snapshot_id,
                resource_arn="",
            ),
            issue_key={"manual_old": True, "stale_days": self._stale_days},
            estimated_monthly_savings="",
            estimate_confidence=0,
        )

    def _base_scope(self, ctx, *, region: str, resource_type: str, resource_id: str, resource_arn: str) -> Scope:
        # billing_account_id/account_id are required by your contract, so always populate.
        account_id = self._account.account_id
        billing_account_id = self._account.billing_account_id or account_id

        return Scope(
            cloud=ctx.cloud,
            billing_account_id=billing_account_id,
            account_id=account_id,
            region=region,
            service="AmazonRDS",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
        )

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

    account = AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id)
    return RDSSnapshotsCleanupChecker(account=account, stale_days=stale_days)
