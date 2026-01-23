from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Set

from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity
from checks.registry import register_checker


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class RDSSnapshotsCleanupChecker:
    """Detect old manual RDS snapshots and orphaned RDS snapshots.

    Rules:
    - Orphaned snapshots always win (no duplicate findings)
    - Orphan detection applies to ALL snapshots (manual or not)
    - Old snapshot detection applies ONLY to non-orphaned manual snapshots
    """

    checker_id = "aws.rds.snapshots.cleanup"

    def __init__(self, *, stale_days: int = 30) -> None:
        self._stale_days = stale_days

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "rds", None):
            raise RuntimeError("RDSSnapshotsCleanupChecker requires ctx.services.rds")

        rds = ctx.services.rds
        now = _now_utc()
        cutoff = now - timedelta(days=self._stale_days)

        try:
            instances = self._list_db_instances(rds)
            clusters = self._list_db_clusters(rds)
        except ClientError:
            return []

        try:
            for s in self._list_db_snapshots(rds):
                yield from self._evaluate_db_snapshot(ctx, s, instances, clusters, cutoff)
        except ClientError:
            return []

        try:
            for s in self._list_cluster_snapshots(rds):
                yield from self._evaluate_cluster_snapshot(ctx, s, clusters, cutoff)
        except ClientError:
            return []

    def _evaluate_db_snapshot(
        self,
        ctx,
        s: dict,
        instances: Set[str],
        clusters: Set[str],
        cutoff: datetime,
    ) -> Iterable[FindingDraft]:
        sid = s.get("DBSnapshotIdentifier") or ""
        snapshot_type = (s.get("SnapshotType") or "").lower()
        created = _utc(s.get("SnapshotCreateTime"))

        src_instance = s.get("DBInstanceIdentifier")
        is_orphan = bool(src_instance and src_instance not in instances)

        if is_orphan:
            yield self._orphan_finding(ctx, sid, created, "rds_db_snapshot")
            return

        if not snapshot_type.startswith("manual"):
            return

        if not created or created > cutoff:
            return

        yield self._old_manual_finding(ctx, sid, created, "rds_db_snapshot")

    def _evaluate_cluster_snapshot(
        self,
        ctx,
        s: dict,
        clusters: Set[str],
        cutoff: datetime,
    ) -> Iterable[FindingDraft]:
        sid = s.get("DBClusterSnapshotIdentifier") or ""
        snapshot_type = (s.get("SnapshotType") or "").lower()
        created = _utc(s.get("SnapshotCreateTime"))

        src_cluster = s.get("DBClusterIdentifier")
        is_orphan = bool(src_cluster and src_cluster not in clusters)

        if is_orphan:
            yield self._orphan_finding(ctx, sid, created, "rds_cluster_snapshot")
            return

        if not snapshot_type.startswith("manual"):
            return

        if not created or created > cutoff:
            return

        yield self._old_manual_finding(ctx, sid, created, "rds_cluster_snapshot")

    def _orphan_finding(
        self,
        ctx,
        snapshot_id: str,
        created: Optional[datetime],
        resource_type: str,
    ) -> FindingDraft:
        return FindingDraft(
            check_id="aws.rds.snapshots.orphaned",
            check_name="Orphaned RDS snapshot",
            category="cost_optimization",
            status="fail",
            severity=Severity(level="medium", score=60),
            title="RDS snapshot is orphaned",
            message=f"Snapshot '{snapshot_id}' is not associated with any existing RDS resource.",
            recommendation="Review and delete orphaned snapshots if they are no longer required.",
            scope=Scope(
                cloud=ctx.cloud,
                billing_account_id="",
                account_id="",
                region=ctx.services.rds.meta.region_name,
                service="AmazonRDS",
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
                f"{created.date().isoformat()} and exceeds retention."
            ),
            recommendation="Delete old manual snapshots if they are no longer required.",
            scope=Scope(
                cloud=ctx.cloud,
                billing_account_id="",
                account_id="",
                region=ctx.services.rds.meta.region_name,
                service="AmazonRDS",
                resource_type=resource_type,
                resource_id=snapshot_id,
                resource_arn="",
            ),
            issue_key={"manual_old": True},
            estimated_monthly_savings="",
            estimate_confidence=0,
        )

    def _list_db_instances(self, rds) -> Set[str]:
        ids: Set[str] = set()
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if "DBInstanceIdentifier" in db:
                    ids.add(db["DBInstanceIdentifier"])
        return ids

    def _list_db_clusters(self, rds) -> Set[str]:
        ids: Set[str] = set()
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for c in page.get("DBClusters", []):
                if "DBClusterIdentifier" in c:
                    ids.add(c["DBClusterIdentifier"])
        return ids

    def _list_db_snapshots(self, rds):
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate():
            for s in page.get("DBSnapshots", []):
                yield s

    def _list_cluster_snapshots(self, rds):
        paginator = rds.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate():
            for s in page.get("DBClusterSnapshots", []):
                yield s


@register_checker("checks.aws.rds_snapshots_cleanup:RDSSnapshotsCleanupChecker")
def _factory(ctx, bootstrap):
    stale_days = int(bootstrap.get("rds_snapshot_stale_days", 30))
    return RDSSnapshotsCleanupChecker(stale_days=stale_days)
