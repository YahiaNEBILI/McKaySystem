from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Set, Dict, Any, List

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity
from checks.registry import register_checker


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _region_from_client(client: BaseClient) -> str:
    return getattr(getattr(client, "meta", None), "region_name", "") or ""


def _safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _default_snapshot_price_gb_month_usd() -> float:
    # Rough default (US-East) for RDS snapshot storage. Can be overridden via bootstrap.
    return 0.095


def _snapshot_arn(*, partition: str, region: str, account_id: str, kind: str, snapshot_id: str) -> str:
    # kind is "snapshot" or "cluster-snapshot"
    # arn:aws:rds:<region>:<account>:snapshot:<id>
    return f"arn:{partition}:rds:{region}:{account_id}:{kind}:{snapshot_id}"


class RDSSnapshotsCleanupChecker:
    """Two related findings:

    1) Old manual snapshots (DB + cluster) beyond a threshold.
    2) Orphaned manual snapshots whose source DB instance/cluster no longer exists.
    """

    checker_id = "aws.rds.snapshots.cleanup"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        stale_days: int = 90,
        snapshot_price_gb_month_usd: Optional[float] = None,
        provider_partition: str = "aws",
    ) -> None:
        self._account = account
        self._stale_days = int(stale_days)
        self._price_gb_month = float(
            snapshot_price_gb_month_usd
            if snapshot_price_gb_month_usd is not None
            else _default_snapshot_price_gb_month_usd()
        )
        self._partition = provider_partition or "aws"

    def run(self, ctx) -> Iterable[FindingDraft]:
        if ctx.services is None or getattr(ctx.services, "rds", None) is None:
            raise RuntimeError("RDSSnapshotsCleanupChecker requires ctx.services.rds")

        rds: BaseClient = ctx.services.rds
        region = _region_from_client(rds)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cutoff = now - timedelta(days=self._stale_days)

        # Inventory: existing sources for orphan detection
        instances, clusters = self._list_sources(rds)

        # 1) DB snapshots (instances)
        for s in self._list_db_snapshots(rds):
            if (s.get("SnapshotType") or "").lower() != "manual":
                continue

            sid = s.get("DBSnapshotIdentifier") or ""
            if not sid:
                continue

            created = s.get("SnapshotCreateTime")
            created_utc = _utc(created) if isinstance(created, datetime) else None

            src_instance = s.get("DBInstanceIdentifier") or ""
            size_gb = _safe_float(s.get("AllocatedStorage") or 0.0)
            est_cost = size_gb * self._price_gb_month

            scope = Scope(
                cloud=ctx.cloud,
                billing_account_id=self._account.billing_account_id or self._account.account_id,
                account_id=self._account.account_id,
                region=region,
                service="AmazonRDS",
                resource_type="rds_db_snapshot",
                resource_id=sid,
                resource_arn=_snapshot_arn(
                    partition=self._partition,
                    region=region,
                    account_id=self._account.account_id,
                    kind="snapshot",
                    snapshot_id=sid,
                ),
            )

            # Finding A: old manual snapshot
            if created_utc is not None and created_utc < cutoff:
                age_days = int((now - created_utc).total_seconds() // 86400)
                yield FindingDraft(
                    check_id="aws.rds.snapshots.manual_old",
                    check_name="RDS manual snapshot is old",
                    category="waste",
                    status="info",
                    severity=Severity(level="medium", score=50),
                    title="Old RDS manual DB snapshot",
                    message=(
                        f"Manual DB snapshot '{sid}' was created on {created_utc.date().isoformat()} "
                        f"({age_days} days ago), older than the {self._stale_days}-day threshold."
                    ),
                    recommendation="Delete manual snapshots you no longer need, or adjust retention policies.",
                    scope=scope,
                    issue_key={"kind": "db", "snapshot_id": sid, "rule": "manual_old"},
                    estimated_monthly_savings=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimated_monthly_cost=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimate_confidence=80,
                    estimate_notes=(
                        f"Estimated using AllocatedStorage={size_gb:.0f} GiB and "
                        f"${self._price_gb_month:.3f}/GiB-month."
                        if est_cost > 0
                        else "Snapshot size not available; cost estimate is 0."
                    ),
                    dimensions={
                        "source_instance": src_instance,
                        "snapshot_type": "manual",
                        "created_at": created_utc.isoformat().replace("+00:00", "Z") if created_utc else "",
                        "size_gib": str(int(size_gb)),
                    },
                )

            # Finding B: orphaned snapshot (source missing)
            if src_instance and src_instance not in instances:
                yield FindingDraft(
                    check_id="aws.rds.snapshots.orphaned",
                    check_name="RDS snapshot is orphaned",
                    category="waste",
                    status="fail",
                    severity=Severity(level="high", score=90),
                    title="Orphaned RDS manual DB snapshot",
                    message=(
                        f"Snapshot '{sid}' references source instance '{src_instance}', "
                        "but that instance no longer exists in this region."
                    ),
                    recommendation=(
                        "Confirm the snapshot is no longer needed, then delete it to reduce storage costs."
                    ),
                    scope=scope,
                    issue_key={
                        "kind": "db",
                        "snapshot_id": sid,
                        "source_instance": src_instance,
                        "rule": "orphaned",
                    },
                    estimated_monthly_savings=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimated_monthly_cost=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimate_confidence=60,
                    estimate_notes=(
                        f"Estimated using AllocatedStorage={size_gb:.0f} GiB and "
                        f"${self._price_gb_month:.3f}/GiB-month."
                        if est_cost > 0
                        else "Snapshot size not available; cost estimate is 0."
                    ),
                    dimensions={
                        "source_instance": src_instance,
                        "snapshot_type": "manual",
                        "created_at": created_utc.isoformat().replace("+00:00", "Z") if created_utc else "",
                        "size_gib": str(int(size_gb)),
                    },
                )

        # 2) DB cluster snapshots (Aurora)
        for s in self._list_db_cluster_snapshots(rds):
            if (s.get("SnapshotType") or "").lower() != "manual":
                continue

            sid = s.get("DBClusterSnapshotIdentifier") or ""
            if not sid:
                continue

            created = s.get("SnapshotCreateTime")
            created_utc = _utc(created) if isinstance(created, datetime) else None

            src_cluster = s.get("DBClusterIdentifier") or ""
            # Aurora snapshot objects usually do not expose a reliable size.
            size_gb = _safe_float(s.get("AllocatedStorage") or 0.0)
            est_cost = size_gb * self._price_gb_month

            scope = Scope(
                cloud=ctx.cloud,
                billing_account_id=self._account.billing_account_id or self._account.account_id,
                account_id=self._account.account_id,
                region=region,
                service="AmazonRDS",
                resource_type="rds_cluster_snapshot",
                resource_id=sid,
                resource_arn=_snapshot_arn(
                    partition=self._partition,
                    region=region,
                    account_id=self._account.account_id,
                    kind="cluster-snapshot",
                    snapshot_id=sid,
                ),
            )

            # Finding A: old manual cluster snapshot
            if created_utc is not None and created_utc < cutoff:
                age_days = int((now - created_utc).total_seconds() // 86400)
                yield FindingDraft(
                    check_id="aws.rds.snapshots.manual_old",
                    check_name="RDS manual snapshot is old",
                    category="cost",
                    status="fail",
                    severity=Severity(level="medium", score=50),
                    title="Old RDS manual cluster snapshot",
                    message=(
                        f"Manual cluster snapshot '{sid}' was created on {created_utc.date().isoformat()} "
                        f"({age_days} days ago), older than the {self._stale_days}-day threshold."
                    ),
                    recommendation="Delete manual snapshots you no longer need, or adjust retention policies.",
                    scope=scope,
                    issue_key={"kind": "cluster", "snapshot_id": sid, "rule": "manual_old"},
                    estimated_monthly_savings=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimated_monthly_cost=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimate_confidence=30,
                    estimate_notes=(
                        "Aurora snapshot size is often not available via the snapshot API; "
                        "cost estimate may be 0 unless size is provided."
                    ),
                    dimensions={
                        "source_cluster": src_cluster,
                        "snapshot_type": "manual",
                        "created_at": created_utc.isoformat().replace("+00:00", "Z") if created_utc else "",
                        "size_gib_est": str(int(size_gb)),
                    },
                )

            # Finding B: orphaned cluster snapshot
            if src_cluster and src_cluster not in clusters:
                yield FindingDraft(
                    check_id="aws.rds.snapshots.orphaned",
                    check_name="RDS snapshot is orphaned",
                    category="cost",
                    status="info",
                    severity=Severity(level="low", score=20),
                    title="Orphaned RDS manual cluster snapshot",
                    message=(
                        f"Snapshot '{sid}' references source cluster '{src_cluster}', "
                        "but that cluster no longer exists in this region."
                    ),
                    recommendation=(
                        "Confirm the snapshot is no longer needed, then delete it to reduce storage costs."
                    ),
                    scope=scope,
                    issue_key={
                        "kind": "cluster",
                        "snapshot_id": sid,
                        "source_cluster": src_cluster,
                        "rule": "orphaned",
                    },
                    estimated_monthly_savings=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimated_monthly_cost=f"{est_cost:.2f}" if est_cost > 0 else "0",
                    estimate_confidence=30,
                    estimate_notes=(
                        "Aurora snapshot size is often not available via the snapshot API; "
                        "cost estimate may be 0 unless size is provided."
                    ),
                    dimensions={
                        "source_cluster": src_cluster,
                        "snapshot_type": "manual",
                        "created_at": created_utc.isoformat().replace("+00:00", "Z") if created_utc else "",
                        "size_gib_est": str(int(size_gb)),
                    },
                )

    @staticmethod
    def _list_db_snapshots(rds: BaseClient) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(IncludePublic=False, IncludeShared=False):
            out.extend(page.get("DBSnapshots", []) or [])
        return out

    @staticmethod
    def _list_db_cluster_snapshots(rds: BaseClient) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        paginator = rds.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate(IncludePublic=False, IncludeShared=False):
            out.extend(page.get("DBClusterSnapshots", []) or [])
        return out

    @staticmethod
    def _list_sources(rds: BaseClient) -> tuple[Set[str], Set[str]]:
        instances: Set[str] = set()
        clusters: Set[str] = set()

        try:
            p = rds.get_paginator("describe_db_instances")
            for page in p.paginate():
                for i in page.get("DBInstances", []) or []:
                    iid = i.get("DBInstanceIdentifier")
                    if iid:
                        instances.add(str(iid))
        except ClientError:
            # If we can't list instances, orphan detection will be incomplete.
            pass

        try:
            p = rds.get_paginator("describe_db_clusters")
            for page in p.paginate():
                for c in page.get("DBClusters", []) or []:
                    cid = c.get("DBClusterIdentifier")
                    if cid:
                        clusters.add(str(cid))
        except ClientError:
            pass

        return instances, clusters


@register_checker("checks.aws.rds_snapshots_cleanup:RDSSnapshotsCleanupChecker")
def _factory(ctx, bootstrap):
    """Factory registration for default runner discovery.

    Expected bootstrap keys:
      - aws_account_id
      - aws_billing_account_id (optional)
      - rds_snapshot_gb_month_price_usd (optional)
      - rds_snapshot_stale_days (optional)
      - aws_partition (optional; default 'aws')
    """

    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for RDSSnapshotsCleanupChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    stale_days = int(bootstrap.get("rds_snapshot_stale_days") or 30)
    price = bootstrap.get("rds_snapshot_gb_month_price_usd")
    partition = str(bootstrap.get("aws_partition") or "aws")

    return RDSSnapshotsCleanupChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
        stale_days=stale_days,
        snapshot_price_gb_month_usd=float(price) if price is not None else None,
        provider_partition=partition,
    )
