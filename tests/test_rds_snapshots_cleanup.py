"""Unit tests for the RDS snapshots cleanup checker."""

# tests/test_rds_snapshots_cleanup.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

import pytest
from botocore.exceptions import ClientError

from checks.aws.rds_snapshots_cleanup import (
    AwsAccountContext,
    RDSSnapshotsCleanupChecker,
    _resolve_rds_snapshot_storage_price_usd_per_gb_month,
)


# -------------------------
# Minimal fakes (no boto3)
# -------------------------

class _FakePaginator:
    def __init__(self, pages: List[Dict[str, Any]]):
        self._pages = pages

    def paginate(self) -> Iterable[Dict[str, Any]]:
        yield from self._pages


class _FakeRdsClient:
    def __init__(
        self,
        *,
        region: str,
        instances: Optional[List[Dict[str, Any]]] = None,
        clusters: Optional[List[Dict[str, Any]]] = None,
        db_snapshots: Optional[List[Dict[str, Any]]] = None,
        cluster_snapshots: Optional[List[Dict[str, Any]]] = None,
        raise_on: Optional[str] = None,
        raise_code: str = "AccessDeniedException",
    ):
        self.meta = type("Meta", (), {"region_name": region})()
        self._instances = instances or []
        self._clusters = clusters or []
        self._db_snaps = db_snapshots or []
        self._cluster_snaps = cluster_snapshots or []
        self._raise_on = raise_on
        self._raise_code = raise_code

    def get_paginator(self, op: str) -> _FakePaginator:
        if self._raise_on == op:
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}}, op
            )

        if op == "describe_db_instances":
            return _FakePaginator([{"DBInstances": self._instances}])
        if op == "describe_db_clusters":
            return _FakePaginator([{"DBClusters": self._clusters}])
        if op == "describe_db_snapshots":
            return _FakePaginator([{"DBSnapshots": self._db_snaps}])
        if op == "describe_db_cluster_snapshots":
            return _FakePaginator([{"DBClusterSnapshots": self._cluster_snaps}])

        raise AssertionError(f"Unexpected paginator op: {op}")


@dataclass
class _FakeServices:
    rds: Any
    pricing: Any = None


@dataclass
class _FakeCtx:
    cloud: str = "aws"
    services: Any = None


# -------------------------
# Helpers
# -------------------------

def _utc(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def _mk_checker(stale_days: int = 30) -> RDSSnapshotsCleanupChecker:
    return RDSSnapshotsCleanupChecker(
        account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"),
        stale_days=stale_days,
        snapshot_gb_month_price_usd=0.095,
    )


# -------------------------
# Tests
# -------------------------

def test_suppressed_snapshot_emits_no_finding():
    checker = _mk_checker()

    snap = {
        "DBSnapshotIdentifier": "snap-1",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(365),
        "DBInstanceIdentifier": "db-1",
        "AllocatedStorage": 100,
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-1",
        "TagList": [{"Key": "retain", "Value": "true"}],
    }

    rds = _FakeRdsClient(region="eu-west-1", instances=[{"DBInstanceIdentifier": "db-1"}], db_snapshots=[snap])
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert findings == []


def test_orphaned_db_snapshot_emits_orphan_only():
    checker = _mk_checker()

    snap = {
        "DBSnapshotIdentifier": "snap-orphan",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(10),
        "DBInstanceIdentifier": "db-missing",
        "AllocatedStorage": 50,
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-orphan",
        "TagList": [],
    }

    rds = _FakeRdsClient(region="eu-west-1", instances=[{"DBInstanceIdentifier": "db-present"}], db_snapshots=[snap])
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.rds.snapshots.orphaned"
    assert f.estimated_monthly_cost is not None
    assert f.estimated_monthly_savings == f.estimated_monthly_cost
    assert f.estimate_confidence == 50


def test_old_manual_db_snapshot_emits_manual_old():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBSnapshotIdentifier": "snap-old",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(45),
        "DBInstanceIdentifier": "db-1",
        "AllocatedStorage": 20,
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-old",
        "TagList": [],
    }

    rds = _FakeRdsClient(region="eu-west-1", instances=[{"DBInstanceIdentifier": "db-1"}], db_snapshots=[snap])
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.rds.snapshots.manual.old"


def test_automated_snapshot_never_emits_manual_old():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBSnapshotIdentifier": "snap-auto",
        "SnapshotType": "automated",
        "SnapshotCreateTime": _utc(400),
        "DBInstanceIdentifier": "db-1",
        "AllocatedStorage": 20,
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-auto",
        "TagList": [],
    }

    rds = _FakeRdsClient(region="eu-west-1", instances=[{"DBInstanceIdentifier": "db-1"}], db_snapshots=[snap])
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    assert list(checker.run(ctx)) == []


def test_cross_region_guard_prevents_orphan_false_positive():
    checker = _mk_checker()

    snap = {
        "DBSnapshotIdentifier": "snap-xr",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(10),
        "DBInstanceIdentifier": "db-missing",
        "AllocatedStorage": 20,
        "SourceRegion": "us-east-1",  # different from current region
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-xr",
        "TagList": [],
    }

    rds = _FakeRdsClient(region="eu-west-1", instances=[{"DBInstanceIdentifier": "db-present"}], db_snapshots=[snap])
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    # Not orphaned due to cross-region guard; and it’s not "old" because created 10d ago.
    assert list(checker.run(ctx)) == []


def test_access_error_emits_single_info_and_stops():
    checker = _mk_checker()

    # Raise on describe_db_instances => the checker should emit one access_error finding and stop.
    rds = _FakeRdsClient(region="eu-west-1", raise_on="describe_db_instances")
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.rds.snapshots.access.error"
    assert findings[0].status == "info"


def test_cluster_snapshot_cost_unknown_when_no_allocated_storage():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBClusterSnapshotIdentifier": "csnap-old",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(45),
        "DBClusterIdentifier": "cluster-1",
        "DBClusterSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:cluster-snapshot:csnap-old",
        "TagList": [],
        # no AllocatedStorage
    }

    rds = _FakeRdsClient(
        region="eu-west-1",
        clusters=[{"DBClusterIdentifier": "cluster-1"}],
        cluster_snapshots=[snap],
    )
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.rds.snapshots.manual.old"
    assert f.estimated_monthly_cost is None
    assert f.estimate_confidence == 10


def test_orphaned_cluster_snapshot():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBClusterSnapshotIdentifier": "csnap-orphan",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(5),
        "DBClusterIdentifier": "cluster-missing",
        "DBClusterSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:cluster-snapshot:csnap-orphan",
        "AllocatedStorage": 100,  # even if present, should be orphan finding
        "TagList": [],
    }

    rds = _FakeRdsClient(
        region="eu-west-1",
        clusters=[{"DBClusterIdentifier": "cluster-present"}],
        cluster_snapshots=[snap],
    )
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.rds.snapshots.orphaned"
    assert findings[0].scope.resource_id == "csnap-orphan"


def test_old_manual_cluster_snapshot_suppressed():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBClusterSnapshotIdentifier": "csnap-old-supp",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(120),
        "DBClusterIdentifier": "cluster-1",
        "DBClusterSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:cluster-snapshot:csnap-old-supp",
        "TagList": [{"Key": "purpose", "Value": "retain"}],
    }

    rds = _FakeRdsClient(
        region="eu-west-1",
        clusters=[{"DBClusterIdentifier": "cluster-1"}],
        cluster_snapshots=[snap],
    )
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    assert list(checker.run(ctx)) == []


def test_manual_old_but_cross_region():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBSnapshotIdentifier": "snap-old-xr",
        "SnapshotType": "manual",
        "SnapshotCreateTime": _utc(90),
        "DBInstanceIdentifier": "db-missing",  # would look orphan, but XR guard disables orphan
        "AllocatedStorage": 10,
        "SourceRegion": "us-east-1",
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-old-xr",
        "TagList": [],
    }

    rds = _FakeRdsClient(
        region="eu-west-1",
        instances=[{"DBInstanceIdentifier": "db-present"}],
        db_snapshots=[snap],
    )
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.rds.snapshots.manual.old"


def test_snapshot_missing_create_time():
    checker = _mk_checker(stale_days=30)

    snap = {
        "DBSnapshotIdentifier": "snap-missing-ct",
        "SnapshotType": "manual",
        "SnapshotCreateTime": None,
        "DBInstanceIdentifier": "db-1",
        "AllocatedStorage": 10,
        "DBSnapshotArn": "arn:aws:rds:eu-west-1:111111111111:snapshot:snap-missing-ct",
        "TagList": [],
    }

    rds = _FakeRdsClient(
        region="eu-west-1",
        instances=[{"DBInstanceIdentifier": "db-1"}],
        db_snapshots=[snap],
    )
    ctx = _FakeCtx(services=_FakeServices(rds=rds))

    assert list(checker.run(ctx)) == []


def test_pricing_helper_falls_back_when_service_raises_type_error() -> None:
    class _BadPricing:
        def rds_backup_storage_gb_month(self, *, region: str) -> Any:
            _ = region
            raise TypeError("bad pricing payload")

    ctx = _FakeCtx(services=_FakeServices(rds=None, pricing=_BadPricing()))
    price, notes, confidence = _resolve_rds_snapshot_storage_price_usd_per_gb_month(
        ctx,
        "eu-west-1",
        default_price=0.095,
    )
    assert price == 0.095
    assert confidence == 30
    assert "using default price" in notes


def test_pricing_helper_falls_back_when_quote_is_malformed() -> None:
    class _MalformedPricing:
        def rds_backup_storage_gb_month(self, *, region: str) -> Any:
            _ = region
            return SimpleNamespace(unit_price_usd="not-a-number", source="catalog", as_of=object(), unit="GB-Mo")

    ctx = _FakeCtx(services=_FakeServices(rds=None, pricing=_MalformedPricing()))
    price, notes, confidence = _resolve_rds_snapshot_storage_price_usd_per_gb_month(
        ctx,
        "eu-west-1",
        default_price=0.095,
    )
    assert price == 0.095
    assert confidence == 30
    assert "using default price" in notes
