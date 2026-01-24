# tests/test_rds_instances_optimizations.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import pytest

from checks.aws.rds_instances_optimizations import (
    AwsAccountContext,
    RDSInstancesOptimizationsChecker,
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
        tags_by_arn: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        self.meta = type("Meta", (), {"region_name": region})()
        self._instances = instances or []
        self._tags_by_arn = tags_by_arn or {}

    def get_paginator(self, op_name: str) -> _FakePaginator:
        assert op_name == "describe_db_instances"
        return _FakePaginator([{"DBInstances": self._instances}])

    def list_tags_for_resource(self, *, ResourceName: str) -> Dict[str, Any]:
        tags = self._tags_by_arn.get(ResourceName, {})
        return {"TagList": [{"Key": k, "Value": v} for k, v in tags.items()]}


class _FakeCloudWatchClient:
    def __init__(self, *, free_storage_bytes: Optional[List[float]] = None) -> None:
        self._free_storage_bytes = free_storage_bytes

    def get_metric_statistics(self, **kwargs: Any) -> Dict[str, Any]:
        # Only support the metric used by this checker.
        assert kwargs.get("Namespace") == "AWS/RDS"
        assert kwargs.get("MetricName") == "FreeStorageSpace"
        if self._free_storage_bytes is None:
            return {"Datapoints": []}
        return {
            "Datapoints": [{"Average": v} for v in self._free_storage_bytes],
        }


@dataclass
class _FakeServices:
    rds: Any
    cloudwatch: Any = None


class _FakeCtx:
    cloud: str = "aws"
    services: Any = None


def _mk_checker() -> RDSInstancesOptimizationsChecker:
    return RDSInstancesOptimizationsChecker(
        account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"),
        storage_gb_month_price_usd=0.115,
        storage_window_days=14,
        overprov_used_ratio_threshold=0.40,
        overprov_min_excess_gb=20.0,
    )


def _gb_to_bytes(gb: float) -> float:
    return gb * 1024.0 * 1024.0 * 1024.0


def test_stopped_instances_with_storage_emits() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db1"
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db1",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "stopped",
                "AllocatedStorage": 100,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "mysql",
                "EngineVersion": "8.0.35",
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=_FakeCloudWatchClient(free_storage_bytes=None))

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.instances.stopped_storage")
    assert f.status == "fail"
    assert f.estimated_monthly_cost is not None
    assert float(f.estimated_monthly_cost) > 0.0
    assert f.estimated_monthly_savings is not None
    assert float(f.estimated_monthly_savings) > 0.0


def test_storage_overprovisioned_emits_using_free_storage_p95() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db2"
    # Allocated 100GB, free ~90GB => used ~10GB => overprovisioned
    free_series = [_gb_to_bytes(90.0)] * 24
    cw = _FakeCloudWatchClient(free_storage_bytes=free_series)
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db2",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 100,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "postgres",
                "EngineVersion": "15.4",
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.storage.overprovisioned")
    assert f.status == "fail"
    assert f.estimated_monthly_savings is not None
    assert float(f.estimated_monthly_savings) > 0.0
    assert f.dimensions.get("allocated_gb") == "100"
    assert "p95_free_gb" in f.dimensions


def test_multi_az_non_prod_emits_when_env_tag_non_prod() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db3"
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db3",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": True,
                "DBInstanceClass": "db.t3.small",
                "Engine": "mysql",
                "EngineVersion": "8.0.34",
            }
        ],
        tags_by_arn={arn: {"env": "staging"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=_FakeCloudWatchClient(free_storage_bytes=None))

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.multi_az.non_prod")
    assert f.status == "fail"
    assert f.estimate_confidence is not None
    assert int(f.estimate_confidence) <= 40


def test_multi_az_non_prod_suppressed_when_env_prod() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db4"
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db4",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": True,
                "DBInstanceClass": "db.t3.small",
                "Engine": "mysql",
                "EngineVersion": "8.0.34",
            }
        ],
        tags_by_arn={arn: {"env": "prod"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=_FakeCloudWatchClient(free_storage_bytes=None))

    findings = list(_mk_checker().run(ctx))
    assert all(x.check_id != "aws.rds.multi_az.non_prod" for x in findings)


def test_instance_family_old_generation_emits() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db5"
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db5",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": False,
                "DBInstanceClass": "db.m3.large",
                "Engine": "postgres",
                "EngineVersion": "15.4",
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=_FakeCloudWatchClient(free_storage_bytes=None))

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.instance_family.old_generation")
    assert f.status == "fail"
    assert f.dimensions.get("family") == "m3"


@pytest.mark.parametrize(
    "engine,version,should_emit",
    [
        ("mysql", "5.6.51", True),
        ("mysql", "5.7.44", True),
        ("mysql", "8.0.35", False),
        ("postgres", "9.6.24", True),
        ("postgres", "10.21", True),
        ("postgres", "11.18", True),
        ("postgres", "12.0", False),
        ("aurora-postgresql", "11.9", True),
        ("aurora-mysql", "5.7.mysql_aurora.2.11.3", True),
    ],
)
def test_engine_needs_upgrade_policy(engine: str, version: str, should_emit: bool) -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db6"
    rds = _FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db6",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": engine,
                "EngineVersion": version,
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = _FakeCtx()
    ctx.services = _FakeServices(rds=rds, cloudwatch=_FakeCloudWatchClient(free_storage_bytes=None))

    findings = list(_mk_checker().run(ctx))
    has = any(x.check_id == "aws.rds.engine.needs_upgrade" for x in findings)
    assert has is should_emit
