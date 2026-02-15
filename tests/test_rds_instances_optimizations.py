"""Unit tests for the RDS instances optimizations checker."""

# tests/test_rds_instances_optimizations.py
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from botocore.exceptions import ClientError

from checks.aws.rds_instances_optimizations import (
    AwsAccountContext,
    RDSInstancesOptimizationsChecker,
    _arn_partition,
)
from tests.aws_mocks import FakeRdsClient, make_run_ctx


def _gb_to_bytes(gb: float) -> float:
    return gb * 1024.0 * 1024.0 * 1024.0


class _FakeCloudWatchClient:
    """
    Fake CloudWatch that supports get_metric_data (used by the checker).

    It inspects MetricDataQueries and returns the configured values for each:
      (MetricName, DBInstanceIdentifier) -> values
    """
    def __init__(self, *, series_by_metric_and_instance: dict[str, dict[str, list[float]]] | None = None) -> None:
        # e.g. {"FreeStorageSpace": {"db2":[...bytes...]}, "ReadIOPS":{"replica1":[...]} }
        self._data = series_by_metric_and_instance or {}

    def get_metric_data(self, **kwargs: Any) -> dict[str, Any]:
        queries: Sequence[dict[str, Any]] = kwargs.get("MetricDataQueries", []) or []
        results: list[dict[str, Any]] = []

        for q in queries:
            qid = q.get("Id")
            metric_stat = q.get("MetricStat", {}) or {}
            metric = metric_stat.get("Metric", {}) or {}
            metric_name = metric.get("MetricName")
            dims = metric.get("Dimensions", []) or []
            iid = ""
            for d in dims:
                if d.get("Name") == "DBInstanceIdentifier":
                    iid = str(d.get("Value") or "")
                    break

            values = []
            if metric_name and iid:
                values = list(self._data.get(str(metric_name), {}).get(iid, []))

            results.append(
                {
                    "Id": qid,
                    "Values": values,
                    "Timestamps": [],
                    "StatusCode": "Complete",
                }
            )

        return {"MetricDataResults": results}


def _mk_checker() -> RDSInstancesOptimizationsChecker:
    return RDSInstancesOptimizationsChecker(
        account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"),
        storage_gb_month_price_usd=0.115,
        storage_window_days=14,
        storage_period_seconds=86400,
        overprov_used_ratio_threshold=0.40,
        overprov_min_excess_gb=20.0,
        replica_unused_window_days=14,
        replica_period_seconds=86400,
        replica_read_iops_p95_threshold=0.1,
        replica_min_datapoints=7,
    )


def test_stopped_instances_with_storage_emits() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db1"
    rds = FakeRdsClient(
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.instances.stopped.storage")
    assert f.status == "fail"
    assert f.estimated_monthly_cost is not None
    assert float(f.estimated_monthly_cost) > 0.0
    assert f.estimated_monthly_savings is not None
    assert float(f.estimated_monthly_savings) > 0.0


def test_storage_overprovisioned_emits_using_free_storage_p95() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db2"
    # Allocated 100GB, "free" ~90GB => used ~10GB => overprovisioned
    free_series = [_gb_to_bytes(90.0)] * 14  # daily for 14d
    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={
            "FreeStorageSpace": {"db2": free_series},
        }
    )
    rds = FakeRdsClient(
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
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.storage.overprovisioned")
    assert f.status == "fail"
    assert f.estimated_monthly_savings is not None
    assert float(f.estimated_monthly_savings) > 0.0
    assert f.dimensions.get("allocated_gb") == "100"
    assert "p95_free_gb" in f.dimensions


def test_multi_az_non_prod_emits_when_env_tag_non_prod() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db3"
    rds = FakeRdsClient(
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.multi.az.non.prod")
    assert f.status == "fail"
    assert f.estimate_confidence is not None
    assert int(f.estimate_confidence) <= 40


def test_multi_az_non_prod_suppressed_when_env_prod() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db4"
    rds = FakeRdsClient(
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(x.check_id != "aws.rds.multi.az.non.prod" for x in findings)


def test_instance_family_old_generation_emits() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db5"
    rds = FakeRdsClient(
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    f = next(x for x in findings if x.check_id == "aws.rds.instance.family.old.generation")
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
    rds = FakeRdsClient(
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    has = any(x.check_id == "aws.rds.engine.needs.upgrade" for x in findings)
    assert has is should_emit

def test_storage_overprovisioned_no_finding_when_datapoints_too_sparse() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db_sparse"
    # Only 2 datapoints -> checker requires >=3 for storage overprov
    free_series = [_gb_to_bytes(90.0)] * 2
    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={"FreeStorageSpace": {"db_sparse": free_series}}
    )
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db_sparse",
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
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(x.check_id != "aws.rds.storage.overprovisioned" for x in findings)


def test_storage_overprovisioned_no_finding_when_allocated_storage_missing_or_zero() -> None:
    arn0 = "arn:aws:rds:eu-west-3:111111111111:db:db0"
    arn_missing = "arn:aws:rds:eu-west-3:111111111111:db:db_missing"

    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={
            "FreeStorageSpace": {
                "db0": [_gb_to_bytes(90.0)] * 14,
                "db_missing": [_gb_to_bytes(90.0)] * 14,
            }
        }
    )
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db0",
                "DBInstanceArn": arn0,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 0,  # explicit 0
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "postgres",
                "EngineVersion": "15.4",
            },
            {
                "DBInstanceIdentifier": "db_missing",
                "DBInstanceArn": arn_missing,
                "DBInstanceStatus": "available",
                # AllocatedStorage missing -> treated as 0.0 in checker
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "postgres",
                "EngineVersion": "15.4",
            },
        ],
        tags_by_arn={arn0: {"env": "dev"}, arn_missing: {"env": "dev"}},
    )
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(x.check_id != "aws.rds.storage.overprovisioned" for x in findings)


def test_multi_az_missing_env_tag_no_finding() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db_no_env"
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db_no_env",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": True,
                "DBInstanceClass": "db.t3.small",
                "Engine": "mysql",
                "EngineVersion": "8.0.34",
            }
        ],
        tags_by_arn={arn: {"owner": "team-a"}},  # no env-related tag
    )
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(x.check_id != "aws.rds.multi.az.non.prod" for x in findings)


@pytest.mark.parametrize(
    "engine,version,should_emit",
    [
        # Realistic: empty/None-like should not emit
        ("postgres", "", False), # empty version (should not crash, not emit)
        ("mysql", "", False), # empty
        ("", "11.0", False), # empty
        ("not-a-db", "1.2.3", False), # unkown

        # Realistic numeric versions
        ("postgres", "11.22", True),   # < (12,0) triggers policy
        ("postgres", "12.0", False),   # meets policy
        ("postgres", "15.4", False),   # meets policy

        ("mariadb", "10.5.18", True),  # < (10,6) triggers policy
        ("mariadb", "10.6.12", False), # meets policy
        ("mariadb", "10.10.2", False), # meets policy (important: 10.10 > 10.6)
    ],
)


def test_engine_versions_do_not_crash_and_follow_policy(
    engine: str, version: str, should_emit: bool
) -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db_weird"
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db_weird",
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
    cw = _FakeCloudWatchClient(series_by_metric_and_instance={})
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))

    emitted = any(f.check_id == "aws.rds.engine.needs.upgrade" for f in findings)
    assert emitted is should_emit


def test_unused_read_replica_emits_when_p95_read_iops_zero() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:replica1"
    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={
            # 14 days of daily datapoints => enough for coverage checks
            "ReadIOPS": {"replica1": [0.0] * 14},
            "DatabaseConnections": {"replica1": [0.0] * 14},
        }
    )
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "replica1",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "postgres",
                "EngineVersion": "15.4",
                "ReadReplicaSourceDBInstanceIdentifier": "primary1",
                # Old enough to not be filtered out (<7d)
                "InstanceCreateTime": datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC),
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert any(f.check_id == "aws.rds.read.replica.unused" for f in findings)


def test_unused_read_replica_suppressed_by_purpose_tag() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:replica_suppressed"
    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={
            "ReadIOPS": {"replica_suppressed": [0.0] * 14},
            "DatabaseConnections": {"replica_suppressed": [0.0] * 14},
        }
    )
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "replica_suppressed",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "postgres",
                "EngineVersion": "15.4",
                "ReadReplicaSourceDBInstanceIdentifier": "primary1",
                "InstanceCreateTime": datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC),
            }
        ],
        # Suppression: purpose/failover/migration etc
        tags_by_arn={arn: {"env": "dev", "purpose": "migration"}},
    )
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(f.check_id != "aws.rds.read.replica.unused" for f in findings)


def test_unused_read_replica_skipped_for_aurora() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:aurora_replica"
    cw = _FakeCloudWatchClient(
        series_by_metric_and_instance={
            "ReadIOPS": {"aurora_replica": [0.0] * 14},
            "DatabaseConnections": {"aurora_replica": [0.0] * 14},
        }
    )
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "aurora_replica",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,
                "MultiAZ": False,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "aurora-postgresql",
                "EngineVersion": "15.4",
                "ReadReplicaSourceDBInstanceIdentifier": "aurora_primary",
                "InstanceCreateTime": datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC),
            }
        ],
        tags_by_arn={arn: {"env": "dev"}},
    )
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))
    assert all(f.check_id != "aws.rds.read.replica.unused" for f in findings)


class _FakeCloudWatchClientDeny:
    def get_metric_data(self, **kwargs: Any) -> dict[str, Any]:
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            operation_name="GetMetricData",
        )


def test_cloudwatch_access_error_emits_and_checker_continues() -> None:
    arn = "arn:aws:rds:eu-west-3:111111111111:db:db_cw_denied"
    cw = _FakeCloudWatchClientDeny()
    rds = FakeRdsClient(
        region="eu-west-3",
        instances=[
            {
                "DBInstanceIdentifier": "db_cw_denied",
                "DBInstanceArn": arn,
                "DBInstanceStatus": "available",
                "AllocatedStorage": 20,  # triggers storage metrics fetch
                "MultiAZ": True,         # triggers multi-az non-prod (tag based)
                "DBInstanceClass": "db.t3.small",
                "Engine": "mysql",
                "EngineVersion": "8.0.35",
            }
        ],
        tags_by_arn={arn: {"env": "staging"}},
    )
    ctx = make_run_ctx(rds=rds, cloudwatch=cw)

    findings = list(_mk_checker().run(ctx))

    assert any(f.check_id == "aws.rds.instances.access.error" for f in findings)
    assert any(f.check_id == "aws.rds.multi.az.non.prod" for f in findings)


def test_arn_partition_returns_empty_on_malformed_value() -> None:
    assert _arn_partition(cast(Any, None)) == ""


def test_access_error_handles_malformed_clienterror_response() -> None:
    checker = _mk_checker()
    ctx = make_run_ctx(rds=None, cloudwatch=None)

    class _BadClientError(Exception):
        response = 123

    finding = checker._access_error(
        ctx,
        region="eu-west-3",
        action="describe_db_instances",
        exc=cast(ClientError, _BadClientError()),
    )
    assert finding.check_id == "aws.rds.instances.access.error"
    assert "ErrorCode=" in finding.message

