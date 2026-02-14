"""Unit tests for the EFS file systems checker."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

from botocore.exceptions import ClientError

import pytest

from checks.aws.efs_filesystems import EFSFileSystemsChecker, EFSFileSystemsConfig
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    """Minimal paginator fake."""

    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEFS:
    """Minimal EFS fake for this checker."""

    def __init__(
        self,
        *,
        region: str,
        file_systems: List[Mapping[str, Any]],
        lifecycle_by_id: Optional[Dict[str, Mapping[str, Any]]] = None,
        backup_by_id: Optional[Dict[str, Mapping[str, Any]]] = None,
        lifecycle_policy_not_found: Optional[set[str]] = None,
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._file_systems = list(file_systems)
        self._lifecycle_by_id = lifecycle_by_id or {}
        self._backup_by_id = backup_by_id or {}
        self._lc_not_found = lifecycle_policy_not_found or set()

    def get_paginator(self, op_name: str) -> FakePaginator:
        if op_name == "describe_file_systems":
            return FakePaginator([{"FileSystems": list(self._file_systems)}])
        raise KeyError(op_name)

    def describe_lifecycle_configuration(self, *, FileSystemId: str) -> Mapping[str, Any]:
        if FileSystemId in self._lc_not_found:
            raise ClientError(
                error_response={"Error": {"Code": "PolicyNotFound", "Message": "not found"}},
                operation_name="DescribeLifecycleConfiguration",
            )
        return dict(self._lifecycle_by_id.get(FileSystemId, {"LifecyclePolicies": []}))

    def describe_backup_policy(self, *, FileSystemId: str) -> Mapping[str, Any]:
        return dict(self._backup_by_id.get(FileSystemId, {"BackupPolicy": {"Status": "ENABLED"}}))


class FakeCloudWatch:
    """Minimal CloudWatch fake for GetMetricData."""

    def __init__(self, *, values_by_id: Dict[str, List[float]]) -> None:
        self._values_by_id = values_by_id

    def get_metric_data(self, *, MetricDataQueries: List[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:
        results: List[Dict[str, Any]] = []
        for q in MetricDataQueries:
            qid = str(q.get("Id") or "")
            results.append({"Id": qid, "Values": list(self._values_by_id.get(qid, []))})
        return {"MetricDataResults": results}


def _mk_ctx(*, efs: FakeEFS, cloudwatch: Optional[FakeCloudWatch] = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(efs=efs, cloudwatch=cloudwatch),
        ),
    )


def _fs(
    *,
    fs_id: str = "fs-1",
    arn: str = "arn:aws:efs:eu-west-1:111111111111:file-system/fs-1",
    throughput_mode: str = "bursting",
    provisioned_mibps: Optional[float] = None,
    encrypted: bool = True,
    tags: Optional[List[Mapping[str, str]]] = None,
) -> Mapping[str, Any]:
    out: Dict[str, Any] = {
        "FileSystemId": fs_id,
        "FileSystemArn": arn,
        "ThroughputMode": throughput_mode,
        "Encrypted": encrypted,
        "Tags": tags or [],
    }
    if provisioned_mibps is not None:
        out["ProvisionedThroughputInMibps"] = float(provisioned_mibps)
    return out


def test_lifecycle_missing_emits_when_policy_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(region="eu-west-1", file_systems=[_fs()], lifecycle_policy_not_found={"fs-1"})
    ctx = _mk_ctx(efs=efs)

    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=EFSFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.efs.filesystems.lifecycle_missing" for f in findings)


def test_unused_emits_when_low_io_and_no_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(
        region="eu-west-1",
        file_systems=[_fs(fs_id="fs-1")],
        lifecycle_by_id={"fs-1": {"LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}]}},
    )

    # The checker issues IDs: m0r, m0w, m0c, m0p
    cw = FakeCloudWatch(
        values_by_id={
            "m0r": [0.0] * 10,
            "m0w": [0.0] * 10,
            "m0c": [0.0] * 10,
            "m0p": [0.0] * 10,
        }
    )
    ctx = _mk_ctx(efs=efs, cloudwatch=cw)

    cfg = EFSFileSystemsConfig(lookback_days=14, min_daily_datapoints=7, unused_p95_daily_io_bytes_threshold=1.0)
    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=cfg)
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.efs.filesystems.unused" for f in findings)


def test_provisioned_throughput_underutilized_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(
        region="eu-west-1",
        file_systems=[_fs(fs_id="fs-1", throughput_mode="provisioned", provisioned_mibps=32.0)],
        lifecycle_by_id={"fs-1": {"LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}]}},
    )

    cw = FakeCloudWatch(
        values_by_id={
            "m0r": [1000.0] * 10,
            "m0w": [1000.0] * 10,
            "m0c": [1.0] * 10,
            "m0p": [1.0] * 10,  # p95 PercentIOLimit very low
        }
    )
    ctx = _mk_ctx(efs=efs, cloudwatch=cw)

    cfg = EFSFileSystemsConfig(underutilized_p95_percent_io_limit_threshold=20.0)
    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=cfg)
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.efs.filesystems.provisioned_throughput_underutilized" for f in findings)


def test_backup_disabled_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(
        region="eu-west-1",
        file_systems=[_fs(fs_id="fs-1")],
        lifecycle_by_id={"fs-1": {"LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}]}},
        backup_by_id={"fs-1": {"BackupPolicy": {"Status": "DISABLED"}}},
    )
    ctx = _mk_ctx(efs=efs, cloudwatch=None)

    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=EFSFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.efs.filesystems.backup_disabled" for f in findings)


def test_unencrypted_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(
        region="eu-west-1",
        file_systems=[_fs(fs_id="fs-1", encrypted=False)],
        lifecycle_by_id={"fs-1": {"LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}]}},
    )
    ctx = _mk_ctx(efs=efs, cloudwatch=None)

    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=EFSFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.efs.filesystems.unencrypted" for f in findings)


def test_access_error_emits_when_list_filesystems_is_malformed() -> None:
    class BrokenEFS:
        def __init__(self) -> None:
            self.meta = SimpleNamespace(region_name="eu-west-1")

        def get_paginator(self, _op_name: str) -> Any:
            raise TypeError("broken paginator")

    ctx = cast(
        RunContext,
        SimpleNamespace(cloud="aws", services=SimpleNamespace(efs=BrokenEFS(), cloudwatch=None)),
    )
    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=EFSFileSystemsConfig())
    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.efs.filesystems.access_error"


def test_metrics_malformed_values_fallback_to_best_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.efs_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    efs = FakeEFS(region="eu-west-1", file_systems=[_fs()], lifecycle_policy_not_found={"fs-1"})
    cw = FakeCloudWatch(values_by_id={"m0r": ["bad"], "m0w": [0.0], "m0c": [0.0], "m0p": [0.0]})
    ctx = _mk_ctx(efs=efs, cloudwatch=cw)

    checker = EFSFileSystemsChecker(account_id="111111111111", cfg=EFSFileSystemsConfig())
    findings = list(checker.run(ctx))
    assert any(f.check_id == "aws.efs.filesystems.lifecycle_missing" for f in findings)
