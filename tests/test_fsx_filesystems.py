"""Unit tests for the FSx file systems checker."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

import pytest

from checks.aws.fsx_filesystems import FSxFileSystemsChecker, FSxFileSystemsConfig
from contracts.finops_checker_pattern import RunContext


class FakeFSx:
    """Minimal FSx fake for this checker."""

    def __init__(self, *, region: str, file_systems: List[Mapping[str, Any]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._file_systems = file_systems

    def describe_file_systems(self, **_kwargs: Any) -> Mapping[str, Any]:
        return {"FileSystems": list(self._file_systems)}


class FakeCloudWatch:
    """Minimal CloudWatch fake (get_metric_statistics only)."""

    def __init__(self, *, datapoints_by_metric: Dict[str, List[Mapping[str, Any]]]) -> None:
        self._datapoints_by_metric = datapoints_by_metric

    def get_metric_statistics(self, *, MetricName: str, **_kwargs: Any) -> Mapping[str, Any]:
        return {"Datapoints": list(self._datapoints_by_metric.get(MetricName, []))}


def _mk_ctx(*, fsx: FakeFSx, cloudwatch: Optional[FakeCloudWatch] = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(fsx=fsx, cloudwatch=cloudwatch),
        ),
    )


def _fs(
    *,
    fs_id: str = "fs-1",
    fs_type: str = "WINDOWS",
    arn: str = "arn:aws:fsx:eu-west-1:111111111111:file-system/fs-1",
    tags: Optional[List[Mapping[str, str]]] = None,
    windows_cfg: Optional[Mapping[str, Any]] = None,
    storage_capacity: int = 1024,
    creation_time: Optional[datetime] = None,
) -> Mapping[str, Any]:
    out: Dict[str, Any] = {
        "FileSystemId": fs_id,
        "FileSystemType": fs_type,
        "ResourceARN": arn,
        "StorageCapacity": storage_capacity,
        "Tags": tags or [],
    }
    if creation_time is not None:
        out["CreationTime"] = creation_time
    if windows_cfg is not None:
        out["WindowsConfiguration"] = dict(windows_cfg)
    return out


def test_possible_unused_emits_when_metrics_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(region="eu-west-1", file_systems=[_fs()])
    # Provide datapoints with zeros so "metrics are seen" but show no activity
    cw = FakeCloudWatch(
        datapoints_by_metric={
            "DataReadBytes": [{"Sum": 0.0}],
            "DataWriteBytes": [{"Sum": 0.0}],
            "ThroughputUtilization": [{"Average": 0.0}],
        }
    )
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig(unused_lookback_days=14))
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.filesystems.possible.unused" for f in findings)


def test_multi_az_in_nonprod_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "dev"}, {"Key": "owner", "Value": "team-a"}],
                windows_cfg={"DeploymentType": "MULTI_AZ_1", "AutomaticBackupRetentionDays": 7, "CopyTagsToBackups": True},
            )
        ],
    )
    cw = FakeCloudWatch(datapoints_by_metric={"DataReadBytes": [{"Sum": 1.0}]})  # active or not doesn't matter here
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.filesystems.multi.az.in.nonprod" for f in findings)


def test_windows_backups_disabled_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "team-a"}],
                windows_cfg={"DeploymentType": "SINGLE_AZ_1", "AutomaticBackupRetentionDays": 0, "CopyTagsToBackups": True},
            )
        ],
    )
    cw = FakeCloudWatch(datapoints_by_metric={"DataReadBytes": [{"Sum": 1.0}]})
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.windows.backups.disabled" for f in findings)


def test_windows_copy_tags_disabled_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "team-a"}],
                windows_cfg={"AutomaticBackupRetentionDays": 7, "CopyTagsToBackups": False},
            )
        ],
    )
    cw = FakeCloudWatch(datapoints_by_metric={"DataReadBytes": [{"Sum": 1.0}]})
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.windows.copy.tags.to.backups.disabled" for f in findings)


def test_windows_maintenance_window_missing_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "team-a"}],
                windows_cfg={"AutomaticBackupRetentionDays": 7, "CopyTagsToBackups": True},
            )
        ],
    )
    cw = FakeCloudWatch(datapoints_by_metric={"DataReadBytes": [{"Sum": 1.0}]})
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.windows.maintenance.window.missing" for f in findings)


def test_missing_required_tags_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "prod"}],  # missing owner
                windows_cfg={"AutomaticBackupRetentionDays": 7, "CopyTagsToBackups": True},
            )
        ],
    )
    cw = FakeCloudWatch(datapoints_by_metric={"DataReadBytes": [{"Sum": 1.0}]})
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(
        account_id="111111111111",
        cfg=FSxFileSystemsConfig(required_tag_keys=("env", "owner")),
    )
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.filesystems.missing.required.tags" for f in findings)


def test_windows_storage_type_mismatch_emits_when_ssd_low_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.fsx_filesystems as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc))

    fsx = FakeFSx(
        region="eu-west-1",
        file_systems=[
            _fs(
                tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "team-a"}],
                windows_cfg={"StorageType": "SSD", "AutomaticBackupRetentionDays": 7, "CopyTagsToBackups": True},
            )
        ],
    )

    # Low activity over the window: metrics exist, but show near-zero.
    cw = FakeCloudWatch(
        datapoints_by_metric={
            "DataReadBytes": [{"Sum": 0.0}],
            "DataWriteBytes": [{"Sum": 0.0}],
            "ThroughputUtilization": [{"Average": 0.0}],
        }
    )
    ctx = _mk_ctx(fsx=fsx, cloudwatch=cw)

    checker = FSxFileSystemsChecker(account_id="111111111111", cfg=FSxFileSystemsConfig())
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.fsx.windows.storage.type.mismatch" for f in findings)


def test_fsx_storage_pricing_uses_service_quote() -> None:
    import checks.aws.fsx_filesystems as mod

    quote = SimpleNamespace(
        unit_price_usd=0.22,
        source="catalog",
        as_of=datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc),
        unit="GB-Mo",
    )

    pricing = SimpleNamespace(
        location_for_region=lambda _region: "EU (Ireland)",
        get_on_demand_unit_price=lambda **_kwargs: quote,
    )
    ctx = cast(RunContext, SimpleNamespace(cloud="aws", services=SimpleNamespace(pricing=pricing)))

    price, notes, confidence = mod._resolve_fsx_storage_price_usd_per_gb_month(
        ctx,
        region="eu-west-1",
        fs_type="WINDOWS",
        storage_type="SSD",
    )

    assert price == pytest.approx(0.22)
    assert confidence == 70
    assert "PricingService catalog" in notes


def test_fsx_storage_pricing_falls_back_on_lookup_error() -> None:
    import checks.aws.fsx_filesystems as mod

    def _raise_type_error(**_kwargs: Any) -> Any:
        raise TypeError("boom")

    pricing = SimpleNamespace(
        location_for_region=lambda _region: "EU (Ireland)",
        get_on_demand_unit_price=_raise_type_error,
    )
    ctx = cast(RunContext, SimpleNamespace(cloud="aws", services=SimpleNamespace(pricing=pricing)))

    price, notes, confidence = mod._resolve_fsx_storage_price_usd_per_gb_month(
        ctx,
        region="eu-west-1",
        fs_type="WINDOWS",
        storage_type="SSD",
    )

    assert price == pytest.approx(0.13)
    assert confidence == 30
    assert "fallback pricing" in notes


def test_fsx_throughput_pricing_tries_multiple_units() -> None:
    import checks.aws.fsx_filesystems as mod

    calls: List[str] = []

    def _get_on_demand_unit_price(*, unit: str, **_kwargs: Any) -> Any:
        calls.append(unit)
        if unit == "MBps-month":
            return SimpleNamespace(
                unit_price_usd=1.7,
                source="catalog",
                as_of=datetime(2026, 1, 27, 12, 0, 0, tzinfo=timezone.utc),
                unit=unit,
            )
        return None

    pricing = SimpleNamespace(
        location_for_region=lambda _region: "EU (Ireland)",
        get_on_demand_unit_price=_get_on_demand_unit_price,
    )
    ctx = cast(RunContext, SimpleNamespace(cloud="aws", services=SimpleNamespace(pricing=pricing)))

    price, notes, confidence = mod._resolve_fsx_throughput_price_usd_per_mbps_month(
        ctx,
        region="eu-west-1",
        fs_type="WINDOWS",
    )

    assert price == pytest.approx(1.7)
    assert confidence == 70
    assert "PricingService catalog" in notes
    assert "MBps-Mo" in calls
    assert "MBps-month" in calls
