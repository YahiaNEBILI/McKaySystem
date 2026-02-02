"""Unit tests for the EBS storage checker."""

# tests/checks/aws/test_ebs_storage.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

import pytest

from checks.aws.ebs_storage import EBSStorageChecker, EBSStorageConfig
from contracts.finops_checker_pattern import RunContext
from checks.aws import _common

class FakePaginator:
    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEC2:
    """
    Minimal EC2 fake:
      - meta.region_name
      - get_paginator(op_name) -> FakePaginator
    """

    def __init__(self, *, region: str, pages_by_op: Dict[str, List[Mapping[str, Any]]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeEC2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)


@dataclass
class FakeServices:
    ec2: Any


@dataclass
class FakeRunContext:
    cloud: str
    services: Any


def _dt(days_ago: int) -> datetime:
    # Helper for test data; "now" will be monkeypatched.
    return datetime(2026, 1, 24, tzinfo=timezone.utc) - timedelta(days=days_ago)


def _run(
    *,
    monkeypatch: pytest.MonkeyPatch,
    ec2: FakeEC2,
    cfg: Optional[EBSStorageConfig] = None,
) -> List[Any]:

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(_common, "now_utc", lambda: now)

    # Duck-typed context; cast keeps Pylance happy.
    ctx = cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(ec2=ec2),
        ),
    )

    checker = EBSStorageChecker(account_id="123456789012", cfg=cfg)
    return list(checker.run(ctx))


def _find(findings: List[Any], check_id: str) -> List[Any]:
    return [f for f in findings if getattr(f, "check_id", "") == check_id]


def test_unattached_volume_emits_with_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-1",
                            "State": "available",
                            "Attachments": [],
                            "CreateTime": _dt(10),
                            "VolumeType": "gp2",
                            "Size": 100,
                            "Encrypted": True,
                            "Tags": [],
                        }
                    ]
                }
            ],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [{"Snapshots": []}],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2, cfg=EBSStorageConfig(unattached_min_age_days=7))
    hits = _find(findings, "aws.ec2.ebs.unattached_volume")
    assert len(hits) == 1
    f = hits[0]
    assert f.status == "fail"
    assert f.scope.resource_id == "vol-1"
    # 100 GB * $0.10 = $10.00 (fallback)
    assert float(f.estimated_monthly_cost) == pytest.approx(10.0, rel=1e-6)
    assert float(f.estimated_monthly_savings) == pytest.approx(10.0, rel=1e-6)
    assert f.dimensions["age_days"] in ("10", "9", "11")  # defensive around day rounding


def test_unattached_volume_suppressed_by_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-suppressed",
                            "State": "available",
                            "Attachments": [],
                            "CreateTime": _dt(60),
                            "VolumeType": "gp2",
                            "Size": 50,
                            "Encrypted": True,
                            "Tags": [{"Key": "purpose", "Value": "retain"}],
                        }
                    ]
                }
            ],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [{"Snapshots": []}],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2)
    assert _find(findings, "aws.ec2.ebs.unattached_volume") == []


def test_gp2_to_gp3_emits_savings(monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-gp2",
                            "State": "in-use",
                            "Attachments": [{"InstanceId": "i-1"}],
                            "CreateTime": _dt(1),
                            "VolumeType": "gp2",
                            "Size": 200,
                            "Encrypted": True,
                            "Tags": [],
                        }
                    ]
                }
            ],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [{"Snapshots": []}],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2)
    hits = _find(findings, "aws.ec2.ebs.gp2_to_gp3")
    assert len(hits) == 1
    f = hits[0]
    assert f.scope.resource_id == "vol-gp2"
    # 200 GB * ($0.10 - $0.08) = $4.00
    assert float(f.estimated_monthly_savings) == pytest.approx(4.0, rel=1e-6)
    assert "storage-only" in (f.estimate_notes or "").lower()


def test_old_snapshot_emits_when_not_referenced_by_ami(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = EBSStorageConfig(snapshot_old_age_days=45)

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [{"Volumes": []}],
            "describe_images": [{"Images": []}],  # no AMIs reference it
            "describe_snapshots": [
                {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-old",
                            "StartTime": _dt(90),
                            "VolumeSize": 300,
                            "Encrypted": True,
                            "Description": "manual snapshot",
                            "Tags": [],
                        }
                    ]
                }
            ],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2, cfg=cfg)
    hits = _find(findings, "aws.ec2.ebs.old_snapshot")
    assert len(hits) == 1
    f = hits[0]
    assert f.scope.resource_id == "snap-old"
    # Conservative estimate: 300 GB * $0.10 = $30.00
    assert float(f.estimated_monthly_cost) == pytest.approx(30.0, rel=1e-6)
    assert float(f.estimated_monthly_savings) == pytest.approx(30.0, rel=1e-6)
    assert f.dimensions["referenced_by_ami"] == "false"
    assert f.dimensions["aws_backup_managed"] == "false"


def test_old_snapshot_skipped_when_referenced_by_ami(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = EBSStorageConfig(snapshot_old_age_days=45)

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [{"Volumes": []}],
            "describe_images": [
                {
                    "Images": [
                        {
                            "ImageId": "ami-1",
                            "BlockDeviceMappings": [
                                {"Ebs": {"SnapshotId": "snap-ref"}},
                            ],
                        }
                    ]
                }
            ],
            "describe_snapshots": [
                {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-ref",
                            "StartTime": _dt(120),
                            "VolumeSize": 50,
                            "Encrypted": True,
                            "Description": "referenced by ami",
                            "Tags": [],
                        }
                    ]
                }
            ],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2, cfg=cfg)
    assert _find(findings, "aws.ec2.ebs.old_snapshot") == []


def test_aws_backup_managed_snapshots_are_guardrailed(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Guardrail applies to:
      - old_snapshot cleanup signal
      - unencrypted snapshot governance signal
    """
    cfg = EBSStorageConfig(snapshot_old_age_days=45)

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [{"Volumes": []}],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [
                {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-backup-old",
                            "StartTime": _dt(120),
                            "VolumeSize": 10,
                            "Encrypted": True,
                            "Description": "Created by AWS Backup",
                            "Tags": [{"Key": "aws:backup:source-resource", "Value": "arn:..."}],
                        },
                        {
                            "SnapshotId": "snap-backup-unenc",
                            "StartTime": _dt(5),
                            "VolumeSize": 10,
                            "Encrypted": False,
                            "Description": "AWS Backup snapshot",
                            "Tags": [{"Key": "aws:backup:job-id", "Value": "job-1"}],
                        },
                    ]
                }
            ],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2, cfg=cfg)
    assert _find(findings, "aws.ec2.ebs.old_snapshot") == []
    assert _find(findings, "aws.ec2.ebs.snapshot_unencrypted") == []


def test_unencrypted_volume_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-unenc",
                            "State": "in-use",
                            "Attachments": [{"InstanceId": "i-1"}],
                            "CreateTime": _dt(5),
                            "VolumeType": "gp3",
                            "Size": 20,
                            "Encrypted": False,
                            "Tags": [],
                        }
                    ]
                }
            ],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [{"Snapshots": []}],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2)
    hits = _find(findings, "aws.ec2.ebs.volume_unencrypted")
    assert len(hits) == 1
    f = hits[0]
    assert f.scope.resource_id == "vol-unenc"
    assert f.category == "governance"
    assert f.sub_category == "encryption"
    assert f.dimensions["encrypted"] == "false"


def test_unencrypted_snapshot_emits_when_not_backup(monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_volumes": [{"Volumes": []}],
            "describe_images": [{"Images": []}],
            "describe_snapshots": [
                {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-unenc",
                            "StartTime": _dt(3),
                            "VolumeSize": 123,
                            "Encrypted": False,
                            "Description": "manual snapshot",
                            "Tags": [],
                        }
                    ]
                }
            ],
        },
    )

    findings = _run(monkeypatch=monkeypatch, ec2=ec2)
    hits = _find(findings, "aws.ec2.ebs.snapshot_unencrypted")
    assert len(hits) == 1
    f = hits[0]
    assert f.scope.resource_id == "snap-unenc"
    assert f.category == "governance"
    assert f.sub_category == "encryption"
    assert f.dimensions["encrypted"] == "false"
    assert f.dimensions["aws_backup_managed"] == "false"
