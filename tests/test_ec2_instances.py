"""Unit tests for the EC2 instances checker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

import pytest

from checks.aws.ec2_instances import EC2InstancesChecker, EC2InstancesConfig
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEC2:
    """Minimal EC2 fake for this checker."""

    def __init__(self, *, region: str, pages_by_op: Dict[str, List[Mapping[str, Any]]], volumes: Optional[Dict[str, Any]] = None) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op
        self._volumes = volumes or {}

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeEC2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)

    def describe_volumes(self, *, VolumeIds: List[str]) -> Mapping[str, Any]:
        vols = [self._volumes[v] for v in VolumeIds if v in self._volumes]
        return {"Volumes": vols}


class FakeCloudWatch:
    def __init__(self, *, results_by_id: Dict[str, List[float]]) -> None:
        self._results_by_id = results_by_id

    def get_metric_data(self, *, MetricDataQueries: List[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:
        out = []
        for q in MetricDataQueries:
            qid = str(q.get("Id"))
            out.append({"Id": qid, "Values": list(self._results_by_id.get(qid, []))})
        return {"MetricDataResults": out}


class FakePriceQuote:
    def __init__(self, unit_price: float) -> None:
        self.unit_price = unit_price


class FakePricing:
    def location_for_region(self, region: str) -> str:
        assert region
        return "EU (Paris)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        assert service_code == "AmazonEC2"
        assert unit == "Hrs"
        # Return a stable fake hourly price.
        return FakePriceQuote(0.1)


class FakePricingByType:
    """Pricing fake that returns deterministic hourly prices by EC2 instance type."""

    def __init__(self, hourly_by_instance_type: Dict[str, float]) -> None:
        self._hourly_by_instance_type = dict(hourly_by_instance_type)

    def location_for_region(self, region: str) -> str:
        assert region
        return "EU (Paris)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        assert service_code == "AmazonEC2"
        assert unit == "Hrs"
        instance_type = ""
        for filt in list(filters or []):
            if str((filt or {}).get("Field") or "") == "instanceType":
                instance_type = str((filt or {}).get("Value") or "")
                break
        return FakePriceQuote(float(self._hourly_by_instance_type.get(instance_type, 0.1)))


def _mk_ctx(*, ec2: FakeEC2, cloudwatch: Optional[FakeCloudWatch] = None, pricing: Optional[Any] = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(ec2=ec2, cloudwatch=cloudwatch, pricing=pricing),
        ),
    )


def test_underutilized_running_instance_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-1",
                                    "InstanceType": "t3.micro",
                                    "State": {"Name": "running"},
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )

    # Batch queries: cpu0/ni0/no0 for the first instance
    cw = FakeCloudWatch(results_by_id={"cpu0": [2.0, 3.0], "ni0": [1024.0], "no0": [1024.0]})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    checker = EC2InstancesChecker(account=mod.AwsAccountContext(account_id="123", billing_account_id="123"), cfg=EC2InstancesConfig())
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.underutilized"]
    assert len(hits) == 1
    f = hits[0]
    assert f.scope.resource_id == "i-1"
    # 0.1 $/hr * 730 = 73
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(73.0, rel=1e-6)


def test_underutilized_includes_rightsizing_target_and_delta(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-rightsize",
                                    "InstanceType": "m5.2xlarge",
                                    "State": {"Name": "running"},
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )

    cw = FakeCloudWatch(results_by_id={"cpu0": [1.0, 2.0], "ni0": [1024.0], "no0": [1024.0]})
    pricing = FakePricingByType({"m5.2xlarge": 0.40, "m5.xlarge": 0.20})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=pricing)

    checker = EC2InstancesChecker(account=mod.AwsAccountContext(account_id="123", billing_account_id="123"))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.underutilized"]
    assert len(hits) == 1
    f = hits[0]
    assert "m5.2xlarge to m5.xlarge" in f.recommendation
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(292.0, rel=1e-6)
    assert float(f.estimated_monthly_savings or 0.0) == pytest.approx(146.0, rel=1e-6)
    assert (f.dimensions or {}).get("recommended_instance_type") == "m5.xlarge"
    assert (f.dimensions or {}).get("rightsizing_monthly_savings_usd") == "146.00"


def test_stopped_long_emits_with_storage_estimate(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-stop",
                                    "InstanceType": "t3.micro",
                                    "State": {"Name": "stopped"},
                                    "StateTransitionReason": "User initiated (2025-12-01 00:00:00)",
                                    "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
        volumes={"vol-1": {"VolumeId": "vol-1", "Size": 100, "VolumeType": "gp2"}},
    )

    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = EC2InstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
        cfg=EC2InstancesConfig(stopped_long_age_days=30),
    )
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.stopped.long"]
    assert len(hits) == 1
    f = hits[0]
    # 100 GiB * 0.10 = 10
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(10.0, rel=1e-6)


def test_old_generation_family_emits_info(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {"Instances": [{"InstanceId": "i-old", "InstanceType": "m3.large", "State": {"Name": "running"}}]}
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = EC2InstancesChecker(account=mod.AwsAccountContext(account_id="123", billing_account_id="123"))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.old.generation"]
    assert len(hits) == 1
    assert hits[0].status == "info"


def test_missing_tags_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {"InstanceId": "i-tag", "InstanceType": "m6i.large", "State": {"Name": "running"}, "Tags": [{"Key": "env", "Value": "prod"}]}
                            ]
                        }
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )

    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = mod.EC2InstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
        cfg=mod.EC2InstancesConfig(required_instance_tag_keys=("owner", "env", "cost_center")),
    )
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.tags.missing"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "i-tag"
    assert "owner" in (hits[0].dimensions or {}).get("missing_tag_keys", "")


def test_t_family_credit_issue_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-t", "InstanceType": "t3.micro", "State": {"Name": "running"}}]}]}],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )

    # Credit queries will be cb0/sc0 for the first instance in batch
    cw = FakeCloudWatch(results_by_id={"cb0": [10.0], "sc0": [0.0]})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=None)

    checker = mod.EC2InstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
        cfg=mod.EC2InstancesConfig(t_credit_balance_min_threshold=20.0, t_credit_lookback_days=7),
    )
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.t.credit.issues"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "i-t"


def test_imdsv1_allowed_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "t3.micro", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "optional"}}]}]}
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = mod.EC2InstancesChecker(account=mod.AwsAccountContext(account_id="123", billing_account_id="123"))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.instances.security.imdsv1.allowed"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "i-1"


def test_unused_security_group_excludes_referenced(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [{"Reservations": []}],
            "describe_network_interfaces": [
                {
                    "NetworkInterfaces": [
                        {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-attached", "GroupName": "used"}]}
                    ]
                }
            ],
            "describe_security_groups": [
                {
                    "SecurityGroups": [
                        {"GroupId": "sg-attached", "GroupName": "used", "IpPermissions": [], "IpPermissionsEgress": []},
                        {"GroupId": "sg-unused", "GroupName": "unused", "IpPermissions": [], "IpPermissionsEgress": []},
                        # Referenced by another SG rule => excluded
                        {
                            "GroupId": "sg-ref",
                            "GroupName": "referenced",
                            "IpPermissions": [],
                            "IpPermissionsEgress": [],
                        },
                        {
                            "GroupId": "sg-has-ref",
                            "GroupName": "has-ref",
                            "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-ref"}]}],
                            "IpPermissionsEgress": [],
                        },
                    ]
                }
            ],
        },
    )

    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = EC2InstancesChecker(account=mod.AwsAccountContext(account_id="123", billing_account_id="123"))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.security.groups.unused"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "sg-unused"


def test_pricing_lookup_handles_malformed_pricing_data() -> None:
    import checks.aws.ec2_instances as mod

    class BadPricing:
        def location_for_region(self, _region: str) -> str:
            return "EU (Paris)"

        def get_on_demand_unit_price(self, **_kwargs: Any) -> Any:
            return SimpleNamespace(unit_price="not-a-number")

    monthly, confidence, notes = mod._estimate_instance_monthly_cost_usd(
        cast(RunContext, SimpleNamespace(services=SimpleNamespace(pricing=BadPricing()))),
        region="eu-west-3",
        instance_type="t3.micro",
    )
    assert monthly is None
    assert confidence == 35
    assert "invalid on-demand EC2 unit price" in notes


def test_stopped_long_ignores_malformed_volume_size(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.ec2_instances as mod

    monkeypatch.setattr(mod, "now_utc", lambda: datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc))
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-stop-bad-vol",
                                    "InstanceType": "t3.micro",
                                    "State": {"Name": "stopped"},
                                    "StateTransitionReason": "User initiated (2025-12-01 00:00:00)",
                                    "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-bad"}}],
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_network_interfaces": [{"NetworkInterfaces": []}],
        },
        volumes={"vol-bad": {"VolumeId": "vol-bad", "Size": "oops", "VolumeType": "gp2"}},
    )

    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)
    checker = EC2InstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
        cfg=EC2InstancesConfig(stopped_long_age_days=30),
    )
    findings = list(checker.run(ctx))
    hit = next(f for f in findings if f.check_id == "aws.ec2.instances.stopped.long")
    assert hit.scope.resource_id == "i-stop-bad-vol"
    assert float(hit.estimated_monthly_cost or 0.0) == pytest.approx(0.0, rel=1e-6)
