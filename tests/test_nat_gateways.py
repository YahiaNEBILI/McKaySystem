"""Unit tests for the NAT Gateways checker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, cast

import pytest
from botocore.exceptions import ClientError

from checks.aws.nat_gateways import NatGatewaysChecker, NatGatewaysConfig
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEC2:
    """Minimal EC2 fake for NAT checker."""

    def __init__(
        self,
        *,
        region: str,
        pages_by_op: Dict[str, List[Mapping[str, Any]]],
        subnets: Optional[Dict[str, Mapping[str, Any]]] = None,
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op
        self._subnets = subnets or {}

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeEC2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)

    def describe_subnets(self, *, SubnetIds: Sequence[str]) -> Mapping[str, Any]:
        items = [self._subnets[sid] for sid in SubnetIds if sid in self._subnets]
        return {"Subnets": items}


class FakeEC2AccessDenied(FakeEC2):
    """EC2 fake that raises an AccessDenied-like ClientError."""

    def get_paginator(self, op_name: str) -> FakePaginator:  # pylint: disable=unused-argument
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetPaginator",
        )

    def describe_nat_gateways(self, **_kwargs: Any) -> Mapping[str, Any]:
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="DescribeNatGateways",
        )


class FakeCloudWatch:
    def __init__(self, *, out_by_id: Dict[str, List[float]], in_by_id: Dict[str, List[float]]) -> None:
        self._out_by_id = out_by_id
        self._in_by_id = in_by_id

    def get_metric_data(self, *, MetricDataQueries: List[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:
        results: List[Dict[str, Any]] = []
        for q in MetricDataQueries:
            qid = str(q.get("Id"))
            metric = q.get("MetricStat", {}).get("Metric", {})
            name = str(metric.get("MetricName") or "")
            if name == "BytesOutToDestination":
                vals = list(self._out_by_id.get(qid, []))
            else:
                vals = list(self._in_by_id.get(qid, []))
            results.append({"Id": qid, "Values": vals})
        return {"MetricDataResults": results}


class FakeCloudWatchAccessDenied(FakeCloudWatch):
    def get_metric_data(self, *, MetricDataQueries: List[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:  # pylint: disable=unused-argument
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetMetricData",
        )


class FakePriceQuote:
    def __init__(self, unit_price: float) -> None:
        self.unit_price = unit_price


class FakePricing:
    def location_for_region(self, region: str) -> str:
        assert region
        return "EU (Paris)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        assert service_code == "AmazonEC2"
        if unit == "Hrs":
            return FakePriceQuote(0.05)
        return FakePriceQuote(0.04)


def _mk_ctx(*, ec2: FakeEC2, cloudwatch: Optional[FakeCloudWatch] = None, pricing: Optional[Any] = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(ec2=ec2, cloudwatch=cloudwatch, pricing=pricing),
        ),
    )


def test_orphaned_nat_gateway_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=2),
        "Tags": [{"Key": "Name", "Value": "orphan"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": []}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.orphaned"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "nat-1"


def test_idle_nat_gateway_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }

    rt = {
        "RouteTableId": "rtb-1",
        "Associations": [{"SubnetId": "subnet-private"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt]}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )

    # qid for first NAT is "m0"
    cw = FakeCloudWatch(out_by_id={"m0": [100.0] * 10}, in_by_id={"m0": [100.0] * 10})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(lookback_days=14, min_daily_datapoints=7, idle_p95_daily_bytes_threshold=1_000.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.idle"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "nat-1"


def test_high_data_processing_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }
    rt = {
        "RouteTableId": "rtb-1",
        "Associations": [{"SubnetId": "subnet-private"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt]}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )

    # 5 GiB/day out + 5 GiB/day in => 10 GiB/day merged -> ~300 GiB/month
    day_bytes = 5 * (1024.0**3)
    cw = FakeCloudWatch(out_by_id={"m0": [day_bytes] * 10}, in_by_id={"m0": [day_bytes] * 10})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(high_data_processing_gib_month_threshold=100.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.high_data_processing"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "nat-1"


def test_cross_az_nat_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }

    rt = {
        "RouteTableId": "rtb-1",
        "Associations": [{"SubnetId": "subnet-private"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt]}],
        },
        subnets={
            "subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"},
            "subnet-private": {"SubnetId": "subnet-private", "AvailabilityZone": "eu-west-3b"},
        },
    )

    # Provide metrics but prevent idle triggering
    cw = FakeCloudWatch(out_by_id={"m0": [1_000_000.0] * 10}, in_by_id={"m0": [1_000_000.0] * 10})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(idle_p95_daily_bytes_threshold=0.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.cross_az"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "nat-1"


def test_access_denied_emits_access_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The checker should not crash on missing EC2 permissions."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    ec2 = FakeEC2AccessDenied(region="eu-west-3", pages_by_op={})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=None)

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.ec2.nat_gateways.access_error" for f in findings)


def test_cloudwatch_access_denied_emits_missing_permission_and_inventory_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """CloudWatch metrics may be denied; inventory-only signals should still work."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=2),
        "Tags": [],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": []}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )

    cw = FakeCloudWatchAccessDenied(out_by_id={}, in_by_id={})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.ec2.nat_gateways.orphaned" for f in findings)
    perm = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.missing_permission"]
    assert len(perm) == 1
    assert perm[0].issue_key.get("operation") == "cloudwatch:GetMetricData"


@pytest.mark.parametrize(
    "tag_key,tag_value",
    [
        ("finops:ignore", "true"),
        ("keep", "true"),
        ("do-not-delete", "1"),
    ],
)
def test_suppression_tags_skip(monkeypatch: pytest.MonkeyPatch, tag_key: str, tag_value: str) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [{"Key": tag_key, "Value": tag_value}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": []}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    assert findings == []



def test_pagination_multiple_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat1 = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-1",
        "CreateTime": now - timedelta(days=5),
        "Tags": [],
    }
    nat2 = {
        "NatGatewayId": "nat-2",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-2",
        "CreateTime": now - timedelta(days=5),
        "Tags": [],
    }

    # Route tables empty => both orphaned
    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat1]}, {"NatGateways": [nat2]}],
            "describe_route_tables": [{"RouteTables": []}, {"RouteTables": []}],
        },
        subnets={
            "subnet-nat-1": {"SubnetId": "subnet-nat-1", "AvailabilityZone": "eu-west-3a"},
            "subnet-nat-2": {"SubnetId": "subnet-nat-2", "AvailabilityZone": "eu-west-3b"},
        },
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.orphaned"]
    assert {f.scope.resource_id for f in hits} == {"nat-1", "nat-2"}


def test_determinism_shuffled_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same resources in different input order must yield identical outputs."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat_a = {
        "NatGatewayId": "nat-a",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-a",
        "CreateTime": now - timedelta(days=3),
        "Tags": [],
    }
    nat_b = {
        "NatGatewayId": "nat-b",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-b",
        "CreateTime": now - timedelta(days=3),
        "Tags": [],
    }

    pages1 = {"describe_nat_gateways": [{"NatGateways": [nat_a, nat_b]}], "describe_route_tables": [{"RouteTables": []}]}
    pages2 = {"describe_nat_gateways": [{"NatGateways": [nat_b, nat_a]}], "describe_route_tables": [{"RouteTables": []}]}

    subnets = {
        "subnet-nat-a": {"SubnetId": "subnet-nat-a", "AvailabilityZone": "eu-west-3a"},
        "subnet-nat-b": {"SubnetId": "subnet-nat-b", "AvailabilityZone": "eu-west-3b"},
    }

    ctx1 = _mk_ctx(ec2=FakeEC2(region="eu-west-3", pages_by_op=pages1, subnets=subnets), cloudwatch=None, pricing=FakePricing())
    ctx2 = _mk_ctx(ec2=FakeEC2(region="eu-west-3", pages_by_op=pages2, subnets=subnets), cloudwatch=None, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    f1 = list(checker.run(ctx1))
    f2 = list(checker.run(ctx2))

    def _sig(fs: List[Any]) -> List[Any]:
        return sorted(
            [(x.check_id, x.scope.resource_id, tuple(sorted((x.issue_key or {}).items()))) for x in fs],
            key=lambda t: (t[0], t[1], t[2]),
        )

    assert _sig(f1) == _sig(f2)

def test_public_route_table_skips_cross_az(monkeypatch: pytest.MonkeyPatch) -> None:
    """Public/shared route tables (default route to IGW) should not drive cross-AZ inference."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }

    # Route table associated to a subnet in a different AZ, but it's public (default route to IGW),
    # so the checker should not emit cross-AZ based on it.
    rt_public = {
        "RouteTableId": "rtb-public",
        "Associations": [{"SubnetId": "subnet-public-ish"}],
        "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"},
            {"DestinationCidrBlock": "10.0.0.0/8", "NatGatewayId": "nat-1"},
        ],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt_public]}],
        },
        subnets={
            "subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"},
            "subnet-public-ish": {"SubnetId": "subnet-public-ish", "AvailabilityZone": "eu-west-3b"},
        },
    )

    # Provide metrics but prevent idle triggering
    cw = FakeCloudWatch(out_by_id={"m0": [1_000_000.0] * 10}, in_by_id={"m0": [1_000_000.0] * 10})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(idle_p95_daily_bytes_threshold=0.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    assert not any(f.check_id == "aws.ec2.nat_gateways.cross_az" for f in findings)


def test_nat_states_deleted_skipped_deleting_no_orphan(monkeypatch: pytest.MonkeyPatch) -> None:
    """deleted NATs are skipped; deleting NATs should not emit orphaned findings; pending is evaluated."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat_pending = {
        "NatGatewayId": "nat-pending",
        "State": "pending",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-a",
        "CreateTime": now - timedelta(days=5),
        "Tags": [],
    }
    nat_deleting = {
        "NatGatewayId": "nat-deleting",
        "State": "deleting",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-b",
        "CreateTime": now - timedelta(days=5),
        "Tags": [],
    }
    nat_deleted = {
        "NatGatewayId": "nat-deleted",
        "State": "deleted",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat-c",
        "CreateTime": now - timedelta(days=5),
        "Tags": [],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat_pending, nat_deleting, nat_deleted]}],
            "describe_route_tables": [{"RouteTables": []}],
        },
        subnets={
            "subnet-nat-a": {"SubnetId": "subnet-nat-a", "AvailabilityZone": "eu-west-3a"},
            "subnet-nat-b": {"SubnetId": "subnet-nat-b", "AvailabilityZone": "eu-west-3b"},
            "subnet-nat-c": {"SubnetId": "subnet-nat-c", "AvailabilityZone": "eu-west-3c"},
        },
    )
    ctx = _mk_ctx(ec2=ec2, cloudwatch=None, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    orphaned = [f for f in findings if f.check_id == "aws.ec2.nat_gateways.orphaned"]
    assert {f.scope.resource_id for f in orphaned} == {"nat-pending"}
    assert not any(f.scope.resource_id == "nat-deleting" for f in orphaned)
    assert not any(f.scope.resource_id == "nat-deleted" for f in orphaned)


def test_low_datapoint_count_blocks_metric_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """If metrics exist but there are too few datapoints, idle/high_data should not trigger."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }

    rt = {
        "RouteTableId": "rtb-1",
        "Associations": [{"SubnetId": "subnet-private"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt]}],
        },
        subnets={
            "subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"},
            "subnet-private": {"SubnetId": "subnet-private", "AvailabilityZone": "eu-west-3a"},
        },
    )

    # Only 3 datapoints => below min_daily_datapoints=7
    cw = FakeCloudWatch(out_by_id={"m0": [0.0, 0.0, 0.0]}, in_by_id={"m0": [0.0, 0.0, 0.0]})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(lookback_days=14, min_daily_datapoints=7, idle_p95_daily_bytes_threshold=1_000.0, high_data_processing_gib_month_threshold=1.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    assert not any(f.check_id == "aws.ec2.nat_gateways.idle" for f in findings)
    assert not any(f.check_id == "aws.ec2.nat_gateways.high_data_processing" for f in findings)


def test_p95_computation_floor_index_regression(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test: p95 should use floor index, not round() (which would bias to the max for small n)."""

    import checks.aws.nat_gateways as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    nat = {
        "NatGatewayId": "nat-1",
        "State": "available",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-nat",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }

    rt = {
        "RouteTableId": "rtb-1",
        "Associations": [{"SubnetId": "subnet-private"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
    }

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": [{"NatGateways": [nat]}],
            "describe_route_tables": [{"RouteTables": [rt]}],
        },
        subnets={"subnet-nat": {"SubnetId": "subnet-nat", "AvailabilityZone": "eu-west-3a"}},
    )

    # 5 datapoints: if p95 used round(), idx would be 4 (max) => large bytes => not idle.
    # With floor, idx=int(0.95*(5-1))=3 => value=0 => idle.
    vals = [0.0, 0.0, 0.0, 0.0, 10_000_000.0]
    cw = FakeCloudWatch(out_by_id={"m0": vals}, in_by_id={"m0": [0.0] * 5})
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(min_daily_datapoints=1, idle_p95_daily_bytes_threshold=1.0)
    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.ec2.nat_gateways.idle" for f in findings)
