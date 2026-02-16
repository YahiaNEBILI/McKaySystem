"""Unit tests for the ALB/NLB (ELBv2) checker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast
from dataclasses import dataclass

import pytest

from botocore.exceptions import ClientError

from checks.aws.elbv2_load_balancers import ElbV2LoadBalancersChecker, ElbV2LoadBalancersConfig
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: List[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeElbv2:
    """Minimal ELBv2 fake."""

    def __init__(self, *, region: str, pages_by_op: Dict[str, List[Mapping[str, Any]]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op
        self._tags_by_arn: Dict[str, Dict[str, str]] = {}
        self._target_health_by_tg: Dict[str, List[Mapping[str, Any]]] = {}

    def set_tags(self, arn: str, tags: Dict[str, str]) -> None:
        self._tags_by_arn[str(arn)] = dict(tags)

    def set_target_health(self, tg_arn: str, desc: List[Mapping[str, Any]]) -> None:
        self._target_health_by_tg[str(tg_arn)] = list(desc)

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeElbv2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)

    def describe_tags(self, *, ResourceArns: List[str]) -> Mapping[str, Any]:
        out = []
        for arn in ResourceArns:
            tmap = self._tags_by_arn.get(str(arn), {})
            out.append(
                {
                    "ResourceArn": arn,
                    "Tags": [{"Key": k, "Value": v} for k, v in tmap.items()],
                }
            )
        return {"TagDescriptions": out}

    def describe_target_health(self, *, TargetGroupArn: str) -> Mapping[str, Any]:
        return {"TargetHealthDescriptions": self._target_health_by_tg.get(str(TargetGroupArn), [])}


@dataclass
class FakeElbv2AccessDenied:
    """ELBv2 fake that raises AccessDenied for both paginator and direct calls."""
    region: str
    pages_by_op: Dict[str, Any]

    def __post_init__(self) -> None:
        # mimic boto3 client's region metadata
        self.meta = SimpleNamespace(region_name=self.region)

    def get_paginator(self, _op_name: str):
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="GetPaginator",
        )

    def describe_load_balancers(self, **_kwargs: Any) -> Mapping[str, Any]:
        raise ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "denied"}},
            operation_name="DescribeLoadBalancers",
        )

class FakeCloudWatch:
    def __init__(self, *, by_id: Dict[str, List[float]]) -> None:
        self._by_id = by_id

    def get_metric_data(self, *, MetricDataQueries: List[Mapping[str, Any]], **_kwargs: Any) -> Mapping[str, Any]:
        out = []
        for q in MetricDataQueries:
            qid = str(q.get("Id"))
            out.append({"Id": qid, "Values": list(self._by_id.get(qid, []))})
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
        # Don't care about filters in unit tests.
        return FakePriceQuote(0.03)


def _mk_ctx(*, elbv2: Any, cloudwatch: Optional[Any] = None, pricing: Optional[Any] = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(elbv2=elbv2, cloudwatch=cloudwatch, pricing=pricing),
        ),
    )


def _lb_arn(suffix: str) -> str:
    return f"arn:aws:elasticloadbalancing:eu-west-3:111111111111:loadbalancer/{suffix}"


def test_no_listeners_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.elbv2_load_balancers as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    arn = _lb_arn("app/test/123")
    lb = {
        "LoadBalancerArn": arn,
        "LoadBalancerName": "test",
        "Type": "application",
        "Scheme": "internet-facing",
        "CreatedTime": now - timedelta(days=10),
    }

    elbv2 = FakeElbv2(
        region="eu-west-3",
        pages_by_op={
            "describe_load_balancers": [{"LoadBalancers": [lb]}],
            "describe_listeners": [{"Listeners": []}],
            "describe_target_groups": [{"TargetGroups": []}],
        },
    )

    ctx = _mk_ctx(elbv2=elbv2, cloudwatch=None, pricing=FakePricing())
    checker = ElbV2LoadBalancersChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.elbv2.load.balancers.no.listeners"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "test"


def test_idle_alb_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.elbv2_load_balancers as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    arn = _lb_arn("app/idle/123")
    lb = {
        "LoadBalancerArn": arn,
        "LoadBalancerName": "idle",
        "Type": "application",
        "Scheme": "internal",
        "CreatedTime": now - timedelta(days=10),
    }

    listener = {"ListenerArn": "lst-1", "DefaultActions": [{"Type": "forward", "TargetGroupArn": "tg-1"}]}
    tg = {"TargetGroupArn": "tg-1", "TargetType": "instance"}

    elbv2 = FakeElbv2(
        region="eu-west-3",
        pages_by_op={
            "describe_load_balancers": [{"LoadBalancers": [lb]}],
            "describe_listeners": [{"Listeners": [listener]}],
            "describe_target_groups": [{"TargetGroups": [tg]}],
        },
    )
    elbv2.set_target_health("tg-1", [{"TargetHealth": {"State": "healthy"}}])

    # CloudWatch queries will be m0; return zeros so p95 is 0.
    cw = FakeCloudWatch(by_id={"m0": [0.0] * 14})
    ctx = _mk_ctx(elbv2=elbv2, cloudwatch=cw, pricing=FakePricing())

    cfg = ElbV2LoadBalancersConfig(lookback_days=14, idle_p95_daily_requests_threshold=1.0)
    checker = ElbV2LoadBalancersChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.elbv2.load.balancers.idle"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "idle"


def test_no_registered_targets_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.elbv2_load_balancers as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    arn = _lb_arn("net/notargets/123")
    lb = {
        "LoadBalancerArn": arn,
        "LoadBalancerName": "notargets",
        "Type": "network",
        "Scheme": "internal",
        "CreatedTime": now - timedelta(days=10),
    }

    listener = {"ListenerArn": "lst-1", "DefaultActions": [{"Type": "forward", "TargetGroupArn": "tg-1"}]}
    tg = {"TargetGroupArn": "tg-1", "TargetType": "ip"}

    elbv2 = FakeElbv2(
        region="eu-west-3",
        pages_by_op={
            "describe_load_balancers": [{"LoadBalancers": [lb]}],
            "describe_listeners": [{"Listeners": [listener]}],
            "describe_target_groups": [{"TargetGroups": [tg]}],
        },
    )
    elbv2.set_target_health("tg-1", [])

    # Make sure idle does not trigger (set high values)
    cw = FakeCloudWatch(by_id={"m0": [1_000_000.0] * 14})
    ctx = _mk_ctx(elbv2=elbv2, cloudwatch=cw, pricing=FakePricing())

    cfg = ElbV2LoadBalancersConfig(idle_p95_daily_new_flows_threshold=0.0)
    checker = ElbV2LoadBalancersChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.elbv2.load.balancers.no.registered.targets"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "notargets"


def test_no_healthy_targets_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.elbv2_load_balancers as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    arn = _lb_arn("app/unhealthy/123")
    lb = {
        "LoadBalancerArn": arn,
        "LoadBalancerName": "unhealthy",
        "Type": "application",
        "Scheme": "internal",
        "CreatedTime": now - timedelta(days=10),
    }

    listener = {"ListenerArn": "lst-1", "DefaultActions": [{"Type": "forward", "TargetGroupArn": "tg-1"}]}
    tg = {"TargetGroupArn": "tg-1", "TargetType": "instance"}

    elbv2 = FakeElbv2(
        region="eu-west-3",
        pages_by_op={
            "describe_load_balancers": [{"LoadBalancers": [lb]}],
            "describe_listeners": [{"Listeners": [listener]}],
            "describe_target_groups": [{"TargetGroups": [tg]}],
        },
    )
    elbv2.set_target_health("tg-1", [{"TargetHealth": {"State": "unhealthy"}}])

    cw = FakeCloudWatch(by_id={"m0": [1_000_000.0] * 14})
    ctx = _mk_ctx(elbv2=elbv2, cloudwatch=cw, pricing=FakePricing())

    cfg = ElbV2LoadBalancersConfig(idle_p95_daily_requests_threshold=0.0)
    checker = ElbV2LoadBalancersChecker(account_id="123", billing_account_id="123", cfg=cfg)
    findings = list(checker.run(ctx))

    hits = [f for f in findings if f.check_id == "aws.elbv2.load.balancers.no.healthy.targets"]
    assert len(hits) == 1
    assert hits[0].scope.resource_id == "unhealthy"


def test_access_denied_emits_access_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import checks.aws.elbv2_load_balancers as mod

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    elbv2 = FakeElbv2AccessDenied(region="eu-west-3", pages_by_op={})
    ctx = _mk_ctx(elbv2=elbv2, cloudwatch=None, pricing=None)

    checker = ElbV2LoadBalancersChecker(account_id="123", billing_account_id="123")
    findings = list(checker.run(ctx))

    assert any(f.check_id == "aws.elbv2.load.balancers.access.error" for f in findings)
