"""Unit tests for the EC2 Savings Plans checker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import SimpleNamespace
from typing import Any, cast

import pytest

from checks.aws.ec2_savings_plans import EC2SavingsPlansChecker
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEC2:
    """Minimal EC2 fake for Savings Plans checker tests."""

    def __init__(self, *, region: str, pages_by_op: dict[str, list[Mapping[str, Any]]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeEC2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)


class FakeSavingsPlans:
    """Savings Plans API fake using deterministic paged responses."""

    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def describe_savings_plans(self, **kwargs: Any) -> Mapping[str, Any]:
        _ = kwargs.get("states")
        token = str(kwargs.get("nextToken") or "")
        idx = int(token) if token else 0
        if idx >= len(self._pages):
            return {"savingsPlans": []}
        payload = dict(self._pages[idx])
        if idx + 1 < len(self._pages):
            payload["nextToken"] = str(idx + 1)
        return payload


class FakePriceQuote:
    def __init__(self, unit_price: float) -> None:
        self.unit_price = unit_price


class FakePricingByType:
    """Pricing fake returning deterministic hourly prices by instance type."""

    def __init__(self, hourly_by_instance_type: dict[str, float]) -> None:
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


def _mk_ctx(*, ec2: FakeEC2, savingsplans: Any | None, pricing: Any | None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(ec2=ec2, savingsplans=savingsplans, pricing=pricing),
        ),
    )


def _running_instance(instance_id: str, instance_type: str) -> dict[str, Any]:
    return {
        "InstanceId": instance_id,
        "InstanceType": instance_type,
        "State": {"Name": "running"},
        "Placement": {"AvailabilityZone": "eu-west-3a"},
    }


def test_savings_plans_coverage_gap_emits() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {"Reservations": [{"Instances": [_running_instance("i-1", "m5.large"), _running_instance("i-2", "m5.large")]}]}
            ]
        },
    )
    sp = FakeSavingsPlans(pages=[{"savingsPlans": []}])
    pricing = FakePricingByType({"m5.large": 0.10})

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(_mk_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    hits = [f for f in findings if f.check_id == "aws.ec2.savings.plans.coverage.gap"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(146.0, rel=1e-6)
    assert float(f.estimated_monthly_savings or 0.0) == pytest.approx(36.5, rel=1e-6)
    assert "$0.2000/hr" in f.recommendation
    assert (f.dimensions or {}).get("coverage_pct") == "0.00"


def test_savings_plans_utilization_low_emits() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={"describe_instances": [{"Reservations": [{"Instances": [_running_instance("i-1", "m5.large")]}]}]},
    )
    sp = FakeSavingsPlans(
        pages=[
            {
                "savingsPlans": [
                    {
                        "savingsPlanArn": "arn:aws:savingsplans:us-east-1:123:savingsplan/sp-1",
                        "savingsPlanType": "Compute",
                        "commitment": "1.0",
                        "state": "active",
                    }
                ]
            }
        ]
    )
    pricing = FakePricingByType({"m5.large": 0.10})

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(_mk_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    hits = [f for f in findings if f.check_id == "aws.ec2.savings.plans.utilization.low"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(657.0, rel=1e-6)
    assert (f.dimensions or {}).get("unused_usd_per_hour") == "0.9000"
    assert (f.dimensions or {}).get("utilization_pct") == "10.00"


def test_savings_plans_malformed_commitment_is_tolerated() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={"describe_instances": [{"Reservations": [{"Instances": [_running_instance("i-1", "m5.large")]}]}]},
    )
    sp = FakeSavingsPlans(
        pages=[{"savingsPlans": [{"savingsPlanType": "Compute", "commitment": "oops", "state": "active"}]}]
    )
    pricing = FakePricingByType({"m5.large": 0.10})

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(_mk_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    assert any(f.check_id == "aws.ec2.savings.plans.coverage.gap" for f in findings)


def test_savings_plans_missing_client_returns_empty() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakeEC2(region="eu-west-3", pages_by_op={"describe_instances": [{"Reservations": [{"Instances": []}]}]})
    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(_mk_ctx(ec2=ec2, savingsplans=None, pricing=None)))
    assert findings == []

