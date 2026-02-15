"""Unit tests for the EC2 Reserved Instances checker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import SimpleNamespace
from typing import Any, cast

import pytest

from checks.aws.ec2_reserved_instances import EC2ReservedInstancesChecker
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class FakeEC2:
    """Minimal EC2 fake for RI checker tests."""

    def __init__(self, *, region: str, pages_by_op: dict[str, list[Mapping[str, Any]]]) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = pages_by_op

    def get_paginator(self, op_name: str) -> FakePaginator:
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakeEC2 has no paginator pages configured for {op_name}")
        return FakePaginator(pages)


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


def _mk_ctx(*, ec2: FakeEC2, pricing: Any | None = None) -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(ec2=ec2, pricing=pricing),
        ),
    )


def test_ri_coverage_gap_emits() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-a",
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3a"},
                                },
                                {
                                    "InstanceId": "i-b",
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3b"},
                                },
                                {
                                    "InstanceId": "i-c",
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3b"},
                                },
                            ]
                        }
                    ]
                }
            ],
            "describe_reserved_instances": [
                {
                    "ReservedInstances": [
                        {
                            "ReservedInstancesId": "ri-1",
                            "InstanceType": "m5.large",
                            "InstanceCount": 1,
                            "ProductDescription": "Linux/UNIX",
                            "InstanceTenancy": "default",
                            "Scope": "Region",
                            "State": "active",
                        }
                    ]
                }
            ],
        },
    )

    checker = EC2ReservedInstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    ctx = _mk_ctx(ec2=ec2, pricing=FakePricingByType({"m5.large": 0.10}))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.ri.coverage.gap"]
    assert len(hits) == 1
    f = hits[0]
    assert "Increase RI coverage for m5.large by ~2 instance(s)" in f.recommendation
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(146.0, rel=1e-6)
    assert float(f.estimated_monthly_savings or 0.0) == pytest.approx(43.8, rel=1e-6)
    assert (f.dimensions or {}).get("uncovered_count") == "2"


def test_ri_utilization_low_emits() -> None:
    import checks.aws.ec2_reserved_instances as mod

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
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3a"},
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_reserved_instances": [
                {
                    "ReservedInstances": [
                        {
                            "ReservedInstancesId": "ri-1",
                            "InstanceType": "m5.large",
                            "InstanceCount": 3,
                            "ProductDescription": "Linux/UNIX",
                            "InstanceTenancy": "default",
                            "Scope": "Region",
                            "State": "active",
                        }
                    ]
                }
            ],
        },
    )

    checker = EC2ReservedInstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    ctx = _mk_ctx(ec2=ec2, pricing=FakePricingByType({"m5.large": 0.10}))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.ri.utilization.low"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(102.2, rel=1e-6)
    assert (f.dimensions or {}).get("unused_count") == "2"
    assert (f.dimensions or {}).get("utilization_pct") == "33.33"


def test_ri_az_scope_is_applied_before_regional() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-a",
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3a"},
                                },
                                {
                                    "InstanceId": "i-b",
                                    "InstanceType": "m5.large",
                                    "PlatformDetails": "Linux/UNIX",
                                    "State": {"Name": "running"},
                                    "Placement": {"Tenancy": "default", "AvailabilityZone": "eu-west-3b"},
                                },
                            ]
                        }
                    ]
                }
            ],
            "describe_reserved_instances": [
                {
                    "ReservedInstances": [
                        {
                            "ReservedInstancesId": "ri-az",
                            "InstanceType": "m5.large",
                            "InstanceCount": 1,
                            "ProductDescription": "Linux/UNIX",
                            "InstanceTenancy": "default",
                            "Scope": "Availability Zone",
                            "AvailabilityZone": "eu-west-3a",
                            "State": "active",
                        }
                    ]
                }
            ],
        },
    )

    checker = EC2ReservedInstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    ctx = _mk_ctx(ec2=ec2, pricing=FakePricingByType({"m5.large": 0.10}))
    findings = list(checker.run(ctx))
    gap = next(f for f in findings if f.check_id == "aws.ec2.ri.coverage.gap")
    assert (gap.dimensions or {}).get("uncovered_count") == "1"


def test_ri_malformed_payload_is_ignored() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [{"Reservations": [{"Instances": []}]}],
            "describe_reserved_instances": [
                {
                    "ReservedInstances": [
                        {
                            "ReservedInstancesId": "ri-bad",
                            "InstanceType": "m5.large",
                            "InstanceCount": "not-a-number",
                            "ProductDescription": "Linux/UNIX",
                            "InstanceTenancy": "default",
                            "Scope": "Region",
                            "State": "active",
                        }
                    ]
                }
            ],
        },
    )

    checker = EC2ReservedInstancesChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(_mk_ctx(ec2=ec2, pricing=FakePricingByType({"m5.large": 0.10}))))
    assert findings == []
