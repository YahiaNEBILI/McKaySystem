"""Unit tests for the EC2 Savings Plans checker."""

from __future__ import annotations

from typing import Any

import pytest

from checks.aws.ec2_savings_plans import EC2SavingsPlansChecker
from tests.aws_mocks import (
    FakePaginatedAwsClient,
    FakePricingByField,
    FakeSavingsPlansClient,
    make_run_ctx,
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

    ec2 = FakePaginatedAwsClient(
        region="eu-west-3",
        pages_by_op={
            "describe_instances": [
                {"Reservations": [{"Instances": [_running_instance("i-1", "m5.large"), _running_instance("i-2", "m5.large")]}]}
            ]
        },
    )
    sp = FakeSavingsPlansClient(pages=[{"savingsPlans": []}])
    pricing = FakePricingByField({"m5.large": 0.10}, field_name="instanceType")

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(make_run_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    hits = [f for f in findings if f.check_id == "aws.ec2.savings.plans.coverage.gap"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(146.0, rel=1e-6)
    assert float(f.estimated_monthly_savings or 0.0) == pytest.approx(36.5, rel=1e-6)
    assert "$0.2000/hr" in f.recommendation
    assert (f.dimensions or {}).get("coverage_pct") == "0.00"


def test_savings_plans_utilization_low_emits() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakePaginatedAwsClient(
        region="eu-west-3",
        pages_by_op={"describe_instances": [{"Reservations": [{"Instances": [_running_instance("i-1", "m5.large")]}]}]},
    )
    sp = FakeSavingsPlansClient(
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
    pricing = FakePricingByField({"m5.large": 0.10}, field_name="instanceType")

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(make_run_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    hits = [f for f in findings if f.check_id == "aws.ec2.savings.plans.utilization.low"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(657.0, rel=1e-6)
    assert (f.dimensions or {}).get("unused_usd_per_hour") == "0.9000"
    assert (f.dimensions or {}).get("utilization_pct") == "10.00"


def test_savings_plans_malformed_commitment_is_tolerated() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakePaginatedAwsClient(
        region="eu-west-3",
        pages_by_op={"describe_instances": [{"Reservations": [{"Instances": [_running_instance("i-1", "m5.large")]}]}]},
    )
    sp = FakeSavingsPlansClient(
        pages=[{"savingsPlans": [{"savingsPlanType": "Compute", "commitment": "oops", "state": "active"}]}]
    )
    pricing = FakePricingByField({"m5.large": 0.10}, field_name="instanceType")

    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(make_run_ctx(ec2=ec2, savingsplans=sp, pricing=pricing)))
    assert any(f.check_id == "aws.ec2.savings.plans.coverage.gap" for f in findings)


def test_savings_plans_missing_client_returns_empty() -> None:
    import checks.aws.ec2_savings_plans as mod

    ec2 = FakePaginatedAwsClient(region="eu-west-3", pages_by_op={"describe_instances": [{"Reservations": [{"Instances": []}]}]})
    checker = EC2SavingsPlansChecker(
        account=mod.AwsAccountContext(account_id="123", billing_account_id="123"),
    )
    findings = list(checker.run(make_run_ctx(ec2=ec2, savingsplans=None, pricing=None)))
    assert findings == []
