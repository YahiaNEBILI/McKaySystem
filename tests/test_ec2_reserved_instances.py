"""Unit tests for the EC2 Reserved Instances checker."""

from __future__ import annotations

import pytest

from checks.aws.ec2_reserved_instances import EC2ReservedInstancesChecker
from tests.aws_mocks import FakePaginatedAwsClient, FakePricingByField, make_run_ctx


def test_ri_coverage_gap_emits() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakePaginatedAwsClient(
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
    ctx = make_run_ctx(ec2=ec2, pricing=FakePricingByField({"m5.large": 0.10}, field_name="instanceType"))
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

    ec2 = FakePaginatedAwsClient(
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
    ctx = make_run_ctx(ec2=ec2, pricing=FakePricingByField({"m5.large": 0.10}, field_name="instanceType"))
    findings = list(checker.run(ctx))
    hits = [f for f in findings if f.check_id == "aws.ec2.ri.utilization.low"]
    assert len(hits) == 1
    f = hits[0]
    assert float(f.estimated_monthly_cost or 0.0) == pytest.approx(102.2, rel=1e-6)
    assert (f.dimensions or {}).get("unused_count") == "2"
    assert (f.dimensions or {}).get("utilization_pct") == "33.33"


def test_ri_az_scope_is_applied_before_regional() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakePaginatedAwsClient(
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
    ctx = make_run_ctx(ec2=ec2, pricing=FakePricingByField({"m5.large": 0.10}, field_name="instanceType"))
    findings = list(checker.run(ctx))
    gap = next(f for f in findings if f.check_id == "aws.ec2.ri.coverage.gap")
    assert (gap.dimensions or {}).get("uncovered_count") == "1"


def test_ri_malformed_payload_is_ignored() -> None:
    import checks.aws.ec2_reserved_instances as mod

    ec2 = FakePaginatedAwsClient(
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
    findings = list(
        checker.run(make_run_ctx(ec2=ec2, pricing=FakePricingByField({"m5.large": 0.10}, field_name="instanceType")))
    )
    assert findings == []
