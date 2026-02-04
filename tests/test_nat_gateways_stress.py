# tests/stress/test_nat_gateways_stress.py

import time
import random
import tracemalloc
from datetime import datetime, timedelta, timezone

import pytest

from checks.aws.nat_gateways import NatGatewaysChecker, NatGatewaysConfig
from contracts.finops_checker_pattern import RunContext
from types import SimpleNamespace

from test_nat_gateways import FakeEC2, FakeCloudWatch, FakePricing, _mk_ctx


pytestmark = pytest.mark.stress


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_nat(i, now):
    """Generate a NAT with realistic fields."""
    return {
        "NatGatewayId": f"nat-{i}",
        "State": "available",
        "VpcId": f"vpc-{i % 20}",
        "SubnetId": f"subnet-{i}",
        "CreateTime": now - timedelta(days=10),
        "Tags": [],
    }


def make_route_table(i):
    """Private subnet route table pointing to NAT i."""
    return {
        "RouteTableId": f"rtb-{i}",
        "Associations": [{"SubnetId": f"subnet-{i}"}],
        "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": f"nat-{i}"}
        ],
    }


def make_subnet(i):
    """Alternate subnets across 3 AZs."""
    az_letter = chr(97 + (i % 3))  # a, b, c
    return {
        "SubnetId": f"subnet-{i}",
        "AvailabilityZone": f"eu-west-3{az_letter}",
    }


# ---------------------------------------------------------------------------
# Actual stress tests
# ---------------------------------------------------------------------------

def test_stress_2000_nat_gateways(monkeypatch: pytest.MonkeyPatch):
    """
    Stress test: 2000 NAT gateways, 2000 route tables, realistic subnets.
    Validates performance, memory footprint, and absence of errors.
    """

    # Fix timestamp for determinism
    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)

    # Monkeypatch now_utc
    import checks.aws.nat_gateways as mod
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    # Generate the dataset
    N = 2000

    nat_pages = [{"NatGateways": [make_nat(i, now)]} for i in range(N)]
    rt_pages = [{"RouteTables": [make_route_table(i)]} for i in range(N)]

    subnets = {f"subnet-{i}": make_subnet(i) for i in range(N)}

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": nat_pages,
            "describe_route_tables": rt_pages,
        },
        subnets=subnets,
    )

    # Force first 50 NATs to have extremely low traffic → trigger idle
    out_metrics = {}
    in_metrics = {}

    for i in range(N):
        if i < 50:
            # p95 = 0 → always idle
            out_metrics[f"m{i}"] = [0] * 30
            in_metrics[f"m{i}"]  = [0] * 30
        else:
            # random values for general stress
            out_metrics[f"m{i}"] = [random.randint(0, 2_000_000) for _ in range(30)]
            in_metrics[f"m{i}"]  = [random.randint(0, 2_000_000) for _ in range(30)]

    cw = FakeCloudWatch(out_by_id=out_metrics, in_by_id=in_metrics)

    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    cfg = NatGatewaysConfig(
        lookback_days=14,
        min_daily_datapoints=7,
        idle_p95_daily_bytes_threshold=1_000,
        high_data_processing_gib_month_threshold=5,
    )

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123", cfg=cfg)

    # ---------------------------------------------
    # Time measurement
    # ---------------------------------------------
    start = time.time()
    findings = list(checker.run(ctx))
    elapsed = time.time() - start

    print(f"\n[STRESS] Processed {N} NAT gateways in {elapsed:.2f}s "
          f"({N/elapsed:.1f} NAT/s)")

    # Should complete quickly (your implementation is very efficient)
    assert elapsed < 8.0, "Stress test exceeded time budget"

    # ---------------------------------------------
    # Memory footprint measurement
    # ---------------------------------------------
    tracemalloc.start()
    _ = list(checker.run(ctx))
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"[STRESS] Peak memory: {peak/1_000_000:.1f} MB")

    # Should remain well under 200MB even under large loads
    assert peak < 200_000_000

    # ---------------------------------------------
    # Basic correctness checks
    # ---------------------------------------------

    # All NATs are referenced → no orphan findings
    assert not any(f.check_id.endswith("orphaned") for f in findings)

    # Verify some high_data or idle findings appear (depends on random values)
    has_metrics_findings = any(
        f.check_id.endswith("high_data_processing") or
        f.check_id.endswith("idle")
        for f in findings
    )
    assert has_metrics_findings, "Expected at least some metric-based findings"


def test_cloudwatch_batching_correctness(monkeypatch: pytest.MonkeyPatch):
    """
    Ensures batching logic works correctly when >1000 NATs require multiple
    GetMetricData calls.
    """

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    import checks.aws.nat_gateways as mod
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    N = 1200

    # NATs and route tables
    nat_pages = [{"NatGateways": [make_nat(i, now)]} for i in range(N)]
    rt_pages = [{"RouteTables": [make_route_table(i)]} for i in range(N)]
    subnets = {f"subnet-{i}": make_subnet(i) for i in range(N)}

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": nat_pages,
            "describe_route_tables": rt_pages,
        },
        subnets=subnets,
    )

    # Track number of calls
    class CountingCW(FakeCloudWatch):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.calls = 0

        def get_metric_data(self, *args, **kwargs):
            self.calls += 1
            return super().get_metric_data(*args, **kwargs)

    out_metrics = {f"m{i}": [1.0] * 14 for i in range(N)}
    in_metrics = {f"m{i}": [1.0] * 14 for i in range(N)}

    cw = CountingCW(out_by_id=out_metrics, in_by_id=in_metrics)
    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")

    findings = list(checker.run(ctx))

    # Your checker uses batch_size=100 → for 1200 NATs, 12 batches per metric.
    # Each metric_name ("BytesOutToDestination" and "BytesInFromDestination")
    # is fetched separately.
    expected_calls = (N // 100) * 2
    if N % 100 != 0:
        expected_calls += 2  # final partial batches

    assert cw.calls == expected_calls, (
        f"Expected {expected_calls} CloudWatch calls, got {cw.calls}"
    )

    print(f"[STRESS] CloudWatch batching OK ({cw.calls} calls).")


def test_extreme_randomized(monkeypatch: pytest.MonkeyPatch):
    """
    Hypothesis-like randomized stress: randomized NAT subnet AZs,
    randomized traffic bursts, randomized routing correctness.
    Validates checker stability under unexpected patterns.
    """

    now = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    import checks.aws.nat_gateways as mod
    monkeypatch.setattr(mod, "now_utc", lambda: now)

    N = 1000

    def random_az():
        return f"eu-west-3{random.choice('abc')}"

    # NATs
    nat_pages = [{"NatGateways": [make_nat(i, now)]} for i in range(N)]

    # Random route correctness
    def random_rt(i):
        if random.random() < 0.2:
            # 20% cross-AZ incorrect route
            return {
                "RouteTableId": f"rtb-{i}",
                "Associations": [{"SubnetId": f"subnet-{i}-wrong"}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": f"nat-{i}"}],
            }
        else:
            # Correct route
            return make_route_table(i)

    rt_pages = [{"RouteTables": [random_rt(i)]} for i in range(N)]

    # Random subnets
    subnets = {
        f"subnet-{i}": {"SubnetId": f"subnet-{i}", "AvailabilityZone": random_az()}
        for i in range(N)
    }
    subnets.update({
        f"subnet-{i}-wrong": {"SubnetId": f"subnet-{i}-wrong", "AvailabilityZone": random_az()}
        for i in range(N)
    })

    ec2 = FakeEC2(
        region="eu-west-3",
        pages_by_op={
            "describe_nat_gateways": nat_pages,
            "describe_route_tables": rt_pages,
        },
        subnets=subnets,
    )

    # Random metric patterns
    out_metrics = {
        f"m{i}": [random.randint(0, 5_000_000) for _ in range(random.randint(5, 30))]
        for i in range(N)
    }
    in_metrics = {
        f"m{i}": [random.randint(0, 5_000_000) for _ in range(random.randint(5, 30))]
        for i in range(N)
    }

    cw = FakeCloudWatch(out_by_id=out_metrics, in_by_id=in_metrics)

    ctx = _mk_ctx(ec2=ec2, cloudwatch=cw, pricing=FakePricing())

    checker = NatGatewaysChecker(account_id="123", billing_account_id="123")

    # Should not raise exceptions regardless of random patterns
    findings = list(checker.run(ctx))

    assert isinstance(findings, list)
    assert all(hasattr(f, "check_id") for f in findings)

    print(f"[STRESS] Randomized test produced {len(findings)} findings.")