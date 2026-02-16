"""
checks/aws/ec2_reserved_instances.py

EC2 Reserved Instance (RI) coverage and utilization checker.

Signals:
1) RI coverage gaps (running instances not covered by active RIs)
2) Low RI utilization (active RI commitments with low matching usage)

Design notes
------------
- Deterministic output: stable sorting by key and no randomization.
- Best-effort matching:
  - Match by (instance_type, platform, tenancy)
  - Apply AZ-scoped RIs first, then regional RIs
- Cost estimates use on-demand pricing as baseline with configurable factors.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from checks.aws._common import (
    AwsAccountContext,
    PricingResolver,
    build_scope,
    get_logger,
    money,
    safe_region_from_client,
)
from checks.aws.defaults import (
    EC2_MAX_FINDINGS_PER_TYPE,
    EC2_RI_MIN_COVERAGE_GAP_INSTANCES,
    EC2_RI_POTENTIAL_SAVINGS_DISCOUNT_FACTOR,
    EC2_RI_UNUSED_EFFECTIVE_COST_FACTOR,
    EC2_RI_UTILIZATION_LOW_THRESHOLD_PCT,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

_LOGGER = get_logger("ec2_reserved_instances")


@dataclass(frozen=True)
class EC2ReservedInstancesConfig:
    """Configuration knobs for RI coverage analyzer."""

    utilization_low_threshold_pct: float = EC2_RI_UTILIZATION_LOW_THRESHOLD_PCT
    min_coverage_gap_instances: int = EC2_RI_MIN_COVERAGE_GAP_INSTANCES
    potential_savings_discount_factor: float = EC2_RI_POTENTIAL_SAVINGS_DISCOUNT_FACTOR
    unused_effective_cost_factor: float = EC2_RI_UNUSED_EFFECTIVE_COST_FACTOR
    max_findings_per_type: int = EC2_MAX_FINDINGS_PER_TYPE


def _safe_int(value: Any, *, default: int = 0) -> int:
    """Best-effort integer conversion."""
    if isinstance(value, bool):
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _normalize_platform(value: Any) -> str:
    """Normalize platform labels from instance and RI payloads."""
    text = str(value or "").strip().lower()
    if not text:
        return "linux"
    if "windows" in text:
        return "windows"
    if "red hat" in text or "rhel" in text:
        return "rhel"
    if "suse" in text:
        return "suse"
    return "linux"


def _normalize_tenancy(value: Any) -> str:
    """Normalize tenancy labels to stable categories."""
    text = str(value or "").strip().lower()
    if text in {"dedicated", "host"}:
        return text
    return "default"


def _instance_monthly_cost(
    ctx: RunContext,
    *,
    region: str,
    instance_type: str,
) -> tuple[float | None, int, str]:
    """Resolve on-demand monthly cost for an EC2 instance type."""
    return PricingResolver(ctx).resolve_ec2_instance_monthly_cost(
        region=region,
        instance_type=instance_type,
        call_exceptions=(AttributeError, TypeError, ValueError, BotoCoreError, ClientError),
    )


class EC2ReservedInstancesChecker:
    """Analyze EC2 Reserved Instance coverage and utilization."""

    checker_id = "aws.ec2.reserved.instances"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: EC2ReservedInstancesConfig | None = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or EC2ReservedInstancesConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        ec2 = getattr(getattr(ctx, "services", None), "ec2", None)
        if ec2 is None:
            return []

        region = safe_region_from_client(ec2)
        try:
            instances = list(self._list_running_instances(ec2))
            reserved = list(self._list_active_reserved_instances(ec2))
        except (BotoCoreError, ClientError):
            return []

        if not instances and not reserved:
            return []

        # running counts by (instance_type, platform, tenancy, az)
        running_az: dict[tuple[str, str, str, str], int] = {}
        for ins in instances:
            itype = str(ins.get("InstanceType") or "").strip().lower()
            if not itype:
                continue
            platform = _normalize_platform(ins.get("PlatformDetails") or ins.get("Platform"))
            tenancy = _normalize_tenancy(((ins.get("Placement") or {}) if isinstance(ins, Mapping) else {}).get("Tenancy"))
            az = str(((ins.get("Placement") or {}) if isinstance(ins, Mapping) else {}).get("AvailabilityZone") or "").strip().lower()
            if not az:
                az = "unknown"
            key = (itype, platform, tenancy, az)
            running_az[key] = int(running_az.get(key, 0) + 1)

        # reserved counts split by AZ-scoped vs regional.
        reserved_az: dict[tuple[str, str, str, str], int] = {}
        reserved_regional: dict[tuple[str, str, str], int] = {}
        for ri in reserved:
            itype = str(ri.get("InstanceType") or "").strip().lower()
            if not itype:
                continue
            count = _safe_int(ri.get("InstanceCount"), default=0)
            if count <= 0:
                continue
            platform = _normalize_platform(ri.get("ProductDescription"))
            tenancy = _normalize_tenancy(ri.get("InstanceTenancy"))
            scope = str(ri.get("Scope") or "").strip().lower()
            az = str(ri.get("AvailabilityZone") or "").strip().lower()
            if "availability" in scope and az:
                az_key = (itype, platform, tenancy, az)
                reserved_az[az_key] = int(reserved_az.get(az_key, 0) + count)
            else:
                base_key = (itype, platform, tenancy)
                reserved_regional[base_key] = int(reserved_regional.get(base_key, 0) + count)

        if not running_az and not reserved_az and not reserved_regional:
            return []

        running_remaining = dict(running_az)
        used_reserved_by_base: dict[tuple[str, str, str], int] = {}

        # Apply AZ-scoped reservations first.
        for key_az in sorted(reserved_az):
            reserved_count = int(reserved_az.get(key_az, 0))
            running_count = int(running_remaining.get(key_az, 0))
            if reserved_count <= 0 or running_count <= 0:
                continue
            covered = min(reserved_count, running_count)
            running_remaining[key_az] = int(running_count - covered)
            base = key_az[:3]
            used_reserved_by_base[base] = int(used_reserved_by_base.get(base, 0) + covered)

        # Then apply regional reservations to remaining running usage.
        running_az_keys = sorted(running_remaining)
        bases: set[tuple[str, str, str]] = {k[:3] for k in running_az_keys}
        bases.update(reserved_regional.keys())
        bases.update(k[:3] for k in reserved_az)

        for base in sorted(bases):
            regional_reserved = int(reserved_regional.get(base, 0))
            if regional_reserved <= 0:
                continue
            keys_for_base = [k for k in running_az_keys if k[:3] == base]
            remaining_running = sum(int(running_remaining.get(k, 0)) for k in keys_for_base)
            if remaining_running <= 0:
                continue
            covered = min(remaining_running, regional_reserved)
            used_reserved_by_base[base] = int(used_reserved_by_base.get(base, 0) + covered)
            remaining_to_allocate = covered
            for key_az in keys_for_base:
                if remaining_to_allocate <= 0:
                    break
                current = int(running_remaining.get(key_az, 0))
                if current <= 0:
                    continue
                used_here = min(current, remaining_to_allocate)
                running_remaining[key_az] = int(current - used_here)
                remaining_to_allocate -= used_here

        running_by_base: dict[tuple[str, str, str], int] = {}
        for key_az, count in running_az.items():
            base = key_az[:3]
            running_by_base[base] = int(running_by_base.get(base, 0) + int(count))

        reserved_az_by_base: dict[tuple[str, str, str], int] = {}
        for key_az, count in reserved_az.items():
            base = key_az[:3]
            reserved_az_by_base[base] = int(reserved_az_by_base.get(base, 0) + int(count))

        on_demand_cost_cache: dict[str, tuple[float | None, int, str]] = {}

        def _cost_for(instance_type: str) -> tuple[float | None, int, str]:
            cached = on_demand_cost_cache.get(instance_type)
            if cached is not None:
                return cached
            resolved = _instance_monthly_cost(ctx, region=region, instance_type=instance_type)
            on_demand_cost_cache[instance_type] = resolved
            return resolved

        findings: list[FindingDraft] = []
        cfg = self._cfg

        for base in sorted(bases):
            instance_type, platform, tenancy = base
            running_count = int(running_by_base.get(base, 0))
            reserved_count = int(reserved_az_by_base.get(base, 0) + reserved_regional.get(base, 0))
            used_reserved = int(used_reserved_by_base.get(base, 0))

            if running_count <= 0 and reserved_count <= 0:
                continue

            uncovered = max(0, running_count - used_reserved)
            unused = max(0, reserved_count - used_reserved)
            coverage_pct = (100.0 * float(used_reserved) / float(running_count)) if running_count > 0 else 100.0
            utilization_pct = (100.0 * float(used_reserved) / float(reserved_count)) if reserved_count > 0 else 100.0

            monthly_on_demand, pricing_conf, pricing_notes = _cost_for(instance_type)
            coverage_gap_cost = None
            potential_savings = None
            unused_commitment_cost = None

            if monthly_on_demand is not None and monthly_on_demand > 0.0:
                if uncovered > 0:
                    coverage_gap_cost = money(float(uncovered) * monthly_on_demand)
                    potential_savings = money(coverage_gap_cost * float(cfg.potential_savings_discount_factor))
                if unused > 0:
                    unused_commitment_cost = money(
                        float(unused) * monthly_on_demand * float(cfg.unused_effective_cost_factor)
                    )

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="reserved-instance-class",
                resource_id=f"{instance_type}:{platform}:{tenancy}",
            )

            if uncovered >= int(max(1, cfg.min_coverage_gap_instances)):
                findings.append(
                    FindingDraft(
                        check_id="aws.ec2.ri.coverage.gap",
                        check_name="EC2 Reserved Instance coverage gap",
                        category="cost",
                        sub_category="commitments",
                        status="fail",
                        severity=Severity(level="high" if uncovered >= 5 else "medium", score=(700 if uncovered >= 5 else 560)),
                        title=(
                            f"Reserved Instance coverage gap for {instance_type} "
                            f"({platform}, {tenancy})"
                        ),
                        scope=scope,
                        message=(
                            f"Running={running_count}, active RI={reserved_count}, covered={used_reserved}, "
                            f"uncovered={uncovered} ({coverage_pct:.1f}% coverage)."
                        ),
                        recommendation=(
                            f"Increase RI coverage for {instance_type} by ~{uncovered} instance(s) after validating "
                            "steady-state usage and commitment term flexibility."
                        ),
                        estimated_monthly_cost=coverage_gap_cost,
                        estimated_monthly_savings=potential_savings,
                        estimate_confidence=int(min(80, max(30, pricing_conf))),
                        estimate_notes=(
                            f"Coverage gap estimated with on-demand baseline; potential savings assumes ~"
                            f"{cfg.potential_savings_discount_factor * 100:.0f}% RI discount. {pricing_notes}"
                        ),
                        dimensions={
                            "instance_type": instance_type,
                            "platform": platform,
                            "tenancy": tenancy,
                            "running_count": str(running_count),
                            "reserved_count": str(reserved_count),
                            "covered_count": str(used_reserved),
                            "uncovered_count": str(uncovered),
                            "coverage_pct": f"{coverage_pct:.2f}",
                            "target_coverage_pct": "90.00",
                        },
                        issue_key={
                            "instance_type": instance_type,
                            "platform": platform,
                            "tenancy": tenancy,
                            "signal": "ri_coverage_gap",
                        },
                    )
                )

            if reserved_count > 0 and unused > 0 and utilization_pct < float(cfg.utilization_low_threshold_pct):
                findings.append(
                    FindingDraft(
                        check_id="aws.ec2.ri.utilization.low",
                        check_name="EC2 Reserved Instance utilization low",
                        category="cost",
                        sub_category="commitments",
                        status="fail",
                        severity=Severity(level=("high" if utilization_pct < 50.0 else "medium"), score=(680 if utilization_pct < 50.0 else 540)),
                        title=(
                            f"Reserved Instance utilization low for {instance_type} "
                            f"({platform}, {tenancy})"
                        ),
                        scope=scope,
                        message=(
                            f"Active RI={reserved_count}, covered={used_reserved}, unused={unused} "
                            f"({utilization_pct:.1f}% utilization)."
                        ),
                        recommendation=(
                            "Review RI commitments for this class: consider modifications/exchanges, "
                            "workload rebalancing, or marketplace listing (where applicable)."
                        ),
                        estimated_monthly_cost=unused_commitment_cost,
                        estimated_monthly_savings=None,
                        estimate_confidence=int(min(75, max(25, pricing_conf))),
                        estimate_notes=(
                            f"Unused commitment cost approximated at ~{cfg.unused_effective_cost_factor * 100:.0f}% "
                            f"of on-demand baseline for unused reserved units. {pricing_notes}"
                        ),
                        dimensions={
                            "instance_type": instance_type,
                            "platform": platform,
                            "tenancy": tenancy,
                            "running_count": str(running_count),
                            "reserved_count": str(reserved_count),
                            "covered_count": str(used_reserved),
                            "unused_count": str(unused),
                            "utilization_pct": f"{utilization_pct:.2f}",
                            "target_utilization_pct": f"{cfg.utilization_low_threshold_pct:.2f}",
                        },
                        issue_key={
                            "instance_type": instance_type,
                            "platform": platform,
                            "tenancy": tenancy,
                            "signal": "ri_utilization_low",
                        },
                    )
                )

            if len(findings) >= int(cfg.max_findings_per_type):
                break

        return findings

    def _list_running_instances(self, ec2: Any) -> Iterator[Mapping[str, Any]]:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
        ):
            reservations = page.get("Reservations", []) if isinstance(page, Mapping) else []
            for reservation in reservations or []:
                instances = (reservation or {}).get("Instances", []) if isinstance(reservation, Mapping) else []
                for ins in instances or []:
                    if isinstance(ins, Mapping):
                        yield ins

    def _list_active_reserved_instances(self, ec2: Any) -> Iterator[Mapping[str, Any]]:
        paginator = ec2.get_paginator("describe_reserved_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "state", "Values": ["active", "payment-pending"]}],
        ):
            rows = page.get("ReservedInstances", []) if isinstance(page, Mapping) else []
            for row in rows or []:
                if isinstance(row, Mapping):
                    yield row


SPEC = "checks.aws.ec2_reserved_instances:EC2ReservedInstancesChecker"


@register_checker(SPEC)
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    """Instantiate RI checker from runtime bootstrap data."""
    _ = ctx
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for EC2ReservedInstancesChecker)")
    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    return EC2ReservedInstancesChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
    )
