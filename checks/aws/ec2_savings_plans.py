"""
checks/aws/ec2_savings_plans.py

EC2 Savings Plans recommendation checker.

Signals:
1) Savings Plan coverage gap (estimated EC2 on-demand demand exceeds active commitment)
2) Savings Plan utilization low (active commitment appears underused)
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
    EC2_SP_LOW_UTILIZATION_THRESHOLD_PCT,
    EC2_SP_MIN_COVERAGE_GAP_USD_PER_HOUR,
    EC2_SP_POTENTIAL_SAVINGS_DISCOUNT_FACTOR,
    EC2_SP_UNUSED_COMMITMENT_COST_FACTOR,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

_LOGGER = get_logger("ec2_savings_plans")


@dataclass(frozen=True)
class EC2SavingsPlansConfig:
    """Configuration knobs for EC2 Savings Plans recommendations."""

    low_utilization_threshold_pct: float = EC2_SP_LOW_UTILIZATION_THRESHOLD_PCT
    min_coverage_gap_usd_per_hour: float = EC2_SP_MIN_COVERAGE_GAP_USD_PER_HOUR
    potential_savings_discount_factor: float = EC2_SP_POTENTIAL_SAVINGS_DISCOUNT_FACTOR
    unused_commitment_cost_factor: float = EC2_SP_UNUSED_COMMITMENT_COST_FACTOR
    max_findings_per_type: int = EC2_MAX_FINDINGS_PER_TYPE


def _safe_float(value: Any) -> float | None:
    """Best-effort float conversion."""
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _estimate_instance_monthly_cost_usd(
    ctx: RunContext,
    *,
    region: str,
    instance_type: str,
) -> tuple[float | None, int, str]:
    """Best-effort on-demand monthly EC2 instance cost estimate."""
    return PricingResolver(ctx).resolve_ec2_instance_monthly_cost(
        region=region,
        instance_type=instance_type,
        call_exceptions=(AttributeError, TypeError, ValueError, BotoCoreError, ClientError),
    )


def _round_hourly(value: float) -> float:
    """Round hourly monetary values to 4 decimals for stable payload rendering."""
    return round(float(value), 4)


class EC2SavingsPlansChecker:
    """Detect EC2 Savings Plan coverage/utilization opportunities."""

    checker_id = "aws.ec2.savings.plans"
    is_regional = False

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: EC2SavingsPlansConfig | None = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or EC2SavingsPlansConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        ec2 = getattr(getattr(ctx, "services", None), "ec2", None)
        savingsplans = getattr(getattr(ctx, "services", None), "savingsplans", None)
        if ec2 is None or savingsplans is None:
            return []

        region = safe_region_from_client(ec2)
        try:
            instances = list(self._list_running_instances(ec2))
            plans = list(self._list_active_savings_plans(savingsplans))
        except (BotoCoreError, ClientError):
            return []

        if not instances and not plans:
            return []

        type_counts: dict[str, int] = {}
        price_cache: dict[str, tuple[float | None, int, str]] = {}
        demand_hourly = 0.0
        pricing_conf_values: list[int] = []
        pricing_notes: list[str] = []

        for ins in instances:
            instance_type = str(ins.get("InstanceType") or "").strip().lower()
            if not instance_type:
                continue
            type_counts[instance_type] = int(type_counts.get(instance_type, 0) + 1)
            cached = price_cache.get(instance_type)
            if cached is None:
                cached = _estimate_instance_monthly_cost_usd(ctx, region=region, instance_type=instance_type)
                price_cache[instance_type] = cached
            monthly_cost, confidence, notes = cached
            pricing_conf_values.append(int(confidence))
            if notes and notes not in pricing_notes:
                pricing_notes.append(notes)
            if monthly_cost is not None and monthly_cost > 0.0:
                demand_hourly += float(monthly_cost) / 730.0

        demand_hourly = _round_hourly(demand_hourly)

        commitment_hourly = 0.0
        plan_types: dict[str, int] = {}
        for plan in plans:
            plan_type = str(plan.get("savingsPlanType") or "").strip()
            plan_types[plan_type] = int(plan_types.get(plan_type, 0) + 1)
            commitment = _safe_float(plan.get("commitment"))
            if commitment is None or commitment <= 0.0:
                continue
            commitment_hourly += commitment
        commitment_hourly = _round_hourly(commitment_hourly)

        if demand_hourly <= 0.0 and commitment_hourly <= 0.0:
            return []

        total_running = int(sum(type_counts.values()))
        top_types = sorted(type_counts.items(), key=lambda item: (-int(item[1]), item[0]))
        top_types_str = ",".join(f"{itype}:{count}" for itype, count in top_types[:5])
        pricing_conf = int(round(sum(pricing_conf_values) / max(1, len(pricing_conf_values))))
        pricing_note = "; ".join(pricing_notes[:3])
        cfg = self._cfg
        findings: list[FindingDraft] = []

        covered_hourly = min(demand_hourly, commitment_hourly)
        uncovered_hourly = max(0.0, demand_hourly - commitment_hourly)
        unused_hourly = max(0.0, commitment_hourly - demand_hourly)
        coverage_pct = (100.0 * covered_hourly / demand_hourly) if demand_hourly > 0.0 else 100.0
        utilization_pct = (100.0 * covered_hourly / commitment_hourly) if commitment_hourly > 0.0 else 100.0

        scope = build_scope(
            ctx,
            account=self._account,
            region=region,
            service="ec2",
            resource_type="savings-plan-portfolio",
            resource_id="ec2-savings-plans",
        )

        if uncovered_hourly >= float(cfg.min_coverage_gap_usd_per_hour):
            monthly_uncovered_cost = money(uncovered_hourly * 730.0)
            potential_monthly_savings = money(
                monthly_uncovered_cost * float(cfg.potential_savings_discount_factor)
            )
            findings.append(
                FindingDraft(
                    check_id="aws.ec2.savings.plans.coverage.gap",
                    check_name="EC2 Savings Plan coverage gap",
                    category="cost",
                    sub_category="commitments",
                    status="fail",
                    severity=Severity(level="high" if uncovered_hourly >= 1.0 else "medium", score=(700 if uncovered_hourly >= 1.0 else 560)),
                    title="EC2 Savings Plan coverage appears below estimated steady-state demand",
                    scope=scope,
                    message=(
                        f"Estimated EC2 demand is ~${demand_hourly:.4f}/hr and active Savings Plan commitment "
                        f"is ~${commitment_hourly:.4f}/hr (coverage ~{coverage_pct:.1f}%)."
                    ),
                    recommendation=(
                        f"Increase Savings Plan commitment by about ${uncovered_hourly:.4f}/hr after validating "
                        "steady-state usage and term/payment flexibility."
                    ),
                    estimated_monthly_cost=monthly_uncovered_cost,
                    estimated_monthly_savings=potential_monthly_savings,
                    estimate_confidence=int(min(80, max(30, pricing_conf))),
                    estimate_notes=(
                        f"Coverage gap based on on-demand EC2 baseline; potential savings assumes ~"
                        f"{cfg.potential_savings_discount_factor * 100:.0f}% Savings Plan discount. {pricing_note}"
                    ),
                    dimensions={
                        "running_instance_count": str(total_running),
                        "running_top_instance_types": top_types_str,
                        "savings_plan_types": ",".join(f"{k}:{v}" for k, v in sorted(plan_types.items())),
                        "estimated_demand_usd_per_hour": f"{demand_hourly:.4f}",
                        "committed_usd_per_hour": f"{commitment_hourly:.4f}",
                        "covered_usd_per_hour": f"{covered_hourly:.4f}",
                        "uncovered_usd_per_hour": f"{uncovered_hourly:.4f}",
                        "coverage_pct": f"{coverage_pct:.2f}",
                        "target_coverage_pct": "90.00",
                    },
                    issue_key={"signal": "savings_plans_coverage_gap", "portfolio": "ec2"},
                )
            )

        if commitment_hourly > 0.0 and utilization_pct < float(cfg.low_utilization_threshold_pct) and unused_hourly > 0.0:
            monthly_unused_commitment = money(
                unused_hourly * 730.0 * float(cfg.unused_commitment_cost_factor)
            )
            findings.append(
                FindingDraft(
                    check_id="aws.ec2.savings.plans.utilization.low",
                    check_name="EC2 Savings Plan utilization low",
                    category="cost",
                    sub_category="commitments",
                    status="fail",
                    severity=Severity(level=("high" if utilization_pct < 50.0 else "medium"), score=(680 if utilization_pct < 50.0 else 540)),
                    title="EC2 Savings Plan utilization appears low",
                    scope=scope,
                    message=(
                        f"Estimated committed usage is ~{utilization_pct:.1f}% "
                        f"(commitment ~${commitment_hourly:.4f}/hr, demand ~${demand_hourly:.4f}/hr)."
                    ),
                    recommendation=(
                        "Review Savings Plan utilization and rebalance workloads to covered usage. "
                        "If persistent, adjust future commitments and term strategy."
                    ),
                    estimated_monthly_cost=monthly_unused_commitment,
                    estimated_monthly_savings=None,
                    estimate_confidence=int(min(75, max(25, pricing_conf))),
                    estimate_notes=(
                        f"Unused commitment approximated from commitment-demand delta with factor "
                        f"{cfg.unused_commitment_cost_factor:.2f}. {pricing_note}"
                    ),
                    dimensions={
                        "running_instance_count": str(total_running),
                        "running_top_instance_types": top_types_str,
                        "savings_plan_types": ",".join(f"{k}:{v}" for k, v in sorted(plan_types.items())),
                        "estimated_demand_usd_per_hour": f"{demand_hourly:.4f}",
                        "committed_usd_per_hour": f"{commitment_hourly:.4f}",
                        "unused_usd_per_hour": f"{unused_hourly:.4f}",
                        "utilization_pct": f"{utilization_pct:.2f}",
                        "target_utilization_pct": f"{cfg.low_utilization_threshold_pct:.2f}",
                    },
                    issue_key={"signal": "savings_plans_utilization_low", "portfolio": "ec2"},
                )
            )

        return findings[: int(cfg.max_findings_per_type)]

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

    def _list_active_savings_plans(self, savingsplans: Any) -> Iterator[Mapping[str, Any]]:
        next_token: str | None = None
        while True:
            kwargs: dict[str, Any] = {"states": ["active", "payment-pending"]}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = savingsplans.describe_savings_plans(**kwargs)
            plans = resp.get("savingsPlans", []) if isinstance(resp, Mapping) else []
            for plan in plans or []:
                if not isinstance(plan, Mapping):
                    continue
                plan_type = str(plan.get("savingsPlanType") or "").strip().lower()
                if plan_type not in {"compute", "ec2instance"}:
                    continue
                yield plan
            next_token_raw = (resp or {}).get("nextToken") if isinstance(resp, Mapping) else None
            next_token = str(next_token_raw).strip() if next_token_raw is not None else ""
            if not next_token:
                break


SPEC = "checks.aws.ec2_savings_plans:EC2SavingsPlansChecker"


@register_checker(SPEC)
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    """Instantiate Savings Plans checker from runtime bootstrap data."""
    _ = ctx
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for EC2SavingsPlansChecker)")
    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    return EC2SavingsPlansChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
    )
