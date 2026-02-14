"""
AWS Backup Plans & Recovery Points Checker
==========================================

Infra-native FinOps checker for AWS Backup configuration hygiene and retention risk.

It emits findings for three issue types (distinct check_id values):

1) aws.backup.plans.no_selections
   Backup plans that have zero selections (i.e., no resources are included),
   so the plan effectively backs up nothing.

2) aws.backup.rules.no_lifecycle
   Backup plan rules with no lifecycle configuration (neither cold-storage
   transition nor delete-after retention). These rules can retain recovery
   points indefinitely by default, often unintentionally.

3) aws.backup.recovery_points.stale
   Recovery points older than a configurable threshold (default: 90 days)
   that are not near an automatic delete date and are likely ready to prune.

Design notes
------------
- Uses AWS Backup APIs (boto3 "backup" client).
- Produces FindingDraft objects compatible with the engine contract.
- Best-effort cost estimation for stale recovery points:
    estimated_monthly_cost ~= size_gb * price_per_gb_month
  This is intentionally approximate (pricing varies by region and resource type).
- Graceful degradation: if inventory calls fail due to permissions, emit a single
  INFO finding and stop cleanly.

Minimum permissions (read-only):
- backup:ListBackupPlans
- backup:ListBackupSelections
- backup:GetBackupPlan
- backup:ListBackupVaults
- backup:ListRecoveryPointsByBackupVault
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Iterable, Iterator, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.aws._common import (
    build_scope,
    AwsAccountContext,
    gb_from_bytes,
    is_suppressed,
    money,
    now_utc,
    paginate_items,
    pricing_first_positive,
    pricing_service,
    safe_float,
    safe_region_from_client,
    utc,
)
from checks.aws.defaults import (
    BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD,
    BACKUP_PLANS_SKIP_IF_DELETING_WITHIN_DAYS,
    BACKUP_PLANS_STALE_DAYS,
    BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import FindingDraft, RunContext, Scope, Severity

# Best-effort suppression keys/values (recovery point list responses may not always include tags).
_SUPPRESS_KEYS = {
    "retain",
    "legal-hold",
    "legal_hold",
    "backup-policy",
    "backup_policy",
    "suppress",
    "keep",
}
_SUPPRESS_VALUES = set(_SUPPRESS_KEYS)


def _pricing_backup_gb_month_price(
    ctx: Any,
    *,
    region: str,
    storage_class: str,
    fallback_usd: float,
) -> tuple[float, str, int]:
    """
    Best-effort unit price lookup via ctx.services.pricing.

    This checker historically used fixed warm/cold $/GB-month defaults. We keep that as a fallback
    to avoid regressions in environments/tests where PricingService is not wired.

    Returns: (unit_price_usd_per_gb_month, notes, confidence)
    """
    pricing = pricing_service(ctx)
    if pricing is None:
        return float(fallback_usd), "PricingService unavailable; using configured fallback $/GB-month.", 10

    # Normalize storage class signals from AWS Backup list responses
    normalized = str(storage_class or "").strip().lower()
    if normalized in {"cold", "cold_storage", "coldstorage"}:
        tier = "cold"
    else:
        tier = "warm"

    candidates = (
        "backup_storage_gb_month_price",
        "backup_gb_month_price",
        "aws_backup_storage_gb_month_price",
        "aws_backup_gb_month_price",
    )

    price_f, method_name = pricing_first_positive(
        pricing,
        method_names=candidates,
        kwargs_variants=(
            {"region": region, "tier": tier},
            {"region": region, "storage_class": tier},
        ),
        args_variants=((region, tier),),
    )
    if price_f is not None:
        return float(price_f), f"Unit price from PricingService ({method_name}, tier={tier}).", 60

    return float(fallback_usd), "PricingService did not provide a unit price; using configured fallback $/GB-month.", 15


class AwsBackupPlansAuditChecker:
    """
    One checker, three issue types (distinct check_id values).
    """

    checker_id = "aws.backup.governance.plans.audit"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        stale_days: int = BACKUP_PLANS_STALE_DAYS,
        warm_gb_month_price_usd: float = BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD,
        cold_gb_month_price_usd: float = BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD,
        skip_if_deleting_within_days: int = BACKUP_PLANS_SKIP_IF_DELETING_WITHIN_DAYS,
    ) -> None:
        self._account = account
        self._stale_days = int(stale_days)
        self._warm_price = float(warm_gb_month_price_usd)
        self._cold_price = float(cold_gb_month_price_usd)
        self._skip_if_deleting_within_days = int(skip_if_deleting_within_days)

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        if ctx.services is None or not getattr(ctx.services, "backup", None):
            raise RuntimeError("AwsBackupPlansAuditChecker requires ctx.services.backup")

        backup: BaseClient = ctx.services.backup
        region = safe_region_from_client(backup)

        # Run sections independently so we can produce a single clear access error per missing permission set.
        try:
            yield from self._plans_without_selections(ctx, backup, region)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "list_backup_plans/list_backup_selections", exc)
            return

        try:
            yield from self._rules_no_lifecycle(ctx, backup, region)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "get_backup_plan", exc)
            return

        try:
            yield from self._stale_recovery_points(ctx, backup, region)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "list_backup_vaults/list_recovery_points_by_backup_vault", exc)
            return

    # ------------------------- 1) plans without selections ------------------------- #

    def _plans_without_selections(self, ctx, backup: BaseClient, region: str) -> Iterable[FindingDraft]:
        for plan in paginate_items(backup, "list_backup_plans", "BackupPlansList"):
            plan_id = str(plan.get("BackupPlanId") or "")
            plan_name = str(plan.get("BackupPlanName") or plan_id or "")
            if not plan_id:
                continue

            # List selections (can be paginated)
            has_any_selection = False
            for _sel in paginate_items(
                backup,
                "list_backup_selections",
                "BackupSelectionsList",
                params={"BackupPlanId": plan_id},
            ):
                has_any_selection = True
                break
            if has_any_selection:
                continue

            yield FindingDraft(
                check_id="aws.backup.plans.no_selections",
                check_name="Backup plans without selections",
                category="governance",
                status="fail",
                severity=Severity(level="low", score=45),
                title="Backup plan has no selections (backs up nothing)",
                message=f"Backup plan '{plan_name}' ({plan_id}) has zero selections and protects no resources.",
                recommendation="Add backup selections (tag-based or explicit resource ARNs) or delete the unused plan.",
                scope=self._base_scope(
                    ctx,
                    region=region,
                    resource_type="backup_plan",
                    resource_id=plan_id,
                    resource_arn="",
                ),
                issue_key={"rule": "no_selections", "plan_id": plan_id},
                dimensions={"plan_name": plan_name},
            )

    # ------------------------- 2) rules missing lifecycle -------------------------- #

    def _rules_no_lifecycle(self, ctx, backup: BaseClient, region: str) -> Iterable[FindingDraft]:
        for plan in paginate_items(backup, "list_backup_plans", "BackupPlansList"):
            plan_id = str(plan.get("BackupPlanId") or "")
            plan_name = str(plan.get("BackupPlanName") or plan_id or "")
            if not plan_id:
                continue

            detail = backup.get_backup_plan(BackupPlanId=plan_id).get("BackupPlan", {}) or {}
            rules = detail.get("Rules", []) or []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                rule_name = str(rule.get("RuleName") or "")
                lifecycle = rule.get("Lifecycle") or {}
                move_days = lifecycle.get("MoveToColdStorageAfterDays")
                delete_days = lifecycle.get("DeleteAfterDays")

                # Treat None/0 as "not set"
                if (move_days in (None, 0)) and (delete_days in (None, 0)):
                    yield FindingDraft(
                        check_id="aws.backup.rules.no_lifecycle",
                        check_name="Backup rules missing lifecycle",
                        category="governance",
                        status="fail",
                        severity=Severity(level="medium", score=70),
                        title="Backup rule has no lifecycle (no cold storage or delete retention)",
                        message=(
                            f"Backup rule '{rule_name}' in plan '{plan_name}' has no lifecycle "
                            "(no cold storage transition and no delete-after retention)."
                        ),
                        recommendation=(
                            "Define a lifecycle on the rule (MoveToColdStorageAfterDays and/or DeleteAfterDays) "
                            "to enforce retention and reduce long-term storage waste."
                        ),
                        scope=self._base_scope(
                            ctx,
                            region=region,
                            resource_type="backup_rule",
                            resource_id=f"{plan_id}:{rule_name}",
                            resource_arn="",
                        ),
                        issue_key={"rule": "no_lifecycle", "plan_id": plan_id, "rule_name": rule_name},
                        dimensions={
                            "plan_name": plan_name,
                            "rule_name": rule_name,
                            "move_to_cold_after_days": str(move_days) if move_days is not None else "",
                            "delete_after_days": str(delete_days) if delete_days is not None else "",
                        },
                    )

    # ------------------------- 3) stale recovery points --------------------------- #

    def _stale_recovery_points(self, ctx, backup: BaseClient, region: str) -> Iterable[FindingDraft]:
        now = now_utc()
        cutoff = (now - timedelta(days=self._stale_days)).replace(microsecond=0)
        skip_cutoff = now + timedelta(days=self._skip_if_deleting_within_days)

        for vault in paginate_items(backup, "list_backup_vaults", "BackupVaultList"):
            vault_name = str(vault.get("BackupVaultName") or "")
            if not vault_name:
                continue

            for rp in paginate_items(
                backup,
                "list_recovery_points_by_backup_vault",
                "RecoveryPoints",
                params={"BackupVaultName": vault_name},
            ):
                arn = str(rp.get("RecoveryPointArn") or "")
                created = utc(rp.get("CreationDate"))
                status = str(rp.get("Status") or "")
                storage_class = str(rp.get("StorageClass") or "").upper()

                if not arn or created is None:
                    continue
                if status.upper() in {"DELETED", "EXPIRED"}:
                    continue
                if created >= cutoff:
                    continue

                # If AWS already plans to delete soon, skip to reduce noise.
                calc_lifecycle = rp.get("CalculatedLifecycle") or {}
                delete_at = utc(calc_lifecycle.get("DeleteAt")) if isinstance(calc_lifecycle, dict) else None
                if delete_at is not None and delete_at <= skip_cutoff:
                    continue

                # Best-effort suppression (may not be present for all list responses).
                if is_suppressed(rp.get("Tags"), suppress_keys=_SUPPRESS_KEYS, suppress_values=_SUPPRESS_VALUES):
                    continue

                size_gb = gb_from_bytes(rp.get("BackupSizeInBytes"))

                fallback_unit = self._cold_price if storage_class == "COLD" else self._warm_price
                unit, unit_notes, unit_conf = _pricing_backup_gb_month_price(
                    ctx,
                    region=region,
                    storage_class=storage_class,
                    fallback_usd=fallback_unit,
                )
                est_cost = (size_gb * unit) if (size_gb > 0.0 and unit > 0.0) else 0.0

                # Heuristic: if stale and not auto-expiring soon, potential savings ~= monthly cost (deletion).
                potential = est_cost

                resource_type = str(rp.get("ResourceType") or "")
                resource_arn = str(rp.get("ResourceArn") or "")

                yield FindingDraft(
                    check_id="aws.backup.recovery_points.stale",
                    check_name="Stale AWS Backup recovery points",
                    category="waste",
                    status="fail",
                    severity=Severity(level="medium", score=65),
                    title=f"Stale recovery point older than {self._stale_days} days",
                    message=(
                        f"Recovery point is {int((now - created).days)} days old in vault '{vault_name}'. "
                        "It is not scheduled to delete soon and may be eligible for pruning."
                    ),
                    recommendation="Review retention needs and delete/expire unused recovery points.",
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="recovery_point",
                        resource_id=arn,
                        resource_arn=arn,
                    ),
                    issue_key={"rule": "stale_recovery_point", "vault": vault_name, "recovery_point_arn": arn},
                    dimensions={
                        "vault": vault_name,
                        "resource_type": resource_type,
                        "resource_arn": resource_arn,
                        "storage_class": storage_class,
                        "created_at": created.isoformat().replace("+00:00", "Z"),
                        "delete_at": delete_at.isoformat().replace("+00:00", "Z") if delete_at else "",
                        "size_gb": f"{size_gb:.3f}",
                    },
                    estimated_monthly_cost=money(est_cost) if est_cost > 0.0 else None,
                    estimated_monthly_savings=money(potential) if potential > 0.0 else None,
                    estimate_confidence=(min(90, max(20, unit_conf + 10)) if est_cost > 0.0 else 10),
                    estimate_notes=(
                        f"Estimated from BackupSizeInBytes and $/GB-month unit price. {unit_notes} "
                        "Actual AWS Backup storage pricing varies by region and protected resource type."
                    ),
                )

    # ------------------------------ findings helpers ------------------------------ #

    def _access_error_finding(self, ctx, region: str, operation: str, exc: ClientError) -> FindingDraft:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return FindingDraft(
            check_id="aws.backup.access_error",
            check_name="AWS Backup access error",
            category="inventory",
            status="info",
            severity=Severity(level="low", score=10),
            title="Unable to enumerate AWS Backup inventory",
            message=f"Failed to call {operation} ({code}). Some AWS Backup checks were skipped.",
            recommendation="Grant AWS Backup read permissions (List/Get) for plans, selections, vaults, and recovery points.",
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type="backup_inventory",
                resource_id=operation,
                resource_arn="",
            ),
            issue_key={"rule": "access_error", "operation": operation, "error": code},
            estimated_monthly_savings=None,
            estimated_monthly_cost=None,
            estimate_confidence=0,
            estimate_notes="",
        )

    def _base_scope(
        self,
        ctx,
        *,
        region: str,
        resource_type: str,
        resource_id: str,
        resource_arn: str,
    ) -> Scope:
        account_id = self._account.account_id
        billing_account_id = self._account.billing_account_id or account_id
        return build_scope(
            ctx,
            account=self._account,
            region=region,
            service="AWSBackup",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            billing_account_id=billing_account_id,
        )


@register_checker("checks.aws.backup_plans_audit:AwsBackupPlansAuditChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> AwsBackupPlansAuditChecker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for AwsBackupPlansAuditChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    partition = str(bootstrap.get("aws_partition") or "aws")

    stale_days = int(bootstrap.get("backup_stale_recovery_point_days", BACKUP_PLANS_STALE_DAYS))

    # Cost estimation knobs (approximate defaults)
    warm_price = safe_float(
        bootstrap.get("backup_warm_gb_month_price_usd", BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD),
        default=BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD,
    )
    cold_price = safe_float(
        bootstrap.get("backup_cold_gb_month_price_usd", BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD),
        default=BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD,
    )

    skip_if_deleting_within_days = int(
        bootstrap.get("backup_skip_if_deleting_within_days", BACKUP_PLANS_SKIP_IF_DELETING_WITHIN_DAYS)
    )

    account = AwsAccountContext(
        account_id=account_id,
        billing_account_id=billing_account_id,
        partition=partition,
    )
    return AwsBackupPlansAuditChecker(
        account=account,
        stale_days=stale_days,
        warm_gb_month_price_usd=warm_price,
        cold_gb_month_price_usd=cold_price,
        skip_if_deleting_within_days=skip_if_deleting_within_days,
    )
