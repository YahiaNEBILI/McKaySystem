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

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Scope, Severity

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


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_region_from_client(client: Any) -> str:
    try:
        return str(getattr(getattr(client, "meta", None), "region_name", "") or "")
    except Exception:  # pragma: no cover
        return ""


def _fmt_money_usd(amount: float) -> str:
    return f"{amount:.2f}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        if isinstance(value, (int, float)):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _gb_from_bytes(size_bytes: Any) -> float:
    size = _safe_float(size_bytes, default=0.0)
    if size <= 0.0:
        return 0.0
    return size / (1024.0**3)


def _is_suppressed(tags: Any) -> bool:
    """
    Return True if tags imply intentional retention.

    `tags` may be:
      - dict {k:v}
      - list of {"Key":..,"Value":..}
      - None
    """
    if not tags:
        return False

    if isinstance(tags, dict):
        for k, v in tags.items():
            if str(k).strip().lower() in _SUPPRESS_KEYS:
                return True
            if str(v).strip().lower() in _SUPPRESS_VALUES:
                return True
        return False

    if isinstance(tags, list):
        for item in tags:
            if not isinstance(item, dict):
                continue
            key = str(item.get("Key") or "").strip().lower()
            val = str(item.get("Value") or "").strip().lower()
            if key in _SUPPRESS_KEYS or val in _SUPPRESS_VALUES:
                return True
        return False

    return False


def _paginate_items(
    client: BaseClient,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    """
    Yield dict items from either a paginator (preferred) or a NextToken loop fallback.

    This keeps the checker robust against local stubs/mocks that may not implement paginator behavior.
    """
    params = dict(params or {})

    # Prefer paginator if present and works
    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**params):
                for item in page.get(result_key, []) or []:
                    if isinstance(item, dict):
                        yield item
            return
        except Exception:
            # Fall back to token loop below
            pass

    next_token: Optional[str] = None
    while True:
        call = getattr(client, operation)
        req = dict(params)
        if next_token:
            req["NextToken"] = next_token
        resp = call(**req) if req else call()
        for item in resp.get(result_key, []) or []:
            if isinstance(item, dict):
                yield item
        next_token = resp.get("NextToken")
        if not next_token:
            break


class AwsBackupPlansAuditChecker:
    """
    One checker, three issue types (distinct check_id values).
    """

    checker_id = "aws.backup.governance.plans_audit"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        stale_days: int = 90,
        warm_gb_month_price_usd: float = 0.05,
        cold_gb_month_price_usd: float = 0.01,
        skip_if_deleting_within_days: int = 14,
    ) -> None:
        self._account = account
        self._stale_days = int(stale_days)
        self._warm_price = float(warm_gb_month_price_usd)
        self._cold_price = float(cold_gb_month_price_usd)
        self._skip_if_deleting_within_days = int(skip_if_deleting_within_days)

    def run(self, ctx) -> Iterable[FindingDraft]:
        if ctx.services is None or not getattr(ctx.services, "backup", None):
            raise RuntimeError("AwsBackupPlansAuditChecker requires ctx.services.backup")

        backup: BaseClient = ctx.services.backup
        region = _safe_region_from_client(backup)

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
        for plan in _paginate_items(backup, "list_backup_plans", "BackupPlansList"):
            plan_id = str(plan.get("BackupPlanId") or "")
            plan_name = str(plan.get("BackupPlanName") or plan_id or "")
            if not plan_id:
                continue

            # List selections (can be paginated)
            has_any_selection = False
            for _sel in _paginate_items(
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
        for plan in _paginate_items(backup, "list_backup_plans", "BackupPlansList"):
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
        now = _now_utc()
        cutoff = (now - timedelta(days=self._stale_days)).replace(microsecond=0)
        skip_cutoff = now + timedelta(days=self._skip_if_deleting_within_days)

        for vault in _paginate_items(backup, "list_backup_vaults", "BackupVaultList"):
            vault_name = str(vault.get("BackupVaultName") or "")
            if not vault_name:
                continue

            for rp in _paginate_items(
                backup,
                "list_recovery_points_by_backup_vault",
                "RecoveryPoints",
                params={"BackupVaultName": vault_name},
            ):
                arn = str(rp.get("RecoveryPointArn") or "")
                created = _utc(rp.get("CreationDate"))
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
                delete_at = _utc(calc_lifecycle.get("DeleteAt")) if isinstance(calc_lifecycle, dict) else None
                if delete_at is not None and delete_at <= skip_cutoff:
                    continue

                # Best-effort suppression (may not be present for all list responses).
                if _is_suppressed(rp.get("Tags")):
                    continue

                size_gb = _gb_from_bytes(rp.get("BackupSizeInBytes"))
                unit = self._cold_price if storage_class == "COLD" else self._warm_price
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
                    estimated_monthly_cost=_fmt_money_usd(est_cost) if est_cost > 0.0 else None,
                    estimated_monthly_savings=_fmt_money_usd(potential) if potential > 0.0 else None,
                    estimate_confidence=50 if est_cost > 0.0 else 10,
                    estimate_notes=(
                        "Estimated from BackupSizeInBytes and configurable $/GB-month unit price. "
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
        return Scope(
            cloud=ctx.cloud,
            provider_partition=self._account.partition,
            billing_account_id=billing_account_id,
            account_id=account_id,
            region=region,
            service="AWSBackup",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
        )


@register_checker("checks.aws.backup_plans_audit:AwsBackupPlansAuditChecker")
def _factory(ctx, bootstrap):
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for AwsBackupPlansAuditChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    partition = str(bootstrap.get("aws_partition") or "aws")

    stale_days = int(bootstrap.get("backup_stale_recovery_point_days", 90))

    # Cost estimation knobs (approximate defaults)
    warm_price = _safe_float(bootstrap.get("backup_warm_gb_month_price_usd", 0.05), default=0.05)
    cold_price = _safe_float(bootstrap.get("backup_cold_gb_month_price_usd", 0.01), default=0.01)

    skip_if_deleting_within_days = int(bootstrap.get("backup_skip_if_deleting_within_days", 14))

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
