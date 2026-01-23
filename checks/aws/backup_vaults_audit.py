"""
AWS Backup Vaults Audit Checker
===============================

This module adds two governance-oriented checks for AWS Backup vaults:

1) aws.backup.vaults.no_lifecycle
   IMPORTANT NOTE (AWS reality):
   AWS Backup retention "lifecycle" (cold storage / delete after) is defined on
   *backup plan rules*, not on vaults. However, AWS Backup *does* provide a
   vault-level retention guardrail called **Vault Lock** (min/max retention).
   This check therefore uses Vault Lock as the vault-level lifecycle/retention
   control and flags vaults that lack guardrails or effectively allow infinite
   retention.

   Detects:
     - Vaults with no Vault Lock configuration (no retention guardrail).
     - Vaults with Vault Lock missing/zero MaxRetentionDays (allows "never delete").
     - (Optional) Vault Lock values out of org standards.

2) aws.backup.vaults.access_policy_misconfig
   Detects common misconfigurations in backup vault access policies:
     - No access policy (low signal, but useful governance gap)
     - Wildcard principals in Allow statements ("*" or {"AWS":"*"})
     - Cross-account principals not in an allowlist (bootstrap-configurable)
     - Broad destructive permissions granted to non-allowlisted principals

Design notes
------------
- Uses only AWS Backup APIs (boto3 "backup" client).
- Produces FindingDraft objects compatible with the engine contract.
- Graceful degradation: on permission errors, emits a single INFO finding and stops.

Permissions required (minimum):
- backup:ListBackupVaults
- backup:GetBackupVaultLockConfiguration
- backup:GetBackupVaultAccessPolicy
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Scope, Severity


# Actions that are generally high-impact if granted broadly.
_SENSITIVE_ACTIONS = {
    "backup:deletebackupvault",
    "backup:deletebackupvaultaccesspolicy",
    "backup:putbackupvaultaccesspolicy",
    "backup:deletebackupvaultlockconfiguration",
    "backup:putbackupvaultlockconfiguration",
    "backup:deletebackupplan",
    "backup:deletebackupselection",
    "backup:deleterecoverypoint",
    "backup:startrestorejob",
    "backup:copyfrombackupvault",
    "backup:copyintobackupvault",
    "backup:*",
    "*",
}


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def _safe_region_from_client(client: Any) -> str:
    try:
        return str(getattr(getattr(client, "meta", None), "region_name", "") or "")
    except Exception:  # pragma: no cover
        return ""


def _paginate_items(
    client: BaseClient,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    params = dict(params or {})

    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**params):
                for item in page.get(result_key, []) or []:
                    if isinstance(item, dict):
                        yield item
            return
        except Exception:
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _parse_account_id_from_principal(principal: str) -> Optional[str]:
    """
    Supports:
      - "123456789012"
      - "arn:aws:iam::123456789012:root"
      - "arn:aws:iam::123456789012:role/SomeRole"
    """
    p = str(principal or "").strip()
    if not p:
        return None
    if p.isdigit() and len(p) == 12:
        return p
    if p.startswith("arn:"):
        parts = p.split(":")
        # arn:partition:service:region:account-id:resource
        if len(parts) >= 6:
            acct = parts[4]
            if acct and acct.isdigit() and len(acct) == 12:
                return acct
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_action(action: Any) -> Set[str]:
    """
    Action can be a string or list; normalize to lowercase set.
    """
    actions: Set[str] = set()
    for a in _as_list(action):
        if a is None:
            continue
        actions.add(str(a).strip().lower())
    return actions


def _principal_is_wildcard(principal: Any) -> bool:
    # Principal can be "*", {"AWS":"*"}, {"AWS":[...]} etc.
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


def _extract_principals(principal: Any) -> List[str]:
    """
    Return a list of principal strings (best-effort).
    """
    principals: List[str] = []
    if principal is None:
        return principals

    if isinstance(principal, str):
        principals.append(principal)
        return principals

    if isinstance(principal, dict):
        aws = principal.get("AWS")
        for x in _as_list(aws):
            if x is None:
                continue
            principals.append(str(x))
        return principals

    if isinstance(principal, list):
        for x in principal:
            if x is None:
                continue
            principals.append(str(x))
        return principals

    return principals


class AwsBackupVaultsAuditChecker:
    """
    One checker module, two check_id outputs:
      - aws.backup.vaults.no_lifecycle
      - aws.backup.vaults.access_policy_misconfig
    """

    checker_id = "aws.backup.vaults.audit"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        expected_lock_min_days: Optional[int] = None,
        expected_lock_max_days: Optional[int] = None,
        allowed_cross_account_ids: Optional[Set[str]] = None,
    ) -> None:
        self._account = account
        self._expected_lock_min_days = expected_lock_min_days
        self._expected_lock_max_days = expected_lock_max_days
        self._allowed_cross_account_ids = allowed_cross_account_ids or set()

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "backup", None):
            raise RuntimeError("AwsBackupVaultsAuditChecker requires ctx.services.backup")

        backup: BaseClient = ctx.services.backup
        region = _safe_region_from_client(backup)

        try:
            vaults = list(_paginate_items(backup, "list_backup_vaults", "BackupVaultList"))
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "list_backup_vaults", exc)
            return

        # Vault Lock / "vault lifecycle guardrail"
        try:
            for v in vaults:
                yield from self._check_vault_lock(ctx, backup, region, v)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "get_backup_vault_lock_configuration", exc)
            return

        # Access policy checks
        try:
            for v in vaults:
                yield from self._check_access_policy(ctx, backup, region, v)
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "get_backup_vault_access_policy", exc)
            return

    # ------------------------------ Check 1: Vault Lock ------------------------------ #

    def _check_vault_lock(self, ctx, backup: BaseClient, region: str, vault: Dict[str, Any]) -> Iterable[FindingDraft]:
        vault_name = str(vault.get("BackupVaultName") or "")
        vault_arn = str(vault.get("BackupVaultArn") or "")
        if not vault_name:
            return

        # If no Vault Lock config exists, AWS returns ResourceNotFoundException.
        try:
            resp = backup.get_backup_vault_lock_configuration(BackupVaultName=vault_name)
            lock = resp or {}
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "ResourceNotFound"}:
                yield FindingDraft(
                    check_id="aws.backup.vaults.no_lifecycle",
                    check_name="AWS Backup vault retention guardrails (Vault Lock)",
                    category="governance",
                    status="fail",
                    severity=Severity(level="medium", score=70),
                    title="Backup vault has no Vault Lock (no retention guardrail)",
                    message=(
                        f"Backup vault '{vault_name}' has no Vault Lock configuration. "
                        "This means there is no vault-level min/max retention guardrail; "
                        "retention is entirely dependent on backup plan rules and can drift to 'retain forever'."
                    ),
                    recommendation=(
                        "Consider configuring Vault Lock (min/max retention) for this vault to enforce "
                        "organization retention standards and prevent indefinite accumulation."
                    ),
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "vault_lock_missing", "vault": vault_name},
                    dimensions={"vault_arn": vault_arn},
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Vault-level retention guardrail; cost impact depends on current recovery points and plan rules.",
                )
                return
            raise

        min_days = _safe_int(lock.get("MinRetentionDays"), default=0)
        max_days = _safe_int(lock.get("MaxRetentionDays"), default=0)
        changeable = _safe_int(lock.get("ChangeableForDays"), default=0)

        # If MaxRetentionDays is missing/0, treat as "allows never delete" for governance.
        if max_days <= 0:
            yield FindingDraft(
                check_id="aws.backup.vaults.no_lifecycle",
                check_name="AWS Backup vault retention guardrails (Vault Lock)",
                category="governance",
                status="fail",
                severity=Severity(level="medium", score=75),
                title="Backup vault Vault Lock allows indefinite retention",
                message=(
                    f"Backup vault '{vault_name}' has Vault Lock configured but MaxRetentionDays is not set "
                    "or is zero. This can allow recovery points to be retained indefinitely."
                ),
                recommendation="Set a MaxRetentionDays value aligned with your retention standards.",
                scope=self._base_scope(
                    ctx,
                    region=region,
                    resource_type="backup_vault",
                    resource_id=vault_name,
                    resource_arn=vault_arn,
                ),
                issue_key={"rule": "vault_lock_no_max", "vault": vault_name},
                dimensions={
                    "vault_arn": vault_arn,
                    "min_retention_days": str(min_days),
                    "max_retention_days": str(max_days),
                    "changeable_for_days": str(changeable),
                },
                estimated_monthly_cost=None,
                estimated_monthly_savings=None,
                estimate_confidence=0,
                estimate_notes="Vault Lock max retention missing/zero; cost impact depends on actual retained recovery points.",
            )
            return

        # Optional org standards enforcement
        if self._expected_lock_min_days is not None and min_days != int(self._expected_lock_min_days):
            yield self._vault_lock_out_of_standard(
                ctx,
                region,
                vault_name,
                vault_arn,
                min_days,
                max_days,
                changeable,
                reason="MinRetentionDays differs from expected org standard.",
            )
            return

        if self._expected_lock_max_days is not None and max_days != int(self._expected_lock_max_days):
            yield self._vault_lock_out_of_standard(
                ctx,
                region,
                vault_name,
                vault_arn,
                min_days,
                max_days,
                changeable,
                reason="MaxRetentionDays differs from expected org standard.",
            )
            return

    def _vault_lock_out_of_standard(
        self,
        ctx,
        region: str,
        vault_name: str,
        vault_arn: str,
        min_days: int,
        max_days: int,
        changeable: int,
        *,
        reason: str,
    ) -> FindingDraft:
        expected_min = "" if self._expected_lock_min_days is None else str(self._expected_lock_min_days)
        expected_max = "" if self._expected_lock_max_days is None else str(self._expected_lock_max_days)

        return FindingDraft(
            check_id="aws.backup.vaults.no_lifecycle",
            check_name="AWS Backup vault retention guardrails (Vault Lock)",
            category="governance",
            status="fail",
            severity=Severity(level="low", score=55),
            title="Backup vault Vault Lock is out of org standard",
            message=f"Backup vault '{vault_name}' Vault Lock configuration is out of standard: {reason}",
            recommendation="Update Vault Lock retention values to match your organization standards (if applicable).",
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type="backup_vault",
                resource_id=vault_name,
                resource_arn=vault_arn,
            ),
            issue_key={"rule": "vault_lock_out_of_standard", "vault": vault_name},
            dimensions={
                "vault_arn": vault_arn,
                "min_retention_days": str(min_days),
                "max_retention_days": str(max_days),
                "changeable_for_days": str(changeable),
                "expected_min_retention_days": expected_min,
                "expected_max_retention_days": expected_max,
            },
            estimated_monthly_cost=None,
            estimated_monthly_savings=None,
            estimate_confidence=0,
            estimate_notes="Standardization finding; does not estimate storage cost directly.",
        )

    # ------------------------------ Check 2: Access Policy ------------------------------ #

    def _check_access_policy(self, ctx, backup: BaseClient, region: str, vault: Dict[str, Any]) -> Iterable[FindingDraft]:
        vault_name = str(vault.get("BackupVaultName") or "")
        vault_arn = str(vault.get("BackupVaultArn") or "")
        if not vault_name:
            return

        try:
            resp = backup.get_backup_vault_access_policy(BackupVaultName=vault_name) or {}
            policy_str = str(resp.get("Policy") or "").strip()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "ResourceNotFound"}:
                # No access policy exists
                yield FindingDraft(
                    check_id="aws.backup.vaults.access_policy_misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="governance",
                    status="fail",
                    severity=Severity(level="low", score=40),
                    title="Backup vault has no access policy",
                    message=(
                        f"Backup vault '{vault_name}' has no access policy. This isn't always wrong, "
                        "but it often indicates governance is not explicit (especially in multi-account orgs)."
                    ),
                    recommendation=(
                        "If you use cross-account backup copy/restore or centralized backup management, "
                        "define an explicit vault access policy. Otherwise, consider documenting that this is intended."
                    ),
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "no_access_policy", "vault": vault_name},
                    dimensions={"vault_arn": vault_arn},
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Governance signal; not a direct cost estimate.",
                )
                return
            raise

        if not policy_str:
            # Treat empty policy as missing
            yield FindingDraft(
                check_id="aws.backup.vaults.access_policy_misconfig",
                check_name="AWS Backup vault access policy misconfiguration",
                category="governance",
                status="fail",
                severity=Severity(level="low", score=40),
                title="Backup vault access policy is empty",
                message=f"Backup vault '{vault_name}' returned an empty access policy document.",
                recommendation="Set a valid access policy or remove the policy entirely if not needed.",
                scope=self._base_scope(
                    ctx,
                    region=region,
                    resource_type="backup_vault",
                    resource_id=vault_name,
                    resource_arn=vault_arn,
                ),
                issue_key={"rule": "empty_access_policy", "vault": vault_name},
                dimensions={"vault_arn": vault_arn},
                estimated_monthly_cost=None,
                estimated_monthly_savings=None,
                estimate_confidence=0,
                estimate_notes="Governance signal; not a direct cost estimate.",
            )
            return

        try:
            policy = json.loads(policy_str)
        except json.JSONDecodeError:
            yield FindingDraft(
                check_id="aws.backup.vaults.access_policy_misconfig",
                check_name="AWS Backup vault access policy misconfiguration",
                category="governance",
                status="fail",
                severity=Severity(level="medium", score=65),
                title="Backup vault access policy is not valid JSON",
                message=f"Backup vault '{vault_name}' access policy could not be parsed as JSON.",
                recommendation="Fix the access policy JSON document and re-apply it.",
                scope=self._base_scope(
                    ctx,
                    region=region,
                    resource_type="backup_vault",
                    resource_id=vault_name,
                    resource_arn=vault_arn,
                ),
                issue_key={"rule": "invalid_policy_json", "vault": vault_name},
                dimensions={"vault_arn": vault_arn},
                estimated_monthly_cost=None,
                estimated_monthly_savings=None,
                estimate_confidence=0,
                estimate_notes="Governance signal; not a direct cost estimate.",
            )
            return

        statements = policy.get("Statement")
        if statements is None:
            statements = []
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            statements = []

        # Evaluate statements and emit the *most severe* single finding per vault to avoid noise.
        worst: Optional[FindingDraft] = None

        for st in statements:
            if not isinstance(st, dict):
                continue

            effect = str(st.get("Effect") or "").strip().lower()
            if effect != "allow":
                continue

            principal = st.get("Principal")
            actions = _normalize_action(st.get("Action"))
            sid = str(st.get("Sid") or "")

            # 1) Wildcard principal is always bad in an Allow statement.
            if _principal_is_wildcard(principal):
                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access_policy_misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="security",
                    status="fail",
                    severity=Severity(level="high", score=90),
                    title="Backup vault access policy allows wildcard principal",
                    message=(
                        f"Backup vault '{vault_name}' access policy contains an Allow statement with wildcard "
                        f"principal ('*'). This is overly permissive."
                    ),
                    recommendation="Restrict principals to specific AWS accounts/roles and limit actions to required operations.",
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "wildcard_principal", "vault": vault_name, "sid": sid},
                    dimensions={
                        "vault_arn": vault_arn,
                        "sid": sid,
                        "actions": ",".join(sorted(actions)),
                    },
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Security/governance risk; not a direct cost estimate.",
                )
                worst = self._pick_worst(worst, candidate)
                continue

            # 2) Cross-account principals
            principals = _extract_principals(principal)
            cross_accounts: Set[str] = set()
            for p in principals:
                acct = _parse_account_id_from_principal(p)
                if acct and acct != self._account.account_id and acct not in self._allowed_cross_account_ids:
                    cross_accounts.add(acct)

            # 3) Broad sensitive actions to cross-account or unknown principals is higher severity
            has_sensitive = any(a in _SENSITIVE_ACTIONS for a in actions)

            if cross_accounts:
                sev = Severity(level="high", score=85) if has_sensitive else Severity(level="medium", score=70)
                title = "Backup vault access policy allows cross-account access"
                if has_sensitive:
                    title = "Backup vault access policy grants broad sensitive permissions cross-account"

                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access_policy_misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="security",
                    status="fail",
                    severity=sev,
                    title=title,
                    message=(
                        f"Backup vault '{vault_name}' access policy allows principals from other AWS accounts "
                        f"not in the allowlist: {', '.join(sorted(cross_accounts))}."
                    ),
                    recommendation=(
                        "Restrict the policy to an approved allowlist of accounts/roles, "
                        "and limit actions to the minimum necessary."
                    ),
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "cross_account_access", "vault": vault_name, "sid": sid},
                    dimensions={
                        "vault_arn": vault_arn,
                        "sid": sid,
                        "cross_account_ids": ",".join(sorted(cross_accounts)),
                        "actions": ",".join(sorted(actions)),
                        "sensitive_actions": "true" if has_sensitive else "false",
                    },
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Security/governance risk; not a direct cost estimate.",
                )
                worst = self._pick_worst(worst, candidate)
                continue

            # 4) If not cross-account, still flag overly broad sensitive actions to non-wildcard principals (lower severity)
            if has_sensitive and principals:
                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access_policy_misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="security",
                    status="fail",
                    severity=Severity(level="medium", score=65),
                    title="Backup vault access policy grants broad sensitive permissions",
                    message=(
                        f"Backup vault '{vault_name}' access policy includes sensitive actions "
                        f"({', '.join(sorted(actions & _SENSITIVE_ACTIONS))})."
                    ),
                    recommendation="Scope sensitive actions to tightly controlled admin roles and consider adding explicit conditions.",
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "broad_sensitive_actions", "vault": vault_name, "sid": sid},
                    dimensions={
                        "vault_arn": vault_arn,
                        "sid": sid,
                        "principals": ",".join(principals),
                        "actions": ",".join(sorted(actions)),
                    },
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Security/governance risk; not a direct cost estimate.",
                )
                worst = self._pick_worst(worst, candidate)

        if worst is not None:
            yield worst

    def _pick_worst(self, current: Optional[FindingDraft], candidate: FindingDraft) -> FindingDraft:
        if current is None:
            return candidate
        if int(candidate.severity.score) > int(current.severity.score):
            return candidate
        return current

    # ------------------------------ Helpers ------------------------------ #

    def _access_error_finding(self, ctx, region: str, operation: str, exc: ClientError) -> FindingDraft:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return FindingDraft(
            check_id="aws.backup.access_error",
            check_name="AWS Backup access error",
            category="inventory",
            status="info",
            severity=Severity(level="low", score=10),
            title="Unable to enumerate AWS Backup vault inventory",
            message=f"Failed to call {operation} ({code}). Some AWS Backup vault checks were skipped.",
            recommendation="Grant AWS Backup read permissions for vault listing, lock configuration, and access policies.",
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type="backup_inventory",
                resource_id=operation,
                resource_arn="",
            ),
            issue_key={"rule": "access_error", "operation": operation, "error": code},
            estimated_monthly_cost=None,
            estimated_monthly_savings=None,
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


@register_checker("checks.aws.backup_vaults_audit:AwsBackupVaultsAuditChecker")
def _factory(ctx, bootstrap):
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for AwsBackupVaultsAuditChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    partition = str(bootstrap.get("aws_partition") or "aws")

    # Optional org standards for Vault Lock.
    expected_lock_min_days = bootstrap.get("backup_vault_lock_expected_min_retention_days")
    expected_lock_max_days = bootstrap.get("backup_vault_lock_expected_max_retention_days")
    if expected_lock_min_days is not None:
        expected_lock_min_days = int(expected_lock_min_days)
    if expected_lock_max_days is not None:
        expected_lock_max_days = int(expected_lock_max_days)

    # Allowlist for legitimate cross-account access (comma-separated or list).
    allowlist: Set[str] = set()
    raw_allow = bootstrap.get("backup_vault_allowed_cross_account_ids")
    if isinstance(raw_allow, list):
        for x in raw_allow:
            s = str(x).strip()
            if s:
                allowlist.add(s)
    elif raw_allow is not None:
        for part in str(raw_allow).split(","):
            s = part.strip()
            if s:
                allowlist.add(s)

    account = AwsAccountContext(
        account_id=account_id,
        billing_account_id=billing_account_id,
        partition=partition,
    )
    return AwsBackupVaultsAuditChecker(
        account=account,
        expected_lock_min_days=expected_lock_min_days,
        expected_lock_max_days=expected_lock_max_days,
        allowed_cross_account_ids=allowlist,
    )
