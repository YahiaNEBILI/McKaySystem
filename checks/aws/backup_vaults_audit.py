"""
AWS Backup Vaults Audit Checker
===============================

This module adds two governance-oriented checks for AWS Backup vaults:

1) aws.backup.vaults.no.lifecycle
   IMPORTANT NOTE (AWS reality):
   AWS Backup retention "lifecycle" (cold storage / delete after) is defined on
   *backup plan rules*, not on vaults. However, AWS Backup provides a vault-level
   retention guardrail called **Vault Lock** (min/max retention).
   This check uses the Vault Lock fields returned by `DescribeBackupVault`
   (Locked / MinRetentionDays / MaxRetentionDays) and flags vaults that lack
   guardrails or effectively allow indefinite retention.

   Detects:
     - Vaults with no Vault Lock fields present (no retention guardrail).
     - Vaults with MaxRetentionDays missing/zero (allows "never delete").
     - Vault Lock values inconsistent with org standards (optional thresholds).

   FinOps enhancement:
     - For the "no max retention" case, attaches a best-effort estimate of the
       *current* recovery point storage cost in the vault (warm/cold), using
       PricingService when available.

2) aws.backup.vaults.access.policy.misconfig
   Detects common misconfigurations in backup vault access policies:
     - No access policy (low signal, but useful governance gap)
     - Wildcard principals in Allow statements ("*" or {"AWS":"*"})
     - Cross-account principals not in an allowlist (bootstrap-configurable)
     - Broad destructive permissions granted to non-allowlisted principals

   Security nuance:
     - If a wildcard principal is constrained by aws:PrincipalOrgID, severity is
       downgraded (still risky, but materially less than public "*").

Design notes
------------
- Uses only AWS Backup APIs (boto3 "backup" client).
- Produces FindingDraft objects compatible with the engine contract.
- Graceful degradation: on permission errors, emits a single INFO finding and stops.

Permissions required (minimum):
- backup:ListBackupVaults
- backup:DescribeBackupVault
- backup:GetBackupVaultAccessPolicy
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.aws._common import (
    AwsAccountContext,
    PricingResolver,
    build_scope,
    get_logger,
    money,
    paginate_items,
    safe_region_from_client,
)
from checks.aws.defaults import BACKUP_VAULTS_COLD_FALLBACK_USD, BACKUP_VAULTS_WARM_FALLBACK_USD
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import FindingDraft, RunContext, Scope, Severity

# Logger for this module
_LOGGER = get_logger("backup_vaults_audit")


# Actions that are generally high-impact if granted broadly.
_SENSITIVE_ACTIONS: set[str] = {
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _pricing_backup_gb_month_price(
    ctx: Any,
    *,
    region: str,
    storage_class: str,
    fallback_usd: float,
) -> tuple[float, str, int]:
    """Best-effort lookup of AWS Backup storage $/GB-month.

    Uses ctx.services.pricing if available. Falls back to provided default price.

    Returns: (unit_price_usd, notes, confidence)
    """
    return PricingResolver(ctx).resolve_backup_storage_price(
        region=region,
        storage_class=storage_class,
        fallback_usd=fallback_usd,
        method_names=(
            "backup_storage_gb_month",
            "backup_storage_gb_month_price",
            "backup_gb_month_price",
            "aws_backup_storage_gb_month_price",
            "aws_backup_gb_month_price",
        ),
        kwargs_variants=(
            {"region": "{region}", "storage_class": "{storage_class}"},
            {"region": "{region}", "storage_class": "{tier}"},
            {"region": "{region}", "tier": "{tier}"},
        ),
        args_variants=(("{region}", "{storage_class}"), ("{region}", "{tier}")),
        resolved_confidence=70,
        fallback_confidence_when_no_service=0,
        fallback_confidence_when_lookup_fails=0,
        no_service_note="Fallback pricing (no PricingService)",
        lookup_failed_note="Fallback pricing (PricingService unavailable/unknown)",
        resolved_note_template="PricingService ({method_name})",
    )


def _parse_account_id_from_principal(principal: str) -> str | None:
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


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_action(action: Any) -> set[str]:
    """Action can be a string or list; normalize to lowercase set."""
    actions: set[str] = set()
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


def _extract_principals(principal: Any) -> list[str]:
    """Return a list of principal strings (best-effort)."""
    principals: list[str] = []
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


def _extract_org_ids_from_condition(condition: Any) -> list[str]:
    """Best-effort extraction of aws:PrincipalOrgID values from a policy Condition."""
    if not isinstance(condition, dict):
        return []

    org_ids: list[str] = []
    for op in (
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    ):
        block = condition.get(op)
        if not isinstance(block, dict):
            continue
        val = block.get("aws:PrincipalOrgID")
        if val is None:
            continue
        for x in _as_list(val):
            s = str(x or "").strip()
            if s:
                org_ids.append(s)

    # de-dupe, keep order
    seen: set[str] = set()
    out: list[str] = []
    for x in org_ids:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


class AwsBackupVaultsAuditChecker:
    """
    One checker module, two check_id outputs:
      - aws.backup.vaults.no.lifecycle
      - aws.backup.vaults.access.policy.misconfig
    """

    checker_id = "aws.backup.vaults.audit"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        expected_lock_min_days: int | None = None,
        expected_lock_max_days: int | None = None,
        allowed_cross_account_ids: set[str] | None = None,
    ) -> None:
        self._account = account
        self._expected_lock_min_days = expected_lock_min_days
        self._expected_lock_max_days = expected_lock_max_days
        self._allowed_cross_account_ids = allowed_cross_account_ids or set()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting AWS Backup vaults audit check")
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "backup", None):
            raise RuntimeError("AwsBackupVaultsAuditChecker requires ctx.services.backup")

        backup: BaseClient = ctx.services.backup
        region = safe_region_from_client(backup)
        _LOGGER.debug("Backup vaults check running", extra={"region": region})

        try:
            vaults = list(paginate_items(backup, "list_backup_vaults", "BackupVaultList"))
        except ClientError as exc:
            yield self._access_error_finding(ctx, region, "list_backup_vaults", exc)
            return

        _LOGGER.info("Listed Backup vaults", extra={"count": len(vaults), "region": region})

        # Per-vault evaluation:
        # 1) Vault Lock / lifecycle guardrail
        # 2) Access policy (only if lifecycle is OK)
        for v in vaults:
            try:
                lock_findings = list(self._check_vault_lock(ctx, backup, region, v))
            except ClientError as exc:
                # Single access_error and stop on describe_backup_vault failure
                yield self._access_error_finding(ctx, region, "describe_backup_vault", exc)
                return

            if lock_findings:
                yield from lock_findings
                # If retention guardrail is failing, do not emit policy findings too
                continue

            try:
                yield from self._check_access_policy(ctx, backup, region, v)
            except ClientError as exc:
                yield self._access_error_finding(ctx, region, "get_backup_vault_access_policy", exc)
                return

    # ------------------------------ Check 1: Vault Lock ------------------------------ #

    def _check_vault_lock(
        self,
        ctx,
        backup: BaseClient,
        region: str,
        vault: dict[str, Any],
    ) -> Iterable[FindingDraft]:
        """
        Vault Lock / retention guardrails.

        Uses canonical check_id 'aws.backup.vaults.no.lifecycle'.
        """
        vault_name = str(vault.get("BackupVaultName") or "unknown")
        vault_arn = str(vault.get("BackupVaultArn") or "")

        # Let ClientError bubble to run() so "single access_error and stop" keeps passing.
        desc = backup.describe_backup_vault(BackupVaultName=vault_name)
        vlc = desc.get("VaultLockConfiguration") or {}

        locked_flag = desc.get("Locked", vlc.get("Locked"))
        min_days_raw = vlc.get("MinRetentionDays", desc.get("MinRetentionDays"))
        max_days_raw = vlc.get("MaxRetentionDays", desc.get("MaxRetentionDays"))

        min_days = _safe_int(min_days_raw) or 0
        max_days = _safe_int(max_days_raw) or 0

        # Case 1: no Vault Lock configured at all
        no_lock_fields = locked_flag is None and min_days_raw is None and max_days_raw is None

        # Configured but ineffective (no guardrail)
        disabled_guardrail = locked_flag is False and min_days == 0 and max_days == 0

        # Case 2: no max retention => indefinite retention risk
        no_max = max_days <= 0

        # "Standard" expectations: enforce only when provided.
        expected_min = _safe_int(getattr(self, "_expected_lock_min_days", None)) or 0
        expected_max = _safe_int(getattr(self, "_expected_lock_max_days", None)) or 0

        out_of_standard = False
        if expected_min > 0 and min_days < expected_min:
            out_of_standard = True
        if expected_max > 0 and max_days > expected_max:
            out_of_standard = True

        if not (no_lock_fields or disabled_guardrail or no_max or out_of_standard):
            return

        # Rule mapping (tests may assert these exact strings)
        if no_lock_fields or disabled_guardrail:
            rule = "vault_lock_missing"
        elif no_max:
            rule = "vault_lock_no_max"
        else:
            rule = "vault_lock_out_of_standard"

        # (2) Attach best-effort monthly storage cost estimate for "no max retention"
        est_cost: float | None = None
        est_notes: str = ""
        est_conf: int = 0
        if rule == "vault_lock_no_max":
            est_cost, est_notes, est_conf = self._estimate_vault_monthly_storage_cost(
                ctx,
                backup,
                region=region,
                vault_name=vault_name,
            )

        est_cost_str = ""
        if est_cost is not None:
            try:
                est_cost_rounded = money(float(est_cost))
                est_cost_str = f"${est_cost_rounded:,.2f}"
            except (TypeError, ValueError, OverflowError):
                est_cost_str = ""

        # Severity mapping: out_of_standard is low, everything else medium
        severity = (
            Severity(level="low", score=40)
            if rule == "vault_lock_out_of_standard"
            else Severity(level="medium", score=70)
        )

        if rule == "vault_lock_missing":
            if no_lock_fields:
                reason = "Vault Lock is not configured."
            else:
                reason = "Vault Lock is configured but ineffective (Locked=False and min/max retention are 0)."
        elif rule == "vault_lock_no_max":
            reason = "Vault Lock does not enforce a maximum retention (MaxRetentionDays is missing/0)."
        else:
            reason = (
                "Vault Lock retention does not match the expected standard "
                f"(min={min_days}, max={max_days}, expected_min={expected_min or 'n/a'}, expected_max={expected_max or 'n/a'})."
            )

        cost_suffix = ""
        if rule == "vault_lock_no_max" and est_cost_str:
            cost_suffix = f" Observed recovery point storage estimate: {est_cost_str}/month."

        yield FindingDraft(
            check_id="aws.backup.vaults.no.lifecycle",
            check_name="AWS Backup vault retention guardrails",
            category="backup.governance",
            status="fail",
            severity=severity,
            title="Backup vault has no effective retention guardrail",
            message=(
                f"Backup vault '{vault_name}' has no effective retention guardrail. {reason} "
                "Retention may drift to indefinite accumulation."
                f"{cost_suffix}"
            ),
            recommendation=(
                "Configure Vault Lock with explicit minimum and maximum retention aligned with policy "
                "(or adjust expected min/max thresholds)."
            ),
            scope=self._base_scope(
                ctx,
                region=region,
                resource_type="backup_vault",
                resource_id=vault_name,
                resource_arn=vault_arn,
            ),
            issue_key={
                "rule": rule,
                "vault": vault_name,
            },
            dimensions={
                "vault_arn": vault_arn,
                "locked": str(locked_flag),
                "min_retention_days": str(min_days),
                "max_retention_days": str(max_days),
            },
            estimated_monthly_cost=est_cost,
            estimated_monthly_savings=None,
            estimate_confidence=int(est_conf or 0),
            estimate_notes=str(est_notes or ""),
        )

    # ------------------------------ Check 2: Access Policy ------------------------------ #

    def _check_access_policy(
        self,
        ctx,
        backup: BaseClient,
        region: str,
        vault: dict[str, Any],
    ) -> Iterable[FindingDraft]:
        vault_name = str(vault.get("BackupVaultName") or "")
        vault_arn = str(vault.get("BackupVaultArn") or "")
        if not vault_name:
            return

        # --- helpers local to this method ---
        def _resource_mentions_vault(resource: Any, arn: str) -> bool:
            if not arn:
                return False
            for r in _as_list(resource):
                s = str(r or "").strip()
                if not s:
                    continue
                if s == "*" or s == arn:
                    return True
                if arn in s:
                    return True
            return False

        def _is_resource_star(resource: Any) -> bool:
            for r in _as_list(resource):
                if str(r or "").strip() == "*":
                    return True
            return False

        def _matches_action_pattern(action: str, pattern: str) -> bool:
            a = str(action or "").strip().lower()
            p = str(pattern or "").strip().lower()
            if not p:
                return False
            if p == "*":
                return True
            if p.endswith("*"):
                return a.startswith(p[:-1])
            return a == p

        def _has_sensitive_action(actions: set[str]) -> bool:
            for a in actions:
                for pat in _SENSITIVE_ACTIONS:
                    if _matches_action_pattern(a, pat):
                        return True
            return False

        def _matched_sensitive_actions(actions: set[str]) -> list[str]:
            out: list[str] = []
            for a in sorted(actions):
                if any(_matches_action_pattern(a, pat) for pat in _SENSITIVE_ACTIONS):
                    out.append(a)
            return out

        # --- fetch policy ---
        try:
            resp = backup.get_backup_vault_access_policy(BackupVaultName=vault_name) or {}
            policy_str = str(resp.get("Policy") or "").strip()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "ResourceNotFound"}:
                # No access policy exists
                yield FindingDraft(
                    check_id="aws.backup.vaults.access.policy.misconfig",
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
            yield FindingDraft(
                check_id="aws.backup.vaults.access.policy.misconfig",
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
                check_id="aws.backup.vaults.access.policy.misconfig",
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

        worst: FindingDraft | None = None

        for st in statements:
            if not isinstance(st, dict):
                continue

            effect = str(st.get("Effect") or "").strip().lower()
            if effect != "allow":
                continue

            sid = str(st.get("Sid") or "")
            principal = st.get("Principal")
            not_principal = st.get("NotPrincipal")
            actions = _normalize_action(st.get("Action"))
            resource = st.get("Resource")
            condition = st.get("Condition")

            # --- 0) NotPrincipal: we don't fully interpret it; surface as info to avoid silent misses.
            if not_principal is not None:
                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access.policy.misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="governance",
                    status="info",
                    severity=Severity(level="low", score=20),
                    title="Backup vault access policy uses NotPrincipal",
                    message=(
                        f"Backup vault '{vault_name}' access policy contains an Allow statement using NotPrincipal. "
                        "This checker does not fully evaluate NotPrincipal semantics; please review the statement manually."
                    ),
                    recommendation="Review the NotPrincipal statement to ensure access is correctly restricted.",
                    scope=self._base_scope(
                        ctx,
                        region=region,
                        resource_type="backup_vault",
                        resource_id=vault_name,
                        resource_arn=vault_arn,
                    ),
                    issue_key={"rule": "uses_notprincipal", "vault": vault_name, "sid": sid},
                    dimensions={"vault_arn": vault_arn, "sid": sid},
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="NotPrincipal is not evaluated by this checker.",
                )
                worst = self._pick_worst(worst, candidate)
                continue

            # --- 1) Wildcard principal: ALWAYS highest priority (but downgrade slightly with OrgID condition or non-vault resource)
            if _principal_is_wildcard(principal):
                org_ids = _extract_org_ids_from_condition(condition)
                has_org = bool(org_ids)

                resource_star = _is_resource_star(resource)
                mentions_vault = _resource_mentions_vault(resource, vault_arn)

                # Base severity: very high
                sev = Severity(level="high", score=95)

                # If constrained by Org, reduce (still higher than cross-account and broad actions)
                if has_org:
                    sev = Severity(level="medium", score=85)

                # If resource is not "*" and doesn't even mention this vault ARN, treat as less directly relevant
                # (but still a governance smell).
                if (resource is not None) and (not resource_star) and (not mentions_vault):
                    if has_org:
                        sev = Severity(level="low", score=45)
                    else:
                        sev = Severity(level="medium", score=65)

                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access.policy.misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="security",
                    status="fail",
                    severity=sev,
                    title="Backup vault access policy allows wildcard principal",
                    message=(
                        f"Backup vault '{vault_name}' access policy contains an Allow statement with wildcard "
                        "principal ('*'). This is overly permissive."
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
                        "resource": ",".join(str(x) for x in _as_list(resource)) if resource is not None else "",
                        "has_org_condition": "true" if has_org else "false",
                        "org_ids": ",".join(org_ids),
                    },
                    estimated_monthly_cost=None,
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes="Security/governance risk; not a direct cost estimate.",
                )
                worst = self._pick_worst(worst, candidate)
                # CRITICAL: do not fall through to other checks for the same statement
                continue

            # --- 2) Cross-account principals (not in allowlist)
            principals = _extract_principals(principal)
            cross_accounts: set[str] = set()
            for p in principals:
                acct = _parse_account_id_from_principal(p)
                if acct and acct != self._account.account_id and acct not in self._allowed_cross_account_ids:
                    cross_accounts.add(acct)

            has_sensitive = _has_sensitive_action(actions)

            if cross_accounts:
                sev = Severity(level="high", score=80) if has_sensitive else Severity(level="medium", score=70)
                title = "Backup vault access policy allows cross-account access"
                if has_sensitive:
                    title = "Backup vault access policy grants broad sensitive permissions cross-account"

                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access.policy.misconfig",
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

            # --- 3) Broad sensitive actions (even without cross-account)
            if has_sensitive and principals:
                matched = _matched_sensitive_actions(actions)
                candidate = FindingDraft(
                    check_id="aws.backup.vaults.access.policy.misconfig",
                    check_name="AWS Backup vault access policy misconfiguration",
                    category="security",
                    status="fail",
                    severity=Severity(level="medium", score=65),
                    title="Backup vault access policy grants broad sensitive permissions",
                    message=(
                        f"Backup vault '{vault_name}' access policy includes sensitive actions "
                        f"({', '.join(matched) if matched else ', '.join(sorted(actions))})."
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


    def _pick_worst(self, current: FindingDraft | None, candidate: FindingDraft) -> FindingDraft:
        if current is None:
            return candidate

        cur = int(current.severity.score)
        new = int(candidate.severity.score)

        if new > cur:
            return candidate

        if new == cur:
            # deterministic tie-break: prefer wildcard principal rule
            cur_rule = str(getattr(current, "issue_key", {}).get("rule", ""))
            new_rule = str(getattr(candidate, "issue_key", {}).get("rule", ""))
            if new_rule == "wildcard_principal" and cur_rule != "wildcard_principal":
                return candidate

        return current

    def _estimate_vault_monthly_storage_cost(
        self,
        ctx: Any,
        backup: BaseClient,
        *,
        region: str,
        vault_name: str,
        warm_fallback_usd: float = BACKUP_VAULTS_WARM_FALLBACK_USD,
        cold_fallback_usd: float = BACKUP_VAULTS_COLD_FALLBACK_USD,
    ) -> tuple[float | None, str, int]:
        """Estimate monthly storage cost for recovery points currently in a vault.

        Best-effort only:
          - enumerates recovery points via ListRecoveryPointsByBackupVault
          - sums bytes by StorageClass (WARM/COLD)
          - applies PricingService unit prices when available, else fallbacks

        Returns (monthly_cost_usd | None, notes, confidence).
        """
        total_warm_bytes = 0
        total_cold_bytes = 0
        try:
            for rp in paginate_items(
                backup,
                "list_recovery_points_by_backup_vault",
                "RecoveryPoints",
                params={"BackupVaultName": vault_name},
            ):
                storage_class = str(rp.get("StorageClass") or "WARM").upper()
                size_bytes = rp.get("BackupSizeInBytes")
                try:
                    b = int(size_bytes or 0)
                except (TypeError, ValueError):
                    b = 0
                if b <= 0:
                    continue
                if storage_class == "COLD":
                    total_cold_bytes += b
                else:
                    total_warm_bytes += b
        except ClientError:
            return None, "Unable to enumerate recovery points", 0
        except (AttributeError, TypeError, ValueError):  # pragma: no cover
            return None, "Unable to enumerate recovery points", 0

        gb_warm = float(total_warm_bytes) / (1024.0**3)
        gb_cold = float(total_cold_bytes) / (1024.0**3)
        if gb_warm <= 0.0 and gb_cold <= 0.0:
            return 0.0, "No recovery point storage observed", 20

        warm_unit, warm_notes, warm_conf = _pricing_backup_gb_month_price(
            ctx,
            region=region,
            storage_class="WARM",
            fallback_usd=warm_fallback_usd,
        )
        cold_unit, cold_notes, cold_conf = _pricing_backup_gb_month_price(
            ctx,
            region=region,
            storage_class="COLD",
            fallback_usd=cold_fallback_usd,
        )

        cost = gb_warm * warm_unit + gb_cold * cold_unit
        notes = f"{warm_notes}; {cold_notes}; warm_gb={gb_warm:.3f} cold_gb={gb_cold:.3f}"
        confidence = min(100, max(warm_conf, cold_conf))
        return cost, notes, confidence

    # ------------------------------ Helpers ------------------------------ #

    def _access_error_finding(self, ctx, region: str, operation: str, exc: ClientError) -> FindingDraft:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return FindingDraft(
            check_id="aws.backup.access.error",
            check_name="AWS Backup access error",
            category="inventory",
            status="info",
            severity=Severity(level="low", score=10),
            title="Unable to enumerate AWS Backup vault inventory",
            message=f"Failed to call {operation} ({code}). Some AWS Backup vault checks were skipped.",
            recommendation="Grant AWS Backup read permissions for vault listing, describe, and access policies.",
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


@register_checker("checks.aws.backup_vaults_audit:AwsBackupVaultsAuditChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> AwsBackupVaultsAuditChecker:
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
    allowlist: set[str] = set()
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
