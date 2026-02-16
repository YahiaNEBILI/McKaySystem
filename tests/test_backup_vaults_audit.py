"""Unit tests for the AWS Backup Vaults audit checker."""

from __future__ import annotations

from checks.aws._common import AwsAccountContext
from checks.aws.backup_vaults_audit import AwsBackupVaultsAuditChecker
from tests.aws_mocks import FakeBackupClient, make_run_ctx


class _FakePricing:
    """Minimal PricingService stub for backup storage GB-month prices."""

    def __init__(self, *, warm: float | None = None, cold: float | None = None):
        self._warm = warm
        self._cold = cold

    def backup_storage_gb_month(self, *, region: str, storage_class: str) -> float | None:
        _ = region
        sc = str(storage_class).upper()
        if sc == "COLD":
            return self._cold
        return self._warm


def _mk_checker(
    *,
    expected_min: int | None = None,
    expected_max: int | None = None,
    allowlist: list[str] | None = None,
) -> AwsBackupVaultsAuditChecker:
    return AwsBackupVaultsAuditChecker(
        account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"),
        expected_lock_min_days=expected_min,
        expected_lock_max_days=expected_max,
        allowed_cross_account_ids=set(allowlist or []),
    )


# -------------------------
# Tests: Vault Lock (no_lifecycle)
# -------------------------

def test_vault_lock_missing_fields_emits_no_lifecycle():
    """Vault Lock fields absent -> treat as missing retention guardrail (no_lifecycle)."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-a", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-a"}
    ]
    describe = {
        # No Locked/MinRetentionDays/MaxRetentionDays fields => treated as "no vault lock"
        "vault-a": {"BackupVaultName": "vault-a"},
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-a": {}})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no.lifecycle"
    assert f.issue_key["rule"] == "vault_lock_missing"
    assert f.scope.resource_id == "vault-a"


def test_vault_lock_no_max_cost_estimate_enumeration_denied_sets_none():
    """If recovery points cannot be listed, estimated_monthly_cost should be None (unknown)."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-deny", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-deny"}
    ]
    describe = {
        "vault-deny": {"BackupVaultName": "vault-deny", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name=describe,
        policy_by_name={"vault-deny": {}},
        recovery_points_by_vault={"vault-deny": [{"StorageClass": "WARM", "BackupSizeInBytes": 123}]},
        raise_on="list_recovery_points_by_backup_vault",
    )
    ctx = make_run_ctx(backup=backup, pricing=_FakePricing(warm=0.05, cold=0.01))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.issue_key["rule"] == "vault_lock_no_max"
    assert f.estimated_monthly_cost is None
    assert isinstance(f.estimate_confidence, int)
    assert f.estimate_confidence == 0
    assert "Unable to enumerate" in (f.estimate_notes or "")


def test_vault_lock_no_max_cost_estimate_empty_vault_is_zero():
    """If the vault has no recovery points, estimated_monthly_cost should be 0.0 (known empty)."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-empty", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-empty"}
    ]
    describe = {
        "vault-empty": {"BackupVaultName": "vault-empty", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name=describe,
        policy_by_name={"vault-empty": {}},
        recovery_points_by_vault={"vault-empty": []},
    )
    ctx = make_run_ctx(backup=backup, pricing=_FakePricing(warm=0.05, cold=0.01))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.issue_key["rule"] == "vault_lock_no_max"
    assert f.estimated_monthly_cost is not None
    assert float(f.estimated_monthly_cost) == 0.0
    assert isinstance(f.estimate_confidence, int)
    assert f.estimate_confidence == 20
    assert "No recovery point storage observed" in (f.estimate_notes or "")


def test_vault_lock_disabled_zero_zero_emits_missing():
    """Vault Lock present but ineffective (Locked=False, min/max=0) -> treat as missing guardrail."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-a2", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-a2"}
    ]
    describe = {
        "vault-a2": {"BackupVaultName": "vault-a2", "Locked": False, "MinRetentionDays": 0, "MaxRetentionDays": 0},
    }
    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name=describe,
        policy_by_name={"vault-a2": {"Version": "2012-10-17", "Statement": []}},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no.lifecycle"
    assert f.issue_key["rule"] == "vault_lock_missing"
    assert f.scope.resource_id == "vault-a2"


def test_vault_lock_no_max_emits_indefinite_retention():
    """MaxRetentionDays=0 -> indefinite retention risk -> emit no_lifecycle with vault_lock_no_max rule."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-b", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-b"}
    ]
    describe = {
        "vault-b": {"BackupVaultName": "vault-b", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-b": {}})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no.lifecycle"
    assert f.issue_key["rule"] == "vault_lock_no_max"
    assert f.severity.level in ("medium", "high")


def test_vault_lock_no_max_attaches_cost_estimate_with_pricing_service():
    """For vault_lock_no_max, the checker should attach an estimated_monthly_cost (best-effort)."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-cost", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-cost"}
    ]
    describe = {
        "vault-cost": {"BackupVaultName": "vault-cost", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }

    gib = 1024 ** 3
    recovery_points_by_vault = {
        "vault-cost": [
            {"StorageClass": "WARM", "BackupSizeInBytes": 10 * gib},  # 10 GiB
            {"StorageClass": "COLD", "BackupSizeInBytes": 5 * gib},   # 5 GiB
        ]
    }

    pricing = _FakePricing(warm=0.05, cold=0.01)  # $/GB-month
    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name=describe,
        policy_by_name={"vault-cost": {}},
        recovery_points_by_vault=recovery_points_by_vault,
    )
    ctx = make_run_ctx(backup=backup, pricing=pricing)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no.lifecycle"
    assert f.issue_key["rule"] == "vault_lock_no_max"

    # Expected: 10 * 0.05 + 5 * 0.01 = 0.50 + 0.05 = 0.55
    assert f.estimated_monthly_cost is not None
    assert round(float(f.estimated_monthly_cost), 2) == 0.55
    assert f.estimate_confidence is not None
    assert isinstance(f.estimate_confidence, int)
    assert f.estimate_confidence >= 1
    assert "PricingService" in (f.estimate_notes or "")


def test_vault_lock_no_max_ignores_malformed_recovery_point_size():
    """Malformed BackupSizeInBytes should be ignored (not crash), valid points still counted."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-bad-size", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-bad-size"}
    ]
    describe = {
        "vault-bad-size": {"BackupVaultName": "vault-bad-size", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }
    gib = 1024 ** 3
    recovery_points_by_vault = {
        "vault-bad-size": [
            {"StorageClass": "WARM", "BackupSizeInBytes": "invalid-size"},
            {"StorageClass": "WARM", "BackupSizeInBytes": 2 * gib},
        ]
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name=describe,
        policy_by_name={"vault-bad-size": {}},
        recovery_points_by_vault=recovery_points_by_vault,
    )
    ctx = make_run_ctx(backup=backup, pricing=_FakePricing(warm=0.05, cold=0.01))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.issue_key["rule"] == "vault_lock_no_max"
    assert float(f.estimated_monthly_cost or 0.0) == 0.10


def test_vault_lock_out_of_standard_emits_low():
    """Configured Vault Lock that violates expected min/max -> emit low severity out_of_standard finding."""
    checker = _mk_checker(expected_min=14, expected_max=90)

    vaults = [
        {"BackupVaultName": "vault-c", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-c"}
    ]
    describe = {
        "vault-c": {"BackupVaultName": "vault-c", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 90},
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-c": {}})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no.lifecycle"
    assert f.issue_key["rule"] == "vault_lock_out_of_standard"
    assert f.severity.level == "low"

# -------------------------
# Tests: Access Policy (access_policy_misconfig)
# -------------------------


def test_access_policy_notprincipal_emits_info():
    checker = _mk_checker()

    vaults = [{"BackupVaultName": "vault-np", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-np"}]
    describe = {"vault-np": {"BackupVaultName": "vault-np", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30}}

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "NP", "Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::333333333333:root"}, "Action": "backup:*", "Resource": "*"},
        ],
    }

    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-np": policy})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access.policy.misconfig"
    assert f.status == "info"
    assert f.issue_key["rule"] == "uses_notprincipal"


def test_access_policy_missing_emits_low_misconfig():
    """When lifecycle is OK but access policy is missing -> emit low access_policy_misconfig."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-d", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-d"}
    ]
    describe = {
        "vault-d": {"BackupVaultName": "vault-d", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access.policy.misconfig"
    assert f.issue_key["rule"] == "no_access_policy"
    assert f.severity.level == "low"


def test_access_policy_wildcard_principal_emits_high():
    """Wildcard principal in access policy should be flagged as high severity misconfiguration."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-e", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-e"}
    ]
    describe = {
        "vault-e": {"BackupVaultName": "vault-e", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "S1", "Effect": "Allow", "Principal": "*", "Action": "backup:*", "Resource": "*"},
        ],
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-e": policy})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access.policy.misconfig"
    assert f.issue_key["rule"] == "wildcard_principal"
    assert f.severity.level == "high"
    assert (f.dimensions.get("has_org_condition") or "false") == "false"


def test_access_policy_wildcard_principal_with_org_condition_downgrades():
    """Wildcard principal constrained by aws:PrincipalOrgID should be downgraded (still fail)."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-org", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-org"}
    ]
    describe = {
        "vault-org": {"BackupVaultName": "vault-org", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S1",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "backup:*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            },
        ],
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-org": policy})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access.policy.misconfig"
    assert f.issue_key["rule"] == "wildcard_principal"
    assert f.severity.level in ("medium", "high")  # your checker downgrades to medium
    assert (f.dimensions.get("has_org_condition") or "false") == "true"
    assert "o-1234567890" in (f.dimensions.get("org_ids") or "")


def test_access_policy_cross_account_not_allowlisted_emits_fail():
    """Cross-account access not in allowlist should emit fail with cross_account_access rule."""
    checker = _mk_checker(allowlist=["222222222222"])

    vaults = [
        {"BackupVaultName": "vault-f", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-f"}
    ]
    describe = {
        "vault-f": {"BackupVaultName": "vault-f", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Cross1",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::333333333333:root"},
                "Action": ["backup:DeleteRecoveryPoint"],
                "Resource": "*",
            }
        ],
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-f": policy})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access.policy.misconfig"
    assert f.issue_key["rule"] == "cross_account_access"
    assert "333333333333" in (f.dimensions.get("cross_account_ids") or "")


def test_access_policy_emits_only_worst_per_vault():
    """If multiple policy issues exist, only the worst finding should be emitted per vault."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-g", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-g"}
    ]
    describe = {
        "vault-g": {"BackupVaultName": "vault-g", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Cross",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::333333333333:root"},
                "Action": ["backup:ListBackupJobs"],
                "Resource": "*",
            },
            {"Sid": "Wild", "Effect": "Allow", "Principal": "*", "Action": "backup:*", "Resource": "*"},
        ],
    }
    backup = FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-g": policy})
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].issue_key["rule"] == "wildcard_principal"


# -------------------------
# Tests: Access errors
# -------------------------

def test_list_vaults_access_error_emits_single_info_and_stops():
    """Access denied listing vaults -> emit single info access_error and stop."""
    checker = _mk_checker()

    backup = FakeBackupClient(region="eu-west-1", raise_on="list_backup_vaults")
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access.error"
    assert findings[0].status == "info"


def test_describe_vault_access_error_emits_single_info_and_stops():
    """Access denied describing a vault -> emit single info access_error and stop."""
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-h", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-h"}
    ]
    backup = FakeBackupClient(
        region="eu-west-1",
        vaults=vaults,
        describe_by_name={},
        policy_by_name={},
        raise_on="describe_backup_vault",
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access.error"
    assert findings[0].status == "info"

