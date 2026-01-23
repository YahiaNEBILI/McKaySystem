# tests/test_backup_vaults_audit.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import json
from botocore.exceptions import ClientError

from checks.aws.backup_vaults_audit import AwsAccountContext, AwsBackupVaultsAuditChecker


class _FakePaginator:
    def __init__(self, pages: List[Dict[str, Any]]):
        self._pages = pages

    def paginate(self, **_kwargs) -> Iterable[Dict[str, Any]]:
        yield from self._pages


class _FakeBackupClient:
    """
    Fake backup client with both paginator and direct-call methods, to match
    _paginate_items() behavior (it may fall back to direct call).
    """

    def __init__(
        self,
        *,
        region: str,
        vaults: Optional[List[Dict[str, Any]]] = None,
        describe_by_name: Optional[Dict[str, Dict[str, Any]]] = None,
        policy_by_name: Optional[Dict[str, Any]] = None,
        raise_on: Optional[str] = None,
        raise_code: str = "AccessDeniedException",
    ):
        self.meta = type("Meta", (), {"region_name": region})()
        self._vaults = vaults or []
        self._describe_by_name = describe_by_name or {}
        self._policy_by_name = policy_by_name or {}
        self._raise_on = raise_on
        self._raise_code = raise_code

    # ------------- paginator -------------
    def get_paginator(self, op: str) -> _FakePaginator:
        if self._raise_on == op:
            raise ClientError({"Error": {"Code": self._raise_code, "Message": "Denied"}}, op)

        if op == "list_backup_vaults":
            return _FakePaginator([{"BackupVaultList": self._vaults}])

        raise AssertionError(f"Unexpected paginator op: {op}")

    # ------------- direct calls (fallback path in _paginate_items) -------------

    def list_backup_vaults(self, **_kwargs) -> Dict[str, Any]:
        if self._raise_on == "list_backup_vaults":
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}},
                "list_backup_vaults",
            )
        # minimal NextToken-compatible shape
        return {"BackupVaultList": self._vaults}

    def describe_backup_vault(self, *, BackupVaultName: str) -> Dict[str, Any]:
        if self._raise_on == "describe_backup_vault":
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}},
                "describe_backup_vault",
            )

        if BackupVaultName not in self._describe_by_name:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "NotFound"}},
                "describe_backup_vault",
            )
        return self._describe_by_name[BackupVaultName]

    def get_backup_vault_access_policy(self, *, BackupVaultName: str) -> Dict[str, Any]:
        if self._raise_on == "get_backup_vault_access_policy":
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}},
                "get_backup_vault_access_policy",
            )

        val = self._policy_by_name.get(BackupVaultName, None)
        if val is None:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "NotFound"}},
                "get_backup_vault_access_policy",
            )
        if isinstance(val, str):
            return {"Policy": val}
        return {"Policy": json.dumps(val)}


@dataclass
class _FakeServices:
    backup: Any
    rds: Any = None
    s3: Any = None


@dataclass
class _FakeCtx:
    cloud: str = "aws"
    services: Any = None


def _mk_checker(
    *,
    expected_min: Optional[int] = None,
    expected_max: Optional[int] = None,
    allowlist: Optional[List[str]] = None,
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
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-a", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-a"}
    ]
    describe = {
        # No Locked/MinRetentionDays/MaxRetentionDays fields => treated as "no vault lock"
        "vault-a": {"BackupVaultName": "vault-a"},
    }
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-a": {}})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no_lifecycle"
    assert f.issue_key["rule"] == "vault_lock_missing"
    assert f.scope.resource_id == "vault-a"


def test_vault_lock_no_max_emits_indefinite_retention():
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-b", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-b"}
    ]
    describe = {
        "vault-b": {"BackupVaultName": "vault-b", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 0},
    }
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-b": {}})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no_lifecycle"
    assert f.issue_key["rule"] == "vault_lock_no_max"
    assert f.severity.level in ("medium", "high")


def test_vault_lock_out_of_standard_emits_low():
    checker = _mk_checker(expected_min=14, expected_max=90)

    vaults = [
        {"BackupVaultName": "vault-c", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-c"}
    ]
    describe = {
        "vault-c": {"BackupVaultName": "vault-c", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 90},
    }
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-c": {}})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.no_lifecycle"
    assert f.issue_key["rule"] == "vault_lock_out_of_standard"
    assert f.severity.level == "low"


# -------------------------
# Tests: Access Policy (access_policy_misconfig)
# -------------------------

def test_access_policy_missing_emits_low_misconfig():
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-d", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-d"}
    ]
    describe = {
        "vault-d": {"BackupVaultName": "vault-d", "Locked": True, "MinRetentionDays": 7, "MaxRetentionDays": 30},
    }
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access_policy_misconfig"
    assert f.issue_key["rule"] == "no_access_policy"
    assert f.severity.level == "low"


def test_access_policy_wildcard_principal_emits_high():
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
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-e": policy})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access_policy_misconfig"
    assert f.issue_key["rule"] == "wildcard_principal"
    assert f.severity.level == "high"


def test_access_policy_cross_account_not_allowlisted_emits_fail():
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
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-f": policy})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "aws.backup.vaults.access_policy_misconfig"
    assert f.issue_key["rule"] == "cross_account_access"
    assert "333333333333" in (f.dimensions.get("cross_account_ids") or "")


def test_access_policy_emits_only_worst_per_vault():
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
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name=describe, policy_by_name={"vault-g": policy})
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].issue_key["rule"] == "wildcard_principal"


# -------------------------
# Tests: Access errors
# -------------------------

def test_list_vaults_access_error_emits_single_info_and_stops():
    checker = _mk_checker()

    # Raise on direct op name ("list_backup_vaults") so both paginator and fallback path fail consistently.
    backup = _FakeBackupClient(region="eu-west-1", raise_on="list_backup_vaults")
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access_error"
    assert findings[0].status == "info"


def test_describe_vault_access_error_emits_single_info_and_stops():
    checker = _mk_checker()

    vaults = [
        {"BackupVaultName": "vault-h", "BackupVaultArn": "arn:aws:backup:eu-west-1:111111111111:backup-vault:vault-h"}
    ]
    backup = _FakeBackupClient(region="eu-west-1", vaults=vaults, describe_by_name={}, policy_by_name={}, raise_on="describe_backup_vault")
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access_error"
    assert findings[0].status == "info"
