"""Unit tests for the AWS Backup Plans audit checker."""

# tests/test_backup_plans_audit.py
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from checks.aws.backup_plans_audit import AwsAccountContext, AwsBackupPlansAuditChecker
from tests.aws_mocks import FakeBackupClient, make_run_ctx


def _mk_checker(
    *,
    stale_days: int = 90,
    warm_price: float = 0.05,
    cold_price: float = 0.01,
    skip_if_deleting_within_days: int = 14,
) -> AwsBackupPlansAuditChecker:
    return AwsBackupPlansAuditChecker(
        account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"),
        stale_days=stale_days,
        warm_gb_month_price_usd=warm_price,
        cold_gb_month_price_usd=cold_price,
        skip_if_deleting_within_days=skip_if_deleting_within_days,
    )


# -------------------------
# Tests: Plans without selections
# -------------------------

def test_plan_without_selections_emits_finding():
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-1", "BackupPlanName": "plan-one"}]
    selections_by_plan = {"p-1": []}  # no selections

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id={},
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert any(f.check_id == "aws.backup.plans.no.selections" for f in findings)
    f = [x for x in findings if x.check_id == "aws.backup.plans.no.selections"][0]
    assert f.issue_key["plan_id"] == "p-1"
    assert f.status == "fail"


def test_plan_with_selections_is_ok_no_finding():
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-2", "BackupPlanName": "plan-two"}]
    selections_by_plan = {"p-2": [{"SelectionId": "s-1"}]}

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.plans.no.selections" for f in findings)


# -------------------------
# Tests: Rules missing lifecycle
# -------------------------

def test_rule_missing_lifecycle_emits_finding():
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-3", "BackupPlanName": "plan-three"}]
    selections_by_plan = {"p-3": [{"SelectionId": "s-1"}]}  # ensure plan isn't flagged for selections
    plan_detail_by_id = {
        "p-3": {
            "Rules": [
                {"RuleName": "daily", "Lifecycle": {}},
            ]
        }
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert any(f.check_id == "aws.backup.rules.no.lifecycle" for f in findings)
    f = [x for x in findings if x.check_id == "aws.backup.rules.no.lifecycle"][0]
    assert f.issue_key["plan_id"] == "p-3"
    assert f.issue_key["rule_name"] == "daily"


def test_rule_with_delete_after_is_ok():
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-4", "BackupPlanName": "plan-four"}]
    selections_by_plan = {"p-4": [{"SelectionId": "s-1"}]}
    plan_detail_by_id = {
        "p-4": {
            "Rules": [
                {"RuleName": "daily", "Lifecycle": {"DeleteAfterDays": 30}},
            ]
        }
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.rules.no.lifecycle" for f in findings)


# -------------------------
# Tests: Stale recovery points
# -------------------------

def test_stale_recovery_point_emits_finding_and_estimates_cost():
    checker = _mk_checker(stale_days=30, warm_price=0.05, cold_price=0.01)

    plans = [{"BackupPlanId": "p-5", "BackupPlanName": "plan-five"}]
    selections_by_plan = {"p-5": [{"SelectionId": "s-1"}]}
    plan_detail_by_id = {"p-5": {"Rules": []}}

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(UTC) - timedelta(days=60)

    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-1",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,  # 1 GiB
        "ResourceType": "EBS",
        "ResourceArn": "arn:aws:ec2:eu-west-1:111111111111:volume/vol-1",
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    stale = [x for x in findings if x.check_id == "aws.backup.recovery.points.stale"]
    assert len(stale) == 1

    f = stale[0]
    assert f.estimated_monthly_cost is not None
    assert float(f.estimated_monthly_cost) == pytest.approx(0.05, abs=0.01)
    assert f.estimate_confidence is not None


def test_recovery_point_recent_is_not_emitted():
    checker = _mk_checker(stale_days=30)

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(UTC) - timedelta(days=10)
    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-2",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=[],
        selections_by_plan={},
        plan_detail_by_id={},
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.recovery.points.stale" for f in findings)


def test_recovery_point_deleting_soon_is_skipped():
    checker = _mk_checker(stale_days=30, skip_if_deleting_within_days=14)

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(UTC) - timedelta(days=60)
    delete_at = datetime.now(UTC) + timedelta(days=7)

    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-3",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,
        "CalculatedLifecycle": {"DeleteAt": delete_at},
    }

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=[],
        selections_by_plan={},
        plan_detail_by_id={},
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.recovery.points.stale" for f in findings)


# -------------------------
# Tests: Access errors
# -------------------------

def test_access_error_on_list_backup_plans_emits_single_info_and_stops():
    checker = _mk_checker()
    backup = FakeBackupClient(region="eu-west-1", raise_on="list_backup_plans")
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access.error"
    assert findings[0].status == "info"


def test_access_error_on_get_backup_plan_emits_access_error():
    """
    In the checker, the 'plans without selections' stage runs before 'get_backup_plan'.
    So depending on input, you may get findings from stage 1 before the access error occurs.

    We ensure stage 1 produces no finding by providing a selection,
    then expect exactly one access_error finding.
    """
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-1", "BackupPlanName": "plan-one"}]
    selections_by_plan = {"p-1": [{"SelectionId": "s-1"}]}  # stage 1 should NOT emit no_selections

    backup = FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id={},
        raise_on="get_backup_plan",
    )
    ctx = make_run_ctx(backup=backup)

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access.error"
    assert findings[0].status == "info"

