# tests/test_backup_plans_audit.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

import json
import pytest
from botocore.exceptions import ClientError

from checks.aws.backup_plans_audit import AwsAccountContext, AwsBackupPlansAuditChecker


# -------------------------
# Minimal fakes (no boto3)
# -------------------------

class _FakePaginator:
    def __init__(self, op: str, client: "_FakeBackupClient"):
        self._op = op
        self._client = client

    def paginate(self, **kwargs) -> Iterable[Dict[str, Any]]:
        op = self._op

        if op == "list_backup_plans":
            yield {"BackupPlansList": self._client._plans}
            return

        if op == "list_backup_selections":
            plan_id = str(kwargs.get("BackupPlanId") or "")
            yield {"BackupSelectionsList": self._client._selections_by_plan.get(plan_id, [])}
            return

        if op == "list_backup_vaults":
            yield {"BackupVaultList": self._client._vaults}
            return

        if op == "list_recovery_points_by_backup_vault":
            vault_name = str(kwargs.get("BackupVaultName") or "")
            yield {"RecoveryPoints": self._client._recovery_points_by_vault.get(vault_name, [])}
            return

        raise AssertionError(f"Unexpected paginate op: {op}")


class _FakeBackupClient:
    """
    Fake backup client covering all operations used by AwsBackupPlansAuditChecker.

    IMPORTANT:
    The checker uses `_paginate_items()` which prefers paginators.
    So our fake paginator MUST return per-kwargs results.
    """

    def __init__(
        self,
        *,
        region: str,
        plans: Optional[List[Dict[str, Any]]] = None,
        selections_by_plan: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        plan_detail_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
        vaults: Optional[List[Dict[str, Any]]] = None,
        recovery_points_by_vault: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        raise_on: Optional[str] = None,
        raise_code: str = "AccessDeniedException",
    ) -> None:
        self.meta = type("Meta", (), {"region_name": region})()
        self._plans = plans or []
        self._selections_by_plan = selections_by_plan or {}
        self._plan_detail_by_id = plan_detail_by_id or {}
        self._vaults = vaults or []
        self._recovery_points_by_vault = recovery_points_by_vault or {}
        self._raise_on = raise_on
        self._raise_code = raise_code

    def get_paginator(self, op: str) -> _FakePaginator:
        if self._raise_on == op:
            raise ClientError({"Error": {"Code": self._raise_code, "Message": "Denied"}}, op)
        return _FakePaginator(op, self)

    # direct-call fallbacks (in case paginator path fails)
    def list_backup_plans(self, **_kwargs) -> Dict[str, Any]:
        if self._raise_on == "list_backup_plans":
            raise ClientError({"Error": {"Code": self._raise_code, "Message": "Denied"}}, "list_backup_plans")
        return {"BackupPlansList": self._plans}

    def list_backup_selections(self, *, BackupPlanId: str, **_kwargs) -> Dict[str, Any]:
        if self._raise_on == "list_backup_selections":
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}},
                "list_backup_selections",
            )
        return {"BackupSelectionsList": self._selections_by_plan.get(BackupPlanId, [])}

    def get_backup_plan(self, *, BackupPlanId: str) -> Dict[str, Any]:
        if self._raise_on == "get_backup_plan":
            raise ClientError({"Error": {"Code": self._raise_code, "Message": "Denied"}}, "get_backup_plan")
        return {"BackupPlan": self._plan_detail_by_id.get(BackupPlanId, {})}

    def list_backup_vaults(self, **_kwargs) -> Dict[str, Any]:
        if self._raise_on == "list_backup_vaults":
            raise ClientError({"Error": {"Code": self._raise_code, "Message": "Denied"}}, "list_backup_vaults")
        return {"BackupVaultList": self._vaults}

    def list_recovery_points_by_backup_vault(self, *, BackupVaultName: str, **_kwargs) -> Dict[str, Any]:
        if self._raise_on == "list_recovery_points_by_backup_vault":
            raise ClientError(
                {"Error": {"Code": self._raise_code, "Message": "Denied"}},
                "list_recovery_points_by_backup_vault",
            )
        return {"RecoveryPoints": self._recovery_points_by_vault.get(BackupVaultName, [])}


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

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id={},
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert any(f.check_id == "aws.backup.plans.no_selections" for f in findings)
    f = [x for x in findings if x.check_id == "aws.backup.plans.no_selections"][0]
    assert f.issue_key["plan_id"] == "p-1"
    assert f.status == "fail"


def test_plan_with_selections_is_ok_no_finding():
    checker = _mk_checker()

    plans = [{"BackupPlanId": "p-2", "BackupPlanName": "plan-two"}]
    selections_by_plan = {"p-2": [{"SelectionId": "s-1"}]}

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.plans.no_selections" for f in findings)


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

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert any(f.check_id == "aws.backup.rules.no_lifecycle" for f in findings)
    f = [x for x in findings if x.check_id == "aws.backup.rules.no_lifecycle"][0]
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

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=[],
        recovery_points_by_vault={},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.rules.no_lifecycle" for f in findings)


# -------------------------
# Tests: Stale recovery points
# -------------------------

def test_stale_recovery_point_emits_finding_and_estimates_cost():
    checker = _mk_checker(stale_days=30, warm_price=0.05, cold_price=0.01)

    plans = [{"BackupPlanId": "p-5", "BackupPlanName": "plan-five"}]
    selections_by_plan = {"p-5": [{"SelectionId": "s-1"}]}
    plan_detail_by_id = {"p-5": {"Rules": []}}

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(timezone.utc) - timedelta(days=60)

    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-1",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,  # 1 GiB
        "ResourceType": "EBS",
        "ResourceArn": "arn:aws:ec2:eu-west-1:111111111111:volume/vol-1",
    }

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id=plan_detail_by_id,
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    stale = [x for x in findings if x.check_id == "aws.backup.recovery_points.stale"]
    assert len(stale) == 1

    f = stale[0]
    assert f.estimated_monthly_cost is not None
    assert float(f.estimated_monthly_cost) == pytest.approx(0.05, abs=0.01)
    assert f.estimate_confidence is not None


def test_recovery_point_recent_is_not_emitted():
    checker = _mk_checker(stale_days=30)

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(timezone.utc) - timedelta(days=10)
    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-2",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,
    }

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=[],
        selections_by_plan={},
        plan_detail_by_id={},
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.recovery_points.stale" for f in findings)


def test_recovery_point_deleting_soon_is_skipped():
    checker = _mk_checker(stale_days=30, skip_if_deleting_within_days=14)

    vaults = [{"BackupVaultName": "vault-a"}]
    created = datetime.now(timezone.utc) - timedelta(days=60)
    delete_at = datetime.now(timezone.utc) + timedelta(days=7)

    rp = {
        "RecoveryPointArn": "arn:aws:backup:eu-west-1:111111111111:recovery-point:rp-3",
        "CreationDate": created,
        "Status": "COMPLETED",
        "StorageClass": "WARM",
        "BackupSizeInBytes": 1024 ** 3,
        "CalculatedLifecycle": {"DeleteAt": delete_at},
    }

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=[],
        selections_by_plan={},
        plan_detail_by_id={},
        vaults=vaults,
        recovery_points_by_vault={"vault-a": [rp]},
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert not any(f.check_id == "aws.backup.recovery_points.stale" for f in findings)


# -------------------------
# Tests: Access errors
# -------------------------

def test_access_error_on_list_backup_plans_emits_single_info_and_stops():
    checker = _mk_checker()
    backup = _FakeBackupClient(region="eu-west-1", raise_on="list_backup_plans")
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access_error"
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

    backup = _FakeBackupClient(
        region="eu-west-1",
        plans=plans,
        selections_by_plan=selections_by_plan,
        plan_detail_by_id={},
        raise_on="get_backup_plan",
    )
    ctx = _FakeCtx(services=_FakeServices(backup=backup))

    findings = list(checker.run(ctx))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.backup.access_error"
    assert findings[0].status == "info"
