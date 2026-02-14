"""Rule-level tests for the AWS Backup vault risk correlation rule."""

from __future__ import annotations

from pathlib import Path

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity

from tests.correlation._harness import (
    make_ctx,
    run_correlation_and_read_rows,
    signature,
    write_input_parquet_single_file,
)


def _draft_vault_signal(
    *,
    check_id: str,
    account_id: str,
    region: str,
    vault_name: str,
    score: int = 850,
) -> FindingDraft:
    return FindingDraft(
        check_id=check_id,
        check_name=check_id,
        category="governance",
        status="fail",
        severity=Severity(level="high" if score >= 800 else "medium", score=score),
        title=f"Vault signal: {check_id} ({vault_name})",
        scope=Scope(
            cloud="aws",
            account_id=account_id,
            region=region,
            service="backup",
            resource_type="backup_vault",
            resource_id=vault_name,
            resource_arn=f"arn:aws:backup:{region}:{account_id}:backup-vault:{vault_name}",
        ),
        message="test fixture",
        recommendation="",
        estimate_confidence=50,
        dimensions={},
        issue_key={"check_id": check_id, "account_id": account_id, "region": region, "vault": vault_name},
    )


def _draft_stale_recovery_point(
    *,
    account_id: str,
    region: str,
    vault_name: str,
    rp_id: str = "rp-00000001",
    score: int = 650,
) -> FindingDraft:
    return FindingDraft(
        check_id="aws.backup.recovery.points.stale",
        check_name="aws.backup.recovery.points.stale",
        category="governance",
        status="fail",
        severity=Severity(level="medium", score=score),
        title=f"Stale recovery point in {vault_name}",
        scope=Scope(
            cloud="aws",
            account_id=account_id,
            region=region,
            service="backup",
            resource_type="recovery_point",
            resource_id=rp_id,
            resource_arn=f"arn:aws:backup:{region}:{account_id}:recovery-point:{rp_id}",
        ),
        message="test fixture",
        recommendation="",
        estimate_confidence=50,
        estimated_monthly_cost=12.345678,
        # IMPORTANT: the rule joins via this dimension
        dimensions={"vault_name": vault_name},
        issue_key={
            "check_id": "aws.backup.recovery.points.stale",
            "account_id": account_id,
            "region": region,
            "vault": vault_name,
        },
    )


def test_rule_emits_when_two_signals_present(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-001"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no.lifecycle",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
        ),
        _draft_stale_recovery_point(
            account_id=account_id,
            region=region,
            vault_name=vault_name,
            rp_id="rp-00000001",
        ),
    ]

    write_input_parquet_single_file(base_dir=raw_dir, ctx=corr.ctx, drafts=drafts)

    stats, rows = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir,
        threads=2,
        finding_id_mode="stable",
    )

    assert stats["enabled"] is True
    assert stats["errors"] == 0
    assert len(rows) >= 1, "Expected at least one correlated finding when >=2 signals exist for the same vault"


def test_rule_does_not_emit_with_single_signal(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-002"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no.lifecycle",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
        ),
    ]

    write_input_parquet_single_file(base_dir=raw_dir, ctx=corr.ctx, drafts=drafts)

    stats, rows = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir,
        threads=2,
        finding_id_mode="stable",
    )

    assert stats["enabled"] is True
    assert stats["errors"] == 0
    assert len(rows) == 0, "Expected zero correlated findings when only one signal exists for a vault"


def test_rule_is_deterministic_for_same_input(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir1 = tmp_path / "corr1"
    out_dir2 = tmp_path / "corr2"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-003"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no.lifecycle",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
        ),
        _draft_stale_recovery_point(
            account_id=account_id,
            region=region,
            vault_name=vault_name,
            rp_id="rp-00000002",
        ),
        # extra signal to reduce risk of borderline rule tweaks later
        _draft_vault_signal(
            check_id="aws.backup.vaults.access.policy.misconfig",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
            score=900,
        ),
    ]

    write_input_parquet_single_file(base_dir=raw_dir, ctx=corr.ctx, drafts=drafts)

    stats1, rows1 = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir1,
        threads=2,
        finding_id_mode="stable",
    )
    assert stats1["enabled"] is True
    assert stats1["errors"] == 0

    stats2, rows2 = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir2,
        threads=2,
        finding_id_mode="stable",
    )
    assert stats2["enabled"] is True
    assert stats2["errors"] == 0

    assert len(rows1) >= 1
    assert len(rows2) >= 1
    assert signature(rows1) == signature(rows2), "Correlated outputs should be identical for identical inputs"
