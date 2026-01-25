"""Rule-level tests for correlating unattached + unencrypted EBS signals."""

from __future__ import annotations

from pathlib import Path

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity

from tests.correlation._harness import (
    make_ctx,
    run_correlation_and_read_rows,
    signature,
    write_input_parquet_single_file,
)


def _draft_unattached_volume(
    *,
    account_id: str,
    region: str,
    volume_id: str,
    volume_type: str = "gp3",
    size_gb: int = 100,
    age_days: int = 45,
    monthly_cost: float = 9.5,
) -> FindingDraft:
    return FindingDraft(
        check_id="aws.ec2.ebs.unattached_volume",
        check_name="Unattached EBS volume",
        category="cost",
        sub_category="storage",
        status="fail",
        severity=Severity(level="medium", score=700),
        title=f"Unattached EBS volume {volume_id}",
        message="test fixture",
        recommendation="",
        scope=Scope(
            cloud="aws",
            account_id=account_id,
            region=region,
            service="AmazonEC2",
            resource_type="ebs_volume",
            resource_id=volume_id,
            resource_arn=f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
        ),
        estimated_monthly_cost=monthly_cost,
        estimated_monthly_savings=monthly_cost,
        estimate_confidence=55,
        dimensions={
            "volume_type": volume_type,
            "size_gb": str(size_gb),
            "age_days": str(age_days),
        },
        issue_key={
            "check_id": "aws.ec2.ebs.unattached_volume",
            "account_id": account_id,
            "region": region,
            "volume_id": volume_id,
        },
    )


def _draft_volume_unencrypted(
    *,
    account_id: str,
    region: str,
    volume_id: str,
    volume_type: str = "gp3",
    size_gb: int = 100,
) -> FindingDraft:
    return FindingDraft(
        check_id="aws.ec2.ebs.volume_unencrypted",
        check_name="Unencrypted EBS volume",
        category="governance",
        sub_category="security",
        status="fail",
        severity=Severity(level="high", score=850),
        title=f"Unencrypted EBS volume {volume_id}",
        message="test fixture",
        recommendation="",
        scope=Scope(
            cloud="aws",
            account_id=account_id,
            region=region,
            service="AmazonEC2",
            resource_type="ebs_volume",
            resource_id=volume_id,
            resource_arn=f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
        ),
        estimate_confidence=100,
        dimensions={
            "volume_type": volume_type,
            "size_gb": str(size_gb),
            "encrypted": "false",
        },
        issue_key={
            "check_id": "aws.ec2.ebs.volume_unencrypted",
            "account_id": account_id,
            "region": region,
            "volume_id": volume_id,
        },
    )


def test_rule_emits_when_both_signals_present(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    volume_id = "vol-0abc123def456"

    drafts = [
        _draft_unattached_volume(account_id=account_id, region=region, volume_id=volume_id),
        _draft_volume_unencrypted(account_id=account_id, region=region, volume_id=volume_id),
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

    corr_rows = [r for r in rows if r.get("check_id") == "aws.ec2.correlation.ebs_unattached_unencrypted"]
    assert len(corr_rows) == 1
    assert corr_rows[0]["scope"]["resource_id"] == volume_id


def test_rule_does_not_emit_if_one_signal_missing(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    volume_id = "vol-0missing"

    drafts = [_draft_unattached_volume(account_id=account_id, region=region, volume_id=volume_id)]

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
    assert len([r for r in rows if r.get("check_id") == "aws.ec2.correlation.ebs_unattached_unencrypted"]) == 0


def test_rule_is_deterministic_for_same_input(tmp_path: Path) -> None:
    corr = make_ctx()
    raw_dir = tmp_path / "finops_findings"
    out_dir1 = tmp_path / "corr1"
    out_dir2 = tmp_path / "corr2"

    account_id = "123456789012"
    region = "eu-west-1"
    volume_id = "vol-0deterministic"

    drafts = [
        _draft_unattached_volume(
            account_id=account_id,
            region=region,
            volume_id=volume_id,
            monthly_cost=55.0,
        ),
        _draft_volume_unencrypted(account_id=account_id, region=region, volume_id=volume_id),
    ]

    write_input_parquet_single_file(base_dir=raw_dir, ctx=corr.ctx, drafts=drafts)

    _, rows1 = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir1,
        threads=2,
        finding_id_mode="stable",
    )
    _, rows2 = run_correlation_and_read_rows(
        corr_run=corr,
        raw_dir=raw_dir,
        out_dir=out_dir2,
        threads=2,
        finding_id_mode="stable",
    )

    assert signature(rows1) == signature(rows2)
