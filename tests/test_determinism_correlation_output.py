"""Determinism tests for correlated findings output.

These tests ensure that correlation results do not depend on input ordering.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity
from tests._determinism import canonical_hash, shuffled
from tests.correlation._harness import make_ctx, run_correlation_and_read_rows, write_input_parquet_single_file


def _drafts_fixture() -> list[FindingDraft]:
    return [
        FindingDraft(
            check_id="aws.backup.vaults.audit",
            check_name="AWS Backup vaults audit",
            category="backup",
            status="fail",
            severity=Severity(level="medium", score=60),
            title="Vault missing lock",
            scope=Scope(
                cloud="aws",
                account_id="111111111111",
                region="eu-west-1",
                service="AWSBackup",
                resource_type="backup_vault",
                resource_id="vault/a",
            ),
            issue_key={"type": "vault_lock", "vault": "a"},
            message="Vault a has no lock",
        ),
        FindingDraft(
            check_id="aws.backup.governance.plans.audit",
            check_name="AWS Backup plans audit",
            category="backup",
            status="fail",
            severity=Severity(level="low", score=30),
            title="Plan missing tag",
            scope=Scope(
                cloud="aws",
                account_id="111111111111",
                region="eu-west-1",
                service="AWSBackup",
                resource_type="backup_plan",
                resource_id="plan/p1",
            ),
            issue_key={"type": "plan_tag", "plan": "p1"},
            message="Plan p1 missing required tag",
        ),
    ]


def test_correlation_same_input_produces_identical_output_hash(tmp_path: Path) -> None:
    """
    Determinism guardrail:
      same raw findings -> identical correlated output (logical hash).
    """
    fixed_ts = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    corr_run = make_ctx(tenant_id="acme", workspace_id="prod", run_id="test-corr-fixed", run_ts=fixed_ts)

    raw_dir = tmp_path / "raw"
    out_1 = tmp_path / "corr1"
    out_2 = tmp_path / "corr2"

    write_input_parquet_single_file(base_dir=raw_dir, ctx=corr_run.ctx, drafts=_drafts_fixture(), filename="input.parquet")

    _, rows_1 = run_correlation_and_read_rows(corr_run=corr_run, raw_dir=raw_dir, out_dir=out_1)
    _, rows_2 = run_correlation_and_read_rows(corr_run=corr_run, raw_dir=raw_dir, out_dir=out_2)

    h1 = canonical_hash(rows_1)
    h2 = canonical_hash(rows_2)
    assert h1 == h2


def test_correlation_shuffled_input_produces_identical_output_hash(tmp_path: Path) -> None:
    """
    Extra guardrail:
      shuffle raw findings row order -> correlation output must still be identical.
    """
    fixed_ts = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    corr_run = make_ctx(tenant_id="acme", workspace_id="prod", run_id="test-corr-fixed", run_ts=fixed_ts)

    drafts = _drafts_fixture()

    raw_a = tmp_path / "raw_a"
    raw_b = tmp_path / "raw_b"
    out_a = tmp_path / "corr_a"
    out_b = tmp_path / "corr_b"

    write_input_parquet_single_file(base_dir=raw_a, ctx=corr_run.ctx, drafts=drafts, filename="input.parquet")
    write_input_parquet_single_file(base_dir=raw_b, ctx=corr_run.ctx, drafts=shuffled(drafts, seed=2024), filename="input.parquet")

    _, rows_1 = run_correlation_and_read_rows(corr_run=corr_run, raw_dir=raw_a, out_dir=out_a)
    _, rows_2 = run_correlation_and_read_rows(corr_run=corr_run, raw_dir=raw_b, out_dir=out_b)

    h1 = canonical_hash(rows_1)
    h2 = canonical_hash(rows_2)
    assert h1 == h2
