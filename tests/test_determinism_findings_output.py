from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity
from tests._determinism import canonical_hash, shuffled
from tests.correlation._harness import make_ctx, read_parquet_rows_duckdb, write_input_parquet_single_file


def _drafts_fixture() -> list[FindingDraft]:
    return [
        FindingDraft(
            check_id="aws.backup.vaults_audit",
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
            check_id="aws.backup.plans_audit",
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
        FindingDraft(
            check_id="aws.ebs.storage",
            check_name="EBS storage checks",
            category="storage",
            status="fail",
            severity=Severity(level="high", score=80),
            title="Unencrypted volume",
            scope=Scope(
                cloud="aws",
                account_id="111111111111",
                region="eu-west-1",
                service="AmazonEC2",
                resource_type="ebs_volume",
                resource_id="vol-123",
            ),
            issue_key={"type": "unencrypted", "volume": "vol-123"},
            message="Volume vol-123 is not encrypted",
        ),
    ]


def test_same_input_shuffled_produces_identical_logical_hash(tmp_path: Path) -> None:
    """
    Determinism guardrail:
      same logical input, shuffled order -> identical logical output.

    We hash canonicalized row dicts read via DuckDB (not raw parquet bytes).
    """
    fixed_ts = datetime(2026, 1, 24, 12, 0, 0, tzinfo=timezone.utc)
    corr_run = make_ctx(tenant_id="acme", workspace_id="prod", run_id="test-run-fixed", run_ts=fixed_ts)

    drafts = _drafts_fixture()
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"

    write_input_parquet_single_file(base_dir=out_a, ctx=corr_run.ctx, drafts=drafts, filename="input.parquet")
    write_input_parquet_single_file(
        base_dir=out_b,
        ctx=corr_run.ctx,
        drafts=shuffled(drafts, seed=999),
        filename="input.parquet",
    )

    rows_a = read_parquet_rows_duckdb(out_a)
    rows_b = read_parquet_rows_duckdb(out_b)

    assert rows_a, "sanity: expected rows in output A"
    assert rows_b, "sanity: expected rows in output B"

    h1 = canonical_hash(rows_a)
    h2 = canonical_hash(rows_b)
    assert h1 == h2
