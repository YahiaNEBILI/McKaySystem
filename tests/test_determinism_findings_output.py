"""Determinism tests for raw findings output.

The runner/writer should produce stable Parquet output regardless of discovery
order or internal iteration ordering.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from contracts.finops_checker_pattern import FindingDraft
from tests._determinism import canonical_hash, shuffled
from tests.correlation._harness import make_ctx, read_parquet_rows_duckdb, write_input_parquet_single_file
from tests.factories import make_finding_draft, make_scope, make_severity


def _drafts_fixture() -> list[FindingDraft]:
    return [
        make_finding_draft(
            check_id="aws.backup.vaults.audit",
            check_name="AWS Backup vaults audit",
            category="backup",
            title="Vault missing lock",
            severity=make_severity(level="medium", score=60),
            scope=make_scope(
                service="AWSBackup",
                resource_type="backup_vault",
                resource_id="vault/a",
            ),
            issue_key={"type": "vault_lock", "vault": "a"},
            message="Vault a has no lock",
        ),
        make_finding_draft(
            check_id="aws.backup.governance.plans.audit",
            check_name="AWS Backup plans audit",
            category="backup",
            title="Plan missing tag",
            severity=make_severity(level="low", score=30),
            scope=make_scope(
                service="AWSBackup",
                resource_type="backup_plan",
                resource_id="plan/p1",
            ),
            issue_key={"type": "plan_tag", "plan": "p1"},
            message="Plan p1 missing required tag",
        ),
        make_finding_draft(
            check_id="aws.ec2.ebs.storage",
            check_name="EBS storage checks",
            category="storage",
            title="Unencrypted volume",
            severity=make_severity(level="high", score=80),
            scope=make_scope(
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
    fixed_ts = datetime(2026, 1, 24, 12, 0, 0, tzinfo=UTC)
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
