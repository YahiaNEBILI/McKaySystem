from __future__ import annotations

import glob
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pyarrow.parquet as pq

from contracts.finops_checker_pattern import (
    FindingDraft,
    RunContext,
    Scope,
    Severity,
    build_finding_record,
)
from contracts.finops_contracts import build_ids_and_validate
from pipeline.correlation.correlate_findings import run_correlation
from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION

import pyarrow as pa
import duckdb

from contracts.schema import FINOPS_FINDINGS_SCHEMA
from contracts.storage_cast import cast_for_storage


@dataclass(frozen=True)
class _CtxBundle:
    ctx: RunContext
    tenant_id: str
    workspace_id: str
    run_id: str
    run_ts: datetime


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_ctx(*, tenant_id: str = "acme", workspace_id: str = "prod") -> _CtxBundle:
    run_ts = _utc_now()
    run_id = f"test-{run_ts.isoformat().replace('+00:00', 'Z')}"
    ctx = RunContext(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=run_id,
        run_ts=run_ts,
        engine_name=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        rulepack_version=RULEPACK_VERSION,
        schema_version=SCHEMA_VERSION,
        default_currency="USD",
        cloud="aws",
        services=None,
    )
    return _CtxBundle(ctx=ctx, tenant_id=tenant_id, workspace_id=workspace_id, run_id=run_id, run_ts=run_ts)


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
        check_id="aws.backup.recovery_points.stale",
        check_name="aws.backup.recovery_points.stale",
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
        estimated_monthly_cost="12.345678",
        # IMPORTANT: the rule joins via this dimension
        dimensions={"vault_name": vault_name},
        issue_key={"check_id": "aws.backup.recovery_points.stale", "account_id": account_id, "region": region, "vault": vault_name},
    )


def _iter_records(ctx: RunContext, drafts: Iterable[FindingDraft]) -> Iterable[Dict]:
    for d in drafts:
        rec = build_finding_record(ctx, d, source_ref="tests.test_rule_aws_backup_vault_risk")
        # stable IDs for determinism tests
        build_ids_and_validate(rec, issue_key=d.issue_key, finding_id_salt=None)
        yield rec


def _write_findings_parquet(base_dir: Path, ctx: RunContext, drafts: List[FindingDraft]) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for rec in _iter_records(ctx, drafts):
        # Cast exactly like production storage contract
        rows.append(cast_for_storage(rec, FINOPS_FINDINGS_SCHEMA))

    table = pa.Table.from_pylist(rows, schema=FINOPS_FINDINGS_SCHEMA)
    pq.write_table(table, base_dir / "input.parquet", use_dictionary=False)



def _read_correlated_rows(corr_dir: Path) -> List[Dict]:
    files = sorted(glob.glob(str(corr_dir / "**" / "*.parquet"), recursive=True))
    files = [
        f for f in files
        if "\\_errors\\" not in f and "/_errors/" not in f
        and "\\_debug\\" not in f and "/_debug/" not in f
    ]
    if not files:
        return []

    # DuckDB reads mixed dictionary/string encodings without PyArrow merge issues.
    con = duckdb.connect(database=":memory:")

    # DuckDB prefers forward slashes on Windows paths.
    files_sql = ", ".join([f"'{Path(p).as_posix()}'" for p in files])
    sql = f"""
        SELECT *
        FROM read_parquet([{files_sql}], union_by_name=true)
    """
    rel = con.execute(sql)
    cols = [d[0] for d in rel.description]
    rows = [dict(zip(cols, r)) for r in rel.fetchall()]
    con.close()
    return rows


def _signature(rows: List[Dict]) -> List[Tuple[str, str, str]]:
    """
    Build a deterministic signature for comparison across runs.

    We try a few keys because exact column names can evolve.
    """
    sig: List[Tuple[str, str, str]] = []
    for r in rows:
        finding_id = str(r.get("finding_id", ""))
        fingerprint = str(r.get("fingerprint", ""))
        issue_key = str(r.get("issue_key", r.get("issue_key_json", r.get("issue_key_str", ""))))
        sig.append((finding_id, fingerprint, issue_key))
    sig.sort()
    return sig


def test_rule_emits_when_two_signals_present(tmp_path: Path) -> None:
    bundle = _make_ctx()
    raw_dir = tmp_path / "finops_findings"
    corr_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-001"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no_lifecycle",
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

    _write_findings_parquet(raw_dir, bundle.ctx, drafts)

    stats = run_correlation(
        tenant_id=bundle.tenant_id,
        workspace_id=bundle.workspace_id,
        run_id=bundle.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(corr_dir),
        threads=2,
        finding_id_mode="stable",
        run_ts=bundle.run_ts,
    )

    assert stats["enabled"] is True
    assert stats["errors"] == 0

    rows = _read_correlated_rows(corr_dir)
    assert len(rows) >= 1, "Expected at least one correlated finding when >=2 signals exist for the same vault"


def test_rule_does_not_emit_with_single_signal(tmp_path: Path) -> None:
    bundle = _make_ctx()
    raw_dir = tmp_path / "finops_findings"
    corr_dir = tmp_path / "finops_findings_correlated"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-002"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no_lifecycle",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
        ),
        # no second signal → should not meet signal_count>=2
    ]

    _write_findings_parquet(raw_dir, bundle.ctx, drafts)

    stats = run_correlation(
        tenant_id=bundle.tenant_id,
        workspace_id=bundle.workspace_id,
        run_id=bundle.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(corr_dir),
        threads=2,
        finding_id_mode="stable",
        run_ts=bundle.run_ts,
    )

    assert stats["enabled"] is True
    assert stats["errors"] == 0

    rows = _read_correlated_rows(corr_dir)
    assert len(rows) == 0, "Expected zero correlated findings when only one signal exists for a vault"


def test_rule_is_deterministic_for_same_input(tmp_path: Path) -> None:
    # We run correlation twice on identical parquet input in two different output dirs
    bundle = _make_ctx()
    raw_dir = tmp_path / "finops_findings"
    corr_dir1 = tmp_path / "corr1"
    corr_dir2 = tmp_path / "corr2"

    account_id = "123456789012"
    region = "eu-west-1"
    vault_name = "vault-003"

    drafts = [
        _draft_vault_signal(
            check_id="aws.backup.vaults.no_lifecycle",
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
        # add a third signal to reduce chance of borderline rule tweaks later
        _draft_vault_signal(
            check_id="aws.backup.vaults.access_policy_misconfig",
            account_id=account_id,
            region=region,
            vault_name=vault_name,
            score=900,
        ),
    ]

    _write_findings_parquet(raw_dir, bundle.ctx, drafts)

    stats1 = run_correlation(
        tenant_id=bundle.tenant_id,
        workspace_id=bundle.workspace_id,
        run_id=bundle.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(corr_dir1),
        threads=2,
        finding_id_mode="stable",
        run_ts=bundle.run_ts,
    )
    assert stats1["errors"] == 0

    stats2 = run_correlation(
        tenant_id=bundle.tenant_id,
        workspace_id=bundle.workspace_id,
        run_id=bundle.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(corr_dir2),
        threads=2,
        finding_id_mode="stable",
        run_ts=bundle.run_ts,
    )
    assert stats2["errors"] == 0

    rows1 = _read_correlated_rows(corr_dir1)
    rows2 = _read_correlated_rows(corr_dir2)

    assert len(rows1) >= 1
    assert len(rows2) >= 1

    assert _signature(rows1) == _signature(rows2), "Correlated outputs should be identical for identical inputs"
