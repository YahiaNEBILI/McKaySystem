"""Test harness for correlation rules.

These helpers build synthetic Parquet datasets and run the correlation engine
end-to-end for rule-level tests.
"""

from __future__ import annotations

import glob
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Sequence

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from contracts.finops_checker_pattern import FindingDraft, RunContext, build_finding_record
from contracts.finops_contracts import build_ids_and_validate
from contracts.schema import FINOPS_FINDINGS_SCHEMA
from contracts.storage_cast import cast_for_storage
from pipeline.correlation.correlate_findings import run_correlation
from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION


@dataclass(frozen=True)
class CorrRun:
    tenant_id: str
    workspace_id: str
    run_id: str
    run_ts: datetime
    ctx: RunContext


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_ctx(
    *,
    tenant_id: str = "acme",
    workspace_id: str = "prod",
    run_id: Optional[str] = None,
    run_ts: Optional[datetime] = None,
    cloud: str = "aws",
) -> CorrRun:
    ts = run_ts or utc_now()
    rid = run_id or f"test-{ts.isoformat().replace('+00:00', 'Z')}"
    ctx = RunContext(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=rid,
        run_ts=ts,
        engine_name=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        rulepack_version=RULEPACK_VERSION,
        schema_version=SCHEMA_VERSION,
        default_currency="USD",
        cloud=cloud,
        services=None,
    )
    return CorrRun(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=rid,
        run_ts=ts,
        ctx=ctx,
    )


def build_wire_records(
    *,
    ctx: RunContext,
    drafts: Iterable[FindingDraft],
    source_ref: str = "tests.correlation.harness",
    finding_id_salt: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Produce fully validated wire-format records (the same as checkers produce),
    with deterministic IDs when finding_id_salt is None.
    """
    out: List[Dict[str, Any]] = []
    for d in drafts:
        rec = build_finding_record(ctx, d, source_ref=source_ref)
        # Ensure deterministic IDs for repeatability unless caller chooses a salt
        build_ids_and_validate(rec, issue_key=d.issue_key, finding_id_salt=finding_id_salt)
        out.append(rec)
    return out


def write_input_parquet_single_file(
    *,
    base_dir: Path,
    ctx: RunContext,
    drafts: List[FindingDraft],
    filename: str = "input.parquet",
    finding_id_salt: Optional[str] = None,
) -> Path:
    """
    Writes a *single* parquet file matching the storage schema.
    This avoids Arrow schema merge problems in unit tests while still using
    the real record builder + storage contract casting.
    """
    base_dir.mkdir(parents=True, exist_ok=True)

    wire = build_wire_records(ctx=ctx, drafts=drafts, finding_id_salt=finding_id_salt)
    storage_rows = [cast_for_storage(r, FINOPS_FINDINGS_SCHEMA) for r in wire]

    table = pa.Table.from_pylist(storage_rows, schema=FINOPS_FINDINGS_SCHEMA)
    out_path = base_dir / filename
    pq.write_table(table, out_path, use_dictionary=False)
    return out_path


def run_correlation_and_read_rows(
    *,
    corr_run: CorrRun,
    raw_dir: Path,
    out_dir: Path,
    threads: int = 2,
    finding_id_mode: str = "stable",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Runs the real correlation pipeline and returns:
      (stats_dict_from_run_correlation, correlated_rows_as_dicts)

    Rows are read via DuckDB to avoid PyArrow schema-merge errors.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = run_correlation(
        tenant_id=corr_run.tenant_id,
        workspace_id=corr_run.workspace_id,
        run_id=corr_run.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(out_dir),
        threads=int(threads),
        finding_id_mode=finding_id_mode,
        run_ts=corr_run.run_ts,
    )
    rows = read_parquet_rows_duckdb(out_dir)
    return stats, rows


def read_parquet_rows_duckdb(parquet_root: Path) -> List[Dict[str, Any]]:
    """
    Read all parquet files under parquet_root (excluding _errors/_debug) via DuckDB.
    This avoids Arrow 'string vs dictionary<string>' merge issues.
    """
    files = sorted(glob.glob(str(parquet_root / "**" / "*.parquet"), recursive=True))
    files = [
        f
        for f in files
        if "\\_errors\\" not in f
        and "/_errors/" not in f
        and "\\_debug\\" not in f
        and "/_debug/" not in f
    ]
    if not files:
        return []

    con = duckdb.connect(database=":memory:")
    try:
        files_sql = ", ".join([f"'{Path(p).as_posix()}'" for p in files])
        sql = f"SELECT * FROM read_parquet([{files_sql}], union_by_name=true)"
        cur = con.execute(sql)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        con.close()


def signature(
    rows: Sequence[Mapping[str, Any]],
    *,
    id_keys: Tuple[str, ...] = (
        "finding_id",
        "fingerprint",
        "issue_key",
        "issue_key_json",
        "issue_key_str",
        "rule_id",
        "check_id",
    ),
) -> List[Tuple[str, ...]]:
    """
    Deterministic signature for comparing outputs across runs.

    It tries several common key names and emits a tuple of strings per row.
    Any missing key contributes an empty string.
    """
    sig: List[Tuple[str, ...]] = []
    for r in rows:
        sig.append(tuple(str(r.get(k, "")) for k in id_keys))
    sig.sort()
    return sig
