# scripts/stress/stress_end_to_end.py
"""
To run the stress engine : 
python tools/stress/stress_engine.py --n 200000 --workdir .stress --clean
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator

import threading

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

from contracts.finops_checker_pattern import (
    FindingDraft,
    RunContext,
    Scope,
    Severity,
    build_finding_record,
)
from contracts.finops_contracts import build_ids_and_validate
from pipeline.correlation.correlate_findings import run_correlation
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig
from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION


# This mirrors pipeline/correlation/rules/aws_backup_vault_risk.sql
REQUIRED_CHECK_IDS_FOR_DEFAULT_RULEPACK = (
    "aws.backup.vaults.no_lifecycle",
    "aws.backup.vaults.access_policy_misconfig",
    "aws.backup.recovery_points.stale",
    "aws.backup.rules.no_lifecycle",
    "aws.backup.plans.no_selections",
)


@dataclass(frozen=True)
class Timings:
    generate_s: float
    write_s: float
    correlate_s: float


@dataclass
class MemStats:
    rss_mb: float = 0.0
    peak_rss_mb: float = 0.0


class MemSampler:
    def __init__(self, *, interval_s: float = 0.2) -> None:
        self._interval_s = interval_s
        self._stop = threading.Event()
        self.stats = MemStats()
        self._thread: threading.Thread | None = None

        self._proc = psutil.Process(os.getpid()) if psutil else None

    def __enter__(self) -> "MemSampler":
        if not self._proc:
            return self
        self._thread = threading.Thread(target=self._run, name="mem-sampler", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._proc:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        # final sample
        self._sample()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(self._interval_s)

    def _sample(self) -> None:
        if not self._proc:
            return
        rss = float(self._proc.memory_info().rss) / (1024.0 * 1024.0)
        self.stats.rss_mb = rss
        if rss > self.stats.peak_rss_mb:
            self.stats.peak_rss_mb = rss


class SyntheticBulkChecker:
    """Fast synthetic checker that emits findings shaped like real ones."""

    checker_id = "stress.synthetic.bulk"

    def __init__(self, *, n: int, seed: int) -> None:
        self._n = int(n)
        self._rng = random.Random(int(seed))

        self._regions = ["eu-west-3", "eu-west-1", "us-east-1", "us-west-2"]
        self._accounts = ["123456789012", "234567890123", "345678901234"]
        self._vault_names = [f"vault-{i:03d}" for i in range(250)]

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        check_ids = list(REQUIRED_CHECK_IDS_FOR_DEFAULT_RULEPACK)

        for i in range(self._n):
            check_id = check_ids[i % len(check_ids)]
            region = self._regions[i % len(self._regions)]
            account_id = self._accounts[i % len(self._accounts)]
            vault_name = self._vault_names[i % len(self._vault_names)]

            # Two shapes expected by your default correlation rule:
            # - vault-centric: scope.resource_type='backup_vault' and scope.resource_id=vault_name
            # - recovery_point scoped, with dimensions['vault_name']=vault_name
            if check_id == "aws.backup.recovery_points.stale":
                scope = Scope(
                    cloud=ctx.cloud,
                    account_id=account_id,
                    region=region,
                    service="backup",
                    resource_type="recovery_point",
                    resource_id=f"rp-{i:08x}",
                    resource_arn=f"arn:aws:backup:{region}:{account_id}:recovery-point:rp-{i:08x}",
                )
                dimensions = {"vault_name": vault_name}
                est_monthly_cost = f"{(self._rng.random() * 25.0):.6f}"
                title = f"Stale recovery point: {vault_name}"
            else:
                scope = Scope(
                    cloud=ctx.cloud,
                    account_id=account_id,
                    region=region,
                    service="backup",
                    resource_type="backup_vault",
                    resource_id=vault_name,
                    resource_arn=f"arn:aws:backup:{region}:{account_id}:backup-vault:{vault_name}",
                )
                dimensions = {}
                est_monthly_cost = ""
                title = f"Vault risk signal: {check_id} ({vault_name})"

            sev_score = 400 + (i % 500)
            sev_level = "medium" if sev_score < 800 else "high"

            yield FindingDraft(
                check_id=check_id,
                check_name=check_id,
                category="governance",
                status="fail",
                severity=Severity(level=sev_level, score=sev_score),
                title=title,
                scope=scope,
                message="synthetic stress row",
                recommendation="",
                estimate_confidence=50,
                estimated_monthly_cost=est_monthly_cost or None,
                dimensions=dimensions,
                # keep stable-ish issue keys (controls determinism)
                issue_key={
                    "check_id": check_id,
                    "account_id": account_id,
                    "region": region,
                    "vault": vault_name,
                    "i": str(i),
                },
            )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_ctx(*, tenant: str, workspace: str) -> RunContext:
    run_ts = _utc_now()
    run_id = f"stress-{run_ts.isoformat().replace('+00:00', 'Z')}"
    return RunContext(
        tenant_id=tenant,
        workspace_id=workspace,
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


def _iter_wire_records(*, ctx: RunContext, checker: SyntheticBulkChecker, finding_id_mode: str) -> Iterator[Dict]:
    mode = (finding_id_mode or "stable").strip().lower()
    if mode == "stable":
        salt = None
    elif mode == "per_run":
        salt = ctx.run_id
    elif mode == "per_day":
        salt = ctx.run_ts.date().isoformat()
    else:
        salt = None

    for draft in checker.run(ctx):
        rec = build_finding_record(ctx, draft, source_ref=checker.checker_id)
        build_ids_and_validate(rec, issue_key=draft.issue_key, finding_id_salt=salt)
        yield rec


def _write_raw_findings(*, out_dir: Path, records: Iterable[Dict], max_buffered_rows: int) -> int:
    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(out_dir),
            compression="zstd",
            max_rows_per_file=200_000,
            max_buffered_rows=int(max_buffered_rows),
            drop_invalid_on_cast=False,
        )
    )
    written = 0
    for rec in records:
        writer.append(rec)
        written += 1
    writer.close()
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description="Stress check: checkers + writer + correlation")
    ap.add_argument("--n", type=int, default=100_000, help="Number of synthetic findings")
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed")
    ap.add_argument("--tenant", type=str, default="acme", help="Tenant id")
    ap.add_argument("--workspace", type=str, default="prod", help="Workspace id")
    ap.add_argument("--workdir", type=str, default=".stress", help="Working directory")
    ap.add_argument("--finding-id-mode", type=str, default="stable", choices=["stable", "per_run", "per_day"])
    ap.add_argument("--threads", type=int, default=4, help="DuckDB threads for correlation")
    ap.add_argument("--max-buffered-rows", type=int, default=50_000, help="Writer flush threshold")
    ap.add_argument("--clean", action="store_true", help="Delete workdir before running")
    args = ap.parse_args()

    workdir = Path(args.workdir)
    raw_dir = workdir / "finops_findings"
    corr_dir = workdir / "finops_findings_correlated"

    if args.clean and workdir.exists():
        shutil.rmtree(workdir)

    raw_dir.mkdir(parents=True, exist_ok=True)
    corr_dir.mkdir(parents=True, exist_ok=True)

    ctx = _make_ctx(tenant=args.tenant, workspace=args.workspace)
    checker = SyntheticBulkChecker(n=int(args.n), seed=int(args.seed))

    t0 = time.perf_counter()
    records = _iter_wire_records(ctx=ctx, checker=checker, finding_id_mode=args.finding_id_mode)
    t_gen_done = time.perf_counter()

    written = _write_raw_findings(out_dir=raw_dir, records=records, max_buffered_rows=int(args.max_buffered_rows))
    t_write_done = time.perf_counter()

    with MemSampler(interval_s=0.2) as ms_write:
        written = _write_raw_findings(out_dir=raw_dir, records=records, max_buffered_rows=int(args.max_buffered_rows))
    t_write_done = time.perf_counter()

    with MemSampler(interval_s=0.2) as ms_corr:
        corr_stats = run_correlation(
            tenant_id=args.tenant,
            workspace_id=args.workspace,
            run_id=ctx.run_id,
            findings_glob=str(raw_dir / "**" / "*.parquet"),
            out_dir=str(corr_dir),
            threads=int(args.threads),
            finding_id_mode=args.finding_id_mode,
            run_ts=ctx.run_ts,
        )
    t_corr_done = time.perf_counter()

    corr_stats = run_correlation(
        tenant_id=args.tenant,
        workspace_id=args.workspace,
        run_id=ctx.run_id,
        findings_glob=str(raw_dir / "**" / "*.parquet"),
        out_dir=str(corr_dir),
        threads=int(args.threads),
        finding_id_mode=args.finding_id_mode,
        run_ts=ctx.run_ts,
    )
    t_corr_done = time.perf_counter()

    timings = Timings(
        generate_s=t_gen_done - t0,
        write_s=t_write_done - t_gen_done,
        correlate_s=t_corr_done - t_write_done,
    )

    print("\n=== Stress summary ===")
    print(f"rows_written={written}")
    print(f"generate_s={timings.generate_s:.2f}")
    print(f"write_s={timings.write_s:.2f}")
    print(f"correlate_s={timings.correlate_s:.2f}")
    print(f"correlation={corr_stats}")
    print(f"write_peak_rss_mb={ms_write.stats.peak_rss_mb:.1f}")
    print(f"correlate_peak_rss_mb={ms_corr.stats.peak_rss_mb:.1f}")

    if psutil is None:
        print("note=psutil_not_installed (memory stats disabled)")


    max_corr_s = float(os.environ.get("MAX_CORRELATE_S", "0") or "0")
    if max_corr_s > 0 and timings.correlate_s > max_corr_s:
        raise SystemExit(f"Correlation too slow: {timings.correlate_s:.2f}s > {max_corr_s:.2f}s")


if __name__ == "__main__":
    main()
