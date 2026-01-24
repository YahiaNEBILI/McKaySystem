"""
runner.py

FinOps SaaS runner (checkers -> validated wire findings -> storage-cast -> parquet).

Default behavior: run ALL registered checkers (discovered under the `checks` package).
Optional behavior: run only selected checkers via --checker, and/or exclude via --exclude-checker.

NEW: Correlation step
--------------------
After writing raw findings to Parquet, the runner can optionally run the correlation engine,
which reads the raw Parquet dataset and emits *meta-findings* to a separate Parquet dataset.

Pipeline:
  checkers -> findings_raw parquet
    -> correlation -> findings_correlated parquet
      -> duckdb/json export (should UNION both datasets)

Multi-region execution
----------------------
Regions are configured in infra/aws_config.py (AWS_REGIONS).
No CLI args are used for region selection.

Run everything (default):
python runner.py --tenant acme --workspace prod

Disable correlation:
python runner.py --tenant acme --workspace prod --no-correlation

Custom correlated output directory:
python runner.py --tenant acme --workspace prod --correlation-out data/finops_findings_correlated

Run everything except one checker:
python runner.py --tenant acme --workspace prod --exclude-checker checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker

Run a subset:
python runner.py --tenant acme --workspace prod --checker checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker
"""

from __future__ import annotations

import argparse
import glob
import importlib
import os
import pkgutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

import boto3

import checks  # IMPORTANT: used for module discovery
from checks.registry import get_factory, list_specs
from contracts.finops_checker_pattern import Checker, CheckerRunner, RunContext
from contracts.services import ServicesFactory, Services
from infra.aws_config import SDK_CONFIG
from infra.pipeline_paths import PipelinePaths
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig
from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _has_parquet(globs_list: Sequence[str]) -> bool:
    for g in globs_list:
        if glob.glob(g, recursive=True):
            return True
    return False


def _non_empty_dir(path: str) -> bool:
    return os.path.isdir(path) and bool(glob.glob(f"{path}/**/*.parquet", recursive=True))


def _make_run_id(run_ts: datetime) -> str:
    return f"run-{run_ts.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')}"


def _discover_all_checker_specs() -> list[str]:
    """
    Import all modules under the `checks` package so they can register factories/classes.
    Returns all registered checker specs in deterministic order.
    """
    prefix = checks.__name__ + "."
    for mod in pkgutil.walk_packages(checks.__path__, prefix):
        importlib.import_module(mod.name)

    specs = list_specs()
    if not specs:
        raise RuntimeError(
            "No checkers registered. Ensure checker modules register themselves in checks.registry."
        )
    return specs


def _load_checker(dotted_path: str, *, ctx: RunContext, bootstrap: dict) -> Checker:
    """
    Load a checker instance from a dotted import path.

    Format:
      module.path:ClassName
    Example:
      checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker
    """
    if ":" not in dotted_path:
        raise ValueError("Checker path must be like 'module.path:ClassName'")
    module_path, class_name = dotted_path.split(":", 1)

    # Importing the module can register a factory in checks.registry.
    module = importlib.import_module(module_path)

    # If a factory is registered for this spec, use it.
    factory = get_factory(dotted_path)
    if factory is not None:
        instance = factory(ctx, bootstrap)
        if not hasattr(instance, "run") or not hasattr(instance, "checker_id"):
            raise TypeError(f"Factory for '{dotted_path}' did not return a valid Checker")
        return instance

    # Fallback: plain no-arg constructor (legacy/simple checkers).
    klass = getattr(module, class_name, None)
    if klass is None:
        raise ValueError(f"Class '{class_name}' not found in module '{module_path}'")

    instance = klass()
    if not hasattr(instance, "run") or not hasattr(instance, "checker_id"):
        raise TypeError(f"{dotted_path} is not a valid Checker (missing run/checker_id)")
    return instance


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FinOps runner (checkers -> findings parquet)")

    # User inputs (allowed)
    parser.add_argument("--tenant", required=True, help="Tenant identifier (e.g. acme)")
    parser.add_argument("--workspace", default="default", help="Workspace/environment (e.g. prod/dev)")
    parser.add_argument("--cloud", default="aws", choices=["aws", "azure", "gcp"], help="Cloud provider")
    parser.add_argument("--currency", default="USD", help="Default currency for actual.model.currency")

    parser.add_argument(
        "--out",
        default="",
        help="Output base directory for finops_findings parquet dataset "
        "(default: infra.pipeline_paths.PipelinePaths.findings_raw_dir())",
    )

    parser.add_argument(
        "--finding-id-mode",
        default="stable",
        choices=["stable", "per_run", "per_day"],
        help="How finding_id is salted (stable/per_run/per_day)",
    )

    # By default: run everything (registered).
    # If user provides --checker, run only those (after applying exclusions).
    parser.add_argument(
        "--checker",
        action="append",
        default=None,  # None means "user did not specify"
        help="Checker to run, format: module.path:ClassName. Repeatable. If omitted, runs all checkers.",
    )

    parser.add_argument(
        "--exclude-checker",
        action="append",
        default=[],
        help="Checker spec(s) to exclude (same format as --checker). Repeatable.",
    )

    parser.add_argument(
        "--drop-invalid-on-cast",
        action="store_true",
        help="If set, records failing storage casting are skipped instead of failing the run.",
    )

    # Correlation controls
    parser.add_argument(
        "--no-correlation",
        action="store_true",
        help="Disable correlation step (meta-findings).",
    )
    parser.add_argument(
        "--correlation-out",
        default="",
        help="Output base directory for correlated findings parquet dataset "
        "(default: infra.pipeline_paths.PipelinePaths.findings_correlated_dir())",
    )
    parser.add_argument(
        "--correlation-threads",
        type=int,
        default=4,
        help="DuckDB threads for correlation engine (default: 4).",
    )

    # Convenience
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="Print engine/rulepack/schema versions and exit.",
    )

    return parser.parse_args(argv)


def _run_correlation_step(
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    findings_glob: str,
    out_dir: str,
    threads: int,
    finding_id_mode: str,
) -> dict:
    """
    Run correlation step if available.

    Returns a dict of stats for printing.
    """
    try:
        from pipeline.correlation.correlate_findings import (  # pylint: disable=import-error
            run_correlation,
        )
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] Correlation step skipped: pipeline/correlate_findings.py not available ({exc})")
        return {"enabled": False, "emitted": 0, "errors": 0, "out_dir": out_dir}

    stats = run_correlation(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=run_id,
        findings_glob=findings_glob,
        out_dir=out_dir,
        threads=int(threads),
        finding_id_mode=finding_id_mode,
    )

    if not isinstance(stats, dict):
        return {"enabled": True, "emitted": 0, "errors": 0, "out_dir": out_dir}
    return stats


def run_cost_enrichment_if_available(
    *,
    tenant_id: str,
    findings_globs: List[str],
    raw_cur_globs: List[str],
    cur_facts_globs: List[str],
    enriched_out_dir: str,
) -> bool:
    """
    Normalize CUR (if raw files exist) and enrich findings with actual costs.

    Returns:
      True  -> enriched dataset was produced / updated
      False -> enrichment skipped (CUR unavailable)
    """
    try:
        from pipeline.cur.normalize_cur import CurNormalizeConfig, normalize_cur
        from pipeline.cur.cost_enrich import CostEnrichConfig, enrich_findings_with_cur
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] CUR enrichment unavailable (modules missing): {exc}")
        return False

    if _has_parquet(raw_cur_globs):
        print("[INFO] CUR raw files detected, normalizing...")
        normalize_cur(
            CurNormalizeConfig(
                tenant_id=tenant_id,
                input_globs=list(raw_cur_globs),
                out_dir=str(PipelinePaths().cur_facts_dir()),
            )
        )
    else:
        print("[INFO] No raw CUR files detected, skipping normalization")

    if not _has_parquet(cur_facts_globs):
        print("[INFO] No CUR facts available, skipping cost enrichment")
        return False

    print("[INFO] Enriching findings with actual costs from CUR")
    enrich_findings_with_cur(
        CostEnrichConfig(
            tenant_id=tenant_id,
            findings_globs=findings_globs,
            cur_facts_globs=list(cur_facts_globs),
            out_dir=enriched_out_dir,
        )
    )
    return True


def _get_configured_regions() -> List[str]:
    """
    Read region list from configuration (infra/aws_config.py).

    Expected: AWS_REGIONS = ["eu-west-3", "us-east-1", ...]
    """
    try:
        from infra.aws_config import AWS_REGIONS  # type: ignore  # pylint: disable=import-error
    except Exception as exc:
        raise RuntimeError(
            "Multi-region runner requires AWS_REGIONS in infra/aws_config.py "
            "(e.g. AWS_REGIONS = ['eu-west-3'])."
        ) from exc

    regions = [str(r).strip() for r in (AWS_REGIONS or []) if str(r).strip()]
    if not regions:
        raise RuntimeError(
            "AWS_REGIONS is empty. Configure infra/aws_config.py with at least one region."
        )

    seen = set()
    ordered: List[str] = []
    for r in regions:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ordered


def _make_ctx(
    *,
    args: argparse.Namespace,
    run_id: str,
    run_ts: datetime,
    services: Services,
) -> RunContext:
    return RunContext(
        tenant_id=args.tenant,
        workspace_id=args.workspace,
        run_id=run_id,
        run_ts=run_ts,
        engine_name=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        rulepack_version=RULEPACK_VERSION,
        schema_version=SCHEMA_VERSION,
        default_currency=args.currency,
        cloud=args.cloud,
        services=services,
    )


def _partition_checkers_by_scope(
    *,
    checker_specs: List[str],
    ctx_control: RunContext,
    bootstrap: dict,
) -> Tuple[List[Checker], List[str]]:
    """
    Instantiate once using the control ctx so we can detect checker.is_regional.

    Returns:
      - global_checkers: instantiated (run once)
      - regional_specs: specs to instantiate per region
    """
    global_checkers: List[Checker] = []
    regional_specs: List[str] = []

    for spec in checker_specs:
        inst = _load_checker(spec, ctx=ctx_control, bootstrap=bootstrap)
        is_regional = bool(getattr(inst, "is_regional", True))
        if is_regional:
            regional_specs.append(spec)
        else:
            global_checkers.append(inst)

    return global_checkers, regional_specs


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)

    if args.print_version:
        print(f"ENGINE_NAME={ENGINE_NAME}")
        print(f"ENGINE_VERSION={ENGINE_VERSION}")
        print(f"RULEPACK_VERSION={RULEPACK_VERSION}")
        print(f"SCHEMA_VERSION={SCHEMA_VERSION}")
        return 0

    paths = PipelinePaths()

    # Centralized defaults (CLI overrides still win)
    raw_out_dir = args.out.strip() or str(paths.findings_raw_dir())
    corr_out_dir = args.correlation_out.strip() or str(paths.findings_correlated_dir())
    enriched_out_dir = str(paths.findings_enriched_dir())

    run_ts = _utc_now()
    run_id = _make_run_id(run_ts)

    # --- Regions (config-driven) ---
    regions = _get_configured_regions()
    control_region = regions[0]

    # --- Services / AWS bootstrapping ---
    session = boto3.Session()
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    factory = ServicesFactory(session=session, sdk_config=SDK_CONFIG)

    # Bootstrap is runtime data that checker factories may need.
    bootstrap: dict = {
        "aws_account_id": account_id,
        "aws_billing_account_id": account_id,
    }

    # Control ctx (first region) is used for:
    #  - instantiating once to detect is_regional
    #  - running global checkers
    control_services = factory.for_region(control_region)
    ctx_control = _make_ctx(args=args, run_id=run_id, run_ts=run_ts, services=control_services)

    # --- Resolve which checkers to run ---
    if args.checker is None:
        checker_specs = _discover_all_checker_specs()
    else:
        checker_specs = list(args.checker)

    exclude = set(args.exclude_checker or [])
    checker_specs = [s for s in checker_specs if s not in exclude]

    if not checker_specs:
        raise RuntimeError("No checkers selected to run (after exclusions).")

    global_checkers, regional_specs = _partition_checkers_by_scope(
        checker_specs=checker_specs,
        ctx_control=ctx_control,
        bootstrap=bootstrap,
    )

    runner = CheckerRunner(finding_id_salt_mode=args.finding_id_mode)

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=raw_out_dir,
            drop_invalid_on_cast=bool(args.drop_invalid_on_cast),
        )
    )

    total_valid = 0
    total_invalid_count = 0
    total_invalid_errors: List[str] = []
    per_region_valid: Dict[str, int] = {}

    # --- Run global checkers (once, in control region) ---
    if global_checkers:
        global_result = runner.run_many(global_checkers, ctx_control)
        writer.extend(global_result.valid_findings)

        total_valid += len(global_result.valid_findings)
        total_invalid_count += int(global_result.invalid_findings)
        total_invalid_errors.extend(global_result.invalid_errors or [])

    # --- Run regional checkers per configured region ---
    for region in regions:
        svcs = factory.for_region(region)
        ctx_region = _make_ctx(args=args, run_id=run_id, run_ts=run_ts, services=svcs)

        regional_checkers: List[Checker] = []
        for spec in regional_specs:
            regional_checkers.append(_load_checker(spec, ctx=ctx_region, bootstrap=bootstrap))

        if not regional_checkers:
            per_region_valid[region] = 0
            continue

        region_result = runner.run_many(regional_checkers, ctx_region)
        writer.extend(region_result.valid_findings)

        per_region_valid[region] = len(region_result.valid_findings)
        total_valid += len(region_result.valid_findings)
        total_invalid_count += int(region_result.invalid_findings)
        total_invalid_errors.extend(region_result.invalid_errors or [])

    stats = writer.close()

    # --- Optional: Correlation step (meta-findings) ---
    corr_stats: dict = {"enabled": False, "emitted": 0, "errors": 0, "out_dir": ""}

    if not args.no_correlation:
        raw_glob = paths.raw_findings_glob()
        corr_stats = _run_correlation_step(
            tenant_id=args.tenant,
            workspace_id=args.workspace,
            run_id=run_id,
            findings_glob=raw_glob,
            out_dir=corr_out_dir,
            threads=args.correlation_threads,
            finding_id_mode=args.finding_id_mode,
        )

    # --- Optional: CUR cost enrichment (best-effort) ---
    run_cost_enrichment_if_available(
        tenant_id=args.tenant,
        findings_globs=[
            paths.raw_findings_glob(),
            paths.correlated_findings_glob(),
        ],
        raw_cur_globs=[
            str(paths.cur_raw_dir() / "**/*.parquet"),
        ],
        cur_facts_globs=[
            str(paths.cur_facts_dir() / "**/*.parquet"),
        ],
        enriched_out_dir=enriched_out_dir,
    )

    # --- Summary ---
    print("=== Run summary ===")
    print(f"tenant: {args.tenant}")
    print(f"workspace: {args.workspace}")
    print(f"cloud: {args.cloud}")
    print(f"run_id: {run_id}")
    print(f"run_ts: {run_ts.astimezone(timezone.utc).isoformat().replace('+00:00','Z')}")

    print(f"regions_configured: {len(regions)}")
    print(f"regions: {', '.join(regions)}")
    print(f"control_region: {control_region}")

    print(f"out_raw: {raw_out_dir}")
    print(f"out_correlated: {corr_out_dir}")
    print(f"out_enriched: {enriched_out_dir}")

    print(f"checkers_selected: {len(checker_specs)}")
    print(f"global_checkers: {len(global_checkers)}")
    print(f"regional_checkers: {len(regional_specs)}")

    if per_region_valid:
        print("--- Findings per region ---")
        for r in regions:
            print(f"{r}: {per_region_valid.get(r, 0)}")

    print(f"engine_name: {ENGINE_NAME}")
    print(f"engine_version: {ENGINE_VERSION}")
    print(f"rulepack_version: {RULEPACK_VERSION}")
    print(f"schema_version: {SCHEMA_VERSION}")

    print(f"valid_findings: {total_valid}")
    print(f"invalid_findings: {total_invalid_count}")

    print(f"writer_received: {stats.received}")
    print(f"writer_written: {stats.written}")
    print(f"writer_dropped_cast_errors: {stats.dropped_cast_errors}")

    # Correlation summary
    if corr_stats.get("enabled"):
        print("--- Correlation ---")
        print(f"correlation_out: {corr_stats.get('out_dir', '')}")
        print(f"correlation_rules_enabled: {corr_stats.get('rules_enabled', '')}")
        print(f"correlation_emitted: {corr_stats.get('emitted', 0)}")
        print(f"correlation_errors: {corr_stats.get('errors', 0)}")
    else:
        print("--- Correlation ---")
        print("correlation: disabled/skipped")

    if total_invalid_errors:
        print("\n--- Sample validation errors (contract layer) ---")
        for e in total_invalid_errors[:10]:
            print(f"- {e}")

    if stats.cast_errors:
        print("\n--- Sample storage cast errors (storage boundary) ---")
        for e in stats.cast_errors[:10]:
            print(f"- {e}")

    # Non-zero exit code if nothing was written but we did receive records
    if stats.written == 0 and stats.received > 0:
        return 2

    if corr_stats.get("enabled") and int(corr_stats.get("errors", 0)) > 0:
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
