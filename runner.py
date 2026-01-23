"""
runner.py

FinOps SaaS runner (checkers -> validated wire findings -> storage-cast -> parquet).

Default behavior: run ALL registered checkers (discovered under the `checks` package).
Optional behavior: run only selected checkers via --checker, and/or exclude via --exclude-checker.

If your imports are "from contracts..." / "from pipeline..." / "from checks...",
ensure your repo root is on PYTHONPATH (pytest.ini already does this for tests).

Run everything (default):
python runner.py --tenant acme --workspace prod

Run everything except one checker:
python runner.py --tenant acme --workspace prod --exclude-checker checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker

Run a subset:
python runner.py --tenant acme --workspace prod --checker checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
from datetime import datetime, timezone
from typing import List, Sequence

import boto3

import checks  # IMPORTANT: used for module discovery
from checks.registry import get_factory, list_specs
from contracts.finops_checker_pattern import Checker, CheckerRunner, RunContext
from contracts.services import Services
from infra.aws_config import SDK_CONFIG
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig
from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
        default="data/finops_findings",
        help="Output base directory for finops_findings parquet dataset",
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

    # Convenience
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="Print engine/rulepack/schema versions and exit.",
    )

    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)

    if args.print_version:
        print(f"ENGINE_NAME={ENGINE_NAME}")
        print(f"ENGINE_VERSION={ENGINE_VERSION}")
        print(f"RULEPACK_VERSION={RULEPACK_VERSION}")
        print(f"SCHEMA_VERSION={SCHEMA_VERSION}")
        return 0

    run_ts = _utc_now()
    run_id = _make_run_id(run_ts)

    # --- Services / AWS bootstrapping ---
    session = boto3.Session()
    sts = session.client("sts")
    s3 = session.client("s3", config=SDK_CONFIG)
    rds = session.client("rds", config=SDK_CONFIG)

    account_id = sts.get_caller_identity()["Account"]

    services = Services(s3=s3, rds=rds)

    # Bootstrap is runtime data that checker factories may need.
    bootstrap: dict = {
        "aws_account_id": account_id,
        "aws_billing_account_id": account_id,
        # Optional: configure RDS snapshot cleanup heuristics
        # "rds_snapshot_stale_days": 30,
        # "rds_snapshot_gb_month_price_usd": 0.095,
    }

    ctx = RunContext(
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

    # --- Resolve which checkers to run ---
    if args.checker is None:
        # User did not specify any checker -> run ALL registered checkers
        checker_specs = _discover_all_checker_specs()
    else:
        # Explicit list provided -> run only those
        checker_specs = list(args.checker)

    exclude = set(args.exclude_checker or [])
    checker_specs = [s for s in checker_specs if s not in exclude]

    if not checker_specs:
        raise RuntimeError("No checkers selected to run (after exclusions).")

    # --- Instantiate checkers ---
    checkers: List[Checker] = []
    for spec in checker_specs:
        checkers.append(_load_checker(spec, ctx=ctx, bootstrap=bootstrap))

    # --- Run + persist ---
    runner = CheckerRunner(finding_id_salt_mode=args.finding_id_mode)
    result = runner.run_many(checkers, ctx)

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=args.out,
            drop_invalid_on_cast=bool(args.drop_invalid_on_cast),
        )
    )
    writer.extend(result.valid_findings)
    stats = writer.close()

    # --- Summary ---
    print("=== Run summary ===")
    print(f"tenant: {args.tenant}")
    print(f"workspace: {args.workspace}")
    print(f"cloud: {args.cloud}")
    print(f"run_id: {run_id}")
    print(f"run_ts: {run_ts.astimezone(timezone.utc).isoformat().replace('+00:00','Z')}")
    print(f"checkers_selected: {len(checkers)}")

    print(f"engine_name: {ENGINE_NAME}")
    print(f"engine_version: {ENGINE_VERSION}")
    print(f"rulepack_version: {RULEPACK_VERSION}")
    print(f"schema_version: {SCHEMA_VERSION}")

    print(f"valid_findings: {len(result.valid_findings)}")
    print(f"invalid_findings: {result.invalid_findings}")

    print(f"writer_received: {stats.received}")
    print(f"writer_written: {stats.written}")
    print(f"writer_dropped_cast_errors: {stats.dropped_cast_errors}")

    if result.invalid_errors:
        print("\n--- Sample validation errors (contract layer) ---")
        for e in result.invalid_errors[:10]:
            print(f"- {e}")

    if stats.cast_errors:
        print("\n--- Sample storage cast errors (storage boundary) ---")
        for e in stats.cast_errors[:10]:
            print(f"- {e}")

    # Non-zero exit code if nothing was written but we did receive records
    if stats.written == 0 and stats.received > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
