"""
runner.py

FinOps SaaS runner (checkers -> validated wire findings -> storage-cast -> parquet).

Run this from repo root.

Example (PowerShell):
  python runner.py --tenant acme --workspace prod `
    --checker checks.aws.ec2_graviton:ExampleGravitonChecker `
    --out data/finops_findings

If your imports are "from contracts..." / "from pipeline..." / "from checks...",
ensure your repo root is on PYTHONPATH (pytest.ini already does this for tests).
"""

from __future__ import annotations

import argparse
import importlib
import sys
from datetime import datetime, timezone
from typing import List, Sequence

from contracts.finops_checker_pattern import Checker, CheckerRunner, RunContext
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig

from version import ENGINE_NAME, ENGINE_VERSION, RULEPACK_VERSION, SCHEMA_VERSION


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_run_id(run_ts: datetime) -> str:
    return f"run-{run_ts.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')}"


def _load_checker(dotted_path: str) -> Checker:
    """
    Load a checker instance from a dotted import path.

    Format:
      module.path:ClassName

    Example:
      checks.aws.ec2_graviton:ExampleGravitonChecker
    """
    if ":" not in dotted_path:
        raise ValueError("Checker path must be like 'module.path:ClassName'")
    module_path, class_name = dotted_path.split(":", 1)

    module = importlib.import_module(module_path)
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

    parser.add_argument(
        "--checker",
        action="append",
        required=True,
        help="Checker to run, format: module.path:ClassName. Can be provided multiple times.",
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
    )

    checkers: List[Checker] = []
    for dotted in args.checker:
        checkers.append(_load_checker(dotted))

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

    print("=== Run summary ===")
    print(f"tenant: {args.tenant}")
    print(f"workspace: {args.workspace}")
    print(f"cloud: {args.cloud}")
    print(f"run_id: {run_id}")
    print(f"run_ts: {run_ts.astimezone(timezone.utc).isoformat().replace('+00:00','Z')}")
    print(f"checkers: {len(checkers)}")

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
