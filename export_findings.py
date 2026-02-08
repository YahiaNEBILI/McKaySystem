"""Convenience script to export findings to JSON.

This module is intentionally tiny so it can be used as a one-liner during local
development:

  python export_findings.py

It reads the default pipeline paths from :class:`infra.pipeline_paths.PipelinePaths`
and runs :func:`pipeline.export_json.run_export`.

Notes
-----
- The tenant id is an input to the export (used to filter / label output). For
  real usage, prefer calling :func:`pipeline.export_json.run_export` from your
  own driver script and passing the tenant id explicitly.
"""

import argparse
import os

from infra.pipeline_paths import PipelinePaths
from pipeline.export_json import ExportConfig, run_export


def main() -> None:
    """Run the JSON export using the repository default paths."""

    parser = argparse.ArgumentParser(description="Export findings to JSON.")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("TENANT_ID", "engie"),
        help="Tenant id to filter the export (or set TENANT_ID).",
    )
    args = parser.parse_args()

    paths = PipelinePaths()
    cfg = ExportConfig(
        findings_globs=paths.export_findings_globs(),
        tenant_id=args.tenant_id,
        out_dir=str(paths.export_dir()),
    )
    run_export(cfg)


if __name__ == "__main__":
    main()