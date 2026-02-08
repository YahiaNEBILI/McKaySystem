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
from pathlib import Path

from infra.pipeline_paths import PipelinePaths
from pipeline.export_json import ExportConfig, run_export
import json

from pipeline.run_manifest import find_manifest, load_manifest


def main() -> None:
    """Run the JSON export using the repository default paths."""

    parser = argparse.ArgumentParser(description="Export findings to JSON.")
    parser.add_argument(
        "--manifest",
        default=None,
        help=(
            "Optional path to run_manifest.json. If provided (or discoverable), "
            "tenant/workspace and dataset paths will be sourced from the manifest."
        ),
    )
    parser.add_argument(
        "--tenant-id",
        default=None,
        help="Tenant id to filter the export (or set TENANT_ID).",
    )
    args = parser.parse_args()

    paths = PipelinePaths()

    # Prefer manifest if available to avoid hidden defaults.
    manifest = None
    mpath = Path(args.manifest).resolve() if args.manifest else None
    if mpath and mpath.exists():
        manifest = load_manifest(mpath)
    else:
        discovered = find_manifest(Path.cwd())
        if discovered and discovered.exists():
            manifest = load_manifest(discovered)

    tenant_id = (args.tenant_id or os.environ.get("TENANT_ID") or "").strip()
    if manifest and not tenant_id:
        tenant_id = manifest.tenant_id

    if not tenant_id:
        raise SystemExit("Missing --tenant-id (or TENANT_ID env var, or a manifest with tenant_id).")

    # If we have manifest paths, export from those; otherwise fall back to defaults.
    if manifest and (manifest.out_raw or manifest.out_correlated):
        globs = []
        if manifest.out_raw:
            globs.append(str(Path(manifest.out_raw) / "**/*.parquet"))
        if manifest.out_correlated:
            globs.append(str(Path(manifest.out_correlated) / "**/*.parquet"))
    else:
        globs = paths.export_findings_globs()

    out_dir = str(paths.export_dir())
    if manifest and manifest.export_dir:
        out_dir = str(manifest.export_dir)

    cfg = ExportConfig(findings_globs=globs, tenant_id=tenant_id, out_dir=out_dir)
    run_export(cfg)

    # Copy the manifest alongside webapp JSON so downstream consumers can validate.
    if manifest:
        out_p = Path(out_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        (out_p / "run_manifest.json").write_text(
            json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()