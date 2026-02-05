"""
mckaysystem/cli.py

Single-entry CLI to run McKaySystem end-to-end (CloudShell-friendly).

Replaces the manual sequence:
- python runner.py --tenant ... --workspace ... --out ...
- python export_findings.py
- zip -r webapp_data.zip webapp_data/
- export DB_URL=...
- export TENANT_ID=...
- export WORKSPACE=...
- python ingest_exported_json.py

Usage
-----
# After: pip install -e .[dev]  (or pip install .)
mckay run-all --tenant engie --workspace noprod --out data/finops_findings --db-url "postgresql://..."

# Or step-by-step
mckay run --tenant engie --workspace noprod --out data/finops_findings
mckay export
mckay zip
mckay ingest --db-url "postgresql://..."
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def _repo_root() -> Path:
    """
    Best-effort repo root resolver.

    We keep it simple: assume CLI lives at <repo>/mckaysystem/cli.py.
    """
    return Path(__file__).resolve().parents[1]


def _python() -> str:
    return sys.executable


def _run_cmd(cmd: List[str], *, cwd: Optional[Path] = None) -> None:
    try:
        subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def _env_default(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v


def cmd_run(args: argparse.Namespace) -> None:
    root = _repo_root()
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")
    out_dir = args.out or _env_default("OUT_DIR", "data/finops_findings")

    if not tenant:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    runner = root / "runner.py"
    if not runner.exists():
        raise SystemExit(f"runner.py not found at {runner}")

    cmd = [_python(), str(runner), "--tenant", tenant, "--workspace", workspace, "--out", out_dir]
    _run_cmd(cmd, cwd=root)


def cmd_export(args: argparse.Namespace) -> None:  # pylint: disable=unused-argument
    root = _repo_root()
    exporter = root / "export_findings.py"
    if not exporter.exists():
        raise SystemExit(f"export_findings.py not found at {exporter}")

    _run_cmd([_python(), str(exporter)], cwd=root)


def cmd_zip(args: argparse.Namespace) -> None:
    root = _repo_root()
    webapp_dir = root / (args.webapp_dir or "webapp_data")
    zip_path = root / (args.zip_path or "webapp_data.zip")

    if not webapp_dir.exists() or not webapp_dir.is_dir():
        raise SystemExit(f"webapp_data directory not found: {webapp_dir}")

    # Prefer Python stdlib zipfile to avoid relying on zip binary in every environment.
    import zipfile  # local import on purpose

    # Create zip (overwrite)
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(webapp_dir.rglob("*")):
            if p.is_dir():
                continue
            arcname = p.relative_to(root)
            zf.write(p, arcname.as_posix())

    print(f"Wrote {zip_path}")


def cmd_ingest(args: argparse.Namespace) -> None:
    root = _repo_root()
    ingester = root / "ingest_exported_json.py"
    if not ingester.exists():
        raise SystemExit(f"ingest_exported_json.py not found at {ingester}")

    db_url = args.db_url or _env_default("DB_URL")
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")

    if not db_url:
        raise SystemExit("Missing --db-url (or DB_URL env var).")
    if not tenant:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    # The ingester script expects env vars (per your current workflow).
    env = dict(os.environ)
    env["DB_URL"] = db_url
    env["TENANT_ID"] = tenant
    env["WORKSPACE"] = workspace

    try:
        subprocess.run([_python(), str(ingester)], cwd=str(root), env=env, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def cmd_run_all(args: argparse.Namespace) -> None:
    # 1) run
    cmd_run(args)

    # 2) export
    if not args.skip_export:
        cmd_export(args)

    # 3) zip
    if not args.skip_zip:
        cmd_zip(args)

    # 4) ingest (optional)
    if args.skip_ingest:
        return

    # Ingest only if db_url present (arg or env), else be explicit.
    db_url = args.db_url or _env_default("DB_URL")
    if not db_url:
        print("DB_URL not set and --db-url not provided → skipping ingest.")
        return

    cmd_ingest(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mckay", description="McKaySystem CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Shared arguments helpers
    def add_tenant_workspace(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--tenant", default=None, help="Tenant id (or TENANT_ID env var).")
        sp.add_argument("--workspace", default=None, help="Workspace (or WORKSPACE env var).")

    # run
    sp = sub.add_parser("run", help="Run checkers and produce parquet output.")
    add_tenant_workspace(sp)
    sp.add_argument("--out", default=None, help="Output directory (or OUT_DIR env var). Default: data/finops_findings")
    sp.set_defaults(func=cmd_run)

    # export
    sp = sub.add_parser("export", help="Export findings to webapp_data/ (calls export_findings.py).")
    sp.set_defaults(func=cmd_export)

    # zip
    sp = sub.add_parser("zip", help="Zip webapp_data/ into webapp_data.zip")
    sp.add_argument("--webapp-dir", default=None, help="Directory to zip. Default: webapp_data")
    sp.add_argument("--zip-path", default=None, help="Zip output path. Default: webapp_data.zip")
    sp.set_defaults(func=cmd_zip)

    # ingest
    sp = sub.add_parser("ingest", help="Ingest exported JSON into DB (calls ingest_exported_json.py).")
    add_tenant_workspace(sp)
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.set_defaults(func=cmd_ingest)

    # run-all
    sp = sub.add_parser("run-all", help="Run → export → zip → (optional) ingest.")
    add_tenant_workspace(sp)
    sp.add_argument("--out", default=None, help="Output directory (or OUT_DIR env var).")
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.add_argument("--skip-export", action="store_true", help="Skip export step.")
    sp.add_argument("--skip-zip", action="store_true", help="Skip zip step.")
    sp.add_argument("--skip-ingest", action="store_true", help="Skip ingest step.")
    sp.add_argument("--webapp-dir", default=None, help="Directory to zip. Default: webapp_data")
    sp.add_argument("--zip-path", default=None, help="Zip output path. Default: webapp_data.zip")
    sp.set_defaults(func=cmd_run_all)

    return p


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
