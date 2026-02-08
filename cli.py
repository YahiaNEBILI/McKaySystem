"""
McKaySystem CLI (flat-layout friendly).

Usage
-----
mckay run-all --tenant engie --workspace noprod --out data/finops_findings --db-url "postgresql://..."
mckay run --tenant engie --workspace noprod --out data/finops_findings
mckay export
mckay zip
mckay ingest --db-url "postgresql://..."
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def _walk_up_for_root(start: Path) -> Optional[Path]:
    """Walk up from *start* to find a project root marker."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(10):
        if (cur / "pyproject.toml").exists() or (cur / "runner.py").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _repo_root() -> Path:
    """Resolve the working project root.

    When installed via pip, ``__file__`` points into site-packages, not the repo.
    In that scenario, we prefer the current working directory (CloudShell usage:
    you typically run the command from the repo).
    """
    return _walk_up_for_root(Path.cwd()) or _walk_up_for_root(Path(__file__)) or Path.cwd().resolve()


def _module_exists(mod_name: str) -> bool:
    return importlib.util.find_spec(mod_name) is not None


def _python() -> str:
    return sys.executable


def _run_cmd(cmd: List[str], *, cwd: Optional[Path] = None, env: Optional[dict] = None) -> None:
    try:
        subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)
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

    # Run as module so it works whether we're in-repo or installed as py-modules
    if not _module_exists("runner") and not (root / "runner.py").exists():
        raise SystemExit(
            "runner module not found. Run from the project directory or ensure runner.py is installed as a module."
        )

    cmd = [_python(), "-m", "runner", "--tenant", tenant, "--workspace", workspace, "--out", out_dir]
    _run_cmd(cmd, cwd=root)


def cmd_export(args: argparse.Namespace) -> None:  # pylint: disable=unused-argument
    root = _repo_root()
    if not _module_exists("export_findings") and not (root / "export_findings.py").exists():
        raise SystemExit(
            "export_findings module not found. Run from the project directory or ensure export_findings.py is installed."
        )
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")
    out_dir = args.out or _env_default("OUT_DIR", "data/finops_findings")

    if not tenant:
        raise SystemExit("Missing --tenant for export (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace for export (or WORKSPACE env var).")

    # Ensure downstream script sees the same run identity.
    env = dict(os.environ)
    env["TENANT_ID"] = tenant
    env["WORKSPACE"] = workspace

    manifest_path = str((Path(out_dir) / "run_manifest.json").resolve())
    cmd = [_python(), "-m", "export_findings", "--tenant-id", tenant, "--manifest", manifest_path]
    _run_cmd(cmd, cwd=root, env=env)


def cmd_zip(args: argparse.Namespace) -> None:
    root = _repo_root()
    webapp_dir = root / (args.webapp_dir or "webapp_data")
    zip_path = root / (args.zip_path or "webapp_data.zip")

    if not webapp_dir.exists() or not webapp_dir.is_dir():
        raise SystemExit(f"webapp_data directory not found: {webapp_dir}")

    import zipfile  # local import on purpose

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
    if not _module_exists("ingest_exported_json") and not (root / "ingest_exported_json.py").exists():
        raise SystemExit(
            "ingest_exported_json module not found. Run from the project directory or ensure ingest_exported_json.py is installed."
        )

    db_url = args.db_url or _env_default("DB_URL")
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")

    if not db_url:
        raise SystemExit("Missing --db-url (or DB_URL env var).")
    if not tenant:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    env = dict(os.environ)
    env["DB_URL"] = db_url
    env["TENANT_ID"] = tenant
    env["WORKSPACE"] = workspace

    _run_cmd([_python(), "-m", "ingest_exported_json"], cwd=root, env=env)


def cmd_run_all(args: argparse.Namespace) -> None:
    cmd_run(args)

    if not args.skip_export:
        cmd_export(args)

    if not args.skip_zip:
        cmd_zip(args)

    if args.skip_ingest:
        return

    db_url = args.db_url or _env_default("DB_URL")
    if not db_url:
        print("DB_URL not set and --db-url not provided → skipping ingest.")
        return

    cmd_ingest(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mckay", description="McKaySystem CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_tenant_workspace(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--tenant", default=None, help="Tenant id (or TENANT_ID env var).")
        sp.add_argument("--workspace", default=None, help="Workspace (or WORKSPACE env var).")

    sp = sub.add_parser("run", help="Run checkers and produce parquet output.")
    add_tenant_workspace(sp)
    sp.add_argument("--out", default=None, help="Output directory (or OUT_DIR env var). Default: data/finops_findings")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("export", help="Export findings to webapp_data/ (calls export_findings).")
    add_tenant_workspace(sp)
    sp.add_argument("--out", default=None, help="Output directory used by runner (or OUT_DIR env var).")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("zip", help="Zip webapp_data/ into webapp_data.zip")
    sp.add_argument("--webapp-dir", default=None, help="Directory to zip. Default: webapp_data")
    sp.add_argument("--zip-path", default=None, help="Zip output path. Default: webapp_data.zip")
    sp.set_defaults(func=cmd_zip)

    sp = sub.add_parser("ingest", help="Ingest exported JSON into DB (calls ingest_exported_json).")
    add_tenant_workspace(sp)
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.set_defaults(func=cmd_ingest)

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
