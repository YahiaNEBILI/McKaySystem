"""CLI entry points for running worker, ingest, export, recovery, and migrations."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from apps.backend.scope_bootstrap import (
    ScopeBootstrapOptions,
    ScopeBootstrapRequest,
    bootstrap_scope_admin,
)
from infra.config import get_settings

logger = logging.getLogger(__name__)


def _walk_up_for_root(start: Path) -> Path | None:
    """Walk up from *start* to find a project root marker."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(10):
        if (cur / "pyproject.toml").exists() or (cur / "apps/worker/runner.py").exists():
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


def _python() -> str:
    return sys.executable


def _run_cmd(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    try:
        subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def _env_default(name: str, default: str | None = None) -> str | None:
    settings = get_settings(reload=True)
    value_map = {
        "DB_URL": settings.db.url,
        "TENANT_ID": settings.worker.tenant_id,
        "WORKSPACE": settings.worker.workspace,
        "OUT_DIR": settings.worker.out_dir,
        "MANIFEST_PATH": settings.worker.manifest_path,
        "PRICING_VERSION": settings.worker.pricing_version,
        "FINOPS_PRICING_VERSION": settings.worker.pricing_version,
        "PRICING_SOURCE": settings.worker.pricing_source,
        "FINOPS_PRICING_SOURCE": settings.worker.pricing_source,
    }
    v = value_map.get(name)
    if v is None or str(v).strip() == "":
        return default
    return str(v)


def _pricing_env_from_args(args: argparse.Namespace) -> dict[str, str]:
    """Build optional pricing metadata env overrides for runner commands."""
    env: dict[str, str] = {}
    pricing_version = (
        getattr(args, "pricing_version", None)
        or _env_default("PRICING_VERSION")
        or _env_default("FINOPS_PRICING_VERSION")
    )
    pricing_source = (
        getattr(args, "pricing_source", None)
        or _env_default("PRICING_SOURCE")
        or _env_default("FINOPS_PRICING_SOURCE")
    )
    if pricing_version:
        env["PRICING_VERSION"] = pricing_version
    if pricing_source:
        env["PRICING_SOURCE"] = pricing_source
    return env


def cmd_run(args: argparse.Namespace) -> None:
    root = _repo_root()
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")
    out_dir = args.out or _env_default("OUT_DIR", "data/finops_findings")

    if not tenant:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    runner_module = "apps.worker.runner"
    if not (root / "apps/worker/runner.py").exists():
        raise SystemExit(f"{runner_module} module not found. Run from the project directory.")

    tenant_s = str(tenant)
    workspace_s = str(workspace)
    out_dir_s = str(out_dir or "data/finops_findings")
    cmd = [
        _python(),
        "-m",
        runner_module,
        "--tenant",
        tenant_s,
        "--workspace",
        workspace_s,
        "--out",
        out_dir_s,
    ]
    env = dict(os.environ)
    env.update(_pricing_env_from_args(args))
    _run_cmd(cmd, cwd=root, env=env)


def cmd_export(args: argparse.Namespace) -> None:
    root = _repo_root()
    export_module = "apps.worker.export_findings"
    if not (root / "apps/worker/export_findings.py").exists():
        raise SystemExit(f"{export_module} module not found. Run from the project directory.")
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

    out_dir_s = str(out_dir or "data/finops_findings")
    manifest_path = str((Path(out_dir_s) / "run_manifest.json").resolve())
    cmd = [_python(), "-m", export_module, "--tenant-id", str(tenant), "--manifest", manifest_path]
    _run_cmd(cmd, cwd=root, env=env)


def cmd_ingest(args: argparse.Namespace) -> None:
    root = _repo_root()
    ingest_module = "apps.worker.ingest_parquet"
    if not (root / "apps/worker/ingest_parquet.py").exists():
        raise SystemExit(f"{ingest_module} module not found. Run from the project directory.")

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

    cmd = [_python(), "-m", ingest_module]
    manifest_arg = getattr(args, "manifest", None)
    if manifest_arg:
        cmd.extend(["--manifest", str(manifest_arg)])
    else:
        out_dir = getattr(args, "out", None)
        if out_dir:
            mpath = Path(out_dir) / "run_manifest.json"
            if mpath.exists():
                cmd.extend(["--manifest", str(mpath)])
    _run_cmd(cmd, cwd=root, env=env)


def cmd_migrate(args: argparse.Namespace) -> None:
    root = _repo_root()
    migrate_module = "apps.backend.db_migrate"
    if not (root / "apps/backend/db_migrate.py").exists():
        raise SystemExit(
            f"{migrate_module} module not found. Run from the project directory."
        )

    env = None
    if args.db_url:
        env = dict(os.environ)
        env["DB_URL"] = args.db_url

    cmd = [_python(), "-m", migrate_module]
    if args.dry_run:
        cmd.append("--dry-run")
    if args.migrations_dir:
        cmd.extend(["--migrations-dir", str(args.migrations_dir)])
    _run_cmd(cmd, cwd=root, env=env)


def cmd_recover(args: argparse.Namespace) -> None:
    root = _repo_root()
    recover_module = "apps.worker.recover_runs"
    if not (root / "apps/worker/recover_runs.py").exists():
        raise SystemExit(
            f"{recover_module} module not found. Run from the project directory."
        )

    db_url = args.db_url or _env_default("DB_URL")
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")

    limit = getattr(args, "limit", None)
    if limit is None:
        limit = getattr(args, "recover_limit", 200)
    actor = getattr(args, "actor", None)
    if actor is None:
        actor = getattr(args, "recover_actor", None)

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

    try:
        limit_n = int(limit if limit is not None else 200)
    except (TypeError, ValueError) as exc:
        raise SystemExit("Invalid --limit value; expected integer.") from exc

    cmd = [
        _python(),
        "-m",
        recover_module,
        "--tenant",
        str(tenant),
        "--workspace",
        str(workspace),
        "--limit",
        str(max(1, limit_n)),
    ]
    if actor:
        cmd.extend(["--actor", str(actor)])
    _run_cmd(cmd, cwd=root, env=env)


def cmd_run_all(args: argparse.Namespace) -> None:
    cmd_run(args)

    if args.skip_ingest:
        if not args.skip_export:
            cmd_export(args)
        return

    db_url = args.db_url or _env_default("DB_URL")
    if not db_url:
        logger.warning("DB_URL not set and --db-url not provided; skipping ingest")
        if not args.skip_export:
            cmd_export(args)
        return

    if not args.skip_recover:
        cmd_recover(args)

    cmd_ingest(args)

    if not args.skip_export:
        cmd_export(args)


def _password_from_args(args: argparse.Namespace) -> str:
    """Resolve bootstrap password from CLI args or an environment variable.

    Args:
        args: Parsed command args.

    Returns:
        Plaintext password.

    Raises:
        SystemExit: Password is missing from both configured sources.
    """
    explicit = str(getattr(args, "password", "") or "").strip()
    if explicit:
        return explicit
    env_name = str(getattr(args, "password_env", "") or "").strip()
    if env_name:
        env_value = str(os.environ.get(env_name, "")).strip()
        if env_value:
            return env_value
    raise SystemExit("Missing bootstrap password: pass --password or set the configured --password-env variable.")


def cmd_bootstrap_scope(args: argparse.Namespace) -> None:
    """Bootstrap user + RBAC role for one tenant/workspace scope."""
    tenant = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")
    if not tenant:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    result = bootstrap_scope_admin(
        ScopeBootstrapRequest(
            tenant_id=str(tenant),
            workspace=str(workspace),
            user_id=str(args.user_id),
            email=str(args.email),
            password=_password_from_args(args),
            options=ScopeBootstrapOptions(
                full_name=args.full_name,
                role_id=args.role_id,
                granted_by=args.granted_by,
                is_superadmin=bool(args.superadmin),
                create_api_key=bool(args.create_api_key),
                api_key_name=args.api_key_name,
                api_key_description=args.api_key_description,
            ),
        )
    )
    sys.stdout.write(f"{json.dumps(result, separators=(',', ':'), sort_keys=True)}\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mckay", description="McKaySystem CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_tenant_workspace(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--tenant", default=None, help="Tenant id (or TENANT_ID env var).")
        sp.add_argument("--workspace", default=None, help="Workspace (or WORKSPACE env var).")

    def add_pricing_metadata(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--pricing-version",
            default=None,
            help=(
                "Pricing snapshot version for run metadata "
                "(or PRICING_VERSION / FINOPS_PRICING_VERSION env var)."
            ),
        )
        sp.add_argument(
            "--pricing-source",
            default=None,
            help=(
                "Pricing source label for run metadata "
                "(or PRICING_SOURCE / FINOPS_PRICING_SOURCE env var)."
            ),
        )

    sp = sub.add_parser("run", help="Run checkers and produce parquet output.")
    add_tenant_workspace(sp)
    add_pricing_metadata(sp)
    sp.add_argument("--out", default=None, help="Output directory (or OUT_DIR env var). Default: data/finops_findings")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("export", help="Export findings to webapp_data/ (calls export_findings).")
    add_tenant_workspace(sp)
    sp.add_argument("--out", default=None, help="Output directory used by runner (or OUT_DIR env var).")
    sp.set_defaults(func=cmd_export)
    sp = sub.add_parser("ingest", help="Ingest parquet datasets into DB (calls ingest_parquet).")
    add_tenant_workspace(sp)
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.add_argument("--manifest", default=None, help="Path to run_manifest.json (optional).")
    sp.set_defaults(func=cmd_ingest)
    sp = sub.add_parser("recover", help="Recover stale run locks/states for one tenant/workspace.")
    add_tenant_workspace(sp)
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.add_argument("--limit", type=int, default=200, help="Max rows per recovery step (default: 200).")
    sp.add_argument("--actor", default=None, help="Actor id recorded in run_events.")
    sp.set_defaults(func=cmd_recover)
    sp = sub.add_parser("migrate", help="Apply database migrations.")
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.add_argument("--dry-run", action="store_true", help="Show pending migrations without applying.")
    sp.add_argument("--migrations-dir", default=None, help="Path to migrations directory (optional).")
    sp.set_defaults(func=cmd_migrate)
    sp = sub.add_parser("run-all", help="Run -> ingest -> (optional) export.")
    add_tenant_workspace(sp)
    add_pricing_metadata(sp)
    sp.add_argument("--out", default=None, help="Output directory (or OUT_DIR env var).")
    sp.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    sp.add_argument("--skip-export", action="store_true", help="Skip export step.")
    sp.add_argument("--skip-ingest", action="store_true", help="Skip ingest step.")
    sp.add_argument("--skip-recover", action="store_true", help="Skip stale run recovery before ingest.")
    sp.add_argument("--recover-limit", type=int, default=200, help="Recovery row limit before ingest.")
    sp.add_argument("--recover-actor", default=None, help="Recovery actor id before ingest.")
    sp.set_defaults(func=cmd_run_all)

    sp = sub.add_parser(
        "bootstrap-scope",
        help=(
            "Idempotently bootstrap scoped RBAC access: seed scope, upsert user, "
            "assign role, and optionally issue one API key."
        ),
    )
    add_tenant_workspace(sp)
    sp.add_argument("--user-id", required=True, help="Scoped user identifier.")
    sp.add_argument("--email", required=True, help="User email (normalized to lowercase).")
    sp.add_argument(
        "--password",
        default=None,
        help="Plaintext password. Prefer using --password-env to avoid shell history leakage.",
    )
    sp.add_argument(
        "--password-env",
        default="MCKAY_BOOTSTRAP_PASSWORD",
        help="Environment variable name to read password from when --password is omitted.",
    )
    sp.add_argument("--full-name", default=None, help="Optional user display name.")
    sp.add_argument("--role-id", default="admin", help="Role id to assign (default: admin).")
    sp.add_argument(
        "--granted-by",
        default="bootstrap-cli",
        help="Grant actor marker stored in user_workspace_roles.",
    )
    sp.add_argument(
        "--superadmin",
        action="store_true",
        help="Set users.is_superadmin=true for this user.",
    )
    sp.add_argument(
        "--create-api-key",
        action="store_true",
        help="Create and return one raw API key for the bootstrapped user.",
    )
    sp.add_argument(
        "--api-key-name",
        default="bootstrap-cli",
        help="API key name when --create-api-key is used.",
    )
    sp.add_argument(
        "--api-key-description",
        default=None,
        help="Optional API key description when --create-api-key is used.",
    )
    sp.set_defaults(func=cmd_bootstrap_scope)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()



