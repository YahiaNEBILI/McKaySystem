"""Recover stale run orchestration state for one tenant/workspace."""

from __future__ import annotations

import argparse
import os

from apps.backend.db import db_conn
from apps.backend.run_state import default_owner, recover_stale_runs_for_scope
from infra.config import get_settings


def _env_default(name: str, default: str | None = None) -> str | None:
    """Return centralized config value for a known env key."""
    settings = get_settings(reload=True)
    value_map = {
        "DB_URL": settings.db.url,
        "TENANT_ID": settings.worker.tenant_id,
        "WORKSPACE": settings.worker.workspace,
    }
    value = value_map.get(name)
    if value is None or str(value).strip() == "":
        return default
    return str(value)


def run_recovery(*, tenant_id: str, workspace: str, actor: str, limit: int) -> None:
    """Run one committed recovery sweep for a single tenant/workspace scope."""
    with db_conn() as conn:
        stats = recover_stale_runs_for_scope(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            actor=actor,
            limit=limit,
        )
        conn.commit()
    print(
        "OK: run recovery complete "
        f"tenant={tenant_id} workspace={workspace} "
        f"expired_locks_reaped={stats.expired_locks_reaped} "
        f"stale_runs_failed={stats.stale_runs_failed}"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for stale-run recovery."""
    parser = argparse.ArgumentParser(description="Recover stale run state for one tenant/workspace.")
    parser.add_argument("--tenant", default=None, help="Tenant id (or TENANT_ID env var).")
    parser.add_argument("--workspace", default=None, help="Workspace (or WORKSPACE env var).")
    parser.add_argument("--db-url", default=None, help="Database URL (or DB_URL env var).")
    parser.add_argument("--actor", default=None, help="Actor identifier recorded in run_events.")
    parser.add_argument("--limit", type=int, default=200, help="Max rows per recovery step (default: 200).")
    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    tenant_id = args.tenant or _env_default("TENANT_ID")
    workspace = args.workspace or _env_default("WORKSPACE")
    db_url = args.db_url or _env_default("DB_URL")
    actor = args.actor or default_owner("run_recover")

    if not tenant_id:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")
    if not db_url:
        raise SystemExit("Missing --db-url (or DB_URL env var).")

    os.environ["DB_URL"] = db_url
    run_recovery(
        tenant_id=tenant_id,
        workspace=workspace,
        actor=actor,
        limit=max(1, int(args.limit)),
    )


if __name__ == "__main__":
    main()
