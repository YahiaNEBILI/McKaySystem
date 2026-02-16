"""
Minimal migration runner for the Postgres schema.

Usage:
  python -m apps.backend.db_migrate
  python -m apps.backend.db_migrate --dry-run
  python -m apps.backend.db_migrate --migrations-dir migrations
"""

from __future__ import annotations

import argparse
import importlib.util
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path

from apps.backend.db import db_conn
from infra.config import get_settings


def _ensure_migrations_table(conn) -> None:
    """Create schema_migrations table if missing."""
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
              version TEXT PRIMARY KEY,
              applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    conn.commit()


def _applied_versions(conn) -> set[str]:
    """Return applied migration versions from the DB."""
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations")
        rows = cur.fetchall() or []
    return {str(r[0]) for r in rows if r and r[0]}


def _split_sql(sql: str) -> list[str]:
    """Split a SQL file into statements (supports comments and dollar-quoting)."""
    statements: list[str] = []
    buf: list[str] = []
    in_squote = False
    in_line_comment = False
    in_block_comment = False
    in_dollar = False
    dollar_tag = ""

    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            buf.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                buf.append(ch)
                buf.append(nxt)
                i += 2
                continue
            buf.append(ch)
            i += 1
            continue

        if in_squote:
            buf.append(ch)
            if ch == "'":
                if nxt == "'":
                    buf.append(nxt)
                    i += 2
                    continue
                in_squote = False
            i += 1
            continue

        if in_dollar:
            if dollar_tag and sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                in_dollar = False
                dollar_tag = ""
                continue
            buf.append(ch)
            i += 1
            continue

        if ch == "-" and nxt == "-":
            in_line_comment = True
            buf.append(ch)
            buf.append(nxt)
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            buf.append(ch)
            buf.append(nxt)
            i += 2
            continue
        if ch == "'":
            in_squote = True
            buf.append(ch)
            i += 1
            continue
        if ch == "$":
            j = i + 1
            while j < n and sql[j] != "$":
                if not (sql[j].isalnum() or sql[j] == "_"):
                    j = -1
                    break
                j += 1
            if j != -1 and j < n and sql[j] == "$":
                dollar_tag = sql[i : j + 1]
                in_dollar = True
                buf.append(dollar_tag)
                i = j + 1
                continue

        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _db_url() -> str:
    """Read DB_URL from the environment."""
    url = str(get_settings(reload=True).db.url or "").strip()
    if not url:
        raise RuntimeError("DB_URL is not set. Use `mckay migrate --db-url ...` or set DB_URL.")
    return url


@contextmanager
def _direct_conn():
    """Create a direct psycopg2 connection (outside pool)."""
    import psycopg2  # type: ignore

    conn = psycopg2.connect(dsn=_db_url())
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _execute_concurrently(stmt: str) -> None:
    """Execute a CONCURRENTLY statement using a direct connection."""
    with _direct_conn() as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(stmt)


def _execute_stmt(conn, stmt: str) -> None:
    """Execute a single SQL statement, handling CONCURRENTLY safely."""
    sql = stmt.strip()
    if not sql:
        return
    if "CONCURRENTLY" in sql.upper():
        _execute_concurrently(sql)
        return

    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()


def _apply_sql_migration(conn, path: Path) -> None:
    """Apply a .sql migration file."""
    raw = path.read_text(encoding="utf-8")
    for stmt in _split_sql(raw):
        _execute_stmt(conn, stmt)


def _apply_py_migration(conn, path: Path) -> None:
    """Apply a .py migration module with upgrade(conn)."""
    mod_name = f"migration_{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load migration module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    if not hasattr(module, "upgrade"):
        raise RuntimeError(f"Migration module missing upgrade(): {path}")
    module.upgrade(conn)


def _iter_migration_files(migrations_dir: Path) -> Iterable[Path]:
    """List migration files in name order."""
    files = []
    if not migrations_dir.exists():
        return files
    for p in migrations_dir.iterdir():
        if p.is_file() and p.suffix in {".sql", ".py"}:
            files.append(p)
    return sorted(files, key=lambda p: p.name)


def pending_migration_versions(conn, *, migrations_dir: Path) -> list[str]:
    """Return pending migration versions for the provided connection."""
    _ensure_migrations_table(conn)
    applied = _applied_versions(conn)
    pending: list[str] = []
    for path in _iter_migration_files(migrations_dir):
        version = path.stem
        if version not in applied:
            pending.append(version)
    return pending


def ensure_schema_current(*, migrations_dir: Path) -> None:
    """Fail fast when database schema is behind local migrations."""
    with db_conn() as conn:
        pending = pending_migration_versions(conn, migrations_dir=migrations_dir)
    if pending:
        pending_csv = ", ".join(pending)
        raise RuntimeError(
            f"Database schema is out of date. Pending migrations: {pending_csv}. "
            "Run `mckay migrate` (or `python -m apps.backend.db_migrate`) before ingest/API startup."
        )


def run_migrations(*, migrations_dir: Path, dry_run: bool = False) -> None:
    """Apply pending migrations (or print them in dry-run)."""
    with db_conn() as conn:
        pending_versions = set(pending_migration_versions(conn, migrations_dir=migrations_dir))
        pending = [p for p in _iter_migration_files(migrations_dir) if p.stem in pending_versions]

        if dry_run:
            for p in pending:
                print(f"PENDING: {p.name}")
            if not pending:
                print("No pending migrations.")
            return

        for path in pending:
            version = path.stem
            print(f"Applying {path.name}...")
            if path.suffix == ".sql":
                _apply_sql_migration(conn, path)
            else:
                _apply_py_migration(conn, path)

            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)",
                    (version,),
                )
            conn.commit()
            print(f"Applied {version}")


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Apply database migrations.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show pending migrations without applying.",
    )
    parser.add_argument(
        "--migrations-dir",
        default=str(Path(__file__).resolve().parents[2] / "migrations"),
        help="Path to migrations directory (default: ./migrations).",
    )
    args = parser.parse_args(argv)

    run_migrations(
        migrations_dir=Path(args.migrations_dir),
        dry_run=bool(args.dry_run),
    )


if __name__ == "__main__":
    main()
