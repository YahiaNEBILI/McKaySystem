"""Unit tests for db_migrate helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from apps.backend import db_migrate


def test_split_sql_handles_single_quotes() -> None:
    sql = "INSERT INTO t VALUES ('a;b'); SELECT 1;"
    stmts = db_migrate._split_sql(sql)  # pylint: disable=protected-access
    assert len(stmts) == 2
    assert "INSERT INTO t" in stmts[0]
    assert "SELECT 1" in stmts[1]


def test_split_sql_handles_dollar_quoting() -> None:
    sql = """
    CREATE OR REPLACE FUNCTION foo() RETURNS void AS $$
    BEGIN
      PERFORM 1;
      PERFORM 2;
    END;
    $$ LANGUAGE plpgsql;
    CREATE TABLE t(x int);
    """
    stmts = db_migrate._split_sql(sql)  # pylint: disable=protected-access
    assert len(stmts) == 2
    assert "FUNCTION foo" in stmts[0]
    assert "CREATE TABLE t" in stmts[1]


def test_split_sql_handles_tagged_dollar_quoting() -> None:
    sql = """
    DO $tag$
    BEGIN
      PERFORM 1;
    END;
    $tag$;
    SELECT 1;
    """
    stmts = db_migrate._split_sql(sql)  # pylint: disable=protected-access
    assert len(stmts) == 2
    assert "DO $tag$" in stmts[0]
    assert "SELECT 1" in stmts[1]


def test_execute_stmt_concurrently_uses_direct_conn(monkeypatch) -> None:
    called = []

    def _fake_execute(sql: str) -> None:
        called.append(sql)

    monkeypatch.setattr(db_migrate, "_execute_concurrently", _fake_execute)

    class DummyConn:
        pass

    db_migrate._execute_stmt(DummyConn(), "CREATE INDEX CONCURRENTLY idx_x ON t(x)")
    assert called


def test_pending_migration_versions_returns_only_pending(monkeypatch) -> None:
    monkeypatch.setattr(db_migrate, "_ensure_migrations_table", lambda _conn: None)
    monkeypatch.setattr(db_migrate, "_applied_versions", lambda _conn: {"001_init"})
    monkeypatch.setattr(
        db_migrate,
        "_iter_migration_files",
        lambda _migrations_dir: [Path("001_init.sql"), Path("002_next.sql"), Path("003_more.py")],
    )

    pending = db_migrate.pending_migration_versions(object(), migrations_dir=Path("migrations"))
    assert pending == ["002_next", "003_more"]


def test_ensure_schema_current_raises_on_pending_migrations(monkeypatch) -> None:
    class _DummyCtx:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
            return False

    monkeypatch.setattr(db_migrate, "db_conn", lambda: _DummyCtx())
    monkeypatch.setattr(
        db_migrate,
        "pending_migration_versions",
        lambda _conn, migrations_dir: ["003_finding_aggregates_current"],
    )

    with pytest.raises(RuntimeError, match="003_finding_aggregates_current"):
        db_migrate.ensure_schema_current(migrations_dir=Path("migrations"))
