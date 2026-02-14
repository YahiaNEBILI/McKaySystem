from __future__ import annotations

"""Unit tests for db_migrate helpers."""

import db_migrate


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
