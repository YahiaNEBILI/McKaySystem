"""Tests for pooled DB connection lifecycle behavior."""

from __future__ import annotations

from typing import Any

import apps.backend.db as db_mod


class _FakeConn:
    """Minimal fake psycopg2 connection."""

    def __init__(self, *, rollback_raises: bool = False) -> None:
        self.rollback_calls = 0
        self.close_calls = 0
        self._rollback_raises = rollback_raises

    def rollback(self) -> None:
        """Record rollback and optionally raise."""
        self.rollback_calls += 1
        if self._rollback_raises:
            raise RuntimeError("rollback failed")

    def close(self) -> None:
        """Record close call."""
        self.close_calls += 1


class _FakePool:
    """Minimal fake pool exposing getconn/putconn."""

    def __init__(self, conn: _FakeConn, *, put_raises: bool = False) -> None:
        self._conn = conn
        self.put_calls = 0
        self._put_raises = put_raises

    def getconn(self) -> _FakeConn:
        """Return the managed fake connection."""
        return self._conn

    def putconn(self, conn: _FakeConn) -> None:
        """Record putconn call and optionally raise."""
        assert conn is self._conn
        self.put_calls += 1
        if self._put_raises:
            raise RuntimeError("putconn failed")


def test_db_conn_rolls_back_before_return(monkeypatch: Any) -> None:
    """db_conn should rollback before returning a connection to pool."""
    conn = _FakeConn()
    pool = _FakePool(conn)
    monkeypatch.setattr(db_mod, "_get_pool", lambda: pool)

    with db_mod.db_conn() as acquired:
        assert acquired is conn

    assert conn.rollback_calls == 1
    assert pool.put_calls == 1
    assert conn.close_calls == 0


def test_db_conn_still_returns_connection_when_rollback_fails(monkeypatch: Any) -> None:
    """Rollback failures should not prevent returning the connection to pool."""
    conn = _FakeConn(rollback_raises=True)
    pool = _FakePool(conn)
    monkeypatch.setattr(db_mod, "_get_pool", lambda: pool)

    with db_mod.db_conn():
        pass

    assert conn.rollback_calls == 1
    assert pool.put_calls == 1
    assert conn.close_calls == 0


def test_db_conn_closes_when_putconn_fails(monkeypatch: Any) -> None:
    """If putconn fails, db_conn should close the connection."""
    conn = _FakeConn()
    pool = _FakePool(conn, put_raises=True)
    monkeypatch.setattr(db_mod, "_get_pool", lambda: pool)

    with db_mod.db_conn():
        pass

    assert conn.rollback_calls == 1
    assert pool.put_calls == 1
    assert conn.close_calls == 1
