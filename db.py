from __future__ import annotations

"""db.py

Tiny PostgreSQL helper module (psycopg2) with a process-global connection pool.

Design goals
------------
- Fast in hosted runtimes (e.g. PythonAnywhere + remote Postgres like Neon): reuse
  pooled connections instead of reconnecting per request.
- Simple primitives with explicit transaction control.
- Provide both tuple-based helpers and dict-row helpers (RealDictCursor).

Environment
-----------
- DB_URL (required)
- DB_POOL_MAXCONN (default 10)
- DB_CONNECT_TIMEOUT (default 5 seconds)
"""

import atexit
import json
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Sequence, Tuple, List, Dict


def _db_url() -> str:
    url = os.getenv("DB_URL")
    if not url:
        raise RuntimeError("DB_URL is not set")
    return url


_POOL = None
_POOL_DSN: Optional[str] = None


def _get_pool():
    """Return a process-global psycopg2 pool, creating it on first use."""
    global _POOL, _POOL_DSN

    dsn = _db_url()
    if _POOL is not None and _POOL_DSN == dsn:
        return _POOL

    import psycopg2  # type: ignore  # noqa: F401
    from psycopg2.pool import SimpleConnectionPool  # type: ignore

    _POOL = SimpleConnectionPool(
        minconn=1,
        maxconn=int(os.getenv("DB_POOL_MAXCONN", "10")),
        dsn=dsn,
        connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", "5")),
    )
    _POOL_DSN = dsn
    return _POOL


def _close_pool() -> None:
    """Close the pool on process exit."""
    global _POOL
    try:
        if _POOL is not None:
            _POOL.closeall()
    except Exception:
        # best-effort cleanup
        pass
    finally:
        _POOL = None


atexit.register(_close_pool)


@contextmanager
def db_conn() -> Iterator[Any]:
    """Yield a pooled psycopg2 connection.

    Callers should NOT close the connection; it is returned to the pool.
    """
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        try:
            pool.putconn(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------
# Low-level *_conn primitives
# ---------------------------

def fetch_one_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
    """Execute a query on an existing connection and return one row (or None)."""
    with conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()


def fetch_all_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> List[Tuple[Any, ...]]:
    """Execute a query on an existing connection and return all rows."""
    with conn.cursor() as cur:
        cur.execute(sql, params or ())
        return list(cur.fetchall())


def execute_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> None:
    """Execute a statement on an existing connection (no returned rows)."""
    with conn.cursor() as cur:
        cur.execute(sql, params or ())


# ---------------------------
# Dict-row helpers
# ---------------------------

def fetch_all_dict_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
    """Execute a query and return rows as dicts (RealDictCursor)."""
    from psycopg2.extras import RealDictCursor  # type: ignore

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params or ())
        return [dict(r) for r in cur.fetchall()]


def fetch_one_dict_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Dict[str, Any]]:
    """Execute a query and return a single row as dict (or None)."""
    from psycopg2.extras import RealDictCursor  # type: ignore

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params or ())
        row = cur.fetchone()
        return dict(row) if row else None


# ---------------------------
# Convenience helpers (pooled)
# ---------------------------

def fetch_one(sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
    with db_conn() as conn:
        try:
            return fetch_one_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def fetch_all(sql: str, params: Optional[Sequence[Any]] = None) -> List[Tuple[Any, ...]]:
    with db_conn() as conn:
        try:
            return fetch_all_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def fetch_one_dict(sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Dict[str, Any]]:
    with db_conn() as conn:
        try:
            return fetch_one_dict_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def fetch_all_dict(sql: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
    with db_conn() as conn:
        try:
            return fetch_all_dict_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def execute(sql: str, params: Optional[Sequence[Any]] = None) -> None:
    with db_conn() as conn:
        try:
            execute_conn(conn, sql, params)
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def execute_many(sql: str, seq_of_params: List[Sequence[Any]]) -> None:
    if not seq_of_params:
        return
    with db_conn() as conn:
        try:
            with conn.cursor() as cur:
                cur.executemany(sql, seq_of_params)
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


# ---------------------------
# JSON helpers
# ---------------------------

def to_jsonb(value: Any) -> str:
    """Serialize a Python object to a JSON string suitable for ::jsonb."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
