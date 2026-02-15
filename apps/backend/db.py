"""
db.py

Tiny DB helper module for PostgreSQL (psycopg2) with connection pooling.

Why pooling matters
-------------------
Opening a new connection per query is extremely slow with remote Postgres
(e.g. Neon) + hosted app runtimes (e.g. PythonAnywhere). We use a process-global
SimpleConnectionPool and provide small helpers for common patterns.

Additional helpers
------------------
This module also provides *_conn variants (e.g. fetch_all_conn) so request
handlers can reuse a single connection for many queries (reducing round-trips
and pool checkout overhead).

JSON helpers are included because the app stores/reads JSONB blobs (e.g.
dashboard_cache payload).
"""

from __future__ import annotations

import atexit
import json
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Sequence, Tuple

from apps.backend.db_metrics import measure_query


def _db_url() -> str:
    url = os.getenv("DB_URL")
    if not url:
        raise RuntimeError("DB_URL is not set")
    return url


# Keep a single global pool per process.
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
        pass
    finally:
        _POOL = None


atexit.register(_close_pool)


@contextmanager
def db_conn() -> Iterator[Any]:
    """Yield a pooled psycopg2 connection.

    IMPORTANT:
    - Reuses connections (pool) instead of reconnecting on every query.
    - Callers should NOT close the connection; it is returned to the pool.
    - Always ends any open transaction before returning the connection to pool.
    """
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        # Prevent "idle in transaction" pooled connections from reusing stale
        # snapshots across requests (critical for API read-after-write behavior).
        try:
            conn.rollback()
        except Exception:
            pass
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

def _query_name(sql: str, *, operation: str) -> str:
    """Return a stable query operation label for metrics/logging."""
    text = " ".join(str(sql or "").strip().split())
    if not text:
        return operation
    first_token = text.split(" ", 1)[0].lower()
    return f"{operation}:{first_token}"


def fetch_one_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
    """Execute a query on an existing connection and return one row (or None)."""
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="fetch_one_conn")):
            cur.execute(sql, params or ())
        return cur.fetchone()


def fetch_all_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> list[Tuple[Any, ...]]:
    """Execute a query on an existing connection and return all rows."""
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="fetch_all_conn")):
            cur.execute(sql, params or ())
        return cur.fetchall()


def execute_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> None:
    """Execute a statement on an existing connection (no returned rows)."""
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="execute_conn")):
            cur.execute(sql, params or ())


def execute_many_conn(conn: Any, sql: str, seq_of_params: list[Sequence[Any]]) -> None:
    """Execute a statement against many parameter sets on an existing connection."""
    if not seq_of_params:
        return
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="execute_many_conn")):
            cur.executemany(sql, seq_of_params)


# ---------------------------
# Convenience helpers (pooled)
# ---------------------------

def fetch_one(sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
    """Execute a query and return one row (or None)."""
    with db_conn() as conn:
        try:
            return fetch_one_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def fetch_all(sql: str, params: Optional[Sequence[Any]] = None) -> list[Tuple[Any, ...]]:
    """Execute a query and return all rows."""
    with db_conn() as conn:
        try:
            return fetch_all_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


def execute(sql: str, params: Optional[Sequence[Any]] = None) -> None:
    """Execute a statement (no returned rows) and commit."""
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


def execute_many(sql: str, seq_of_params: list[Sequence[Any]]) -> None:
    """Execute a statement against many parameter sets and commit."""
    if not seq_of_params:
        return
    with db_conn() as conn:
        try:
            execute_many_conn(conn, sql, seq_of_params)
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


def fetch_jsonb_one_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> Any:
    """Fetch a single JSON/JSONB column value from an existing connection."""
    row = fetch_one_conn(conn, sql, params)
    if not row:
        return None
    return row[0]


def fetch_jsonb_one(sql: str, params: Optional[Sequence[Any]] = None) -> Any:
    """Fetch a single JSON/JSONB column value using a pooled connection."""
    with db_conn() as conn:
        try:
            return fetch_jsonb_one_conn(conn, sql, params)
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


# ---------------------------
# Dict row helpers
# ---------------------------

def _cols_from_description(desc: Any) -> list[str]:
    """Extract column names from cursor.description safely."""
    if not desc:
        return []
    cols: list[str] = []
    for i, d in enumerate(desc):
        # psycopg2 description items are sequences; be defensive anyway
        name = None
        try:
            name = d[0]
        except (IndexError, KeyError, TypeError):
            name = None
        cols.append(str(name) if name else f"col_{i}")
    return cols


def _rows_to_dicts(cursor: Any, rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    """Convert cursor rows into list of dicts using cursor.description."""
    cols = _cols_from_description(getattr(cursor, "description", None))
    if not cols:
        return []
    # zip truncates to shortest; avoids IndexError if row/cols length mismatch
    return [dict(zip(cols, r, strict=False)) for r in rows]


def fetch_one_dict_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[dict[str, Any]]:
    """Execute a query and return one row as a dict (or None)."""
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="fetch_one_dict_conn")):
            cur.execute(sql, params or ())
        row = cur.fetchone()
        if row is None:
            return None
        cols = _cols_from_description(getattr(cur, "description", None))
        if not cols:
            return None
        return dict(zip(cols, row, strict=False))


def fetch_all_dict_conn(conn: Any, sql: str, params: Optional[Sequence[Any]] = None) -> list[dict[str, Any]]:
    """Execute a query and return all rows as dicts."""
    with conn.cursor() as cur:
        with measure_query(_query_name(sql, operation="fetch_all_dict_conn")):
            cur.execute(sql, params or ())
        rows = cur.fetchall()
        return _rows_to_dicts(cur, rows)
