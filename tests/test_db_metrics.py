"""Unit tests for DB query instrumentation helpers."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import apps.backend.db as db_mod
import apps.backend.db_metrics as db_metrics


class _FakeCursor:
    """Minimal cursor implementation used for DB instrumentation tests."""

    def __init__(self) -> None:
        self.executed_sql: list[str] = []
        self.executed_many_sql: list[str] = []
        self.description = [("ok", None, None, None, None, None, None)]

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False

    def execute(self, sql: str, params: Sequence[Any]) -> None:
        """Record execute SQL."""
        _ = params
        self.executed_sql.append(str(sql))

    def executemany(self, sql: str, seq_of_params: Sequence[Sequence[Any]]) -> None:
        """Record executemany SQL."""
        _ = seq_of_params
        self.executed_many_sql.append(str(sql))

    def fetchone(self) -> tuple[int]:
        """Return one fixed row."""
        return (1,)

    def fetchall(self) -> list[tuple[int]]:
        """Return fixed rows."""
        return [(1,)]


class _FakeConn:
    """Minimal connection exposing cursor()."""

    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _FakeCursor:
        """Return shared fake cursor instance."""
        return self._cursor


def test_measure_query_emits_histogram(monkeypatch: Any) -> None:
    """measure_query should emit a histogram observation with query tag."""
    monkeypatch.setenv("DB_QUERY_METRICS_ENABLED", "1")
    monkeypatch.setenv("DB_SLOW_QUERY_THRESHOLD_MS", "9999")

    ticks = iter([1.0, 1.25])
    monkeypatch.setattr(db_metrics.time, "perf_counter", lambda: next(ticks))

    seen: list[tuple[str, float, list[str]]] = []

    def _emit(name: str, value: float, tags: Sequence[str]) -> None:
        seen.append((name, value, list(tags)))

    db_metrics.register_histogram_emitter(_emit)
    try:
        with db_metrics.measure_query("fetch_findings"):
            pass
    finally:
        db_metrics.register_histogram_emitter(None)

    assert len(seen) == 1
    metric_name, value, tags = seen[0]
    assert metric_name == "db_query_duration_ms"
    assert value == 250.0
    assert tags == ["query:fetch_findings"]


def test_measure_query_logs_slow_query(monkeypatch: Any, caplog: Any) -> None:
    """measure_query should emit warning logs when threshold is exceeded."""
    monkeypatch.setenv("DB_QUERY_METRICS_ENABLED", "1")
    monkeypatch.setenv("DB_SLOW_QUERY_THRESHOLD_MS", "10")

    ticks = iter([2.0, 2.05])  # 50ms
    monkeypatch.setattr(db_metrics.time, "perf_counter", lambda: next(ticks))

    caplog.set_level("WARNING")
    with db_metrics.measure_query("slow_path"):
        pass

    messages = [r.message for r in caplog.records]
    assert any("slow_query query_name=slow_path duration_ms=50.00" in m for m in messages)


def test_measure_query_disabled_skips_emission(monkeypatch: Any) -> None:
    """measure_query should not emit metrics when instrumentation is disabled."""
    monkeypatch.setenv("DB_QUERY_METRICS_ENABLED", "0")
    monkeypatch.setenv("DB_SLOW_QUERY_THRESHOLD_MS", "0")

    seen: list[tuple[str, float, list[str]]] = []

    def _emit(name: str, value: float, tags: Sequence[str]) -> None:
        seen.append((name, value, list(tags)))

    db_metrics.register_histogram_emitter(_emit)
    try:
        with db_metrics.measure_query("disabled_case"):
            pass
    finally:
        db_metrics.register_histogram_emitter(None)

    assert seen == []


def test_db_conn_primitives_use_measure_query(monkeypatch: Any) -> None:
    """db primitives should wrap execution with measure_query labels."""
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)

    measured: list[str] = []

    @contextmanager
    def _capture(name: str) -> Iterator[None]:
        measured.append(name)
        yield

    monkeypatch.setattr(db_mod, "measure_query", _capture)

    _ = db_mod.fetch_one_conn(conn, "SELECT 1")
    _ = db_mod.fetch_all_conn(conn, "SELECT 2")
    _ = db_mod.fetch_one_dict_conn(conn, "SELECT 3")
    _ = db_mod.fetch_all_dict_conn(conn, "SELECT 4")
    db_mod.execute_conn(conn, "UPDATE t SET x = 1")
    db_mod.execute_many_conn(conn, "INSERT INTO t(x) VALUES (%s)", [(1,), (2,)])

    assert measured == [
        "fetch_one_conn:select",
        "fetch_all_conn:select",
        "fetch_one_dict_conn:select",
        "fetch_all_dict_conn:select",
        "execute_conn:update",
        "execute_many_conn:insert",
    ]
