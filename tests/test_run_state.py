"""Unit tests for run-state recovery helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from apps.backend import run_state


class _FakeCursor:
    """Very small cursor stub fed by a per-connection result queue."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self._rows: list[tuple[Any, ...]] = []
        self.rowcount = 0

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        self._conn.executes.append((sql, params))
        if self._conn.results:
            queued = self._conn.results.pop(0)
            self._rows = list(queued)
        else:
            self._rows = []
        self.rowcount = len(self._rows)

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _FakeConn:
    """Connection stub exposing ``cursor()`` and recording SQL calls."""

    def __init__(self, *, results: list[list[tuple[Any, ...]]]) -> None:
        self.results = list(results)
        self.executes: list[tuple[str, tuple[Any, ...] | None]] = []

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


def test_recover_stale_runs_for_scope_reaps_and_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expired locks are reaped and lockless running runs are failed with events."""
    expires_at = datetime(2026, 2, 14, 13, 0, tzinfo=timezone.utc)
    conn = _FakeConn(
        results=[
            [("run-a", "owner-a", expires_at)],
            [("run-a",), ("run-b",)],
        ]
    )

    events: list[dict[str, Any]] = []

    def _capture_event(_conn: Any, **kwargs: Any) -> None:
        events.append(kwargs)

    monkeypatch.setattr(run_state, "append_run_event", _capture_event)

    stats = run_state.recover_stale_runs_for_scope(
        conn,
        tenant_id="acme",
        workspace="prod",
        actor="recover:tester",
        limit=25,
    )

    assert stats.expired_locks_reaped == 1
    assert stats.stale_runs_failed == 2
    assert stats.recovered_run_ids == ("run-a", "run-b")
    assert len(events) == 3
    assert events[0]["event_type"] == "run.lock.expired"
    assert events[1]["payload"]["reason"] == "recovery:expired_lock"
    assert events[2]["payload"]["reason"] == "recovery:no_active_lock"
    assert all(e["tenant_id"] == "acme" for e in events)
    assert all(e["workspace"] == "prod" for e in events)


def test_recover_stale_runs_for_scope_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """No stale rows produces zero counts and no events."""
    conn = _FakeConn(results=[[], []])
    events: list[dict[str, Any]] = []

    def _capture_event(_conn: Any, **kwargs: Any) -> None:
        events.append(kwargs)

    monkeypatch.setattr(run_state, "append_run_event", _capture_event)

    stats = run_state.recover_stale_runs_for_scope(
        conn,
        tenant_id="acme",
        workspace="prod",
        actor="recover:tester",
        limit=5,
    )

    assert stats.expired_locks_reaped == 0
    assert stats.stale_runs_failed == 0
    assert stats.recovered_run_ids == ()
    assert events == []


def test_recover_stale_runs_for_scope_rejects_invalid_limit() -> None:
    """Recovery rejects non-positive limits."""
    conn = _FakeConn(results=[])
    with pytest.raises(ValueError, match="limit"):
        run_state.recover_stale_runs_for_scope(
            conn,
            tenant_id="acme",
            workspace="prod",
            actor="recover:tester",
            limit=0,
        )
