"""Tests for lifecycle audit write isolation via savepoints."""

from __future__ import annotations

from typing import Any

import apps.flask_api.flask_app as flask_app


class _FakeConn:
    """Minimal fake DB connection exposing cursor()."""

    def __init__(self, *, fail_finding_state_audit: bool, fail_lifecycle_audit: bool) -> None:
        self.aborted = False
        self.fail_finding_state_audit = fail_finding_state_audit
        self.fail_lifecycle_audit = fail_lifecycle_audit
        self.inserts: list[str] = []

    def cursor(self) -> _FakeCursor:
        """Return a fake cursor."""
        return _FakeCursor(self)


class _FakeCursor:
    """Cursor simulator with transaction-abort semantics."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        return False

    def execute(self, sql: str, params: Any = None) -> None:  # pylint: disable=unused-argument
        """Execute fake SQL and emulate abort/reset behavior."""
        text = str(sql).strip().upper()
        if text.startswith("SAVEPOINT "):
            return
        if text.startswith("ROLLBACK TO SAVEPOINT "):
            self._conn.aborted = False
            return
        if text.startswith("RELEASE SAVEPOINT "):
            return

        if self._conn.aborted:
            raise RuntimeError("current transaction is aborted")

        if "INSERT INTO FINDING_STATE_AUDIT" in text:
            if self._conn.fail_finding_state_audit:
                self._conn.aborted = True
                raise RuntimeError('relation "finding_state_audit" does not exist')
            self._conn.inserts.append("finding_state_audit")
            return

        if "INSERT INTO LIFECYCLE_AUDIT" in text:
            if self._conn.fail_lifecycle_audit:
                self._conn.aborted = True
                raise RuntimeError('relation "lifecycle_audit" does not exist')
            self._conn.inserts.append("lifecycle_audit")
            return


def _call_audit(conn: _FakeConn) -> None:
    """Invoke _audit_lifecycle with fixed values."""
    flask_app._audit_lifecycle(
        conn,
        tenant_id="engie",
        workspace="sbx",
        action="ignore",
        subject_type="fingerprint",
        subject_id="fp-1",
        state="ignored",
        snooze_until=None,
        reason="test",
        updated_by="probe-test",
    )


def test_audit_fallback_does_not_leave_aborted_transaction() -> None:
    """If first audit table is missing, fallback insert should still succeed."""
    conn = _FakeConn(fail_finding_state_audit=True, fail_lifecycle_audit=False)
    _call_audit(conn)
    assert conn.inserts == ["lifecycle_audit"]
    assert conn.aborted is False


def test_audit_failures_are_isolated_from_caller_transaction() -> None:
    """If both audit inserts fail, transaction state must be restored."""
    conn = _FakeConn(fail_finding_state_audit=True, fail_lifecycle_audit=True)
    _call_audit(conn)
    assert conn.inserts == []
    assert conn.aborted is False
