"""Unit tests for remediation worker queue/execution flow."""
# pylint: disable=too-few-public-methods,protected-access

from __future__ import annotations

from typing import Any, Literal

import pytest

from apps.worker import remediation_worker
from services.remediation.base import ActionResult


class _FakeCursor:
    """Minimal cursor test double for SQL capture in worker helpers."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.rowcount = conn.rowcount

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False

    def execute(self, sql: str, params: Any = None) -> None:
        self._conn.executes.append((sql, params))
        self.rowcount = self._conn.rowcount


class _FakeConn:
    """Minimal connection test double for worker helpers."""

    def __init__(self, *, rowcount: int = 1) -> None:
        self.rowcount = rowcount
        self.executes: list[tuple[str, Any]] = []

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def commit(self) -> None:
        return


class _ConnCtx:
    """Context manager returning a shared fake connection."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeConn:
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False


class _FakeOutcome:
    """Executor outcome stub compatible with worker expectations."""

    def __init__(self, *, ok: bool, message: str) -> None:
        self.result = ActionResult(ok=ok, message=message, details={"source": "test"})


class _FakeExecutor:
    """Executor stub returning deterministic outcome."""

    def __init__(self, *, ok: bool) -> None:
        self._ok = ok
        self.requests: list[Any] = []

    def run(self, request: Any) -> _FakeOutcome:
        self.requests.append(request)
        return _FakeOutcome(ok=self._ok, message="done" if self._ok else "failed")


class _FakeServicesFactory:
    """ServicesFactory stub that records requested region."""

    def __init__(self) -> None:
        self.regions: list[str] = []

    def for_region(self, region: str) -> Any:
        self.regions.append(region)
        return object()


def test_claim_actions_query_is_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Claim SQL must scope by tenant/workspace and approved status."""
    captured: dict[str, Any] = {}

    def _fake_fetch_all_dict_conn(_conn: Any, sql: str, params: Any = None) -> list[dict[str, Any]]:
        captured["sql"] = sql
        captured["params"] = params
        return []

    monkeypatch.setattr(remediation_worker, "fetch_all_dict_conn", _fake_fetch_all_dict_conn)
    rows = remediation_worker._claim_actions(
        object(),
        tenant_id="acme",
        workspace="prod",
        limit=7,
    )

    assert rows == []
    sql = str(captured.get("sql") or "").lower()
    assert "from remediation_actions" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql
    assert "status = %s" in sql
    assert "for update skip locked" in sql
    assert captured.get("params") == ("acme", "prod", "approved", 7, "running")


def test_update_action_result_requires_running_row() -> None:
    """Result update should fail fast when running row is missing."""
    conn = _FakeConn(rowcount=0)
    with pytest.raises(RuntimeError, match="remediation_action_update_failed"):
        remediation_worker._update_action_result(
            conn,
            outcome={
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-1",
                "status": "completed",
                "reason": "ok",
                "event_type": "remediation.completed",
                "actor_id": "worker:test",
                "execution_meta": {"execution": {"ok": True}},
            },
        )


def test_process_approved_actions_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Worker should claim approved actions and persist completed outcome."""
    conn = _FakeConn()
    updates: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    impacts: list[dict[str, Any]] = []

    monkeypatch.setattr(remediation_worker, "db_conn", lambda: _ConnCtx(conn))
    monkeypatch.setattr(
        remediation_worker,
        "_claim_actions",
        lambda *_args, **_kwargs: [
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-1",
                "fingerprint": "fp-1",
                "check_id": "aws.ec2.instances.underutilized",
                "action_type": "stop",
                "action_payload": {"instance_id": "i-123", "region": "us-east-2"},
                "dry_run": True,
            }
        ],
    )
    monkeypatch.setattr(
        remediation_worker,
        "_update_action_result",
        lambda _conn, **kwargs: updates.append(kwargs),
    )
    monkeypatch.setattr(
        remediation_worker,
        "_audit_action_outcome",
        lambda _conn, **kwargs: audits.append(kwargs),
    )
    monkeypatch.setattr(
        remediation_worker,
        "upsert_action_impact",
        lambda _conn, **kwargs: impacts.append(kwargs) or True,
    )

    services_factory = _FakeServicesFactory()
    executor = _FakeExecutor(ok=True)
    stats = remediation_worker.process_approved_actions(
        options=remediation_worker.RemediationWorkerOptions(
            tenant_id="acme",
            workspace="prod",
            limit=10,
        ),
        executor=executor,  # type: ignore[arg-type]
        services_factory=services_factory,  # type: ignore[arg-type]
    )

    assert stats.claimed == 1
    assert stats.completed == 1
    assert stats.failed == 0
    assert services_factory.regions == ["us-east-2"]
    assert updates and updates[0]["outcome"]["status"] == "completed"
    assert audits and audits[0]["outcome"]["event_type"] == "remediation.completed"
    assert impacts and impacts[0]["action_id"] == "act-1"


def test_process_approved_actions_marks_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Worker should persist failed status when executor outcome is not ok."""
    conn = _FakeConn()
    updates: list[dict[str, Any]] = []

    monkeypatch.setattr(remediation_worker, "db_conn", lambda: _ConnCtx(conn))
    monkeypatch.setattr(
        remediation_worker,
        "_claim_actions",
        lambda *_args, **_kwargs: [
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "action_id": "act-2",
                "fingerprint": "fp-2",
                "check_id": "aws.ec2.instances.underutilized",
                "action_type": "stop",
                "action_payload": {"instance_id": "i-999"},
                "dry_run": False,
            }
        ],
    )
    monkeypatch.setattr(
        remediation_worker,
        "_update_action_result",
        lambda _conn, **kwargs: updates.append(kwargs),
    )
    monkeypatch.setattr(remediation_worker, "_audit_action_outcome", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        remediation_worker,
        "upsert_action_impact",
        lambda _conn, **_kwargs: True,
    )

    stats = remediation_worker.process_approved_actions(
        options=remediation_worker.RemediationWorkerOptions(
            tenant_id="acme",
            workspace="prod",
            limit=5,
        ),
        executor=_FakeExecutor(ok=False),  # type: ignore[arg-type]
        services_factory=_FakeServicesFactory(),  # type: ignore[arg-type]
    )

    assert stats.claimed == 1
    assert stats.completed == 0
    assert stats.failed == 1
    assert updates and updates[0]["outcome"]["status"] == "failed"
