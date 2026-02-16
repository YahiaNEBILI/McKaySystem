"""Tests for remediation executor, preconditions, and Phase 2 actions."""

from __future__ import annotations

import asyncio
from typing import Any

from botocore.exceptions import ClientError

from services.remediation.audit import InMemoryRemediationAuditSink
from services.remediation.base import ActionContext
from services.remediation.executor import ExecutionRequest, RemediationExecutor
from services.remediation.registry import ActionRegistry


class _FakeEc2Client:
    """Minimal EC2 fake for stop/delete action tests."""

    def __init__(self) -> None:
        self.stop_calls: list[list[str]] = []
        self.delete_calls: list[str] = []
        self.stop_error_code: str | None = None
        self.delete_error_code: str | None = None

    def stop_instances(self, *, InstanceIds: list[str]) -> dict[str, Any]:
        """Record stop call or raise deterministic ClientError."""
        if self.stop_error_code:
            raise ClientError(
                {"Error": {"Code": self.stop_error_code, "Message": "stop failed"}},
                "StopInstances",
            )
        self.stop_calls.append(list(InstanceIds))
        return {"StoppingInstances": [{"InstanceId": iid} for iid in InstanceIds]}

    def delete_snapshot(self, *, SnapshotId: str) -> dict[str, Any]:
        """Record delete call or raise deterministic ClientError."""
        if self.delete_error_code:
            raise ClientError(
                {"Error": {"Code": self.delete_error_code, "Message": "delete failed"}},
                "DeleteSnapshot",
            )
        self.delete_calls.append(SnapshotId)
        return {}


def _registry() -> ActionRegistry:
    """Build discovered action registry."""
    registry = ActionRegistry()
    registry.discover()
    return registry


def _ctx(
    *,
    action_id: str,
    check_id: str,
    services: dict[str, Any] | None = None,
) -> ActionContext:
    """Build deterministic ActionContext for unit tests."""
    return ActionContext(
        tenant_id="acme",
        workspace="prod",
        action_id=action_id,
        fingerprint="fp-1",
        check_id=check_id,
        services=services or {},
    )


def test_executor_stop_action_dry_run_success() -> None:
    """Dry-run should validate payload and return deterministic stop preview."""
    sink = InMemoryRemediationAuditSink()
    executor = RemediationExecutor(registry=_registry(), audit_sink=sink)
    outcome = executor.run(
        ExecutionRequest(
            ctx=_ctx(action_id="act-stop-1", check_id="aws.ec2.instances.underutilized"),
            action_type="stop",
            payload={"instance_id": "i-1234567890abcdef0"},
            dry_run=True,
        )
    )

    assert outcome.result.ok is True
    assert outcome.result.details.get("operation") == "stop_instances"
    events = sink.events()
    assert len(events) == 1
    assert events[0].action_id == "act-stop-1"
    assert events[0].dry_run is True


def test_executor_stop_action_execute_calls_ec2() -> None:
    """Execute should call EC2 stop_instances when client is provided."""
    ec2 = _FakeEc2Client()
    executor = RemediationExecutor(registry=_registry())
    outcome = executor.run(
        ExecutionRequest(
            ctx=_ctx(
                action_id="act-stop-2",
                check_id="aws.ec2.instances.underutilized",
                services={"ec2": ec2},
            ),
            action_type="stop",
            payload={"instance_id": "i-aaaaaaaaaaaaaaaaa"},
            dry_run=False,
        )
    )

    assert outcome.result.ok is True
    assert ec2.stop_calls == [["i-aaaaaaaaaaaaaaaaa"]]


def test_executor_stop_action_precondition_blocks_wrong_check() -> None:
    """Stop action should fail fast when check_id is not allowed."""
    executor = RemediationExecutor(registry=_registry())
    outcome = executor.run(
        ExecutionRequest(
            ctx=_ctx(action_id="act-stop-3", check_id="aws.ec2.nat.gateways.idle"),
            action_type="stop",
            payload={"instance_id": "i-aaaaaaaaaaaaaaaaa"},
            dry_run=True,
        )
    )

    assert outcome.result.ok is False
    assert outcome.result.details.get("code") == "check_id_not_allowed"


def test_executor_stop_action_not_found_is_idempotent_success() -> None:
    """InvalidInstanceID.NotFound should be treated as idempotent success."""
    ec2 = _FakeEc2Client()
    ec2.stop_error_code = "InvalidInstanceID.NotFound"
    executor = RemediationExecutor(registry=_registry())
    outcome = executor.run(
        ExecutionRequest(
            ctx=_ctx(
                action_id="act-stop-4",
                check_id="aws.ec2.instances.underutilized",
                services={"ec2": ec2},
            ),
            action_type="stop",
            payload={"instance_id": "i-bbbbbbbbbbbbbbbbb"},
            dry_run=False,
        )
    )

    assert outcome.result.ok is True
    assert outcome.result.details.get("idempotent") == "true"


def test_executor_delete_snapshot_execute_calls_ec2() -> None:
    """Execute should call EC2 delete_snapshot for old EBS snapshot findings."""
    ec2 = _FakeEc2Client()
    executor = RemediationExecutor(registry=_registry())
    outcome = executor.run(
        ExecutionRequest(
            ctx=_ctx(
                action_id="act-snap-1",
                check_id="aws.ec2.ebs.old.snapshot",
                services={"ec2": ec2},
            ),
            action_type="delete_snapshot",
            payload={"snapshot_id": "snap-0123456789abcdef0"},
            dry_run=False,
        )
    )

    assert outcome.result.ok is True
    assert ec2.delete_calls == ["snap-0123456789abcdef0"]


def test_executor_run_many_async_preserves_order() -> None:
    """Async executor should return outcomes in request order."""
    executor = RemediationExecutor(registry=_registry())
    requests = [
        ExecutionRequest(
            ctx=_ctx(action_id="act-async-1", check_id="aws.ec2.instances.underutilized"),
            action_type="stop",
            payload={"instance_id": "i-11111111111111111"},
            dry_run=True,
        ),
        ExecutionRequest(
            ctx=_ctx(action_id="act-async-2", check_id="aws.ec2.ebs.old.snapshot"),
            action_type="delete_snapshot",
            payload={"snapshot_id": "snap-11111111111111111"},
            dry_run=True,
        ),
    ]

    outcomes = asyncio.run(executor.run_many(requests, max_concurrency=2))
    assert [o.ctx.action_id for o in outcomes] == ["act-async-1", "act-async-2"]
    assert all(o.result.ok for o in outcomes)
