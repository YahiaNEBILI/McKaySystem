"""Remediation executor orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from services.remediation.audit import (
    NoopRemediationAuditSink,
    RemediationAuditEvent,
    RemediationAuditSink,
)
from services.remediation.base import ActionContext, ActionResult
from services.remediation.preconditions import evaluate_preconditions
from services.remediation.registry import ActionRegistry


@dataclass(frozen=True)
class ExecutionRequest:
    """Input payload for one remediation execution request."""

    ctx: ActionContext
    action_type: str
    payload: Mapping[str, Any]
    dry_run: bool = True


@dataclass(frozen=True)
class ExecutionOutcome:
    """Normalized output for one remediation execution request."""

    ctx: ActionContext
    action_type: str
    dry_run: bool
    result: ActionResult


class RemediationExecutor:
    """Execute remediation actions with validation, preconditions, and auditing."""

    def __init__(
        self,
        *,
        registry: ActionRegistry | None = None,
        audit_sink: RemediationAuditSink | None = None,
        auto_discover: bool = True,
    ) -> None:
        if registry is None:
            registry = ActionRegistry()
        if auto_discover:
            registry.discover()
        self._registry = registry
        self._audit_sink = audit_sink or NoopRemediationAuditSink()

    def run(self, request: ExecutionRequest) -> ExecutionOutcome:
        """Execute one remediation request and emit an audit event."""
        action_type = str(request.action_type or "").strip().lower()
        payload = dict(request.payload)
        result: ActionResult

        try:
            action = self._registry.create(action_type)
        except KeyError:
            result = ActionResult(ok=False, message=f"unknown action_type: {action_type!r}")
            return self._finalize(request=request, action_type=action_type, result=result)

        try:
            action.validate_payload(payload)
        except ValueError as exc:
            result = ActionResult(ok=False, message=str(exc))
            return self._finalize(request=request, action_type=action_type, result=result)

        precondition_result = evaluate_preconditions(
            preconditions=action.preconditions,
            ctx=request.ctx,
            payload=payload,
        )
        if not precondition_result.ok:
            result = ActionResult(
                ok=False,
                message=precondition_result.message or precondition_result.code,
                details={"code": precondition_result.code},
            )
            return self._finalize(request=request, action_type=action_type, result=result)

        try:
            if request.dry_run:
                result = action.dry_run(request.ctx, payload)
            else:
                result = action.execute(request.ctx, payload)
        except (ValueError, TypeError, KeyError, RuntimeError, AttributeError) as exc:
            result = ActionResult(ok=False, message=str(exc))
        return self._finalize(request=request, action_type=action_type, result=result)

    async def run_many(
        self,
        requests: Sequence[ExecutionRequest],
        *,
        max_concurrency: int = 4,
    ) -> list[ExecutionOutcome]:
        """Execute many remediation requests concurrently with stable ordering."""
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _run_one(request: ExecutionRequest) -> ExecutionOutcome:
            async with semaphore:
                return await asyncio.to_thread(self.run, request)

        tasks = [_run_one(request) for request in requests]
        return list(await asyncio.gather(*tasks))

    def _finalize(
        self,
        *,
        request: ExecutionRequest,
        action_type: str,
        result: ActionResult,
    ) -> ExecutionOutcome:
        """Create outcome and emit one deterministic audit event."""
        outcome = ExecutionOutcome(
            ctx=request.ctx,
            action_type=action_type,
            dry_run=request.dry_run,
            result=result,
        )
        self._audit_sink.record_event(
            RemediationAuditEvent(
                tenant_id=request.ctx.tenant_id,
                workspace=request.ctx.workspace,
                action_id=request.ctx.action_id,
                action_type=action_type,
                dry_run=request.dry_run,
                ok=result.ok,
                message=result.message,
                details=dict(result.details),
            )
        )
        return outcome
