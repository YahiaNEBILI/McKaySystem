"""No-op remediation action used for dry-run framework validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from services.remediation.base import ActionContext, ActionResult, RemediationAction
from services.remediation.registry import register_action


@register_action("noop")
class NoopRemediationAction(RemediationAction):
    """Action that validates framework wiring without external side effects."""

    action_type = "noop"
    check_ids = ()

    def dry_run(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Always succeed for deterministic framework smoke checks."""
        _ = payload
        return ActionResult(ok=True, message=f"noop dry-run for {ctx.action_id}")

    def execute(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Always succeed; does not call external systems."""
        _ = payload
        return ActionResult(ok=True, message=f"noop execute for {ctx.action_id}")
