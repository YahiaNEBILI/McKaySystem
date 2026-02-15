"""Shared helpers for remediation action implementations."""

from __future__ import annotations

from typing import Any

from services.remediation.base import ActionContext, ActionResult


def require_ec2_client(ctx: ActionContext) -> tuple[Any | None, ActionResult | None]:
    """Resolve EC2 client from action context or return deterministic error result."""
    ec2 = ctx.services.get("ec2")
    if ec2 is None:
        return None, ActionResult(
            ok=False,
            message="ec2 client is required in ActionContext.services['ec2']",
        )
    return ec2, None
