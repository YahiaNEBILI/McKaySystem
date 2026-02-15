"""EC2 stop remediation action."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from services.remediation.actions._common import require_ec2_client
from services.remediation.base import ActionContext, ActionResult, RemediationAction
from services.remediation.preconditions import (
    AllowedCheckIdsPrecondition,
    RequiredPayloadKeysPrecondition,
)
from services.remediation.registry import register_action

_EC2_STOP_CHECK_IDS = ("aws.ec2.instances.underutilized",)


def _instance_id(payload: Mapping[str, Any]) -> str:
    """Extract normalized EC2 instance id from payload."""
    return str(payload.get("instance_id") or "").strip()


@register_action("stop")
class Ec2StopAction(RemediationAction):
    """Stop one EC2 instance when preconditions pass."""

    action_type = "stop"
    check_ids = _EC2_STOP_CHECK_IDS
    preconditions = (
        AllowedCheckIdsPrecondition(allowed_check_ids=_EC2_STOP_CHECK_IDS),
        RequiredPayloadKeysPrecondition(required_keys=("instance_id",)),
    )

    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        """Validate that payload contains a plausible EC2 instance id."""
        instance_id = _instance_id(payload)
        if not instance_id:
            raise ValueError("instance_id is required")
        if not instance_id.startswith("i-"):
            raise ValueError("instance_id must start with 'i-'")

    def dry_run(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Return deterministic dry-run confirmation."""
        instance_id = _instance_id(payload)
        return ActionResult(
            ok=True,
            message=f"dry-run: stop EC2 instance {instance_id}",
            details={
                "action_id": ctx.action_id,
                "instance_id": instance_id,
                "operation": "stop_instances",
            },
        )

    def execute(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Call EC2 stop_instances with idempotent handling for already-stopped/missing."""
        instance_id = _instance_id(payload)
        ec2, err = require_ec2_client(ctx)
        if err is not None:
            return err
        assert ec2 is not None
        try:
            ec2.stop_instances(InstanceIds=[instance_id])
            return ActionResult(
                ok=True,
                message=f"stopped EC2 instance {instance_id}",
                details={"instance_id": instance_id, "operation": "stop_instances"},
            )
        except ClientError as exc:
            error = exc.response.get("Error") or {}
            code = str(error.get("Code") or "")
            if code in {"IncorrectInstanceState", "InvalidInstanceID.NotFound"}:
                return ActionResult(
                    ok=True,
                    message=f"instance {instance_id} already stopped or missing",
                    details={"instance_id": instance_id, "error_code": code, "idempotent": "true"},
                )
            return ActionResult(
                ok=False,
                message=f"failed to stop instance {instance_id}: {code or 'unknown_error'}",
                details={"instance_id": instance_id, "error_code": code},
            )
        except (AttributeError, TypeError, ValueError) as exc:
            return ActionResult(
                ok=False,
                message=f"failed to stop instance {instance_id}: {exc}",
                details={"instance_id": instance_id},
            )
