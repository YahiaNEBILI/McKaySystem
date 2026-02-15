"""EBS snapshot delete remediation action."""

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

_SNAPSHOT_DELETE_CHECK_IDS = ("aws.ec2.ebs.old.snapshot",)


def _snapshot_id(payload: Mapping[str, Any]) -> str:
    """Extract normalized EBS snapshot id from payload."""
    return str(payload.get("snapshot_id") or "").strip()


@register_action("delete_snapshot")
class SnapshotDeleteAction(RemediationAction):
    """Delete one EBS snapshot when preconditions pass."""

    action_type = "delete_snapshot"
    check_ids = _SNAPSHOT_DELETE_CHECK_IDS
    preconditions = (
        AllowedCheckIdsPrecondition(allowed_check_ids=_SNAPSHOT_DELETE_CHECK_IDS),
        RequiredPayloadKeysPrecondition(required_keys=("snapshot_id",)),
    )

    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        """Validate that payload contains a plausible snapshot id."""
        snapshot_id = _snapshot_id(payload)
        if not snapshot_id:
            raise ValueError("snapshot_id is required")
        if not snapshot_id.startswith("snap-"):
            raise ValueError("snapshot_id must start with 'snap-'")

    def dry_run(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Return deterministic dry-run confirmation."""
        snapshot_id = _snapshot_id(payload)
        return ActionResult(
            ok=True,
            message=f"dry-run: delete EBS snapshot {snapshot_id}",
            details={
                "action_id": ctx.action_id,
                "snapshot_id": snapshot_id,
                "operation": "delete_snapshot",
            },
        )

    def execute(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Call EC2 delete_snapshot with idempotent handling for missing snapshots."""
        snapshot_id = _snapshot_id(payload)
        ec2_client, error_result = require_ec2_client(ctx)
        if error_result is not None:
            return error_result
        if ec2_client is None:
            return ActionResult(ok=False, message="ec2 client resolution failed")
        try:
            ec2_client.delete_snapshot(SnapshotId=snapshot_id)
            return ActionResult(
                ok=True,
                message=f"deleted EBS snapshot {snapshot_id}",
                details={"snapshot_id": snapshot_id, "operation": "delete_snapshot"},
            )
        except ClientError as exc:
            error = exc.response.get("Error") or {}
            code = str(error.get("Code") or "")
            if code == "InvalidSnapshot.NotFound":
                return ActionResult(
                    ok=True,
                    message=f"snapshot {snapshot_id} already missing",
                    details={"snapshot_id": snapshot_id, "error_code": code, "idempotent": "true"},
                )
            return ActionResult(
                ok=False,
                message=f"failed to delete snapshot {snapshot_id}: {code or 'unknown_error'}",
                details={"snapshot_id": snapshot_id, "error_code": code},
            )
        except (AttributeError, TypeError, ValueError) as exc:
            return ActionResult(
                ok=False,
                message=f"failed to delete snapshot {snapshot_id}: {exc}",
                details={"snapshot_id": snapshot_id},
            )
