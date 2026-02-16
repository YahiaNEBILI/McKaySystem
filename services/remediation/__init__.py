"""Remediation framework primitives.

This package contains:
- action contracts (`base.py`)
- registry/discovery (`registry.py`)
- built-in actions (`actions/`)
"""

from services.remediation.base import (
    ActionContext,
    ActionResult,
    RemediationAction,
    RetryPolicy,
)
from services.remediation.executor import ExecutionOutcome, ExecutionRequest, RemediationExecutor
from services.remediation.preconditions import (
    ActionPrecondition,
    AllowedCheckIdsPrecondition,
    PreconditionResult,
    RequiredPayloadKeysPrecondition,
)
from services.remediation.registry import ActionRegistry, list_action_types, register_action

__all__ = [
    "ActionContext",
    "ActionResult",
    "RemediationAction",
    "RetryPolicy",
    "PreconditionResult",
    "ActionPrecondition",
    "RequiredPayloadKeysPrecondition",
    "AllowedCheckIdsPrecondition",
    "ActionRegistry",
    "register_action",
    "list_action_types",
    "ExecutionRequest",
    "ExecutionOutcome",
    "RemediationExecutor",
]
