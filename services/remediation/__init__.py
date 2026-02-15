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
from services.remediation.registry import ActionRegistry, list_action_types, register_action

__all__ = [
    "ActionContext",
    "ActionResult",
    "RemediationAction",
    "RetryPolicy",
    "ActionRegistry",
    "register_action",
    "list_action_types",
]
