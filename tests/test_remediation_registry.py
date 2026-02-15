"""Tests for remediation action registry and discovery."""

from __future__ import annotations

import pytest

from services.remediation.base import ActionContext
from services.remediation.registry import ActionRegistry


def test_registry_discovery_lists_builtin_actions() -> None:
    """Action registry discovery should register built-in actions deterministically."""
    registry = ActionRegistry()
    registry.discover()

    action_types = registry.list_types()
    assert "noop" in action_types
    assert action_types == sorted(action_types)


def test_registry_create_instantiates_action() -> None:
    """Registry should instantiate registered action implementations."""
    registry = ActionRegistry()
    registry.discover()

    action = registry.create("noop")
    result = action.dry_run(
        ActionContext(
            tenant_id="acme",
            workspace="prod",
            action_id="act-1",
            fingerprint="fp-1",
            check_id="aws.ec2.instances.underutilized",
        ),
        payload={},
    )
    assert result.ok is True
    assert "act-1" in result.message


def test_registry_create_unknown_raises() -> None:
    """Unknown action types should fail fast."""
    registry = ActionRegistry()
    registry.discover()
    with pytest.raises(KeyError):
        registry.create("does-not-exist")
