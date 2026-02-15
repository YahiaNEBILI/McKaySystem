"""Registry and discovery for remediation action implementations."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable

from services.remediation.base import RemediationAction

ActionType = type[RemediationAction]

_ACTION_REGISTRY: dict[str, ActionType] = {}


def register_action(action_type: str) -> Callable[[ActionType], ActionType]:
    """Register a remediation action class under an action_type key."""

    normalized = str(action_type or "").strip().lower()
    if not normalized:
        raise ValueError("action_type must be non-empty")

    def _decorator(klass: ActionType) -> ActionType:
        if normalized in _ACTION_REGISTRY:
            raise KeyError(f"Action already registered for '{normalized}'")
        _ACTION_REGISTRY[normalized] = klass
        return klass

    return _decorator


def list_action_types() -> list[str]:
    """Return registered action types in deterministic order."""
    return sorted(_ACTION_REGISTRY.keys())


class ActionRegistry:
    """Action registry facade with discovery and instantiation helpers."""

    def discover(self, package_name: str = "services.remediation.actions") -> None:
        """Import all modules under the actions package."""
        package = importlib.import_module(package_name)
        package_path = getattr(package, "__path__", None)
        if package_path is None:
            return
        prefix = package.__name__ + "."
        for module_info in pkgutil.walk_packages(package_path, prefix):
            importlib.import_module(module_info.name)

    def list_types(self) -> list[str]:
        """Return registered action types."""
        return list_action_types()

    def get_class(self, action_type: str) -> ActionType | None:
        """Return registered action class for an action_type."""
        key = str(action_type or "").strip().lower()
        if not key:
            return None
        return _ACTION_REGISTRY.get(key)

    def create(self, action_type: str) -> RemediationAction:
        """Instantiate a registered action implementation."""
        klass = self.get_class(action_type)
        if klass is None:
            raise KeyError(f"Unknown action_type: {action_type!r}")
        return klass()
