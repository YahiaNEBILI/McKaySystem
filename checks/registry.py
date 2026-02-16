"""Checker registry used by the worker runner.

Checker modules can register a factory for each checker spec so the runner
can instantiate checkers without per-module branching logic.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from contracts.finops_checker_pattern import Checker, RunContext

Bootstrap = dict[str, Any]
CheckerFactory = Callable[[RunContext, Bootstrap], Checker]

_REGISTRY: dict[str, CheckerFactory] = {}


def register_checker(spec: str) -> Callable[[CheckerFactory], CheckerFactory]:
    """Register a checker factory for a spec string."""

    def _decorator(factory: CheckerFactory) -> CheckerFactory:
        if spec in _REGISTRY:
            raise KeyError(f"Checker factory already registered for '{spec}'")
        _REGISTRY[spec] = factory
        return factory

    return _decorator


def register_class(spec: str, klass: Callable[[], Checker]) -> None:
    """Register a no-arg checker class."""

    def _factory(_ctx: RunContext, _bootstrap: Bootstrap) -> Checker:
        return klass()

    if spec in _REGISTRY:
        raise KeyError(f"Checker factory already registered for '{spec}'")
    _REGISTRY[spec] = _factory


def get_factory(spec: str) -> CheckerFactory | None:
    """Return the registered factory for a checker spec."""
    return _REGISTRY.get(spec)


def list_specs() -> list[str]:
    """Return all registered checker specs in deterministic order."""
    return sorted(_REGISTRY.keys())
