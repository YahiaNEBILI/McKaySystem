# checks/registry.py
"""
Lightweight checker registry / factory.

The runner imports checker modules by dotted path. That import can register
a factory for the checker class, allowing uniform instantiation without
runner special-casing.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from contracts.finops_checker_pattern import Checker, RunContext

Bootstrap = Dict[str, Any]
CheckerFactory = Callable[[RunContext, Bootstrap], Checker]

_REGISTRY: Dict[str, CheckerFactory] = {}


def register_checker(spec: str) -> Callable[[CheckerFactory], CheckerFactory]:
    """Register a factory for a checker.

    spec is the exact string passed to --checker, typically: "module.path:ClassName"
    """
    def _decorator(factory: CheckerFactory) -> CheckerFactory:
        if spec in _REGISTRY:
            raise KeyError(f"Checker factory already registered for '{spec}'")
        _REGISTRY[spec] = factory
        return factory

    return _decorator


def get_factory(spec: str) -> Optional[CheckerFactory]:
    return _REGISTRY.get(spec)
