# checks/registry.py
"""
Lightweight checker registry / factory.

The runner imports checker modules by dotted path. That import can register
a factory for the checker class, allowing uniform instantiation without
runner special-casing.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, List

from contracts.finops_checker_pattern import Checker, RunContext

Bootstrap = Dict[str, Any]
CheckerFactory = Callable[[RunContext, Bootstrap], Checker]

_REGISTRY: Dict[str, CheckerFactory] = {}


def register_checker(spec: str) -> Callable[[CheckerFactory], CheckerFactory]:
    """Register a factory for a checker.

    spec should match what runner uses, e.g. "checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker"
    """
    def _decorator(factory: CheckerFactory) -> CheckerFactory:
        if spec in _REGISTRY:
            raise KeyError(f"Checker factory already registered for '{spec}'")
        _REGISTRY[spec] = factory
        return factory
    return _decorator


def register_class(spec: str, klass: type) -> None:
    """Register a no-arg checker class as a factory."""
    def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
        return klass()  # type: ignore[call-arg]
    if spec in _REGISTRY:
        raise KeyError(f"Checker factory already registered for '{spec}'")
    _REGISTRY[spec] = _factory


def get_factory(spec: str) -> Optional[CheckerFactory]:
    return _REGISTRY.get(spec)


def list_specs() -> List[str]:
    """All registered checker specs in deterministic order."""
    return sorted(_REGISTRY.keys())
