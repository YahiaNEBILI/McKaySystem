"""Precondition primitives for remediation actions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from services.remediation.base import ActionContext


@dataclass(frozen=True)
class PreconditionResult:
    """Deterministic precondition evaluation result."""

    ok: bool
    code: str = ""
    message: str = ""


class ActionPrecondition(ABC):
    """Contract for reusable remediation action preconditions."""

    code: str = "precondition_failed"

    def describe(self) -> str:
        """Return deterministic precondition description."""
        return self.__class__.__name__

    @abstractmethod
    def evaluate(self, ctx: ActionContext, payload: Mapping[str, Any]) -> PreconditionResult:
        """Evaluate one precondition for an action payload."""
        raise NotImplementedError


@dataclass(frozen=True)
class RequiredPayloadKeysPrecondition(ActionPrecondition):
    """Ensure required payload keys are present and non-empty."""

    required_keys: tuple[str, ...]
    code: str = "missing_payload_keys"

    def evaluate(self, ctx: ActionContext, payload: Mapping[str, Any]) -> PreconditionResult:
        """Validate payload contains all required keys."""
        _ = ctx
        missing: list[str] = []
        for key in self.required_keys:
            value = payload.get(key)
            if value is None:
                missing.append(key)
                continue
            if isinstance(value, str) and not value.strip():
                missing.append(key)
        if missing:
            return PreconditionResult(
                ok=False,
                code=self.code,
                message=f"missing required payload keys: {', '.join(sorted(missing))}",
            )
        return PreconditionResult(ok=True)


@dataclass(frozen=True)
class AllowedCheckIdsPrecondition(ActionPrecondition):
    """Ensure the finding check_id is allowed for an action."""

    allowed_check_ids: tuple[str, ...]
    code: str = "check_id_not_allowed"

    def evaluate(self, ctx: ActionContext, payload: Mapping[str, Any]) -> PreconditionResult:
        """Validate action runs only for explicitly supported check IDs."""
        _ = payload
        check_id = str(ctx.check_id or "").strip()
        if check_id in self.allowed_check_ids:
            return PreconditionResult(ok=True)
        allowed = ", ".join(sorted(self.allowed_check_ids))
        return PreconditionResult(
            ok=False,
            code=self.code,
            message=f"check_id '{check_id}' is not allowed; expected one of: {allowed}",
        )


def evaluate_preconditions(
    *,
    preconditions: Sequence[ActionPrecondition],
    ctx: ActionContext,
    payload: Mapping[str, Any],
) -> PreconditionResult:
    """Evaluate preconditions deterministically and return first failure."""
    for precondition in preconditions:
        result = precondition.evaluate(ctx, payload)
        if not result.ok:
            return result
    return PreconditionResult(ok=True)
