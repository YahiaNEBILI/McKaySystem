"""Base contracts for remediation actions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from services.remediation.preconditions import ActionPrecondition


@dataclass(frozen=True)
class RetryPolicy:
    """Retry policy for action execution."""

    max_attempts: int = 1
    backoff_seconds: int = 0


@dataclass(frozen=True)
class ActionContext:
    """Immutable runtime context for one remediation action."""

    tenant_id: str
    workspace: str
    action_id: str
    fingerprint: str
    check_id: str
    run_id: str = ""
    services: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionResult:
    """Normalized remediation action result."""

    ok: bool
    message: str = ""
    details: dict[str, str] = field(default_factory=dict)


class RemediationAction(ABC):
    """Abstract remediation action contract."""

    action_type: str = ""
    check_ids: tuple[str, ...] = ()
    retry_policy: RetryPolicy = RetryPolicy()
    preconditions: tuple[ActionPrecondition, ...] = ()

    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        """Validate action payload before dry-run/execute."""
        _ = payload

    @abstractmethod
    def dry_run(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Validate intended action without mutating infrastructure."""
        raise NotImplementedError

    @abstractmethod
    def execute(self, ctx: ActionContext, payload: Mapping[str, Any]) -> ActionResult:
        """Execute action against target infrastructure."""
        raise NotImplementedError
