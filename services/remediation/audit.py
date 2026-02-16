"""Audit sink primitives for remediation execution events."""

from __future__ import annotations

from typing import NamedTuple, Protocol


class RemediationAuditEvent(NamedTuple):
    """Immutable remediation execution audit event."""

    tenant_id: str
    workspace: str
    action_id: str
    action_type: str
    dry_run: bool
    ok: bool
    message: str
    details: dict[str, str]


class RemediationAuditSink(Protocol):
    """Protocol for remediation audit event sinks."""

    def sink_name(self) -> str:
        """Return deterministic sink name for diagnostics."""

    def record_event(self, event: RemediationAuditEvent) -> None:
        """Record one remediation execution event."""


class NoopRemediationAuditSink:
    """No-op sink used when no audit destination is configured."""

    def sink_name(self) -> str:
        """Return deterministic sink identifier."""
        return "noop"

    def record_event(self, event: RemediationAuditEvent) -> None:
        """Discard audit event."""
        _ = event


class InMemoryRemediationAuditSink:
    """In-memory audit sink for deterministic unit tests."""

    def __init__(self) -> None:
        self._events: list[RemediationAuditEvent] = []

    def record_event(self, event: RemediationAuditEvent) -> None:
        """Store audit event in insertion order."""
        self._events.append(event)

    def sink_name(self) -> str:
        """Return deterministic sink identifier."""
        return "in_memory"

    def events(self) -> list[RemediationAuditEvent]:
        """Return a copy of recorded events."""
        return list(self._events)
