"""Shared lightweight factories for tests.

These helpers reduce repeated FindingDraft/Scope boilerplate without introducing
runtime dependencies on external factory libraries.
"""

from __future__ import annotations

from typing import Any

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity


def make_scope(**overrides: Any) -> Scope:
    """Build a Scope with deterministic defaults and optional overrides."""
    data: dict[str, Any] = {
        "cloud": "aws",
        "account_id": "111111111111",
        "region": "eu-west-1",
        "service": "AmazonEC2",
        "resource_type": "ec2_instance",
        "resource_id": "i-default",
    }
    data.update(overrides)
    return Scope(**data)


def make_severity(*, level: str = "medium", score: int = 60) -> Severity:
    """Build a Severity value object."""
    return Severity(level=level, score=score)


def make_finding_draft(**overrides: Any) -> FindingDraft:
    """Build a FindingDraft with deterministic defaults and optional overrides."""
    data: dict[str, Any] = {
        "check_id": "aws.ec2.instances.unused",
        "check_name": "EC2 unused instances",
        "category": "optimization",
        "status": "fail",
        "severity": make_severity(),
        "title": "Unused EC2 instance",
        "scope": make_scope(),
        "message": "Instance has near-zero utilization.",
        "issue_key": {"type": "unused"},
    }
    data.update(overrides)
    return FindingDraft(**data)

