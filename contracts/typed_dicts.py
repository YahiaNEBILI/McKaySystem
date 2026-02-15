"""
TypedDict definitions for wire formats and API contracts.

This module provides explicit type definitions for data moving between
components, ensuring type safety and making the codebase more approachable
for AI agents.

Usage:
    from contracts.typed_dicts import FindingWireFormat, ScopeWireFormat
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class ScopeWireFormat(TypedDict):
    """
    Wire format for scope information.

    Represents the cloud resource scope that a finding targets.
    All fields are optional to allow partial scope definitions.
    """
    cloud: str  # "aws" | "azure" | "gcp" | ...
    provider_partition: NotRequired[str]  # aws partition "aws"/"aws-cn"/"aws-us-gov"
    organization_id: NotRequired[str]  # org/management group/billing account id
    billing_account_id: NotRequired[str]  # payer / billing root
    account_id: str  # linked account / subscription / project
    region: NotRequired[str]
    availability_zone: NotRequired[str]
    service: NotRequired[str]  # e.g. "AmazonEC2", "S3"
    resource_type: NotRequired[str]  # e.g. "ec2_instance", "s3_bucket"
    resource_id: NotRequired[str]  # e.g. "i-...", bucket name, resource ARN
    resource_arn: NotRequired[str]  # optional (aws)


class SeverityWireFormat(TypedDict):
    """
    Wire format for severity information.
    """
    level: str  # "info"|"low"|"medium"|"high"|"critical"
    score: int  # 0..1000


class LifecycleWireFormat(TypedDict):
    """
    Wire format for lifecycle status tracking.
    """
    status: str  # "open"|"acknowledged"|"snoozed"|"resolved"|"ignored"
    first_seen_ts: NotRequired[str]  # ISO8601
    last_seen_ts: NotRequired[str]  # ISO8601
    resolved_ts: NotRequired[str]  # ISO8601
    snooze_until_ts: NotRequired[str]  # ISO8601


class CostModelWireFormat(TypedDict):
    """
    Wire format for cost model metadata.
    """
    currency: NotRequired[str]  # "USD", "EUR"
    cost_model: NotRequired[str]  # "unblended" | "amortized" | "net" | "blended"
    granularity: NotRequired[str]  # "daily" | "hourly" | "monthly" | "period"
    period_start: NotRequired[str]  # ISO date
    period_end: NotRequired[str]  # ISO date


class AttributionWireFormat(TypedDict):
    """
    Wire format for cost attribution summary.
    """
    method: NotRequired[str]  # "exact_resource_id" | "tag" | "heuristic" | ...
    confidence: NotRequired[int]  # 0..100
    matched_keys: NotRequired[list[str]]  # which keys matched


class SourceWireFormat(TypedDict):
    """
    Wire format for source information.
    """
    source_type: str  # "scanner" | "api" | "import"
    source_ref: str  # checker ID or import source
    schema_version: int


class FindingWireFormat(TypedDict):
    """
    Complete wire format for a FinOps finding.

    This is the canonical format used for:
    - Storage (Parquet)
    - Database persistence
    - API responses

    All fields are required unless marked as NotRequired.
    """
    # Identity (required)
    tenant_id: str
    workspace_id: str
    finding_id: str
    fingerprint: str

    # Run context (required)
    run_id: str
    run_ts: str  # ISO8601

    # Check metadata (required)
    check_id: str
    check_name: str
    category: str
    sub_category: NotRequired[str]

    # Status & Severity (required)
    status: str  # "pass"|"fail"|"info"|"unknown"
    severity: SeverityWireFormat

    # Title & Description (required)
    title: str
    message: NotRequired[str]

    # Scope (required)
    scope: ScopeWireFormat

    # Remediation (optional)
    recommendation: NotRequired[str]
    remediation: NotRequired[str]

    # Cost estimation (optional)
    estimated_monthly_savings: NotRequired[float]
    estimated_monthly_cost: NotRequired[float]
    estimate_confidence: NotRequired[int | str]
    estimate_notes: NotRequired[str]

    # Lifecycle tracking (optional)
    lifecycle: NotRequired[LifecycleWireFormat]

    # Attribution (optional)
    attribution: NotRequired[AttributionWireFormat]

    # Cost model (optional)
    cost_model: NotRequired[CostModelWireFormat]

    # Metadata (optional)
    tags: NotRequired[dict[str, str]]
    labels: NotRequired[dict[str, str]]
    dimensions: NotRequired[dict[str, str]]
    frameworks: NotRequired[list[str]]
    links: NotRequired[list[dict[str, str]]]

    # Source (required)
    source: SourceWireFormat


class FindingFilterParams(TypedDict, total=False):
    """
    Typed filter parameters for finding queries.

    Used in API endpoints to validate and document filter options.
    """
    tenant_id: str
    workspace: str
    status: NotRequired[str | list[str]]
    severity: NotRequired[str | list[str]]
    check_id: NotRequired[str | list[str]]
    category: NotRequired[str | list[str]]
    account_id: NotRequired[str | list[str]]
    region: NotRequired[str | list[str]]
    service: NotRequired[str | list[str]]
    has_savings: NotRequired[bool]
    search: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]
    sort_by: NotRequired[str]
    sort_order: NotRequired[Literal["asc", "desc"]]


class PaginationMeta(TypedDict):
    """
    Pagination metadata for list endpoints.
    """
    total: int
    limit: int
    offset: int
    has_more: bool


class FindingListResponse(TypedDict):
    """
    Standard response format for finding list endpoints.
    """
    data: list[FindingWireFormat]
    pagination: PaginationMeta


class LifecycleActionParams(TypedDict):
    """
    Parameters for lifecycle actions (resolve, snooze, acknowledge).
    """
    tenant_id: str
    workspace: str
    fingerprint: str
    action: str  # "resolve"|"snooze"|"acknowledge"|"ignore"
    reason: NotRequired[str]
    snooze_until: NotRequired[str]  # ISO8601


class RunStatus(TypedDict):
    """
    Status information for a run.
    """
    tenant_id: str
    workspace: str
    run_id: str
    status: str  # "running"|"completed"|"failed"|"partial"
    started_at: str
    completed_at: NotRequired[str]
    findings_count: NotRequired[int]
    errors: NotRequired[list[str]]
