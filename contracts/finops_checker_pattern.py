"""
finops_checker_pattern.py

A standard, low-boilerplate pattern for FinOps checkers.

Goals:
- Checkers focus on business logic, not boilerplate.
- Consistent schema output for finops_findings.
- Deterministic IDs + validation through finops_contracts.py (your module).
- Writer-agnostic: this module only produces dict records.

How to use:
- Implement checkers as callables that yield FindingDraft objects (or emit via emitter).
- Run them with CheckerRunner, which:
  - injects a RunContext
  - builds canonical findings
  - computes fingerprint/finding_id
  - validates required fields and enums
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from .finops_contracts import (
    ValidationError,
    build_ids_and_validate,
    normalize_str,
)
from .services import Services

# -----------------------------
# Core data structures
# -----------------------------


@dataclass(frozen=True)
class RunContext:
    """
    Immutable per-run context injected into all checkers.
    """
    tenant_id: str
    workspace_id: str
    run_id: str
    run_ts: datetime

    engine_name: str = "finops_engine"
    engine_version: str = "0.0.0"
    rulepack_version: str = "0.0.0"
    schema_version: int = 1

    default_currency: str = "USD"
    cloud: str = "aws"  # "aws"|"azure"|"gcp"
    services: Services | None = None

    def to_source_struct(self, *, source_ref: str, source_type: str = "scanner") -> dict[str, Any]:
        return {
            "source_type": source_type,
            "source_ref": source_ref,
            "schema_version": int(self.schema_version),
        }


@dataclass(frozen=True)
class Scope:
    """
    Strongly-typed scope builder to keep your checkers consistent.
    """
    cloud: str
    account_id: str
    region: str
    service: str
    resource_type: str = ""
    resource_id: str = ""
    billing_account_id: str = ""
    availability_zone: str = ""
    organization_id: str = ""
    provider_partition: str = ""
    resource_arn: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "provider_partition": self.provider_partition,
            "organization_id": self.organization_id,
            "billing_account_id": self.billing_account_id,
            "account_id": self.account_id,
            "region": self.region,
            "availability_zone": self.availability_zone,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
        }


@dataclass(frozen=True)
class Severity:
    level: str  # "info"|"low"|"medium"|"high"|"critical"
    score: int  # 0..1000 (or 0..100)


@dataclass(frozen=True)
class FindingDraft:
    """
    What a checker produces: a minimal structured draft.
    The runner will turn it into a final finops_findings record (dict) with IDs and validation.
    """
    check_id: str
    check_name: str
    category: str
    status: str  # pass|fail|info|unknown
    severity: Severity
    title: str

    scope: Scope

    message: str = ""
    recommendation: str = ""
    remediation: str = ""
    sub_category: str = ""
    frameworks: tuple[str, ...] = ()

    # Estimation fields: keep them optional
    # NOTE: money values must be numeric (float) or None. Formatting is a presentation concern.
    estimated_monthly_savings: float | None = None
    estimated_monthly_cost: float | None = None
    estimate_confidence: int | str | None = None  # allow "low"/"medium"/"high" too
    estimate_notes: str = ""

    # Extra dimensions
    tags: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    dimensions: dict[str, str] = field(default_factory=dict)

    # Issue discriminator for fingerprint stability
    issue_key: dict[str, Any] = field(default_factory=dict)

    # Links (optional)
    links: list[dict[str, str]] = field(default_factory=list)

    def with_issue(self, **kwargs: Any) -> FindingDraft:
        """
        Convenience: create a new draft with issue_key extended.
        """
        new_issue = dict(self.issue_key)
        for k, v in kwargs.items():
            new_issue[str(k)] = v
        return FindingDraft(**{**self.__dict__, "issue_key": new_issue})


# -----------------------------
# Checker protocol & runner
# -----------------------------


class Checker(Protocol):
    """
    A checker produces FindingDrafts.
    """
    checker_id: str  # for source_ref / logging

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        """
        Yield FindingDraft items.
        """
        raise NotImplementedError


@dataclass
class CheckerResult:
    valid_findings: list[dict[str, Any]] = field(default_factory=list)
    invalid_findings: int = 0
    invalid_errors: list[str] = field(default_factory=list)


class CheckerRunner:
    """Runs one or many checkers and outputs validated finops_findings records (dicts).

    This class orchestrates the execution of checkers, handling:
    - Running individual or multiple checkers
    - Validation mode (lenient vs strict)
    - Salt mode for finding_id stability (stable/per_run/per_day)
    - Error collection and reporting

    The runner follows this pipeline:
        1. For each checker, call checker.run(ctx) to get FindingDrafts
        2. Convert each draft to canonical record via build_finding_record()
        3. Validate and compute IDs via build_ids_and_validate()
        4. Collect valid findings and errors

    Attributes:
        _salt_mode: Controls finding_id stability across runs
        _validation_mode: Controls how validation failures are handled

    Example:
        >>> runner = CheckerRunner(finding_id_salt_mode="stable", validation_mode="lenient")
        >>> result = runner.run_one(my_checker, ctx)
        >>> len(result.valid_findings)
        42
        >>> result.invalid_findings
        3
    """
    def __init__(
        self,
        *,
        finding_id_salt_mode: str = "stable",
        validation_mode: str = "lenient",
    ) -> None:
        """
        finding_id_salt_mode:
          - "stable": finding_id is stable across time (salt=None)
          - "per_run": finding_id changes each run (salt=run_id)
          - "per_day": finding_id changes each day (salt=YYYY-MM-DD)
        """
        allowed = {"stable", "per_run", "per_day"}
        if finding_id_salt_mode not in allowed:
            raise ValueError(f"finding_id_salt_mode must be one of {sorted(allowed)}")
        self._salt_mode = finding_id_salt_mode
        allowed_modes = {"lenient", "strict"}
        if validation_mode not in allowed_modes:
            raise ValueError(f"validation_mode must be one of {sorted(allowed_modes)}")
        self._validation_mode = validation_mode

    def _compute_salt(self, ctx: RunContext) -> str | None:
        if self._salt_mode == "stable":
            return None
        if self._salt_mode == "per_run":
            return ctx.run_id
        # per_day
        return ctx.run_ts.astimezone(UTC).date().isoformat()

    def run_one(self, checker: Checker, ctx: RunContext) -> CheckerResult:
        """Run a single checker and return validated findings.

        Executes the checker, validates all produced findings, and returns
        a result containing valid findings and any validation errors.

        Args:
            checker: A Checker instance to run
            ctx: RunContext with tenant/workspace/run information

        Returns:
            CheckerResult containing:
                - valid_findings: List of validated finding dicts
                - invalid_findings: Count of invalid findings
                - invalid_errors: List of error messages (up to 50)

        Raises:
            NotImplementedError: If checker.run() is not implemented

        Note:
            In lenient mode (default), validation errors are captured but
            don't stop processing. In strict mode, first error raises.

        Example:
            >>> runner = CheckerRunner(validation_mode="lenient")
            >>> result = runner.run_one(EC2Checker(), ctx)
            >>> for finding in result.valid_findings:
            ...     print(finding["fingerprint"])
        """
        result = CheckerResult()
        salt = self._compute_salt(ctx)

        for draft in checker.run(ctx):
            record = build_finding_record(ctx, draft, source_ref=checker.checker_id)
            if self._validation_mode == "strict":
                build_ids_and_validate(
                    record,
                    issue_key=draft.issue_key,
                    finding_id_salt=salt,
                )
                result.valid_findings.append(record)
                continue

            # lenient mode: count and record validation failures
            try:
                build_ids_and_validate(
                    record,
                    issue_key=draft.issue_key,
                    finding_id_salt=salt,
                )
                result.valid_findings.append(record)
            except ValidationError as exc:
                result.invalid_findings += 1

                # Add context to pinpoint the source checker + scope
                if len(result.invalid_errors) < 50:
                    check_id = ""
                    try:
                        check_id = getattr(checker, "check_id", "") or checker.__class__.__name__
                    except Exception:  # pragma: no cover
                        check_id = "unknown-checker"

                    scope = {}
                    try:
                        scope = (record.get("scope") or {}) if isinstance(record, dict) else {}
                    except Exception:  # pragma: no cover
                        scope = {}

                    preview = {
                        "check_id": record.get("check_id") if isinstance(record, dict) else "",
                        "resource": (scope.get("resource_id") or scope.get("resource_arn") or "") if isinstance(scope, dict) else "",
                        "region": scope.get("region") if isinstance(scope, dict) else "",
                        "account_id": scope.get("account_id") if isinstance(scope, dict) else "",
                    }

                    result.invalid_errors.append(f"[{check_id}] {exc} | preview={preview!r}")


        return result

    def run_many(self, checkers: Sequence[Checker], ctx: RunContext) -> CheckerResult:
        """Run multiple checkers and merge results.

        Executes all checkers sequentially, merging their results into a single
        CheckerResult. This is useful for running all checkers for a service
        or running all checkers in a single run.

        Args:
            checkers: Sequence of Checker instances to run
            ctx: RunContext with tenant/workspace/run information

        Returns:
            CheckerResult containing merged results from all checkers:
                - valid_findings: Combined list of all valid findings
                - invalid_findings: Total count of invalid findings
                - invalid_errors: Combined error messages (max 50)

        Note:
            Errors are collected up to a maximum of 50 to prevent
            memory issues with very large datasets.

        Example:
            >>> checkers = [EC2Checker(), RDSChecker(), S3Checker()]
            >>> runner = CheckerRunner()
            >>> result = runner.run_many(checkers, ctx)
            >>> print(f"Total findings: {len(result.valid_findings)}")
            Total findings: 156
        """
        merged = CheckerResult()
        for checker in checkers:
            r = self.run_one(checker, ctx)
            merged.valid_findings.extend(r.valid_findings)
            merged.invalid_findings += r.invalid_findings
            merged.invalid_errors.extend(r.invalid_errors[: max(0, 50 - len(merged.invalid_errors))])
        return merged


# -----------------------------
# Record builder (draft -> canonical dict)
# -----------------------------


def _money_or_zero(value: Any) -> float:
    """Normalize money to a numeric type.

    Strict policy: money values must be numeric (float/int) or None.
    We keep downstream invariants stable by returning 0.0 when missing.

    Args:
        value: Any value to normalize (can be None, int, float, or invalid type)

    Returns:
        float: Normalized monetary value, 0.0 for None/invalid

    Raises:
        ValueError: If value is a boolean (common bug)

    Example:
        >>> _money_or_zero(None)
        0.0
        >>> _money_or_zero(100.50)
        100.5
        >>> _money_or_zero("100")  # Raises - strings not allowed
        ValueError: money value must be numeric or None, got str: '100'
    """
    if value is None:
        return 0.0
    if isinstance(value, bool):
        raise ValueError("money value cannot be bool")
    if isinstance(value, (int, float)):
        return float(value)
    # Any string formatting must happen at presentation time, never in findings.
    raise ValueError(f"money value must be numeric or None, got {type(value).__name__}: {value!r}")


def _normalize_estimate_confidence(value: Any) -> int:
    """Normalize confidence to an int 0..100.

    Converts various confidence representations to a standardized 0-100 integer.
    This ensures consistent confidence scoring across all checkers.

    Args:
        value: Confidence value in various formats

    Returns:
        int: Normalized confidence score 0-100

    Conversion rules:
        - None/empty -> 0
        - int/float -> clamped to 0-100
        - "low"/"l" -> 30
        - "medium"/"med"/"m" -> 60
        - "high"/"h" -> 85
        - numeric string -> parsed and clamped
        - invalid string -> 0

    Example:
        >>> _normalize_estimate_confidence(None)
        0
        >>> _normalize_estimate_confidence("high")
        85
        >>> _normalize_estimate_confidence(75)
        75
    """
    if value is None or isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        try:
            n = int(round(float(value)))
        except (ValueError, TypeError):
            return 0
        return max(0, min(100, n))
    if isinstance(value, str):
        txt = value.strip().lower()
        if txt in {"", "unknown", "n/a", "na", "none"}:
            return 0
        if txt in {"low", "l"}:
            return 30
        if txt in {"medium", "med", "m"}:
            return 60
        if txt in {"high", "h"}:
            return 85
        try:
            n = int(round(float(txt)))
        except (ValueError, TypeError):
            return 0
        return max(0, min(100, n))
    return 0


def build_finding_record(ctx: RunContext, draft: FindingDraft, *, source_ref: str) -> dict[str, Any]:
    """Convert a FindingDraft into a finops_findings dict.

    This function transforms a checker-specific FindingDraft into the canonical
    finops_findings record format. It handles:
    - String normalization (trimming, lowercasing where appropriate)
    - Default value injection for optional fields
    - Scope and severity structure creation
    - Cost estimation normalization

    Note:
        IDs (fingerprint, finding_id) are NOT added here - those are computed
        by build_ids_and_validate() in finops_contracts.py.

    Args:
        ctx: Run context with tenant/workspace/run information
        draft: FindingDraft from checker
        source_ref: Reference to the source checker (for audit trail)

    Returns:
        Dict[str, Any]: Canonical finops_findings record with all fields
                       except fingerprint and finding_id

    Raises:
        ValueError: If required fields are missing from draft

    Example:
        >>> ctx = RunContext(tenant_id="acme", workspace_id="prod",
        ...                   run_id="run-001", run_ts=datetime.now())
        >>> draft = FindingDraft(check_id="ec2_unused", ...)
        >>> record = build_finding_record(ctx, draft, source_ref="ec2_instances")
        >>> "fingerprint" in record
        False  # Added later by build_ids_and_validate
    """
    tenant_id = normalize_str(ctx.tenant_id)
    workspace_id = normalize_str(ctx.workspace_id, lower=False)
    now = datetime.now(UTC)

    record: dict[str, Any] = {
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,

        # run identity
        "run_id": normalize_str(ctx.run_id, lower=False),
        "run_ts": ctx.run_ts,        # datetime is ok; contracts module serializes deterministically
        "ingested_ts": now,

        # engine metadata
        "engine_name": normalize_str(ctx.engine_name, lower=False),
        "engine_version": normalize_str(ctx.engine_version, lower=False),
        "rulepack_version": normalize_str(ctx.rulepack_version, lower=False),

        # check identity
        "check_id": normalize_str(draft.check_id),
        "check_name": normalize_str(draft.check_name, lower=False),
        "category": normalize_str(draft.category),
        "sub_category": normalize_str(draft.sub_category),
        "frameworks": list(draft.frameworks) if draft.frameworks else [],

        # target scope
        "scope": draft.scope.to_dict(),

        # result and severity
        "status": normalize_str(draft.status),
        "severity": {
            "level": normalize_str(draft.severity.level),
            "score": int(draft.severity.score),
        },

        # content
        "title": normalize_str(draft.title, lower=False),
        "message": normalize_str(draft.message, lower=False),
        "recommendation": normalize_str(draft.recommendation, lower=False),
        "remediation": normalize_str(draft.remediation, lower=False),
        "links": draft.links,

        # estimation
        "estimated": {
            # Enforce: cost fields always present ("0" if missing)
            "monthly_savings": _money_or_zero(draft.estimated_monthly_savings),
            "monthly_cost": _money_or_zero(draft.estimated_monthly_cost),
            "one_time_savings": 0.0,
            # Normalize: confidence is always 0..100 int
            "confidence": _normalize_estimate_confidence(draft.estimate_confidence),
            "notes": normalize_str(draft.estimate_notes, lower=False),
        },

        # actual is optional; keep empty structure to ease downstream usage
        "actual": {
            "cost_7d": None,
            "cost_30d": None,
            "cost_mtd": None,
            "cost_prev_month": None,
            "savings_7d": None,
            "savings_30d": None,
            "model": {
                "currency": normalize_str(ctx.default_currency, lower=False),
                "cost_model": "",
                "granularity": "",
                "period_start": "",
                "period_end": "",
            },
            "attribution": {
                "method": "",
                "confidence": 0,
                "matched_keys": [],
            },
        },

        # lifecycle is optional; initialize minimal
        "lifecycle": {
            "status": "open" if normalize_str(draft.status) == "fail" else "",
            "first_seen_ts": "",
            "last_seen_ts": "",
            "resolved_ts": "",
            "snooze_until_ts": "",
        },

        # extensions
        "tags": {str(k): str(v) for k, v in (draft.tags or {}).items()},
        "labels": {str(k): str(v) for k, v in (draft.labels or {}).items()},
        "dimensions": {str(k): str(v) for k, v in (draft.dimensions or {}).items()},
        "metrics": {},  # keep empty; can be filled by specific checkers if needed
        "metadata_json": "",

        # lineage
        "source": ctx.to_source_struct(source_ref=source_ref),
    }

    return record


# -----------------------------
# Optional: Emitter helper (nice when checkers want to push results)
# -----------------------------


@dataclass
class FindingEmitter:
    """
    Helper for checkers that prefer push-style (emit) instead of yielding.
    It still produces FindingDrafts; the runner will handle IDs/validation.
    """
    _items: list[FindingDraft] = field(default_factory=list)

    def emit(self, draft: FindingDraft) -> None:
        self._items.append(draft)

    def items(self) -> list[FindingDraft]:
        return list(self._items)


# -----------------------------
# Example checker implementations
# -----------------------------


class ExampleGravitonChecker:
    checker_id = "checker.aws.ec2.graviton"

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        # In real code, iterate over instances from AWS APIs, inventory, etc.
        instances = [
            {"account_id": "123456789012", "region": "eu-west-3", "instance_id": "i-0abc", "arch": "x86_64"},
            {"account_id": "123456789012", "region": "eu-west-3", "instance_id": "i-0def", "arch": "arm64"},
        ]

        for inst in instances:
            if inst["arch"] != "x86_64":
                continue

            scope = Scope(
                cloud=ctx.cloud,
                billing_account_id=inst["account_id"],
                account_id=inst["account_id"],
                region=inst["region"],
                service="AmazonEC2",
                resource_type="ec2_instance",
                resource_id=inst["instance_id"],
                resource_arn="",  # fill if you have it
            )

            draft = FindingDraft(
                check_id="aws.ec2.rightsize.graviton",
                check_name="EC2 Graviton candidates",
                category="rightsizing",
                status="fail",
                severity=Severity(level="medium", score=60),
                title="Instance is likely Graviton-compatible",
                message="This x86_64 instance appears compatible with Graviton families.",
                recommendation="Evaluate switching to m7g/c7g/r7g families.",
                scope=scope,
                estimated_monthly_savings=12.340000,
                estimate_confidence=70,
                issue_key={
                    "recommended_arch": "arm64",
                    "recommended_families": "m7g,c7g,r7g",
                },
                dimensions={
                    "current_arch": inst["arch"],
                },
            )

            yield draft


# -----------------------------
# Example usage (no writer)
# -----------------------------


def example_run() -> None:
    ctx = RunContext(
        tenant_id="acme",
        workspace_id="prod",
        run_id="run-2026-01-22T10:00:00Z",
        run_ts=datetime.now(UTC),
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=1,
        default_currency="USD",
        cloud="aws",
    )

    runner = CheckerRunner(finding_id_salt_mode="stable")
    res = runner.run_many([ExampleGravitonChecker()], ctx)

    # res.valid_findings is a list[dict] ready to be written as Parquet rows later
    # res.invalid_findings / res.invalid_errors give you data quality visibility
    _ = res
