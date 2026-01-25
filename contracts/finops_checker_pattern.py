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

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, Union

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
    services: Optional[Services] = None

    def to_source_struct(self, *, source_ref: str, source_type: str = "scanner") -> Dict[str, Any]:
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

    def to_dict(self) -> Dict[str, Any]:
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
    frameworks: Tuple[str, ...] = ()

    # Estimation fields: keep them optional
    # NOTE: money values must be numeric (float) or None. Formatting is a presentation concern.
    estimated_monthly_savings: Optional[float] = None
    estimated_monthly_cost: Optional[float] = None
    estimate_confidence: Optional[Union[int, str]] = None  # allow "low"/"medium"/"high" too
    estimate_notes: str = ""

    # Extra dimensions
    tags: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    dimensions: Dict[str, str] = field(default_factory=dict)

    # Issue discriminator for fingerprint stability
    issue_key: Dict[str, Any] = field(default_factory=dict)

    # Links (optional)
    links: List[Dict[str, str]] = field(default_factory=list)

    def with_issue(self, **kwargs: Any) -> "FindingDraft":
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
    valid_findings: List[Dict[str, Any]] = field(default_factory=list)
    invalid_findings: int = 0
    invalid_errors: List[str] = field(default_factory=list)


class CheckerRunner:
    """
    Runs one or many checkers and outputs validated finops_findings records (dicts).
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

    def _compute_salt(self, ctx: RunContext) -> Optional[str]:
        if self._salt_mode == "stable":
            return None
        if self._salt_mode == "per_run":
            return ctx.run_id
        # per_day
        return ctx.run_ts.astimezone(timezone.utc).date().isoformat()

    def run_one(self, checker: Checker, ctx: RunContext) -> CheckerResult:
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
                if len(result.invalid_errors) < 50:
                    result.invalid_errors.append(str(exc))

        return result

    def run_many(self, checkers: Sequence[Checker], ctx: RunContext) -> CheckerResult:
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

    Strict policy (Option B): money values must be numeric (float/int) or None.
    We keep downstream invariants stable by returning 0.0 when missing.
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

    Accepts:
      - None -> 0
      - int/float -> clamped 0..100
      - str: "low"|"medium"|"high"|"unknown" plus numeric strings
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


def build_finding_record(ctx: RunContext, draft: FindingDraft, *, source_ref: str) -> Dict[str, Any]:
    """
    Convert a FindingDraft into a finops_findings dict.
    IDs are not added here (done by build_ids_and_validate()).
    """
    tenant_id = normalize_str(ctx.tenant_id)
    workspace_id = normalize_str(ctx.workspace_id, lower=False)
    now = datetime.now(timezone.utc)

    record: Dict[str, Any] = {
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
    _items: List[FindingDraft] = field(default_factory=list)

    def emit(self, draft: FindingDraft) -> None:
        self._items.append(draft)

    def items(self) -> List[FindingDraft]:
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
        run_ts=datetime.now(timezone.utc),
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
