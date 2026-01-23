"""
finops_contracts.py

Canonicalization, stable hashing (hex), ID generation, and validations for the
FinOps SaaS canonical schema.

This module is intentionally writer-agnostic: it does not read/write Parquet/CSV.
It provides:
- Canonicalization utilities for scope + issue keys
- Deterministic hashing (SHA-256 hex)
- fingerprint and finding_id generation
- Required-fields validation for finops_findings records

IDs:
- fingerprint = stable identity of the issue on the target across runs
- finding_id  = storage identity derived from fingerprint (stable/per_run/per_day via salt)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Mapping, Optional, Tuple

# -----------------------------
# Contract constants / enums
# -----------------------------

FINDING_STATUS_VALUES: Tuple[str, ...] = ("pass", "fail", "info", "unknown")
SEVERITY_LEVEL_VALUES: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")
LIFECYCLE_STATUS_VALUES: Tuple[str, ...] = ("open", "acknowledged", "snoozed", "resolved", "ignored")

ATTRIBUTION_METHOD_VALUES: Tuple[str, ...] = (
    "exact_resource_id",
    "tag",
    "heuristic",
    "shared_unallocated",
    "none",
)

COST_MODEL_VALUES: Tuple[str, ...] = ("unblended", "amortized", "net", "blended")

# Required fields for a record to be considered valid (minimal contract)
REQUIRED_FIELDS: Tuple[str, ...] = (
    "tenant_id",
    "finding_id",
    "fingerprint",
    "run_id",
    "run_ts",
    "check_id",
    "status",
    "severity.level",
    "scope.cloud",
    "scope.account_id",
    "scope.service",
    "source.schema_version",
)

# Minimal expected schema version for this contract module
MIN_SCHEMA_VERSION = 1
MAX_SCHEMA_VERSION = 65535  # uint16


# -----------------------------
# Exceptions
# -----------------------------


class ContractError(ValueError):
    """Base contract error."""


class ValidationError(ContractError):
    """Raised when a record does not satisfy required fields or constraints."""


# -----------------------------
# JSON canonicalization + hashing
# -----------------------------


def _to_json_compatible(value: Any) -> Any:
    """Convert common Python types into JSON-compatible primitives deterministically."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, date) and not isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        seq = [_to_json_compatible(v) for v in value]
        if isinstance(value, set):
            return sorted(seq, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
        return seq
    return str(value)


def canonical_json_dumps(payload: Mapping[str, Any]) -> str:
    """Deterministic JSON serialization: sorted keys, no whitespace, UTF-8."""
    compatible = _to_json_compatible(payload)
    return json.dumps(compatible, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex_from_json(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 over canonical JSON and return hex digest."""
    data = canonical_json_dumps(payload).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# -----------------------------
# Canonicalization
# -----------------------------


def normalize_str(value: Any, *, lower: bool = True, none_as_empty: bool = True) -> str:
    """Normalize strings for deterministic keys: trim, optional lowercase, None->''."""
    if value is None:
        return "" if none_as_empty else "null"
    text = str(value).strip()
    return text.lower() if lower else text


@dataclass(frozen=True)
class ScopeKey:
    """Canonical scope key used in fingerprint generation."""
    cloud: str
    billing_account_id: str
    account_id: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    resource_arn: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "cloud": self.cloud,
            "billing_account_id": self.billing_account_id,
            "account_id": self.account_id,
            "region": self.region,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
        }


def canonicalize_scope(scope: Mapping[str, Any]) -> ScopeKey:
    """Canonicalize raw `scope` dict into a stable ScopeKey."""
    cloud = normalize_str(scope.get("cloud"))
    billing_account_id = normalize_str(scope.get("billing_account_id"))
    account_id = normalize_str(scope.get("account_id"))
    region = normalize_str(scope.get("region"))
    service = normalize_str(scope.get("service"))
    resource_type = normalize_str(scope.get("resource_type"))

    # Keep case for provider IDs / ARNs (do not lower)
    resource_id = normalize_str(scope.get("resource_id"), lower=False)
    resource_arn = normalize_str(scope.get("resource_arn"), lower=False)

    return ScopeKey(
        cloud=cloud,
        billing_account_id=billing_account_id,
        account_id=account_id,
        region=region,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_arn=resource_arn,
    )


def canonicalize_issue_key(issue_key: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Canonicalize issue_key as sorted dict[str,str]."""
    if not issue_key:
        return {}
    out: Dict[str, str] = {}
    for k, v in issue_key.items():
        key = normalize_str(k)
        out[key] = normalize_str(v, lower=False)
    return dict(sorted(out.items(), key=lambda item: item[0]))


# -----------------------------
# ID generation
# -----------------------------


def compute_fingerprint(
    *,
    tenant_id: str,
    check_id: str,
    scope: Mapping[str, Any],
    issue_key: Optional[Mapping[str, Any]] = None,
) -> str:
    """fingerprint = stable identity of an issue on a target across runs."""
    payload = {
        "tenant_id": normalize_str(tenant_id),
        "check_id": normalize_str(check_id),
        "scope": canonicalize_scope(scope).to_dict(),
        "issue": canonicalize_issue_key(issue_key),
    }
    return sha256_hex_from_json(payload)


def compute_finding_id(
    *,
    tenant_id: str,
    fingerprint: str,
    id_salt: Optional[str] = None,
) -> str:
    """finding_id = storage id derived from fingerprint, optionally salted."""
    payload = {
        "tenant_id": normalize_str(tenant_id),
        "fingerprint": normalize_str(fingerprint, lower=True),
        "salt": normalize_str(id_salt, lower=False) if id_salt is not None else "",
    }
    return sha256_hex_from_json(payload)


# -----------------------------
# Validation utilities
# -----------------------------


def _get_nested(record: Mapping[str, Any], dotted_path: str) -> Any:
    """Retrieve nested dict values using dot notation. Returns None if missing."""
    current: Any = record
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and normalize_str(value, lower=False) != ""


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Accept datetime or ISO-8601 string. Return UTC datetime.
    Supported string forms:
      - 2026-01-23T10:00:00Z
      - 2026-01-23T10:00:00+00:00
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Minimal ISO parse without external deps
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _parse_decimal(value: Any) -> Optional[Decimal]:
    """
    Accept Decimal, int, float, or numeric string. Return Decimal.
    Empty string -> None.
    """
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, (int,)):
        return Decimal(value)
    if isinstance(value, float):
        # Convert through string to reduce binary float surprises
        return Decimal(str(value))
    if isinstance(value, str):
        txt = value.strip()
        if txt == "":
            return None
        try:
            return Decimal(txt)
        except InvalidOperation:
            return None
    return None


# -----------------------------
# Validations: required, enums, and coherence
# -----------------------------


def validate_required_fields(record: Mapping[str, Any]) -> List[str]:
    """Validate presence (non-empty) of REQUIRED_FIELDS. Return list of missing paths."""
    missing: List[str] = []
    for field_path in REQUIRED_FIELDS:
        value = _get_nested(record, field_path)
        if value is None:
            missing.append(field_path)
            continue
        if isinstance(value, str) and normalize_str(value, lower=False) == "":
            missing.append(field_path)
    return missing


def validate_enums(record: Mapping[str, Any]) -> List[str]:
    """Validate enum constraints. Return list of error strings."""
    errors: List[str] = []

    status = _get_nested(record, "status")
    if status is not None:
        st = normalize_str(status)
        if st not in FINDING_STATUS_VALUES:
            errors.append(f"status must be one of {FINDING_STATUS_VALUES}, got '{status}'")

    sev_level = _get_nested(record, "severity.level")
    if sev_level is not None:
        sl = normalize_str(sev_level)
        if sl not in SEVERITY_LEVEL_VALUES:
            errors.append(f"severity.level must be one of {SEVERITY_LEVEL_VALUES}, got '{sev_level}'")

    lifecycle_status = _get_nested(record, "lifecycle.status")
    if lifecycle_status is not None and normalize_str(lifecycle_status, lower=False) != "":
        ls = normalize_str(lifecycle_status)
        if ls not in LIFECYCLE_STATUS_VALUES:
            errors.append(f"lifecycle.status must be one of {LIFECYCLE_STATUS_VALUES}, got '{lifecycle_status}'")

    cost_model = _get_nested(record, "actual.model.cost_model")
    if cost_model is not None and normalize_str(cost_model, lower=False) != "":
        cm = normalize_str(cost_model)
        if cm not in COST_MODEL_VALUES:
            errors.append(f"actual.model.cost_model must be one of {COST_MODEL_VALUES}, got '{cost_model}'")

    attribution_method = _get_nested(record, "actual.attribution.method")
    if attribution_method is not None and normalize_str(attribution_method, lower=False) != "":
        am = normalize_str(attribution_method)
        if am not in ATTRIBUTION_METHOD_VALUES:
            errors.append(
                "actual.attribution.method must be one of "
                f"{ATTRIBUTION_METHOD_VALUES}, got '{attribution_method}'"
            )

    confidence = _get_nested(record, "actual.attribution.confidence")
    if confidence is not None and normalize_str(confidence, lower=False) != "":
        try:
            conf_int = int(confidence)
            if conf_int < 0 or conf_int > 100:
                errors.append("actual.attribution.confidence must be within 0..100")
        except (ValueError, TypeError):
            errors.append("actual.attribution.confidence must be an integer within 0..100")

    return errors


def validate_types_and_coherence(record: Mapping[str, Any]) -> List[str]:
    """
    Validate basic types and cross-field coherence. Return list of error strings.
    This is intentionally pragmatic (not full schema enforcement).
    """
    errors: List[str] = []

    # run_ts must be parseable datetime
    run_ts = _get_nested(record, "run_ts")
    if _parse_datetime(run_ts) is None:
        errors.append("run_ts must be a datetime or ISO-8601 string (UTC recommended)")

    ingested_ts = _get_nested(record, "ingested_ts")
    if ingested_ts is not None and normalize_str(ingested_ts, lower=False) != "":
        if _parse_datetime(ingested_ts) is None:
            errors.append("ingested_ts must be a datetime or ISO-8601 string")

    # schema_version must be int within uint16 range
    schema_version = _get_nested(record, "source.schema_version")
    try:
        sv = int(schema_version)
        if sv < MIN_SCHEMA_VERSION or sv > MAX_SCHEMA_VERSION:
            errors.append(f"source.schema_version must be within {MIN_SCHEMA_VERSION}..{MAX_SCHEMA_VERSION}")
    except (ValueError, TypeError):
        errors.append("source.schema_version must be an integer")

    # severity.score must be int and non-negative (bound it if you want)
    sev_score = _get_nested(record, "severity.score")
    if sev_score is not None:
        try:
            sc = int(sev_score)
            if sc < 0 or sc > 1000:
                errors.append("severity.score must be within 0..1000")
        except (ValueError, TypeError):
            errors.append("severity.score must be an integer within 0..1000")

    # scope minimal coherence
    scope = _get_nested(record, "scope")
    if isinstance(scope, Mapping):
        cloud = normalize_str(scope.get("cloud"))
        account_id = normalize_str(scope.get("account_id"), lower=False)
        service = normalize_str(scope.get("service"))
        if cloud == "":
            errors.append("scope.cloud must be non-empty")
        if account_id.strip() == "":
            errors.append("scope.account_id must be non-empty")
        if service == "":
            errors.append("scope.service must be non-empty")
    else:
        errors.append("scope must be an object (dict)")

    # status vs lifecycle coherence (soft rule)
    status = normalize_str(_get_nested(record, "status"))
    lifecycle_status = normalize_str(_get_nested(record, "lifecycle.status"))
    if status == "fail" and lifecycle_status == "":
        # allowed, but recommended default is "open" (runner sets it)
        pass
    if status in ("pass", "info") and lifecycle_status in ("open", "acknowledged"):
        errors.append("lifecycle.status seems inconsistent with status (pass/info should not be open/acknowledged)")

    # Money fields: accept empty string/None, otherwise must be decimal-like
    for path in (
        "estimated.monthly_savings",
        "estimated.monthly_cost",
        "estimated.one_time_savings",
        "actual.cost_7d",
        "actual.cost_30d",
        "actual.cost_mtd",
        "actual.cost_prev_month",
        "actual.savings_7d",
        "actual.savings_30d",
    ):
        val = _get_nested(record, path)
        if val is None:
            continue
        if isinstance(val, str) and val.strip() == "":
            continue
        if _parse_decimal(val) is None:
            errors.append(f"{path} must be numeric (Decimal/int/float or numeric string), got '{val}'")

    # Currency required if you have any actual cost model or any money fields set (soft rule)
    currency = _get_nested(record, "actual.model.currency") or _get_nested(record, "estimated.currency")
    # If any actual costs are present, currency should be present
    any_actual = any(
        _parse_decimal(_get_nested(record, p)) is not None
        for p in ("actual.cost_7d", "actual.cost_30d", "actual.cost_mtd", "actual.cost_prev_month")
    )
    if any_actual and not _is_non_empty_string(currency):
        errors.append("actual.model.currency should be set when actual costs are present")

    return errors


def validate_record_or_raise(record: Mapping[str, Any]) -> None:
    """Validate required fields + enums + coherence; raise ValidationError on failure."""
    missing = validate_required_fields(record)
    enum_errors = validate_enums(record)
    coherence_errors = validate_types_and_coherence(record)

    if missing or enum_errors or coherence_errors:
        parts: List[str] = []
        if missing:
            parts.append(f"Missing/empty required fields: {missing}")
        if enum_errors:
            parts.append("Enum errors: " + "; ".join(enum_errors))
        if coherence_errors:
            parts.append("Type/coherence errors: " + "; ".join(coherence_errors))
        raise ValidationError(" | ".join(parts))


# -----------------------------
# High-level helper: build IDs and validate
# -----------------------------


def build_ids_and_validate(
    record: Dict[str, Any],
    *,
    issue_key: Optional[Mapping[str, Any]] = None,
    finding_id_salt: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience helper:
    - Compute fingerprint from tenant_id, check_id, scope, issue_key
    - Compute finding_id from tenant_id, fingerprint, salt (optional)
    - Insert them into the record
    - Validate required fields, enums, and coherence

    Returns the updated record (mutates input record).
    """
    tenant_id = normalize_str(record.get("tenant_id"))
    check_id = normalize_str(record.get("check_id"))
    scope = record.get("scope") or {}

    if tenant_id == "" or check_id == "" or not isinstance(scope, Mapping):
        raise ValidationError("tenant_id, check_id and scope must be provided to build IDs")

    fingerprint = compute_fingerprint(
        tenant_id=tenant_id,
        check_id=check_id,
        scope=scope,
        issue_key=issue_key,
    )
    record["fingerprint"] = fingerprint

    finding_id = compute_finding_id(
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        id_salt=finding_id_salt,
    )
    record["finding_id"] = finding_id

    validate_record_or_raise(record)
    return record
