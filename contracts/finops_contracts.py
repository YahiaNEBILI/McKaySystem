"""
finops_contracts.py

Canonicalization, stable hashing (hex), ID generation, and validation for the
FinOps SaaS canonical schema.

This module is intentionally writer-agnostic: it does not read/write Parquet/CSV.
It provides:
- Canonicalization utilities for scope + issue keys
- Deterministic hashing (SHA-256 hex)
- fingerprint and finding_id generation
- Required-fields validation for finops_findings records

Design goals:
- Deterministic outputs across runs and machines
- Pylint-friendly, type-hinted, side-effect free
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from decimal import Decimal
from dateutil import parser as _dtparser  # type: ignore

try:
    import pyarrow as pa  # optional; only needed when using Arrow schemas
except Exception:  # pragma: no cover
    pa = None  # type: ignore


# -----------------------------
# Contract constants / enums
# -----------------------------

FINDING_STATUS_VALUES: Tuple[str, ...] = ("pass", "fail", "info", "unknown")

SEVERITY_LEVEL_VALUES: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")

LIFECYCLE_STATUS_VALUES: Tuple[str, ...] = (
    "open",
    "acknowledged",
    "snoozed",
    "resolved",
    "ignored",
)

ATTRIBUTION_METHOD_VALUES: Tuple[str, ...] = (
    "exact_resource_id",
    "tag",
    "heuristic",
    "shared_unallocated",
    "none",
)

COST_MODEL_VALUES: Tuple[str, ...] = ("unblended", "amortized", "net", "blended")


# Minimal required fields for a finops_findings row to be considered valid
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


# -----------------------------
# Exceptions
# -----------------------------


class ContractError(ValueError):
    """Base contract error."""


class ValidationError(ContractError):
    """Raised when a record does not satisfy required fields or enum constraints."""


# -----------------------------
# Helpers: JSON canonicalization + hashing
# -----------------------------


def _to_json_compatible(value: Any) -> Any:
    """
    Convert common Python types into JSON-compatible primitives deterministically.
    """
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        # Always serialize datetimes to UTC ISO 8601 with 'Z'
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, date) and not isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        # Sets are unordered; sort their stringified JSON to ensure determinism
        seq = [_to_json_compatible(v) for v in value]
        if isinstance(value, set):
            return sorted(seq, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
        return seq
    # Fallback: stable string representation
    return str(value)


def canonical_json_dumps(payload: Mapping[str, Any]) -> str:
    """
    Deterministic JSON serialization:
    - sort keys
    - no whitespace
    - ensure_ascii=False for stable UTF-8
    """
    compatible = _to_json_compatible(payload)
    return json.dumps(compatible, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex_from_json(payload: Mapping[str, Any]) -> str:
    """
    Compute SHA-256 over the canonical JSON representation and return hex digest.
    """
    data = canonical_json_dumps(payload).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# -----------------------------
# Canonicalization rules
# -----------------------------


def normalize_str(value: Any, *, lower: bool = True, none_as_empty: bool = True) -> str:
    """
    Normalize strings for deterministic keys:
    - None -> "" by default
    - strip whitespace
    - lower-case by default
    """
    if value is None:
        return "" if none_as_empty else "null"
    text = str(value).strip()
    return text.lower() if lower else text


@dataclass(frozen=True)
class ScopeKey:
    """
    Canonical scope key used in fingerprint generation.

    Note: Keep this minimal & stable. Add new fields only when necessary.
    """
    cloud: str
    billing_account_id: str
    account_id: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    resource_arn: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Return a JSON-serializable representation."""
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
    """
    Canonicalize a raw `scope` dict (potentially messy input) into a stable ScopeKey.

    Expected inputs may contain missing keys; they are normalized to "".
    """
    cloud = normalize_str(scope.get("cloud"))
    billing_account_id = normalize_str(scope.get("billing_account_id"))
    account_id = normalize_str(scope.get("account_id"))
    region = normalize_str(scope.get("region"))
    service = normalize_str(scope.get("service"))
    resource_type = normalize_str(scope.get("resource_type"))
    resource_id = normalize_str(scope.get("resource_id"), lower=False)
    resource_arn = normalize_str(scope.get("resource_arn"), lower=False)

    # Prefer ARN as resource identifier when present (but keep both)
    # We do NOT force-lower AWS IDs/ARNs; keep original case stability.
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
    """
    Canonicalize issue_key as a sorted dict[str, str] for determinism.

    Rules:
    - Only flat key/value pairs (nested structures should be flattened by caller)
    - Keys: normalized to lower-case and trimmed
    - Values: stringified; None -> ""
    """
    if not issue_key:
        return {}

    out: Dict[str, str] = {}
    for k, v in issue_key.items():
        key = normalize_str(k)
        out[key] = normalize_str(v, lower=False)

    # Ensure deterministic ordering by returning a normal dict with sorted keys.
    return dict(sorted(out.items(), key=lambda item: item[0]))


# -----------------------------
# ID generation
# -----------------------------



# -----------------------------
# Fingerprint contract (LOCKED)
# -----------------------------

FINGERPRINT_CONTRACT_VERSION: int = 1

# These are the ONLY top-level keys hashed for fingerprint stability.
# Changing this (or the canonicalization of its children) is a breaking change.
FINGERPRINT_PAYLOAD_KEYS_V1: Tuple[str, ...] = ("tenant_id", "check_id", "scope", "issue")

# Scope fields hashed inside the fingerprint.
FINGERPRINT_SCOPE_FIELDS_V1: Tuple[str, ...] = (
    "cloud",
    "billing_account_id",
    "account_id",
    "region",
    "service",
    "resource_type",
    "resource_id",
    "resource_arn",
)

def fingerprint_payload_v1(
    *,
    tenant_id: str,
    check_id: str,
    scope: Mapping[str, Any],
    issue_key: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the exact payload hashed by :func:`compute_fingerprint`.

    This function exists so the fingerprint contract is explicit, testable,
    and easy to keep stable over time.
    """
    payload: Dict[str, Any] = {
        "tenant_id": normalize_str(tenant_id),
        "check_id": normalize_str(check_id),
        "scope": canonicalize_scope(scope).to_dict(),
        "issue": canonicalize_issue_key(issue_key),
    }
    # Defensive: ensure we never accidentally add keys.
    return {k: payload[k] for k in FINGERPRINT_PAYLOAD_KEYS_V1}

def compute_fingerprint(
    *,
    tenant_id: str,
    check_id: str,
    scope: Mapping[str, Any],
    issue_key: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    fingerprint identifies the same issue on the same target across runs.

    fingerprint = sha256_hex({
        "tenant_id": ...,
        "check_id": ...,
        "scope": <canonical_scope>,
        "issue": <canonical_issue_key>
    })
    """
    payload = fingerprint_payload_v1(tenant_id=tenant_id, check_id=check_id, scope=scope, issue_key=issue_key)
    return sha256_hex_from_json(payload)


def compute_finding_id(
    *,
    tenant_id: str,
    fingerprint: str,
    id_salt: Optional[str] = None,
) -> str:
    """
    finding_id identifies a finding record. You may choose to:
    - make it stable across time: id_salt=None (recommended when you store lifecycle separately)
    - or make it unique per period/run: id_salt="YYYY-MM-DD" or run_id

    finding_id = sha256_hex({
        "tenant_id": ...,
        "fingerprint": ...,
        "salt": ...
    })
    """
    payload = {
        "tenant_id": normalize_str(tenant_id),
        "fingerprint": normalize_str(fingerprint, lower=True),
        "salt": normalize_str(id_salt, lower=False) if id_salt is not None else "",
    }
    return sha256_hex_from_json(payload)


# -----------------------------
# Validation
# -----------------------------


def _get_nested(record: Mapping[str, Any], dotted_path: str) -> Any:
    """
    Retrieve nested dict values using dot notation, e.g. "severity.level".
    Returns None if any part is missing.
    """
    current: Any = record
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def validate_required_fields(record: Mapping[str, Any]) -> List[str]:
    """
    Validate presence (non-empty) of REQUIRED_FIELDS.
    Returns a list of missing field paths.
    """
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
    """
    Validate key enum constraints. Returns a list of error strings.
    """
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
    if confidence is not None:
        try:
            conf_int = int(confidence)
            if conf_int < 0 or conf_int > 100:
                errors.append("actual.attribution.confidence must be within 0..100")
        except (ValueError, TypeError):
            errors.append("actual.attribution.confidence must be an integer within 0..100")

    return errors


def validate_record_or_raise(record: Mapping[str, Any]) -> None:
    """
    Validate required fields and key enums; raise ValidationError on failure.
    """
    missing = validate_required_fields(record)
    enum_errors = validate_enums(record)

    if missing or enum_errors:
        parts: List[str] = []
        if missing:
            parts.append(f"Missing/empty required fields: {missing}")
        if enum_errors:
            parts.append("Enum/constraint errors: " + "; ".join(enum_errors))
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
    - Validate required fields and enums

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

    # Ensure run_ts is datetime or ISO string; required field check accepts string,
    # but you should standardize upstream.
    validate_record_or_raise(record)
    return record


# -----------------------------
# Optional: normalization for Arrow/Parquet writers
# -----------------------------

def _parse_utc_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(value, str):
        dt = _dtparser.isoparse(value)
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise TypeError(f"Cannot parse datetime from {type(value)}")

def _parse_date(value: Any) -> Optional[date]:
    if value is None or value == "":
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise TypeError(f"Cannot parse date from {type(value)}")


def normalize_record_for_arrow(
    record: Mapping[str, Any],
    *,
    schema: Any,
) -> Dict[str, Any]:
    """Normalize a finding record to match a PyArrow schema.

    Purpose (small-team friendly):
    - keep your in-memory / JSON record flexible (empty strings, decimal strings, ISO timestamps)
    - convert ONLY at the storage boundary so Parquet/Arrow writers don't choke

    Conversions:
    - "" / None -> None for non-string typed fields
    - decimal fields -> Decimal
    - timestamp fields -> timezone-aware UTC datetime
    - date32 fields -> datetime.date

    `schema` should be a `pyarrow.Schema` (e.g., schemas.FINOPS_FINDINGS_SCHEMA).
    """
    if pa is None:
        raise RuntimeError("pyarrow is not available; cannot normalize for Arrow")

    def convert(value: Any, dtype: Any) -> Any:
        if pa.types.is_struct(dtype):
            value = value or {}
            if not isinstance(value, Mapping):
                raise TypeError(f"Expected struct (dict) for {dtype}, got {type(value)}")
            out: Dict[str, Any] = {}
            for field in dtype:
                out[field.name] = convert(value.get(field.name), field.type)
            return out

        if pa.types.is_list(dtype):
            if value is None or value == "":
                return None
            if not isinstance(value, list):
                raise TypeError(f"Expected list for {dtype}, got {type(value)}")
            return [convert(v, dtype.value_type) for v in value]

        if pa.types.is_map(dtype):
            if value is None or value == "":
                return None
            if not isinstance(value, Mapping):
                raise TypeError(f"Expected map/dict for {dtype}, got {type(value)}")
            # keys must be strings for our schemas
            return {str(k): convert(v, dtype.item_type) for k, v in value.items()}

        if pa.types.is_decimal(dtype):
            if value is None or value == "":
                return None
            if isinstance(value, Decimal):
                return value
            return Decimal(str(value))

        if pa.types.is_timestamp(dtype):
            return _parse_utc_datetime(value)

        if pa.types.is_date32(dtype):
            return _parse_date(value)

        if pa.types.is_integer(dtype):
            if value is None or value == "":
                return None
            return int(value)

        if pa.types.is_floating(dtype):
            if value is None or value == "":
                return None
            return float(value)

        if pa.types.is_boolean(dtype):
            if value is None or value == "":
                return None
            return bool(value)

        # strings and other types: keep as-is, but standardize None -> ""
        if pa.types.is_string(dtype):
            return "" if value is None else str(value)

        return value

    if not isinstance(schema, pa.Schema):
        raise TypeError("schema must be a pyarrow.Schema")

    out: Dict[str, Any] = {}
    for field in schema:
        out[field.name] = convert(record.get(field.name), field.type)
    return out


def _self_test_fingerprint_contract() -> None:
    """Lightweight self-test to catch accidental fingerprint breaking changes."""
    # Ensure payload keys remain locked
    p = fingerprint_payload_v1(
        tenant_id="TenantA",
        check_id="aws.ec2.test",
        scope={"cloud": "aws", "account_id": "123", "service": "ec2", "region": "us-east-1"},
        issue_key={"k": "v"},
    )
    assert tuple(p.keys()) == FINGERPRINT_PAYLOAD_KEYS_V1
    # Ensure scope fields are present (even if empty)
    for k in FINGERPRINT_SCOPE_FIELDS_V1:
        assert k in p["scope"]

    # Ensure determinism
    f1 = compute_fingerprint(tenant_id="TenantA", check_id="aws.ec2.test", scope={"cloud":"aws","account_id":"123","service":"ec2","region":"us-east-1"}, issue_key={"k":"v"})
    f2 = compute_fingerprint(tenant_id="TenantA", check_id="aws.ec2.test", scope={"region":"us-east-1","service":"ec2","account_id":"123","cloud":"aws"}, issue_key={"k":"v"})
    assert f1 == f2


if __name__ == "__main__":  # pragma: no cover
    _self_test_fingerprint_contract()
