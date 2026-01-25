"""Shared helpers for AWS checkers.

The checker layer tends to repeat a few patterns:
- normalize tags from multiple AWS shapes
- apply retention / suppression tag logic
- normalize timestamps to UTC
- extract region from boto3 clients or ARNs

Keeping these helpers in one place reduces duplication and makes behavior
consistent across checkers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping, Optional


@dataclass(frozen=True)
class AwsAccountContext:
    """Account context injected into checkers.

    Most checkers only need an account_id; billing_account_id is kept to align
    with the broader contracts used by the pipeline.
    """

    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Return ``dt`` converted to timezone-aware UTC (or None)."""

    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def now_utc() -> datetime:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc)


def safe_region_from_client(client: Any) -> str:
    """Best-effort region name extraction from a boto3 client."""

    try:
        return str(getattr(getattr(client, "meta", None), "region_name", "") or "")
    except Exception:  # pragma: no cover
        return ""


def arn_region(arn: str) -> str:
    """Return the region component of an ARN (or empty string)."""

    # arn:partition:service:region:account:resource...
    try:
        parts = str(arn or "").split(":")
        if len(parts) >= 4 and parts[0] == "arn":
            return parts[3] or ""
    except Exception:  # pragma: no cover
        return ""
    return ""


def safe_float(value: Any, default: float = 0.0) -> float:
    """Best-effort float conversion."""

    try:
        if value is None:
            return float(default)
        if isinstance(value, (int, float)):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def money(amount: float) -> float:
    """Round a money amount to 2 decimals.

    This is intentionally numeric (presentation formatting is handled elsewhere).
    """

    return round(float(amount), 2)


def gb_from_bytes(size_bytes: Any) -> float:
    """Convert bytes to GiB as a float (0.0 if missing/invalid)."""

    size = safe_float(size_bytes, default=0.0)
    if size <= 0.0:
        return 0.0
    return size / (1024.0**3)


def normalize_tags(tags: Any) -> dict[str, str]:
    """Normalize AWS tags into a ``{lower_key: lower_value}`` dict.

    Supports common AWS shapes:
    - dict of {k:v}
    - list of {"Key":..., "Value":...}
    - None

    Values are lowercased and stripped. Missing values become an empty string.
    """

    out: dict[str, str] = {}
    if not tags:
        return out

    if isinstance(tags, Mapping):
        for k, v in tags.items():
            key = str(k or "").strip().lower()
            if not key:
                continue
            out[key] = str(v or "").strip().lower()
        return out

    if isinstance(tags, list):
        for item in tags:
            if not isinstance(item, Mapping):
                continue
            key = str(item.get("Key") or "").strip().lower()
            if not key:
                continue
            out[key] = str(item.get("Value") or "").strip().lower()
        return out

    # Unknown shape
    return out


def is_suppressed(
    tags: Any,
    *,
    suppress_keys: set[str] | frozenset[str],
    suppress_values: Optional[set[str] | frozenset[str]] = None,
    value_prefixes: tuple[str, ...] = (),
    value_only_if_key_suppressed: bool = False,
    prefix_only_if_key_suppressed: bool = True,
) -> bool:
    """Return True if tags indicate intentional retention/suppression.

    - Key-only suppression: if a tag key is present in ``suppress_keys``.
    - Value suppression: if a tag value is in ``suppress_values``.
    - Prefix suppression: if a value starts with one of ``value_prefixes``.
      If ``prefix_only_if_key_suppressed`` is True, prefix checks only apply
      when the corresponding key is in ``suppress_keys`` (safer default).

    ``tags`` may be any shape supported by :func:`normalize_tags`.
    """

    norm = normalize_tags(tags)
    if not norm:
        return False

    keys = {str(k).strip().lower() for k in suppress_keys if str(k).strip()}
    values = {str(v).strip().lower() for v in (suppress_values or set()) if str(v).strip()}
    prefixes = tuple(str(p).strip().lower() for p in value_prefixes if str(p).strip())

    for k, v in norm.items():
        if k in keys:
            return True
        if v in values and (not value_only_if_key_suppressed or k in keys):
            return True

    if prefixes:
        for k, v in norm.items():
            if not v:
                continue
            if prefix_only_if_key_suppressed and k not in keys:
                continue
            for p in prefixes:
                if v.startswith(p):
                    return True

    return False
