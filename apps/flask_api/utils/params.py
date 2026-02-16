"""Query and payload parameter parsing helpers for Flask API.

Provides utilities for extracting and validating request parameters
from query strings and JSON payloads.
"""

from datetime import UTC, datetime
from typing import Any

from flask import request

# Sentinel value for missing optional parameters
_MISSING = object()


def _q(name: str, default: str | None = None) -> str | None:
    """Get a query parameter value with optional default.

    Args:
        name: Parameter name
        default: Default value if not present

    Returns:
        Parameter value or default
    """
    v = request.args.get(name)
    if v is None or v == "":
        return default
    return v


def _require_scope_from_query() -> tuple[str, str]:
    """Extract required tenant_id and workspace from query parameters.

    Accepts either 'tenant_id' or 'tenant' (alias) and 'workspace'.

    Returns:
        Tuple of (tenant_id, workspace)

    Raises:
        ValueError: If tenant_id or workspace is missing/invalid
    """
    tenant_id = _q("tenant_id") or _q("tenant") or ""
    workspace = _q("workspace") or _q("ws") or ""

    if not tenant_id or not workspace:
        missing = []
        if not tenant_id:
            missing.append("tenant_id")
        if not workspace:
            missing.append("workspace")
        raise ValueError(f"Missing required query params: {', '.join(missing)}")

    return tenant_id.strip(), workspace.strip()


def _require_scope_from_json(payload: dict[str, Any]) -> tuple[str, str]:
    """Extract required tenant_id and workspace from JSON payload.

    Accepts either 'tenant_id' or 'tenant' (alias) and 'workspace'.

    Args:
        payload: JSON payload dictionary

    Returns:
        Tuple of (tenant_id, workspace)

    Raises:
        ValueError: If tenant_id or workspace is missing/invalid
    """
    tenant_id = str(payload.get("tenant_id") or payload.get("tenant") or "").strip()
    workspace = str(payload.get("workspace") or payload.get("ws") or "").strip()

    if not tenant_id or not workspace:
        missing = []
        if not tenant_id:
            missing.append("tenant_id")
        if not workspace:
            missing.append("workspace")
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    return tenant_id, workspace


def _safe_scope_from_request() -> tuple[str | None, str | None]:
    """Safely extract tenant_id and workspace from request.

    Does not raise - returns None values if not present.
    Useful for logging or optional scoping.

    Returns:
        Tuple of (tenant_id or None, workspace or None)
    """
    tenant_id = _q("tenant_id") or _q("tenant") or None
    workspace = _q("workspace") or _q("ws") or None
    if tenant_id:
        tenant_id = tenant_id.strip() or None
    if workspace:
        workspace = workspace.strip() or None
    return tenant_id, workspace


def _parse_int(
    value: str | None, *, default: int, min_v: int, max_v: int
) -> int:
    """Parse an integer query parameter with bounds checking.

    Args:
        value: String value to parse
        default: Default value if empty
        min_v: Minimum allowed value
        max_v: Maximum allowed value

    Returns:
        Parsed integer value

    Raises:
        ValueError: If value is not a valid integer or out of bounds
    """
    if value is None or value == "":
        return default
    try:
        n = int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid integer value: {value!r}") from exc
    if n < min_v or n > max_v:
        raise ValueError(f"Value {n} out of range [{min_v}, {max_v}]")
    return n


def _parse_csv_list(value: str | None) -> list[str] | None:
    """Parse a comma-separated list of values.

    Args:
        value: Comma-separated string

    Returns:
        List of trimmed strings, or None if empty
    """
    if not value:
        return None
    items = [x.strip() for x in value.split(",") if x.strip()]
    return items or None


def _parse_iso8601_dt(
    value: str | None, *, field_name: str = "timestamp"
) -> datetime | None:
    """Parse an ISO-8601 timestamp into a UTC-aware datetime.

    Accepts timestamps with or without timezone, and trailing 'Z'.

    Args:
        value: ISO-8601 timestamp string
        field_name: Field name for error messages

    Returns:
        UTC-aware datetime, or None if value is empty

    Raises:
        ValueError: If timestamp format is invalid
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"Invalid {field_name} (expected ISO-8601): {s!r}"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _coerce_optional_text(value: Any) -> str | None:
    """Normalize optional API text values to trimmed strings or None.

    Args:
        value: Value to coerce

    Returns:
        Trimmed string or None
    """
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _payload_optional_text(payload: dict[str, Any], key: str) -> Any:
    """Return normalized payload value for a key or _MISSING when absent.

    Args:
        payload: JSON payload dictionary
        key: Key to look up

    Returns:
        Normalized text value, or _MISSING sentinel if key not present
    """
    if key not in payload:
        return _MISSING
    return _coerce_optional_text(payload.get(key))


def _coerce_positive_int(value: Any, *, field_name: str) -> int:
    """Parse a required positive integer field from JSON payload data.

    Args:
        value: Value to parse
        field_name: Field name for error messages

    Returns:
        Positive integer value

    Raises:
        ValueError: If value is not a valid positive integer
    """
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if n <= 0:
        raise ValueError(f"{field_name} must be > 0")
    return n


def _coerce_non_negative_int(value: Any, *, field_name: str) -> int:
    """Parse a required non-negative integer field from JSON payload data.

    Args:
        value: Value to parse
        field_name: Field name for error messages

    Returns:
        Non-negative integer value

    Raises:
        ValueError: If value is not a valid non-negative integer
    """
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if n < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return n


def _coerce_optional_float(value: Any, *, field_name: str) -> float | None:
    """Parse an optional float value from JSON payload data.

    Args:
        value: Value to parse
        field_name: Field name for error messages

    Returns:
        Float value or None

    Raises:
        ValueError: If value cannot be parsed as float
    """
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a number") from exc


def _coerce_text_list(value: Any, *, field_name: str) -> list[str] | None:
    """Normalize list-like API input into a compact list of strings.

    Accepts comma-separated strings or actual lists.

    Args:
        value: Value to coerce
        field_name: Field name for error messages

    Returns:
        List of trimmed strings, or None

    Raises:
        ValueError: If value cannot be coerced to a list
    """
    if value is None:
        return None
    if isinstance(value, str):
        items = [x.strip() for x in value.split(",") if x.strip()]
        return items or None
    if isinstance(value, (list, tuple)):
        result = []
        for item in value:
            if item is not None:
                text = str(item).strip()
                if text:
                    result.append(text)
        return result or None
    raise ValueError(f"{field_name} must be a string or list")
