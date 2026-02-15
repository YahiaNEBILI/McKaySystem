"""Payload helpers for Flask API.

Provides utilities for extracting and transforming data from finding payloads,
run metadata, and other JSON structures.
"""

import json
from typing import Any, Dict, Optional


def _as_float(value: Any, *, default: float = 0.0) -> float:
    """Best-effort float conversion for API payload values.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Float value or default
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _payload_dict(value: Any) -> Dict[str, Any]:
    """Normalize finding payload to a dictionary.

    Accepts dict, JSON string, or empty/invalid values.

    Args:
        value: Value to normalize

    Returns:
        Dictionary representation
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _as_int_0_100(value: Any) -> Optional[int]:
    """Coerce an optional confidence-like value to an integer between 0 and 100.

    Args:
        value: Value to coerce

    Returns:
        Integer between 0-100, or None if value is None
    """
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, n))


def _payload_optional_str(payload: Dict[str, Any], *path: str) -> Optional[str]:
    """Get an optional non-empty nested string from payload path.

    Args:
        payload: Dictionary to traverse
        path: Sequence of keys to traverse

    Returns:
        Non-empty string, or None if not found or empty
    """
    cur: Any = payload
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    if cur is None:
        return None
    text = str(cur).strip()
    return text or None


def _payload_estimated_confidence(payload: Dict[str, Any]) -> Optional[int]:
    """Extract estimated confidence from canonical payload structure.

    Looks in payload.estimated.confidence

    Args:
        payload: Finding payload dictionary

    Returns:
        Confidence value (0-100) or None
    """
    est = payload.get("estimated")
    if not isinstance(est, dict):
        return None
    return _as_int_0_100(est.get("confidence"))


def _payload_pricing_source(payload: Dict[str, Any]) -> Optional[str]:
    """Extract pricing source when available in finding payload.

    Checks multiple possible paths for pricing source.

    Args:
        payload: Finding payload dictionary

    Returns:
        Pricing source string or None
    """
    from_estimated = (
        _payload_optional_str(payload, "estimated", "pricing_source")
        or _payload_optional_str(payload, "estimated", "price_source")
    )
    if from_estimated:
        return from_estimated

    from_dimensions = (
        _payload_optional_str(payload, "dimensions", "pricing_source")
        or _payload_optional_str(payload, "dimensions", "price_source")
    )
    if from_dimensions:
        return from_dimensions

    return None


def _payload_pricing_version(payload: Dict[str, Any]) -> Optional[str]:
    """Extract pricing version when available in finding payload.

    Args:
        payload: Finding payload dictionary

    Returns:
        Pricing version string or None
    """
    return (
        _payload_optional_str(payload, "estimated", "pricing_version")
        or _payload_optional_str(payload, "pricing_version")
    )


def _run_meta_pricing_source(run_meta: Dict[str, Any]) -> Optional[str]:
    """Extract pricing source from run metadata payload when available.

    Args:
        run_meta: Run metadata dictionary

    Returns:
        Pricing source string or None
    """
    return _payload_optional_str(run_meta, "pricing_source")


def _run_meta_pricing_version(run_meta: Dict[str, Any]) -> Optional[str]:
    """Extract pricing version from run metadata payload when available.

    Args:
        run_meta: Run metadata dictionary

    Returns:
        Pricing version string or None
    """
    return _payload_optional_str(run_meta, "pricing_version")
