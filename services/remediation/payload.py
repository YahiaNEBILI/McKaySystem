"""Payload normalization helpers for remediation APIs and workers."""

from __future__ import annotations

import json
from typing import Any


def normalize_action_payload(value: Any) -> dict[str, Any]:
    """Normalize remediation action payload to a dictionary.

    Args:
        value: Payload value from DB/API that may be a dict or JSON string.

    Returns:
        Normalized dictionary payload. Invalid/non-dict inputs return {}.
    """
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}
