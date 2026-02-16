"""Flask API utilities package.

This package contains shared utilities for the Flask API, organized into focused modules:
- responses: Standardized HTTP response helpers
- params: Query and payload parameter parsing
- payload: Payload extraction and transformation helpers
- db_utils: Database and state management helpers (when needed)
- openapi: OpenAPI specification generation
"""

# Re-export commonly used functions for convenience
from apps.flask_api.utils.params import (
    _MISSING,
    _coerce_non_negative_int,
    _coerce_optional_float,
    _coerce_optional_text,
    _coerce_positive_int,
    _coerce_text_list,
    _parse_csv_list,
    _parse_int,
    _parse_iso8601_dt,
    _payload_optional_text,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
    _safe_scope_from_request,
)
from apps.flask_api.utils.payload import (
    _as_float,
    _as_int_0_100,
    _payload_dict,
    _payload_estimated_confidence,
    _payload_optional_str,
    _payload_pricing_source,
    _payload_pricing_version,
    _run_meta_pricing_source,
    _run_meta_pricing_version,
)
from apps.flask_api.utils.responses import _err, _json, _ok

__all__ = [
    # responses
    "_ok",
    "_err",
    "_json",
    # params
    "_q",
    "_require_scope_from_query",
    "_require_scope_from_json",
    "_parse_int",
    "_parse_csv_list",
    "_parse_iso8601_dt",
    "_coerce_optional_text",
    "_payload_optional_text",
    "_coerce_positive_int",
    "_safe_scope_from_request",
    "_coerce_non_negative_int",
    "_coerce_optional_float",
    "_coerce_text_list",
    "_MISSING",
    # payload
    "_as_float",
    "_payload_dict",
    "_as_int_0_100",
    "_payload_optional_str",
    "_payload_estimated_confidence",
    "_payload_pricing_source",
    "_payload_pricing_version",
    "_run_meta_pricing_source",
    "_run_meta_pricing_version",
]
