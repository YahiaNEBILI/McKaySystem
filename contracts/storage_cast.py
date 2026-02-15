"""Casting helpers from wire-format findings to Arrow/storage format.

The storage boundary is intentionally strict: any schema/type mismatch should be
surfaced early (tests/CI) rather than silently drifting.
"""

# finops/contracts/storage_cast.py
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

import pyarrow as pa


class StorageCastError(ValueError):
    """Raised when a wire record cannot be cast to the Arrow storage schema."""


def _parse_datetime_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        txt = value.strip()
        if txt == "":
            return None
        try:
            if txt.endswith("Z"):
                txt = txt[:-1] + "+00:00"
            dt = datetime.fromisoformat(txt)
        except ValueError:
            return None
        dt = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    return None


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, str):
        txt = value.strip()
        if txt == "":
            return None
        try:
            return date.fromisoformat(txt)
        except ValueError:
            return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    return None


def _parse_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, str):
        txt = value.strip()
        if txt == "":
            return None
        try:
            return Decimal(txt)
        except InvalidOperation:
            return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    return None


def _empty_to_none_if_needed(value: Any, field_type: pa.DataType) -> Any:
    # For non-string fields, "" should become None
    if isinstance(value, str) and value == "":
        if pa.types.is_string(field_type) or pa.types.is_large_string(field_type):
            return value
        return None
    return value


def cast_value(value: Any, field_type: pa.DataType) -> Any:
    """
    Cast a single value to match an Arrow field type.
    Returns Python values suitable for pa.Table.from_pylist(..., schema=...).
    """
    value = _empty_to_none_if_needed(value, field_type)
    if value is None:
        return None

    # Strings
    if pa.types.is_string(field_type) or pa.types.is_large_string(field_type):
        return str(value)

    # Boolean
    if pa.types.is_boolean(field_type):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int,)):
            return bool(value)
        if isinstance(value, str):
            txt = value.strip().lower()
            if txt in ("true", "1", "yes", "y"):
                return True
            if txt in ("false", "0", "no", "n"):
                return False
        raise StorageCastError(f"Cannot cast {value!r} to bool")

    # Integers
    if pa.types.is_integer(field_type):
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise StorageCastError(f"Cannot cast {value!r} to int") from exc

    # Decimal
    if pa.types.is_decimal(field_type):
        dec = _parse_decimal(value)
        if dec is None:
            raise StorageCastError(f"Cannot cast {value!r} to Decimal")
        return dec

    # Timestamp (tz-aware)
    if pa.types.is_timestamp(field_type):
        dt = _parse_datetime_utc(value)
        if dt is None:
            raise StorageCastError(f"Cannot cast {value!r} to datetime")
        # Ensure tz is UTC for consistency
        return dt.astimezone(UTC)

    # Date32/Date64
    if pa.types.is_date(field_type):
        d = _parse_date(value)
        if d is None:
            raise StorageCastError(f"Cannot cast {value!r} to date")
        return d

    # Struct
    if pa.types.is_struct(field_type):
        if not isinstance(value, Mapping):
            raise StorageCastError(f"Cannot cast {value!r} to struct")
        out: dict[str, Any] = {}
        for subfield in field_type:
            out[subfield.name] = cast_value(value.get(subfield.name), subfield.type)
        return out

    # List
    if pa.types.is_list(field_type) or pa.types.is_large_list(field_type):
        if value is None:
            return None
        if not isinstance(value, list):
            raise StorageCastError(f"Cannot cast {value!r} to list")
        item_type = field_type.value_type
        return [cast_value(v, item_type) for v in value]

    # Map
    if pa.types.is_map(field_type):
        if not isinstance(value, Mapping):
            # Accept list of pairs? keep it simple: mapping only
            raise StorageCastError(f"Cannot cast {value!r} to map")
        key_type = field_type.key_type
        item_type = field_type.item_type
        out_map: dict[Any, Any] = {}
        for k, v in value.items():
            ck = cast_value(k, key_type)
            cv = cast_value(v, item_type)
            out_map[ck] = cv
        return out_map

    # Fallback: allow if it's already compatible; else stringify is dangerous
    return value


def cast_for_storage(wire_record: Mapping[str, Any], schema: pa.Schema) -> dict[str, Any]:
    """
    Cast a wire-format record into a storage-format record that matches the given Arrow schema.
    Unknown fields are ignored (schema is the contract for storage).
    Missing fields are set to None (or nested None) as appropriate.
    """
    out: dict[str, Any] = {}
    for field in schema:
        out[field.name] = cast_value(wire_record.get(field.name), field.type)
    return out
