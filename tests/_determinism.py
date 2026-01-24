# tests/_determinism.py
from __future__ import annotations

import hashlib
import json
import random
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Iterable, Mapping, Sequence


_VOLATILE_KEYS = {
    # These are expected to differ across runs unless you pin run_id/run_ts
    "run_id",
    "run_ts",
    "ingested_ts",
    "created_at",
    "updated_at",
    # Depending on your pipeline, these may contain temp file paths, etc.
    "source_ref",
    "source_ref_path",
}


def shuffled(seq: Sequence[Any], *, seed: int = 12345) -> list[Any]:
    """
    Return a deterministically shuffled copy of seq.
    """
    out = list(seq)
    rng = random.Random(seed)
    rng.shuffle(out)
    return out


def _to_jsonable(v: Any) -> Any:
    """
    Convert common non-JSON types to a stable JSON-friendly representation.
    """
    if v is None or isinstance(v, (bool, int, float, str)):
        return v

    # datetimes: normalize to UTC ISO-8601 with Z
    if isinstance(v, datetime):
        dt = v.astimezone(timezone.utc) if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    if isinstance(v, date):
        return v.isoformat()

    if isinstance(v, Decimal):
        # Deterministic string representation
        return format(v, "f")

    if isinstance(v, bytes):
        # Stable, readable representation (avoid base64 dependency)
        return v.hex()

    if isinstance(v, (list, tuple)):
        return [_to_jsonable(x) for x in v]

    if isinstance(v, dict):
        return {str(k): _to_jsonable(val) for k, val in v.items()}

    # Fallback: stable string conversion
    return str(v)


def canonical_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    drop_keys: set[str] | None = None,
    sort_keys: Sequence[str] = ("fingerprint", "finding_id", "check_id", "rule_id"),
) -> list[dict[str, Any]]:
    """
    Canonicalize row dictionaries so that:
      - volatile fields can be dropped
      - dict ordering is stable
      - row ordering is stable
      - values are JSON-serializable in a stable way
    """
    drop = set(_VOLATILE_KEYS)
    if drop_keys:
        drop |= set(drop_keys)

    canon: list[dict[str, Any]] = []
    for r in rows:
        d: dict[str, Any] = {}
        for k in sorted(r.keys()):
            if k in drop:
                continue
            d[k] = _to_jsonable(r.get(k))
        canon.append(d)

    def _row_sort_key(dct: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple(dct.get(k, "") for k in sort_keys) + tuple(
            # tie-breaker across other fields to keep deterministic ordering
            (k, dct.get(k, "")) for k in sorted(dct.keys())
        )

    canon.sort(key=_row_sort_key)
    return canon


def canonical_hash(
    rows: Iterable[Mapping[str, Any]],
    *,
    drop_keys: set[str] | None = None,
    sort_keys: Sequence[str] = ("fingerprint", "finding_id", "check_id", "rule_id"),
) -> str:
    """
    Hash the *logical content* of rows (not parquet bytes).
    This avoids false nondeterminism from parquet writer metadata/encoding.
    """
    canon = canonical_rows(rows, drop_keys=drop_keys, sort_keys=sort_keys)
    payload = json.dumps(canon, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
