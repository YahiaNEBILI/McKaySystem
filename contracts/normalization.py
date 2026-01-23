""" ensures that the structures exist (severity, scope, estimated, actual, source, etc.)

converts datetime / ISO string → ISO UTC ‘…Z’

converts money fields to decimal string

normalises maps (tags, labels, etc.) to dict[str,str]

fills in missing fields with ‘’ / {} / [] according to the contract """

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Mapping

# Reuse helpers from finops_contracts.py (or keep these local)
def _dt_to_utc_iso(value: Any) -> str:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return ""
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        txt = value.strip()
        if txt.endswith("Z"):
            return txt
        # Try parse basic ISO
        try:
            if txt.endswith("Z"):
                txt = txt[:-1] + "+00:00"
            dt = datetime.fromisoformat(txt)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            return ""
    return ""

def _to_str_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: Dict[str, str] = {}
    for k, v in value.items():
        if k is None:
            continue
        out[str(k)] = "" if v is None else str(v)
    return out

def _to_decimal_str(value: Any) -> str:
    """
    Normalize money/decimal fields to string:
    - "" if missing
    - Decimal/int/float/numeric str -> normalized string
    """
    if value is None:
        return ""
    if isinstance(value, str):
        txt = value.strip()
        if txt == "":
            return ""
        # keep as-is if looks numeric; optionally normalize via Decimal
        try:
            return str(Decimal(txt))
        except Exception:
            return ""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (int, float)):
        return str(Decimal(str(value)))
    return ""

def _ensure_dict(record: Dict[str, Any], key: str) -> Dict[str, Any]:
    val = record.get(key)
    if isinstance(val, dict):
        return val
    record[key] = {}
    return record[key]

def normalize_for_arrow(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make record safe for Arrow schema materialization:
    - ensure required structs exist
    - coerce timestamps and money fields
    - normalize maps/lists
    """
    # Top-level timestamps
    record["run_ts"] = _dt_to_utc_iso(record.get("run_ts"))
    record["ingested_ts"] = _dt_to_utc_iso(record.get("ingested_ts"))

    # Severity struct
    sev = _ensure_dict(record, "severity")
    sev.setdefault("level", "")
    sev.setdefault("score", 0)
    try:
        sev["score"] = int(sev.get("score") or 0)
    except (ValueError, TypeError):
        sev["score"] = 0

    # Scope struct
    scope = _ensure_dict(record, "scope")
    # Minimal keys you expect (fill missing)
    for k in (
        "cloud",
        "provider_partition",
        "organization_id",
        "billing_account_id",
        "account_id",
        "region",
        "availability_zone",
        "service",
        "resource_type",
        "resource_id",
        "resource_arn",
    ):
        scope.setdefault(k, "")

    # Estimated struct
    est = _ensure_dict(record, "estimated")
    est.setdefault("monthly_savings", "")
    est.setdefault("monthly_cost", "")
    est.setdefault("one_time_savings", "")
    est.setdefault("confidence", 0)
    est.setdefault("notes", "")
    est["monthly_savings"] = _to_decimal_str(est.get("monthly_savings"))
    est["monthly_cost"] = _to_decimal_str(est.get("monthly_cost"))
    est["one_time_savings"] = _to_decimal_str(est.get("one_time_savings"))
    try:
        est["confidence"] = int(est.get("confidence") or 0)
    except (ValueError, TypeError):
        est["confidence"] = 0

    # Actual struct
    act = _ensure_dict(record, "actual")
    for k in ("cost_7d", "cost_30d", "cost_mtd", "cost_prev_month", "savings_7d", "savings_30d"):
        act.setdefault(k, "")
        act[k] = _to_decimal_str(act.get(k))

    model = act.get("model")
    if not isinstance(model, dict):
        model = {}
        act["model"] = model
    model.setdefault("currency", "")
    model.setdefault("cost_model", "")
    model.setdefault("granularity", "")
    model.setdefault("period_start", "")  # keep as YYYY-MM-DD strings or dates; pick one convention
    model.setdefault("period_end", "")

    attribution = act.get("attribution")
    if not isinstance(attribution, dict):
        attribution = {}
        act["attribution"] = attribution
    attribution.setdefault("method", "")
    attribution.setdefault("confidence", 0)
    attribution.setdefault("matched_keys", [])
    try:
        attribution["confidence"] = int(attribution.get("confidence") or 0)
    except (ValueError, TypeError):
        attribution["confidence"] = 0
    if not isinstance(attribution.get("matched_keys"), list):
        attribution["matched_keys"] = []

    # Lifecycle struct
    life = _ensure_dict(record, "lifecycle")
    life.setdefault("status", "")
    for k in ("first_seen_ts", "last_seen_ts", "resolved_ts", "snooze_until_ts"):
        life.setdefault(k, "")
        life[k] = _dt_to_utc_iso(life.get(k))

    # Links list
    links = record.get("links")
    if not isinstance(links, list):
        record["links"] = []
    else:
        # ensure link items are dicts with label/url
        cleaned = []
        for item in links:
            if isinstance(item, dict):
                cleaned.append({"label": str(item.get("label", "")), "url": str(item.get("url", ""))})
        record["links"] = cleaned

    # Maps
    record["tags"] = _to_str_map(record.get("tags"))
    record["labels"] = _to_str_map(record.get("labels"))
    record["dimensions"] = _to_str_map(record.get("dimensions"))

    metrics = record.get("metrics")
    if not isinstance(metrics, Mapping):
        record["metrics"] = {}
    else:
        # normalize numeric metric values to decimal strings too (if you store MONEY in schema)
        norm_metrics: Dict[str, str] = {}
        for k, v in metrics.items():
            if k is None:
                continue
            norm_metrics[str(k)] = _to_decimal_str(v)
        record["metrics"] = norm_metrics

    # Source struct
    src = _ensure_dict(record, "source")
    src.setdefault("source_type", "")
    src.setdefault("source_ref", "")
    src.setdefault("schema_version", 1)
    try:
        src["schema_version"] = int(src.get("schema_version") or 1)
    except (ValueError, TypeError):
        src["schema_version"] = 1

    # Optional fields that should exist as strings
    for k in ("tenant_id", "workspace_id", "engine_name", "engine_version", "rulepack_version",
              "check_id", "check_name", "category", "sub_category", "status", "title",
              "message", "recommendation", "remediation", "metadata_json", "run_id"):
        if k not in record or record[k] is None:
            record[k] = ""
        elif not isinstance(record[k], str):
            record[k] = str(record[k])

    # Frameworks list
    if not isinstance(record.get("frameworks"), list):
        record["frameworks"] = []

    return record
