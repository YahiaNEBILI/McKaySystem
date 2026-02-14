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
from typing import Any, Dict, Iterator, Mapping, MutableMapping, Optional, Sequence, Tuple

from contracts.finops_checker_pattern import Scope


@dataclass(frozen=True)
class AwsAccountContext:
    """Account context injected into checkers.

    Most checkers only need an account_id; billing_account_id is kept to align
    with the broader contracts used by the pipeline.
    """

    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def build_scope(
    ctx: Any,
    *,
    account: AwsAccountContext,
    region: str,
    service: str,
    resource_type: str = "",
    resource_id: str = "",
    resource_arn: str = "",
    billing_account_id: Optional[str] = None,
    availability_zone: str = "",
    organization_id: str = "",
) -> Scope:
    """Build a consistent :class:`~contracts.finops_checker_pattern.Scope`.

    Checkers should avoid hand-building Scope objects to keep identity stable
    across the codebase and to ensure CUR enrichment has consistent keys.
    """

    cloud = str(getattr(ctx, "cloud", "") or "aws")
    billing = str(billing_account_id or account.billing_account_id or account.account_id or "")
    return Scope(
        cloud=cloud,
        provider_partition=str(account.partition or ""),
        organization_id=str(organization_id or ""),
        billing_account_id=billing,
        account_id=str(account.account_id or ""),
        region=str(region or ""),
        availability_zone=str(availability_zone or ""),
        service=str(service or ""),
        resource_type=str(resource_type or ""),
        resource_id=str(resource_id or ""),
        resource_arn=str(resource_arn or ""),
    )


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


def paginate_items(
    client: Any,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    request_token_key: str = "NextToken",
    response_token_keys: Sequence[str] = ("NextToken",),
    paginator_fallback_exceptions: Tuple[type[Exception], ...] = (Exception,),
) -> Iterator[Dict[str, Any]]:
    """Yield dict items from paginator when available, else token-loop fallback.

    This keeps checker pagination behavior deterministic while still supporting
    unit-test fakes/mocks that do not fully implement boto3 paginators.
    """
    params = dict(params or {})

    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**params):
                for item in page.get(result_key, []) or []:
                    if isinstance(item, dict):
                        yield item
            return
        except paginator_fallback_exceptions:
            pass

    call = getattr(client, operation, None)
    if call is None:
        raise AttributeError(f"client has no operation {operation}")

    next_token: Optional[str] = None
    while True:
        req = dict(params)
        if next_token:
            req[request_token_key] = next_token
        resp = call(**req) if req else call()
        for item in resp.get(result_key, []) or []:
            if isinstance(item, dict):
                yield item

        next_token = None
        for key in response_token_keys:
            token = resp.get(key)
            if token:
                next_token = str(token)
                break
        if not next_token:
            break


def pricing_service(ctx: Any) -> Any:
    """Return PricingService from RunContext-like objects, else None."""
    return getattr(getattr(ctx, "services", None), "pricing", None)


def pricing_first_positive(
    pricing: Any,
    *,
    method_names: Sequence[str],
    kwargs_variants: Sequence[Mapping[str, Any]] = (),
    args_variants: Sequence[Sequence[Any]] = (),
    call_exceptions: Tuple[type[Exception], ...] = (Exception,),
) -> Tuple[Optional[float], str]:
    """Return first strictly-positive pricing value and method name.

    This helper is intentionally best-effort: it tries multiple method names and
    call signatures and returns ``(None, "")`` when no positive price is found.
    """
    if pricing is None:
        return None, ""

    for method_name in method_names:
        fn = getattr(pricing, method_name, None)
        if not callable(fn):
            continue

        for kwargs in kwargs_variants:
            try:
                value = fn(**dict(kwargs))
            except call_exceptions:
                continue
            try:
                price = float(value)
            except (TypeError, ValueError):
                continue
            if price > 0.0:
                return price, method_name

        for args in args_variants:
            try:
                value = fn(*tuple(args))
            except call_exceptions:
                continue
            try:
                price = float(value)
            except (TypeError, ValueError):
                continue
            if price > 0.0:
                return price, method_name

    return None, ""


def pricing_location_for_region(pricing: Any, region: str) -> str:
    """Return pricing location for a region, or empty string on failure."""
    if pricing is None:
        return ""
    fn = getattr(pricing, "location_for_region", None)
    if not callable(fn):
        return ""
    try:
        return str(fn(region) or "")
    except (AttributeError, TypeError, ValueError):
        return ""


def pricing_quote_unit_price(quote: Any) -> Optional[float]:
    """Extract a positive unit price from a quote-like object."""
    if quote is None:
        return None
    for attr in ("unit_price_usd", "unit_price", "price"):
        try:
            raw = getattr(quote, attr, None)
            if raw is None:
                continue
            value = float(raw)
        except (AttributeError, TypeError, ValueError):
            continue
        if value > 0.0:
            return value
    return None


def pricing_on_demand_first_positive(
    pricing: Any,
    *,
    service_code: str,
    attempts: Sequence[Tuple[str, Sequence[Mapping[str, str]]]],
    call_exceptions: Tuple[type[Exception], ...],
) -> Tuple[Optional[float], Any]:
    """Return first positive on-demand quote price for (unit, filters) attempts.

    Returns ``(price, quote)`` where ``quote`` is the raw quote object. If no
    match is found, returns ``(None, None)``.
    """
    if pricing is None:
        return None, None
    fn = getattr(pricing, "get_on_demand_unit_price", None)
    if not callable(fn):
        return None, None

    for unit, filters in attempts:
        try:
            quote = fn(service_code=service_code, filters=list(filters), unit=unit)
        except call_exceptions:
            continue
        price = pricing_quote_unit_price(quote)
        if price is not None and price > 0.0:
            return float(price), quote

    return None, None
