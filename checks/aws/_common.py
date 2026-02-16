"""Shared helpers for AWS checkers.

The checker layer tends to repeat a few patterns:
- normalize tags from multiple AWS shapes
- apply retention / suppression tag logic
- normalize timestamps to UTC
- extract region from boto3 clients or ARNs
- structured logging for debugging complex scenarios

Keeping these helpers in one place reduces duplication and makes behavior
consistent across checkers.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from contracts.finops_checker_pattern import Scope

# Logger name prefix for AWS checkers
_LOGGER_PREFIX = "mckay.checks.aws"


def get_logger(name: str) -> logging.Logger:
    """Get a logger for an AWS checker module.

    Args:
        name: The checker name (e.g., 'ec2_instances', 'ebs_storage').

    Returns:
        A configured logger instance.
    """
    return logging.getLogger(f"{_LOGGER_PREFIX}.{name}")


@dataclass(frozen=True)
class AwsAccountContext:
    """Account context injected into checkers.

    Most checkers only need an account_id; billing_account_id is kept to align
    with the broader contracts used by the pipeline.
    """

    account_id: str
    billing_account_id: str | None = None
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
    billing_account_id: str | None = None,
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


def utc(dt: datetime | None) -> datetime | None:
    """Return ``dt`` converted to timezone-aware UTC (or None)."""

    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def now_utc() -> datetime:
    """Return the current UTC timestamp."""

    return datetime.now(UTC)


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
    suppress_values: set[str] | frozenset[str] | None = None,
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
    params: dict[str, Any] | None = None,
    request_token_key: str = "NextToken",
    response_token_keys: Sequence[str] = ("NextToken",),
    paginator_fallback_exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Iterator[dict[str, Any]]:
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

    next_token: str | None = None
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
    call_exceptions: tuple[type[Exception], ...] = (Exception,),
) -> tuple[float | None, str]:
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


def pricing_quote_unit_price(quote: Any) -> float | None:
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
    attempts: Sequence[tuple[str, Sequence[Mapping[str, str]]]],
    call_exceptions: tuple[type[Exception], ...],
) -> tuple[float | None, Any]:
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


def percentile(values: Sequence[float], p: float, *, method: str = "linear") -> float | None:
    """Compute percentile from a sequence without external dependencies.

    Supported methods:
    - ``linear``: linear interpolation between neighboring points.
    - ``floor``: floor index selection (nearest-rank lower bound).
    - ``nearest``: nearest index selection (round to nearest rank).
    """
    numbers: list[float] = []
    for value in values:
        try:
            numbers.append(float(value))
        except (TypeError, ValueError):
            continue
    if not numbers:
        return None

    numbers.sort()
    if p <= 0.0:
        return numbers[0]
    if p >= 100.0:
        return numbers[-1]

    idx = (len(numbers) - 1) * (float(p) / 100.0)
    if method == "linear":
        floor_idx = int(idx)
        ceil_idx = min(floor_idx + 1, len(numbers) - 1)
        if floor_idx == ceil_idx:
            return numbers[floor_idx]
        return (numbers[floor_idx] * (ceil_idx - idx)) + (numbers[ceil_idx] * (idx - floor_idx))

    if method == "floor":
        floor_idx = int(idx)
        floor_idx = max(0, min(floor_idx, len(numbers) - 1))
        return numbers[floor_idx]

    if method == "nearest":
        near_idx = int(round(idx))
        near_idx = max(0, min(near_idx, len(numbers) - 1))
        return numbers[near_idx]

    raise ValueError(f"Unsupported percentile method: {method}")


class PricingResolver:
    """Best-effort pricing resolver used by AWS checkers."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def _pricing(self) -> Any:
        return pricing_service(self._ctx)

    def resolve_ec2_instance_monthly_cost(
        self,
        *,
        region: str,
        instance_type: str,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float | None, int, str]:
        """Resolve EC2 on-demand Linux/shared monthly cost."""
        pricing = self._pricing()
        if pricing is None:
            return None, 30, "pricing service not available"

        location = pricing_location_for_region(pricing, region)
        if not location:
            return None, 30, "pricing location unavailable"

        attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Compute Instance"},
                {"Field": "instanceType", "Value": instance_type},
                {"Field": "operatingSystem", "Value": "Linux"},
                {"Field": "tenancy", "Value": "Shared"},
                {"Field": "preInstalledSw", "Value": "NA"},
                {"Field": "capacitystatus", "Value": "Used"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "instanceType", "Value": instance_type},
                {"Field": "operatingSystem", "Value": "Linux"},
                {"Field": "tenancy", "Value": "Shared"},
            ],
        ]

        quote = None
        fn = getattr(pricing, "get_on_demand_unit_price", None)
        if not callable(fn):
            return None, 35, "no on-demand EC2 price match"
        for filters in attempts:
            try:
                quote = fn(service_code="AmazonEC2", filters=filters, unit="Hrs")
            except call_exceptions:
                quote = None
            if quote is not None:
                break

        if quote is None:
            return None, 35, "no on-demand EC2 price match"

        try:
            hourly = float(getattr(quote, "unit_price", None) or getattr(quote, "price", None) or 0.0)
        except (AttributeError, TypeError, ValueError):
            hourly = 0.0
        if hourly <= 0.0:
            return None, 35, "invalid on-demand EC2 unit price"

        return money(hourly * 730.0), 75, "on-demand Linux shared"

    def estimate_ebs_monthly_cost(
        self,
        *,
        size_gib: float,
        volume_type: str,
        fallback_prices: Mapping[str, float],
        default_price: float = 0.10,
    ) -> float:
        """Estimate EBS storage monthly cost from fallback pricing."""
        price = float(fallback_prices.get(str(volume_type or "gp2"), default_price))
        return money(float(size_gib) * price)

    def resolve_ebs_volume_storage_price(
        self,
        *,
        region: str,
        volume_type: str,
        fallback_prices: Mapping[str, float],
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve EBS volume storage unit price (GB-Mo)."""
        default_price = float(fallback_prices.get(str(volume_type or "gp2"), 0.10))
        pricing = self._pricing()
        if pricing is None:
            return default_price, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return default_price, "Pricing region mapping missing; using fallback pricing.", 30

        vt = str(volume_type or "gp2").strip().lower()
        usage_types: list[str]
        if vt == "gp2":
            usage_types = ["EBS:VolumeUsage.gp2", "EBS:VolumeUsage"]
        elif vt == "gp3":
            usage_types = ["EBS:VolumeUsage.gp3", "EBS:VolumeUsage"]
        elif vt in ("io1", "io2"):
            usage_types = ["EBS:VolumeUsage.piops", "EBS:VolumeUsage.io2", "EBS:VolumeUsage"]
        elif vt == "st1":
            usage_types = ["EBS:VolumeUsage.st1", "EBS:VolumeUsage"]
        elif vt == "sc1":
            usage_types = ["EBS:VolumeUsage.sc1", "EBS:VolumeUsage"]
        else:
            usage_types = ["EBS:VolumeUsage"]

        attempts = [
            (
                "GB-Mo",
                [
                    {"Field": "location", "Value": location},
                    {"Field": "productFamily", "Value": "Storage"},
                    {"Field": "usagetype", "Value": usage_type},
                ],
            )
            for usage_type in usage_types
        ]
        price, quote = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonEC2",
            attempts=attempts,
            call_exceptions=call_exceptions,
        )
        if price is not None and quote is not None:
            source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
            as_of = getattr(quote, "as_of", None)
            unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
            as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
            return (
                float(price),
                f"PricingService {source} as_of={as_of_txt} unit={unit}",
                60 if source == "cache" else 70,
            )

        return default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30

    def resolve_ebs_snapshot_storage_price(
        self,
        *,
        region: str,
        default_price: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve EBS snapshot storage unit price (GB-Mo)."""
        pricing = self._pricing()
        if pricing is None:
            return default_price, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return default_price, "Pricing region mapping missing; using fallback pricing.", 30

        price, quote = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonEC2",
            attempts=(
                (
                    "GB-Mo",
                    [
                        {"Field": "location", "Value": location},
                        {"Field": "productFamily", "Value": "Storage"},
                        {"Field": "usagetype", "Value": "EBS:SnapshotUsage"},
                    ],
                ),
            ),
            call_exceptions=call_exceptions,
        )
        if price is not None and quote is not None:
            source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
            as_of = getattr(quote, "as_of", None)
            unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
            as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
            return (
                float(price),
                f"PricingService {source} as_of={as_of_txt} unit={unit}",
                60 if source == "cache" else 70,
            )

        return default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30

    def resolve_rds_instance_hour_price(
        self,
        *,
        region: str,
        db_instance_class: str,
        deployment_option: str,
        engine: str,
        license_model: str,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float | None, str, int]:
        """Resolve RDS on-demand hourly instance price."""
        pricing = self._pricing()
        if pricing is None:
            return None, "PricingService unavailable; leaving instance pricing unknown.", 20

        fn = getattr(pricing, "rds_instance_hour", None)
        if not callable(fn):
            return None, "Pricing lookup failed/unknown; leaving instance pricing unknown.", 20

        try:
            quote = fn(
                region=region,
                db_instance_class=db_instance_class,
                deployment_option=deployment_option,
                database_engine=engine or None,
                license_model=license_model or None,
            )
        except call_exceptions:
            quote = None

        if quote is None:
            return None, "Pricing lookup failed/unknown; leaving instance pricing unknown.", 20

        conf = 70 if str(getattr(quote, "source", "")) == "pricing_api" else 60
        return (
            float(quote.unit_price_usd),
            f"PricingService {quote.source} as_of={quote.as_of.isoformat()} unit={quote.unit}",
            conf,
        )

    def resolve_nat_pricing(
        self,
        *,
        region: str,
        fallback_hourly_usd: float,
        fallback_data_usd_per_gb: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, float, str, int]:
        """Resolve NAT gateway hourly and per-GB processing prices."""
        pricing = self._pricing()
        if pricing is None:
            return fallback_hourly_usd, fallback_data_usd_per_gb, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return fallback_hourly_usd, fallback_data_usd_per_gb, "Pricing region mapping missing; using fallback pricing.", 30

        notes: list[str] = []
        hourly_attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "NAT Gateway"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "usagetype", "Value": "NatGateway-Hours"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "group", "Value": "NAT Gateway"},
            ],
        ]
        hourly, _ = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonEC2",
            attempts=[("Hrs", filters) for filters in hourly_attempts],
            call_exceptions=call_exceptions,
        )
        if hourly and hourly > 0.0:
            notes.append("on-demand hourly price resolved via PricingService")

        data_attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "usagetype", "Value": "NatGateway-Bytes"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "group", "Value": "NAT Gateway"},
                {"Field": "operation", "Value": "DataProcessing"},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "NAT Gateway"},
                {"Field": "operation", "Value": "DataProcessing"},
            ],
        ]
        per_gb, _ = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonEC2",
            attempts=[("GB", filters) for filters in data_attempts],
            call_exceptions=call_exceptions,
        )
        if per_gb and per_gb > 0.0:
            notes.append("on-demand data processing price resolved via PricingService")

        final_hourly = float(hourly if hourly and hourly > 0.0 else fallback_hourly_usd)
        final_per_gb = float(per_gb if per_gb and per_gb > 0.0 else fallback_data_usd_per_gb)
        confidence = 75 if hourly and per_gb else 55 if (hourly or per_gb) else 30
        if not notes:
            notes.append("using fallback pricing")
        return final_hourly, final_per_gb, "; ".join(notes), confidence

    def resolve_elb_hourly_price(
        self,
        *,
        region: str,
        lb_type: str,
        fallback_alb_hourly_usd: float,
        fallback_nlb_hourly_usd: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve ALB/NLB hourly price."""
        fallback = fallback_alb_hourly_usd if lb_type == "application" else fallback_nlb_hourly_usd
        pricing = self._pricing()
        if pricing is None:
            return fallback, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return fallback, "Pricing region mapping missing; using fallback pricing.", 30

        attempts: list[list[dict[str, str]]]
        if lb_type == "application":
            attempts = [
                [
                    {"Field": "location", "Value": location},
                    {"Field": "productFamily", "Value": "Load Balancer"},
                    {"Field": "group", "Value": "Application Load Balancer"},
                ],
                [
                    {"Field": "location", "Value": location},
                    {"Field": "usagetype", "Value": "LoadBalancerUsage"},
                ],
            ]
        else:
            attempts = [
                [
                    {"Field": "location", "Value": location},
                    {"Field": "productFamily", "Value": "Load Balancer"},
                    {"Field": "group", "Value": "Network Load Balancer"},
                ],
                [
                    {"Field": "location", "Value": location},
                    {"Field": "usagetype", "Value": "NetworkLoadBalancerUsage"},
                ],
            ]

        hourly, _ = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonEC2",
            attempts=[("Hrs", filters) for filters in attempts],
            call_exceptions=call_exceptions,
        )
        if hourly and hourly > 0.0:
            return float(hourly), "on-demand hourly price resolved via PricingService", 60

        return float(fallback), "using fallback pricing", 30

    def resolve_s3_storage_price(
        self,
        *,
        region: str,
        pricing_storage_class: str,
        fallback_usd_per_gb_month: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int, str]:
        """Resolve S3 storage unit price (GB-Mo)."""
        fallback = (
            float(fallback_usd_per_gb_month),
            f"Fallback pricing used (no PricingService quote) for {pricing_storage_class}.",
            55,
            "fallback",
        )

        pricing = self._pricing()
        if pricing is None:
            return fallback

        location = pricing_location_for_region(pricing, region)
        if not location:
            return fallback

        attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "storageClass", "Value": pricing_storage_class},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "volumeType", "Value": pricing_storage_class},
            ],
        ]
        fn = getattr(pricing, "get_on_demand_unit_price", None)
        if not callable(fn):
            return fallback

        for filters in attempts:
            try:
                quote = fn(service_code="AmazonS3", filters=filters, unit="GB-Mo")
            except call_exceptions:
                quote = None
            if quote is None:
                continue
            try:
                unit_price = float(getattr(quote, "unit_price_usd", fallback_usd_per_gb_month))
            except (AttributeError, TypeError, ValueError):
                continue
            if unit_price <= 0.0:
                continue
            source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
            return (
                unit_price,
                f"PricingService quote for S3 {pricing_storage_class} in {location} ({source}).",
                80,
                source,
            )
        return fallback

    def resolve_fsx_storage_price(
        self,
        *,
        region: str,
        fs_type: str,
        storage_type: str,
        default_price: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve FSx storage unit price (GB-Mo)."""
        pricing = self._pricing()
        if pricing is None:
            return default_price, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return default_price, "Pricing region mapping missing; using fallback pricing.", 30

        attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
                {"Field": "storageType", "Value": str(storage_type).upper()},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "File System Storage"},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
            ],
        ]

        price, quote = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonFSx",
            attempts=[("GB-Mo", filters) for filters in attempts],
            call_exceptions=call_exceptions,
        )
        if price is not None and quote is not None:
            source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
            as_of = getattr(quote, "as_of", None)
            unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
            as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
            return (
                float(price),
                f"PricingService {source} as_of={as_of_txt} unit={unit}",
                60 if source == "cache" else 70,
            )

        return default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30

    def resolve_fsx_throughput_price(
        self,
        *,
        region: str,
        fs_type: str,
        default_price: float,
        units: Sequence[str],
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve FSx throughput unit price (MBps-Mo style units)."""
        if default_price <= 0.0:
            return 0.0, "No throughput fallback for this FSx type; leaving throughput estimate as 0.", 20

        pricing = self._pricing()
        if pricing is None:
            return default_price, "PricingService unavailable; using fallback pricing.", 30

        location = pricing_location_for_region(pricing, region)
        if not location:
            return default_price, "Pricing region mapping missing; using fallback pricing.", 30

        attempts: list[list[dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Provisioned Throughput"},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "System Operation"},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "fileSystemType", "Value": str(fs_type).upper()},
            ],
        ]
        attempt_units = [(unit, filters) for unit in units for filters in attempts]
        price, quote = pricing_on_demand_first_positive(
            pricing,
            service_code="AmazonFSx",
            attempts=attempt_units,
            call_exceptions=call_exceptions,
        )
        if price is not None and quote is not None:
            source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
            as_of = getattr(quote, "as_of", None)
            unit = str(getattr(quote, "unit", "MBps-Mo") or "MBps-Mo")
            as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
            return (
                float(price),
                f"PricingService {source} as_of={as_of_txt} unit={unit}",
                60 if source == "cache" else 70,
            )

        return default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30

    def resolve_rds_snapshot_storage_price(
        self,
        *,
        region: str,
        default_price: float,
        call_exceptions: tuple[type[Exception], ...],
    ) -> tuple[float, str, int]:
        """Resolve RDS snapshot storage unit price (GB-Mo)."""
        pricing = self._pricing()
        if pricing is None:
            return default_price, "PricingService unavailable; using default price.", 30

        fn = getattr(pricing, "rds_backup_storage_gb_month", None)
        if not callable(fn):
            return default_price, "Pricing lookup failed/unknown; using default price.", 30

        try:
            quote = fn(region=region)
        except call_exceptions:
            quote = None
        if quote is None:
            return default_price, "Pricing lookup failed/unknown; using default price.", 30

        try:
            price = float(quote.unit_price_usd)
        except (AttributeError, TypeError, ValueError):
            return default_price, "Pricing lookup failed/unknown; using default price.", 30

        source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
        as_of = getattr(quote, "as_of", None)
        unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
        as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
        return (
            price,
            f"PricingService {source} as_of={as_of_txt} unit={unit}",
            60 if source == "cache" else 70,
        )

    def resolve_backup_storage_price(
        self,
        *,
        region: str,
        storage_class: str,
        fallback_usd: float,
        method_names: Sequence[str],
        kwargs_variants: Sequence[Mapping[str, Any]],
        args_variants: Sequence[Sequence[Any]],
        resolved_confidence: int,
        fallback_confidence_when_no_service: int,
        fallback_confidence_when_lookup_fails: int,
        no_service_note: str,
        lookup_failed_note: str,
        resolved_note_template: str,
    ) -> tuple[float, str, int]:
        """Resolve AWS Backup storage unit price (GB-Mo)."""
        pricing = self._pricing()
        if pricing is None:
            return float(fallback_usd), no_service_note, int(fallback_confidence_when_no_service)

        normalized = str(storage_class or "").strip().lower()
        tier = "cold" if normalized in {"cold", "cold_storage", "coldstorage"} else "warm"

        rendered_kwargs = []
        for kwargs in kwargs_variants:
            rendered_kwargs.append(
                {
                    k: (tier if v == "{tier}" else storage_class if v == "{storage_class}" else region if v == "{region}" else v)
                    for k, v in kwargs.items()
                }
            )
        rendered_args: list[tuple[Any, ...]] = []
        for args in args_variants:
            rendered_args.append(
                tuple(tier if a == "{tier}" else storage_class if a == "{storage_class}" else region if a == "{region}" else a for a in args)
            )

        unit_price, method_name = pricing_first_positive(
            pricing,
            method_names=method_names,
            kwargs_variants=tuple(rendered_kwargs),
            args_variants=tuple(rendered_args),
        )
        if unit_price is None:
            return float(fallback_usd), lookup_failed_note, int(fallback_confidence_when_lookup_fails)
        return float(unit_price), resolved_note_template.format(method_name=method_name, tier=tier), int(resolved_confidence)
