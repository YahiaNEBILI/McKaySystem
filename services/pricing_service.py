"""
services/pricing_service.py

AWS Pricing Service (cached, safe, shared)
==========================================

Goals:
- Provide a single PricingService usable by all checkers
- Avoid per-resource Pricing API calls (slow) via caching/memoization
- Be resilient: if Pricing API fails or mapping is missing, return None
- Keep interface small, composable, and deterministic

Notes:
- AWS Pricing is a global service; in AWS commercial partition it is typically accessed
  via us-east-1. (Gov/China partitions differ; we handle as best-effort.)
- Pricing filters require "location" like "EU (Paris)", not region code "eu-west-3".
  We ship a mapping for common regions. Unknown regions => None.

Minimal IAM permission:
- pricing:GetProducts
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from botocore.exceptions import BotoCoreError, ClientError


# -------------------------
# Region -> "location" mapping (commercial partition)
# Extend as needed.
# -------------------------
_REGION_TO_LOCATION: Dict[str, str] = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "sa-east-1": "South America (São Paulo)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-central-2": "EU (Zurich)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "eu-south-2": "EU (Spain)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "af-south-1": "Africa (Cape Town)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def _json_dumps_stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class PriceQuote:
    """
    Represents a single resolved unit price quote.

    - unit_price_usd: e.g. 0.1234
    - unit: e.g. "Hrs", "GB-Mo"
    - source: "pricing_api" or "cache"
    - as_of: timestamp for cache freshness
    """
    unit_price_usd: float
    unit: str
    source: str
    as_of: datetime


class PricingCache:
    """
    A small JSON cache storing resolved prices by key.

    File format:
      {
        "version": 1,
        "items": {
          "<key>": {"value": 0.1234, "unit": "Hrs", "ts": "2026-01-24T12:34:56Z"}
        }
      }
    """

    def __init__(self, *, path: Path, ttl: timedelta) -> None:
        self._path = path
        self._ttl = ttl
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            items = raw.get("items", {})
            if isinstance(items, dict):
                self._mem = items
        except Exception:
            # Cache is optional; ignore corrupt files.
            self._mem = {}

    def get(self, key: str) -> Optional[PriceQuote]:
        self._load()
        item = self._mem.get(key)
        if not isinstance(item, dict):
            return None

        ts = item.get("ts")
        unit = str(item.get("unit") or "")
        val = _safe_float(item.get("value"))
        if val is None or not unit or not ts:
            return None

        try:
            as_of = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return None

        if _utc_now() - as_of > self._ttl:
            return None

        return PriceQuote(unit_price_usd=val, unit=unit, source="cache", as_of=as_of)

    def put(self, key: str, quote: PriceQuote) -> None:
        self._load()
        self._mem[key] = {
            "value": quote.unit_price_usd,
            "unit": quote.unit,
            "ts": quote.as_of.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self._flush_best_effort()

    def _flush_best_effort(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1, "items": self._mem}
            self._path.write_text(_json_dumps_stable(payload), encoding="utf-8")
        except Exception:
            # Optional cache: ignore write issues (read-only fs, permissions, etc.)
            return


class PricingService:
    """
    Shared service that resolves AWS public on-demand prices using Pricing API.

    Designed to be injected into Services and reused by all checkers.

    The primary method is:
      get_on_demand_unit_price(service_code, filters, unit)

    Convenience methods exist for common FinOps checks.
    """

    def __init__(
        self,
        *,
        pricing_client: Any,
        cache: Optional[PricingCache] = None,
        partition: str = "aws",
    ) -> None:
        self._client = pricing_client
        self._cache = cache
        self._partition = partition
        self._memo: Dict[str, PriceQuote] = {}

    # -------------------------
    # Public helpers
    # -------------------------

    def location_for_region(self, region: str) -> Optional[str]:
        return _REGION_TO_LOCATION.get(str(region or "").strip())

    def get_on_demand_unit_price(
        self,
        *,
        service_code: str,
        filters: Sequence[Mapping[str, str]],
        unit: str,
    ) -> Optional[PriceQuote]:
        """
        Return a PriceQuote for the given AWS Pricing query.

        `filters` is a sequence of dicts: {"Field": "...", "Value": "..."}.
        All filters are applied as TERM_MATCH.

        `unit` is expected unit from the price dimensions (e.g., "Hrs", "GB-Mo").
        """
        normalized_filters = [
            {"Field": str(f.get("Field") or ""), "Value": str(f.get("Value") or "")}
            for f in filters
            if str(f.get("Field") or "") and str(f.get("Value") or "")
        ]
        key_payload = {
            "partition": self._partition,
            "service_code": service_code,
            "unit": unit,
            "filters": sorted(normalized_filters, key=lambda x: (x["Field"], x["Value"])),
        }
        cache_key = _sha1(_json_dumps_stable(key_payload))

        # in-run memo
        memo = self._memo.get(cache_key)
        if memo is not None:
            return memo

        # disk cache
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._memo[cache_key] = cached
                return cached

        # pricing API
        try:
            api_quote = self._fetch_from_pricing_api(
                service_code=service_code,
                filters=normalized_filters,
                unit=unit,
            )
        except (ClientError, BotoCoreError, ValueError):
            return None

        if api_quote is None:
            return None

        self._memo[cache_key] = api_quote
        if self._cache is not None:
            self._cache.put(cache_key, api_quote)
        return api_quote

    # -------------------------
    # Convenience methods (start small; add more as you need)
    # -------------------------

    def rds_instance_hour(
        self,
        *,
        region: str,
        db_instance_class: str,
        deployment_option: str = "Single-AZ",
        database_engine: Optional[str] = None,
        license_model: Optional[str] = None,
    ) -> Optional[PriceQuote]:
        """
        Best-effort RDS on-demand instance hourly price.

        db_instance_class example: "db.t3.medium"
        Pricing API usually expects instanceType like "t3.medium".
        """
        location = self.location_for_region(region)
        if not location:
            return None

        instance_type = str(db_instance_class or "").strip()
        if instance_type.startswith("db."):
            instance_type = instance_type[3:]

        filters: List[Dict[str, str]] = [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "Database Instance"},
            {"Field": "instanceType", "Value": instance_type},
            {"Field": "deploymentOption", "Value": deployment_option},
        ]
        if database_engine:
            filters.append({"Field": "databaseEngine", "Value": str(database_engine)})
        if license_model:
            filters.append({"Field": "licenseModel", "Value": str(license_model)})

        return self.get_on_demand_unit_price(
            service_code="AmazonRDS",
            filters=filters,
            unit="Hrs",
        )

    def ec2_instance_hour(
        self,
        *,
        region: str,
        instance_type: str,
        operating_system: str = "Linux",
        tenancy: str = "Shared",
        capacitystatus: str = "Used",
        preinstalled_sw: str = "NA",
    ) -> Optional[PriceQuote]:
        """
        Best-effort EC2 on-demand hourly price for common right-sizing checks.
        """
        location = self.location_for_region(region)
        if not location:
            return None

        filters: List[Dict[str, str]] = [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "Compute Instance"},
            {"Field": "instanceType", "Value": str(instance_type)},
            {"Field": "operatingSystem", "Value": operating_system},
            {"Field": "tenancy", "Value": tenancy},
            {"Field": "capacitystatus", "Value": capacitystatus},
            {"Field": "preInstalledSw", "Value": preinstalled_sw},
        ]
        return self.get_on_demand_unit_price(
            service_code="AmazonEC2",
            filters=filters,
            unit="Hrs",
        )

    # -------------------------
    # Internal: pricing parsing
    # -------------------------

    def _fetch_from_pricing_api(
        self,
        *,
        service_code: str,
        filters: Sequence[Mapping[str, str]],
        unit: str,
    ) -> Optional[PriceQuote]:
        """
        Calls Pricing:GetProducts, parses first matching on-demand unit price for `unit`.
        """
        api_filters = [
            {"Type": "TERM_MATCH", "Field": str(f["Field"]), "Value": str(f["Value"])}
            for f in filters
        ]

        # Pricing API can return large pages; we only need the first usable product.
        next_token: Optional[str] = None
        for _ in range(0, 5):  # safety limit
            kwargs: Dict[str, Any] = {
                "ServiceCode": service_code,
                "Filters": api_filters,
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = self._client.get_products(**kwargs)
            price_list = resp.get("PriceList", []) or []
            for item in price_list:
                quote = self._parse_price_item(item, expected_unit=unit)
                if quote is not None:
                    return quote

            next_token = resp.get("NextToken")
            if not next_token:
                break

        return None

    def _parse_price_item(self, item: Any, *, expected_unit: str) -> Optional[PriceQuote]:
        """
        Parse Pricing API PriceList entry (JSON string or dict).
        We look for an OnDemand term and a price dimension matching expected_unit.
        """
        if isinstance(item, str):
            try:
                data = json.loads(item)
            except json.JSONDecodeError:
                return None
        elif isinstance(item, dict):
            data = item
        else:
            return None

        terms = data.get("terms", {})
        ondemand = terms.get("OnDemand", {}) if isinstance(terms, dict) else {}
        if not isinstance(ondemand, dict) or not ondemand:
            return None

        for _, term in ondemand.items():
            if not isinstance(term, dict):
                continue
            dims = term.get("priceDimensions", {})
            if not isinstance(dims, dict):
                continue
            for _, dim in dims.items():
                if not isinstance(dim, dict):
                    continue
                unit = str(dim.get("unit") or "")
                if unit != expected_unit:
                    continue
                price_per_unit = dim.get("pricePerUnit", {})
                if not isinstance(price_per_unit, dict):
                    continue
                usd = _safe_float(price_per_unit.get("USD"))
                if usd is None:
                    continue
                return PriceQuote(
                    unit_price_usd=float(usd),
                    unit=unit,
                    source="pricing_api",
                    as_of=_utc_now(),
                )

        return None


# -------------------------
# Factory helpers
# -------------------------

def make_pricing_cache(
    *,
    base_dir: Path,
    ttl_days: int = 7,
    filename: str = "aws_pricing_cache.json",
) -> PricingCache:
    return PricingCache(path=base_dir / filename, ttl=timedelta(days=int(ttl_days)))


def default_cache_dir() -> Path:
    # Keep it project-local and deterministic.
    return Path("data") / ".cache" / "pricing"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
