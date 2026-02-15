"""Tests for PricingService run metadata helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from services.pricing_service import PriceQuote, PricingService


class _FakeServiceModel:
    api_version = "2017-10-15"


class _FakeClientMeta:
    service_model = _FakeServiceModel()


class _FakePricingClient:
    meta = _FakeClientMeta()

    def get_products(self, **_kwargs):  # type: ignore[no-untyped-def]
        return {"PriceList": []}


class _CacheWithHit:
    def __init__(self, quote: PriceQuote) -> None:
        self._quote = quote

    def get(self, _key: str) -> PriceQuote | None:
        return self._quote

    def put(self, _key: str, _quote: PriceQuote) -> None:
        return


def test_pricing_service_run_metadata_defaults_without_cache() -> None:
    """Without prior lookups, metadata should still expose source/version defaults."""
    service = PricingService(pricing_client=_FakePricingClient(), cache=None)
    metadata = service.run_metadata()
    assert metadata["pricing_source"] == "pricing_api"
    assert metadata["pricing_version"] == "aws_pricing_api_2017-10-15"


def test_pricing_service_run_metadata_tracks_cache_source_after_lookup() -> None:
    """When quotes come from cache, run metadata should report cache as source."""
    quote = PriceQuote(
        unit_price_usd=0.23,
        unit="GB-Mo",
        source="cache",
        as_of=datetime.now(timezone.utc),  # noqa: UP017 - runtime is <3.11 in CI/dev
    )
    cache = _CacheWithHit(quote=quote)
    service = PricingService(pricing_client=_FakePricingClient(), cache=cache)
    resolved = service.get_on_demand_unit_price(
        service_code="AmazonS3",
        filters=({"Field": "location", "Value": "US East (N. Virginia)"},),
        unit="GB-Mo",
    )
    assert resolved is not None
    metadata = service.run_metadata()
    assert metadata["pricing_source"] == "cache"
    assert metadata["pricing_version"] == "aws_pricing_api_2017-10-15"
