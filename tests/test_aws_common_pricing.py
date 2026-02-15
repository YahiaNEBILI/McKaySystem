"""Tests for shared AWS pricing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from checks.aws._common import PricingResolver, percentile, pricing_first_positive, pricing_service


@dataclass
class _Ctx:
    services: Any


def test_pricing_service_from_ctx() -> None:
    pricing = object()
    ctx = _Ctx(services=type("S", (), {"pricing": pricing})())
    assert pricing_service(ctx) is pricing


def test_pricing_first_positive_prefers_first_matching_method() -> None:
    class _Pricing:
        def backup_storage_gb_month_price(self, *, region: str, tier: str) -> float:
            assert region == "eu-west-1"
            assert tier == "warm"
            return 0.12

    price, method = pricing_first_positive(
        _Pricing(),
        method_names=("backup_storage_gb_month_price", "other"),
        kwargs_variants=({"region": "eu-west-1", "tier": "warm"},),
    )
    assert price == 0.12
    assert method == "backup_storage_gb_month_price"


def test_pricing_first_positive_tries_next_signature_after_type_error() -> None:
    class _Pricing:
        def backup_storage_gb_month(self, region: str, storage_class: str) -> float:
            assert region == "eu-west-1"
            assert storage_class == "COLD"
            return 0.01

    price, method = pricing_first_positive(
        _Pricing(),
        method_names=("backup_storage_gb_month",),
        kwargs_variants=(
            {"region": "eu-west-1", "tier": "cold"},  # wrong signature for this fake
            {"region": "eu-west-1", "storage_class": "COLD"},
        ),
    )
    assert price == 0.01
    assert method == "backup_storage_gb_month"


def test_pricing_first_positive_uses_positional_fallback() -> None:
    class _Pricing:
        def backup_gb_month_price(self, region: str, tier: str) -> float:
            assert region == "eu-west-1"
            assert tier == "cold"
            return 0.02

    price, method = pricing_first_positive(
        _Pricing(),
        method_names=("backup_gb_month_price",),
        args_variants=(("eu-west-1", "cold"),),
    )
    assert price == 0.02
    assert method == "backup_gb_month_price"


def test_pricing_first_positive_returns_none_for_non_positive_or_errors() -> None:
    class _Pricing:
        def bad(self, **_kwargs: Any) -> float:
            return 0.0

        def boom(self, **_kwargs: Any) -> float:
            raise ValueError("oops")

    price, method = pricing_first_positive(
        _Pricing(),
        method_names=("bad", "boom"),
        kwargs_variants=({"region": "eu-west-1"},),
    )
    assert price is None
    assert method == ""


def test_percentile_supports_linear_floor_and_nearest_methods() -> None:
    values = [0.0, 10.0, 20.0, 30.0, 40.0]
    assert percentile(values, 95.0, method="linear") == 38.0
    assert percentile(values, 95.0, method="floor") == 30.0
    assert percentile(values, 95.0, method="nearest") == 40.0


def test_percentile_returns_none_for_empty_values() -> None:
    assert percentile([], 95.0) is None


def test_pricing_resolver_backup_storage_substitutes_tier_placeholders() -> None:
    class _Pricing:
        def backup_storage_gb_month_price(self, *, region: str, tier: str) -> float:
            assert region == "eu-west-1"
            assert tier == "cold"
            return 0.011

    ctx = _Ctx(services=type("S", (), {"pricing": _Pricing()})())
    resolver = PricingResolver(ctx)
    price, notes, confidence = resolver.resolve_backup_storage_price(
        region="eu-west-1",
        storage_class="COLD_STORAGE",
        fallback_usd=0.02,
        method_names=("backup_storage_gb_month_price",),
        kwargs_variants=({"region": "{region}", "tier": "{tier}"},),
        args_variants=(),
        resolved_confidence=60,
        fallback_confidence_when_no_service=10,
        fallback_confidence_when_lookup_fails=15,
        no_service_note="no service",
        lookup_failed_note="fallback",
        resolved_note_template="resolved via {method_name} ({tier})",
    )
    assert price == 0.011
    assert confidence == 60
    assert "backup_storage_gb_month_price" in notes
