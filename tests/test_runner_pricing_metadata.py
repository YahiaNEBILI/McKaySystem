"""Unit tests for runner pricing metadata resolution."""

from __future__ import annotations

from types import SimpleNamespace

from apps.worker.runner import _resolve_run_pricing_metadata


def test_resolve_run_pricing_metadata_auto_derives_when_env_missing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Runner should derive pricing metadata from service metadata when env is missing."""
    monkeypatch.delenv("PRICING_VERSION", raising=False)
    monkeypatch.delenv("FINOPS_PRICING_VERSION", raising=False)
    monkeypatch.delenv("PRICING_SOURCE", raising=False)
    monkeypatch.delenv("FINOPS_PRICING_SOURCE", raising=False)

    class _Pricing:
        def run_metadata(self) -> dict[str, str]:
            return {
                "pricing_source": "pricing_api+cache",
                "pricing_version": "aws_pricing_api_2017-10-15",
            }

    services = SimpleNamespace(pricing=_Pricing())
    version, source = _resolve_run_pricing_metadata(services=services)
    assert version == "aws_pricing_api_2017-10-15"
    assert source == "pricing_api+cache"


def test_resolve_run_pricing_metadata_env_overrides_auto(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Explicit env metadata should override any auto-derived values."""
    monkeypatch.setenv("PRICING_VERSION", "aws_2026_02_01")
    monkeypatch.setenv("PRICING_SOURCE", "snapshot")

    class _Pricing:
        def run_metadata(self) -> dict[str, str]:
            return {
                "pricing_source": "pricing_api",
                "pricing_version": "aws_pricing_api_2017-10-15",
            }

    services = SimpleNamespace(pricing=_Pricing())
    version, source = _resolve_run_pricing_metadata(services=services)
    assert version == "aws_2026_02_01"
    assert source == "snapshot"
