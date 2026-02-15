"""Tests for shared AWS test doubles."""

from __future__ import annotations

from typing import Any

import pytest

from tests.aws_mocks import (
    FakePaginatedAwsClient,
    FakePricingByField,
    FakeSavingsPlansClient,
    make_client_error,
)


def test_fake_paginated_client_supports_kwargs_aware_pages() -> None:
    """Paginator page providers should be able to branch on paginate kwargs."""

    def _provider(kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        team = str(kwargs.get("TeamId") or "")
        return [{"Items": [{"team": team}]}]

    client = FakePaginatedAwsClient(region="eu-west-1", pages_by_op={"list_items": _provider})
    pages = list(client.get_paginator("list_items").paginate(TeamId="alpha"))
    assert pages == [{"Items": [{"team": "alpha"}]}]


def test_fake_paginated_client_can_raise_client_error() -> None:
    """Configured error operations should raise a botocore ClientError."""
    client = FakePaginatedAwsClient(region="eu-west-1", pages_by_op={"op": []}, raise_on="op")
    with pytest.raises(type(make_client_error("op"))):
        _ = client.get_paginator("op")


def test_fake_savings_plans_client_token_paging() -> None:
    """Token-based paging should emit nextToken until final page."""
    client = FakeSavingsPlansClient(
        pages=[
            {"savingsPlans": [{"id": "sp-1"}]},
            {"savingsPlans": [{"id": "sp-2"}]},
        ]
    )
    p1 = client.describe_savings_plans(states=["active"])
    p2 = client.describe_savings_plans(states=["active"], nextToken=p1.get("nextToken"))
    p3 = client.describe_savings_plans(states=["active"], nextToken="2")
    assert p1["savingsPlans"][0]["id"] == "sp-1"
    assert p2["savingsPlans"][0]["id"] == "sp-2"
    assert "nextToken" not in p2
    assert p3 == {"savingsPlans": []}


def test_fake_pricing_by_field_returns_default_when_missing() -> None:
    """Pricing fake should return configured default for unknown filter values."""
    pricing = FakePricingByField({"m5.large": 0.10}, field_name="instanceType", default_price=0.25)
    quote = pricing.get_on_demand_unit_price(
        service_code="AmazonEC2",
        unit="Hrs",
        filters=[{"Field": "instanceType", "Value": "unknown.type"}],
    )
    assert quote.unit_price == 0.25
