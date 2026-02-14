"""Tests for shared AWS pagination helper."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import pytest

from checks.aws._common import paginate_items


class _FakePaginator:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        yield from self._pages


class _PaginatorClient:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = pages

    def get_paginator(self, _op: str) -> _FakePaginator:
        return _FakePaginator(self._pages)


class _TokenClient:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = list(pages)
        self._idx = 0

    def list_items(self, **_kwargs: Any) -> Mapping[str, Any]:
        page = self._pages[self._idx]
        self._idx += 1
        return page


class _FallbackClient:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self._pages = list(pages)
        self._idx = 0

    def get_paginator(self, _op: str) -> _FakePaginator:
        raise ValueError("no paginator in fake")

    def list_items(self, **_kwargs: Any) -> Mapping[str, Any]:
        page = self._pages[self._idx]
        self._idx += 1
        return page


def test_paginate_items_prefers_paginator() -> None:
    client = _PaginatorClient(
        pages=[
            {"Items": [{"id": "a"}, "skip"]},
            {"Items": [{"id": "b"}]},
        ]
    )

    out = list(
        paginate_items(
            client,
            "list_items",
            "Items",
            paginator_fallback_exceptions=(ValueError,),
        )
    )
    assert [x["id"] for x in out] == ["a", "b"]


def test_paginate_items_falls_back_to_next_token_loop() -> None:
    client = _FallbackClient(
        pages=[
            {"Items": [{"id": "a"}], "NextToken": "t1"},
            {"Items": [{"id": "b"}]},
        ]
    )

    out = list(
        paginate_items(
            client,
            "list_items",
            "Items",
            paginator_fallback_exceptions=(ValueError,),
        )
    )
    assert [x["id"] for x in out] == ["a", "b"]


def test_paginate_items_supports_custom_marker_keys() -> None:
    client = _TokenClient(
        pages=[
            {"Items": [{"id": "a"}], "NextMarker": "m1"},
            {"Items": [{"id": "b"}]},
        ]
    )

    out = list(
        paginate_items(
            client,
            "list_items",
            "Items",
            request_token_key="Marker",
            response_token_keys=("NextMarker", "Marker"),
            paginator_fallback_exceptions=(AttributeError,),
        )
    )
    assert [x["id"] for x in out] == ["a", "b"]


def test_paginate_items_raises_when_operation_missing() -> None:
    with pytest.raises(AttributeError):
        list(
            paginate_items(
                object(),
                "missing_op",
                "Items",
            )
        )
