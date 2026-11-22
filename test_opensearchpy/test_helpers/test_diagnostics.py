# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import json
from typing import Any, List

import pytest

from opensearchpy import (
    AsyncDiagnosticSampler,
    DiagnosticConfig,
    DiagnosticSampler,
    async_scan_with_summary,
    scan_with_summary,
)
from opensearchpy.helpers import async_sample_results, sample_results


class FakePaginatedClient:
    """Fake client whose pages are only fetched when iterated."""

    def __init__(self, pages: List[dict]) -> None:
        self.pages = pages
        self.search_calls = 0
        self.scroll_calls = 0
        self.clear_scroll_calls = 0
        self.pages_fetched = 0

    def search(self, **kwargs: Any) -> dict:
        self.search_calls += 1
        self.pages_fetched += 1
        return self.pages[0]

    def scroll(self, **kwargs: Any) -> dict:
        self.scroll_calls += 1
        if self.scroll_calls >= len(self.pages):
            return {"_scroll_id": None, "hits": {"hits": []}}
        self.pages_fetched += 1
        return self.pages[self.scroll_calls]

    def clear_scroll(self, **kwargs: Any) -> None:
        self.clear_scroll_calls += 1


class FakeAsyncPaginatedClient:
    def __init__(self, pages: List[dict]) -> None:
        self.pages = pages
        self.search_calls = 0
        self.scroll_calls = 0
        self.clear_scroll_calls = 0
        self.pages_fetched = 0

    async def search(self, **kwargs: Any) -> dict:
        self.search_calls += 1
        self.pages_fetched += 1
        return self.pages[0]

    async def scroll(self, **kwargs: Any) -> dict:
        self.scroll_calls += 1
        if self.scroll_calls >= len(self.pages):
            return {"_scroll_id": None, "hits": {"hits": []}}
        self.pages_fetched += 1
        return self.pages[self.scroll_calls]

    async def clear_scroll(self, **kwargs: Any) -> None:
        self.clear_scroll_calls += 1


def hit(record_id: str, source: dict) -> dict:
    return {"_index": "logs", "_id": record_id, "_source": source}


def pages() -> List[dict]:
    return [
        {
            "_scroll_id": "s1",
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {
                "hits": [
                    hit("1", {"title": "first", "secret": "do-not-log"}),
                    hit("2", {"title": "second", "secret": "do-not-log"}),
                ]
            },
        },
        {
            "_scroll_id": "s2",
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {
                "hits": [
                    hit("3", {"title": "third", "secret": "do-not-log"}),
                    hit("4", {"title": "fourth", "secret": "do-not-log"}),
                ]
            },
        },
        {
            "_scroll_id": "s3",
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {"hits": [hit("5", {"title": "fifth", "secret": "do-not-log"})]},
        },
    ]


def test_scan_with_summary_passes_through_and_bounds_samples() -> None:
    client = FakePaginatedClient(pages())
    stream = scan_with_summary(
        client,
        index="logs",
        fields=("title",),
        max_samples=2,
        preserve_order=True,
        scroll_kwargs={"request_timeout": 30},
    )

    results = list(stream)

    assert [r["_id"] for r in results] == ["1", "2", "3", "4", "5"]
    # The caller sees the same, unmodified hits.
    assert results[0]["_source"] == {"title": "first", "secret": "do-not-log"}

    # Only the requested fields are retained, and only up to max_samples.
    assert stream.summary.samples == [{"title": "first"}, {"title": "second"}]
    assert stream.summary.sampled == 2
    assert stream.summary.truncated is True
    assert stream.summary.seen == 5
    assert stream.summary.errors == []
    assert "secret" not in json.dumps(stream.summary.to_dict())

    # Reading only the first result must not fetch later pages.
    client = FakePaginatedClient(pages())
    stream = scan_with_summary(client, index="logs", fields=("title",), max_samples=5)
    assert next(stream)["_id"] == "1"
    assert client.pages_fetched == 1
    assert client.scroll_calls == 0
    stream.close()


def test_scan_with_summary_stops_reading_after_sample_quota() -> None:
    client = FakePaginatedClient(pages())
    stream = scan_with_summary(
        client, index="logs", fields=("title",), max_samples=1, preserve_order=True
    )

    first = next(stream)
    assert first["_id"] == "1"
    # The sampler does not fetch the second page to fill its quota.
    assert client.pages_fetched == 1
    assert client.scroll_calls == 0
    assert stream.summary.samples == [{"title": "first"}]

    stream.close()
    assert client.clear_scroll_calls == 1


def test_scan_with_summary_contains_decode_failure() -> None:
    client = FakePaginatedClient(
        [
            {
                "_scroll_id": "s1",
                "_shards": {"successful": 1, "skipped": 0, "total": 1},
                "hits": {
                    "hits": [
                        hit(
                            "1",
                            {"title": b"\xff\xfe", "status": "ok"},
                        ),
                        hit("2", {"title": "healthy", "status": "ok"}),
                    ]
                },
            }
        ]
    )

    stream = scan_with_summary(
        client, index="logs", fields=("title", "status"), max_samples=3
    )
    results = list(stream)

    # Both real results still reach the application unchanged.
    assert [r["_id"] for r in results] == ["1", "2"]
    assert results[0]["_source"]["title"] == b"\xff\xfe"

    # The failed record is not sampled; the healthy one is.
    assert stream.summary.samples == [{"title": "healthy", "status": "ok"}]
    assert stream.summary.errors == [
        {"record": 0, "field": "title", "error": "UnicodeDecodeError"}
    ]
    # The error entry contains neither the bytes nor the decoded text.
    assert "ff" not in json.dumps(stream.summary.to_dict()).lower()


def test_summary_only_contains_configured_fields() -> None:
    config = DiagnosticConfig(fields=("meta.id", "title"), max_samples=1)
    stream = DiagnosticSampler(
        [hit("1", {"title": "first", "secret": "do-not-log"})], config
    )
    list(stream)

    assert stream.summary.samples == [{"title": "first"}]
    assert "do-not-log" not in json.dumps(stream.summary.to_dict())


def test_raw_mapping_source_projection() -> None:
    stream = sample_results(
        [{"_source": {"user": {"name": "ada"}, "token": "secret"}}],
        fields=("user.name",),
        max_samples=2,
    )
    assert list(stream) == [{"_source": {"user": {"name": "ada"}, "token": "secret"}}]
    assert stream.samples == [{"user.name": "ada"}]


def test_invalid_configuration() -> None:
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=())
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=("_source",))
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=("title",), max_samples=-1)
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=("title",), max_samples=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=(".bad",))
    with pytest.raises(ValueError):
        DiagnosticSampler([])
    with pytest.raises(ValueError):
        DiagnosticSampler([], DiagnosticConfig(fields=("title",)), fields=("title",))
    with pytest.raises(ValueError):
        DiagnosticConfig(fields=("a..b",))


@pytest.mark.asyncio  # type: ignore
async def test_async_sampler_bounds_samples_and_contains_errors() -> None:
    client = FakeAsyncPaginatedClient(pages())
    stream = async_scan_with_summary(
        client,
        index="logs",
        fields=("title",),
        max_samples=2,
        preserve_order=True,
    )
    collected = []
    async for result in stream:
        collected.append(result)

    assert [r["_id"] for r in collected] == ["1", "2", "3", "4", "5"]
    assert stream.summary.samples == [{"title": "first"}, {"title": "second"}]
    assert stream.summary.truncated is True
    assert stream.summary.errors == []


@pytest.mark.asyncio  # type: ignore
async def test_async_sampler_does_not_prefetch() -> None:
    client = FakeAsyncPaginatedClient(pages())
    stream = async_scan_with_summary(
        client, index="logs", fields=("title",), max_samples=2, preserve_order=True
    )

    first = await stream.__anext__()
    assert first["_id"] == "1"
    assert client.pages_fetched == 1
    assert client.scroll_calls == 0

    await stream.aclose()


@pytest.mark.asyncio  # type: ignore
async def test_async_sampler_decode_failure_keeps_stream() -> None:
    client = FakeAsyncPaginatedClient(
        [
            {
                "_scroll_id": "s1",
                "_shards": {"successful": 1, "skipped": 0, "total": 1},
                "hits": {
                    "hits": [
                        hit("1", {"title": b"\xff\xfe"}),
                        hit("2", {"title": "healthy"}),
                    ]
                },
            }
        ]
    )
    stream = async_sample_results(
        async_scan_with_summary(
            client, index="logs", fields=("title",), max_samples=3
        ),
        fields=("title",),
        max_samples=3,
    )

    collected = []
    async for result in stream:
        collected.append(result)

    assert [r["_id"] for r in collected] == ["1", "2"]
    assert collected[0]["_source"]["title"] == b"\xff\xfe"


def test_sampler_records_only_exception_type() -> None:
    stream = DiagnosticSampler(
        [{"_source": {"title": b"\xff", "status": "ok"}}],
        fields=("title", "status"),
    )
    results = list(stream)

    assert results[0]["_source"]["title"] == b"\xff"
    assert stream.summary.samples == []
    assert stream.summary.errors == [
        {"record": 0, "field": "title", "error": "UnicodeDecodeError"}
    ]


def test_async_exports_are_available() -> None:
    assert AsyncDiagnosticSampler is not None
