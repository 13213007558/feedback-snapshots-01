# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import json
from typing import Any
from unittest import mock

import pytest

from opensearchpy import helpers
from opensearchpy.serializer import JSONSerializer

pytestmark = pytest.mark.asyncio


class _AsyncMemoryClient:
    def __init__(self, identity: str, pages: Any = ()) -> None:
        self.identity = identity
        self.transport = mock.Mock()
        self.transport.serializer = JSONSerializer()
        self.pages = list(pages)
        self.requests: Any = []
        self.active_scrolls: Any = []

    async def search(self, **kwargs: Any) -> Any:
        self.requests.append(("search", kwargs))
        page = self.pages.pop(0) if self.pages else []
        scroll_id = f"{self.identity}-scroll-{len(self.requests)}"
        self.active_scrolls.append(scroll_id)
        return {
            "_scroll_id": scroll_id,
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {"hits": page},
        }

    async def scroll(self, **kwargs: Any) -> Any:
        self.requests.append(("scroll", kwargs))
        page = self.pages.pop(0) if self.pages else []
        return {
            "_scroll_id": kwargs["body"]["scroll_id"],
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {"hits": page},
        }

    async def clear_scroll(self, **kwargs: Any) -> Any:
        self.requests.append(("clear_scroll", kwargs))
        for scroll_id in kwargs["body"]["scroll_id"]:
            if scroll_id in self.active_scrolls:
                self.active_scrolls.remove(scroll_id)
        return {"succeeded": True}

    async def bulk(self, **kwargs: Any) -> Any:
        self.requests.append(("bulk", kwargs))
        action_lines = [
            json.loads(line)
            for line in kwargs["body"].splitlines()
            if line and line.startswith('{"')
        ]
        actions = [
            line
            for line in action_lines
            if set(line) & {"index", "create", "update", "delete"}
        ]
        return {
            "errors": False,
            "items": [
                {"index": {"status": 201, "_index": kwargs.get("index", "?")}}
                for _ in actions
            ],
        }


def _capability(source: Any, target: Any) -> Any:
    return helpers.ReindexCapability(
        source_client=source,
        source_indices=("legacy-a", "legacy-b"),
        target_client=target,
        target_index="migrated",
    )


async def test_async_scan_pages_and_clears_scroll() -> None:
    source = _AsyncMemoryClient(
        "source", pages=[[{"_id": 1}, {"_id": 2}], [{"_id": 3}]]
    )
    target = _AsyncMemoryClient("target")

    hits = [
        hit
        async for hit in helpers.async_scan(
            source,
            index=["legacy-a", "legacy-b"],
            capability=_capability(source, target),
        )
    ]

    assert [hit["_id"] for hit in hits] == [1, 2, 3]
    assert [name for name, _ in source.requests] == [
        "search",
        "scroll",
        "scroll",
        "clear_scroll",
    ]
    assert source.active_scrolls == []


async def test_async_reindex_ignores_source_index_metadata() -> None:
    source = _AsyncMemoryClient(
        "source",
        pages=[
            [
                {
                    "_id": 1,
                    "_index": "source-controlled",
                    "fields": {"_index": "fields-controlled"},
                    "value": "a",
                }
            ]
        ],
    )
    target = _AsyncMemoryClient("target")

    result = await helpers.async_reindex(
        source,
        "legacy-a",
        "migrated",
        target_client=target,
        capability=_capability(source, target),
    )

    assert result == (1, 0)
    bulk_requests = [kwargs for name, kwargs in target.requests if name == "bulk"]
    assert len(bulk_requests) == 1
    assert "source-controlled" not in bulk_requests[0]["body"]
    assert "fields-controlled" not in bulk_requests[0]["body"]
    assert json.loads(bulk_requests[0]["body"].splitlines()[0]) == {
        "index": {"_id": 1, "_index": "migrated"}
    }
    assert source.active_scrolls == []


async def test_async_reindex_rejects_wrong_target_identity_before_request() -> None:
    source = _AsyncMemoryClient("source", pages=[[{"_id": 1}]])
    target = _AsyncMemoryClient("target")
    intruder = _AsyncMemoryClient("intruder")

    with pytest.raises(helpers.ReindexCapabilityError):
        await helpers.async_reindex(
            source,
            "legacy-a",
            "migrated",
            target_client=intruder,
            capability=_capability(source, target),
        )

    assert source.requests == []
    assert target.requests == []
    assert intruder.requests == []


async def test_async_reindex_cleans_up_after_rejected_action() -> None:
    source = _AsyncMemoryClient(
        "source",
        pages=[[{"_id": 1}, {"_id": 2, "_op_type": "not-a-bulk-operation"}]],
    )
    target = _AsyncMemoryClient("target")

    with pytest.raises(helpers.ReindexCapabilityError):
        await helpers.async_reindex(
            source,
            "legacy-a",
            "migrated",
            target_client=target,
            capability=_capability(source, target),
            chunk_size=1,
        )

    assert len(target.requests) == 1
    assert target.requests[0][0] == "bulk"
    assert source.active_scrolls == []
    assert any(name == "clear_scroll" for name, _ in source.requests)
