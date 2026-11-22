# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


from typing import Any, Dict, List

import pytest
from _pytest.mark.structures import MarkDecorator

from opensearchpy._async.helpers.scroll import (
    AsyncOwnedScroll,
    AsyncScrollRegistry,
    aiter_owned_scroll,
)
from opensearchpy.helpers import ScrollClosedError, ScrollOwnershipError

pytestmark: MarkDecorator = pytest.mark.asyncio


def _page(scroll_id: str, *names: str) -> Dict[str, Any]:
    return {
        "_scroll_id": scroll_id,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"hits": [{"_id": name, "_source": {"name": name}} for name in names]},
    }


class FakeNode:
    def __init__(self, name: str, pages: List[Dict[str, Any]]) -> None:
        self.name = name
        self.pages = pages
        self.search_calls: List[Any] = []
        self.scroll_calls: List[Any] = []
        self.clear_calls: List[Any] = []
        self.cleared: List[str] = []

    async def search(self, **kwargs: Any) -> Dict[str, Any]:
        self.search_calls.append(kwargs)
        return self.pages[0]

    async def scroll(self, **kwargs: Any) -> Dict[str, Any]:
        body = kwargs.get("body", {})
        self.scroll_calls.append(body)
        scroll_id = body["scroll_id"]
        for page in self.pages:
            if page["_scroll_id"] == scroll_id:
                index = self.pages.index(page)
                if index + 1 >= len(self.pages):
                    return {"_scroll_id": scroll_id, "hits": {"hits": []}}
                return self.pages[index + 1]
        raise AssertionError("unknown scroll id %r" % scroll_id)

    async def clear_scroll(self, **kwargs: Any) -> Dict[str, Any]:
        body = kwargs.get("body", {})
        self.clear_calls.append(body)
        self.cleared.extend(body.get("scroll_id", []))
        return {"succeeded": True, "num_freed": len(body.get("scroll_id", []))}


class FakeClient:
    def __init__(self, node: FakeNode) -> None:
        self.node = node
        self.transport = self

    async def search(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.node.search(**kwargs)

    async def scroll(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.node.scroll(**kwargs)

    async def clear_scroll(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.node.clear_scroll(**kwargs)


def _two_searches():
    node = FakeNode(
        "node-a",
        [
            _page("a-1", "a1", "a2"),
            _page("a-2", "a3", "a4"),
            _page("a-3", "a5"),
        ],
    )
    other = FakeNode(
        "node-b",
        [
            _page("b-1", "b1", "b2"),
            _page("b-2", "b3"),
        ],
    )
    return node, other


async def test_interleaved_contexts_advance_independently() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    other_client = FakeClient(other)
    registry = AsyncScrollRegistry()

    first = await client.search(index="logs", scroll="1m", body={})
    second = await other_client.search(index="audit", scroll="1m", body={})

    alice = await AsyncOwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )
    bob = await AsyncOwnedScroll.from_response(
        second, using=other_client, actor="bob", registry=registry
    )

    await alice.next_page()
    await bob.next_page()
    await alice.next_page()

    assert [hit["_id"] for hit in alice.hits] == ["a5"]
    assert [hit["_id"] for hit in bob.hits] == ["b3"]
    assert [call["scroll_id"] for call in node.scroll_calls] == ["a-1", "a-2"]
    assert [call["scroll_id"] for call in other.scroll_calls] == ["b-1"]


async def test_other_operator_cannot_resume() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = AsyncScrollRegistry()
    first = await client.search(index="logs", scroll="1m", body={})
    await AsyncOwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    with pytest.raises(ScrollOwnershipError):
        AsyncOwnedScroll.resume(context_id="a-1", actor="mallory", registry=registry)
    assert node.scroll_calls == []
    assert node.clear_calls == []


async def test_closed_context_sends_nothing_more() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = AsyncScrollRegistry()
    first = await client.search(index="logs", scroll="1m", body={})
    cursor = await AsyncOwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    await cursor.close()
    with pytest.raises(ScrollClosedError):
        await cursor.next_page()
    with pytest.raises(ScrollOwnershipError):
        AsyncOwnedScroll.resume(context_id="a-1", actor="alice", registry=registry)
    assert node.cleared == ["a-1"]
    assert node.scroll_calls == []
    assert await cursor.close() is None


async def test_cleanup_goes_to_originating_connection() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    other_client = FakeClient(other)
    registry = AsyncScrollRegistry()
    first = await client.search(index="logs", scroll="1m", body={})
    cursor = await AsyncOwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    await cursor.next_page()
    resumed = AsyncOwnedScroll.resume(
        context_id=cursor.context_id,
        using=other_client,
        actor="alice",
        registry=registry,
    )
    await resumed.close()

    assert node.cleared == ["a-2"]
    assert other.clear_calls == []
    assert other.scroll_calls == []
    assert cursor.closed


async def test_aiter_owned_scroll_drains_and_closes() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = AsyncScrollRegistry()
    first = await client.search(index="logs", scroll="1m", body={})
    cursor = await AsyncOwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    ids = [hit["_id"] async for hit in aiter_owned_scroll(cursor)]
    assert ids == ["a1", "a2", "a3", "a4", "a5"]
    assert cursor.closed
    assert node.cleared == ["a-3"]
