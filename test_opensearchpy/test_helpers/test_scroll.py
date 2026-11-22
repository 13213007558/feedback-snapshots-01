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

from opensearchpy.helpers import (
    OwnedScroll,
    ScrollClosedError,
    ScrollOwnershipError,
    ScrollRegistry,
)
from opensearchpy.helpers.response import Response
from opensearchpy.helpers.scroll import iter_owned_scroll
from opensearchpy.helpers.utils import AttrDict


def _page(scroll_id: str, *names: str) -> Dict[str, Any]:
    return {
        "_scroll_id": scroll_id,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"hits": [{"_id": name, "_source": {"name": name}} for name in names]},
    }


class FakeNode:
    """
    Offline stand-in for one cluster node.

    It hands out rotating scroll ids and records every request so tests can
    assert which node saw which call.
    """

    def __init__(self, name: str, pages: List[Dict[str, Any]]) -> None:
        self.name = name
        self.pages = pages
        self.search_calls: List[Any] = []
        self.scroll_calls: List[Any] = []
        self.clear_calls: List[Any] = []
        self.cleared: List[str] = []

    def search(self, **kwargs: Any) -> Dict[str, Any]:
        self.search_calls.append(kwargs)
        return self.pages[0]

    def scroll(self, **kwargs: Any) -> Dict[str, Any]:
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

    def clear_scroll(self, **kwargs: Any) -> Dict[str, Any]:
        body = kwargs.get("body", {})
        self.clear_calls.append(body)
        self.cleared.extend(body.get("scroll_id", []))
        return {"succeeded": True, "num_freed": len(body.get("scroll_id", []))}


class FakeClient:
    """Client facade over a :class:`FakeNode`, mirroring the real API surface."""

    def __init__(self, node: FakeNode) -> None:
        self.node = node
        self.transport = self

    def search(self, **kwargs: Any) -> Dict[str, Any]:
        return self.node.search(**kwargs)

    def scroll(self, **kwargs: Any) -> Dict[str, Any]:
        return self.node.scroll(**kwargs)

    def clear_scroll(self, **kwargs: Any) -> Dict[str, Any]:
        return self.node.clear_scroll(**kwargs)


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


def test_interleaved_contexts_advance_independently() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    other_client = FakeClient(other)
    registry = ScrollRegistry()

    first = client.search(index="logs", scroll="1m", body={"query": {"match_all": {}}})
    second = other_client.search(
        index="audit", scroll="1m", body={"query": {"match_all": {}}}
    )

    alice = OwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )
    bob = OwnedScroll.from_response(
        second, using=other_client, actor="bob", registry=registry
    )

    assert [hit["_id"] for hit in alice.hits] == ["a1", "a2"]
    assert [hit["_id"] for hit in bob.hits] == ["b1", "b2"]

    alice.next_page()
    bob.next_page()
    alice.next_page()

    assert [hit["_id"] for hit in alice.hits] == ["a5"]
    assert [hit["_id"] for hit in bob.hits] == ["b3"]
    assert alice.scroll_id == "a-3"
    assert bob.scroll_id == "b-2"

    # Each node only ever saw the requests for its own search.
    assert [call["scroll_id"] for call in node.scroll_calls] == ["a-1", "a-2"]
    assert [call["scroll_id"] for call in other.scroll_calls] == ["b-1"]
    assert other.search_calls == [
        {"index": "audit", "scroll": "1m", "body": {"query": {"match_all": {}}}}
    ]


def test_other_operator_cannot_resume_or_advance() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    OwnedScroll.from_response(first, using=client, actor="alice", registry=registry)

    with pytest.raises(ScrollOwnershipError):
        OwnedScroll.resume(context_id="a-1", actor="mallory", registry=registry)
    assert node.scroll_calls == []
    assert node.clear_calls == []


def test_anonymous_context_rejects_wrong_owner_once_bound() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    cursor = OwnedScroll.from_response(first, using=client, registry=registry)

    with pytest.raises(ScrollOwnershipError):
        OwnedScroll.resume(context_id="a-1", actor="alice", registry=registry)
    cursor.close()
    assert node.cleared == ["a-1"]


def test_closed_context_refuses_to_advance_and_sends_nothing() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    cursor = OwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    cursor.close()
    assert node.cleared == ["a-1"]
    scroll_calls_before = len(node.scroll_calls)

    with pytest.raises(ScrollClosedError):
        cursor.next_page()
    with pytest.raises(ScrollOwnershipError):
        OwnedScroll.resume(context_id="a-1", actor="alice", registry=registry)
    assert len(node.scroll_calls) == scroll_calls_before
    assert node.clear_calls == [{"scroll_id": ["a-1"]}]

    # Double close is a no-op.
    assert cursor.close() is None
    assert node.clear_calls == [{"scroll_id": ["a-1"]}]


def test_cleanup_goes_to_originating_connection() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    other_client = FakeClient(other)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    cursor = OwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    cursor.next_page()
    resumed = OwnedScroll.resume(
        context_id=cursor.context_id,
        using=other_client,
        actor="alice",
        registry=registry,
    )
    resumed.close()

    # The clear went to node-a, never to the alias used to resume.
    assert node.cleared == ["a-2"]
    assert other.clear_calls == []
    assert other.scroll_calls == []
    assert cursor.closed


def test_context_id_survives_scroll_id_rotation() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    cursor = OwnedScroll.from_response(
        first, using=client, actor="alice", context_id="search-42", registry=registry
    )

    cursor.next_page()
    state = cursor.pagination_state()
    assert state == {"context_id": "search-42", "scroll_id": "a-2"}

    # Resuming with the persisted current scroll id also resolves the context.
    resumed = OwnedScroll.resume(
        context_id=state["scroll_id"], actor="alice", registry=registry
    )
    assert resumed.context_id == "search-42"
    resumed.next_page()
    assert [hit["_id"] for hit in resumed.hits] == ["a5"]
    resumed.close()
    assert node.cleared == ["a-3"]


def test_iter_owned_scroll_drains_and_closes() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    cursor = OwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )

    assert [hit["_id"] for hit in iter_owned_scroll(cursor)] == [
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
    ]
    assert cursor.closed
    assert node.cleared == ["a-3"]


def test_unowned_context_is_open_to_any_caller_that_knows_it() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = client.search(index="logs", scroll="1m", body={})
    OwnedScroll.from_response(first, using=client, registry=registry)

    cursor = OwnedScroll.resume(context_id="a-1", registry=registry)
    cursor.next_page()
    assert [hit["_id"] for hit in cursor.hits] == ["a3", "a4"]


def test_accepts_attrdict_and_response_objects() -> None:
    node, _ = _two_searches()
    client = FakeClient(node)
    registry = ScrollRegistry()
    first = AttrDict(_page("a-1", "a1", "a2"))
    cursor = OwnedScroll.from_response(
        first, using=client, actor="alice", registry=registry
    )
    assert cursor.scroll_id == "a-1"
    assert [hit["_id"] for hit in cursor.hits] == ["a1", "a2"]

    class FakeSearch:
        def _get_result(self, hit: Any) -> Any:
            return hit

    wrapped = Response(FakeSearch(), _page("a-1", "a1", "a2"))
    cursor = OwnedScroll.from_response(
        wrapped, using=client, actor="bob", context_id="ctx", registry=registry
    )
    assert [hit["_id"] for hit in cursor.hits] == ["a1", "a2"]


def test_closing_one_context_does_not_disturb_the_other() -> None:
    node, other = _two_searches()
    client = FakeClient(node)
    other_client = FakeClient(other)
    registry = ScrollRegistry()

    alice = OwnedScroll.from_response(
        client.search(index="logs", scroll="1m", body={}),
        using=client,
        actor="alice",
        registry=registry,
    )
    bob = OwnedScroll.from_response(
        other_client.search(index="audit", scroll="1m", body={}),
        using=other_client,
        actor="bob",
        registry=registry,
    )

    alice.next_page()
    bob.next_page()
    alice.close()

    # The closed context is done and its node saw exactly one clear request.
    with pytest.raises(ScrollClosedError):
        alice.next_page()
    assert node.cleared == ["a-2"]

    # The other context is still live on its own connection and drains normally.
    assert [hit["_id"] for hit in bob.hits] == ["b3"]
    bob.next_page()
    assert bob.hits == []
    assert other.cleared == []

    bob.close()
    assert other.cleared == ["b-2"]
    assert node.clear_calls == [{"scroll_id": ["a-2"]}]
