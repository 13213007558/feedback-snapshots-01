# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.


import json
import threading
import time
from typing import Any
from unittest import mock
from unittest.mock import Mock

import pytest

from opensearchpy import OpenSearch, helpers
from opensearchpy.serializer import JSONSerializer

from ..test_cases import TestCase

lock_side_effect = threading.Lock()


def mock_process_bulk_chunk(*args: Any, **kwargs: Any) -> Any:
    """
    Threadsafe way of mocking process bulk chunk:
    https://stackoverflow.com/questions/39332139/thread-safe-version-of-mock-call-count
    """

    with lock_side_effect:
        mock_process_bulk_chunk.call_count += 1  # type: ignore
    time.sleep(0.1)
    return []


mock_process_bulk_chunk.call_count = 0  # type: ignore


class TestParallelBulk(TestCase):
    @mock.patch(
        "opensearchpy.helpers.actions._process_bulk_chunk",
        side_effect=mock_process_bulk_chunk,
    )
    def test_all_chunks_sent(self, _process_bulk_chunk: Any) -> None:
        actions = ({"x": i} for i in range(100))
        list(helpers.parallel_bulk(OpenSearch(), actions, chunk_size=2))

        self.assertEqual(50, mock_process_bulk_chunk.call_count)  # type: ignore

    @mock.patch("opensearchpy.OpenSearch.bulk")
    def test_with_all_options(self, _bulk: Any) -> None:
        actions = ({"x": i} for i in range(100))
        list(
            helpers.parallel_bulk(
                client=OpenSearch(),
                actions=actions,
                chunk_size=2,
                raise_on_error=False,
                raise_on_exception=False,
                max_chunk_bytes=20 * 1024 * 1024,
                request_timeout=160,
                ignore_status=(123),
            )
        )

        self.assertEqual(50, _bulk.call_count)
        _bulk.assert_called_with(
            body='{"index":{}}\n{"x":98}\n{"index":{}}\n{"x":99}\n', request_timeout=160
        )

    @mock.patch("opensearchpy.helpers.actions._process_bulk_chunk")
    def test_process_bulk_chunk_with_all_options(
        self, _process_bulk_chunk: Any
    ) -> None:
        actions = ({"x": i} for i in range(100))
        client = OpenSearch()
        list(
            helpers.parallel_bulk(
                client=client,
                actions=actions,
                chunk_size=2,
                raise_on_error=True,
                raise_on_exception=True,
                max_chunk_bytes=20 * 1024 * 1024,
                request_timeout=160,
                ignore_status=(123),
            )
        )

        self.assertEqual(50, _process_bulk_chunk.call_count)
        _process_bulk_chunk.assert_called_with(
            client,
            ['{"index":{}}', '{"x":98}', '{"index":{}}', '{"x":99}'],
            [({"index": {}}, {"x": 98}), ({"index": {}}, {"x": 99})],
            True,
            True,
            123,
            request_timeout=160,
        )

    @pytest.mark.skip  # type: ignore
    @mock.patch(
        "opensearchpy.helpers.actions._process_bulk_chunk",
        # make sure we spend some time in the thread
        side_effect=lambda *args, **kwargs: [
            (True, time.sleep(0.001) or threading.current_thread().ident)  # type: ignore
        ],
    )
    def test_chunk_sent_from_different_threads(self, _process_bulk_chunk: Any) -> None:
        actions = ({"x": i} for i in range(100))
        results = list(
            helpers.parallel_bulk(OpenSearch(), actions, thread_count=10, chunk_size=2)
        )
        self.assertTrue(len({r[1] for r in results}) > 1)


class TestChunkActions(TestCase):
    def setup_method(self, _: Any) -> None:
        """
        creates some documents for testing
        """
        self.actions: Any = [
            ({"index": {}}, {"some": "datá", "i": i}) for i in range(100)
        ]

    def test_expand_action(self) -> None:
        self.assertEqual(helpers.expand_action({}), ({"index": {}}, {}))
        self.assertEqual(
            helpers.expand_action({"key": "val"}), ({"index": {}}, {"key": "val"})
        )

    def test_expand_action_actions(self) -> None:
        self.assertEqual(
            helpers.expand_action(
                {"_op_type": "delete", "_id": "id", "_index": "index"}
            ),
            ({"delete": {"_id": "id", "_index": "index"}}, None),
        )
        self.assertEqual(
            helpers.expand_action(
                {"_op_type": "update", "_id": "id", "_index": "index", "key": "val"}
            ),
            ({"update": {"_id": "id", "_index": "index"}}, {"key": "val"}),
        )
        self.assertEqual(
            helpers.expand_action(
                {"_op_type": "create", "_id": "id", "_index": "index", "key": "val"}
            ),
            ({"create": {"_id": "id", "_index": "index"}}, {"key": "val"}),
        )
        self.assertEqual(
            helpers.expand_action(
                {
                    "_op_type": "create",
                    "_id": "id",
                    "_index": "index",
                    "_source": {"key": "val"},
                }
            ),
            ({"create": {"_id": "id", "_index": "index"}}, {"key": "val"}),
        )

    def test_expand_action_options(self) -> None:
        for option in (
            "_id",
            "_index",
            "_percolate",
            "_timestamp",
            "if_seq_no",
            "if_primary_term",
            "parent",
            "pipeline",
            "retry_on_conflict",
            "routing",
            "version",
            "version_type",
            ("_parent", "parent"),
            ("_retry_on_conflict", "retry_on_conflict"),
            ("_routing", "routing"),
            ("_version", "version"),
            ("_version_type", "version_type"),
            ("_if_seq_no", "if_seq_no"),
            ("_if_primary_term", "if_primary_term"),
        ):
            if isinstance(option, str):
                action_option = option
            else:
                option, action_option = option
            self.assertEqual(
                helpers.expand_action({"key": "val", option: 0}),
                ({"index": {action_option: 0}}, {"key": "val"}),
            )

    def test__source_metadata_or_source(self) -> None:
        self.assertEqual(
            helpers.expand_action({"_source": {"key": "val"}}),
            ({"index": {}}, {"key": "val"}),
        )

        self.assertEqual(
            helpers.expand_action(
                {"_source": ["key"], "key": "val", "_op_type": "update"}
            ),
            ({"update": {"_source": ["key"]}}, {"key": "val"}),
        )

        self.assertEqual(
            helpers.expand_action(
                {"_source": True, "key": "val", "_op_type": "update"}
            ),
            ({"update": {"_source": True}}, {"key": "val"}),
        )

        # This case is only to ensure backwards compatibility with old functionality.
        self.assertEqual(
            helpers.expand_action(
                {"_source": {"key2": "val2"}, "key": "val", "_op_type": "update"}
            ),
            ({"update": {}}, {"key2": "val2"}),
        )

    def test_chunks_are_chopped_by_byte_size(self) -> None:
        self.assertEqual(
            100,
            len(
                list(helpers._chunk_actions(self.actions, 100000, 1, JSONSerializer()))
            ),
        )

    def test_chunks_are_chopped_by_chunk_size(self) -> None:
        self.assertEqual(
            10,
            len(
                list(
                    helpers._chunk_actions(self.actions, 10, 99999999, JSONSerializer())
                )
            ),
        )

    def test_chunks_are_chopped_by_byte_size_properly(self) -> None:
        max_byte_size = 170
        chunks = list(
            helpers._chunk_actions(
                self.actions, 100000, max_byte_size, JSONSerializer()
            )
        )
        self.assertEqual(25, len(chunks))
        for _, chunk_actions in chunks:
            chunk = "".join(chunk_actions)  # fmt: skip
            chunk = chunk if isinstance(chunk, str) else chunk.encode("utf-8")
            self.assertLessEqual(len(chunk), max_byte_size)


class TestExpandActions(TestCase):
    def test_string_actions_are_marked_as_simple_inserts(self) -> None:
        self.assertEqual(
            ('{"index":{}}', "whatever"), helpers.expand_action("whatever")
        )


class TestScanFunction(TestCase):
    @mock.patch("opensearchpy.OpenSearch.clear_scroll")
    @mock.patch("opensearchpy.OpenSearch.scroll")
    @mock.patch("opensearchpy.OpenSearch.search")
    def test_scan_with_missing_hits_key(
        self, mock_search: Mock, mock_scroll: Mock, mock_clear_scroll: Mock
    ) -> None:
        """
        Simulate a response where the 'hits' key is missing
        """
        mock_search.return_value = {"_scroll_id": "dummy_scroll_id", "_shards": {}}

        mock_scroll.side_effect = [{"_scroll_id": "dummy_scroll_id", "_shards": {}}]

        mock_clear_scroll.return_value = None

        client = OpenSearch()

        # The test should pass without raising a KeyError
        scan_result = list(helpers.scan(client, query={"query": {"match_all": {}}}))
        assert scan_result == [], "Expected empty results when 'hits' key is missing"


class _MemoryClient:
    """Small in-memory OpenSearch stand-in that records every request."""

    def __init__(
        self,
        identity: str,
        pages: Any = (),
    ) -> None:
        self.identity = identity
        self.transport = mock.Mock()
        self.transport.serializer = JSONSerializer()
        self.pages = list(pages)
        self.requests: Any = []
        self.active_scrolls: Any = []

    def search(self, **kwargs: Any) -> Any:
        self.requests.append(("search", kwargs))
        page = self.pages.pop(0) if self.pages else []
        scroll_id = f"{self.identity}-scroll-{len(self.requests)}"
        self.active_scrolls.append(scroll_id)
        return {
            "_scroll_id": scroll_id,
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {"hits": page},
        }

    def scroll(self, **kwargs: Any) -> Any:
        self.requests.append(("scroll", kwargs))
        page = self.pages.pop(0) if self.pages else []
        return {
            "_scroll_id": kwargs["body"]["scroll_id"],
            "_shards": {"successful": 1, "skipped": 0, "total": 1},
            "hits": {"hits": page},
        }

    def clear_scroll(self, **kwargs: Any) -> Any:
        self.requests.append(("clear_scroll", kwargs))
        for scroll_id in kwargs["body"]["scroll_id"]:
            if scroll_id in self.active_scrolls:
                self.active_scrolls.remove(scroll_id)
        return {"succeeded": True}

    def bulk(self, **kwargs: Any) -> Any:
        self.requests.append(("bulk", kwargs))
        actions = [
            json.loads(line)
            for line in kwargs["body"].splitlines()
            if line.startswith('{"index"')
        ]
        return {
            "errors": False,
            "items": [
                {"index": {"status": 201, "_index": kwargs.get("index", "?")}}
                for _ in actions
            ],
        }


class TestReindexCapability(TestCase):
    def _capability(self, source: Any, target: Any, **kwargs: Any) -> Any:
        return helpers.ReindexCapability(
            source_client=source,
            source_indices=kwargs.get("source_indices", ("legacy-a", "legacy-b")),
            target_client=target,
            target_index=kwargs.get("target_index", "migrated"),
        )

    def test_scan_pages_and_clears_scroll_with_capability(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}, {"_id": 2}], [{"_id": 3}]])
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        hits = list(
            helpers.scan(
                source,
                index=["legacy-a", "legacy-b"],
                capability=capability,
            )
        )

        self.assertEqual([1, 2, 3], [hit["_id"] for hit in hits])
        self.assertEqual(
            ["search", "scroll", "scroll", "clear_scroll"],
            [name for name, _ in source.requests],
        )
        self.assertEqual(["legacy-a", "legacy-b"], source.requests[0][1]["index"])
        self.assertEqual([], source.active_scrolls)
        self.assertFalse(any(name == "bulk" for name, _ in target.requests))

    def test_reindex_uses_target_identity_and_ignores_source_index_metadata(
        self,
    ) -> None:
        source = _MemoryClient(
            "source",
            pages=[
                [
                    {
                        "_id": 1,
                        "_index": "source-controlled",
                        "fields": {"_index": "fields-controlled"},
                        "value": "a",
                    },
                    {
                        "_id": 2,
                        "fields": {"_index": "another-controlled"},
                        "value": "b",
                    },
                ]
            ],
        )
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        result = helpers.reindex(
            source,
            "legacy-a",
            "migrated",
            target_client=target,
            capability=capability,
            chunk_size=1,
        )

        self.assertEqual((2, 0), result)
        bulk_requests = [kwargs for name, kwargs in target.requests if name == "bulk"]
        self.assertEqual(2, len(bulk_requests))
        for request in bulk_requests:
            for line in request["body"].splitlines():
                if line.startswith('{"index"'):
                    self.assertEqual("migrated", json.loads(line)["index"]["_index"])
            self.assertNotIn("source-controlled", request["body"])
            self.assertNotIn("fields-controlled", request["body"])
            self.assertNotIn("another-controlled", request["body"])

        self.assertFalse(any(name == "bulk" for name, _ in source.requests))
        self.assertEqual([], source.active_scrolls)

    def test_bulk_requires_explicit_or_matching_request_target(self) -> None:
        source = _MemoryClient("source")
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.bulk(target, [{"_id": 1}], capability=capability)
        self.assertEqual([], target.requests)

        result = helpers.bulk(
            target,
            [{"_id": 1}],
            index="migrated",
            capability=capability,
        )
        self.assertEqual((1, []), result)
        self.assertEqual(1, len(target.requests))
        self.assertEqual("migrated", target.requests[0][1]["index"])

    def test_bulk_rejects_nonconcrete_request_target(self) -> None:
        source = _MemoryClient("source")
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        for index in ("migrated-*", "_all", ""):
            with self.assertRaises(helpers.ReindexCapabilityError):
                helpers.bulk(
                    target,
                    [{"_id": 1}],
                    index=index,
                    capability=capability,
                )
        self.assertEqual([], target.requests)

    def test_reindex_rejects_wrong_target_identity_before_any_request(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}]])
        target = _MemoryClient("target")
        intruder = _MemoryClient("intruder")
        capability = self._capability(source, target)

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.reindex(
                source,
                "legacy-a",
                "migrated",
                target_client=intruder,
                capability=capability,
            )

        self.assertEqual([], source.requests)
        self.assertEqual([], target.requests)
        self.assertEqual([], intruder.requests)

    def test_reindex_can_take_target_from_capability(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}]])
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        result = helpers.reindex(
            source,
            "legacy-a",
            target_client=target,
            capability=capability,
        )

        self.assertEqual((1, 0), result)
        action_line = json.loads(target.requests[0][1]["body"].splitlines()[0])
        self.assertEqual("migrated", action_line["index"]["_index"])
        self.assertEqual([], source.active_scrolls)

    def test_reindex_accepts_mapping_declaration(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}]])
        target = _MemoryClient("target")

        result = helpers.reindex(
            source,
            "legacy-a",
            "migrated",
            target_client=target,
            capability={
                "source_client": source,
                "source_indices": ["legacy-a"],
                "target_client": target,
                "target_index": "migrated",
            },
        )

        self.assertEqual((1, 0), result)
        action_line = json.loads(target.requests[0][1]["body"].splitlines()[0])
        self.assertEqual("migrated", action_line["index"]["_index"])

    def test_reindex_rejects_source_outside_scope_before_any_request(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}]])
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.reindex(
                source,
                ["legacy-a", "other-index"],
                "migrated",
                target_client=target,
                capability=capability,
            )

        self.assertEqual([], source.requests)
        self.assertEqual([], target.requests)

    def test_disallowed_bulk_action_cancels_without_sending_chunk(self) -> None:
        source = _MemoryClient("source")
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        def actions() -> Any:
            yield {"_index": "migrated", "_id": 1, "value": "ok"}
            yield {"_index": "not-migrated", "_id": 2, "value": "bad"}

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.bulk(target, actions(), capability=capability, chunk_size=2)

        # The whole chunk is rejected before the client sees it; no partial
        # write of the allowed action occurs.
        self.assertEqual([], target.requests)
        self.assertEqual([], source.requests)

    def test_disallowed_action_after_allowed_chunk_keeps_only_valid_bulk(
        self,
    ) -> None:
        source = _MemoryClient("source")
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        def actions() -> Any:
            yield {"_index": "migrated", "_id": 1, "value": "ok"}
            yield {"_index": "not-migrated", "_id": 2, "value": "bad"}

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.bulk(target, actions(), capability=capability, chunk_size=1)

        self.assertEqual(1, len(target.requests))
        name, request = target.requests[0]
        self.assertEqual("bulk", name)
        action_lines = [
            json.loads(line)
            for line in request["body"].splitlines()
            if line.startswith('{"index"')
        ]
        self.assertEqual([{"index": {"_id": 1, "_index": "migrated"}}], action_lines)
        self.assertNotIn("not-migrated", str(target.requests))

    def test_reindex_cleans_up_after_rejected_action(self) -> None:
        source = _MemoryClient(
            "source",
            pages=[
                [
                    {"_id": 1, "value": "ok"},
                    {"_id": 2, "_op_type": "not-a-bulk-operation"},
                ]
            ],
        )
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        with self.assertRaises(helpers.ReindexCapabilityError):
            helpers.reindex(
                source,
                "legacy-a",
                "migrated",
                target_client=target,
                capability=capability,
                chunk_size=1,
            )

        # The first valid chunk may be written, but the rejected chunk never
        # reaches the target client and the open scroll is cleared.
        self.assertEqual(1, len(target.requests))
        self.assertEqual("bulk", target.requests[0][0])
        self.assertEqual([], source.active_scrolls)
        self.assertTrue(any(name == "clear_scroll" for name, _ in source.requests))

    def test_reindex_revalidates_each_bulk_chunk(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}, {"_id": 2}]])
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        calls = []

        def guarded_bulk(client: Any, actions: Any, **kwargs: Any) -> Any:
            calls.append(list(actions))
            return (2, 0)

        with mock.patch("opensearchpy.helpers.actions.bulk", guarded_bulk):
            result = helpers.reindex(
                source,
                "legacy-a",
                "migrated",
                target_client=target,
                capability=capability,
            )

        self.assertEqual((2, 0), result)
        self.assertEqual(
            ["migrated", "migrated"], [item["_index"] for item in calls[0]]
        )
        self.assertEqual([], target.requests)
        self.assertEqual([], source.active_scrolls)

    def test_reindex_cleans_up_scroll_when_action_construction_fails(self) -> None:
        source = _MemoryClient("source", pages=[[{"_id": 1}, "not-a-hit"]])
        target = _MemoryClient("target")
        capability = self._capability(source, target)

        with self.assertRaises(TypeError):
            helpers.reindex(
                source,
                "legacy-a",
                "migrated",
                target_client=target,
                capability=capability,
                chunk_size=1,
            )

        self.assertEqual([], target.requests)
        self.assertEqual([], source.active_scrolls)
        clear_requests = [
            kwargs for name, kwargs in source.requests if name == "clear_scroll"
        ]
        self.assertTrue(clear_requests)
