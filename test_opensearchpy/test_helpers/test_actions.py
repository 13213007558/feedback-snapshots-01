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
from typing import Any, Dict, List
from unittest import mock
from unittest.mock import Mock

import pytest

from opensearchpy import OpenSearch, helpers
from opensearchpy.helpers.errors import BulkAuthorizationError
from opensearchpy.serializer import JSONSerializer

from ..test_cases import TestCase

lock_side_effect = threading.Lock()

_OP_TYPES = frozenset(("index", "create", "update", "delete"))


def _action_lines(body: str) -> List[Dict[str, Any]]:
    """Return only the action metadata lines from a serialized bulk body."""
    parsed = [json.loads(line) for line in body.splitlines() if line]
    return [line for line in parsed if isinstance(line, dict) and _OP_TYPES & set(line)]


class RecordingBulkClient:
    """Fake bulk endpoint that records exactly what the helper sent."""

    def __init__(self, statuses: Any = None) -> None:
        self.transport = OpenSearch().transport
        self.bodies: List[str] = []
        self.kwargs: List[Dict[str, Any]] = []
        # Per-call status lists; the last one repeats for later calls.
        self.statuses = statuses or []

    def _next_statuses(self, count: int) -> List[int]:
        if len(self.statuses) > 1:
            statuses = list(self.statuses.pop(0))
        elif self.statuses:
            statuses = list(self.statuses[0])
        else:
            statuses = []
        return statuses + [201] * (count - len(statuses))

    def bulk(self, body: str, *args: Any, **kwargs: Any) -> Any:
        self.bodies.append(body)
        self.kwargs.append(kwargs)
        actions = _action_lines(body)
        statuses = self._next_statuses(len(actions))
        items = []
        for action, status in zip(actions, statuses):
            op_type = next(iter(action))
            item: Dict[str, Any] = {"status": status}
            if status >= 300:
                item["error"] = {"type": "rejected", "reason": "retry"}
            items.append({op_type: item})
        return {"items": items}


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


class TestBulkIndexAuthorization(TestCase):
    def test_allowed_outer_index_is_checked_but_unchanged(self) -> None:
        client = RecordingBulkClient()
        actions = [{"_id": 1, "v": "a"}, {"_id": 2, "v": "b"}]

        results = list(
            helpers.streaming_bulk(
                client, actions, index="approved-1", allowed_indexes={"approved-1"}
            )
        )

        self.assertEqual([True, True], [ok for ok, _ in results])
        self.assertEqual(1, len(client.bodies))
        # The helper continues to pass the outer index to the client; the
        # per-action metadata stays index-free, so the client uses it.
        self.assertEqual("approved-1", client.kwargs[0]["index"])
        self.assertEqual(
            [{"index": {"_id": 1}}, {"index": {"_id": 2}}],
            _action_lines(client.bodies[0]),
        )

    def test_denied_outer_index_never_reaches_client(self) -> None:
        client = RecordingBulkClient()
        actions = [{"_id": 1, "v": "a"}]

        with self.assertRaises(BulkAuthorizationError):
            list(
                helpers.streaming_bulk(
                    client, actions, index="other", allowed_indexes={"approved-1"}
                )
            )

        self.assertEqual([], client.bodies)

    def test_per_action_index_is_checked_against_allow_list(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1, "v": "a"},
            {"_index": "other", "_id": 2, "v": "b"},
            {"_index": "approved-2", "_id": 3, "v": "c"},
        ]

        with self.assertRaises(BulkAuthorizationError) as ctx:
            list(
                helpers.streaming_bulk(
                    client, actions, allowed_indexes={"approved-1", "approved-2"}
                )
            )

        # The approved subset is sent; the denied action is reported but never
        # serialized into a request.
        self.assertEqual(1, len(client.bodies))
        self.assertEqual(
            [
                {"index": {"_index": "approved-1", "_id": 1}},
                {"index": {"_index": "approved-2", "_id": 3}},
            ],
            _action_lines(client.bodies[0]),
        )
        self.assertEqual(1, len(ctx.exception.errors))
        self.assertEqual("other", ctx.exception.errors[0]["index"]["_index"])

    def test_raise_on_error_false_reports_denied_action_only(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1, "v": "a"},
            {"_index": "other", "_id": 2, "v": "b"},
        ]

        results = list(
            helpers.streaming_bulk(
                client,
                actions,
                allowed_indexes={"approved-1"},
                raise_on_error=False,
            )
        )

        self.assertEqual([True, False], [ok for ok, _ in results])
        self.assertEqual(1, len(client.bodies))
        denied = results[1][1]["index"]
        self.assertEqual("other", denied["_index"])
        self.assertEqual(403, denied["status"])

    def test_all_denied_chunk_is_not_sent(self) -> None:
        client = RecordingBulkClient()
        actions = [{"_index": "other", "_id": 1}, {"_index": "other", "_id": 2}]

        results = list(
            helpers.streaming_bulk(
                client,
                actions,
                allowed_indexes={"approved-1"},
                raise_on_error=False,
            )
        )

        self.assertEqual([False, False], [ok for ok, _ in results])
        self.assertEqual([], client.bodies)

    def test_denied_actions_are_split_across_chunks(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1},
            {"_index": "other", "_id": 2},
            {"_index": "approved-1", "_id": 3},
        ]

        results = list(
            helpers.streaming_bulk(
                client,
                actions,
                chunk_size=1,
                allowed_indexes={"approved-1"},
                raise_on_error=False,
            )
        )

        self.assertEqual([True, False, True], [ok for ok, _ in results])
        self.assertEqual(2, len(client.bodies))
        self.assertEqual(
            [{"index": {"_index": "approved-1", "_id": 1}}],
            _action_lines(client.bodies[0]),
        )
        self.assertEqual(
            [{"index": {"_index": "approved-1", "_id": 3}}],
            _action_lines(client.bodies[1]),
        )

    def test_per_action_index_overrides_unapproved_outer_index(self) -> None:
        client = RecordingBulkClient()
        actions = [{"_index": "approved-1", "_id": 1, "v": "a"}]

        results = list(
            helpers.streaming_bulk(
                client, actions, index="other", allowed_indexes={"approved-1"}
            )
        )

        self.assertEqual([True], [ok for ok, _ in results])
        self.assertEqual("other", client.kwargs[0]["index"])
        self.assertEqual(
            [{"index": {"_index": "approved-1", "_id": 1}}],
            _action_lines(client.bodies[0]),
        )

    def test_delete_with_per_action_index_is_checked(self) -> None:
        client = RecordingBulkClient()
        actions = [{"_op_type": "delete", "_index": "other", "_id": 1}]

        with self.assertRaises(BulkAuthorizationError) as ctx:
            list(helpers.streaming_bulk(client, actions, allowed_indexes={"approved-1"}))

        self.assertEqual([], client.bodies)
        self.assertEqual(
            {"delete": {"_index": "other", "status": 403, "error": mock.ANY}},
            ctx.exception.errors[0],
        )

    def test_bulk_summary_reports_denied_actions(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1},
            {"_index": "other", "_id": 2},
        ]

        success, errors = helpers.bulk(
            client,
            actions,
            allowed_indexes={"approved-1"},
            raise_on_error=False,
        )

        self.assertEqual(1, success)
        self.assertEqual(1, len(errors))
        self.assertEqual("other", errors[0]["index"]["_index"])
        self.assertEqual(1, len(client.bodies))

    def test_parallel_bulk_uses_same_target_check(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1},
            {"_index": "other", "_id": 2},
            {"_index": "approved-1", "_id": 3},
        ]

        results = list(
            helpers.parallel_bulk(
                client,
                actions,
                chunk_size=2,
                allowed_indexes={"approved-1"},
                raise_on_error=False,
            )
        )

        self.assertEqual([False, True, True], sorted(ok for ok, _ in results))
        sent = [line for body in client.bodies for line in _action_lines(body)]
        self.assertEqual(
            [
                {"index": {"_index": "approved-1", "_id": 1}},
                {"index": {"_index": "approved-1", "_id": 3}},
            ],
            sent,
        )

    def test_parallel_bulk_mixed_chunk_sends_then_raises(self) -> None:
        client = RecordingBulkClient()
        actions = [
            {"_index": "approved-1", "_id": 1},
            {"_index": "other", "_id": 2},
        ]

        with self.assertRaises(BulkAuthorizationError) as ctx:
            list(
                helpers.parallel_bulk(
                    client, actions, chunk_size=2, allowed_indexes={"approved-1"}
                )
            )

        self.assertEqual(
            [{"index": {"_index": "approved-1", "_id": 1}}],
            _action_lines(client.bodies[0]),
        )
        self.assertEqual(1, len(ctx.exception.errors))

    def test_parallel_bulk_denied_outer_index_is_not_sent(self) -> None:
        client = RecordingBulkClient()

        with self.assertRaises(BulkAuthorizationError):
            list(
                helpers.parallel_bulk(
                    client, [{"_id": 1}], index="other", allowed_indexes={"approved-1"}
                )
            )

        self.assertEqual([], client.bodies)

    def test_callable_allow_list_receives_resolved_index(self) -> None:
        seen = []

        def approve(index: Any) -> bool:
            seen.append(index)
            return index.startswith("approved-")

        client = RecordingBulkClient()
        list(
            helpers.streaming_bulk(
                client,
                [{"_index": "approved-1", "_id": 1}, {"_id": 2}],
                index="approved-2",
                allowed_indexes=approve,
            )
        )

        self.assertEqual(["approved-1", "approved-2"], seen)
        self.assertEqual(2, len(_action_lines(client.bodies[0])))

    def test_retry_only_resends_approved_actions(self) -> None:
        client = RecordingBulkClient(statuses=[[429, 201], [201]])
        actions = [
            {"_index": "approved-1", "_id": 1},
            {"_index": "other", "_id": 2},
        ]
        sleeps = []

        with mock.patch("opensearchpy.helpers.actions.time.sleep", sleeps.append):
            results = list(
                helpers.streaming_bulk(
                    client,
                    actions,
                    allowed_indexes={"approved-1"},
                    raise_on_error=False,
                    max_retries=1,
                    initial_backoff=0,
                )
            )

        self.assertEqual([True, False], [ok for ok, _ in results])
        self.assertEqual(2, len(client.bodies))
        for body in client.bodies:
            self.assertEqual(
                [{"index": {"_index": "approved-1", "_id": 1}}],
                _action_lines(body),
            )
        self.assertEqual([0], sleeps)

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
