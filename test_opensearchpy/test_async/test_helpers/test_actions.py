# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import json
from typing import Any, Dict, List

import pytest

from opensearchpy import OpenSearch
from opensearchpy._async.helpers import actions
from opensearchpy.helpers import BulkAuthorizationError

pytestmark = pytest.mark.asyncio

_OP_TYPES = frozenset(("index", "create", "update", "delete"))


def _action_lines(body: str) -> List[Dict[str, Any]]:
    parsed = [json.loads(line) for line in body.splitlines() if line]
    return [line for line in parsed if isinstance(line, dict) and _OP_TYPES & set(line)]


class RecordingBulkClient:
    """Fake async bulk endpoint that records exactly what was sent."""

    def __init__(self) -> None:
        self.transport = OpenSearch().transport
        self.bodies: List[str] = []
        self.kwargs: List[Dict[str, Any]] = []

    async def bulk(self, body: str, *args: Any, **kwargs: Any) -> Any:
        self.bodies.append(body)
        self.kwargs.append(kwargs)
        return {
            "items": [
                {next(iter(action)): {"status": 201}}
                for action in _action_lines(body)
            ]
        }


class TestAsyncStreamingBulkIndexAuthorization:
    async def test_allowed_outer_index_is_passed_through(self) -> None:
        client = RecordingBulkClient()
        results = [
            item
            async for item in actions.async_streaming_bulk(
                client,
                [{"_id": 1}, {"_id": 2}],
                index="approved-1",
                allowed_indexes={"approved-1"},
            )
        ]

        assert [True, True] == [ok for ok, _ in results]
        assert "approved-1" == client.kwargs[0]["index"]
        assert [{"index": {"_id": 1}}, {"index": {"_id": 2}}] == _action_lines(
            client.bodies[0]
        )

    async def test_denied_outer_index_never_reaches_client(self) -> None:
        client = RecordingBulkClient()
        with pytest.raises(BulkAuthorizationError):
            async for _ in actions.async_streaming_bulk(
                client, [{"_id": 1}], index="other", allowed_indexes={"approved-1"}
            ):
                pass

        assert [] == client.bodies

    async def test_per_action_index_is_checked_before_sending(self) -> None:
        client = RecordingBulkClient()
        results = [
            item
            async for item in actions.async_streaming_bulk(
                client,
                [
                    {"_index": "approved-1", "_id": 1},
                    {"_index": "other", "_id": 2},
                ],
                allowed_indexes={"approved-1"},
                raise_on_error=False,
            )
        ]

        assert [True, False] == [ok for ok, _ in results]
        assert 1 == len(client.bodies)
        assert [{"index": {"_index": "approved-1", "_id": 1}}] == _action_lines(
            client.bodies[0]
        )
        assert 403 == results[1][1]["index"]["status"]

    async def test_async_bulk_summary_reports_denied_actions(self) -> None:
        client = RecordingBulkClient()
        success, errors = await actions.async_bulk(
            client,
            [
                {"_index": "approved-1", "_id": 1},
                {"_index": "other", "_id": 2},
            ],
            allowed_indexes={"approved-1"},
            raise_on_error=False,
        )

        assert 1 == success
        assert 1 == len(errors)
        assert "other" == errors[0]["index"]["_index"]
