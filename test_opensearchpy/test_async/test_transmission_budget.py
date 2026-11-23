# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.

import json
from typing import Any

import pytest
from _pytest.mark.structures import MarkDecorator

from opensearchpy import AsyncOpenSearch
from opensearchpy.connection import Connection
from opensearchpy.exceptions import ConnectionTimeout, TransportError
from opensearchpy.helpers import (
    ReceiptStatus,
    TransmissionBudget,
    async_streaming_bulk,
    recoverable_actions,
)

pytestmark: MarkDecorator = pytest.mark.asyncio


class AsyncScriptedConnection(Connection):
    """Local async transport stand-in replaying a scripted sequence of outcomes."""

    def __init__(self, **kwargs: Any) -> None:
        self.script = kwargs.pop("script")
        self.calls: Any = []
        super().__init__(**kwargs)

    async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        outcome = self.script[len(self.calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        if status >= 300:
            raise TransportError(status, body.get("error", "error"), body)
        return status, {}, json.dumps(body)

    async def close(self) -> None:
        pass


def _bulk_response(*id_status: Any) -> Any:
    return (
        200,
        {"items": [{"index": {"_id": i, "status": s}} for i, s in id_status]},
    )


async def test_async_import_shares_the_same_budget_contract() -> None:
    script = [
        # first chunk: a succeeds, b is rejected with 429
        _bulk_response(("a", 200), ("b", 429)),
        # helper retry of b: retryable 503, then 200 with b still 429
        TransportError(503, "unavailable", {}),
        _bulk_response(("b", 429)),
        # next chunk (c, d): sent but no reply comes back
        ConnectionTimeout("N/A", "timed out", Exception("timeout")),
    ]
    budget = TransmissionBudget(4)
    client = AsyncOpenSearch(
        [{"script": script}],
        connection_class=AsyncScriptedConnection,
        max_retries=1,
    )
    actions = [{"_id": doc_id, "doc": doc_id} for doc_id in ("a", "b", "c", "d", "e")]

    results = [
        result
        async for result in async_streaming_bulk(
            client,
            actions,
            chunk_size=2,
            max_retries=1,
            initial_backoff=0,
            raise_on_error=False,
            raise_on_exception=False,
            transmission_budget=budget,
        )
    ]

    connection = client.transport.connection_pool.connections[0]

    # both layers together sent exactly 4 times and charged the shared budget
    assert len(connection.calls) == 4
    assert budget.spent == 4
    assert budget.exhausted

    bodies = [call[0][3] for call in connection.calls]
    assert b'"a"' in bodies[0]
    assert b'"a"' not in bodies[1]
    assert b'"b"' in bodies[1]
    assert b'"b"' in bodies[2]
    assert b'"c"' in bodies[3]
    assert b'"d"' in bodies[3]

    assert [True, False, False, False, False] == [ok for ok, _ in results]
    receipts = [receipt for _, receipt in results]
    assert [
        ReceiptStatus.SUCCEEDED,
        ReceiptStatus.CONFIRMED_FAILURE,
        ReceiptStatus.UNCONFIRMED,
        ReceiptStatus.UNCONFIRMED,
        ReceiptStatus.UNSENT,
    ] == [r.status for r in receipts]
    # the last async action was never sent: no transmission was charged for
    # it and its receipt allows a recovery pass
    assert receipts[4].attempts == 0
    assert [False, True, False, False, True] == [r.resumable for r in receipts]

    recoverable = recoverable_actions(results)
    assert ["b", "e"] == [action[0]["index"]["_id"] for action in recoverable]

    await client.close()
