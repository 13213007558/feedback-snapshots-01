# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.

import json
from typing import Any
from unittest import TestCase

from opensearchpy import OpenSearch, Transport
from opensearchpy.connection import Connection
from opensearchpy.exceptions import (
    ConnectionTimeout,
    TransmissionBudgetExhausted,
    TransportError,
)
from opensearchpy.helpers import (
    ReceiptStatus,
    TransmissionBudget,
    TransmissionReceipt,
    recoverable_actions,
    streaming_bulk,
)


class ScriptedConnection(Connection):
    """Local transport stand-in replaying a scripted sequence of outcomes."""

    def __init__(self, **kwargs: Any) -> None:
        self.script = kwargs.pop("script")
        self.calls: Any = []
        super().__init__(**kwargs)

    def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        outcome = self.script[len(self.calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        if status >= 300:
            raise TransportError(status, body.get("error", "error"), body)
        return status, {}, json.dumps(body)


def _bulk_response(*id_status: Any) -> Any:
    return (
        200,
        {"items": [{"index": {"_id": i, "status": s}} for i, s in id_status]},
    )


class TestTransmissionBudget(TestCase):
    def test_spend_up_to_limit_then_refuses(self) -> None:
        budget = TransmissionBudget(2)
        self.assertTrue(budget.spend())
        self.assertTrue(budget.spend())
        self.assertFalse(budget.spend())
        self.assertEqual(2, budget.spent)
        self.assertEqual(0, budget.remaining)
        self.assertTrue(budget.exhausted)

    def test_negative_limit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TransmissionBudget(-1)

    def test_cancel_never_refunds_already_sent_cost(self) -> None:
        budget = TransmissionBudget(2)
        self.assertTrue(budget.spend())
        budget.cancel()
        # cancellation does not hand back the cost of the sent request
        self.assertEqual(1, budget.spent)
        self.assertEqual(1, budget.remaining)
        self.assertFalse(budget.spend())
        self.assertEqual(1, budget.spent)
        self.assertTrue(budget.cancelled)

    def test_transport_charges_every_transmission_including_retries(self) -> None:
        script = [
            TransportError(503, "unavailable", {}),
            TransportError(503, "unavailable", {}),
            (200, {"ok": True}),
        ]
        t: Any = Transport(
            [{"script": script}], connection_class=ScriptedConnection, max_retries=2
        )
        budget = TransmissionBudget(3)

        resp = t.perform_request("GET", "/", params={"transmission_budget": budget})

        self.assertEqual({"ok": True}, resp)
        connection = t.connection_pool.connections[0]
        # all three sends (initial + two transport internal retries) were charged
        self.assertEqual(3, len(connection.calls))
        self.assertEqual(3, budget.spent)
        # the budget object never leaks into the query string
        self.assertNotIn("transmission_budget", connection.calls[0][0][2])

    def test_transport_raises_instead_of_sending_when_budget_spent(self) -> None:
        t: Any = Transport([{"script": []}], connection_class=ScriptedConnection)
        budget = TransmissionBudget(0)

        with self.assertRaises(TransmissionBudgetExhausted):
            t.perform_request("GET", "/", params={"transmission_budget": budget})

        connection = t.connection_pool.connections[0]
        self.assertEqual(0, len(connection.calls))
        self.assertEqual(0, budget.spent)


class TestStreamingBulkWithBudget(TestCase):
    def _run_import(self, budget: TransmissionBudget) -> Any:
        script = [
            # first chunk: a succeeds, b is rejected with 429
            _bulk_response(("a", 200), ("b", 429)),
            # helper retry of b: retryable 503, then 200 with b still 429
            TransportError(503, "unavailable", {}),
            _bulk_response(("b", 429)),
            # next chunk (c, d): sent but no reply comes back
            ConnectionTimeout("N/A", "timed out", Exception("timeout")),
        ]
        client = OpenSearch(
            [{"script": script}],
            connection_class=ScriptedConnection,
            max_retries=1,
        )
        actions = [{"_id": doc_id, "doc": doc_id} for doc_id in ("a", "b", "c", "d", "e")]
        results = list(
            streaming_bulk(
                client,
                actions,
                chunk_size=2,
                max_retries=1,
                initial_backoff=0,
                raise_on_error=False,
                raise_on_exception=False,
                transmission_budget=budget,
            )
        )
        connection = client.transport.connection_pool.connections[0]
        return results, connection

    def test_budgeted_import_receipts_and_send_counts(self) -> None:
        budget = TransmissionBudget(4)
        results, connection = self._run_import(budget)

        # transport layer actually sent 4 times: chunk(a,b), retry of b,
        # transport-internal retry of the 503, chunk(c)
        self.assertEqual(4, len(connection.calls))
        bodies = [call[0][3] for call in connection.calls]
        # a succeeded on the first send and is never part of a retry
        self.assertIn(b'"a"', bodies[0])
        self.assertNotIn(b'"a"', bodies[1])
        self.assertNotIn(b'"a"', bodies[2])
        # only the rejected b is resent by the helper layer
        self.assertIn(b'"b"', bodies[1])
        self.assertIn(b'"b"', bodies[2])
        # c and d were the last things sent before the budget ran out
        self.assertIn(b'"c"', bodies[3])
        self.assertIn(b'"d"', bodies[3])

        # every real transmission was charged to the shared budget
        self.assertEqual(4, budget.spent)
        self.assertEqual(0, budget.remaining)
        self.assertTrue(budget.exhausted)

        self.assertEqual(5, len(results))
        receipts = [receipt for ok, receipt in results]
        self.assertTrue(all(isinstance(r, TransmissionReceipt) for r in receipts))

        self.assertEqual(
            [True, False, False, False, False], [ok for ok, _ in results]
        )
        self.assertEqual(
            [
                ReceiptStatus.SUCCEEDED,
                ReceiptStatus.CONFIRMED_FAILURE,
                ReceiptStatus.UNCONFIRMED,
                ReceiptStatus.UNCONFIRMED,
                ReceiptStatus.UNSENT,
            ],
            [r.status for r in receipts],
        )
        # the confirmed failure and the unsent action explicitly allow
        # continuation; the unconfirmed one does not
        self.assertEqual(
            [False, True, False, False, True], [r.resumable for r in receipts]
        )
        self.assertEqual(2, receipts[1].attempts)
        self.assertEqual(0, receipts[4].attempts)

        # recovery only picks up the parts the receipts allow to continue
        recoverable = recoverable_actions(results)
        self.assertEqual(
            ["b", "e"], [action[0]["index"]["_id"] for action in recoverable]
        )

    def test_results_without_budget_keep_original_shape(self) -> None:
        script = [_bulk_response(("a", 200), ("b", 429))]
        client = OpenSearch(
            [{"script": script}], connection_class=ScriptedConnection
        )
        results = list(
            streaming_bulk(
                client,
                [{"_id": "a"}, {"_id": "b"}],
                chunk_size=2,
                raise_on_error=False,
            )
        )
        self.assertEqual(2, len(results))
        for ok, info in results:
            self.assertIsInstance(info, dict)
