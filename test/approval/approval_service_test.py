import asyncio

from datetime import timedelta
from test.approval.fake_endpoint import InMemoryFgaEndpoint
from unittest import IsolatedAsyncioTestCase

from openfga_sdk.approval import (
    Approval,
    ApprovalExpiredError,
    ApprovalRegistry,
    ApprovalService,
    ScopeViolation,
    TupleScope,
)
from openfga_sdk.client.models.batch_check_item import ClientBatchCheckItem
from openfga_sdk.client.models.batch_check_request import ClientBatchCheckRequest
from openfga_sdk.client.models.check_request import ClientCheckRequest
from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.client.models.write_request import ClientWriteRequest
from openfga_sdk.exceptions import RateLimitExceededError


def transient(error):
    return isinstance(error, RateLimitExceededError)


def tuple_dict(tuple_key):
    return {
        "user": tuple_key.user,
        "relation": tuple_key.relation,
        "object": tuple_key.object,
    }


class TestApprovalService(IsolatedAsyncioTestCase):
    def setUp(self):
        self.endpoint = InMemoryFgaEndpoint()
        self.registry = ApprovalRegistry()
        self.service = ApprovalService(self.endpoint, self.registry)

    def base_check(self, user="user:anne", relation="reader", obj="document:budget"):
        return ClientCheckRequest(user=user, relation=relation, object=obj)

    def temporary_tuples(self):
        return [
            ClientTuple(user="user:anne", relation="reader", object="document:budget"),
        ]

    async def test_scope_rejects_tuple_outside_approved_range(self):
        out_of_scope = [
            ClientTuple(user="user:anne", relation="reader", object="document:secret")
        ]

        with self.assertRaises(ScopeViolation):
            self.service.issue_approval(
                contextual_tuples=out_of_scope,
                scope=TupleScope(object="document:budget", relation="reader"),
            )

        # Nothing was registered when validation failed.
        self.assertEqual(self.registry.dispatch_log(), [])

    async def test_check_without_approval_keeps_existing_interface(self):
        body = self.base_check()
        response = await self.service.check(body)

        self.assertFalse(response.allowed)
        sent = self.endpoint.received_checks[0]
        self.assertIsNone(sent.contextual_tuples)
        self.assertEqual(self.registry.dispatch_log(), [])

    async def test_check_sends_only_approved_snapshot(self):
        caller_tuples = self.temporary_tuples()
        approval = self.service.issue_approval(
            contextual_tuples=caller_tuples,
            scope=TupleScope(object="document:budget"),
        )

        response = await self.service.check(self.base_check(), approval)

        self.assertTrue(response.allowed)
        sent = self.endpoint.received_checks[0]
        self.assertEqual(
            [tuple_dict(item) for item in sent.contextual_tuples],
            [tuple_dict(caller_tuples[0])],
        )

        records = self.registry.dispatches_for(approval.id)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].tuples[0].as_dict(), tuple_dict(caller_tuples[0]))

    async def test_interleaved_checks_isolate_mutated_caller_list_on_retry(self):
        caller_tuples = self.temporary_tuples()
        approval = self.service.issue_approval(
            contextual_tuples=caller_tuples,
            scope=TupleScope(object="document:budget", relation="reader"),
        )

        # The first physical send of check one fails transiently, but only
        # raises after the test releases this gate.
        failure_gate = asyncio.Event()
        self.endpoint.fail_next_check(
            RateLimitExceededError(503, "temporary"), gate=failure_gate
        )

        first = asyncio.create_task(
            self.service.check_with_retry(
                self.base_check(),
                approval,
                transient,
                max_attempts=3,
                retry_delay=0.05,
            )
        )

        # Wait until check one's first attempt has actually reached the
        # endpoint and is parked on the failure gate.
        while not self.endpoint.received_checks:
            await asyncio.sleep(0)
        self.assertEqual(len(self.endpoint.received_checks), 1)

        # While check one is blocked, the caller mutates the list they hold.
        caller_tuples.append(
            ClientTuple(user="user:mallory", relation="owner", object="document:budget")
        )

        # A second, approval-free check interleaves before check one retries.
        second_body = ClientCheckRequest(
            user="user:bob", relation="reader", object="document:budget"
        )
        second = asyncio.create_task(self.service.check(second_body))
        await asyncio.sleep(0)

        # Release the failed first attempt; its retry now races the backoff.
        failure_gate.set()
        first_response, second_response = await asyncio.gather(first, second)

        # The first attempt was check one; the plain second check landed before
        # the retry, so the retry is the third recorded request.
        self.assertEqual(len(self.endpoint.received_checks), 3)
        self.assertIs(self.endpoint.received_checks[0].object, "document:budget")

        retry_body = self.endpoint.received_checks[2]
        self.assertTrue(first_response.allowed)
        self.assertEqual(
            [tuple_dict(item) for item in retry_body.contextual_tuples],
            [tuple_dict(self.temporary_tuples()[0])],
        )
        self.assertNotIn(
            "user:mallory",
            [item.user for item in retry_body.contextual_tuples],
        )

        # Both physical attempts are traceable to the same approval.
        records = self.registry.dispatches_for(approval.id)
        self.assertEqual([record.attempt for record in records], [1, 2])
        for record in records:
            self.assertEqual(
                [dispatch.as_dict() for dispatch in record.tuples],
                [tuple_dict(self.temporary_tuples()[0])],
            )

        # The second (plain) check carries no temporary tuples at all.
        second_sent = self.endpoint.received_checks[1]
        self.assertIsNone(second_sent.contextual_tuples)
        self.assertFalse(second_response.allowed)

    async def test_retry_succeeds_while_approval_still_valid(self):
        approval = self.service.issue_approval(
            contextual_tuples=self.temporary_tuples(),
            scope=TupleScope(object="document:budget"),
            ttl=timedelta(minutes=5),
        )
        self.endpoint.fail_next_check(RateLimitExceededError(503, "temporary"))

        response = await self.service.check_with_retry(
            self.base_check(), approval, transient, max_attempts=3
        )

        self.assertTrue(response.allowed)
        self.assertEqual(len(self.endpoint.received_checks), 2)
        self.assertEqual(len(self.registry.dispatches_for(approval.id)), 2)

    async def test_retry_fails_fast_when_approval_expires_while_waiting(self):
        approval = self.service.issue_approval(
            contextual_tuples=self.temporary_tuples(),
            scope=TupleScope(object="document:budget"),
            ttl=timedelta(milliseconds=30),
        )
        self.endpoint.fail_next_check(RateLimitExceededError(503, "temporary"))

        # The first attempt is sent while the approval is valid, fails
        # transiently, and the approval lapses during the retry backoff.
        with self.assertRaises(ApprovalExpiredError):
            await self.service.check_with_retry(
                self.base_check(),
                approval,
                transient,
                max_attempts=3,
                retry_delay=0.05,
            )

        # Only the first attempt reached the endpoint; the retry was blocked.
        self.assertEqual(len(self.endpoint.received_checks), 1)
        records = self.registry.dispatches_for(approval.id)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].attempt, 1)

    async def test_expired_approval_is_rejected_even_without_failure(self):
        approval = self.service.issue_approval(
            contextual_tuples=self.temporary_tuples(),
            ttl=timedelta(milliseconds=1),
        )
        await asyncio.sleep(0.02)

        with self.assertRaises(ApprovalExpiredError):
            await self.service.check(self.base_check(), approval)

        self.assertEqual(self.endpoint.received_checks, [])

    async def test_batch_check_sends_each_rows_own_approved_tuples(self):
        shared_caller_list = self.temporary_tuples()
        approval_one = self.service.issue_approval(
            contextual_tuples=shared_caller_list,
            scope=TupleScope(object="document:budget"),
        )
        approval_two = self.service.issue_approval(
            contextual_tuples=[
                ClientTuple(
                    user="user:bob", relation="reader", object="document:roadmap"
                )
            ],
            scope=TupleScope(object="document:roadmap"),
        )

        # The caller mutates the shared list after issuing; the batch must not
        # see the extra tuple.
        shared_caller_list.append(
            ClientTuple(user="user:mallory", relation="owner", object="document:budget")
        )

        body = ClientBatchCheckRequest(
            checks=[
                ClientBatchCheckItem(
                    user="user:anne",
                    relation="reader",
                    object="document:budget",
                    correlation_id="row-1",
                ),
                ClientBatchCheckItem(
                    user="user:bob",
                    relation="reader",
                    object="document:roadmap",
                    correlation_id="row-2",
                ),
                ClientBatchCheckItem(
                    user="user:carol",
                    relation="reader",
                    object="document:budget",
                    correlation_id="row-3",
                ),
            ]
        )

        response = await self.service.batch_check(
            body, approvals={0: approval_one, 1: approval_two}
        )

        self.assertEqual(len(response.result), 3)
        self.assertTrue(response.result[0].allowed)
        self.assertTrue(response.result[1].allowed)
        self.assertFalse(response.result[2].allowed)

        sent_rows = self.endpoint.received_batches[0]
        self.assertEqual(
            sent_rows[0]["contextual_tuples"],
            [
                {
                    "user": "user:anne",
                    "relation": "reader",
                    "object": "document:budget",
                }
            ],
        )
        self.assertEqual(
            sent_rows[1]["contextual_tuples"],
            [
                {
                    "user": "user:bob",
                    "relation": "reader",
                    "object": "document:roadmap",
                }
            ],
        )
        # Row three had no approval and therefore no temporary tuples.
        self.assertEqual(sent_rows[2]["contextual_tuples"], [])
        for row in sent_rows:
            self.assertNotIn(
                "user:mallory",
                [item["user"] for item in row["contextual_tuples"]],
            )

        # One audit record per approved row, keyed by row index and approval.
        log = self.registry.dispatch_log()
        self.assertEqual(
            sorted((record.check_index, record.approval_id) for record in log),
            sorted(
                [
                    (0, approval_one.id),
                    (1, approval_two.id),
                ]
            ),
        )

    async def test_batch_check_expired_approval_blocks_that_row_only(self):
        expired = self.service.issue_approval(
            contextual_tuples=self.temporary_tuples(),
            ttl=timedelta(milliseconds=1),
        )
        await asyncio.sleep(0.02)

        body = ClientBatchCheckRequest(
            checks=[
                ClientBatchCheckItem(
                    user="user:anne",
                    relation="reader",
                    object="document:budget",
                    correlation_id="row-1",
                )
            ]
        )

        with self.assertRaises(ApprovalExpiredError):
            await self.service.batch_check(body, approvals={0: expired})

        self.assertEqual(self.endpoint.received_batches, [])

    async def test_temporary_tuples_never_persist_and_follow_up_is_clean(self):
        approval = self.service.issue_approval(
            contextual_tuples=self.temporary_tuples(),
            scope=TupleScope(object="document:budget"),
        )
        await self.service.check(self.base_check(), approval)

        # A persistent write of an unrelated tuple still works, and contains
        # none of the temporary relationships.
        persistent = ClientTuple(
            user="user:zoe", relation="reader", object="document:handbook"
        )
        await self.endpoint.write(ClientWriteRequest(writes=[persistent]))

        self.assertEqual(
            self.endpoint.persistent_tuples,
            [
                {
                    "user": "user:zoe",
                    "relation": "reader",
                    "object": "document:handbook",
                }
            ],
        )

        # A later ordinary check with no approval sends no contextual tuples.
        follow_up = await self.service.check(
            ClientCheckRequest(
                user="user:anne", relation="reader", object="document:budget"
            )
        )
        self.assertFalse(follow_up.allowed)
        self.assertIsNone(self.endpoint.received_checks[-1].contextual_tuples)

    async def test_approval_snapshot_is_independent_of_caller_list(self):
        caller_tuples = self.temporary_tuples()
        approval = Approval(caller_tuples, scope=TupleScope())

        caller_tuples.clear()
        materialized = approval.materialize()

        self.assertEqual(len(materialized), 1)
        self.assertEqual(materialized[0].user, "user:anne")
