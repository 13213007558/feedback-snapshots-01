# Copyright 2026-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test audit subscriptions against local change stream doubles.

These tests run without a MongoDB server. Two doubles stand in for change
stream cursors backed by one logical deployment: `Approved` keeps delivering
changes while the institution approves the scope, and `Withdrawn` is a copy of
the same changes whose scope is withdrawn while the client is disconnected.
The assertions record the order in which events were processed, the resume
points, and the requests that actually reached the "server".
"""

from __future__ import annotations

import sys
from typing import Any, Mapping

sys.path[0:0] = [""]

from bson import Timestamp
from pymongo.asynchronous.audit import AsyncAuditCursor, AsyncAuditSubscription
from pymongo.audit_shared import AuditBatch, AuditResumePoint, AuditTrail
from pymongo.errors import ConnectionFailure, PyMongoError, ScopeRevokedError
from test.asynchronous import AsyncUnitTest

_IS_SYNC = False

SCOPE = "audit.events"
OTHER_SCOPE = "audit.other"


def _ts(time: int) -> Timestamp:
    return Timestamp(time, 1)


def _change(time: int, operation: str = "insert", scope: str = SCOPE) -> dict:
    """Return a change event shaped like a MongoDB change stream document."""
    return {
        "_id": {"_data": f"token-{time}"},
        "operationType": operation,
        "clusterTime": _ts(time),
        "ns": {"db": scope.split(".", 1)[0], "coll": scope.split(".", 1)[1]},
    }


def _batch(*times: int, cursor_id: int = 1, scope: str = SCOPE) -> AuditBatch:
    changes = [_change(time, scope=scope) for time in times]
    token = {"_data": f"pbrt-{times[-1]}"} if times else None
    return AuditBatch(changes, token, cursor_id, operation_time=_ts(times[-1]) if times else None)


class ChangeStreamDouble:
    """A local change stream double standing in for one deployment.

    Each `aggregate` opens a cursor that serves the rest of `script`. The
    double records every command that reached it, including the `aggregate`
    commands issued to open a stream or to resume one, which is how the tests
    prove that a refused resume never left the client.

    :param name: The label used in failure messages.
    :param clock: The cluster time the double attaches to empty batches.
    :param script: The server responses each getMore returns in order. A
        response is an `AuditBatch`, or a `PyMongoError` that breaks the
        connection.
    """

    def __init__(
        self,
        name: str,
        clock: Timestamp,
        script: list[AuditBatch | PyMongoError],
        scope: str = SCOPE,
    ):
        self.name = name
        self.scope = scope
        self.clock = clock
        self.script = script
        self.requests: list[dict] = []
        self.received_requests: list[dict] = []
        self.resume_points: list[AuditResumePoint | None] = []
        self._offset = 0
        self.down = False

    def issued(self, request: Mapping[str, Any], point: AuditResumePoint | None) -> None:
        self.requests.append(dict(request))
        self.resume_points.append(point)

    def statement(self, point: AuditResumePoint | None) -> dict:
        """Return the command this double would receive at `point`."""
        change_stream: dict[str, Any] = {}
        if point is not None:
            change_stream["resumeAfter"] = point.token
        return {
            "aggregate": self.scope.split(".", 1)[1],
            "pipeline": [{"$changeStream": change_stream}],
        }

    async def open(self, point: AuditResumePoint | None) -> DoubleCursor:
        request = self.statement(point)
        self.issued(request, point)
        if self.down:
            raise ConnectionFailure(f"{self.name} is unreachable")
        self.received_requests.append(dict(request))
        return DoubleCursor(self, request)

    def take(self) -> AuditBatch | PyMongoError:
        """Return the next scripted response for a getMore."""
        if self._offset >= len(self.script):
            return AuditBatch([], None, 0, self.clock)
        response = self.script[self._offset]
        self._offset += 1
        return response


class DoubleCursor(AsyncAuditCursor):
    """A change stream cursor double that serves one double's script."""

    def __init__(self, server: ChangeStreamDouble, request: dict) -> None:
        super().__init__(request)
        self._server = server

    async def next_batch(self) -> AuditBatch:
        if self._server.down:
            raise ConnectionFailure(f"{self._server.name} disconnected")
        response = self._server.take()
        if isinstance(response, PyMongoError):
            raise response
        return response

    async def close(self) -> None:
        pass


async def subscribe(scope: str, trail: AuditTrail, server: ChangeStreamDouble, point):
    """Open an audit subscription against a double."""
    subscription = AsyncAuditSubscription(scope, trail, server.open, point)
    await subscription._initialize()
    return subscription


class TestAsyncAuditSubscription(AsyncUnitTest):
    """Exercise audit subscriptions without a server."""

    async def test_withdrawal_during_disconnection_stops_delivery(self):
        """A withdrawal during a disconnection blocks the buffered event and the resume."""
        trail = AuditTrail()
        server = ChangeStreamDouble("withdrawn", _ts(10), [_batch(1), _batch(2)])
        subscription = await subscribe(
            SCOPE, trail, server, AuditResumePoint(_ts(0), {"_data": "start"})
        )

        self.assertEqual(await subscription.next(), _change(1))
        # The caller keeps the last known resume point to resume from.
        held = subscription.resume_point
        self.assertEqual(held.cluster_time, _ts(1))

        # The deployment becomes unreachable while the client is disconnected,
        # and the withdrawal lands during the same outage.
        server.down = True
        with self.assertRaises(ConnectionFailure):
            await subscription.next()
        trail.revoke(SCOPE, _ts(1), "institution withdrew the range")

        # The caller still has `held`, and the next batch may already be cached
        # on the client. Neither may be used to deliver withdrawn changes.
        with self.assertRaises(ScopeRevokedError):
            await subscription.next()
        self.assertFalse(subscription.alive)

        # The server saw the opening aggregate and the one resume attempt made
        # during the outage. The resume after the withdrawal never reached it.
        self.assertEqual(
            [request["pipeline"][0]["$changeStream"] for request in server.requests],
            [{"resumeAfter": {"_data": "start"}}, {"resumeAfter": {"_data": "pbrt-1"}}],
        )
        kinds = [record["kind"] for record in trail.events]
        self.assertEqual(
            kinds,
            [
                "stream_opened",
                "batch_received",
                "delivered",
                "disconnected",
                "resume_attempted",
                "disconnected",
                "scope_revoked",
                "resume_attempted",
                "resume_refused",
            ],
            kinds,
        )
        withdrawn_at = next(record for record in trail.events if record["kind"] == "scope_revoked")
        self.assertEqual(withdrawn_at["revocation_time"], _ts(1))
        refused = trail.events[-1]
        self.assertEqual(refused["resume_point"]["cluster_time"], _ts(1))
        self.assertNotIn("request", refused)

    async def test_two_doubles_record_order_points_and_actual_resumes(self):
        """The approved double resumes while the disconnected revoked double stops."""
        trail = AuditTrail()
        approved = ChangeStreamDouble(
            "approved",
            _ts(30),
            [_batch(11, scope=OTHER_SCOPE), _batch(12, 13, scope=OTHER_SCOPE)],
            scope=OTHER_SCOPE,
        )
        revoked = ChangeStreamDouble("revoked", _ts(30), [_batch(21, 22), _batch(23)], scope=SCOPE)

        approved_subscription = await subscribe(
            OTHER_SCOPE,
            trail,
            approved,
            AuditResumePoint(_ts(10), {"_data": "approved-start"}, OTHER_SCOPE),
        )
        revoked_subscription = await subscribe(
            SCOPE,
            trail,
            revoked,
            AuditResumePoint(_ts(20), {"_data": "revoked-start"}, SCOPE),
        )
        self.addAsyncCleanup(approved_subscription.close)
        self.addAsyncCleanup(revoked_subscription.close)

        self.assertEqual(await approved_subscription.next(), _change(11, scope=OTHER_SCOPE))
        self.assertEqual(await revoked_subscription.next(), _change(21))
        held_point = revoked_subscription.resume_point
        self.assertEqual(held_point.cluster_time, _ts(21))
        self.assertEqual(held_point.token, {"_data": "token-21"})

        # Event 22 is already buffered. Probe the now-broken cursor without
        # delivering that buffered event, recording the disconnection.
        approved.down = True
        revoked.down = True
        with self.assertRaises(ConnectionFailure):
            await approved_subscription.next()
        await revoked_subscription._fetch()

        trail.revoke_scope(SCOPE, "institution withdrew the scope")

        with self.assertRaises(ScopeRevokedError):
            await revoked_subscription.next()
        with self.assertRaises(ScopeRevokedError):
            await revoked_subscription.next()
        self.assertEqual(revoked_subscription.resume_point, held_point)
        self.assertFalse(revoked_subscription.alive)

        # The caller still holds `held_point`; an explicit resume after the
        # withdrawal is refused before any command reaches either double.
        resumer = AsyncAuditSubscription(SCOPE, trail, revoked.open, held_point)
        with self.assertRaises(ScopeRevokedError):
            await resumer._resume()

        # Recovery of the approved deployment preserves its compliant resume.
        approved.down = False
        self.assertEqual(await approved_subscription.next(), _change(12, scope=OTHER_SCOPE))
        self.assertEqual(await approved_subscription.next(), _change(13, scope=OTHER_SCOPE))
        self.assertEqual(approved_subscription.resume_token, {"_data": "pbrt-13"})

        kinds = [record["kind"] for record in trail.events]
        self.assertEqual(
            kinds,
            [
                "stream_opened",
                "stream_opened",
                "batch_received",
                "delivered",
                "batch_received",
                "delivered",
                "disconnected",
                "resume_attempted",
                "disconnected",
                "disconnected",
                "scope_revoked",
                "delivery_blocked",
                "resume_attempted",
                "resume_refused",
                "resume_attempted",
                "resume_issued",
                "batch_received",
                "delivered",
                "delivered",
            ],
            kinds,
        )

        delivered = [
            record["resume_point"]["token"]["_data"]
            for record in trail.events
            if record["kind"] == "delivered"
        ]
        self.assertEqual(
            delivered,
            ["pbrt-11", "token-21", "token-12", "pbrt-13"],
            delivered,
        )
        blocked = next(record for record in trail.events if record["kind"] == "delivery_blocked")
        self.assertEqual(blocked["blocked_token"], {"_data": "token-22"})
        self.assertEqual(blocked["resume_point"]["token"], {"_data": "token-21"})

        issued_resumes = trail.actual_resume_requests
        self.assertEqual(len(issued_resumes), 1)
        self.assertEqual(issued_resumes[0]["scope"], OTHER_SCOPE)
        self.assertEqual(
            issued_resumes[0]["request"]["pipeline"][0]["$changeStream"],
            {"resumeAfter": {"_data": "pbrt-11"}},
        )

        def change_stream_commands(server: ChangeStreamDouble, received_only: bool):
            requests = server.received_requests if received_only else server.requests
            return [request["pipeline"][0]["$changeStream"] for request in requests]

        self.assertEqual(
            change_stream_commands(approved, received_only=True),
            [
                {"resumeAfter": {"_data": "approved-start"}},
                {"resumeAfter": {"_data": "pbrt-11"}},
            ],
        )
        self.assertEqual(
            change_stream_commands(approved, received_only=False),
            [
                {"resumeAfter": {"_data": "approved-start"}},
                {"resumeAfter": {"_data": "pbrt-11"}},
                {"resumeAfter": {"_data": "pbrt-11"}},
            ],
        )
        self.assertEqual(
            change_stream_commands(revoked, received_only=True),
            [{"resumeAfter": {"_data": "revoked-start"}}],
        )
        self.assertEqual(
            change_stream_commands(revoked, received_only=False),
            [{"resumeAfter": {"_data": "revoked-start"}}],
        )

    async def test_approved_scope_resumes_and_keeps_delivering(self):
        """The approved double resumes after the same disconnection and delivers every event."""
        trail = AuditTrail()
        server = ChangeStreamDouble("approved", _ts(10), [_batch(1), _batch(2, 3)])
        subscription = await subscribe(
            SCOPE, trail, server, AuditResumePoint(_ts(0), {"_data": "start"})
        )
        self.addAsyncCleanup(subscription.close)

        self.assertEqual(await subscription.next(), _change(1))
        server.down = True
        with self.assertRaises(ConnectionFailure):
            await subscription.next()
        server.down = False

        # A later call resumes from the acknowledged point and gets the rest.
        self.assertEqual(await subscription.next(), _change(2))
        self.assertEqual(await subscription.next(), _change(3))

        issued = [request["pipeline"][0]["$changeStream"] for request in server.requests]
        self.assertEqual(
            issued,
            [
                {"resumeAfter": {"_data": "start"}},
                {"resumeAfter": {"_data": "pbrt-1"}},
                {"resumeAfter": {"_data": "pbrt-1"}},
            ],
        )
        kinds = [record["kind"] for record in trail.events]
        self.assertEqual(
            kinds,
            [
                "stream_opened",
                "batch_received",
                "delivered",
                "disconnected",
                "resume_attempted",
                "disconnected",
                "resume_attempted",
                "resume_issued",
                "batch_received",
                "delivered",
                "delivered",
            ],
            kinds,
        )
        resumed = trail.events[7]
        self.assertEqual(resumed["resume_point"]["cluster_time"], _ts(1))
        self.assertEqual(
            resumed["request"]["pipeline"][0]["$changeStream"],
            {"resumeAfter": {"_data": "pbrt-1"}},
        )
        self.assertEqual(subscription.resume_token, {"_data": "pbrt-3"})

    async def test_two_doubles_share_one_ledger(self):
        """Withdrawing one scope leaves the other scope resuming normally."""
        trail = AuditTrail()
        approved = ChangeStreamDouble(
            "approved", _ts(10), [_batch(1, scope=OTHER_SCOPE), _batch(2, scope=OTHER_SCOPE)]
        )
        withdrawn = ChangeStreamDouble("withdrawn", _ts(10), [_batch(4), _batch(5)])
        approved_subscription = await subscribe(OTHER_SCOPE, trail, approved, None)
        withdrawn_subscription = await subscribe(
            SCOPE, trail, withdrawn, AuditResumePoint(_ts(0), {"_data": "start"})
        )
        self.addAsyncCleanup(approved_subscription.close)

        self.assertEqual(await withdrawn_subscription.next(), _change(4))
        withdrawn.down = True
        with self.assertRaises(ConnectionFailure):
            await withdrawn_subscription.next()
        trail.revoke(SCOPE, _ts(4), "institution withdrew the range")

        self.assertEqual(await approved_subscription.next(), _change(1, scope=OTHER_SCOPE))
        self.assertEqual(await approved_subscription.next(), _change(2, scope=OTHER_SCOPE))
        with self.assertRaises(ScopeRevokedError):
            await withdrawn_subscription.next()

        # The withdrawal is checked when the stream is opened and once more
        # before a resume is issued, so the withdrawn double received only the
        # resume attempt made during its outage.
        self.assertEqual(
            [request["pipeline"][0]["$changeStream"] for request in withdrawn.requests],
            [{"resumeAfter": {"_data": "start"}}, {"resumeAfter": {"_data": "pbrt-4"}}],
        )

    async def test_withdrawn_start_point_is_refused_before_server_command(self):
        """Opening from a withdrawn resume point fails without issuing a command."""
        trail = AuditTrail()
        trail.revoke(SCOPE, _ts(5), "range withdrawn")
        server = ChangeStreamDouble("unused", _ts(10), [])

        with self.assertRaises(ScopeRevokedError):
            await subscribe(SCOPE, trail, server, AuditResumePoint(_ts(5), {"_data": "x"}))
        self.assertEqual(server.requests, [])
        kinds = [record["kind"] for record in trail.events]
        self.assertEqual(kinds, ["scope_revoked", "open_refused"])

    async def test_full_scope_revocation_blocks_new_open_future_point_and_buffer(self):
        """A full-scope withdrawal denies fresh opens, future points, and buffers."""
        trail = AuditTrail()
        trail.revoke_scope(SCOPE, "scope access removed")
        server = ChangeStreamDouble("fully-revoked", _ts(10), [_batch(100)])

        with self.assertRaises(ScopeRevokedError):
            await subscribe(SCOPE, trail, server, None)
        with self.assertRaises(ScopeRevokedError):
            await subscribe(SCOPE, trail, server, AuditResumePoint(_ts(999), {"_data": "future"}))
        self.assertEqual(server.requests, [])

        trail = AuditTrail()
        server = ChangeStreamDouble("cached-full", _ts(10), [_batch(1, 100)])
        subscription = await subscribe(SCOPE, trail, server, None)
        self.assertEqual(await subscription.next(), _change(1))
        trail.revoke_scope(SCOPE)
        with self.assertRaises(ScopeRevokedError):
            await subscription.next()
        self.assertFalse(subscription.alive)

    async def test_withdrawal_at_start_does_not_block_later_changes(self):
        """A change after the withdrawal time is delivered normally."""
        trail = AuditTrail()
        trail.revoke(SCOPE, _ts(2), "range withdrawn")
        server = ChangeStreamDouble("later", _ts(10), [_batch(3)])
        subscription = await subscribe(
            SCOPE, trail, server, AuditResumePoint(_ts(3), {"_data": "after"})
        )
        self.assertEqual(await subscription.next(), _change(3))

    async def test_empty_batch_token_is_used_for_the_real_resume(self):
        """An empty batch's post-batch token is the next durable resume point."""
        trail = AuditTrail()
        empty_batch = AuditBatch([], {"_data": "pbrt-5"}, 1, _ts(5))
        server = ChangeStreamDouble("empty-batch", _ts(10), [empty_batch, _batch(6)])
        subscription = await subscribe(SCOPE, trail, server, None)

        await subscription._fetch()
        self.assertEqual(subscription.resume_point.cluster_time, _ts(5))
        self.assertEqual(subscription.resume_token, {"_data": "pbrt-5"})

        server.down = True
        with self.assertRaises(ConnectionFailure):
            await subscription.next()
        server.down = False

        self.assertEqual(await subscription.next(), _change(6))
        self.assertEqual(
            trail.actual_resume_requests[-1]["request"]["pipeline"][0]["$changeStream"],
            {"resumeAfter": {"_data": "pbrt-5"}},
        )
        self.assertEqual(
            [request["pipeline"][0]["$changeStream"] for request in server.received_requests],
            [{}, {"resumeAfter": {"_data": "pbrt-5"}}],
        )

    async def test_mid_batch_resume_point_does_not_skip_events(self):
        """The resume point stays at the last delivered event until the batch ends."""
        trail = AuditTrail()
        server = ChangeStreamDouble("mid-batch", _ts(10), [_batch(1, 2, 3), _batch(4)])
        subscription = await subscribe(SCOPE, trail, server, None)

        self.assertEqual(await subscription.next(), _change(1))
        # Only event 1 was delivered, so event 2 must still be replayable.
        self.assertEqual(subscription.resume_token, {"_data": "token-1"})
        # Events 2 and 3 arrive in the client's buffer; they do not advance the
        # resume point past themselves.
        self.assertEqual(subscription.resume_token, {"_data": "token-1"})
        self.assertEqual(await subscription.next(), _change(2))
        self.assertEqual(subscription.resume_token, {"_data": "token-2"})
        self.assertEqual(await subscription.next(), _change(3))
        # The batch is exhausted, so the server's post-batch token is adopted.
        self.assertEqual(subscription.resume_token, {"_data": "pbrt-3"})
        self.assertEqual(await subscription.next(), _change(4))

    async def test_buffered_event_is_blocked_even_without_a_resume(self):
        """An event cached before the withdrawal is never handed to the caller."""
        trail = AuditTrail()
        server = ChangeStreamDouble("cached", _ts(10), [_batch(1, 2)])
        subscription = await subscribe(SCOPE, trail, server, None)
        self.assertEqual(await subscription.next(), _change(1))
        # Event 2 is already cached on the client when the withdrawal lands.
        trail.revoke(SCOPE, _ts(2), "institution withdrew the range")
        with self.assertRaises(ScopeRevokedError):
            await subscription.next()
        blocked = trail.events[-1]
        self.assertEqual(blocked["kind"], "delivery_blocked")
        self.assertEqual(blocked["operation_type"], "insert")
