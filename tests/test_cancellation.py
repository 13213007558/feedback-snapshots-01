########################################################################
# File name: test_cancellation.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
import asyncio
import base64
import hashlib
import hmac
import unittest
import unittest.mock

import aiosasl
import aiosasl.scram


def run_coroutine(coroutine, timeout=1.0, loop=None):
    if not loop:
        loop = asyncio.get_event_loop()
    return loop.run_until_complete(
        asyncio.wait_for(
            coroutine,
            timeout=timeout))


class PausableSASLInterface(aiosasl.SASLInterface):
    """
    A SASL interface whose reply futures can be held open by the test.

    Every transmission is recorded in :attr:`sent` together with the
    payload. A reply is only delivered once the test calls :meth:`resolve`
    (or :meth:`fail`). Replies scheduled after a cancellation are delivered
    by a detached pump task, which models the real transport: the peer can
    still send a late response even though the local coroutine has stopped
    waiting for it.
    """

    def __init__(self):
        self.sent = []
        self.pending = []
        self.abort_calls = 0
        self._pumps = []

    def _make_pending(self, action, payload):
        self.sent.append((action, payload))
        future = asyncio.get_event_loop().create_future()
        self.pending.append(future)
        return future

    async def initiate(self, mechanism, payload=None):
        return await self._make_pending("auth;" + mechanism, payload)

    async def respond(self, payload):
        return await self._make_pending("response", payload)

    async def abort(self):
        self.abort_calls += 1
        return await self._make_pending("abort", None)

    def _schedule(self, callback):
        # detached task: keeps delivering even if the original consumer was
        # cancelled (its future then transitions to CANCELLED and the
        # result is simply dropped)
        async def pump():
            await asyncio.sleep(0)
            callback()

        task = asyncio.get_event_loop().create_task(pump())
        self._pumps.append(task)

    def resolve(self, value):
        future = self.pending.pop(0)

        def deliver():
            if not future.done():
                future.set_result(value)

        self._schedule(deliver)

    def fail(self, exc):
        future = self.pending.pop(0)

        def deliver():
            if not future.done():
                future.set_exception(exc)

        self._schedule(deliver)

    def drain_pumps(self):
        return asyncio.gather(*self._pumps)


class TestCancellationSemantics(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.intf = PausableSASLInterface()
        self.sm = aiosasl.SASLStateMachine(self.intf)

    def tearDown(self):
        # let any scheduled late replies land before checking for leftover
        # work
        if self.intf._pumps:
            self.loop.run_until_complete(self.intf.drain_pumps())

        # the state machine must never leave background tasks behind:
        # after every scenario the loop has no pending work
        pending = [
            task for task in asyncio.all_tasks(self.loop)
            if not task.done()
        ]
        self.assertEqual(pending, [])
        del self.sm
        del self.intf
        del self.loop

    def _start(self, coroutine):
        task = self.loop.create_task(coroutine)
        self.loop.run_until_complete(asyncio.sleep(0))
        return task

    def _resolve_and_await(self, task, value):
        self.intf.resolve(value)
        return self.loop.run_until_complete(task)

    def test_cancel_credential_fetch_does_not_touch_transport(self):
        async def failing_provider():
            await asyncio.sleep(1000)

        async def run():
            plain = aiosasl.PLAIN(failing_provider)
            await plain.authenticate(self.sm, "PLAIN")

        task = self._start(run())

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        # the credential was never obtained, so not even the initiation
        # request may have been transmitted
        self.assertEqual(self.intf.sent, [])
        self.assertEqual(self.intf.abort_calls, 0)
        self.assertEqual(self.sm._state, aiosasl.SASLState.INITIAL)

    def test_cancel_initiate_marks_indefinite_failure_and_propagates(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))

        self.assertEqual(
            self.intf.sent,
            [("auth;PLAIN", b"payload")],
        )

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        # nothing else was sent, in particular no abort
        self.assertEqual(len(self.intf.sent), 1)
        self.assertEqual(self.intf.abort_calls, 0)

    def test_late_success_after_cancelled_initiate_does_not_recover(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        # the server answers late, with success -- nobody consumes it
        self.intf.resolve((aiosasl.SASLState.SUCCESS, None))
        self.loop.run_until_complete(asyncio.sleep(0))

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        with self.assertRaisesRegex(RuntimeError, "indefinite failure"):
            run_coroutine(self.sm.initiate("PLAIN"))
        with self.assertRaisesRegex(RuntimeError, "indefinite failure"):
            run_coroutine(self.sm.response(b""))
        with self.assertRaisesRegex(RuntimeError, "indefinite failure"):
            run_coroutine(self.sm.abort())

    def test_cancel_response_prevents_further_proof_from_being_sent(self):
        task = self._start(self.sm.initiate("PLAIN", b"first"))
        state, payload = self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"server-data"),
        )
        self.assertEqual(state, aiosasl.SASLState.CHALLENGE)
        self.assertEqual(payload, b"server-data")

        task = self._start(self.sm.response(b"proof"))
        self.assertEqual(
            self.intf.sent[-1],
            ("response", b"proof"),
        )

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        # a late success from the peer cannot resurrect the exchange
        self.intf.resolve((aiosasl.SASLState.SUCCESS, b"final-data"))
        self.loop.run_until_complete(asyncio.sleep(0))

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        # exactly the two expected transmissions, nothing in the background
        self.assertEqual(
            self.intf.sent,
            [
                ("auth;PLAIN", b"first"),
                ("response", b"proof"),
            ],
        )

    def test_cancel_abort_is_indefinite_and_keeps_cancellation(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        task = self._start(self.sm.abort())
        self.assertEqual(self.intf.abort_calls, 1)

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )

    def test_confirmed_abort_enters_failure_state(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        task = self._start(self.sm.abort())
        result = self._resolve_and_await(
            task,
            (aiosasl.SASLState.FAILURE, None),
        )

        self.assertEqual(result, (aiosasl.SASLState.FAILURE, None))
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_legacy_string_failure_reply_confirms_abort(self):
        # interfaces may still use the string states supported by
        # SASLState.from_reply; a string "failure" still confirms the abort
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        task = self._start(self.sm.abort())
        result = self._resolve_and_await(task, ("failure", None))

        self.assertEqual(result, ("failure", None))
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_indefinite_failure_rejects_even_a_second_abort(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        task = self._start(self.sm.abort())
        self.intf.resolve((aiosasl.SASLState.SUCCESS, None))
        with self.assertRaises(aiosasl.SASLFailure):
            self.loop.run_until_complete(task)

        with self.assertRaisesRegex(RuntimeError, "indefinite failure"):
            run_coroutine(self.sm.abort())

    def test_unexpected_success_on_abort_cannot_establish_identity(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        task = self._start(self.sm.abort())
        self.intf.resolve((aiosasl.SASLState.SUCCESS, None))

        with self.assertRaises(aiosasl.SASLFailure):
            self.loop.run_until_complete(task)

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        self.assertNotEqual(self.sm._state, aiosasl.SASLState.SUCCESS)

    def test_abort_failure_exception_is_confirmed_failure(self):
        task = self._start(self.sm.initiate("PLAIN", b"payload"))
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.CHALLENGE, b"go"),
        )

        opaque_error = object()
        task = self._start(self.sm.abort())
        self.intf.fail(aiosasl.SASLFailure(opaque_error))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self.loop.run_until_complete(task)
        self.assertIs(ctx.exception.opaque_error, opaque_error)
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_scram_cancelled_before_proof_does_not_send_proof(self):
        user = "user"
        password = "pencil"
        salt = b"QSXCR+Q6sek8bf92"
        hashfun_factory = hashlib.sha1
        digest_size = hashfun_factory().digest_size
        salted_password = hashlib.pbkdf2_hmac(
            "sha1", password.encode("utf-8"), salt, 4096, digest_size)
        client_key = hmac.new(
            salted_password, b"Client Key", hashfun_factory).digest()

        aiosasl.scram._system_random = unittest.mock.MagicMock()
        aiosasl.scram._system_random.getrandbits.return_value = \
            int.from_bytes(b"foo", "little")

        async def provide_credentials():
            return user, password

        scram = aiosasl.SCRAM(provide_credentials)
        info = aiosasl.scram.Base._supported_hashalgos["SHA-1"]
        token = ("SCRAM-SHA-1", info)

        task = self._start(scram.authenticate(self.sm, token))

        # only the client-first-message has gone onto the wire
        self.assertEqual(len(self.intf.sent), 1)
        self.assertTrue(self.intf.sent[0][0].startswith("auth;"))

        server_first = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(salt),
            b",i=4096",
        ])
        self.intf.resolve((aiosasl.SASLState.CHALLENGE, server_first))
        self.loop.run_until_complete(asyncio.sleep(0))

        # the client proof is now ready and the response is in flight
        self.assertEqual(len(self.intf.sent), 2)
        self.assertEqual(self.intf.sent[1][0], "response")
        proof_payload = self.intf.sent[1][1]
        self.assertIn(b",p=", proof_payload)

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            self.loop.run_until_complete(task)

        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        # a late server success cannot make the proof exchange succeed
        self.intf.resolve((
            aiosasl.SASLState.SUCCESS,
            b"v=" + base64.b64encode(b"bogus"),
        ))
        self.loop.run_until_complete(asyncio.sleep(0))
        self.assertEqual(
            self.sm._state,
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
        # no third transmission ever happened
        self.assertEqual(len(self.intf.sent), 2)

        import random
        aiosasl.scram._system_random = random.SystemRandom()

    def test_fresh_state_machine_authenticates_normally(self):
        async def provide_credentials():
            return "tim", "tanstaaftanstaaf"

        async def run():
            plain = aiosasl.PLAIN(provide_credentials)
            await plain.authenticate(self.sm, "PLAIN")

        task = self._start(run())
        self._resolve_and_await(
            task,
            (aiosasl.SASLState.SUCCESS, None),
        )

        self.assertEqual(self.sm._state, aiosasl.SASLState.SUCCESS)
        self.assertEqual(
            self.intf.sent,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf"),
            ],
        )

    def test_indefinite_failure_is_not_acceptably_returned_by_interface(self):
        # the internal state must never be injectable via an interface reply
        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply(
                aiosasl.SASLState.INDEFINITE_FAILURE)


class TestIndefiniteFailureState(unittest.TestCase):
    def test_state_member_and_value(self):
        self.assertEqual(
            aiosasl.SASLState.INDEFINITE_FAILURE.value,
            "indefinite-failure",
        )
        self.assertIs(
            aiosasl.SASLState("indefinite-failure"),
            aiosasl.SASLState.INDEFINITE_FAILURE,
        )
