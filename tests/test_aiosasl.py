########################################################################
# File name: test_aiosasl.py
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

from aiosasl.channel_binding import TLSUnique
from aiosasl.utils import xor_bytes


def run_coroutine(coroutine, timeout=1.0, loop=None):
    if not loop:
        loop = asyncio.get_event_loop()
    return loop.run_until_complete(
        asyncio.wait_for(
            coroutine,
            timeout=timeout))


class CoroutineMock(unittest.mock.Mock):
    delay = 0

    @asyncio.coroutine
    def __call__(self, *args, **kwargs):
        result = super().__call__(*args, **kwargs)
        yield from asyncio.sleep(self.delay)
        return result


class SASLInterfaceMock(aiosasl.SASLInterface):
    def __init__(self, testobj, action_sequence):
        super().__init__()
        self._testobj = testobj
        self._action_sequence = action_sequence

    def _check_action(self, action, payload):
        try:
            (next_action,
             next_payload,
             new_state,
             result_payload) = self._action_sequence.pop(0)
        except ValueError:
            raise AssertionError(
                "SASL action performed unexpectedly: "
                "{} with payload {}".format(
                    action,
                    payload))

        self._state = new_state

        self._testobj.assertEqual(
            action,
            next_action,
            "SASL action sequence violated")

        self._testobj.assertEqual(
            payload,
            next_payload,
            "SASL payload expectation violated")

        if new_state == "failure" and action != "abort":
            opaque_error, text = result_payload
            raise aiosasl.SASLFailure(opaque_error, text=text)

        if result_payload is not None:
            result_payload = result_payload

        return new_state, result_payload

    async def initiate(self, mechanism, payload=None):
        return self._check_action("auth;"+mechanism, payload)

    async def respond(self, payload):
        return self._check_action("response", payload)

    async def abort(self):
        return self._check_action("abort", None)

    def finalize(self):
        self._testobj.assertFalse(
            self._action_sequence,
            "Not all actions performed")


class TestSASLState(unittest.TestCase):

    def test_from_reply(self):
        self.assertEqual(
            aiosasl.SASLState.from_reply("success"),
            aiosasl.SASLState.SUCCESS
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply("failure"),
            aiosasl.SASLState.FAILURE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply("challenge"),
            aiosasl.SASLState.CHALLENGE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.SUCCESS),
            aiosasl.SASLState.SUCCESS
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.FAILURE),
            aiosasl.SASLState.FAILURE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.CHALLENGE),
            aiosasl.SASLState.CHALLENGE
        )

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply("initial"),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply("success-simulate-initial"),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply(aiosasl.SASLState.INITIAL),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply(
                aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE),


class TestSASLStateMachine(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.intf = unittest.mock.Mock()
        self.intf.initiate = CoroutineMock()
        self.intf.respond = CoroutineMock()
        self.intf.abort = CoroutineMock()
        self.sm = aiosasl.SASLStateMachine(self.intf)

        self.intf.initiate.return_value = (aiosasl.SASLState.SUCCESS, None)

    def test_initiate_calls_to_interface(self):
        result = run_coroutine(
            self.sm.initiate("foo", b"bar")
        )

        self.intf.initiate.assert_called_with(
            "foo",
            payload=b"bar")

        self.assertEqual(
            run_coroutine(self.intf.initiate()),
            result
        )

    def test_reject_double_initiate(self):
        run_coroutine(self.sm.initiate("foo", b"bar"))

        with self.assertRaisesRegex(RuntimeError,
                                    "has already been called"):
            run_coroutine(self.sm.initiate("foo"))

    def test_reject_double_initiate_after_error(self):
        opaque_error = object()
        self.intf.initiate.side_effect = aiosasl.SASLFailure(
            opaque_error
        )

        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(self.sm.initiate("foo", b"bar"))

        with self.assertRaisesRegex(RuntimeError,
                                    "has already been called"):
            run_coroutine(self.sm.initiate("foo"))

    def test_reject_response_without_challenge(self):
        with self.assertRaisesRegex(RuntimeError,
                                    "no challenge"):
            run_coroutine(self.sm.response(b"bar"))

    def test_response_calls_to_interface(self):
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.return_value = (aiosasl.SASLState.SUCCESS, None)

        result = run_coroutine(
            self.sm.response(b"bar")
        )

        self.intf.respond.assert_called_with(b"bar")

        self.assertEqual(
            run_coroutine(self.intf.initiate()),
            result
        )

    def test_response_failure(self):
        opaque_error = object()
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.side_effect = aiosasl.SASLFailure(
            opaque_error
        )

        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(
                self.sm.response(b"bar")
            )

        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_reject_abort_without_initiate(self):
        with self.assertRaises(RuntimeError):
            run_coroutine(self.sm.abort())

    def test_abort_calls_to_interface(self):
        self.sm._state = "challenge"
        self.intf.abort.return_value = ("failure", None)

        self.assertEqual(
            ("failure", None),
            run_coroutine(self.sm.abort())
        )

        self.intf.abort.assert_called_with()
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_abort_set_to_failure_and_re_raise_exceptions(self):
        exc = Exception()
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.abort.side_effect = exc

        with self.assertRaises(Exception) as ctx:
            run_coroutine(self.sm.abort())

        self.assertIs(ctx.exception, exc)

        self.intf.abort.assert_called_with()
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_success_simulated_challenge(self):
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.return_value = ("success", b"payload")
        state, payload = run_coroutine(self.sm.response(b"foobar"))
        self.assertEqual(self.sm._state,
                         aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE)
        self.assertEqual(state, aiosasl.SASLState.CHALLENGE)
        self.assertEqual(payload, b"payload")
        state, payload = run_coroutine(self.sm.response(b""))
        self.assertEqual(state, aiosasl.SASLState.SUCCESS)
        self.assertEqual(payload, None)

    def test_success_simulated_challenge_protocol_violation(self):
        self.sm._state = aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE
        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(self.sm.response(b"not-empty"))
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def tearDown(self):
        del self.sm
        del self.intf
        del self.loop


class TestPLAIN(unittest.TestCase):
    def test_rfc(self):
        user = "tim"
        password = "tanstaaftanstaaf"

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf",
                 "success",
                 None)
            ]))

        async def provide_credentials(*args):
            return user, password

        async def run():
            plain = aiosasl.PLAIN(provide_credentials)
            await plain.authenticate(
                smmock,
                "PLAIN",
            )

        asyncio.get_event_loop().run_until_complete(run())

        smmock.interface.finalize()

    def test_fail_on_protocol_violation(self):
        user = "tim"
        password = "tanstaaftanstaaf"

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf",
                 "challenge",
                 b"foo")
            ]))

        async def provide_credentials(*args):
            return user, password

        async def run():
            plain = aiosasl.PLAIN(provide_credentials)
            await plain.authenticate(
                smmock,
                "PLAIN")

        with self.assertRaisesRegex(aiosasl.SASLFailure,
                                    "protocol violation") as ctx:
            asyncio.get_event_loop().run_until_complete(run())

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

        smmock.interface.finalize()

    def test_reject_NUL_bytes_in_username(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
            ]))

        async def provide_credentials(*args):
            return "\0", "foo"

        with self.assertRaises(ValueError):
            run_coroutine(
                aiosasl.PLAIN(provide_credentials).authenticate(
                    smmock,
                    "PLAIN")
            )

    def test_reject_NUL_bytes_in_password(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
            ]))

        async def provide_credentials(*args):
            return "foo", "\0"

        with self.assertRaises(ValueError):
            run_coroutine(
                aiosasl.PLAIN(provide_credentials).authenticate(
                    smmock,
                    "PLAIN",
                )
            )

    def test_does_not_apply_saslprep(self):
        user = "tim"
        password = "2ø'±s;ßà¼Å"

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0" + password.encode("utf-8"),
                 "success",
                 None)
            ]))

        async def provide_credentials(*args):
            return user, password

        async def run():
            plain = aiosasl.PLAIN(provide_credentials)
            await plain.authenticate(
                smmock,
                "PLAIN",
            )

        asyncio.get_event_loop().run_until_complete(run())

        smmock.interface.finalize()

    def test_supports_PLAIN(self):
        self.assertEqual(
            "PLAIN",
            aiosasl.PLAIN.any_supported(["PLAIN"])
        )

    def test_does_not_support_SCRAM(self):
        self.assertIsNone(
            aiosasl.PLAIN.any_supported(["SCRAM-SHA-1"])
        )


class TestSCRAMNegotiation(unittest.TestCase):
    def test_supports_SCRAM_famliy(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}".format(hashname)
            self.assertEqual(
                (mechanism, unittest.mock.ANY),
                aiosasl.SCRAM.any_supported([mechanism])
            )

    def test_supports_SCRAMPLUS_famliy(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}-PLUS".format(hashname)
            self.assertEqual(
                (mechanism, unittest.mock.ANY),
                aiosasl.SCRAMPLUS.any_supported([mechanism])
            )

    def test_pick_longest_hash_SCRAM(self):
        self.assertEqual(
            ("SCRAM-SHA-256", unittest.mock.ANY),
            aiosasl.SCRAM.any_supported([
                "SCRAM-SHA-1",
                "SCRAM-SHA-256",
                "PLAIN",
            ])
        )

    def test_no_support_for_unregistered_functions(self):
        self.assertEqual(
            ("SCRAM-SHA-256", unittest.mock.ANY),
            aiosasl.SCRAM.any_supported([
                "SCRAM-SHA-1",
                "SCRAM-SHA-256",
                "SCRAM-SHA-512",
                "PLAIN",
            ])
        )

    def test_pick_longest_hash_SCRAMPLUS(self):
        self.assertEqual(
            ("SCRAM-SHA-256-PLUS", unittest.mock.ANY),
            aiosasl.SCRAMPLUS.any_supported([
                "SCRAM-SHA-1-PLUS",
                "SCRAM-SHA-256-PLUS",
                "SCRAM-SHA-224-PLUS",
                "PLAIN",
            ])
        )

    def test_reject_scram_plus_SCRAM(self):
        hashes = ["SHA-1", "SHA-224", "SHA-256",
                  "SHA-512", "SHA-384", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}-PLUS".format(hashname)
            self.assertIsNone(
                aiosasl.SCRAM.any_supported([mechanism])
            )

    def test_reject_scram_SCRAMPLUS(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}".format(hashname)
            self.assertIsNone(
                aiosasl.SCRAMPLUS.any_supported([mechanism])
            )

    def test_reject_md5_SCRAM(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-MD5"])
        )

    def test_reject_md5_SCRAMPLUS(self):
        self.assertIsNone(
            aiosasl.SCRAMPLUS.any_supported(["SCRAM-MD5-PLUS"])
        )

    def test_reject_unknown_hash_functions_SCRAM(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-FOOBAR"])
        )

    def test_reject_unknown_hash_functions_SCRAMPLUS(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-FOOBAR-PLUS"])
        )

    def test_parse_message_reject_long_keys_SCRAM(self):
        with self.assertRaisesRegex(Exception, "protocol violation"):
            list(aiosasl.SCRAM.parse_message(b"foo=bar"))

    def test_parse_message_reject_long_keys_SCRAMPLUS(self):
        with self.assertRaisesRegex(Exception, "protocol violation"):
            list(aiosasl.SCRAMPLUS.parse_message(b"foo=bar"))

    def test_parse_message_reject_m_key_SCRAM(self):
        with self.assertRaisesRegex(Exception, "protocol violation"):
            list(aiosasl.SCRAM.parse_message(b"m=bar"))

    def test_parse_message_reject_m_key_SCRAMPLUS(self):
        with self.assertRaisesRegex(Exception, "protocol violation"):
            list(aiosasl.SCRAMPLUS.parse_message(b"m=bar"))

    def test_parse_message_unescape_n_and_a_payload_SCRAM(self):
        data = list(aiosasl.SCRAM.parse_message(
            b"n=foo=2Cbar=3Dbaz,"
            b"a=fnord=2Cfunky=3Dfunk",
        ))
        self.assertSequenceEqual(
            [
                (b"n", b"foo,bar=baz"),
                (b"a", b"fnord,funky=funk")
            ],
            data
        )

    def test_parse_message_unescape_n_and_a_payload_SCRAMPLUS(self):
        data = list(aiosasl.SCRAMPLUS.parse_message(
            b"n=foo=2Cbar=3Dbaz,a=fnord=2Cfunky=3Dfunk"))
        self.assertSequenceEqual(
            [
                (b"n", b"foo,bar=baz"),
                (b"a", b"fnord,funky=funk")
            ],
            data
        )


class TestSCRAMImpl:
    def setUp(self):
        self.hashfun_factory = hashlib.sha1
        self.digest_size = self.hashfun_factory().digest_size
        self.user = b"user"
        self.user2 = "user\U0001f916".encode("utf-8")
        self.password = b"pencil"
        self.salt = b"QSXCR+Q6sek8bf92"

        aiosasl.scram._system_random = unittest.mock.MagicMock()
        aiosasl.scram._system_random.getrandbits.return_value = \
            int.from_bytes(b"foo", "little")

        self.salted_password = hashlib.pbkdf2_hmac(
            "sha1",
            self.password,
            self.salt,
            4096,
            self.digest_size)

        self.salted_password_4000 = hashlib.pbkdf2_hmac(
            "sha1",
            self.password,
            self.salt,
            4000,
            self.digest_size)

        self.salted_password_5000 = hashlib.pbkdf2_hmac(
            "sha1",
            self.password,
            self.salt,
            5000,
            self.digest_size)

        self.client_key = hmac.new(
            self.salted_password,
            b"Client Key",
            self.hashfun_factory).digest()

        self.client_key_4000 = hmac.new(
            self.salted_password_4000,
            b"Client Key",
            self.hashfun_factory).digest()

        self.client_key_5000 = hmac.new(
            self.salted_password_5000,
            b"Client Key",
            self.hashfun_factory).digest()

        self.stored_key = self.hashfun_factory(
            self.client_key).digest()

        self.stored_key_4000 = self.hashfun_factory(
            self.client_key_4000).digest()

        self.stored_key_5000 = self.hashfun_factory(
            self.client_key_5000).digest()

        self.client_first_message_bare = b"n=user,r=Zm9vAAAAAAAAAAAAAAAA"
        self.client_first_message_bare2 = \
            b"n="+self.user2+b",r=Zm9vAAAAAAAAAAAAAAAA"
        self.server_first_message = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=4096"
        ])
        self.server_first_message_4000 = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=4000"
        ])
        self.server_first_message_5000 = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=5000"
        ])

        if self._scram_plus == 'no':
            self.client_final_message_without_proof = (
                b"c=biws,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        elif self._scram_plus == 'supported':
            self.client_final_message_without_proof = (
                b"c=eSws,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        elif self._scram_plus == 'active':
            self.client_final_message_without_proof = (
                b"c=cD10bHMtdW5pcXVlLCxjaGFubmVsIGJpbmRpbmcgZGF0YQ==,"
                b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        else:
            raise Exception("invalid scram mode")

        self.auth_message = b",".join([
            self.client_first_message_bare,
            self.server_first_message,
            self.client_final_message_without_proof
        ])

        self.auth_message2 = b",".join([
            self.client_first_message_bare2,
            self.server_first_message,
            self.client_final_message_without_proof
        ])

        self.auth_message_4000 = b",".join([
            self.client_first_message_bare,
            self.server_first_message_4000,
            self.client_final_message_without_proof
        ])

        self.auth_message_5000 = b",".join([
            self.client_first_message_bare,
            self.server_first_message_5000,
            self.client_final_message_without_proof
        ])

        self.client_signature = hmac.new(
            self.stored_key,
            self.auth_message,
            self.hashfun_factory).digest()

        self.client_signature2 = hmac.new(
            self.stored_key,
            self.auth_message2,
            self.hashfun_factory).digest()

        self.client_signature_4000 = hmac.new(
            self.stored_key_4000,
            self.auth_message_4000,
            self.hashfun_factory).digest()

        self.client_signature_5000 = hmac.new(
            self.stored_key_5000,
            self.auth_message_5000,
            self.hashfun_factory).digest()

        self.client_proof = xor_bytes(self.client_signature, self.client_key)
        self.client_proof2 = xor_bytes(self.client_signature2, self.client_key)
        self.client_proof_4000 = xor_bytes(self.client_signature_4000,
                                           self.client_key_4000)
        self.client_proof_5000 = xor_bytes(self.client_signature_5000,
                                           self.client_key_5000)

        self.server_key = hmac.new(
            self.salted_password,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_key_4000 = hmac.new(
            self.salted_password_4000,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_key_5000 = hmac.new(
            self.salted_password_5000,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_signature = hmac.new(
            self.server_key,
            self.auth_message,
            self.hashfun_factory).digest()
        self.server_signature2 = hmac.new(
            self.server_key,
            self.auth_message2,
            self.hashfun_factory).digest()
        self.server_signature_4000 = hmac.new(
            self.server_key_4000,
            self.auth_message_4000,
            self.hashfun_factory).digest()
        self.server_signature_5000 = hmac.new(
            self.server_key_5000,
            self.auth_message_5000,
            self.hashfun_factory).digest()

        self._tls_connection = unittest.mock.Mock()
        self._tls_connection.get_finished = unittest.mock.Mock()
        self._tls_connection.get_finished.return_value = \
            b'channel binding data'

    async def _provide_credentials(self, *args):
        return ("user", "pencil")

    def _run(self, smmock, scram):
        info = aiosasl.scram.Base._supported_hashalgos["SHA-1"]
        if self._scram_plus in ('no', 'supported'):
            token = ("SCRAM-SHA-1", info)
        else:
            token = ("SCRAM-SHA-1-PLUS", info)

        result = asyncio.get_event_loop().run_until_complete(
            scram.authenticate(smmock, token)
        )
        smmock.interface.finalize()
        return result

    def tearDown(self):
        import random
        aiosasl.scram._system_random = random.SystemRandom()


class TestSCRAM(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'no'

    def test_rfc(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials)
        )

    def test_unassigned_password_codepoints(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            []))

        async def provide_credentials(*args):
            return ("user", "\U0001f916")

        with self.assertRaisesRegex(ValueError, "unassigned"):
            self._run(
                smmock,
                aiosasl.SCRAM(provide_credentials)
            )

    def test_unassigned_username_codepoints(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare2,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof2),
                 "success",
                 b"v="+base64.b64encode(self.server_signature2))
            ]))

        async def provide_credentials(*args):
            return (self.user2.decode("utf-8"), self.password.decode("utf-8"))

        self._run(
            smmock,
            aiosasl.SCRAM(provide_credentials)
        )

    def test_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"s=hut,t=hefu,c=kup,d=onny"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_other_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"i=sometext,s=ABC,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_incorrect_nonce(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"r=foobar,s="+base64.b64encode(self.salt)+b",i=4096"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaisesRegex(aiosasl.SASLFailure, "nonce") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIsNone(ctx.exception.opaque_error)

    def test_invalid_signature(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(b"fnord"))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIsNone(ctx.exception.opaque_error)
        self.assertIn(
            "signature",
            str(ctx.exception).lower()
        )

    def test_promote_failure_to_authentication_failure(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "failure",
                 ("credentials-expired", None))
            ]))

        with self.assertRaises(aiosasl.AuthenticationFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            "credentials-expired",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation_1(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 None),
            ]))

        with self.assertRaisesRegex(aiosasl.SASLFailure,
                                    "protocol violation") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            "malformed-request",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation_2(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "success", None),
                ("abort", None,
                 "failure", ("aborted", None)),
            ]))

        with self.assertRaisesRegex(aiosasl.SASLFailure,
                                    "protocol violation") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

    def test_too_low_iteration_count(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message.replace(b",i=4096", b",i=4095")),
                ("abort", None,
                 "failure", ("aborted", None)),
            ]))

        with self.assertRaisesRegex(
                aiosasl.SASLFailure,
                r"minimum iteration count for SCRAM-SHA-1 violated "
                r"\(4095 is less than 4096\)") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

    def test_too_low_iteration_count_without_enforcement(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message_4000),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof_4000),
                 "success",
                 b"v="+base64.b64encode(self.server_signature_4000))
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(
                self._provide_credentials,
                enforce_minimum_iteration_count=False,
            )
        )

    def test_high_iteration_count(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message_5000),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof_5000),
                 "success",
                 b"v="+base64.b64encode(self.server_signature_5000))
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials)
        )


class TestSCRAMDowngradeProtection(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'supported'

    def test_rfc_with_downgrade_protection(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"y,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials, after_scram_plus=True)
        )


class TestSCRAMPLUS(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'active'

    def test_rfc(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self._run(
            smmock,
            aiosasl.SCRAMPLUS(
                self._provide_credentials,
                TLSUnique(self._tls_connection)
            )
        )

    def test_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"s=hut,t=hefu,c=kup,d=onny"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_other_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"i=sometext,s=ABC,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_incorrect_nonce(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"r=foobar,s="+base64.b64encode(self.salt)+b",i=4096"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaisesRegex(aiosasl.SASLFailure, "nonce") as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIsNone(ctx.exception.opaque_error)

    def test_invalid_signature(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(b"fnord"))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIsNone(ctx.exception.opaque_error)
        self.assertIn(
            "signature",
            str(ctx.exception).lower()
        )

    def test_promote_failure_to_authentication_failure(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "failure",
                 ("credentials-expired", None))
            ]))

        with self.assertRaises(aiosasl.AuthenticationFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertEqual(
            "credentials-expired",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p="+base64.b64encode(self.client_proof),
                 "challenge",
                 b"foo"),
                ("response", b"", "success", b"bar")
            ]))

        with self.assertRaisesRegex(aiosasl.SASLFailure,
                                    "protocol violation") as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )


class TestANONYMOUS(unittest.TestCase):
    def test_accepts_ANONYMOUS(self):
        self.assertIsNotNone(
            aiosasl.ANONYMOUS.any_supported(["ANONYMOUS"])
        )

    def test_passes_token_through_trace(self):
        with unittest.mock.patch("aiosasl.stringprep.trace") as trace:
            trace.return_value = "traced"

            anon = aiosasl.ANONYMOUS(unittest.mock.sentinel.token)

        trace.assert_called_with(unittest.mock.sentinel.token)

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;ANONYMOUS",
                 b"traced",
                 "success",
                 None)
            ]))

        async def run():
            await anon.authenticate(
                smmock,
                "ANONYMOUS")

        run_coroutine(run())

        smmock.interface.finalize()

    def test_simply_sends_token(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;ANONYMOUS",
                 b"sirhc",
                 "success",
                 None)
            ]))

        async def run():
            anon = aiosasl.ANONYMOUS("sirhc")
            await anon.authenticate(
                smmock,
                "ANONYMOUS")

        run_coroutine(run())

        smmock.interface.finalize()


class TestAuthzidEncoding(unittest.TestCase):
    def test_plain_without_authzid_is_unchanged(self):
        self.assertEqual(
            aiosasl.encode_plain_payload("tim", "tanstaaftanstaaf"),
            b"\0tim\0tanstaaftanstaaf",
        )

    def test_plain_with_authzid_uses_leading_nul_field(self):
        self.assertEqual(
            aiosasl.encode_plain_payload(
                "svc",
                "geheim",
                "alice",
            ),
            b"alice\0svc\0geheim",
        )

    def test_plain_rejects_nul_in_authzid(self):
        with self.assertRaisesRegex(ValueError, "authzid"):
            aiosasl.encode_plain_payload("svc", "geheim", "alice\0admin")

    def test_plain_rejects_nul_in_authcid(self):
        with self.assertRaisesRegex(ValueError, "authcid"):
            aiosasl.encode_plain_payload("sv\0c", "geheim", "alice")

    def test_plain_rejects_nul_in_password(self):
        with self.assertRaisesRegex(ValueError, "password"):
            aiosasl.encode_plain_payload("svc", "ge\0heim", "alice")

    def test_plain_reader_separates_identities(self):
        parsed = aiosasl.parse_plain_client_response(
            b"alice\0svc\0geheim"
        )
        self.assertEqual(parsed.authzid, b"alice")
        self.assertEqual(parsed.authcid, b"svc")
        self.assertEqual(parsed.password, b"geheim")

    def test_plain_reader_legacy_shape_has_no_authzid(self):
        parsed = aiosasl.parse_plain_client_response(
            b"\0svc\0geheim"
        )
        self.assertIsNone(parsed.authzid)
        self.assertEqual(parsed.authcid, b"svc")

    def test_plain_reader_rejects_extra_separator(self):
        with self.assertRaisesRegex(ValueError, "NUL"):
            aiosasl.parse_plain_client_response(
                b"alice\0svc\0ge\0heim"
            )

    def test_gs2_header_escapes_comma_and_equals(self):
        header = aiosasl.build_gs2_header(b"n", "a,b=c")
        self.assertEqual(header, b"n,a=a=2Cb=3Dc,")
        parsed = aiosasl.parse_gs2_header(header)
        self.assertEqual(parsed.flag, b"n")
        self.assertEqual(parsed.authzid, b"a,b=c")

    def test_gs2_header_preserves_literal_escape_lookalike(self):
        header = aiosasl.build_gs2_header(b"n", "a=2Cb")
        self.assertEqual(header, b"n,a=a=3D2Cb,")
        self.assertEqual(
            aiosasl.parse_gs2_header(header).authzid,
            b"a=2Cb",
        )

    def test_gs2_header_without_authzid_is_legacy_shape(self):
        self.assertEqual(aiosasl.build_gs2_header(b"n"), b"n,,")
        self.assertEqual(aiosasl.build_gs2_header(b"y"), b"y,,")
        self.assertEqual(
            aiosasl.build_gs2_header(b"p=tls-unique"),
            b"p=tls-unique,,",
        )

    def test_gs2_reader_rejects_bad_separator_or_escape(self):
        with self.assertRaisesRegex(ValueError, "GS2"):
            aiosasl.parse_gs2_header(b"n,a=alice")
        with self.assertRaisesRegex(ValueError, "escape"):
            aiosasl.parse_gs2_header(b"n,a=al=ZZice,")

    def test_scram_authzid_is_prepared_as_stored_string(self):
        with self.assertRaisesRegex(ValueError, "unassigned"):
            aiosasl.encode_scram_authzid("\U0001f916")

    def test_scram_authcid_allows_unassigned_codepoints(self):
        self.assertEqual(
            aiosasl.encode_scram_authcid("user\U0001f916"),
            "user\U0001f916".encode("utf-8"),
        )

    def test_scram_reader_keeps_both_identities_separate(self):
        payload = (
            b"n,a=a=2Cadmin,"
            b"n=svc,r=Zm9v"
        )
        parsed = aiosasl.parse_scram_client_first(payload)
        self.assertEqual(parsed.gs2.authzid, b"a,admin")
        self.assertEqual(parsed.authcid, b"svc")
        self.assertEqual(parsed.nonce, b"Zm9v")
        self.assertEqual(parsed.bare, b"n=svc,r=Zm9v")

    def test_scram_reader_rejects_swapped_fields(self):
        with self.assertRaisesRegex(ValueError, "authentication identity"):
            aiosasl.parse_scram_client_first(b"n,,r=Zm9v,n=svc")

    def test_scram_client_final_reads_authzid_from_channel_binding(self):
        gs2 = aiosasl.build_gs2_header(b"p=tls-unique", "alice")
        channel_binding = gs2 + b"channel binding data"
        payload = (
            b"c=" + base64.b64encode(channel_binding) +
            b",r=Zm9v,p=cHJvb2Y="
        )

        parsed = aiosasl.parse_scram_client_final(payload)
        self.assertEqual(parsed.gs2.authzid, b"alice")
        self.assertEqual(parsed.channel_binding_data, b"channel binding data")
        self.assertEqual(parsed.nonce, b"Zm9v")
        self.assertEqual(parsed.proof, b"cHJvb2Y=")

    def test_scram_client_final_rejects_duplicate_fields(self):
        gs2 = aiosasl.build_gs2_header(b"n")
        payload = (
            b"c=" + base64.b64encode(gs2) +
            b",r=a,r=b,p=cHJvb2Y="
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            aiosasl.parse_scram_client_final(payload)


class TestAuthzidResolution(unittest.TestCase):
    def test_no_request_uses_authcid(self):
        result = aiosasl.resolve_authorization(
            "svc",
            None,
            mapping={"svc": {"alice"}},
        )
        self.assertEqual(result.effective_identity, "svc")
        self.assertFalse(result.delegated)
        self.assertEqual(result.source, "implicit")

    def test_request_without_trusted_grant_is_refused(self):
        with self.assertRaises(aiosasl.AuthorizationFailure) as ctx:
            aiosasl.resolve_authorization("svc", "alice")
        self.assertEqual(ctx.exception.authcid, "svc")
        self.assertEqual(ctx.exception.authzid, "alice")

    def test_request_not_in_mapping_is_refused(self):
        with self.assertRaises(aiosasl.AuthorizationFailure):
            aiosasl.resolve_authorization(
                "svc",
                "alice",
                mapping={"svc": {"bob"}},
            )

    def test_mapping_is_scoped_to_authcid(self):
        with self.assertRaises(aiosasl.AuthorizationFailure):
            aiosasl.resolve_authorization(
                "other-svc",
                "alice",
                mapping={"svc": {"alice"}},
            )

    def test_mapping_grants_delegation(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            mapping={"svc": {"alice"}},
        )
        self.assertEqual(result.authcid, "svc")
        self.assertEqual(result.requested_authzid, "alice")
        self.assertEqual(result.effective_identity, "alice")
        self.assertTrue(result.delegated)
        self.assertEqual(result.source, "mapping")

    def test_server_identity_grants_delegation(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            server_identity="alice",
        )
        self.assertEqual(result.effective_identity, "alice")
        self.assertEqual(result.source, "server")

    def test_server_identity_wins_over_mapping(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            server_identity="alice",
            mapping={"svc": set()},
        )
        self.assertEqual(result.source, "server")

    def test_server_may_report_another_effective_identity(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            server_identity="role-operator",
        )
        self.assertEqual(result.effective_identity, "role-operator")
        self.assertEqual(result.source, "server")

    def test_server_may_map_request_to_role(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            server_identity="role-operator",
            mapping={"svc": set()},
        )
        self.assertEqual(result.effective_identity, "role-operator")
        self.assertTrue(result.delegated)
        self.assertEqual(result.source, "server")

    def test_callable_mapping_grants_delegation(self):
        seen = []

        def grant(authcid, authzid):
            seen.append((authcid, authzid))
            return authzid == "alice"

        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            mapping=grant,
        )
        self.assertEqual(result.effective_identity, "alice")
        self.assertEqual(result.source, "mapping")
        self.assertEqual(seen, [("svc", "alice")])

    def test_callable_mapping_can_refuse(self):
        with self.assertRaises(aiosasl.AuthorizationFailure):
            aiosasl.resolve_authorization(
                "svc",
                "alice",
                mapping=lambda authcid, authzid: False,
            )

    def test_empty_request_is_treated_as_absent(self):
        result = aiosasl.resolve_authorization("svc", "")
        self.assertIsNone(result.requested_authzid)
        self.assertEqual(result.effective_identity, "svc")
        self.assertFalse(result.delegated)

    def test_failure_is_a_sasl_error_but_not_authentication_failure(self):
        exc = aiosasl.AuthorizationFailure("svc", "alice")
        self.assertIsInstance(exc, aiosasl.SASLError)
        self.assertNotIsInstance(exc, aiosasl.AuthenticationFailure)
        self.assertIn("authorization failed", str(exc))

    def test_server_decline_does_not_delegate(self):
        result = aiosasl.resolve_authorization(
            "svc",
            "alice",
            server_identity="svc",
            mapping={"svc": {"alice"}},
        )
        self.assertEqual(result.effective_identity, "svc")
        self.assertFalse(result.delegated)


class TestPLAINAuthzid(unittest.TestCase):
    def test_wire_payload_with_authzid(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"alice\0tim\0tanstaaftanstaaf",
                 "success",
                 None)
            ]))

        async def provide_credentials():
            return "tim", "tanstaaftanstaaf"

        run_coroutine(
            aiosasl.PLAIN(
                provide_credentials,
                authzid="alice",
            ).authenticate(smmock, "PLAIN")
        )

        smmock.interface.finalize()

    def test_reader_sees_distinct_identities(self):
        parsed = aiosasl.parse_plain_client_response(
            aiosasl.encode_plain_payload("svc", "secret", "alice")
        )
        self.assertEqual(parsed.authcid, b"svc")
        self.assertEqual(parsed.authzid, b"alice")
        self.assertNotEqual(parsed.authcid, parsed.authzid)

    def test_without_authzid_wire_shape_is_unchanged(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf",
                 "success",
                 None)
            ]))

        async def provide_credentials():
            return "tim", "tanstaaftanstaaf"

        run_coroutine(
            aiosasl.PLAIN(provide_credentials).authenticate(
                smmock,
                "PLAIN",
            )
        )

        smmock.interface.finalize()

    def test_plain_authzid_is_literal_and_not_gs2_escaped(self):
        parsed = aiosasl.parse_plain_client_response(
            aiosasl.encode_plain_payload("svc", "secret", "a,b=c")
        )
        self.assertEqual(parsed.authzid, b"a,b=c")

    def test_reject_nul_authzid_before_sending(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(self, []))

        async def provide_credentials():
            return "svc", "secret"

        with self.assertRaisesRegex(ValueError, "authzid"):
            run_coroutine(
                aiosasl.PLAIN(
                    provide_credentials,
                    authzid="alice\0admin",
                ).authenticate(smmock, "PLAIN")
            )

        self.assertEqual(smmock._state, aiosasl.SASLState.INITIAL)

    def test_empty_authzid_keeps_legacy_payload(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0svc\0secret",
                 "success",
                 None)
            ]))

        async def provide_credentials():
            return "svc", "secret"

        run_coroutine(
            aiosasl.PLAIN(
                provide_credentials,
                authzid="",
            ).authenticate(smmock, "PLAIN")
        )

        smmock.interface.finalize()


class TestSCRAMAuthzid(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = "no"

    def _expected_final(self, gs2_header):
        client_final = (
            b"c=" + base64.b64encode(gs2_header) +
            b",r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"
        )
        auth_message = b",".join([
            self.client_first_message_bare,
            self.server_first_message,
            client_final,
        ])
        client_signature = hmac.new(
            self.stored_key,
            auth_message,
            self.hashfun_factory,
        ).digest()
        proof = xor_bytes(client_signature, self.client_key)
        server_signature = hmac.new(
            self.server_key,
            auth_message,
            self.hashfun_factory,
        ).digest()
        return (
            client_final + b",p=" + base64.b64encode(proof),
            b"v=" + base64.b64encode(server_signature),
        )

    def test_fixed_transcript_with_authzid(self):
        gs2_header = b"n,a=alice,"
        expected_response, expected_success = self._expected_final(gs2_header)

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 gs2_header + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 expected_response,
                 "success",
                 expected_success),
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(
                self._provide_credentials,
                authzid="alice",
            )
        )

    def test_reader_sees_both_identities_in_fixed_transcript(self):
        first = aiosasl.parse_scram_client_first(
            aiosasl.build_gs2_header(b"n", "alice") +
            self.client_first_message_bare
        )
        self.assertEqual(first.gs2.authzid, b"alice")
        self.assertEqual(first.authcid, b"user")

        final, _ = self._expected_final(first.gs2.raw)
        parsed_final = aiosasl.parse_scram_client_final(final)
        self.assertEqual(parsed_final.gs2.authzid, b"alice")
        self.assertEqual(parsed_final.gs2.raw, first.gs2.raw)
        self.assertEqual(
            parsed_final.nonce,
            first.nonce + b"3rfcNHYJY1ZVvWVs7j",
        )

    def test_authzid_is_gs2_escaped_in_transcript(self):
        gs2_header = b"n,a=a=2Cadmin=3Dops,"
        expected_response, expected_success = self._expected_final(gs2_header)

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 gs2_header + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 expected_response,
                 "success",
                 expected_success),
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(
                self._provide_credentials,
                authzid="a,admin=ops",
            )
        )

        parsed = aiosasl.parse_scram_client_first(
            gs2_header + self.client_first_message_bare
        )
        self.assertEqual(parsed.gs2.authzid, b"a,admin=ops")

    def test_without_authzid_transcript_is_unchanged(self):
        # The legacy fixed transcript from TestSCRAM.test_rfc.
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,," + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p=" + base64.b64encode(self.client_proof),
                 "success",
                 b"v=" + base64.b64encode(self.server_signature)),
            ]))

        self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

    def test_empty_authzid_keeps_legacy_gs2_header(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,," + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p=" + base64.b64encode(self.client_proof),
                 "success",
                 b"v=" + base64.b64encode(self.server_signature)),
            ]))

        self._run(
            smmock,
            aiosasl.SCRAM(
                self._provide_credentials,
                authzid="",
            ),
        )

    def test_reject_unassigned_authzid_before_sending(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(self, []))

        with self.assertRaisesRegex(ValueError, "unassigned"):
            self._run(
                smmock,
                aiosasl.SCRAM(
                    self._provide_credentials,
                    authzid="\U0001f916",
                ),
            )


class TestSCRAMPLUSAuthzid(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = "active"

    def test_fixed_transcript_with_authzid_and_channel_binding(self):
        gs2_header = b"p=tls-unique,a=alice,"
        cb_data = b"channel binding data"
        client_final = (
            b"c=" + base64.b64encode(gs2_header + cb_data) +
            b",r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"
        )
        auth_message = b",".join([
            self.client_first_message_bare,
            self.server_first_message,
            client_final,
        ])
        client_signature = hmac.new(
            self.stored_key,
            auth_message,
            self.hashfun_factory,
        ).digest()
        proof = xor_bytes(client_signature, self.client_key)
        server_signature = hmac.new(
            self.server_key,
            auth_message,
            self.hashfun_factory,
        ).digest()

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 gs2_header + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 client_final + b",p=" + base64.b64encode(proof),
                 "success",
                 b"v=" + base64.b64encode(server_signature)),
            ]))

        self._run(
            smmock,
            aiosasl.SCRAMPLUS(
                self._provide_credentials,
                TLSUnique(self._tls_connection),
                authzid="alice",
            )
        )

        parsed = aiosasl.parse_scram_client_final(
            client_final + b",p=" + base64.b64encode(proof)
        )
        self.assertEqual(parsed.gs2.authzid, b"alice")
        self.assertEqual(parsed.gs2.flag, b"p=tls-unique")
        self.assertEqual(parsed.channel_binding_data, cb_data)

    def test_without_authzid_transcript_is_unchanged(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,," + self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                 b",p=" + base64.b64encode(self.client_proof),
                 "success",
                 b"v=" + base64.b64encode(self.server_signature)),
            ]))

        self._run(
            smmock,
            aiosasl.SCRAMPLUS(
                self._provide_credentials,
                TLSUnique(self._tls_connection),
            )
        )
