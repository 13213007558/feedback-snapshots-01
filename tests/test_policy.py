########################################################################
# File name: test_policy.py
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
import base64
import hashlib
import hmac
import typing
import unittest

from aiosasl import SASLInterface, SASLState, common
from aiosasl.channel_binding import ChannelBindingProvider
from aiosasl.utils import xor_bytes
from aiosasl.policy import (
    ClientCapabilities,
    MechanismCandidates,
    NoAcceptableMechanism,
    SASLPolicy,
    TransportSecurity,
    authenticate,
    select_mechanism,
)


USERNAME = "user"
PASSWORD = "pencil"
SALT = b"QSXCR+Q6sek8bf92"
ITERATIONS = 4096
CB_NAME = b"tls-unique"
CB_DATA = b"channel binding data"


class RecordingCredentialProvider:
    """Credential provider which records every invocation."""

    def __init__(self, username: str = USERNAME,
                 password: str = PASSWORD):
        self.calls = 0
        self._username = username
        self._password = password

    async def __call__(self) -> typing.Tuple[str, str]:
        self.calls += 1
        return self._username, self._password


class FakeChannelBindingProvider(ChannelBindingProvider):
    @property
    def cb_name(self) -> bytes:
        return CB_NAME

    def extract_cb_data(self) -> bytes:
        return CB_DATA


def _parse(msg: bytes) -> typing.Dict[bytes, bytes]:
    result = {}
    for part in msg.split(b","):
        if not part:
            continue
        key, _, value = part.partition(b"=")
        result[key] = value
    return result


class ScramServer:
    """Minimal SCRAM/SCRAM-PLUS server for driving happy paths."""

    def __init__(self, hash_name: str, expect_gs2: bytes,
                 expect_cb: typing.Optional[bytes],
                 reject_auth: bool = False):
        self._hash_name = hash_name
        self._expect_gs2 = expect_gs2
        self._expect_cb = expect_cb
        self._reject_auth = reject_auth
        self._auth_message = b""
        self._salted_password = b""
        self._nonce = b""
        self._done = False

    def initiate(self, mechanism: str,
                 payload: typing.Optional[bytes]
                 ) -> typing.Tuple[SASLState, typing.Optional[bytes]]:
        assert payload is not None
        gs2_end = payload.index(b",,") + 2
        gs2_header = payload[:gs2_end]
        self.assertEqual(gs2_header, self._expect_gs2)
        client_first_bare = payload[gs2_end:]
        first = _parse(client_first_bare)
        self._nonce = first[b"r"] + b"server-nonce"

        salted_password = hashlib.pbkdf2_hmac(
            self._hash_name,
            PASSWORD.encode("utf-8"),
            SALT,
            ITERATIONS,
        )
        self._salted_password = salted_password

        server_first = b"r=" + self._nonce + b",s=" + \
            base64.b64encode(SALT) + b",i=" + str(ITERATIONS).encode()
        self._auth_message = client_first_bare + b"," + server_first
        return SASLState.CHALLENGE, server_first

    def respond(self, payload: bytes
                ) -> typing.Tuple[SASLState, typing.Optional[bytes]]:
        if self._done:
            # Pseudo-challenge answer from the unfolded success.
            return SASLState.SUCCESS, None

        final = _parse(payload)
        cb_received = base64.b64decode(final[b"c"])
        if self._expect_cb is not None:
            expected = self._expect_gs2 + self._expect_cb
        else:
            expected = self._expect_gs2
        self.assertEqual(cb_received, expected)

        without_proof = payload[:payload.index(b",p=")]
        self._auth_message += b"," + without_proof

        client_key = hmac.new(
            self._salted_password, b"Client Key",
            self._hash_name).digest()
        stored_key = hashlib.new(
            self._hash_name, client_key).digest()
        client_signature = hmac.new(
            stored_key, self._auth_message,
            self._hash_name).digest()
        proof = base64.b64decode(final[b"p"])
        self.assertEqual(
            xor_bytes(client_signature, client_key), proof)

        if self._reject_auth:
            raise common.AuthenticationFailure(
                "invalid-credentials")

        server_key = hmac.new(
            self._salted_password, b"Server Key",
            self._hash_name).digest()
        server_signature = hmac.new(
            server_key, self._auth_message,
            self._hash_name).digest()
        server_final = b"v=" + base64.b64encode(server_signature)
        self._done = True
        return SASLState.SUCCESS, server_final

    def abort(self) -> None:
        raise common.SASLFailure("aborted")

    def assertEqual(self, first: typing.Any,
                    second: typing.Any) -> None:
        if first != second:
            raise AssertionError(
                "{!r} != {!r}".format(first, second))


class RecordingSASLInterface(SASLInterface):
    """
    Record-based SASL interface.  It records every action and either
    delegates to a :class:`ScramServer` or follows a fixed script.
    """

    def __init__(self, scram: typing.Optional[ScramServer] = None,
                 script: typing.Optional[typing.List[typing.Any]] = None):
        self.actions = []  # type: typing.List[typing.Tuple[str, str]]
        self._scram = scram
        self._script = list(script or [])

    async def initiate(self, mechanism: str,
                       payload: typing.Optional[bytes] = None
                       ) -> typing.Tuple[SASLState,
                                         typing.Optional[bytes]]:
        self.actions.append(("initiate", mechanism))
        if self._scram is not None:
            return self._scram.initiate(mechanism, payload)
        expected_mech, state, result = self._script.pop(0)
        assert mechanism == expected_mech
        return state, result

    async def respond(self, payload: bytes
                      ) -> typing.Tuple[SASLState,
                                        typing.Optional[bytes]]:
        self.actions.append(("respond", ""))
        if self._scram is not None:
            return self._scram.respond(payload)
        state, result = self._script.pop(0)
        return state, result

    async def abort(self) -> None:
        self.actions.append(("abort", ""))
        if self._scram is not None:
            self._scram.abort()
        raise common.SASLFailure("aborted")


def make_capabilities() -> typing.Tuple[
        ClientCapabilities, RecordingCredentialProvider]:
    provider = RecordingCredentialProvider()
    return (
        ClientCapabilities(credential_provider=provider),
        provider,
    )


def trusted_tls_with_cb() -> TransportSecurity:
    return TransportSecurity(
        tls_established=True,
        tls_verified=True,
        channel_binding=FakeChannelBindingProvider(),
    )


class TestTransportSecurity(unittest.TestCase):
    def test_cleartext_is_not_trusted(self):
        transport = TransportSecurity()
        self.assertFalse(transport.is_trusted)
        self.assertFalse(transport.channel_binding_available)

    def test_encrypted_but_unverified_is_not_trusted(self):
        transport = TransportSecurity(
            tls_established=True,
            tls_verified=False,
            channel_binding=FakeChannelBindingProvider(),
        )
        self.assertFalse(transport.is_trusted)
        self.assertFalse(transport.channel_binding_available)

    def test_verified_tls_without_cb_is_trusted_but_not_bound(self):
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        self.assertTrue(transport.is_trusted)
        self.assertFalse(transport.channel_binding_available)

    def test_verified_tls_with_cb(self):
        transport = trusted_tls_with_cb()
        self.assertTrue(transport.is_trusted)
        self.assertTrue(transport.channel_binding_available)


class TestMechanismSelection(unittest.TestCase):
    def test_plain_only_over_cleartext_is_rejected(self):
        capabilities, provider = make_capabilities()
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["PLAIN"],
                capabilities,
                TransportSecurity(),
                SASLPolicy(),
            )
        # Rejection happens before credentials are ever requested.
        self.assertEqual(provider.calls, 0)

    def test_plain_only_over_unverified_tls_is_rejected(self):
        capabilities, provider = make_capabilities()
        transport = TransportSecurity(
            tls_established=True, tls_verified=False)
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["PLAIN"], capabilities, transport, SASLPolicy())
        self.assertEqual(provider.calls, 0)

    def test_plain_allowed_on_trusted_transport(self):
        capabilities, provider = make_capabilities()
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        candidate = select_mechanism(
            ["PLAIN"], capabilities, transport, SASLPolicy())
        self.assertEqual(candidate.name, "PLAIN")
        self.assertTrue(candidate.sends_password)
        self.assertEqual(provider.calls, 0)

    def test_plain_disabled_by_policy_even_on_trusted_transport(self):
        capabilities, _ = make_capabilities()
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        policy = SASLPolicy(allow_plain=False)
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["PLAIN"], capabilities, transport, policy)

    def test_scram_rejected_over_cleartext(self):
        capabilities, provider = make_capabilities()
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["SCRAM-SHA-256"],
                capabilities,
                TransportSecurity(),
                SASLPolicy(),
            )
        self.assertEqual(provider.calls, 0)

    def test_scram_plus_preferred_when_cb_available(self):
        capabilities, _ = make_capabilities()
        advertised = [
            "SCRAM-SHA-256",
            "SCRAM-SHA-256-PLUS",
            "PLAIN",
        ]
        candidate = select_mechanism(
            advertised,
            capabilities,
            trusted_tls_with_cb(),
            SASLPolicy(),
        )
        self.assertEqual(candidate.name, "SCRAM-SHA-256-PLUS")
        self.assertTrue(candidate.channel_bound)
        self.assertFalse(candidate.scram_downgrade)

    def test_scram_plus_not_offered_falls_back_with_signal(self):
        capabilities, _ = make_capabilities()
        transport = trusted_tls_with_cb()
        candidate = select_mechanism(
            ["SCRAM-SHA-256", "PLAIN"],
            capabilities,
            transport,
            SASLPolicy(),
        )
        self.assertEqual(candidate.name, "SCRAM-SHA-256")
        self.assertFalse(candidate.channel_bound)
        # Client had PLUS capability but uses plain SCRAM: the
        # downgrade must be signalled via GS2 "y,,".
        self.assertTrue(candidate.scram_downgrade)
        self.assertEqual(
            candidate.mechanism._get_gs2_header(), b"y,,")

    def test_plain_scram_without_plus_capability_uses_n_header(self):
        capabilities, _ = make_capabilities()
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        candidate = select_mechanism(
            ["SCRAM-SHA-256"],
            capabilities,
            transport,
            SASLPolicy(),
        )
        self.assertEqual(candidate.name, "SCRAM-SHA-256")
        self.assertFalse(candidate.scram_downgrade)
        self.assertEqual(
            candidate.mechanism._get_gs2_header(), b"n,,")

    def test_cb_advertised_but_unavailable_uses_plain_scram(self):
        capabilities, _ = make_capabilities()
        # Verified TLS without a channel binding provider.
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        candidate = select_mechanism(
            ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
            capabilities,
            transport,
            SASLPolicy(),
        )
        self.assertEqual(candidate.name, "SCRAM-SHA-256")
        # No PLUS capability -> no downgrade signal required.
        self.assertFalse(candidate.scram_downgrade)

    def test_anonymous_works_without_trust(self):
        provider = RecordingCredentialProvider()
        capabilities = ClientCapabilities(
            credential_provider=provider,
            anonymous_token="sirhc",
        )
        policy = SASLPolicy(allow_anonymous=True)
        candidate = select_mechanism(
            ["ANONYMOUS"],
            capabilities,
            TransportSecurity(),
            policy,
        )
        self.assertEqual(candidate.name, "ANONYMOUS")
        self.assertFalse(candidate.sends_password)
        self.assertEqual(provider.calls, 0)

    def test_anonymous_disabled_by_default(self):
        capabilities, _ = make_capabilities()
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["ANONYMOUS"],
                capabilities,
                TransportSecurity(),
                SASLPolicy(),
            )

    def test_candidates_are_a_sequence(self):
        capabilities, _ = make_capabilities()
        from aiosasl.policy import _ordered_candidates
        ordered = _ordered_candidates(
            ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "PLAIN"],
            capabilities,
            trusted_tls_with_cb(),
            SASLPolicy(),
        )
        candidates = MechanismCandidates(
            ordered, ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "PLAIN"])
        self.assertEqual(len(candidates), 3)
        self.assertEqual(
            [c.name for c in candidates],
            [
                "SCRAM-SHA-256-PLUS",
                "SCRAM-SHA-256",
                "PLAIN",
            ],
        )
        self.assertEqual(candidates[0].name, "SCRAM-SHA-256-PLUS")

    def test_selector_can_reorder_policy_compliant_candidates(self):
        capabilities, _ = make_capabilities()

        def prefer_plain(candidates, transport, policy):
            for candidate in candidates:
                if candidate.name == "PLAIN":
                    return candidate
            return None

        candidate = select_mechanism(
            ["SCRAM-SHA-256", "PLAIN"],
            capabilities,
            TransportSecurity(
                tls_established=True, tls_verified=True),
            SASLPolicy(),
            selector=prefer_plain,
        )
        self.assertEqual(candidate.name, "PLAIN")

    def test_selector_returning_none_aborts(self):
        capabilities, _ = make_capabilities()
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["PLAIN"],
                capabilities,
                TransportSecurity(
                    tls_established=True, tls_verified=True),
                SASLPolicy(),
                selector=lambda c, t, p: None,
            )

    def test_selector_cannot_revive_rejected_mechanism(self):
        capabilities, _ = make_capabilities()
        captured = {}

        def spy(candidates, transport, policy):
            captured["candidates"] = candidates
            return candidates[0]

        # Over cleartext PLAIN must not even be offered to the hook.
        with self.assertRaises(NoAcceptableMechanism):
            select_mechanism(
                ["PLAIN"],
                capabilities,
                TransportSecurity(),
                SASLPolicy(),
                selector=spy,
            )
        self.assertNotIn("candidates", captured)

    def test_invalid_password_attempt_cap_rejected(self):
        with self.assertRaises(ValueError):
            SASLPolicy(max_password_attempts=0)


def run(coro):
    import asyncio
    return asyncio.get_event_loop().run_until_complete(coro)


class TestAuthenticate(unittest.TestCase):
    def test_plain_succeeds_on_trusted_transport(self):
        capabilities, provider = make_capabilities()
        interface = RecordingSASLInterface(script=[
            ("PLAIN", SASLState.SUCCESS, None),
        ])
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        candidate = run(authenticate(
            interface,
            ["PLAIN"],
            capabilities,
            transport,
            SASLPolicy(),
        ))
        self.assertEqual(candidate.name, "PLAIN")
        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            interface.actions, [("initiate", "PLAIN")])

    def test_plain_rejected_before_contacting_server(self):
        capabilities, provider = make_capabilities()
        interface = RecordingSASLInterface()
        with self.assertRaises(NoAcceptableMechanism):
            run(authenticate(
                interface,
                ["PLAIN"],
                capabilities,
                TransportSecurity(),
                SASLPolicy(),
            ))
        self.assertEqual(provider.calls, 0)
        self.assertEqual(interface.actions, [])

    def test_scram_succeeds_with_n_header(self):
        capabilities, provider = make_capabilities()
        server = ScramServer(
            hash_name="sha256",
            expect_gs2=b"n,,",
            expect_cb=None,
        )
        interface = RecordingSASLInterface(scram=server)
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        candidate = run(authenticate(
            interface,
            ["SCRAM-SHA-256"],
            capabilities,
            transport,
            SASLPolicy(),
        ))
        self.assertEqual(candidate.name, "SCRAM-SHA-256")
        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            interface.actions[0], ("initiate", "SCRAM-SHA-256"))

    def test_scram_plus_succeeds_with_channel_binding(self):
        capabilities, provider = make_capabilities()
        server = ScramServer(
            hash_name="sha256",
            expect_gs2=b"p=tls-unique,,",
            expect_cb=CB_DATA,
        )
        interface = RecordingSASLInterface(scram=server)
        candidate = run(authenticate(
            interface,
            ["SCRAM-SHA-256-PLUS"],
            capabilities,
            trusted_tls_with_cb(),
            SASLPolicy(),
        ))
        self.assertEqual(candidate.name, "SCRAM-SHA-256-PLUS")
        self.assertTrue(candidate.channel_bound)
        self.assertEqual(provider.calls, 1)

    def test_scram_downgrade_uses_y_header_end_to_end(self):
        capabilities, provider = make_capabilities()
        server = ScramServer(
            hash_name="sha256",
            expect_gs2=b"y,,",
            expect_cb=None,
        )
        interface = RecordingSASLInterface(scram=server)
        # Server supports only plain SCRAM although client has CB.
        candidate = run(authenticate(
            interface,
            ["SCRAM-SHA-256"],
            capabilities,
            trusted_tls_with_cb(),
            SASLPolicy(),
        ))
        self.assertEqual(candidate.name, "SCRAM-SHA-256")
        self.assertTrue(candidate.scram_downgrade)
        self.assertEqual(provider.calls, 1)

    def test_authentication_failure_does_not_retry_password(self):
        capabilities, provider = make_capabilities()
        server = ScramServer(
            hash_name="sha256",
            expect_gs2=b"n,,",
            expect_cb=None,
            reject_auth=True,
        )
        interface = RecordingSASLInterface(scram=server)
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        # Even with retries enabled, an auth failure must stop and must
        # never fall through to PLAIN with the same password.
        policy = SASLPolicy(retry_on_protocol_failure=True)
        with self.assertRaises(common.AuthenticationFailure):
            run(authenticate(
                interface,
                ["SCRAM-SHA-256", "PLAIN"],
                capabilities,
                transport,
                policy,
            ))
        self.assertEqual(provider.calls, 1)
        mechanisms = [
            name
            for action, name in interface.actions
            if action == "initiate"
        ]
        self.assertEqual(mechanisms, ["SCRAM-SHA-256"])

    def test_protocol_failure_no_retry_by_default(self):
        capabilities, provider = make_capabilities()

        class ProtocolFailInterface(RecordingSASLInterface):
            async def initiate(self, mechanism, payload=None):
                self.actions.append(("initiate", mechanism))
                raise common.SASLFailure("temporary-failure")

        interface = ProtocolFailInterface()
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        with self.assertRaises(common.SASLFailure):
            run(authenticate(
                interface,
                ["SCRAM-SHA-256", "PLAIN"],
                capabilities,
                transport,
                SASLPolicy(),
            ))
        self.assertEqual(provider.calls, 1)
        mechanisms = [name for action, name in interface.actions
                      if action == "initiate"]
        self.assertEqual(mechanisms, ["SCRAM-SHA-256"])

    def test_protocol_failure_can_retry_to_another_mechanism(self):
        capabilities, provider = make_capabilities()

        class FailThenPlain(RecordingSASLInterface):
            def __init__(self):
                super().__init__()
                self._first = True

            async def initiate(self, mechanism, payload=None):
                self.actions.append(("initiate", mechanism))
                if mechanism == "SCRAM-SHA-256":
                    raise common.SASLFailure("temporary-failure")
                return SASLState.SUCCESS, None

        interface = FailThenPlain()
        transport = TransportSecurity(
            tls_established=True, tls_verified=True)
        policy = SASLPolicy(
            retry_on_protocol_failure=True,
            max_password_attempts=2,
        )
        candidate = run(authenticate(
            interface,
            ["SCRAM-SHA-256", "PLAIN"],
            capabilities,
            transport,
            policy,
        ))
        self.assertEqual(candidate.name, "PLAIN")
        # Two distinct password mechanisms were allowed by the cap.
        self.assertEqual(provider.calls, 2)

    def test_password_attempt_cap_blocks_third_mechanism(self):
        capabilities, provider = make_capabilities()

        class AlwaysProtocolFail(RecordingSASLInterface):
            async def initiate(self, mechanism, payload=None):
                self.actions.append(("initiate", mechanism))
                raise common.SASLFailure("temporary-failure")

        interface = AlwaysProtocolFail()
        transport = trusted_tls_with_cb()
        policy = SASLPolicy(
            retry_on_protocol_failure=True,
            max_password_attempts=1,
        )
        with self.assertRaises(common.SASLFailure):
            run(authenticate(
                interface,
                ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "PLAIN"],
                capabilities,
                transport,
                policy,
            ))
        mechanisms = [
            name
            for action, name in interface.actions
            if action == "initiate"
        ]
        self.assertEqual(mechanisms, ["SCRAM-SHA-256-PLUS"])
        self.assertEqual(provider.calls, 1)

    def test_anonymous_succeeds_over_cleartext(self):
        provider = RecordingCredentialProvider()
        capabilities = ClientCapabilities(
            credential_provider=provider,
            anonymous_token="sirhc",
        )
        interface = RecordingSASLInterface(script=[
            ("ANONYMOUS", SASLState.SUCCESS, None),
        ])
        policy = SASLPolicy(allow_anonymous=True)
        candidate = run(authenticate(
            interface,
            ["ANONYMOUS"],
            capabilities,
            TransportSecurity(),
            policy,
        ))
        self.assertEqual(candidate.name, "ANONYMOUS")
        self.assertEqual(provider.calls, 0)


if __name__ == "__main__":
    unittest.main()
