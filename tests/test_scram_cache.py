########################################################################
# File name: test_scram_cache.py
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
import inspect
import itertools
import unittest
import unittest.mock

import aiosasl
import aiosasl.scram
from aiosasl.utils import xor_bytes


USERNAME = "user"
PASSWORD = "pencil"
NONCE_FOO = b"Zm9vAAAAAAAAAAAAAAAA"
NONCE_BAR = b"YmFyAAAAAAAAAAAAAAAA"
SERVER_NONCE_SUFFIX = b"3rfcNHYJY1ZVvWVs7j"


class FakeInterface(aiosasl.SASLInterface):
    """Small deterministic SCRAM server for one exchange."""

    def __init__(
            self,
            salt,
            iterations,
            nonce=None,
            version=None,
            on_respond=None,
            valid_signature=True):
        self.salt = salt
        self.iterations = iterations
        self.nonce = nonce
        self.version = version
        self.on_respond = on_respond
        self.valid_signature = valid_signature
        self.auth_messages = []
        self.client_proofs = []
        self.server_signatures = []
        self.gs2_header = None
        self.cb_data = None

    def expected_salted_password(self):
        return hashlib.pbkdf2_hmac(
            "sha1",
            PASSWORD.encode("utf-8"),
            self.salt,
            self.iterations,
        )

    async def initiate(self, mechanism, payload=None):
        marker = payload.index(b",,") + 2
        self.gs2_header = payload[:marker]
        self.client_first_bare = payload[marker:]
        client_nonce = dict(aiosasl.SCRAM.parse_message(
            self.client_first_bare))[b"r"]
        if self.nonce is None:
            self.nonce = client_nonce
        self.server_first = b",".join([
            b"r=" + self.nonce + SERVER_NONCE_SUFFIX,
            b"s=" + base64.b64encode(self.salt),
            b"i=" + str(self.iterations).encode("ascii"),
        ])
        salted = self.expected_salted_password()
        self.client_key = hmac.new(
            salted, b"Client Key", hashlib.sha1).digest()
        self.stored_key = hashlib.sha1(self.client_key).digest()
        return aiosasl.SASLState.CHALLENGE, self.server_first

    async def respond(self, payload):
        assert payload != b""
        reply, separator, proof = payload.partition(b",p=")
        assert separator
        cb_field, _, _ = reply.partition(b",")
        self.cb_data = base64.b64decode(cb_field[2:])
        self.auth_message = b",".join([
            self.client_first_bare,
            self.server_first,
            reply,
        ])
        expected_signature = hmac.new(
            self.stored_key, self.auth_message, hashlib.sha1).digest()
        expected_proof = xor_bytes(expected_signature, self.client_key)
        assert proof == base64.b64encode(expected_proof), payload
        self.client_proofs.append(proof)

        if self.on_respond:
            hook_result = self.on_respond()
            if inspect.isawaitable(hook_result):
                await hook_result

        salted = self.expected_salted_password()
        server_key = hmac.new(
            salted, b"Server Key", hashlib.sha1).digest()
        signature = hmac.new(
            server_key, self.auth_message, hashlib.sha1).digest()
        self.server_signatures.append(signature)
        if not self.valid_signature:
            signature = b"\x00" * len(signature)
        # Returning (SUCCESS, payload) makes the state machine unwrap the
        # final signature into a simulated challenge followed by an empty
        # final response, exactly as a real SCRAM server reply does.
        return aiosasl.SASLState.SUCCESS, b"v=" + base64.b64encode(
            signature)

    async def abort(self):
        return aiosasl.SASLState.FAILURE, None


class CountingPBKDF:
    def __init__(self):
        self.calls = []
        self._real = hashlib.pbkdf2_hmac

    def __call__(self, digest, password, salt, iterations):
        self.calls.append((digest, password, salt, iterations))
        return self._real(digest, password, salt, iterations)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def provide_credentials(version=None):
    async def provider():
        if version is None:
            return USERNAME, PASSWORD
        return USERNAME, PASSWORD, version
    return provider


class CacheTestBase(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.counter = CountingPBKDF()
        patcher = unittest.mock.patch(
            "aiosasl.scram.pbkdf2", self.counter)
        patcher.start()
        self.addCleanup(patcher.stop)

        random_patcher = unittest.mock.patch(
            "aiosasl.scram._system_random")
        self.random = random_patcher.start()
        self.addCleanup(random_patcher.stop)
        self.random.getrandbits.side_effect = itertools.cycle([
            int.from_bytes(b"foo", "little"),
            int.from_bytes(b"bar", "little"),
        ])

    async def _interleave(self, slow_coro, started, release, cache):
        task = self.loop.create_task(slow_coro)
        await started.wait()
        cache.invalidate()
        release.set()
        await task

    def run_auth(self, mechanism, interface=None, **kwargs):
        if interface is None:
            interface = FakeInterface(salt=b"QSXCR+Q6sek8bf92",
                                      iterations=4096)
        sm = aiosasl.SASLStateMachine(interface)
        token = (
            "SCRAM-SHA-1",
            aiosasl.scram.Base._supported_hashalgos["SHA-1"],
        )
        self.loop.run_until_complete(
            mechanism.authenticate(sm, token))
        return interface


class TestDerivedKeyCache(CacheTestBase):
    def test_hit_avoids_second_derivation_but_proofs_are_fresh(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        first = self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 1)
        self.assertEqual(cache.misses, 1)

        second = self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 1)
        self.assertEqual(cache.hits, 1)

        # Both handshakes used their own nonce and therefore their own
        # transcript; only the expensive derivation was shared.
        self.assertNotEqual(first.client_first_bare,
                            second.client_first_bare)
        self.assertNotEqual(first.client_proofs,
                            second.client_proofs)
        self.assertNotEqual(first.server_signatures,
                            second.server_signatures)

    def test_scram_plus_hits_without_sharing_transcript(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        cb_values = iter([b"channel binding data", b"other cb data"])

        class CBProvider:
            cb_name = b"tls-unique"

            def extract_cb_data(inner):
                return next(cb_values)

        mechanism = aiosasl.SCRAMPLUS(
            provide_credentials(version=1),
            CBProvider(),
            cache=cache,
        )

        first = self.run_auth(mechanism)
        second = self.run_auth(mechanism)

        self.assertEqual(len(self.counter.calls), 1)
        self.assertEqual(cache.hits, 1)
        self.assertNotEqual(first.cb_data, second.cb_data)
        self.assertNotEqual(first.client_proofs,
                            second.client_proofs)
        self.assertNotEqual(first.server_signatures,
                            second.server_signatures)

    def test_interleaved_revocation_blocks_late_publication(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)
        release = asyncio.Event()
        started = asyncio.Event()

        async def hold_first_response():
            started.set()
            # The expensive derivation is already done.  Publication only
            # happens after the server signature is verified, so this is a
            # genuine in-flight attempt at the cache boundary.
            await release.wait()

        slow = FakeInterface(
            salt=b"QSXCR+Q6sek8bf92",
            iterations=4096,
            on_respond=hold_first_response,
        )

        async def run_slow():
            sm = aiosasl.SASLStateMachine(slow)
            token = (
                "SCRAM-SHA-1",
                aiosasl.scram.Base._supported_hashalgos["SHA-1"],
            )
            await mechanism.authenticate(sm, token)

        self.loop.run_until_complete(self._interleave(
            run_slow(), started, release, cache))

        self.assertEqual(cache.rejected_stores, 1)
        self.assertEqual(cache.size, 0)

        # A fresh attempt under the new generation derives and publishes.
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)
        self.assertEqual(cache.size, 1)

    def test_salt_change_causes_miss(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        self.run_auth(mechanism)
        self.run_auth(mechanism, interface=FakeInterface(
            salt=b"a-different-salt", iterations=4096))

        self.assertEqual(len(self.counter.calls), 2)
        self.assertEqual(cache.misses, 2)
        self.assertEqual(cache.hits, 0)

    def test_iteration_count_change_causes_miss(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        self.run_auth(mechanism)
        self.run_auth(mechanism, interface=FakeInterface(
            salt=b"QSXCR+Q6sek8bf92", iterations=5000))

        self.assertEqual(len(self.counter.calls), 2)

    def test_credential_version_change_causes_miss(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(provide_credentials(version=1),
                                  cache=cache)
        self.run_auth(mechanism)

        rotated = aiosasl.SCRAM(provide_credentials(version=2),
                                cache=cache)
        self.run_auth(rotated)

        self.assertEqual(len(self.counter.calls), 2)
        self.assertEqual(cache.hits, 0)

    def test_credential_version_provider(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        versions = iter([1, 1, 2])

        async def version_provider(username):
            assert username == USERNAME
            return next(versions)

        mechanism = aiosasl.SCRAM(
            provide_credentials(),
            cache=cache,
            credential_version_provider=version_provider)

        self.run_auth(mechanism)
        self.run_auth(mechanism)
        self.run_auth(mechanism)

        self.assertEqual(len(self.counter.calls), 2)

    def test_versioned_credential_provider_tuple(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        version = [1]

        async def provider():
            return USERNAME, PASSWORD, version[0]

        mechanism = aiosasl.SCRAM(provider, cache=cache)
        self.run_auth(mechanism)
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 1)

        version[0] = 2
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)

    def test_version_provider_may_take_password(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        seen = []

        async def provider(username, password):
            seen.append((username, password))
            return 7

        mechanism = aiosasl.SCRAM(
            provide_credentials(),
            cache=cache,
            credential_version_provider=provider,
        )
        self.run_auth(mechanism)
        self.assertEqual(seen, [(USERNAME, PASSWORD)])

    def test_failed_authentication_does_not_publish(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        with self.assertRaises(aiosasl.SASLFailure):
            self.run_auth(mechanism, interface=FakeInterface(
                salt=b"QSXCR+Q6sek8bf92",
                iterations=4096,
                valid_signature=False))

        self.assertEqual(cache.size, 0)
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)

    def test_invalidation_rejects_late_publication(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        interface = FakeInterface(
            salt=b"QSXCR+Q6sek8bf92",
            iterations=4096,
            on_respond=cache.invalidate,
        )
        self.run_auth(mechanism, interface=interface)

        self.assertEqual(cache.rejected_stores, 1)
        self.assertEqual(cache.size, 0)
        self.assertGreaterEqual(cache.generation, 1)

        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)

    def test_capacity_is_bounded_and_lru(self):
        cache = aiosasl.DerivedKeyCache(capacity=1, ttl=60)
        first = aiosasl.SCRAM(provide_credentials(version=1), cache=cache)
        second = aiosasl.SCRAM(provide_credentials(version=2), cache=cache)

        self.run_auth(first)
        self.run_auth(second)
        self.assertEqual(cache.size, 1)
        self.assertEqual(cache.evictions, 1)

        self.run_auth(first)
        self.assertEqual(len(self.counter.calls), 3)

    def test_lifetime_is_bounded(self):
        clock = Clock()
        cache = aiosasl.DerivedKeyCache(
            capacity=4, ttl=10, clock=clock)
        mechanism = aiosasl.SCRAM(
            provide_credentials(version=1), cache=cache)

        self.run_auth(mechanism)
        clock.advance(9.9)
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 1)

        clock.advance(0.2)
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)

    def test_disabled_cache_keeps_original_behaviour(self):
        mechanism = aiosasl.SCRAM(provide_credentials(version=1))
        self.run_auth(mechanism)
        self.run_auth(mechanism)
        self.assertEqual(len(self.counter.calls), 2)

    def test_public_identity_does_not_expose_secret(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        key = cache.make_key(
            1,
            USERNAME,
            PASSWORD,
            "sha1",
            b"QSXCR+Q6sek8bf92",
            4096,
        )
        rendered = repr(key)
        self.assertNotIn(PASSWORD, rendered)
        self.assertNotIn("pencil", rendered)
        self.assertIn("redacted", rendered)

    def test_cache_alias_and_constructor_validation(self):
        self.assertIs(aiosasl.SCRAMCache, aiosasl.DerivedKeyCache)
        with self.assertRaises(ValueError):
            aiosasl.DerivedKeyCache(capacity=-1)
        with self.assertRaises(TypeError):
            aiosasl.SCRAM(
                provide_credentials(),
                cache=aiosasl.DerivedKeyCache(),
                cache_capacity=1,
            )

    def test_prepared_password_identity(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)

        # SASLprep is applied by SCRAM before make_key.  Callers which pass
        # an unprepared password get a distinct identity; the cache does
        # not silently reinterpret raw secrets.
        key_a = cache.make_key(
            "v1", "user", "I\u00adX", "sha1", b"salt", 4096)
        key_b = cache.make_key(
            "v1", "user", "IX", "sha1", b"salt", 4096)
        self.assertNotEqual(key_a.password_tag, key_b.password_tag)
        self.assertNotEqual(key_a, key_b)

        # Two equal prepared passwords share the same identity.
        key_c = cache.make_key(
            "v1", "user", "IX", "sha1", b"salt", 4096)
        self.assertEqual(key_b, key_c)

    def test_key_does_not_contain_salted_password(self):
        cache = aiosasl.DerivedKeyCache(capacity=4, ttl=60)
        key = cache.make_key(
            1, USERNAME, PASSWORD, "sha1", b"salt", 4096)
        salted = hashlib.pbkdf2_hmac(
            "sha1", PASSWORD.encode(), b"salt", 4096)
        self.assertNotIn(salted, key)
        self.assertNotIn(PASSWORD.encode(), key)
        self.assertNotIn(salted, repr(key).encode())
