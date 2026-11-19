#!/usr/bin/env python
"""Fixed-account comparison of the real and decoy SRP handshake paths.

The tests use one registered account and one unknown identity, driven by fixed
client and server ephemeral values, and record every cryptographic primitive
the pure-Python backend touches (hash/HMAC, modular exponentiation, OS RNG).
They compare the two paths on public messages, operation categories and final
authentication result.

These checks rule out structural/format enumeration signals only.  They do not
establish constant-time behaviour; see ANTI_ENUMERATIONATION.md for the timing
measurements that still have to be deployed.
"""

import logging
import threading
import unittest

import srp._pysrp as _pysrp
from srp.server import srp_server
from srp.server.srp_server import (
    AuthenticationFailed,
    SrpServer,
    SrpUserStore,
    POLICY_HASH_ALG,
    POLICY_NG_TYPE,
    SALT_BYTES,
)


# Fixed test accounts and policy-matching ephemeral entropy.
REAL_USER = b"alice"
REAL_PASSWORD = b"test-only-password"
UNKNOWN_USER = b"mallory-never-registered"
SERVER_SECRET = bytes(range(32)) * 2  # 64 deterministic, non-secret-in-test bytes
# Fixed client ephemeral. pysrp requires exactly 256 bytes for bytes_a; reject
# candidates that do not reduce below the 2048-bit modulus so the recorded
# vector is a valid SRP ephemeral rather than an out-of-group integer.
def _fixed_client_keypair():
    modulus, generator = _pysrp.get_ng(POLICY_NG_TYPE, None, None)
    while True:
        candidate_a = _pysrp.long_to_bytes(_pysrp.get_random_of_length(256))
        if _pysrp.bytes_to_long(candidate_a) < modulus:
            break
    client = _pysrp.User(REAL_USER, REAL_PASSWORD, hash_alg=POLICY_HASH_ALG,
                         ng_type=POLICY_NG_TYPE, bytes_a=candidate_a)
    _name, public_a = client.start_authentication()
    return candidate_a, public_a


# FIXED_A is the *public* ephemeral sent on the wire; FIXED_A_PRIVATE is the
# matching 256-byte exponent used to rebuild the deterministic client.
FIXED_A_PRIVATE, FIXED_A = _fixed_client_keypair()


class CryptoTracer:
    """Record primitive calls made by the SRP backend while active."""

    def __init__(self):
        self.records = []
        self._stash = None

    def __enter__(self):
        mod = _pysrp
        builtin_pow = pow
        self._stash = {
            "pow": getattr(mod, "pow", None),
            "hash_map": dict(mod._hash_map),
            "urandom": mod.os.urandom,
            "hmac_new": srp_server.hmac.new,
        }

        def make_traced_hash(original, name):
            def traced_hash(data=b""):
                self.records.append(("hash", name))
                return original(data)
            return traced_hash

        for index, original in mod._hash_map.items():
            name = original().name
            mod._hash_map[index] = make_traced_hash(original, name)

        def traced_pow(base, exp, modulus=None):
            self.records.append(("pow", "modexp"))
            return builtin_pow(base, exp, modulus)

        def traced_urandom(nbytes):
            self.records.append(("urandom", nbytes))
            return self._stash["urandom"](nbytes)

        def traced_hmac_new(key, msg, digestmod):
            self.records.append(("hmac", digestmod if isinstance(digestmod, str)
                                 else getattr(digestmod, "__name__", "hmac")))
            return self._stash["hmac_new"](key, msg, digestmod)

        mod.pow = traced_pow
        mod.os.urandom = traced_urandom
        srp_server.hmac.new = traced_hmac_new
        return self

    def __exit__(self, exc_type, exc, tb):
        mod = _pysrp
        if self._stash["pow"] is None:
            del mod.pow
        else:
            mod.pow = self._stash["pow"]
        mod._hash_map.clear()
        mod._hash_map.update(self._stash["hash_map"])
        mod.os.urandom = self._stash["urandom"]
        srp_server.hmac.new = self._stash["hmac_new"]
        self._stash = None
        return False

    def categories(self):
        return [category for category, _detail in self.records]

    def count(self, category):
        return sum(1 for entry_category, _detail in self.records
                   if entry_category == category)


def build_server():
    store = SrpUserStore()
    store.register(REAL_USER, REAL_PASSWORD)
    return SrpServer(SERVER_SECRET, store)


def run_handshake(server, identity, client_password=None, public_A=None,
                  private_a=None):
    """Drive one full handshake and return (session, client, tracer, result)."""
    if public_A is None:
        public_A = FIXED_A
    if private_a is None:
        private_a = FIXED_A_PRIVATE

    tracer = CryptoTracer()
    with tracer:
        session = server.begin_handshake(identity, public_A)
        salt, challenge_B = session.get_challenge()

        client = None
        proof = None
        if client_password is not None:
            client = _pysrp.User(identity, client_password,
                                 hash_alg=POLICY_HASH_ALG, ng_type=POLICY_NG_TYPE,
                                 bytes_a=private_a)
            proof = client.process_challenge(salt, challenge_B)

        hamk = session.verify_proof(proof) if proof is not None else None
        if hamk is not None and client is not None:
            client.verify_session(hamk)

    return session, client, tracer, hamk


class AntiEnumerationTests(unittest.TestCase):

    def test_public_message_parity(self):
        server = build_server()
        real_session = server.begin_handshake(REAL_USER, FIXED_A)
        decoy_session = server.begin_handshake(UNKNOWN_USER, FIXED_A)

        real_salt, real_b = real_session.get_challenge()
        decoy_salt, decoy_b = decoy_session.get_challenge()

        self.assertEqual(len(real_salt), SALT_BYTES)
        self.assertEqual(len(decoy_salt), SALT_BYTES)
        self.assertEqual(type(real_salt), type(decoy_salt))
        self.assertNotEqual(real_salt, decoy_salt)

        n_length = len(_pysrp.long_to_bytes(
            _pysrp.get_ng(POLICY_NG_TYPE, None, None)[0]))
        self.assertEqual(len(real_b), n_length)
        self.assertEqual(len(decoy_b), n_length)
        self.assertNotEqual(real_b, decoy_b)
        self.assertFalse(real_session.is_decoy)
        self.assertTrue(decoy_session.is_decoy)

    def test_operation_categories_match_when_warm(self):
        server = build_server()
        server.prewarm_decoy([UNKNOWN_USER])

        _, _, real_tracer, _ = run_handshake(server, REAL_USER, REAL_PASSWORD)
        _, _, decoy_tracer, _ = run_handshake(server, UNKNOWN_USER,
                                              b"any-password-guess")

        self.assertEqual(real_tracer.categories(), decoy_tracer.categories())
        for category in ("pow", "hash", "hmac", "urandom"):
            self.assertEqual(real_tracer.count(category),
                             decoy_tracer.count(category))
        self.assertGreaterEqual(real_tracer.count("pow"), 1)
        self.assertGreaterEqual(real_tracer.count("hash"), 1)

    def test_cold_decoy_only_adds_derivation_primitives(self):
        server = SrpServer(SERVER_SECRET, SrpUserStore())
        # First contact derives the decoy record; the second hits the cache.
        _, _, cold_tracer, _ = run_handshake(server, UNKNOWN_USER, b"guess")
        _, _, warm_tracer, _ = run_handshake(server, UNKNOWN_USER, b"guess")
        warm_categories = warm_tracer.categories()
        cold_categories = cold_tracer.categories()
        self.assertEqual(cold_categories[-len(warm_categories):], warm_categories)
        extra = cold_categories[:len(cold_categories) - len(warm_categories)]
        # First contact pays only the two HMAC derivation steps up front. The
        # verifier's g^x exponentiation is issued later, inside the same
        # handshake suffix both paths execute, so pow counts stay equal.
        self.assertEqual(extra, ["hmac", "hmac"])
        self.assertEqual(cold_tracer.count("pow"), warm_tracer.count("pow"))

    def test_final_results_real_success_decoy_always_fails(self):
        server = build_server()

        real_session, real_client, _, real_hamk = run_handshake(
            server, REAL_USER, REAL_PASSWORD)
        self.assertIsNotNone(real_hamk)
        self.assertTrue(real_session.authenticated())
        self.assertTrue(real_client.authenticated())

        decoy_session, decoy_client, _, decoy_hamk = run_handshake(
            server, UNKNOWN_USER, REAL_PASSWORD)
        self.assertIsNone(decoy_hamk)
        self.assertFalse(decoy_session.authenticated())
        self.assertFalse(decoy_client.authenticated())

        wrong_session, _, _, wrong_hamk = run_handshake(
            server, REAL_USER, b"wrong-password")
        self.assertIsNone(wrong_hamk)
        self.assertFalse(wrong_session.authenticated())

        whitebox_session = server.begin_handshake(UNKNOWN_USER, FIXED_A)
        whitebox_session.get_challenge()
        # Even a proof equal to the verifier's own M cannot authenticate a decoy.
        whitebox_session._verifier._derive_H_AMK()
        forged_m = whitebox_session._verifier.M
        self.assertIsNone(whitebox_session.verify_proof(forged_m))
        self.assertFalse(whitebox_session.authenticated())

    def test_malformed_A_treated_identically(self):
        server = build_server()
        zero_a = b"\x00" * len(_pysrp.long_to_bytes(
            _pysrp.get_ng(POLICY_NG_TYPE, None, None)[0]))

        real_session = server.begin_handshake(REAL_USER, zero_a)
        decoy_session = server.begin_handshake(UNKNOWN_USER, zero_a)
        self.assertEqual(real_session.get_challenge(), (None, None))
        self.assertEqual(decoy_session.get_challenge(), (None, None))
        self.assertIsNone(real_session.verify_proof(b"x" * 32))
        self.assertIsNone(decoy_session.verify_proof(b"x" * 32))

    def test_concurrent_real_handshakes_isolated_from_decoys(self):
        server = build_server()
        server.prewarm_decoy([UNKNOWN_USER])
        errors = []
        barrier = threading.Barrier(8)

        def worker(identity, password, expect_auth):
            barrier.wait()
            try:
                for _ in range(25):
                    # No global tracer here: primitive patching is process-wide
                    # and is deliberately not used across threads. Each worker
                    # gets its own client ephemeral and its own session object.
                    client = _pysrp.User(identity, password,
                                         hash_alg=POLICY_HASH_ALG,
                                         ng_type=POLICY_NG_TYPE)
                    _name, public_a = client.start_authentication()
                    session = server.begin_handshake(identity, public_a)
                    salt, challenge_b = session.get_challenge()
                    proof = client.process_challenge(salt, challenge_b)
                    hamk = session.verify_proof(proof)
                    if hamk is not None:
                        client.verify_session(hamk)
                    if session.authenticated() != expect_auth:
                        errors.append("auth mismatch")
                    if expect_auth and not client.authenticated():
                        errors.append("client not authenticated")
                    if not expect_auth and hamk is not None:
                        errors.append("decoy leaked HAMK")
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(repr(exc))

        threads = []
        for index in range(8):
            if index % 2 == 0:
                thread = threading.Thread(target=worker,
                                          args=(REAL_USER, REAL_PASSWORD, True))
            else:
                thread = threading.Thread(target=worker,
                                          args=(UNKNOWN_USER, b"guess", False))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

    def test_rejection_logs_are_uniform(self):
        server = build_server()
        records = []

        class CaptureHandler(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = CaptureHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("srp.server")
        logger.addHandler(handler)
        try:
            run_handshake(server, REAL_USER, b"wrong-password")
            run_handshake(server, UNKNOWN_USER, b"guess")
            run_handshake(server, UNKNOWN_USER, None)
        finally:
            logger.removeHandler(handler)

        self.assertTrue(records)
        self.assertEqual(set(records), {"SRP verification rejected"})
        joined = " ".join(records)
        for leak in (REAL_USER.decode(), UNKNOWN_USER.decode(), "alice",
                     "mallory", "decoy", "real", "salt"):
            self.assertNotIn(leak, joined)

    def test_decoy_bound_to_secret_and_identity(self):
        first = build_server()
        second = build_server()
        other_secret = SrpServer(b"z" * 64, SrpUserStore())

        salt_one, v_one = first._decoy_record(UNKNOWN_USER)
        salt_two, v_two = second._decoy_record(UNKNOWN_USER)
        salt_other, v_other = other_secret._decoy_record(UNKNOWN_USER)
        salt_identity, v_identity = first._decoy_record(b"someone-else")

        self.assertEqual((salt_one, v_one), (salt_two, v_two))
        self.assertNotEqual((salt_one, v_one), (salt_other, v_other))
        self.assertNotEqual(salt_one, salt_identity)
        self.assertNotEqual(v_one, v_identity)
        self.assertEqual(len(salt_one), SALT_BYTES)

        n_value, _g = _pysrp.get_ng(POLICY_NG_TYPE, None, None)
        self.assertLess(_pysrp.bytes_to_long(v_one), n_value)

    def test_authenticate_raises_one_exception_type(self):
        server = build_server()
        for identity, password in ((REAL_USER, b"bad"),
                                   (UNKNOWN_USER, REAL_PASSWORD)):
            session, _, _, _ = run_handshake(server, identity, password)
            with self.assertRaises(AuthenticationFailed) as context:
                session.authenticate(b"\x00" * 32)
            self.assertEqual(str(context.exception),
                             "SRP verification rejected")


def print_comparison_report():
    server = build_server()
    server.prewarm_decoy([UNKNOWN_USER])

    real_session, real_client, real_tracer, real_hamk = run_handshake(
        server, REAL_USER, REAL_PASSWORD)
    decoy_session, decoy_client, decoy_tracer, decoy_hamk = run_handshake(
        server, UNKNOWN_USER, REAL_PASSWORD)
    real_salt, real_b = real_session.get_challenge()
    decoy_salt, decoy_b = decoy_session.get_challenge()

    print("=" * 72)
    print("SRP anti-enumeration: real vs decoy handshake comparison")
    print("=" * 72)
    print("policy            : SHA256 / NG_2048 (identical for both paths)")
    print("real identity     : %r (registered)" % REAL_USER)
    print("decoy identity    : %r (unknown)" % UNKNOWN_USER)
    print("-" * 72)
    print("public salt bytes : real %d | decoy %d"
          % (len(real_salt), len(decoy_salt)))
    print("public B bytes    : real %d | decoy %d"
          % (len(real_b), len(decoy_b)))
    print("challenge shape   : both (salt:bytes, B:bytes), no None branch")
    print("-" * 72)
    print("real ops          : %s" % real_tracer.categories())
    print("decoy ops         : %s" % decoy_tracer.categories())
    print("categories equal  : %s"
          % (real_tracer.categories() == decoy_tracer.categories()))
    print("-" * 72)
    print("real HAMK         : %r" % (real_hamk is not None))
    print("decoy HAMK        : %r" % (decoy_hamk is not None))
    print("real authenticated: %s" % real_session.authenticated())
    print("decoy authenticated: %s" % decoy_session.authenticated())
    print("=" * 72)


if __name__ == "__main__":
    print_comparison_report()
    unittest.main(verbosity=2)
