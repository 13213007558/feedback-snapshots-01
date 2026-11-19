#!/usr/bin/env python
"""
Negative regression tests for mutual authentication in the pure Python
SRP-6a implementation (srp._pysrp).

These tests pin down that authentication is only established by the
explicit confirmation steps of the protocol:

  * server side: Verifier.verify_session() must see the M that belongs to
    *this* handshake (its own A, B, salt and verifier) before it reports
    authenticated() and releases a session key;
  * client side: User.verify_session() must see the HAMK that corresponds
    to its own M before it reports authenticated() and releases a session
    key.

A client merely *computing* an M (e.g. with a wrong password) must never
be treated by either side as proof of identity, and get_session_key()
must not return a usable key on any failure path.

All artifacts come from the fixed, independently stored expected
transcript in test_pysrp_expected_transcript.json so the tests are fully
deterministic.
"""

import json
import os.path
import unittest

import srp
import srp._pysrp as _pysrp


this_dir = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(this_dir, 'test_pysrp_expected_transcript.json')) as f:
    TRANSCRIPT = json.load(f)

HASH_ALG = getattr(srp, TRANSCRIPT['hash_alg'])
NG_TYPE = getattr(srp, TRANSCRIPT['ng_type'])

WRONG_PASSWORD = b'definitely-not-the-password'


def session_params(name):
    return TRANSCRIPT['sessions'][name]


def build_user(name, password=None):
    params = session_params(name)
    return _pysrp.User(
        params['username'].encode('ascii'),
        password if password is not None else params['password'].encode('ascii'),
        hash_alg=HASH_ALG,
        ng_type=NG_TYPE,
        bytes_a=bytes.fromhex(params['client_ephemeral_secret_hex']),
    )


def build_verifier(name, bytes_A):
    params = session_params(name)
    return _pysrp.Verifier(
        params['username'].encode('ascii'),
        bytes.fromhex(params['salt_hex']),
        bytes.fromhex(params['verifier_hex']),
        bytes_A,
        hash_alg=HASH_ALG,
        ng_type=NG_TYPE,
        bytes_b=bytes.fromhex(params['server_ephemeral_secret_hex']),
    )


def run_handshake(name, password=None):
    """Run one fixed-parameter handshake up to (but not including) the
    client's HAMK confirmation. Returns (usr, svr, M, HAMK)."""
    usr = build_user(name, password)
    uname, A = usr.start_authentication()
    svr = build_verifier(name, A)
    s, B = svr.get_challenge()
    M = usr.process_challenge(s, B)
    HAMK = svr.verify_session(M)
    return usr, svr, M, HAMK


class ExpectedTranscriptTests(unittest.TestCase):
    """The fixed-parameter transcript must reproduce exactly."""

    def check_session(self, name):
        params = session_params(name)
        usr, svr, M, HAMK = run_handshake(name)
        usr.verify_session(HAMK)

        self.assertEqual(M.hex(), params['M_hex'])
        self.assertEqual(HAMK.hex(), params['HAMK_hex'])
        self.assertEqual(usr.M.hex(), params['M_hex'])
        self.assertEqual(usr.H_AMK.hex(), params['HAMK_hex'])
        self.assertTrue(svr.authenticated())
        self.assertTrue(usr.authenticated())
        self.assertEqual(usr.get_session_key().hex(), params['session_key_hex'])
        self.assertEqual(svr.get_session_key().hex(), params['session_key_hex'])

    def test_alice_transcript(self):
        self.check_session('alice')

    def test_bob_transcript(self):
        self.check_session('bob')

    def test_sessions_are_distinct(self):
        alice = session_params('alice')
        bob = session_params('bob')
        self.assertNotEqual(alice['salt_hex'], bob['salt_hex'])
        self.assertNotEqual(alice['A_hex'], bob['A_hex'])
        self.assertNotEqual(alice['B_hex'], bob['B_hex'])
        self.assertNotEqual(alice['M_hex'], bob['M_hex'])
        self.assertNotEqual(alice['HAMK_hex'], bob['HAMK_hex'])
        self.assertNotEqual(alice['session_key_hex'], bob['session_key_hex'])


class CrossSessionSwapTests(unittest.TestCase):
    """Proofs from one handshake must not authenticate another."""

    def setUp(self):
        # Two interleaved handshakes: different usernames, salts and
        # ephemeral key pairs on both sides.
        self.usr_alice = build_user('alice')
        self.usr_bob = build_user('bob')
        _, self.A_alice = self.usr_alice.start_authentication()
        _, self.A_bob = self.usr_bob.start_authentication()
        self.svr_alice = build_verifier('alice', self.A_alice)
        self.svr_bob = build_verifier('bob', self.A_bob)
        self.s_alice, self.B_alice = self.svr_alice.get_challenge()
        self.s_bob, self.B_bob = self.svr_bob.get_challenge()
        self.M_alice = self.usr_alice.process_challenge(self.s_alice, self.B_alice)
        self.M_bob = self.usr_bob.process_challenge(self.s_bob, self.B_bob)

    def test_swapped_client_proofs_rejected(self):
        # Each server receives the M computed for the *other* session.
        self.assertIsNone(self.svr_alice.verify_session(self.M_bob))
        self.assertIsNone(self.svr_bob.verify_session(self.M_alice))

        for svr in (self.svr_alice, self.svr_bob):
            self.assertFalse(svr.authenticated())
            self.assertIsNone(svr.get_session_key())

        # The clients never receive a HAMK, so they must not authenticate
        # even though each successfully computed its own M.
        for usr in (self.usr_alice, self.usr_bob):
            self.assertIsNotNone(usr.M)
            self.assertFalse(usr.authenticated())
            self.assertIsNone(usr.get_session_key())

        # A failed attempt must not poison the verifier: the correct M
        # still completes each handshake.
        HAMK_alice = self.svr_alice.verify_session(self.M_alice)
        HAMK_bob = self.svr_bob.verify_session(self.M_bob)
        self.assertEqual(HAMK_alice.hex(), session_params('alice')['HAMK_hex'])
        self.assertEqual(HAMK_bob.hex(), session_params('bob')['HAMK_hex'])

    def test_swapped_HAMK_rejected(self):
        # Servers get their correct M and authenticate...
        HAMK_alice = self.svr_alice.verify_session(self.M_alice)
        HAMK_bob = self.svr_bob.verify_session(self.M_bob)
        self.assertTrue(self.svr_alice.authenticated())
        self.assertTrue(self.svr_bob.authenticated())

        # ...but each client is handed the HAMK of the other session.
        self.usr_alice.verify_session(HAMK_bob)
        self.usr_bob.verify_session(HAMK_alice)

        for usr in (self.usr_alice, self.usr_bob):
            self.assertFalse(usr.authenticated())
            self.assertIsNone(usr.get_session_key())

        # The matching HAMK still completes each client's authentication.
        self.usr_alice.verify_session(HAMK_alice)
        self.usr_bob.verify_session(HAMK_bob)
        self.assertTrue(self.usr_alice.authenticated())
        self.assertTrue(self.usr_bob.authenticated())

    def test_swapped_ephemeral_A_rejected(self):
        # Alice's M checked against Bob's A (and vice versa) must fail.
        svr_alice_with_bob_A = build_verifier('alice', self.A_bob)
        svr_bob_with_alice_A = build_verifier('bob', self.A_alice)
        self.assertIsNone(svr_alice_with_bob_A.verify_session(self.M_alice))
        self.assertIsNone(svr_bob_with_alice_A.verify_session(self.M_bob))
        self.assertFalse(svr_alice_with_bob_A.authenticated())
        self.assertFalse(svr_bob_with_alice_A.authenticated())
        self.assertIsNone(svr_alice_with_bob_A.get_session_key())
        self.assertIsNone(svr_bob_with_alice_A.get_session_key())

    def test_swapped_salt_rejected(self):
        # Alice's client answers Alice's B but with Bob's salt.
        usr = build_user('alice')
        _, A = usr.start_authentication()
        svr = build_verifier('alice', A)
        _, B = svr.get_challenge()
        M = usr.process_challenge(self.s_bob, B)
        self.assertIsNotNone(M)
        self.assertIsNone(svr.verify_session(M))
        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())


class WrongPasswordTests(unittest.TestCase):
    """A client that computes an M with the wrong password proves nothing."""

    def test_wrong_password_proof_rejected(self):
        usr, svr, M, HAMK = run_handshake('alice', password=WRONG_PASSWORD)

        # The client did compute a proof - it just isn't valid.
        self.assertIsNotNone(M)
        self.assertNotEqual(M.hex(), session_params('alice')['M_hex'])

        # The server rejects it and must not release a key.
        self.assertIsNone(HAMK)
        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())

        # Without a HAMK the client must not consider itself authenticated,
        # even though it locally derived M, H_AMK and K.
        self.assertIsNotNone(usr.H_AMK)
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())


class ReflectionAndReplayTests(unittest.TestCase):

    def test_own_M_reflected_as_HAMK_rejected(self):
        # An attacker echoes the client's own M back as the server's HAMK.
        usr, svr, M, HAMK = run_handshake('alice')
        usr.verify_session(M)
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())

    def test_own_HAMK_reflected_as_M_rejected(self):
        # An attacker echoes a previously observed HAMK back as the
        # client's M in a fresh handshake.
        params = session_params('alice')
        usr = build_user('alice')
        _, A = usr.start_authentication()
        svr = build_verifier('alice', A)
        s, B = svr.get_challenge()
        usr.process_challenge(s, B)
        reflected = svr.verify_session(bytes.fromhex(params['HAMK_hex']))
        # HAMK != M for this transcript, so the reflection must fail.
        self.assertNotEqual(params['HAMK_hex'], params['M_hex'])
        self.assertIsNone(reflected)
        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())

    def test_replay_with_fresh_server_ephemeral_rejected(self):
        # Replaying Alice's M against a new verifier session for the same
        # account (same salt and verifier, fresh ephemeral b) must fail.
        params = session_params('alice')
        fresh_b = bytes.fromhex(session_params('bob')['server_ephemeral_secret_hex'])
        svr2 = _pysrp.Verifier(
            params['username'].encode('ascii'),
            bytes.fromhex(params['salt_hex']),
            bytes.fromhex(params['verifier_hex']),
            bytes.fromhex(params['A_hex']),
            hash_alg=HASH_ALG,
            ng_type=NG_TYPE,
            bytes_b=fresh_b,
        )
        self.assertIsNone(svr2.verify_session(bytes.fromhex(params['M_hex'])))
        self.assertFalse(svr2.authenticated())
        self.assertIsNone(svr2.get_session_key())


class HalfHandshakeTests(unittest.TestCase):
    """Completing only one side of the handshake authenticates nobody."""

    def test_client_stops_after_process_challenge(self):
        usr = build_user('alice')
        _, A = usr.start_authentication()
        svr = build_verifier('alice', A)
        s, B = svr.get_challenge()
        M = usr.process_challenge(s, B)

        # Client holds M, H_AMK and K locally but was never confirmed.
        self.assertIsNotNone(M)
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())

        # Server received A but never verified M.
        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())

    def test_server_stops_before_verify_session(self):
        usr = build_user('alice')
        _, A = usr.start_authentication()
        svr = build_verifier('alice', A)
        s, B = svr.get_challenge()
        usr.process_challenge(s, B)

        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())


class ForcedFlagTests(unittest.TestCase):
    """Artificially setting _authenticated early releases the session key,
    which demonstrates that the flag is the *only* gate on key release.
    Each test names the specific confirmation step it bypasses; these
    tests exist to document why nothing may set that flag except the
    confirmation steps themselves."""

    def test_forced_user_flag_bypasses_verify_session_HAMK_check(self):
        # Bypassed confirmation step: User.verify_session(host_HAMK),
        # which compares the server's HAMK against the locally computed
        # H_AMK before setting _authenticated.
        usr, svr, M, HAMK = run_handshake('alice')
        self.assertFalse(usr.authenticated())
        self.assertIsNone(usr.get_session_key())

        usr._authenticated = True  # skips the HAMK comparison entirely
        self.assertEqual(
            usr.get_session_key().hex(),
            session_params('alice')['session_key_hex'],
            'forcing _authenticated releases K without User.verify_session '
            'ever checking the server HAMK',
        )

    def test_forced_verifier_flag_bypasses_verify_session_M_check(self):
        # Bypassed confirmation step: Verifier.verify_session(user_M),
        # which compares user_M against the M derived for *this* handshake
        # before setting _authenticated.
        usr = build_user('alice')
        _, A = usr.start_authentication()
        svr = build_verifier('alice', A)
        s, B = svr.get_challenge()
        usr.process_challenge(s, B)

        # A rejected proof still derives K internally; the flag alone
        # keeps it from being released.
        wrong_M = bytes.fromhex(session_params('bob')['M_hex'])
        self.assertIsNone(svr.verify_session(wrong_M))
        self.assertFalse(svr.authenticated())
        self.assertIsNone(svr.get_session_key())

        svr._authenticated = True  # skips the user_M == self.M comparison
        self.assertEqual(
            svr.get_session_key().hex(),
            session_params('alice')['session_key_hex'],
            'forcing _authenticated releases K without Verifier.verify_session '
            'ever matching the client M',
        )


if __name__ == '__main__':
    unittest.main()
