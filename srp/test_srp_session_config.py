#!/usr/bin
"""Tests for session-scoped SRP compatibility configuration.

The legacy ``rfc5054_enable()`` / ``no_username_in_x()`` switches mutate
process-global state. Two tenants needing different compatibility modes must
be able to register and authenticate concurrently without one tenant's
global toggles changing the hash inputs of the other tenant's in-flight
handshake. These tests pin that behavior for every available backend.
"""

import threading
import unittest

import srp
import srp._pysrp as _pysrp

try:
    import srp._ctsrp as _ctsrp
    _CTSRP_AVAILABLE = True
except (ImportError, OSError):
    _ctsrp = None
    _CTSRP_AVAILABLE = False


HASH_ALG = srp.SHA256
NG_TYPE = srp.NG_2048
USERNAME = b'tenant-user'
PASSWORD = b'tenant-password'

ALL_CONFIG_IDS = (
    srp.SRP_CONFIG_LEGACY,
    srp.SRP_CONFIG_RFC5054,
    srp.SRP_CONFIG_NO_USERNAME,
    srp.SRP_CONFIG_RFC5054_NO_USER,
)


def _flip_globals():
    """Exercise the legacy process-global switches."""
    _pysrp.rfc5054_enable(not _pysrp._rfc5054_compat)
    _pysrp.no_username_in_x(not _pysrp._no_username_in_x)
    if _CTSRP_AVAILABLE:
        _ctsrp.rfc5054_enable(_pysrp._rfc5054_compat)
        _ctsrp.no_username_in_x(_pysrp._no_username_in_x)


def _reset_globals():
    _pysrp.rfc5054_enable(False)
    _pysrp.no_username_in_x(False)
    if _CTSRP_AVAILABLE:
        _ctsrp.rfc5054_enable(False)
        _ctsrp.no_username_in_x(False)


def make_record(mod, config_id):
    return mod.create_salted_verification_key(
        USERNAME, PASSWORD, HASH_ALG, NG_TYPE, config=config_id)


def run_handshake(mod, record, client_config, server_config,
                  bytes_a=None, bytes_b=None):
    """Full handshake; returns (client_ok, server_ok, HAMK, client_K)."""
    salt, verifier = record
    client = mod.User(USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                      bytes_a=bytes_a, config=client_config)
    _, public_a = client.start_authentication()
    server = mod.Verifier(USERNAME, salt, verifier, public_a,
                          HASH_ALG, NG_TYPE, bytes_b=bytes_b,
                          config=server_config)
    server_salt, challenge = server.get_challenge()
    proof = client.process_challenge(server_salt, challenge)
    hamk = server.verify_session(proof)
    if hamk is not None:
        client.verify_session(hamk)
    return (client.authenticated(), server.authenticated(),
            hamk, client.get_session_key())


class GlobalSwitchGuard(object):
    """Restores the legacy globals even if a test fails."""

    def __enter__(self):
        _reset_globals()
        return self

    def __exit__(self, *exc):
        _reset_globals()
        return False


class SessionConfigTestsBase(object):
    """Backend-agnostic tests; ``mod`` is supplied by concrete subclasses."""

    mod = None

    def test_legacy_defaults_remain_legacy(self):
        with GlobalSwitchGuard():
            record = self.mod.create_salted_verification_key(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE)
            client = self.mod.User(USERNAME, PASSWORD, HASH_ALG, NG_TYPE)
            self.assertEqual(client.get_config_identifier(),
                             srp.DEFAULT_SRP_CONFIG_ID)
            _, public_a = client.start_authentication()
            server = self.mod.Verifier(
                USERNAME, record[0], record[1], public_a, HASH_ALG, NG_TYPE)
            self.assertEqual(server.get_config_identifier(),
                             srp.DEFAULT_SRP_CONFIG_ID)
            salt, challenge = server.get_challenge()
            proof = client.process_challenge(salt, challenge)
            hamk = server.verify_session(proof)
            self.assertIsNotNone(hamk)
            client.verify_session(hamk)
            self.assertTrue(client.authenticated())
            self.assertTrue(server.authenticated())

    def test_none_config_snapshots_globals_at_construction(self):
        with GlobalSwitchGuard():
            self.mod.rfc5054_enable(True)
            record = self.mod.create_salted_verification_key(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE)
            client = self.mod.User(USERNAME, PASSWORD, HASH_ALG, NG_TYPE)
            _, public_a = client.start_authentication()
            server = self.mod.Verifier(
                USERNAME, record[0], record[1], public_a, HASH_ALG, NG_TYPE)
            self.assertTrue(client.get_config().rfc5054_compat)
            # A global change after construction must not affect the session.
            self.mod.rfc5054_enable(False)
            self.mod.no_username_in_x(True)
            salt, challenge = server.get_challenge()
            proof = client.process_challenge(salt, challenge)
            hamk = server.verify_session(proof)
            self.assertIsNotNone(hamk)
            client.verify_session(hamk)
            self.assertTrue(server.authenticated())
            self.assertTrue(client.authenticated())

    def test_every_explicit_mode_authenticates(self):
        with GlobalSwitchGuard():
            for config_id in ALL_CONFIG_IDS:
                record = make_record(self.mod, config_id)
                client_ok, server_ok, hamk, _ = run_handshake(
                    self.mod, record, config_id, config_id)
                self.assertTrue(client_ok, config_id)
                self.assertTrue(server_ok, config_id)
                self.assertIsNotNone(hamk, config_id)

    def test_interleaved_tenants_respect_their_own_mode(self):
        with GlobalSwitchGuard():
            # Registration phase, toggles deliberately between the two tenants.
            record_legacy = make_record(self.mod, srp.SRP_CONFIG_LEGACY)
            _flip_globals()
            record_rfc = make_record(self.mod, srp.SRP_CONFIG_RFC5054)
            _flip_globals()

            # Start an RFC5054 handshake, then flip globals before its proof.
            client_rfc = self.mod.User(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                config=srp.SRP_CONFIG_RFC5054)
            _, public_rfc = client_rfc.start_authentication()
            server_rfc = self.mod.Verifier(
                USERNAME, record_rfc[0], record_rfc[1], public_rfc,
                HASH_ALG, NG_TYPE, config=srp.SRP_CONFIG_RFC5054)
            salt_rfc, challenge_rfc = server_rfc.get_challenge()

            _flip_globals()

            # A legacy tenant registers and authenticates in the middle of the
            # RFC5054 tenant's paused handshake.
            record_legacy_new = make_record(self.mod, srp.SRP_CONFIG_LEGACY)
            legacy_ok = run_handshake(
                self.mod, record_legacy_new,
                srp.SRP_CONFIG_LEGACY, srp.SRP_CONFIG_LEGACY)
            self.assertTrue(legacy_ok[0] and legacy_ok[1])

            # Resume the RFC5054 handshake; globals have changed twice.
            proof_rfc = client_rfc.process_challenge(salt_rfc, challenge_rfc)
            hamk_rfc = server_rfc.verify_session(proof_rfc)
            self.assertIsNotNone(hamk_rfc)
            client_rfc.verify_session(hamk_rfc)
            self.assertTrue(client_rfc.authenticated())
            self.assertTrue(server_rfc.authenticated())

            # The first legacy record keeps its mode despite every toggle.
            legacy_recheck = run_handshake(
                self.mod, record_legacy,
                srp.SRP_CONFIG_LEGACY, srp.SRP_CONFIG_LEGACY)
            self.assertTrue(legacy_recheck[0] and legacy_recheck[1])

    def test_concurrent_tenants_ignore_global_toggles(self):
        with GlobalSwitchGuard():
            records = {
                srp.SRP_CONFIG_LEGACY:
                    make_record(self.mod, srp.SRP_CONFIG_LEGACY),
                srp.SRP_CONFIG_RFC5054:
                    make_record(self.mod, srp.SRP_CONFIG_RFC5054),
            }
            errors = []
            stop = threading.Event()

            def toggle_worker():
                while not stop.is_set():
                    _flip_globals()

            def auth_worker(config_id, iterations):
                try:
                    for _ in range(iterations):
                        client_ok, server_ok, _, _ = run_handshake(
                            self.mod, records[config_id], config_id, config_id)
                        if not client_ok or not server_ok:
                            errors.append(
                                'legal handshake rejected for %s' % config_id)
                except Exception as exc:  # pragma: no cover - failure path
                    errors.append(repr(exc))

            threads = [
                threading.Thread(target=toggle_worker),
                threading.Thread(
                    target=auth_worker,
                    args=(srp.SRP_CONFIG_LEGACY, 6)),
                threading.Thread(
                    target=auth_worker,
                    args=(srp.SRP_CONFIG_RFC5054, 6)),
            ]
            for thread in threads:
                thread.start()
            threads[1].join()
            threads[2].join()
            stop.set()
            threads[0].join()
            self.assertEqual(errors, [])

    def test_cross_mode_proofs_are_always_rejected(self):
        with GlobalSwitchGuard():
            for server_id in ALL_CONFIG_IDS:
                record = make_record(self.mod, server_id)
                for client_id in ALL_CONFIG_IDS:
                    if client_id == server_id:
                        continue
                    _flip_globals()  # globals must not rescue a mode mismatch
                    client_ok, server_ok, hamk, _ = run_handshake(
                        self.mod, record, client_id, server_id)
                    self.assertIsNone(
                        hamk,
                        'mismatch accepted: client=%s server=%s'
                        % (client_id, server_id))
                    self.assertFalse(client_ok)
                    self.assertFalse(server_ok)

    def test_rejected_proof_is_not_retried_with_other_modes(self):
        with GlobalSwitchGuard():
            record = make_record(self.mod, srp.SRP_CONFIG_RFC5054)
            client = self.mod.User(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                config=srp.SRP_CONFIG_LEGACY)
            _, public_a = client.start_authentication()
            server = self.mod.Verifier(
                USERNAME, record[0], record[1], public_a, HASH_ALG, NG_TYPE,
                config=srp.SRP_CONFIG_RFC5054)
            salt, challenge = server.get_challenge()
            proof = client.process_challenge(salt, challenge)
            self.assertIsNone(server.verify_session(proof))
            self.assertFalse(server.authenticated())
            # Re-presenting the same mismatched proof fails again; no internal
            # fallback to weaker/different parameters ever happens.
            self.assertIsNone(server.verify_session(proof))
            self.assertFalse(server.authenticated())

    def test_global_toggles_do_not_change_frozen_session_outputs(self):
        with GlobalSwitchGuard():
            record = make_record(self.mod, srp.SRP_CONFIG_RFC5054)
            ephemeral_len = 256 if self.mod is _pysrp else 32
            bytes_a = _pysrp.long_to_bytes(
                _pysrp.get_random_of_length(ephemeral_len))
            bytes_b = _pysrp.long_to_bytes(
                _pysrp.get_random_of_length(ephemeral_len))

            baseline = run_handshake(
                self.mod, record, srp.SRP_CONFIG_RFC5054,
                srp.SRP_CONFIG_RFC5054, bytes_a, bytes_b)

            _flip_globals()
            toggled = run_handshake(
                self.mod, record, srp.SRP_CONFIG_RFC5054,
                srp.SRP_CONFIG_RFC5054, bytes_a, bytes_b)

            self.assertEqual(baseline[2], toggled[2])
            self.assertEqual(baseline[3], toggled[3])
            self.assertTrue(toggled[0] and toggled[1])

    def test_record_identifier_roundtrip_and_unknown_id_fails_closed(self):
        with GlobalSwitchGuard():
            for config_id in ALL_CONFIG_IDS:
                record = make_record(self.mod, config_id)
                # Server rebuilds the mode from the identifier stored with the
                # salt/verifier rather than from any global switch.
                _flip_globals()
                client = self.mod.User(
                    USERNAME, PASSWORD, HASH_ALG, NG_TYPE, config=config_id)
                _, public_a = client.start_authentication()
                server = self.mod.Verifier(
                    USERNAME, record[0], record[1], public_a,
                    HASH_ALG, NG_TYPE, config=config_id)
                self.assertEqual(server.get_config_identifier(), config_id)
                salt, challenge = server.get_challenge()
                proof = client.process_challenge(salt, challenge)
                self.assertIsNotNone(server.verify_session(proof))

            with self.assertRaises(ValueError):
                self.mod.User(
                    USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                    config='no-such-tenant-mode')
            with self.assertRaises(ValueError):
                self.mod.Verifier(
                    USERNAME, record[0], record[1], None,
                    HASH_ALG, NG_TYPE, config='no-such-tenant-mode')

    def test_config_is_immutable_and_custom_configs_roundtrip(self):
        config = srp.SrpConfig(rfc5054_compat=True, no_username_in_x=True)
        with self.assertRaises(AttributeError):
            config.rfc5054_compat = False
        with GlobalSwitchGuard():
            srp.register_srp_config('tenant-custom', config)
            record = make_record(self.mod, 'tenant-custom')
            client_ok, server_ok, _, _ = run_handshake(
                self.mod, record, 'tenant-custom', 'tenant-custom')
            self.assertTrue(client_ok and server_ok)
        with self.assertRaises(TypeError):
            srp.register_srp_config('bad', object())
        with self.assertRaises(ValueError):
            srp.srp_config_identifier(object())

    def test_legacy_record_migration_path(self):
        with GlobalSwitchGuard():
            # Simulate a pre-existing record that has no stored mode. The
            # migration assigns the default identifier rather than probing.
            legacy_record = self.mod.create_salted_verification_key(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE)
            database = {
                USERNAME: (legacy_record[0], legacy_record[1],
                           srp.DEFAULT_SRP_CONFIG_ID),
            }
            salt, verifier, stored_id = database[USERNAME]
            client_ok, server_ok, _, _ = run_handshake(
                self.mod, (salt, verifier), stored_id, stored_id)
            self.assertTrue(client_ok and server_ok)


@unittest.skipUnless(_CTSRP_AVAILABLE, 'ctypes backend unavailable')
class MixedBackendSessionConfigTests(unittest.TestCase):
    def test_py_client_ct_server_same_mode(self):
        with GlobalSwitchGuard():
            for config_id in ALL_CONFIG_IDS:
                record = _ctsrp.create_salted_verification_key(
                    USERNAME, PASSWORD, HASH_ALG, NG_TYPE, config=config_id)
                client_ok, server_ok, hamk, _ = run_handshake(
                    _ctsrp, record, config_id, config_id)
                self.assertTrue(client_ok and server_ok, config_id)
                self.assertIsNotNone(hamk)

    def test_py_client_ct_server_cross_mode_rejected(self):
        with GlobalSwitchGuard():
            record = _ctsrp.create_salted_verification_key(
                USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                config=srp.SRP_CONFIG_RFC5054)
            client_ok, server_ok, hamk, _ = run_handshake(
                _ctsrp, record, srp.SRP_CONFIG_LEGACY,
                srp.SRP_CONFIG_RFC5054)
            self.assertIsNone(hamk)
            self.assertFalse(client_ok or server_ok)


class PySRPSessionConfigTests(SessionConfigTestsBase, unittest.TestCase):
    mod = _pysrp


@unittest.skipUnless(_CTSRP_AVAILABLE, 'ctypes backend unavailable')
class CTSRPSessionConfigTests(SessionConfigTestsBase, unittest.TestCase):
    mod = _ctsrp


if __name__ == '__main__':
    unittest.main(verbosity=2)
