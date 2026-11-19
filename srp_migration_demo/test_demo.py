"""Unit tests for the SHA-1 -> SHA-256 SRP migration demo.

Run: python -m unittest srp_migration_demo.test_demo -v
"""

import os
import shutil
import tempfile
import unittest

import srp

from .migration import (attempt_login, open_store, register_new_user,
                        review, seed_legacy_user, upgrade_after_login)
from .params import LEGACY_PARAM_SET, TARGET_PARAM_SET, ParameterError
from .protocol import (AuthService, AuthenticationFailed, Client,
                       UpgradeRejected, full_login)
from .store import (ConflictError, SimulatedCrash, _atomic_write,
                    validate_record)


class MigrationTestBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="srp-migrate-test-")
        self.store, _ = open_store(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)


class RecordFormatTests(MigrationTestBase):
    def test_legacy_and_target_records_are_self_describing(self):
        seed_legacy_user(self.store, "alice", "pw")
        register_new_user(self.store, "zoe", "pw")
        legacy = self.store.get_record("alice")
        target = self.store.get_record("zoe")
        self.assertEqual(legacy["param_set"], LEGACY_PARAM_SET)
        self.assertEqual(legacy["params"]["digest"], "sha1")
        self.assertEqual(target["param_set"], TARGET_PARAM_SET)
        self.assertEqual(target["params"]["digest"], "sha256")
        for record in (legacy, target):
            validate_record(record)
            self.assertNotIn("legacy_verifier", record)

    def test_dual_material_record_is_rejected(self):
        seed_legacy_user(self.store, "alice", "pw")
        record = self.store.get_record("alice")
        record["verifier_sha256"] = record["verifier"]
        with self.assertRaises(ValueError):
            validate_record(record)


class LoginAndUpgradeTests(MigrationTestBase):
    def test_full_upgrade_roundtrip(self):
        seed_legacy_user(self.store, "alice", "secret")
        before = self.store.get_record("alice")
        _, after, new_salt, new_v = upgrade_after_login(
            self.store, "alice", "secret")
        self.assertEqual(after["param_set"], TARGET_PARAM_SET)
        self.assertEqual(after["revision"], before["revision"] + 1)
        self.assertNotEqual(after["salt"], before["salt"])
        self.assertNotEqual(after["verifier"], before["verifier"])
        self.assertEqual(self.store.list_journals(), [])
        # The new record authenticates under SHA-256; presenting the legacy
        # parameter set against it is refused before SRP runs (no
        # renegotiation), not merely rejected at proof verification.
        attempt_login(self.store, "alice", "secret", TARGET_PARAM_SET)
        with self.assertRaises(ParameterError):
            attempt_login(self.store, "alice", "secret", LEGACY_PARAM_SET)
        # Honesty: the new verifier is not a function of the old verifier.
        self.assertNotEqual(new_v.hex(), before["verifier"])
        self.assertNotEqual(new_salt.hex(), before["salt"])

    def test_wrong_password_leaves_record_untouched(self):
        seed_legacy_user(self.store, "alice", "secret")
        before = self.store.get_record("alice")
        with self.assertRaises(AuthenticationFailed):
            upgrade_after_login(self.store, "alice", "typo")
        after = self.store.get_record("alice")
        self.assertEqual(after, before)
        self.assertEqual(self.store.list_journals(), [])
        attempt_login(self.store, "alice", "secret", LEGACY_PARAM_SET)

    def test_tampered_envelope_is_rejected(self):
        seed_legacy_user(self.store, "alice", "secret")
        service, sid, client = full_login(
            self.store, "alice", "secret", LEGACY_PARAM_SET)
        envelope, _, _ = client.build_upgrade_envelope(TARGET_PARAM_SET)
        envelope["payload"]["salt"] = "00" * 16
        with self.assertRaises(UpgradeRejected):
            service.begin_upgrade(sid, envelope)
        self.assertEqual(
            self.store.get_record("alice")["param_set"], LEGACY_PARAM_SET)

    def test_illegal_upgrade_path_is_rejected(self):
        # A user already on SHA-256 has no further path in this demo.
        register_new_user(self.store, "zoe", "secret")
        service, sid, client = full_login(
            self.store, "zoe", "secret", TARGET_PARAM_SET)
        envelope, _, _ = client.build_upgrade_envelope(TARGET_PARAM_SET)
        with self.assertRaises(UpgradeRejected):
            service.begin_upgrade(sid, envelope)

    def test_parallel_upgrades_one_winner_one_cas_loss(self):
        seed_legacy_user(self.store, "alice", "secret")
        svc1, sid1, c1 = full_login(
            self.store, "alice", "secret", LEGACY_PARAM_SET)
        svc2, sid2, c2 = full_login(
            self.store, "alice", "secret", LEGACY_PARAM_SET)
        e1, _, _ = c1.build_upgrade_envelope(TARGET_PARAM_SET)
        e2, _, _ = c2.build_upgrade_envelope(TARGET_PARAM_SET)
        svc1.begin_upgrade(sid1, e1)
        svc2.begin_upgrade(sid2, e2)
        winner = svc1.commit_upgrade(sid1)
        self.assertEqual(winner["param_set"], TARGET_PARAM_SET)
        with self.assertRaises(ConflictError):
            svc2.commit_upgrade(sid2)
        self.assertEqual(self.store.list_journals(), [])
        self.assertEqual(
            self.store.get_record("alice")["revision"], winner["revision"])


class RecoveryTests(MigrationTestBase):
    def test_crash_after_replace_is_reconciled_on_restart(self):
        seed_legacy_user(self.store, "alice", "secret")
        with self.assertRaises(SimulatedCrash):
            upgrade_after_login(self.store, "alice", "secret",
                                crash_after_replace=True)
        self.assertEqual(len(self.store.list_journals()), 1)
        store2, recovery = open_store(self.root)
        self.assertEqual(len(recovery["completed_cleanup"]), 1)
        self.assertEqual(store2.list_journals(), [])
        record = store2.get_record("alice")
        self.assertEqual(record["param_set"], TARGET_PARAM_SET)
        attempt_login(store2, "alice", "secret", TARGET_PARAM_SET)

    def test_unapplied_journal_is_quarantined_not_committed(self):
        seed_legacy_user(self.store, "bob", "secret")
        before = self.store.get_record("bob")
        svc, sid, client = full_login(
            self.store, "bob", "secret", LEGACY_PARAM_SET)
        env, _, _ = client.build_upgrade_envelope(TARGET_PARAM_SET)
        svc.begin_upgrade(sid, env)
        store2, recovery = open_store(self.root)
        self.assertEqual(len(recovery["quarantined"]), 1)
        self.assertTrue(os.listdir(store2.quarantine_dir))
        self.assertEqual(store2.list_journals(), [])
        untouched = store2.get_record("bob")
        self.assertEqual(untouched["verifier"], before["verifier"])
        self.assertEqual(untouched["param_set"], LEGACY_PARAM_SET)
        _, after, _, _ = upgrade_after_login(store2, "bob", "secret")
        self.assertEqual(after["param_set"], TARGET_PARAM_SET)


class ParameterBindingTests(MigrationTestBase):
    def test_handshake_cannot_renegotiate_parameter_set(self):
        seed_legacy_user(self.store, "alice", "secret")
        client = Client("alice", "secret", TARGET_PARAM_SET)
        service = AuthService(self.store)
        _, A = client.start()
        with self.assertRaises(ParameterError):
            service.challenge("alice", A, TARGET_PARAM_SET)

    def test_relabelled_verifier_fails_the_new_handshake(self):
        seed_legacy_user(self.store, "alice", "secret")
        legacy = self.store.get_record("alice")
        from .params import describe
        forged = dict(legacy)
        forged["param_set"] = TARGET_PARAM_SET
        forged["params"] = describe(TARGET_PARAM_SET)
        forged["revision"] = legacy["revision"] + 1
        forged["history"] = list(legacy["history"])
        validate_record(forged)  # shape alone cannot detect the lie
        _atomic_write(self.store._user_path("alice"), forged)

        client = Client("alice", "secret", TARGET_PARAM_SET)
        service = AuthService(self.store)
        _, A = client.start()
        sid, salt, B, _ = service.challenge("alice", A, TARGET_PARAM_SET)
        M = client.process_challenge(salt, B, TARGET_PARAM_SET)
        with self.assertRaises(AuthenticationFailed):
            service.verify(sid, M)

    def test_global_toggle_drift_is_detected(self):
        seed_legacy_user(self.store, "alice", "secret")
        srp._mod.rfc5054_enable(True)
        try:
            with self.assertRaises(ParameterError):
                open_store(self.root)
        finally:
            srp._mod.rfc5054_enable(False)

    def test_review_flags_password_requirement(self):
        seed_legacy_user(self.store, "alice", "secret")
        register_new_user(self.store, "zoe", "secret")
        report = review(self.store)
        self.assertEqual([u["username"] for u in report["legacy"]], ["alice"])
        self.assertTrue(report["legacy"][0]["needs_password"])
        self.assertFalse(report["upgraded"][0]["needs_password"])


if __name__ == "__main__":
    unittest.main()
