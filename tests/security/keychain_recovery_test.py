# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
"""
Fault-injection tests for PIB (SQLite) / file-TPM consistency diagnostics and
recovery.  Every test builds its stores inside a TemporaryDirectory and injects
a failure at a specific boundary of key creation, certificate import or
deletion, so the resulting half-finished state is examined exactly the way a
backend would encounter it after a crash.
"""
import os
import sqlite3
from base64 import b64decode
from tempfile import TemporaryDirectory

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from ndn.app_support.security_v2 import self_sign
from ndn.encoding import (Name, MetaInfo, make_data, parse_data)
from ndn.security import (
    KeychainSqlite3, TpmFile,
    check_consistency, apply_repairs, KeychainRecoveryError,
    ConsistencyReport,
    ORPHAN_PRIVATE_KEY, MISSING_PRIVATE_KEY, PRIVATE_KEY_MISMATCH,
    UNREADABLE_PRIVATE_KEY, KEY_WITHOUT_CERTIFICATE,
    DANGLING_KEY_METADATA, DANGLING_CERTIFICATE_METADATA,
    BROKEN_DEFAULT_IDENTITY,
    REMOVE_TPM_FILE, REMOVE_KEY_METADATA, REMOVE_CERTIFICATE_METADATA,
)


class InjectedFailure(Exception):
    """Raised by test doubles to simulate a crash at a specific boundary."""


def open_keychain(base_dir: str) -> tuple[KeychainSqlite3, TpmFile, str, str]:
    pib_path = os.path.join(base_dir, 'pib.db')
    tpm_dir = os.path.join(base_dir, 'ndnsec-key-file')
    KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_dir)
    tpm = TpmFile(tpm_dir)
    return KeychainSqlite3(pib_path, tpm), tpm, pib_path, tpm_dir


def tpm_file_for(tpm_dir: str, key_name) -> str:
    return os.path.join(tpm_dir, TpmFile._to_file_name(Name.to_bytes(key_name)))


def fail_once(method, exc=InjectedFailure):
    """Wrap a bound method so its next call raises and later calls pass through."""
    state = {'failed': False, 'original': method}

    def wrapper(*args, **kwargs):
        if not state['failed']:
            state['failed'] = True
            raise exc('injected failure')
        return state['original'](*args, **kwargs)

    return wrapper


def make_execute_fail_at(substring: str):
    """Return a connection proxy whose execute fails on SQL containing substring."""
    class FailingConnection:
        def __init__(self, conn):
            object.__setattr__(self, '_conn', conn)

        def execute(self, sql, parameters=()):
            if substring in sql:
                raise InjectedFailure(f'injected failure at: {substring}')
            return self._conn.execute(sql, parameters)

        def __getattr__(self, item):
            return getattr(object.__getattribute__(self, '_conn'), item)

        def __setattr__(self, key, value):
            setattr(object.__getattribute__(self, '_conn'), key, value)

    return FailingConnection


def verify_with_pubkey(packet: bytes, pub_key_der: bytes):
    _, _, _, sig_ptrs = parse_data(packet)
    digest = SHA256.new()
    for covered in sig_ptrs.signature_covered_part:
        digest.update(covered)
    try:
        verifier = DSS.new(ECC.import_key(pub_key_der), 'fips-186-3', 'der')
        verifier.verify(digest, bytes(sig_ptrs.signature_value_buf))
    except Exception:
        from Cryptodome.PublicKey import RSA
        from Cryptodome.Signature import pkcs1_15
        pkcs1_15.new(RSA.import_key(pub_key_der)).verify(
            digest, bytes(sig_ptrs.signature_value_buf))
    return sig_ptrs.signature_info.key_locator.name


def codes(report: ConsistencyReport) -> set[str]:
    return {f.code for f in report.findings}


def assert_no_private_material(report: ConsistencyReport, base_dir: str):
    # Collect every base64 chunk of every private key and ensure none of it,
    # nor the decoded DER, appears anywhere in the serialized report.
    blob = str(report.to_dict())
    tpm_dir = report.tpm_path
    for name in os.listdir(tpm_dir):
        if not name.endswith('.privkey'):
            continue
        with open(os.path.join(tpm_dir, name), 'rb') as f:
            raw_b64 = f.read()
        assert raw_b64 not in blob.encode()
        try:
            der = b64decode(raw_b64)
        except Exception:
            # A corrupt file has no DER to leak; its raw bytes were already
            # checked above.
            continue
        assert der.hex() not in blob
        assert der not in blob.encode()


class TestKeychainRecovery:
    def test_healthy_keychain_is_clean_and_signable(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/healthy')
            key = kc.default_identity().default_key()
            pub_key = key.key_bits
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert report.healthy
            assert report.findings == []
            assert report.default_identity == Name.from_str('/test/healthy')
            assert report.default_identity_usable
            assert len(report.key_status) == 1
            assert report.key_status[0].tpm_file_present
            assert report.findings_of(ORPHAN_PRIVATE_KEY) == []

            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            packet = make_data('/test/data', MetaInfo(), b'payload',
                               signer=kc2.get_signer({}))
            key_locator = verify_with_pubkey(packet, pub_key)
            assert Name.normalize(key_locator) == Name.normalize(
                kc2.default_identity().default_key().default_cert().name)
            kc2.shutdown()

    def test_private_key_generated_but_database_fails_leaves_orphan(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.new_identity('/test/orphan')
            # The private key file is written inside generate_key; make the
            # first subsequent database write fail, simulating a crash before
            # any key metadata is committed.
            kc.conn = make_execute_fail_at('INSERT INTO keys')(kc.conn)
            try:
                kc.new_key('/test/orphan')
            except InjectedFailure:
                pass
            else:  # pragma: no cover
                raise AssertionError('failure was not injected')
            kc.shutdown()

            assert len(os.listdir(tpm_dir)) == 1
            orphan_file = os.listdir(tpm_dir)[0]

            report = check_consistency(pib_path, tpm_dir)
            assert not report.healthy
            assert codes(report) == {ORPHAN_PRIVATE_KEY, BROKEN_DEFAULT_IDENTITY}
            finding = report.findings_of(ORPHAN_PRIVATE_KEY)[0]
            assert finding.evidence['tpm_file'] == orphan_file
            # Association evidence is the naming rule, not a guessed same-name key.
            assert finding.evidence['referenced_tpm_files'] == []
            assert len(finding.repairs) == 1
            assert finding.repairs[0].action == REMOVE_TPM_FILE
            # Nothing was promoted to a usable default.
            assert not report.default_identity_usable
            assert_no_private_material(report, tmp)

            results = apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            assert results == [{'action': REMOVE_TPM_FILE, 'target': orphan_file,
                                'applied': True, 'reason': results[0]['reason']}]
            assert os.listdir(tpm_dir) == []
            # The orphan is gone; only the key-less default identity finding stays.
            assert codes(check_consistency(pib_path, tpm_dir)) == {BROKEN_DEFAULT_IDENTITY}

    def test_dangling_metadata_when_tpm_file_disappears(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/dangling')
            key = kc.default_identity().default_key()
            key_name = key.name
            pub_key = key.key_bits
            os.remove(tpm_file_for(tpm_dir, key_name))
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert codes(report) == {MISSING_PRIVATE_KEY, BROKEN_DEFAULT_IDENTITY}
            missing = report.findings_of(MISSING_PRIVATE_KEY)[0]
            assert missing.evidence['key_name'] == Name.to_str(key_name)
            assert missing.evidence['public_key_fingerprint'] == \
                SHA256.new(pub_key).hexdigest()
            assert [r.action for r in missing.repairs] == [REMOVE_KEY_METADATA]
            assert not report.default_identity_usable

            # The broken default must not be handed out as a signer.
            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            try:
                kc2.get_signer({})
            except KeychainRecoveryError:
                pass
            else:  # pragma: no cover
                raise AssertionError('broken default identity was offered as signer')
            kc2.shutdown()

            results = apply_repairs(pib_path, tpm_dir, report,
                                    action_ids={REMOVE_KEY_METADATA})
            assert results[0]['applied'] is True
            # Certificates cascade with the key row; default flags are untouched.
            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.findings_of(MISSING_PRIVATE_KEY) == []
            assert codes(report2) == {BROKEN_DEFAULT_IDENTITY}
            assert report2.default_identity == Name.from_str('/test/dangling')

    def test_half_finished_deletion_orphans_tpm_file(self):
        with TemporaryDirectory() as tmp:
            kc, tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/halfdel')
            key_name = kc.default_identity().default_key().name
            # Metadata commit succeeds; the TPM removal crashes, leaving the
            # private key file behind with no PIB reference.
            tpm.delete_key = fail_once(tpm.delete_key)
            try:
                kc.del_key(key_name)
            except InjectedFailure:
                pass
            else:  # pragma: no cover
                raise AssertionError('failure was not injected')
            kc.shutdown()

            assert len(os.listdir(tpm_dir)) == 1
            report = check_consistency(pib_path, tpm_dir)
            assert codes(report) == {ORPHAN_PRIVATE_KEY, BROKEN_DEFAULT_IDENTITY}
            orphan = report.findings_of(ORPHAN_PRIVATE_KEY)[0]
            assert orphan.evidence['tpm_file'] == os.listdir(tpm_dir)[0]
            assert orphan.evidence['referenced_tpm_files'] == []

            apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.findings_of(ORPHAN_PRIVATE_KEY) == []
            assert os.listdir(tpm_dir) == []

    def test_half_finished_deletion_keeps_tpm_and_dangling_metadata(self):
        with TemporaryDirectory() as tmp:
            kc, tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/halfdel2')
            # A second key is the target: the identity keeps a healthy default
            # key while this key's deletion is interrupted between the two
            # stores.
            victim = kc.new_key('/test/halfdel2')
            victim_name = victim.name
            assert len(os.listdir(tpm_dir)) == 2
            # Model a crash between the PIB commit and the TPM removal: keep
            # the key/cert rows in place while deleting the private key file.
            os.remove(tpm_file_for(tpm_dir, victim_name))
            kc.shutdown()

            # One healthy TPM file remains; the victim's file was removed.
            assert len(os.listdir(tpm_dir)) == 1
            report = check_consistency(pib_path, tpm_dir)
            assert MISSING_PRIVATE_KEY in codes(report)
            missing = report.findings_of(MISSING_PRIVATE_KEY)[0]
            assert missing.evidence['key_name'] == Name.to_str(victim_name)
            # A healthy default key still backs the identity.
            assert report.default_identity_usable
            apply_repairs(pib_path, tpm_dir, report,
                          action_ids={REMOVE_KEY_METADATA})
            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.findings_of(MISSING_PRIVATE_KEY) == []
            assert report2.healthy

    def test_certificate_import_failure_leaves_key_without_certificate(self):
        with TemporaryDirectory() as tmp:
            kc, tpm, pib_path, tpm_dir = open_keychain(tmp)
            # A first, complete key keeps the identity usable while a second
            # key exists with no certificate.
            kc.touch_identity('/test/nocert')
            identity = kc['/test/nocert']
            identity_row = identity.row_id
            # Generate the key pair through the TPM exactly like new_key does,
            # then commit only the key row: the precise state left by a crash
            # during certificate import.
            key_name, pub_key = tpm.generate_key(identity.name)
            kc.conn.execute('INSERT INTO keys (identity_id, key_name, key_bits) '
                            'VALUES (?, ?, ?)',
                            (identity_row, Name.to_bytes(key_name), bytes(pub_key)))
            kc.conn.commit()
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert KEY_WITHOUT_CERTIFICATE in codes(report)
            nocert = report.findings_of(KEY_WITHOUT_CERTIFICATE)[0]
            # This condition is recoverable by importing a cert: no destructive
            # repair is suggested automatically.
            assert nocert.repairs == []
            # The untouched first key keeps the default chain usable.
            assert report.default_identity_usable

            # A fresh keychain still exposes the key and its private material.
            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            identity = kc2['/test/nocert']
            assert len(identity) == 2
            key = identity[key_name]
            assert not key.has_default_cert()
            assert kc2.tpm.key_exist(key.name)
            assert key.key_bits == bytes(pub_key)

            # Recovery path: re-import a self-signed certificate, then sign and
            # verify against the same public key.
            signer = kc2.tpm.get_signer(key.name)
            cert_name, cert_data = self_sign(key.name, pub_key, signer)
            kc2.import_cert(key.name, cert_name, cert_data)
            packet = make_data('/test/data', MetaInfo(), b'payload',
                               signer=kc2.get_signer({'key': key.name}))
            key_locator = verify_with_pubkey(packet, pub_key)
            assert Name.normalize(key_locator) == Name.normalize(cert_name)
            kc2.shutdown()

            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.healthy
            assert report2.default_identity_usable

    def test_retry_after_failure_recovers_and_signs_with_same_public_key(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.new_identity('/test/retry')
            kc.conn = make_execute_fail_at('INSERT INTO keys')(kc.conn)
            try:
                kc.new_key('/test/retry')
            except InjectedFailure:
                pass
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert codes(report) == {ORPHAN_PRIVATE_KEY, BROKEN_DEFAULT_IDENTITY}
            orphan_file = report.findings_of(ORPHAN_PRIVATE_KEY)[0].evidence['tpm_file']

            # Clean the orphan, then retry key generation through a new process
            # equivalent (fresh connection to the same on-disk stores).
            apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            key = kc2.new_key('/test/retry')
            pub_key = key.key_bits
            kc2.set_default_identity('/test/retry')
            packet = make_data('/test/data', MetaInfo(), b'payload',
                               signer=kc2.get_signer({}))
            key_locator = verify_with_pubkey(packet, pub_key)
            assert Name.normalize(key_locator) == Name.normalize(
                key.default_cert().name)
            kc2.shutdown()

            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.healthy
            # The old orphan file is gone; only the retried key's file remains.
            remaining = os.listdir(tpm_dir)
            assert remaining == [TpmFile._to_file_name(Name.to_bytes(key.name))]
            assert orphan_file not in remaining

    def test_private_key_mismatch_detected_by_public_key_not_filename(self):
        with TemporaryDirectory() as tmp:
            kc, tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/mismatch')
            key = kc.default_identity().default_key()
            target_file = tpm_file_for(tpm_dir, key.name)

            # Generate a second, unrelated key and overwrite the first key's
            # file while keeping the correct (Name-hash derived) file name.
            other_name, _other_pub = tpm.generate_key(
                Name.from_str('/test/other'))
            with open(tpm_file_for(tpm_dir, other_name), 'rb') as f:
                foreign_material = f.read()
            with open(target_file, 'wb') as f:
                f.write(foreign_material)
            os.remove(tpm_file_for(tpm_dir, other_name))
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert codes(report) == {PRIVATE_KEY_MISMATCH, BROKEN_DEFAULT_IDENTITY}
            mismatch = report.findings_of(PRIVATE_KEY_MISMATCH)[0]
            assert mismatch.evidence['tpm_file'] == os.path.basename(target_file)
            assert mismatch.evidence['pib_public_key_fingerprint'] != \
                mismatch.evidence['tpm_public_key_fingerprint']
            # Two independent, evidence-backed options are offered; neither is
            # applied automatically.
            assert {r.action for r in mismatch.repairs} == \
                {REMOVE_TPM_FILE, REMOVE_KEY_METADATA}
            assert_no_private_material(report, tmp)
            assert not report.default_identity_usable

    def test_unreadable_private_key_file_is_reported(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/corrupt')
            key_name = kc.default_identity().default_key().name
            with open(tpm_file_for(tpm_dir, key_name), 'wb') as f:
                f.write(b'this is definitely not a key')
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            assert UNREADABLE_PRIVATE_KEY in codes(report)
            unreadable = report.findings_of(UNREADABLE_PRIVATE_KEY)[0]
            assert 'parse_error' in unreadable.evidence
            assert unreadable.repairs[0].action == REMOVE_TPM_FILE
            assert_no_private_material(report, tmp)

    def test_dangling_certificate_row_from_broken_foreign_key(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/fk')
            key = kc.default_identity().default_key()
            cert_name = key.default_cert().name
            # Remove the key row directly, bypassing ON DELETE CASCADE (which is
            # only active under PRAGMA foreign_keys=ON).
            conn = sqlite3.connect(pib_path)
            conn.execute('DELETE FROM keys WHERE key_name=?',
                         (Name.to_bytes(key.name),))
            conn.commit()
            conn.close()

            report = check_consistency(pib_path, tpm_dir)
            assert DANGLING_CERTIFICATE_METADATA in codes(report)
            dangling = report.findings_of(DANGLING_CERTIFICATE_METADATA)[0]
            assert dangling.evidence['certificate_name'] == Name.to_str(cert_name)
            assert dangling.repairs[0].action == REMOVE_CERTIFICATE_METADATA
            # The now-orphaned TPM file is reported independently.
            assert ORPHAN_PRIVATE_KEY in codes(report)

            apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            report2 = check_consistency(pib_path, tpm_dir)
            assert report2.findings_of(DANGLING_CERTIFICATE_METADATA) == []
            assert report2.findings_of(ORPHAN_PRIVATE_KEY) == []

    def test_dangling_key_row_from_broken_foreign_key(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/fk2')
            key_name = kc.default_identity().default_key().name
            conn = sqlite3.connect(pib_path)
            conn.execute('DELETE FROM identities WHERE identity=?',
                         (Name.to_bytes('/test/fk2'),))
            conn.commit()
            conn.close()

            report = check_consistency(pib_path, tpm_dir)
            assert DANGLING_KEY_METADATA in codes(report)
            dangling = report.findings_of(DANGLING_KEY_METADATA)[0]
            assert dangling.evidence['key_name'] == Name.to_str(key_name)
            apply_repairs(pib_path, tpm_dir, report,
                          action_ids={REMOVE_KEY_METADATA})
            assert check_consistency(pib_path, tpm_dir).findings_of(
                DANGLING_KEY_METADATA) == []

    def test_default_identity_repairs_do_not_rewrite_default_flags(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/flags')
            key_name = kc.default_identity().default_key().name
            os.remove(tpm_file_for(tpm_dir, key_name))
            kc.shutdown()

            conn = sqlite3.connect(pib_path)
            cursor = conn.execute('SELECT identity, is_default FROM identities')
            before = cursor.fetchall()
            cursor.close()
            conn.close()

            report = check_consistency(pib_path, tpm_dir)
            apply_repairs(pib_path, tpm_dir, report, apply_all=True)

            conn = sqlite3.connect(pib_path)
            cursor = conn.execute('SELECT identity, is_default FROM identities')
            after = cursor.fetchall()
            cursor.close()
            conn.close()
            assert before == after
            assert not check_consistency(pib_path, tpm_dir).default_identity_usable

    def test_check_is_read_only_and_path_scoped(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/scope')
            kc.shutdown()

            before_pib = open(pib_path, 'rb').read()
            before_tpm = {n: open(os.path.join(tpm_dir, n), 'rb').read()
                          for n in os.listdir(tpm_dir)}
            report = check_consistency(pib_path, tpm_dir)
            assert report.pib_path == pib_path
            assert report.tpm_path == tpm_dir
            assert open(pib_path, 'rb').read() == before_pib
            after_tpm = {n: open(os.path.join(tpm_dir, n), 'rb').read()
                         for n in os.listdir(tpm_dir)}
            assert after_tpm == before_tpm

            # A second, unrelated TPM directory must never be consulted.
            other_tpm = os.path.join(tmp, 'other-tpm')
            os.makedirs(other_tpm)
            report_other = check_consistency(pib_path, other_tpm)
            # The healthy key's private key now looks missing because only the
            # explicitly named (empty) TPM directory was inspected.
            assert MISSING_PRIVATE_KEY in codes(report_other)
            assert report_other.findings_of(ORPHAN_PRIVATE_KEY) == []

            for missing in (os.path.join(tmp, 'no-such-pib.db'),
                            os.path.join(tmp, 'no-such-tpm')):
                try:
                    if missing.endswith('.db'):
                        check_consistency(missing, tpm_dir)
                    else:
                        check_consistency(pib_path, missing)
                except KeychainRecoveryError:
                    pass
                else:  # pragma: no cover
                    raise AssertionError('missing path was not rejected')

    def test_stale_report_action_is_revalidated_and_noop(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/stale')
            key_name = kc.default_identity().default_key().name
            os.remove(tpm_file_for(tpm_dir, key_name))
            kc.shutdown()

            report = check_consistency(pib_path, tpm_dir)
            # Repair the missing key out-of-band before applying the report.
            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            kc2.del_identity('/test/stale')
            kc2.shutdown()

            results = apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            assert all(r['applied'] is False for r in results)

    def test_stale_orphan_repair_skips_file_now_referenced_by_a_key(self):
        with TemporaryDirectory() as tmp:
            kc, tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.new_identity('/test/reuse')
            # Generate a key pair with a fixed key id but never commit its PIB
            # row, producing an orphan whose file name is fully deterministic.
            orphan_name, _orphan_pub = tpm.generate_key(
                Name.from_str('/test/reuse'), key_id='reused-id')
            orphan_file = TpmFile._to_file_name(Name.to_bytes(orphan_name))
            assert os.path.isfile(os.path.join(tpm_dir, orphan_file))

            report = check_consistency(pib_path, tpm_dir)
            assert report.findings_of(ORPHAN_PRIVATE_KEY)[0].evidence['tpm_file'] == orphan_file

            # A new process legitimately creates a key with the same Name, so
            # the previously orphaned file name is now referenced by the PIB.
            kc2 = KeychainSqlite3(pib_path, TpmFile(tpm_dir))
            reused = kc2.new_key('/test/reuse', key_id='reused-id')
            kc2.shutdown()
            assert TpmFile._to_file_name(Name.to_bytes(reused.name)) == orphan_file

            results = apply_repairs(pib_path, tpm_dir, report, apply_all=True)
            assert results[0]['applied'] is False
            # The live private key must survive the stale report.
            assert os.path.isfile(os.path.join(tpm_dir, orphan_file))
            assert check_consistency(pib_path, tpm_dir).findings_of(
                ORPHAN_PRIVATE_KEY) == []

    def test_unknown_action_id_is_rejected(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/unknown')
            kc.shutdown()
            report = check_consistency(pib_path, tpm_dir)
            try:
                apply_repairs(pib_path, tpm_dir, report,
                              action_ids={'do-something-unlisted'})
            except KeychainRecoveryError:
                pass
            else:  # pragma: no cover
                raise AssertionError('unknown action id was accepted')

    def test_report_never_contains_private_key_material(self):
        with TemporaryDirectory() as tmp:
            kc, _tpm, pib_path, tpm_dir = open_keychain(tmp)
            kc.touch_identity('/test/secret')
            key_name = kc.default_identity().default_key().name
            # Produce every kind of evidence in one report.
            with open(tpm_file_for(tpm_dir, key_name), 'wb') as f:
                f.write(b'garbage-not-a-key')
            kc.shutdown()
            report = check_consistency(pib_path, tpm_dir)
            assert not report.healthy
            assert_no_private_material(report, tmp)
