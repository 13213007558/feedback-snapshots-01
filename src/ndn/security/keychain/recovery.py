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
Diagnostic and recovery helpers for a :class:`KeychainSqlite3` PIB paired with a
file-backed TPM (:class:`~ndn.security.tpm.tpm_file.TpmFile`).

Key creation and deletion span two stores that cannot be updated atomically:

* the SQLite PIB database holds the identity, key metadata (including the
  public key bits) and certificates;
* the file TPM holds the private key in a ``*.privkey`` file whose name is the
  SHA-256 of the wire-encoded key Name.

A crash, disk error or injected failure between the two stores therefore leaves
one of them ahead of the other.  This module answers two questions for a
backend without guessing:

1. :func:`check_consistency` reports every way in which the two stores disagree
   for the *exact* PIB path and TPM directory the caller names.  It never opens
   any other location, never writes anything and never promotes a key or
   identity to default.
2. :func:`apply_repairs` performs only the explicit, evidence-backed repair
   actions the caller selects from a report.  The association between a private
   key file and a PIB key is always derived from the key Name hash and, where
   material is available, verified against the stored public key; a file is
   never matched to a key merely because it happens to share a name.

No method in this module returns or logs private key material.  Diagnostic
evidence is limited to Names, file names, public key fingerprints, counters
and error classes.
"""
from __future__ import annotations

import os
import sqlite3
from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

from Cryptodome.PublicKey import RSA, ECC

from ...encoding import FormalName, Name
from ..tpm.tpm_file import TpmFile


# Finding codes
ORPHAN_PRIVATE_KEY = 'orphan-private-key'
MISSING_PRIVATE_KEY = 'missing-private-key'
PRIVATE_KEY_MISMATCH = 'private-key-mismatch'
UNREADABLE_PRIVATE_KEY = 'unreadable-private-key'
KEY_WITHOUT_CERTIFICATE = 'key-without-certificate'
DANGLING_KEY_METADATA = 'dangling-key-metadata'
DANGLING_CERTIFICATE_METADATA = 'dangling-certificate-metadata'
BROKEN_DEFAULT_IDENTITY = 'broken-default-identity'

# Repair action ids
REMOVE_TPM_FILE = 'remove-tpm-file'
REMOVE_KEY_METADATA = 'remove-key-metadata'
REMOVE_CERTIFICATE_METADATA = 'remove-certificate-metadata'

# Severities
ERROR = 'error'
WARNING = 'warning'


class KeychainRecoveryError(Exception):
    """Base class for failures while diagnosing or repairing a keychain."""


@dataclass
class RepairAction:
    """
    A single, explicit repair step proposed for a :class:`ConsistencyFinding`.

    :ivar action: one of the ``REMOVE_*`` action id constants.
    :ivar target: what the action acts on (a TPM file or a PIB row set),
        described by name only.
    :ivar reason: why the action is safe and necessary.
    :ivar evidence: non-secret facts justifying the action.
    """
    action: str
    target: str
    reason: str
    evidence: dict[str, Any]

    @property
    def action_id(self) -> str:
        return self.action

    def to_dict(self) -> dict[str, Any]:
        return {'action': self.action, 'target': self.target,
                'reason': self.reason, 'evidence': dict(self.evidence)}


@dataclass
class ConsistencyFinding:
    """
    One inconsistency observed between the PIB and the TPM.

    :ivar finding_id: stable identifier of the finding within a report.
    :ivar code: one of the finding code constants.
    :ivar severity: :data:`ERROR` or :data:`WARNING`.
    :ivar message: human readable explanation, free of private key material.
    :ivar evidence: non-secret supporting facts (Names, fingerprints, counts).
    :ivar repairs: explicit, evidence-backed repair options.  An empty list
        means the situation must be resolved outside of this module.
    """
    finding_id: str
    code: str
    severity: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    repairs: list[RepairAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'finding_id': self.finding_id, 'code': self.code,
                'severity': self.severity, 'message': self.message,
                'evidence': dict(self.evidence),
                'repairs': [r.to_dict() for r in self.repairs]}


@dataclass
class KeyStatus:
    """Read-only view of one PIB key and how it relates to the TPM."""
    key_name: FormalName
    identity_name: FormalName
    is_default_key: bool
    has_default_certificate: bool
    certificate_count: int
    tpm_file: str
    tpm_file_present: bool
    public_key_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {'key_name': Name.to_str(self.key_name),
                'identity_name': Name.to_str(self.identity_name),
                'is_default_key': self.is_default_key,
                'has_default_certificate': self.has_default_certificate,
                'certificate_count': self.certificate_count,
                'tpm_file': self.tpm_file,
                'tpm_file_present': self.tpm_file_present,
                'public_key_fingerprint': self.public_key_fingerprint}


@dataclass
class ConsistencyReport:
    """
    The result of :func:`check_consistency`.

    :ivar pib_path: the PIB database path that was inspected.
    :ivar tpm_path: the TPM directory that was inspected.
    :ivar healthy: ``True`` when there are no findings.
    :ivar default_identity: the default identity Name, or ``None`` if absent.
    :ivar default_identity_usable: whether the default identity has a complete
        identity -> default key -> default certificate chain backed by a
        matching private key.
    :ivar key_status: per-key diagnostic views.
    :ivar findings: all inconsistencies, each with explicit repair options.
    """
    pib_path: str
    tpm_path: str
    healthy: bool
    default_identity: FormalName | None
    default_identity_usable: bool
    key_status: list[KeyStatus]
    findings: list[ConsistencyFinding]

    def findings_of(self, code: str) -> list[ConsistencyFinding]:
        return [f for f in self.findings if f.code == code]

    def repair_actions(self) -> list[RepairAction]:
        return [action for finding in self.findings for action in finding.repairs]

    def to_dict(self) -> dict[str, Any]:
        return {'pib_path': self.pib_path, 'tpm_path': self.tpm_path,
                'healthy': self.healthy,
                'default_identity': (Name.to_str(self.default_identity)
                                     if self.default_identity is not None else None),
                'default_identity_usable': self.default_identity_usable,
                'key_status': [k.to_dict() for k in self.key_status],
                'findings': [f.to_dict() for f in self.findings]}


def _fingerprint(public_key_der: bytes) -> str:
    return sha256(public_key_der).hexdigest()


def _export_public_key(private_key) -> bytes:
    public_key = (private_key.public_key()
                  if hasattr(private_key, 'public_key')
                  else private_key.publickey())
    return bytes(public_key.export_key(format='DER'))


def _public_key_of_private_file(file_path: str) -> bytes:
    """
    Derive the SubjectPublicKeyInfo DER of a TPM private key file.

    :raises KeychainRecoveryError: if the file cannot be parsed as a supported
        private key.  Error messages only carry the exception class name.
    """
    with open(file_path, 'rb') as f:
        key_b64 = f.read()
    try:
        key_der = b64decode(key_b64)
    except (ValueError, BinasciiError) as exc:
        raise KeychainRecoveryError(f'base64 decode failed: {type(exc).__name__}')
    last_error: Exception | None = None
    for key_cls in (RSA, ECC):
        try:
            private_key = key_cls.import_key(key_der)
            return _export_public_key(private_key)
        except Exception as exc:  # noqa: BLE001 - parser-specific error classes vary
            last_error = exc
    raise KeychainRecoveryError(f'unsupported private key format: '
                                f'{type(last_error).__name__}')


def _open_pib_read_only(pib_path: str) -> sqlite3.Connection:
    if not os.path.isfile(pib_path):
        raise KeychainRecoveryError(f'PIB database does not exist: {pib_path}')
    uri = Path(pib_path).resolve().as_uri() + '?mode=ro'
    return sqlite3.connect(uri, uri=True)


def check_consistency(pib_path: str, tpm_path: str) -> ConsistencyReport:
    """
    Inspect the PIB database at *pib_path* against the file TPM directory at
    *tpm_path* and return a :class:`ConsistencyReport`.

    The inspection is strictly read-only and confined to those two paths; no
    default identity, key or certificate is ever changed, and no other PIB or
    TPM location is consulted.  Private key bytes are never exposed in the
    report; only derived public key fingerprints are.

    :raises KeychainRecoveryError: if either path does not exist or the PIB
        cannot be opened.
    """
    if not os.path.isdir(tpm_path):
        raise KeychainRecoveryError(f'TPM directory does not exist: {tpm_path}')

    findings: list[ConsistencyFinding] = []
    key_status: list[KeyStatus] = []
    finding_counter = 0

    def next_id() -> str:
        nonlocal finding_counter
        finding_counter += 1
        return f'F{finding_counter:04d}'

    conn = _open_pib_read_only(pib_path)
    try:
        # Rows whose foreign key chain is broken (foreign_keys pragma is off by
        # default, so this cannot rely on ON DELETE CASCADE having run).
        cursor = conn.execute(
            'SELECT k.id, k.key_name FROM keys k '
            'LEFT JOIN identities i ON k.identity_id = i.id WHERE i.id IS NULL')
        for row_id, key_name_bytes in cursor.fetchall():
            key_name = Name.from_bytes(key_name_bytes)
            key_file = TpmFile._to_file_name(key_name_bytes)
            findings.append(ConsistencyFinding(
                next_id(), DANGLING_KEY_METADATA, ERROR,
                f'Key {Name.to_str(key_name)} has no owning identity in the PIB',
                {'key_name': Name.to_str(key_name), 'key_row_id': row_id},
                [RepairAction(
                    REMOVE_KEY_METADATA, Name.to_str(key_name),
                    'The key row references an identity that no longer exists; '
                    'its key and certificate rows cannot belong to any identity.',
                    {'key_name': Name.to_str(key_name), 'key_row_id': row_id,
                     'tpm_file': key_file})]))
        cursor.close()

        cursor = conn.execute(
            'SELECT c.id, c.certificate_name FROM certificates c '
            'LEFT JOIN keys k ON c.key_id = k.id WHERE k.id IS NULL')
        for row_id, cert_name_bytes in cursor.fetchall():
            cert_name = Name.from_bytes(cert_name_bytes)
            findings.append(ConsistencyFinding(
                next_id(), DANGLING_CERTIFICATE_METADATA, ERROR,
                f'Certificate {Name.to_str(cert_name)} has no owning key in the PIB',
                {'certificate_name': Name.to_str(cert_name),
                 'certificate_row_id': row_id},
                [RepairAction(
                    REMOVE_CERTIFICATE_METADATA, Name.to_str(cert_name),
                    'The certificate row references a key that no longer exists.',
                    {'certificate_name': Name.to_str(cert_name),
                     'certificate_row_id': row_id})]))
        cursor.close()

        cursor = conn.execute(
            'SELECT i.identity, i.is_default, k.key_name, k.key_bits, k.is_default, '
            '       (SELECT count(*) FROM certificates c WHERE c.key_id = k.id), '
            '       (SELECT count(*) FROM certificates c '
            '          WHERE c.key_id = k.id AND c.is_default = 1) '
            'FROM identities i JOIN keys k ON k.identity_id = i.id '
            'ORDER BY i.id, k.id')
        key_rows = cursor.fetchall()
        cursor.close()

        default_identity_bytes = None
        cursor = conn.execute('SELECT identity FROM identities WHERE is_default = 1')
        row = cursor.fetchone()
        if row is not None:
            default_identity_bytes = row[0]
        cursor.close()

        default_key_exists = default_identity_bytes is not None and any(
            row[0] == default_identity_bytes and row[4] != 0 for row in key_rows)
        default_key_name_bytes = next(
            (row[2] for row in key_rows
             if row[0] == default_identity_bytes and row[4] != 0), None)
    finally:
        conn.close()

    # Every *.privkey file the TPM directory actually contains, keyed by the
    # file name that TpmFile derives from the key Name.
    tpm_files = {name: name for name in os.listdir(tpm_path)
                 if name.endswith('.privkey') and
                 os.path.isfile(os.path.join(tpm_path, name))}
    referenced_files: set[str] = set()
    default_chain_complete = default_identity_bytes is not None
    default_key_private_key_ok = False

    for (identity_bytes, identity_is_default, key_name_bytes, key_bits,
         key_is_default, cert_count, default_cert_count) in key_rows:
        key_name = Name.from_bytes(key_name_bytes)
        identity_name = Name.from_bytes(identity_bytes)
        key_file = TpmFile._to_file_name(key_name_bytes)
        referenced_files.add(key_file)
        file_path = os.path.join(tpm_path, key_file)
        file_present = os.path.isfile(file_path)
        pib_fingerprint = _fingerprint(bytes(key_bits))
        is_default_key_of_default_identity = (
            identity_bytes == default_identity_bytes and
            key_name_bytes == default_key_name_bytes)
        status = KeyStatus(Name.normalize(key_name), Name.normalize(identity_name),
                           key_is_default != 0, default_cert_count > 0, cert_count,
                           key_file, file_present, pib_fingerprint)
        key_status.append(status)

        if not file_present:
            findings.append(ConsistencyFinding(
                next_id(), MISSING_PRIVATE_KEY, ERROR,
                f'PIB key {Name.to_str(key_name)} has no private key in the TPM',
                {'key_name': Name.to_str(key_name), 'identity_name': Name.to_str(identity_name),
                 'expected_tpm_file': key_file,
                 'public_key_fingerprint': pib_fingerprint},
                [RepairAction(
                    REMOVE_KEY_METADATA, Name.to_str(key_name),
                    'The private key named by the key Name hash is absent, so the '
                    'metadata can never sign anything; remove the public-only row set.',
                    {'key_name': Name.to_str(key_name), 'expected_tpm_file': key_file,
                     'public_key_fingerprint': pib_fingerprint})]))
        else:
            try:
                tpm_public_key = _public_key_of_private_file(file_path)
            except KeychainRecoveryError as exc:
                findings.append(ConsistencyFinding(
                    next_id(), UNREADABLE_PRIVATE_KEY, ERROR,
                    f'TPM file for key {Name.to_str(key_name)} cannot be parsed',
                    {'key_name': Name.to_str(key_name), 'tpm_file': key_file,
                     'parse_error': str(exc)},
                    [RepairAction(
                        REMOVE_TPM_FILE, key_file,
                        'The file cannot be decoded as a supported private key and '
                        'cannot be used for signing.',
                        {'key_name': Name.to_str(key_name), 'tpm_file': key_file,
                         'parse_error': str(exc)})]))
                if is_default_key_of_default_identity:
                    default_chain_complete = False
            else:
                tpm_fingerprint = _fingerprint(tpm_public_key)
                if tpm_fingerprint != pib_fingerprint:
                    # Association is proven by the key Name hash; the public
                    # key derived from the private material disagrees with the
                    # public bits recorded in the PIB.
                    findings.append(ConsistencyFinding(
                        next_id(), PRIVATE_KEY_MISMATCH, ERROR,
                        f'Private key in {key_file} does not match the public key '
                        f'recorded for {Name.to_str(key_name)}',
                        {'key_name': Name.to_str(key_name), 'tpm_file': key_file,
                         'pib_public_key_fingerprint': pib_fingerprint,
                         'tpm_public_key_fingerprint': tpm_fingerprint},
                        [RepairAction(
                            REMOVE_TPM_FILE, key_file,
                            'The file resolves to this key by Name hash but its '
                            'derived public key differs from the PIB public key.',
                            {'key_name': Name.to_str(key_name), 'tpm_file': key_file,
                             'pib_public_key_fingerprint': pib_fingerprint,
                             'tpm_public_key_fingerprint': tpm_fingerprint}),
                         RepairAction(
                            REMOVE_KEY_METADATA, Name.to_str(key_name),
                            'The PIB metadata describes a different key pair than '
                            'the private material on disk.',
                            {'key_name': Name.to_str(key_name), 'tpm_file': key_file,
                             'pib_public_key_fingerprint': pib_fingerprint,
                             'tpm_public_key_fingerprint': tpm_fingerprint})]))
                    if is_default_key_of_default_identity:
                        default_chain_complete = False
                elif is_default_key_of_default_identity:
                    default_key_private_key_ok = True

        if cert_count == 0:
            # Not destructive: importing a (self-signed) certificate is the
            # intended resolution and requires the caller to supply it.
            findings.append(ConsistencyFinding(
                next_id(), KEY_WITHOUT_CERTIFICATE, WARNING,
                f'Key {Name.to_str(key_name)} has no certificate in the PIB',
                {'key_name': Name.to_str(key_name), 'identity_name': Name.to_str(identity_name),
                 'tpm_file_present': file_present,
                 'public_key_fingerprint': pib_fingerprint}, []))

        if is_default_key_of_default_identity:
            if not file_present or default_cert_count == 0:
                default_chain_complete = False

    # TPM files that no PIB key Name hashes to.  They are never matched to a key
    # by guesswork: the file name itself is the only available evidence.
    for orphan_file in sorted(set(tpm_files) - referenced_files):
        file_path = os.path.join(tpm_path, orphan_file)
        evidence: dict[str, Any] = {'tpm_file': orphan_file,
                                    'referenced_tpm_files': sorted(referenced_files)}
        try:
            orphan_public_key = _public_key_of_private_file(file_path)
        except KeychainRecoveryError as exc:
            evidence['parse_error'] = str(exc)
            reason = ('The file is not referenced by any PIB key Name hash and '
                      'cannot be parsed as a supported private key.')
        else:
            evidence['public_key_fingerprint'] = _fingerprint(orphan_public_key)
            reason = ('No PIB key Name hashes to this file name, so it cannot be '
                      'associated with any identity through the TPM naming rule.')
        findings.append(ConsistencyFinding(
            next_id(), ORPHAN_PRIVATE_KEY, ERROR,
            f'TPM file {orphan_file} is not referenced by any PIB key',
            evidence,
            [RepairAction(REMOVE_TPM_FILE, orphan_file, reason, dict(evidence))]))

    default_identity = (Name.from_bytes(default_identity_bytes)
                        if default_identity_bytes is not None else None)
    if default_identity is None:
        default_chain_complete = False
    elif not default_key_exists or not default_key_private_key_ok:
        default_chain_complete = False

    if default_identity is not None and not default_chain_complete:
        findings.append(ConsistencyFinding(
            next_id(), BROKEN_DEFAULT_IDENTITY, ERROR,
            f'Default identity {Name.to_str(default_identity)} lacks a complete '
            f'identity -> default key -> default certificate -> private key chain',
            {'default_identity': Name.to_str(default_identity)}, []))

    return ConsistencyReport(pib_path, tpm_path, len(findings) == 0,
                             default_identity, default_chain_complete,
                             key_status, findings)


def _remove_tpm_file(tpm_path: str, file_name: str) -> bool:
    # Refuse anything that is not a direct child of the inspected TPM dir.
    if os.path.basename(file_name) != file_name or not file_name.endswith('.privkey'):
        raise KeychainRecoveryError(f'Refusing to remove TPM path outside the '
                                    f'inspected directory: {file_name}')
    file_path = os.path.join(tpm_path, file_name)
    if os.path.isfile(file_path):
        os.remove(file_path)
        return True
    return False


def apply_repairs(pib_path: str, tpm_path: str, report: ConsistencyReport,
                  action_ids: set[str] | None = None,
                  apply_all: bool = False) -> list[dict[str, Any]]:
    """
    Apply the repair actions proposed in *report* against the PIB and TPM.

    Only actions whose :attr:`RepairAction.action_id` appears in *action_ids*
    (or all actions when *apply_all* is true) are considered.  Every action is
    re-validated against the current state of the stores before it runs, so a
    stale report never deletes the wrong object: a TPM file is removed only if
    no current PIB key Name hashes to it (or it is the verified file of a
    diagnosed key), and metadata is removed by key/certificate Name rather than
    by a row id cached in the report.

    The default identity flags are never modified.

    :return: one result dict per considered action, with ``action``, ``target``,
        ``applied`` (``True``/``False``) and ``reason``.
    :raises KeychainRecoveryError: on an unknown action id or unsafe target.
    """
    if not apply_all and not action_ids:
        return []
    selected = set(action_ids) if action_ids else set()
    known = {REMOVE_TPM_FILE, REMOVE_KEY_METADATA, REMOVE_CERTIFICATE_METADATA}
    unknown = selected - known
    if unknown:
        raise KeychainRecoveryError(f'Unknown repair action id(s): {sorted(unknown)}')

    conn = sqlite3.connect(pib_path)
    results: list[dict[str, Any]] = []
    try:
        # Current key Name -> TPM file name, recomputed live so a stale report
        # can never delete a file that a newly created PIB key now references.
        cursor = conn.execute('SELECT key_name FROM keys')
        current_key_files = {TpmFile._to_file_name(key_name_bytes)
                             for (key_name_bytes,) in cursor.fetchall()}
        cursor.close()
        for finding in report.findings:
            for action in finding.repairs:
                if not apply_all and action.action not in selected:
                    continue
                result = {'action': action.action, 'target': action.target,
                          'applied': False, 'reason': action.reason}
                if action.action == REMOVE_TPM_FILE:
                    file_name = action.target
                    if file_name in current_key_files:
                        result['reason'] = ('A current PIB key now references this TPM '
                                            'file; the stale repair is skipped.')
                    else:
                        removed = _remove_tpm_file(tpm_path, file_name)
                        result['applied'] = removed
                        if not removed:
                            result['reason'] = ('TPM file no longer present; '
                                                'nothing to remove.')
                elif action.action == REMOVE_KEY_METADATA:
                    key_name_bytes = Name.to_bytes(action.target)
                    cursor = conn.execute('SELECT id FROM keys WHERE key_name=?',
                                          (key_name_bytes,))
                    row = cursor.fetchone()
                    cursor.close()
                    if row is None:
                        result['reason'] = 'Key metadata no longer present; nothing to remove.'
                    else:
                        conn.execute('DELETE FROM certificates WHERE key_id=?', (row[0],))
                        conn.execute('DELETE FROM keys WHERE id=?', (row[0],))
                        conn.commit()
                        result['applied'] = True
                elif action.action == REMOVE_CERTIFICATE_METADATA:
                    cert_name_bytes = Name.to_bytes(action.target)
                    cursor = conn.execute(
                        'DELETE FROM certificates WHERE certificate_name=?',
                        (cert_name_bytes,))
                    conn.commit()
                    deleted = cursor.rowcount
                    cursor.close()
                    result['applied'] = deleted > 0
                    if not deleted:
                        result['reason'] = ('Certificate metadata no longer present; '
                                            'nothing to remove.')
                results.append(result)
    finally:
        conn.close()
    return results
