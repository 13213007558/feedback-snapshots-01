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
import os
from tempfile import TemporaryDirectory
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.encoding import make_data, MetaInfo, parse_data, Name
from ndn.security import KeychainSqlite3, TpmFile


class TestSignerSelection:
    """Signer resolution/cache contract.

    A namespace policy must never trust the KeyLocator string alone: the packet
    has to be verified against the public key that actually produced the
    signature. These tests pin both sides for every selection mode.
    """
    tpm_dir: str
    pib_file: str
    keychain: KeychainSqlite3
    tpm: TpmFile
    key_a: object
    key_b: object
    pub_a: bytes
    pub_b: bytes
    cert_a: object
    cert_b: object
    shared_kl: str = '/policy/issuer'

    def setup_method(self):
        # pylint: disable=consider-using-with
        self._tmp = TemporaryDirectory()
        base = self._tmp.name
        self.pib_file = os.path.join(base, 'pib.db')
        self.tpm_dir = os.path.join(base, 'ndnsec-key-file')
        KeychainSqlite3.initialize(self.pib_file, 'tpm-file', self.tpm_dir)
        self.tpm = TpmFile(self.tpm_dir)
        self.keychain = KeychainSqlite3(self.pib_file, self.tpm)
        self.key_a = self.keychain.touch_identity('/ns/A').default_key()
        self.key_b = self.keychain.touch_identity('/ns/B').default_key()
        self.pub_a = bytes(self.key_a.key_bits)
        self.pub_b = bytes(self.key_b.key_bits)
        self.cert_a = self.key_a.default_cert()
        self.cert_b = self.key_b.default_cert()

    def teardown_method(self):
        self.keychain.shutdown()
        self._tmp.cleanup()

    @staticmethod
    def _parse(pkt):
        _, _, _, sig_ptrs = parse_data(pkt)
        return sig_ptrs

    def _verify(self, pkt, pub_der):
        sig_ptrs = self._parse(pkt)
        verifier = DSS.new(ECC.import_key(pub_der), 'fips-186-3', 'der')
        h = SHA256.new()
        for part in sig_ptrs.signature_covered_part:
            h.update(part)
        try:
            verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
            return True
        except ValueError:
            return False

    def _key_locator(self, pkt):
        return Name.normalize(self._parse(pkt).signature_info.key_locator.name)

    def _publish(self, sign_args, content=b'x'):
        return make_data('/ns/data', MetaInfo(), content,
                         signer=self.keychain.get_signer(sign_args))

    def test_explicit_cert_and_key_are_stable(self):
        data_cert = self._publish({'cert': self.cert_a.name})
        assert self._key_locator(data_cert) == Name.normalize(self.cert_a.name)
        assert self._verify(data_cert, self.pub_a)

        data_key = self._publish({'key': self.key_b.name})
        assert self._key_locator(data_key) == Name.normalize(self.cert_b.name)
        assert self._verify(data_key, self.pub_b)

        # Switching the default identity must not perturb explicit selections.
        self.keychain.set_default_identity('/ns/B')
        data_cert = self._publish({'cert': self.cert_a.name})
        data_key = self._publish({'key': self.key_b.name})
        assert self._verify(data_cert, self.pub_a)
        assert self._verify(data_key, self.pub_b)
        # Same selection still returns the cached signer instance.
        assert self.keychain.get_signer({'cert': self.cert_a.name}) is self.keychain.get_signer(
            {'cert': self.cert_a.name})

    def test_default_identity_follows_switch_without_locator_override(self):
        self.keychain.set_default_identity('/ns/A')
        data = self._publish({})
        assert self._key_locator(data) == Name.normalize(self.cert_a.name)
        assert self._verify(data, self.pub_a)
        assert not self._verify(data, self.pub_b)

        self.keychain.set_default_identity('/ns/B')
        data = self._publish({})
        assert self._key_locator(data) == Name.normalize(self.cert_b.name)
        assert self._verify(data, self.pub_b)

    def test_shared_key_locator_tracks_actual_default_key(self):
        # Two namespaces publish under one policy-enforced KeyLocator string.
        self.keychain.set_default_identity('/ns/A')
        data_a = self._publish({'key_locator': self.shared_kl})
        assert self._key_locator(data_a) == Name.normalize(self.shared_kl)
        assert self._verify(data_a, self.pub_a)
        assert not self._verify(data_a, self.pub_b)

        self.keychain.set_default_identity('/ns/B')
        data_b = self._publish({'key_locator': self.shared_kl})
        # KeyLocator string is identical ...
        assert self._key_locator(data_b) == Name.normalize(self.shared_kl)
        # ... but the signature must come from B's private key, not a cached A signer.
        assert self._verify(data_b, self.pub_b)
        assert not self._verify(data_b, self.pub_a)

    def test_same_key_locator_different_keys_keep_distinct_signers(self):
        signer_a = self.keychain.get_signer({'cert': self.cert_a.name,
                                             'key_locator': self.shared_kl})
        signer_b = self.keychain.get_signer({'cert': self.cert_b.name,
                                             'key_locator': self.shared_kl})
        assert signer_a is not signer_b
        data_a = make_data('/ns/data', MetaInfo(), b'a', signer=signer_a)
        data_b = make_data('/ns/data', MetaInfo(), b'b', signer=signer_b)
        assert self._verify(data_a, self.pub_a)
        assert self._verify(data_b, self.pub_b)

    def test_interleaved_two_identity_publishing(self):
        self.keychain.set_default_identity('/ns/A')
        packets = []
        for round_idx in range(3):
            self.keychain.set_default_identity('/ns/A' if round_idx % 2 == 0 else '/ns/B')
            packets.append(self._publish({'key_locator': self.shared_kl},
                                         content=f'r{round_idx}'.encode()))
        expected = (self.pub_a, self.pub_b, self.pub_a)
        for pkt, pub in zip(packets, expected):
            assert self._key_locator(pkt) == Name.normalize(self.shared_kl)
            assert self._verify(pkt, pub)

    def test_set_default_key_and_cert_invalidate_cache(self):
        new_key = self.keychain['/ns/A'].new_key('ec')
        self.keychain['/ns/A'].set_default_key(new_key.name)
        data = self._publish({})
        assert self._key_locator(data) == Name.normalize(new_key.default_cert().name)
        assert self._verify(data, bytes(new_key.key_bits))

        new_cert_name = new_key.default_cert().name
        new_key.set_default_cert(new_cert_name)
        assert self.keychain._signer_cache == {}

    def test_deleted_key_clears_cache_and_fails_fresh_lookup(self):
        signer = self.keychain.get_signer({'cert': self.cert_a.name})
        live = make_data('/ns/data', MetaInfo(), b'live', signer=signer)
        assert self._verify(live, self.pub_a)

        self.keychain.del_identity('/ns/A')
        assert self.keychain._signer_cache == {}
        try:
            self.keychain.get_signer({'cert': self.cert_a.name})
            assert False, 'expected KeyError for a deleted identity'
        except KeyError:
            pass

        # A signer object held by the application keeps its in-memory private key
        # and remains usable; applications must rotate held references themselves.
        stale = make_data('/ns/data', MetaInfo(), b'stale', signer=signer)
        assert self._verify(stale, self.pub_a)

    def test_digest_and_unsigned_branches(self):
        digest = self.keychain.get_signer({'digest_sha256': True})
        assert digest is not None
        assert self.keychain.get_signer({'no_signature': True}) is None
