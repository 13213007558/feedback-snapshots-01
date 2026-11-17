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
"""Regression tests for binding fetched certificates to the request.

A certificate can be correctly signed by the trust anchor and still not be
the certificate the KeyLocator asked for. These tests observe three separate
decisions:

* name binding: is the response the certificate (or key) that was requested?
* certificate structure: does it carry a usable public key with a valid
  ContentType and validity period?
* chain validation: was it signed by the issuer named in its own KeyLocator?

A response is admitted to the public-key cache only after all three pass.
"""
import asyncio as aio
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from Cryptodome.PublicKey import ECC

from ndn import app as ndn_app, encoding as enc, types, utils
from ndn.app_support.security_v2 import (
    CertificateV2SignatureInfo,
    CertificateV2Value,
    ValidityPeriod,
    _CertificateEnvelope,
    derive_cert,
    parse_certificate,
)
from ndn.encoding.ndn_format_0_3 import (
    ContentType,
    MetaInfo,
    write_signature_info,
)
from ndn.encoding.tlv_model import tlv_encode
from ndn.security import (
    CascadeChecker,
    KeychainSqlite3,
    MemoryKeyStorage,
    Sha256WithEcdsaSigner,
    TpmFile,
)
from ndn.transport.dummy_face import DummyFace


def build_certificate(
    cert_name,
    key_bits,
    signer,
    content_type=ContentType.KEY,
    content=None,
    validity=None,
):
    """Encode a V2 certificate whose structure the caller controls.

    A certificate produced here can be correctly signed by the trust anchor
    while still being unusable as a response.
    """
    now = datetime.now(UTC).replace(microsecond=0)
    not_before, not_after = validity or (
        now - timedelta(minutes=1),
        now + timedelta(hours=1),
    )
    signature_info = CertificateV2SignatureInfo(
        validity_period=ValidityPeriod(
            not_before=not_before.strftime('%Y%m%dT%H%M%S').encode(),
            not_after=not_after.strftime('%Y%m%dT%H%M%S').encode(),
        ),
    )
    write_signature_info(signer, signature_info)
    value = CertificateV2Value(
        name=cert_name,
        content=key_bits if content is None else content,
        meta_info=MetaInfo(
            content_type=content_type,
            freshness_period=3600000,
        ),
        signature_info=signature_info,
    )
    return bytes(tlv_encode(
        _CertificateEnvelope(
            value=tlv_encode(value, markers={'##signer': signer})
        )
    ))


class Chain:
    """A real keychain chain plus certificates sharing the same key."""

    def __init__(self, base_dir: str):
        pib_file = os.path.join(base_dir, 'pib.db')
        tpm_dir = os.path.join(base_dir, 'privKeys')
        KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
        self.keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
        self.root = self.keychain.touch_identity('/cascade-test')
        self.root_cert = self.root.default_key().default_cert()
        self.root_signer = self.keychain.get_signer(
            {'cert': self.root_cert.name}
        )

        self.author = self.keychain.touch_identity('/cascade-test/author/alice')
        self.author_key = self.author.default_key()
        now = datetime.now(UTC)

        with patch('ndn.app_support.security_v2.timestamp', return_value=1001):
            self.cert_v1_name, self.cert_v1 = derive_cert(
                self.author_key.name,
                enc.Component.from_str('root'),
                self.author_key.key_bits,
                self.root_signer,
                now,
                3600,
            )
        with patch('ndn.app_support.security_v2.timestamp', return_value=1002):
            self.cert_v2_name, self.cert_v2 = derive_cert(
                self.author_key.name,
                enc.Component.from_str('root'),
                self.author_key.key_bits,
                self.root_signer,
                now,
                3600,
            )
        with patch('ndn.app_support.security_v2.timestamp', return_value=1003):
            self.cert_other_issuer_name, self.cert_other_issuer = derive_cert(
                self.author_key.name,
                enc.Component.from_str('admin'),
                self.author_key.key_bits,
                self.root_signer,
                now,
                3600,
            )

        self.other = self.keychain.touch_identity('/cascade-test/author/bob')
        self.other_key = self.other.default_key()
        with patch('ndn.app_support.security_v2.timestamp', return_value=1004):
            self.other_cert_name, self.other_cert = derive_cert(
                self.other_key.name,
                enc.Component.from_str('root'),
                self.other_key.key_bits,
                self.root_signer,
                now,
                3600,
            )

        self.data_packet = self.make_data_with_locator(self.cert_v1_name)

    def make_data_with_locator(self, locator_name):
        signer = self.keychain.get_signer({
            'cert': self.cert_v1_name,
            'key_locator': locator_name,
        })
        return enc.make_data(
            '/cascade-test/article/alice/post',
            enc.MetaInfo(),
            b'content',
            signer,
        )

    def shutdown(self):
        self.keychain.shutdown()


class ScriptedApp:
    """In-memory network returning prepared packets in order.

    This emulates a malicious forwarder that answers a certificate request
    with whatever packet it likes; it does not enforce the requested name.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    async def express(self, name, validator, **kwargs):
        self.requests.append((enc.Name.normalize(name), dict(kwargs)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        data_name, meta_info, content, sig_ptrs = enc.parse_data(response)
        context = {
            'meta_info': meta_info,
            'sig_ptrs': sig_ptrs,
            'raw_packet': response,
            'deadline': utils.timestamp() + 1000,
        }
        result = await validator(data_name, sig_ptrs, context)
        if result not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
            raise types.ValidationFailure(
                data_name,
                meta_info,
                content,
                sig_ptrs,
                result,
            )
        return data_name, content, context


def digest_component(packet):
    return enc.Component.from_bytes(
        sha256(bytes(packet)).digest(),
        enc.Component.TYPE_IMPLICIT_SHA256,
    )


def validate_once(chain, packet, responses, storage=None):
    name, _, _, sig_ptrs = enc.parse_data(packet)
    app = ScriptedApp(responses)
    storage = storage if storage is not None else MemoryKeyStorage()
    checker = CascadeChecker(app, chain.root_cert.data, storage)
    result = aio.run(checker(
        name,
        sig_ptrs,
        {'deadline': utils.timestamp() + 1000},
    ))
    return result, app, storage


class TestCertificateNameBinding:
    @staticmethod
    def test_full_certificate_name_requires_exact_match():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                assert (
                    CascadeChecker._parse_certificate(
                        chain.cert_v1,
                        chain.cert_v1_name,
                    )[1]
                    == chain.author_key.key_bits
                )
                # Same key, same prefix, different version or issuer.
                for wrong_name in (
                    chain.cert_v2_name,
                    chain.cert_other_issuer_name,
                ):
                    with pytest.raises(
                        ValueError,
                        match='Fetched certificate name does not match'
                        ' KeyLocator',
                    ):
                        CascadeChecker._parse_certificate(
                            chain.cert_v1,
                            wrong_name,
                        )
            finally:
                chain.shutdown()

    @staticmethod
    def test_key_name_accepts_only_certificates_of_that_key():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                assert (
                    CascadeChecker._parse_certificate(
                        chain.cert_v1,
                        chain.author_key.name,
                    )[1]
                    == chain.author_key.key_bits
                )
                for wrong_name in (
                    chain.other_key.name,
                    chain.other_cert_name,
                ):
                    with pytest.raises(
                        ValueError,
                        match='Fetched certificate name does not match'
                        ' KeyLocator',
                    ):
                        CascadeChecker._parse_certificate(
                            chain.cert_v1,
                            wrong_name,
                        )
            finally:
                chain.shutdown()

    @staticmethod
    def test_locator_must_point_at_a_certificate_or_key():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                for locator in (
                    chain.cert_v1_name[:-1],
                    enc.Name.from_str('/cascade-test/article/alice/post'),
                    [],
                ):
                    with pytest.raises(
                        ValueError,
                        match='KeyLocator does not name',
                    ):
                        CascadeChecker._parse_certificate(
                            chain.cert_v1,
                            locator,
                        )
            finally:
                chain.shutdown()

    @staticmethod
    def test_same_key_other_version_is_rejected_then_correct_succeeds():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                storage = MemoryKeyStorage()
                result, app, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [chain.cert_v2],
                    storage,
                )
                assert result is types.ValidResult.FAIL
                assert len(app.requests) == 1
                # A correctly signed certificate of the same key, but of the
                # other version, must not validate the Data nor be cached.
                assert storage.load(chain.cert_v2_name) is None
                assert storage.load(chain.cert_v1_name) is None

                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [chain.cert_v1],
                    storage,
                )
                assert result is types.ValidResult.PASS
                assert (
                    storage.load(chain.cert_v1_name)
                    == chain.author_key.key_bits
                )
            finally:
                chain.shutdown()

    @staticmethod
    def test_implicit_digest_mismatch_is_rejected_before_caching():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                locator = (
                    chain.cert_v1_name
                    + [digest_component(chain.cert_v2)]
                )
                packet = chain.make_data_with_locator(locator)
                result, app, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v1],
                )
                assert result is types.ValidResult.FAIL
                assert len(app.requests) == 1
                assert storage.load(locator) is None
                assert storage.load(chain.cert_v1_name) is None
            finally:
                chain.shutdown()

    @staticmethod
    def test_implicit_digest_match_is_accepted():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                locator = (
                    chain.cert_v1_name
                    + [digest_component(chain.cert_v1)]
                )
                packet = chain.make_data_with_locator(locator)
                result, _, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v1],
                )
                assert result is types.ValidResult.PASS
                assert storage.load(locator) == chain.author_key.key_bits
            finally:
                chain.shutdown()

    @staticmethod
    def test_digest_on_a_key_name_is_rejected_without_fetch():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                locator = (
                    chain.author_key.name
                    + [digest_component(chain.cert_v1)]
                )
                packet = chain.make_data_with_locator(locator)
                result, app, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v1],
                )
                assert result is types.ValidResult.FAIL
                # The request never names a certificate, so nothing is fetched.
                assert not app.requests
                assert storage.load(locator) is None
            finally:
                chain.shutdown()


class TestCertificateStructure:
    @staticmethod
    def test_wrong_content_type_is_rejected_and_not_cached():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                blob = build_certificate(
                    chain.cert_v1_name,
                    chain.author_key.key_bits,
                    chain.root_signer,
                    content_type=ContentType.BLOB,
                )
                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [blob],
                )
                assert result is types.ValidResult.FAIL
                assert storage.load(chain.cert_v1_name) is None

                # The same request succeeds after the correct certificate.
                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [chain.cert_v1],
                )
                assert result is types.ValidResult.PASS
                assert (
                    storage.load(chain.cert_v1_name)
                    == chain.author_key.key_bits
                )
            finally:
                chain.shutdown()

    @staticmethod
    def test_empty_key_content_is_rejected_and_not_cached():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                empty = build_certificate(
                    chain.cert_v1_name,
                    chain.author_key.key_bits,
                    chain.root_signer,
                    content=b'',
                )
                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [empty],
                )
                assert result is types.ValidResult.FAIL
                assert storage.load(chain.cert_v1_name) is None
            finally:
                chain.shutdown()

    @staticmethod
    def test_expired_certificate_is_rejected_and_not_cached():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                expired = build_certificate(
                    chain.cert_v1_name,
                    chain.author_key.key_bits,
                    chain.root_signer,
                    validity=(
                        datetime(2000, 1, 1, tzinfo=UTC),
                        datetime(2001, 1, 1, tzinfo=UTC),
                    ),
                )
                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [expired],
                )
                assert result is types.ValidResult.FAIL
                assert storage.load(chain.cert_v1_name) is None
            finally:
                chain.shutdown()


class TestCertificateChain:
    @staticmethod
    def test_signature_from_wrong_issuer_is_rejected_and_not_cached():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                rogue_key = ECC.generate(curve='P-256')
                # The KeyLocator names the trust anchor, but another key
                # produced the signature.
                rogue_signer = Sha256WithEcdsaSigner(
                    chain.root_cert.name,
                    rogue_key.export_key(format='DER'),
                )
                misissued = build_certificate(
                    chain.cert_v1_name,
                    chain.author_key.key_bits,
                    rogue_signer,
                )
                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [misissued],
                )
                assert result is types.ValidResult.FAIL
                assert storage.load(chain.cert_v1_name) is None

                result, _, storage = validate_once(
                    chain,
                    chain.data_packet,
                    [chain.cert_v1],
                )
                assert result is types.ValidResult.PASS
                assert (
                    storage.load(chain.cert_v1_name)
                    == chain.author_key.key_bits
                )
            finally:
                chain.shutdown()


class TestCacheAdmission:
    @staticmethod
    def test_no_cache_until_requesting_packet_verifies():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                storage = MemoryKeyStorage()
                app = ScriptedApp([chain.cert_v1])
                checker = CascadeChecker(app, chain.root_cert.data, storage)
                name, _, _, sig_ptrs = enc.parse_data(chain.data_packet)
                # The certificate is fully valid, but the Data signature is
                # broken, so validation must fail and the key must stay out of
                # the cache.
                sig_ptrs.signature_value_buf = bytes(
                    len(sig_ptrs.signature_value_buf)
                )
                result = aio.run(checker(
                    name,
                    sig_ptrs,
                    {'deadline': utils.timestamp() + 1000},
                ))
                assert result is types.ValidResult.FAIL
                assert len(app.requests) == 1
                assert storage.load(chain.cert_v1_name) is None
            finally:
                chain.shutdown()
    @staticmethod
    def test_other_version_cache_entry_does_not_satisfy_full_name():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                storage = MemoryKeyStorage()
                storage.save(chain.cert_v1_name, chain.author_key.key_bits)
                packet = chain.make_data_with_locator(chain.cert_v2_name)
                result, app, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v1, chain.cert_v2],
                    storage,
                )
                assert result is types.ValidResult.FAIL
                assert len(app.requests) == 1
                assert storage.load(chain.cert_v2_name) is None

                result, _, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v2],
                    storage,
                )
                assert result is types.ValidResult.PASS
                assert (
                    storage.load(chain.cert_v2_name)
                    == chain.author_key.key_bits
                )
            finally:
                chain.shutdown()

    @staticmethod
    def test_plain_cache_entry_does_not_satisfy_digest_name():
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            try:
                storage = MemoryKeyStorage()
                storage.save(chain.cert_v1_name, chain.author_key.key_bits)
                locator = (
                    chain.cert_v1_name
                    + [digest_component(chain.cert_v2)]
                )
                packet = chain.make_data_with_locator(locator)
                result, app, storage = validate_once(
                    chain,
                    packet,
                    [chain.cert_v1],
                    storage,
                )
                assert result is types.ValidResult.FAIL
                # The cached key cannot prove the digest, so a fetch happens.
                assert len(app.requests) == 1
                assert storage.load(locator) is None
            finally:
                chain.shutdown()


class TestInterleavedMemoryFace:
    @staticmethod
    async def _read_packet(face):
        """Read one TLV packet from the face output buffer."""
        if not face.output_buf:
            face.expected_len = 1
            await aio.wait_for(face.event.wait(), 1.0)
            face.expected_len = 2 ** 32
            face.event.clear()
        buf = bytes(face.output_buf)
        typ, typ_len = enc.parse_tl_num(buf, 0)
        size, size_len = enc.parse_tl_num(buf, typ_len)
        total = typ_len + size_len + size
        face.output_buf = buf[total:]
        return buf[:total]

    @staticmethod
    def test_same_key_certificate_then_requested_certificate():
        """Interleave a wrong and a right certificate on an in-memory Face.

        The Data KeyLocator names the key, so the certificate fetch is a
        prefix Interest and the network may answer with any certificate of
        that key. The first answer is a correctly signed certificate carrying
        the same public key bits, but it expired in 2001. It must not validate
        the Data and must not enter the cache. When the same Data Interest is
        answered again with the current certificate, the same validator must
        succeed.
        """
        with TemporaryDirectory() as base_dir:
            chain = Chain(base_dir)
            storage = MemoryKeyStorage()
            observed = {}
            requests = []
            first_done = aio.Event()
            second_done = aio.Event()

            key_name = chain.author_key.name
            stale_cert = build_certificate(
                chain.cert_v2_name,
                chain.author_key.key_bits,
                chain.root_signer,
                validity=(
                    datetime(2000, 1, 1, tzinfo=UTC),
                    datetime(2001, 1, 1, tzinfo=UTC),
                ),
            )
            assert parse_certificate(stale_cert).name == chain.cert_v2_name
            assert (
                parse_certificate(stale_cert).content
                == chain.author_key.key_bits
            )
            assert enc.Name.is_prefix(key_name, chain.cert_v2_name)
            data_packet = chain.make_data_with_locator(key_name)

            async def record_interest(face):
                interest = await TestInterleavedMemoryFace._read_packet(face)
                name, param, app_param, sig_ptrs = enc.parse_interest(interest)
                requests.append({
                    'name': enc.Name.to_str(name),
                    'can_be_prefix': param.can_be_prefix,
                    'must_be_fresh': param.must_be_fresh,
                    'has_app_param': app_param is not None,
                })
                return name

            async def face_proc(face):
                await record_interest(face)          # Data Interest
                await face.input_packet(data_packet)
                await record_interest(face)          # fetch under the key name
                await face.input_packet(stale_cert)
                await first_done.wait()

                await record_interest(face)          # Data Interest retried
                await face.input_packet(data_packet)
                await record_interest(face)          # fetch under the key name
                await face.input_packet(chain.cert_v1)
                await second_done.wait()

            face = DummyFace(face_proc)
            app = ndn_app.NDNApp(face)
            face.app = app
            checker = CascadeChecker(
                app,
                chain.root_cert.data,
                storage,
            )

            async def attempt():
                try:
                    _, content, _ = await app.express(
                        '/cascade-test/article/alice/post',
                        validator=checker,
                        nonce=None,
                        lifetime=2000,
                    )
                    return types.ValidResult.PASS, content
                except types.ValidationFailure as exc:
                    return exc.result, exc.content

            async def after_start():
                observed['first'] = await attempt()
                observed['after_first'] = storage.load(key_name)
                first_done.set()
                observed['second'] = await attempt()
                observed['after_second'] = storage.load(key_name)
                second_done.set()

            try:
                aio.run(aio.wait_for(app.main_loop(after_start()), 10))
            finally:
                first_done.set()
                second_done.set()
                chain.shutdown()

            assert observed['first'] == (
                types.ValidResult.FAIL,
                b'content',
            )
            # The expired certificate never reached the cache, so the first
            # attempt could not have been satisfied.
            assert observed['after_first'] is None
            assert storage.load(chain.cert_v2_name) is None
            assert observed['second'] == (
                types.ValidResult.PASS,
                b'content',
            )
            assert observed['after_second'] == chain.author_key.key_bits

            assert [item['name'] for item in requests] == [
                '/cascade-test/article/alice/post',
                enc.Name.to_str(key_name),
                '/cascade-test/article/alice/post',
                enc.Name.to_str(key_name),
            ]
            certificate_requests = requests[1::2]
            assert all(
                item['can_be_prefix'] and item['must_be_fresh']
                and not item['has_app_param']
                for item in certificate_requests
            )
