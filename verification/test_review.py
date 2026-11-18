"""Regression tests for the signature-acceptance review.

Run with:  .venv/bin/python -m pytest verification -q
"""

from __future__ import annotations

import asyncio as aio
import os
import sys
from hashlib import sha256

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ndn import encoding as enc
from ndn import types, utils
from ndn.app_support.light_versec import Checker, compile_lvs, lvs_validator
from ndn.security import DigestSha256Signer, HmacSha256Signer, sha256_digest_checker
from verification import run_review as R
from verification.signature_policy import make_strict_validator

HMAC_KEY = R.HMAC_KEY
HMAC_NAME = R.HMAC_KEY_NAME


@pytest.fixture(scope='module')
def material(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp('ndn-material')
    mat = R.build_material(str(tmpdir))
    yield mat
    mat.keychain.shutdown()


@pytest.fixture(scope='module')
def validators(material):
    fake = R.FakeApp([material.alice_cert])
    checker = Checker(compile_lvs(R.LVS_TEXT), {})
    lvs = lvs_validator(checker, fake, material.root_cert)
    strict = make_strict_validator(
        hmac_key=HMAC_KEY,
        hmac_key_name=HMAC_NAME,
        ed25519_pub=material.ed25519_pub,
        ed25519_key_name=material.ed25519_name,
    )
    return strict, lvs, checker


def verdict(validator, packet):
    name, mi, _, sig = enc.parse_data(packet)
    ctx = {'meta_info': mi, 'raw_packet': packet, 'deadline': utils.timestamp() + 4000}
    try:
        result = aio.run(validator(name, sig, ctx))
    except types.ValidationFailure as exc:
        result = exc.result
    return result


class TestDigestIsIntegrityOnly:
    def test_digest_detects_corruption(self):
        pkt = R.make_packet(R.PUBLIC, b'body', DigestSha256Signer(with_signature_time=False))
        named = R.tamper_name(pkt, '/protected/public/stats/tomorrow')
        assert verdict(R.naive_digest_only, named) is types.ValidResult.FAIL

    def test_attacker_recomputes_digest_after_rename(self):
        pkt = R.make_packet(R.PUBLIC, b'body', DigestSha256Signer(with_signature_time=False))
        attacked = R.forge_digest(R.tamper_name(pkt, '/protected/news/bob/article1'))
        assert verdict(R.naive_digest_only, attacked) is types.ValidResult.PASS
        # No key material was used; the packet is now "valid" under an attacker name.
        assert enc.Name.to_str(enc.parse_data(attacked)[0]) == '/protected/news/bob/article1'

    def test_attacker_recomputes_digest_after_content_change(self):
        pkt = R.make_packet(R.PUBLIC, b'body', DigestSha256Signer(with_signature_time=False))
        attacked = R.forge_digest(R.tamper_content(pkt, b'forged'))
        assert verdict(R.naive_digest_only, attacked) is types.ValidResult.PASS
        assert bytes(enc.parse_data(attacked)[2]) == b'forged'

    def test_redigested_protected_name_fails_strict_and_lvs(self, validators):
        strict, lvs, _ = validators
        pkt = R.make_packet(R.PUBLIC, b'body', DigestSha256Signer(with_signature_time=False))
        attacked = R.forge_digest(R.tamper_name(pkt, '/protected/news/bob/article1'))
        assert verdict(strict, attacked) is types.ValidResult.FAIL
        assert verdict(lvs, attacked) is types.ValidResult.FAIL


class TestDigestCheckerFailsOpen:
    @pytest.mark.parametrize('label', ['ed25519', 'hmac', 'unsigned', 'unknown'])
    def test_non_digest_types_pass_the_digest_checker(self, material, label):
        if label == 'ed25519':
            pkt = R.make_packet(R.PUBLISHED, b'x',
                                R.Ed25519Signer(material.ed25519_name, material.ed25519_priv,
                                                with_signature_time=False))
        elif label == 'hmac':
            pkt = R.make_packet(R.PUBLISHED, b'x',
                                HmacSha256Signer(HMAC_NAME, HMAC_KEY, with_signature_time=False))
        else:
            pkt = R.make_packet(R.PUBLISHED, b'x', DigestSha256Signer(with_signature_time=False))
            pkt = (R.strip_signature_info(pkt) if label == 'unsigned'
                   else R.relabel_signature_type(pkt, 99))
        name, _, _, sig = enc.parse_data(pkt)
        assert aio.run(sha256_digest_checker(name, sig, {})) is types.ValidResult.PASS


class TestTypeConfusion:
    def test_hmac_relabelled_as_ed25519_is_rejected(self, validators):
        strict, lvs, _ = validators
        pkt = R.make_packet(R.PUBLISHED, b'x',
                            HmacSha256Signer(HMAC_NAME, HMAC_KEY, with_signature_time=False))
        spoof = R.relabel_signature_type(pkt, enc.SignatureType.ED25519)
        assert verdict(strict, spoof) is types.ValidResult.FAIL
        assert verdict(lvs, spoof) is types.ValidResult.FAIL

    def test_ed25519_relabelled_as_digest_is_rejected(self, material, validators):
        strict, lvs, _ = validators
        pkt = R.make_packet(R.PUBLISHED, b'x',
                            R.Ed25519Signer(material.ed25519_name, material.ed25519_priv,
                                            with_signature_time=False))
        spoof = R.relabel_signature_type(pkt, enc.SignatureType.DIGEST_SHA256)
        assert verdict(strict, spoof) is types.ValidResult.FAIL
        assert verdict(lvs, spoof) is types.ValidResult.FAIL

    def test_unknown_type_is_rejected(self, validators):
        strict, lvs, _ = validators
        pkt = R.make_packet(R.PUBLIC, b'x', DigestSha256Signer(with_signature_time=False))
        assert verdict(strict, R.relabel_signature_type(pkt, 99)) is types.ValidResult.FAIL
        assert verdict(lvs, R.relabel_signature_type(pkt, 99)) is types.ValidResult.FAIL

    def test_unsigned_is_rejected(self, validators):
        strict, lvs, _ = validators
        pkt = R.make_packet(R.PUBLIC, b'x', DigestSha256Signer(with_signature_time=False))
        unsigned = R.strip_signature_info(pkt)
        assert verdict(strict, unsigned) is types.ValidResult.FAIL
        assert verdict(lvs, unsigned) is types.ValidResult.FAIL


class TestPublicKeyNeedsIdentity:
    def test_keylocator_spoof_does_not_confer_identity(self, material, validators):
        strict, lvs, checker = validators
        pkt = R.make_packet(
            R.PUBLISHED, b'x',
            R.Ed25519Signer('/protected/news/author/bob/KEY/demo',
                            material.ed25519_priv, with_signature_time=False),
        )
        assert verdict(strict, pkt) is types.ValidResult.FAIL
        assert verdict(lvs, pkt) is types.ValidResult.FAIL
        assert not checker.check(
            R.PUBLISHED,
            '/protected/news/author/bob/KEY/demo',
        )

    def test_author_binding_blocks_cross_author_publication(self, material, validators):
        _, _, checker = validators
        alice = material.keychain[enc.Name.from_str(R.AUTHOR)]
        alice_locator = next(
            str_name for str_name in
            (enc.Name.to_str(n) for n in alice.default_key())
            if bytes(enc.Name.from_str(str_name)[-2]) == bytes(enc.Component.from_str('root'))
        )
        assert checker.check('/protected/news/alice/article1', alice_locator)
        assert not checker.check('/protected/news/bob/article1', alice_locator)

    def test_valid_certificate_chain_publishes(self, material, validators):
        _, lvs, _ = validators
        alice = material.keychain[enc.Name.from_str(R.AUTHOR)]
        cert_name = next(
            n for n in alice.default_key()
            if bytes(n[-2]) == bytes(enc.Component.from_str('root'))
        )
        signer = material.keychain.get_signer({'cert': cert_name})
        pkt = R.make_packet(R.PUBLISHED, b'x', signer)
        assert verdict(lvs, pkt) is types.ValidResult.PASS

    def test_valid_chain_cannot_publish_as_another_author(self, material, validators):
        _, lvs, _ = validators
        alice = material.keychain[enc.Name.from_str(R.AUTHOR)]
        cert_name = next(
            n for n in alice.default_key()
            if bytes(n[-2]) == bytes(enc.Component.from_str('root'))
        )
        signer = material.keychain.get_signer({'cert': cert_name})
        pkt = R.make_packet(R.PUBLISHED, b'x', signer)
        spoof = R.tamper_name(pkt, '/protected/news/bob/article1')
        assert verdict(lvs, spoof) is types.ValidResult.FAIL
