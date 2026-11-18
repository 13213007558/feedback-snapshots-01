#!/usr/bin/env python3
"""Executable security review: DigestSha256 vs HMAC vs public-key signatures.

Builds real NDN packets with the python-ndn signers in this repository, tampers
with name/content bytes at the wire level, and scores the results under three
acceptance policies: a naive "digest means authenticated" checker, a strict
per-algorithm checker, and the Light VerSec name policy in policy.lvs.

Run:
    .venv/bin/python verification/run_review.py
    .venv/bin/python verification/run_review.py --json
"""

from __future__ import annotations

import argparse
import asyncio as aio
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from tempfile import TemporaryDirectory
from typing import Any

from Cryptodome.PublicKey import ECC

from ndn import encoding as enc
from ndn import types, utils
from ndn.app_support.light_versec import Checker, compile_lvs, lvs_validator
from ndn.app_support.security_v2 import derive_cert
from ndn.encoding.ndn_format_0_3 import TypeNumber, _wrap_tlv
from ndn.security import (
    DigestSha256Signer,
    Ed25519Signer,
    HmacSha256Signer,
    KeychainSqlite3,
    TpmFile,
    sha256_digest_checker,
)

HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.dirname(HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(HERE))

from verification.signature_policy import make_strict_validator  # noqa: E402
LVS_TEXT = open(os.path.join(HERE, 'policy.lvs'), encoding='utf-8').read()

ROOT = '/protected'
AUTHOR = '/protected/news/author/alice'
PUBLISHED = '/protected/news/alice/article1'
PUBLIC = '/protected/public/stats/today'
HMAC_KEY = b'review-demo-hmac-key-32-bytes!!'
HMAC_KEY_NAME = '/protected/news/author/alice/KEY/hmac-demo/key'


# ---------------------------------------------------------------------------
# Wire manipulation
# ---------------------------------------------------------------------------

def make_packet(name: str, content: bytes, signer) -> bytes:
    return bytes(enc.make_data(name, enc.MetaInfo(), content, signer=signer))


def _tlv_spans(buf: bytes):
    offset = 0
    while offset < len(buf):
        t = buf[offset]
        if t < 0xfd:
            typ, o = t, offset + 1
        elif t == 0xfd:
            typ, o = int.from_bytes(buf[offset + 1:offset + 3], 'big'), offset + 3
        else:
            typ, o = int.from_bytes(buf[offset + 1:offset + 5], 'big'), offset + 5
        first = buf[o]
        if first < 0xfd:
            length, v = first, o + 1
        elif first == 0xfd:
            length, v = int.from_bytes(buf[o + 1:o + 3], 'big'), o + 3
        else:
            length, v = int.from_bytes(buf[o + 1:o + 5], 'big'), o + 5
        yield typ, offset, v - offset, length
        offset = v + length


def signature_info_span(covered: bytes) -> tuple[int, int]:
    for typ, start, header_len, length in _tlv_spans(covered):
        if typ == TypeNumber.SIGNATURE_INFO:
            return start, start + header_len + length
    raise ValueError('no SignatureInfo in covered region')


def split_packet(packet: bytes) -> tuple[bytes, int, bytes]:
    _, _, _, sig = enc.parse_data(packet)
    covered = b''.join(bytes(blk) for blk in sig.signature_covered_part)
    return covered, packet.index(covered), bytes(sig.signature_value_buf)


def _rewrap(covered: bytes, sig: bytes | None) -> bytes:
    tail = b'' if sig is None else bytes(_wrap_tlv(TypeNumber.SIGNATURE_VALUE, sig))
    return bytes(_wrap_tlv(TypeNumber.DATA, covered + tail))


def tamper_name(packet: bytes, new_name: str) -> bytes:
    name, _, _, _ = enc.parse_data(packet)
    covered, _, sig = split_packet(packet)
    old = enc.Name.to_bytes(name)
    new = enc.Name.to_bytes(enc.Name.from_str(new_name))
    start = covered.index(old)
    return _rewrap(covered[:start] + new + covered[start + len(old):], sig)


def tamper_content(packet: bytes, new_content: bytes) -> bytes:
    _, _, content, _ = enc.parse_data(packet)
    covered, _, sig = split_packet(packet)
    old = bytes(content)
    idx = covered.index(old)
    assert covered[idx - 2:idx] == bytes([TypeNumber.CONTENT, len(old)])
    new_covered = (
        covered[:idx - 2]
        + bytes([TypeNumber.CONTENT, len(new_content)])
        + new_content
        + covered[idx + len(old):]
    )
    return _rewrap(new_covered, sig)


def forge_digest(packet: bytes) -> bytes:
    """Recompute DigestSha256 over the (already tampered) covered region."""
    covered, _, _ = split_packet(packet)
    return _rewrap(covered, sha256(covered).digest())


def relabel_signature_type(packet: bytes, new_type: int) -> bytes:
    covered, _, sig = split_packet(packet)
    current = signature_type_of(packet)
    old = bytes([TypeNumber.SIGNATURE_TYPE, 1, current])
    assert old in covered
    return _rewrap(covered.replace(old, bytes([TypeNumber.SIGNATURE_TYPE, 1, new_type]), 1), sig)


def strip_signature_info(packet: bytes) -> bytes:
    covered, _, _ = split_packet(packet)
    start, _ = signature_info_span(covered)
    return _rewrap(covered[:start], None)


def signature_type_of(packet: bytes):
    info = enc.parse_data(packet)[3].signature_info
    return None if info is None else info.signature_type


def key_locator_of(packet: bytes):
    info = enc.parse_data(packet)[3].signature_info
    if info is None or info.key_locator is None or info.key_locator.name is None:
        return None
    return enc.Name.to_str(info.key_locator.name)


# ---------------------------------------------------------------------------
# Acceptance policies
# ---------------------------------------------------------------------------

async def naive_digest_only(name, sig, ctx=None):
    """Anti-pattern: treat one digest checker as proof of authentication."""
    return await sha256_digest_checker(name, sig, ctx)


class FakeApp:
    def __init__(self, packets: list[bytes]):
        self.packets = {enc.Name.to_bytes(enc.parse_data(p)[0]): bytes(p) for p in packets}
        self.fetches = 0

    async def express(self, name, validator, **kwargs):
        name = enc.Name.normalize(name)
        self.fetches += 1
        lookup, implicit = name, None
        if enc.Component.get_type(name[-1]) == enc.Component.TYPE_IMPLICIT_SHA256:
            lookup = name[:-1]
            implicit = bytes(enc.Component.get_value(name[-1]))
        try:
            packet = self.packets[enc.Name.to_bytes(lookup)]
        except KeyError:
            raise types.InterestTimeout()
        if implicit is not None and sha256(packet).digest() != implicit:
            raise types.InterestTimeout()
        n, mi, c, sp = enc.parse_data(packet)
        ctx = {
            'meta_info': mi,
            'sig_ptrs': sp,
            'raw_packet': packet,
            'deadline': utils.timestamp() + kwargs.get('lifetime', 4000),
        }
        result = await validator(n, sp, ctx)
        if result not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
            raise types.ValidationFailure(n, mi, c, sp, result)
        return n, c, ctx


# ---------------------------------------------------------------------------
# Scenario material
# ---------------------------------------------------------------------------

@dataclass
class Material:
    root_cert: bytes
    alice_cert: bytes
    ed25519_priv: bytes
    ed25519_pub: bytes
    ed25519_name: str
    keychain: KeychainSqlite3


def build_material(tmpdir: str) -> Material:
    pib, tpm = os.path.join(tmpdir, 'pib.db'), os.path.join(tmpdir, 'keys')
    KeychainSqlite3.initialize(pib, 'tpm-file', tpm)
    kc = KeychainSqlite3(pib, TpmFile(tpm))

    root = kc.touch_identity(ROOT)
    root_cert = root.default_key().default_cert()
    root_signer = kc.get_signer({'cert': root_cert.name})

    alice = kc.touch_identity(AUTHOR)
    alice_key = alice.default_key()
    cert_name, cert_data = derive_cert(
        alice_key.name,
        enc.Component.from_str('root'),
        alice_key.key_bits,
        root_signer,
        datetime.now(UTC),
        3600,
    )
    kc.import_cert(alice_key.name, cert_name, cert_data)

    ed = ECC.generate(curve='ed25519')
    return Material(
        root_cert=root_cert.data,
        alice_cert=cert_data,
        ed25519_priv=ed.export_key(format='DER'),
        ed25519_pub=ed.public_key().export_key(format='DER'),
        ed25519_name=AUTHOR + '/KEY/demo',
        keychain=kc,
    )


PROOFS = {
    'DIGEST_SHA256': {
        'type_value': 0,
        'proves': 'Integrity only: the received bytes match the digest carried in the same packet.',
        'signing_key': 'None.',
        'identity': 'None. There is no KeyLocator and no producer identity.',
        'scope': 'Public, cacheable data where corruption detection is the only goal.',
        'limitation': 'Anyone can change name or content and recompute the digest. It detects accidents, not a malicious publisher.',
    },
    'HMAC_WITH_SHA256': {
        'type_value': 4,
        'proves': 'Possession of a shared secret, plus integrity.',
        'signing_key': 'The symmetric HMAC key, known to every verifier.',
        'identity': 'Whoever holds the key; the KeyLocator names a key but cannot prove it.',
        'scope': 'Closed groups that already share the key out of band.',
        'limitation': 'Any verifier can forge packets; no third-party verification and no non-repudiation.',
    },
    'ED25519': {
        'type_value': 5,
        'proves': 'Possession of the private key matching the named public key, plus integrity.',
        'signing_key': 'The private key; verification needs only the public key.',
        'identity': 'The private-key holder, once a certificate chain binds the key to a name.',
        'scope': 'Open publication, delegated authorities, anything needing non-repudiation.',
        'limitation': 'A bare key proves only "this key signed". Without a name policy any key can sign any name.',
    },
}


def evaluate(packet: bytes, mode: str, strict_validator, lvs) -> str:
    name, mi, _, sig = enc.parse_data(packet)
    ctx = {
        'meta_info': mi,
        'raw_packet': packet,
        'deadline': utils.timestamp() + 4000,
    }
    try:
        if mode == 'naive':
            result = aio.run(naive_digest_only(name, sig, ctx))
        elif mode == 'strict':
            result = aio.run(strict_validator(name, sig, ctx))
        else:
            result = aio.run(lvs(name, sig, ctx))
    except types.ValidationFailure as exc:
        result = exc.result
    except (IndexError, ValueError, TypeError):
        # Malformed packets are a rejection, never a pass.
        return 'FAIL'
    return result.name


def run_review(mat: Material) -> dict[str, Any]:
    content = b'quarterly numbers: revenue up 4%'

    digest_pkt = make_packet(PUBLIC, content, DigestSha256Signer(with_signature_time=False))
    hmac_pkt = make_packet(PUBLISHED, content,
                           HmacSha256Signer(HMAC_KEY_NAME, HMAC_KEY, with_signature_time=False))
    ed_pkt = make_packet(PUBLISHED, content,
                         Ed25519Signer(mat.ed25519_name, mat.ed25519_priv, with_signature_time=False))

    alice_identity = mat.keychain[enc.Name.from_str(AUTHOR)]
    alice_key = alice_identity.default_key()
    derived = next(
        cert_name for cert_name in alice_key
        if bytes(cert_name[-2]) == bytes(enc.Component.from_str('root'))
    )
    cert_signer = mat.keychain.get_signer({'cert': derived})
    cert_pkt = make_packet(PUBLISHED, content, cert_signer)

    fake = FakeApp([mat.alice_cert])
    checker = Checker(compile_lvs(LVS_TEXT), {})
    lvs = lvs_validator(checker, fake, mat.root_cert)
    strict_validator = make_strict_validator(
        hmac_key=HMAC_KEY,
        hmac_key_name=HMAC_KEY_NAME,
        ed25519_pub=mat.ed25519_pub,
        ed25519_key_name=mat.ed25519_name,
    )

    packets = [('digest', digest_pkt), ('hmac', hmac_pkt),
               ('ed25519', ed_pkt), ('cert-chain', cert_pkt)]

    cases = [
        ('digest: original', digest_pkt),
        ('digest: name changed', tamper_name(digest_pkt, '/protected/public/stats/tomorrow')),
        ('digest: name changed + re-digest',
         forge_digest(tamper_name(digest_pkt, '/protected/public/stats/tomorrow'))),
        ('digest: content changed', tamper_content(digest_pkt, b'quarterly numbers: revenue up 400%')),
        ('digest: content changed + re-digest',
         forge_digest(tamper_content(digest_pkt, b'quarterly numbers: revenue up 400%'))),
        ('digest: re-digest named as protected',
         forge_digest(tamper_name(digest_pkt, '/protected/news/bob/article1'))),
        ('hmac: original', hmac_pkt),
        ('hmac: name changed', tamper_name(hmac_pkt, '/protected/news/alice/retracted')),
        ('hmac: content changed', tamper_content(hmac_pkt, b'quarterly numbers: revenue up 400%')),
        ('hmac: relabelled as Ed25519', relabel_signature_type(hmac_pkt, enc.SignatureType.ED25519)),
        ('ed25519: original', ed_pkt),
        ('ed25519: name changed to bob', tamper_name(ed_pkt, '/protected/news/bob/article1')),
        ('ed25519: content changed', tamper_content(ed_pkt, b'quarterly numbers: revenue up 400%')),
        ('ed25519: relabelled as digest', relabel_signature_type(ed_pkt, enc.SignatureType.DIGEST_SHA256)),
        ('ed25519: KeyLocator spoofed to bob',
         make_packet(PUBLISHED, content,
                     Ed25519Signer('/protected/news/author/bob/KEY/demo',
                                   mat.ed25519_priv, with_signature_time=False))),
        ('digest: unknown SignatureType 99', relabel_signature_type(digest_pkt, 99)),
        ('unsigned: no SignatureInfo', strip_signature_info(digest_pkt)),
        ('cert-chain: original', cert_pkt),
        ('cert-chain: name changed to bob', tamper_name(cert_pkt, '/protected/news/bob/article1')),
        ('cert-chain: outside policy', tamper_name(cert_pkt, '/other/news/alice/article1')),
    ]

    matrix = []
    for label, packet in cases:
        matrix.append({
            'case': label,
            'naive': evaluate(packet, 'naive', strict_validator, lvs),
            'strict': evaluate(packet, 'strict', strict_validator, lvs),
            'lvs': evaluate(packet, 'lvs', strict_validator, lvs),
        })
    check_invariants(matrix)

    return {
        'packets': [{
            'label': label,
            'signature_type': signature_type_of(pkt),
            'key_locator': key_locator_of(pkt),
            'size': len(pkt),
        } for label, pkt in packets],
        'matrix': matrix,
        'proofs': PROOFS,
        'findings': FINDINGS,
        'basis': BASIS,
        'verdict': VERDICT,
        'policy': LVS_TEXT.strip(),
    }


def check_invariants(matrix: list[dict[str, Any]]) -> None:
    """Fail loudly if any security claim in the report stops holding."""
    by_case = {row['case']: row for row in matrix}

    def expect(case: str, policy: str, verdict: str) -> None:
        got = by_case[case][policy]
        assert got == verdict, f'{policy} on "{case}": expected {verdict}, got {got}'

    # The naive digest-only policy cannot tell a forgery from an original.
    expect('digest: re-digest named as protected', 'naive', 'PASS')
    expect('digest: content changed + re-digest', 'naive', 'PASS')
    expect('unsigned: no SignatureInfo', 'naive', 'PASS')
    expect('digest: unknown SignatureType 99', 'naive', 'PASS')
    # Relabelling must never steer the strict verifier to a weaker check.
    expect('hmac: relabelled as Ed25519', 'strict', 'FAIL')
    expect('ed25519: relabelled as digest', 'strict', 'FAIL')
    expect('digest: unknown SignatureType 99', 'strict', 'FAIL')
    # Integrity-only acceptance is scoped to the public namespace.
    expect('digest: original', 'strict', 'PASS')
    expect('digest: re-digest named as protected', 'strict', 'FAIL')
    # No tampering or impersonation survives the strict or policy verifier.
    for case in (
        'hmac: name changed', 'hmac: content changed',
        'ed25519: name changed to bob', 'ed25519: content changed',
        'ed25519: KeyLocator spoofed to bob', 'unsigned: no SignatureInfo',
        'cert-chain: name changed to bob', 'cert-chain: outside policy',
    ):
        expect(case, 'strict', 'FAIL')
        expect(case, 'lvs', 'FAIL')
    # Only a certificate-chained, policy-authorized packet is published.
    expect('cert-chain: original', 'lvs', 'PASS')
    expect('ed25519: original', 'lvs', 'FAIL')
    expect('hmac: original', 'lvs', 'FAIL')
    expect('digest: original', 'lvs', 'FAIL')


FINDINGS = [
    {
        'id': 'F1', 'severity': 'HIGH',
        'summary': 'DigestSha256 proves integrity, not a publisher.',
        'detail': 'The digest travels inside the packet it protects, so any party can rewrite '
                  'name or content and recompute it. Accepting a digest can never mean '
                  '"this name was published by a trusted identity".',
    },
    {
        'id': 'F2', 'severity': 'HIGH',
        'summary': 'python-ndn sha256_digest_checker returns PASS for every non-digest type.',
        'detail': 'Unsigned packets, unknown SignatureType values and Ed25519 packets all pass. '
                  'Used as a catch-all it silently accepts everything it does not understand. '
                  'A fallback must be ValidResult.SILENCE or an explicit FAIL, never PASS.',
    },
    {
        'id': 'F3', 'severity': 'HIGH',
        'summary': 'SignatureType is attacker-controlled and must not choose the verifier.',
        'detail': 'Relabelling changes which checker runs. Select the algorithm from trusted '
                  'policy (namespace -> allowed key and algorithm), then require the packet '
                  'type to match. Never let the packet select the weakest path.',
    },
    {
        'id': 'F4', 'severity': 'HIGH',
        'summary': 'Name policy must bind the signing key to the exact protected namespace.',
        'detail': 'A valid public-key signature under a trusted chain still needs an author '
                  'binding. In policy.lvs, alice\'s key can sign /protected/news/alice/* but '
                  'not /protected/news/bob/*; without that check any trusted key signs anything.',
    },
    {
        'id': 'F5', 'severity': 'MEDIUM',
        'summary': 'A KeyLocator is a hint, not an identity.',
        'detail': 'It can name any key. Only a certificate chain to a configured trust anchor '
                  'plus a name policy turns the locator into an authenticated identity.',
    },
    {
        'id': 'F6', 'severity': 'MEDIUM',
        'summary': 'HMAC authenticates a key holder, not a third-party-verifiable identity.',
        'detail': 'Every verifier holds the secret and can forge. Suitable for closed groups, '
                  'never for public publication authority; no non-repudiation.',
    },
]

BASIS = [
    'Accept: DigestSha256 only under /protected/public, where integrity is the sole requirement.',
    'Accept: HMAC only when the KeyLocator matches a provisioned key name in a closed group.',
    'Accept: public-key only when the KeyLocator resolves through a certificate chain to the trust anchor.',
    'Accept: only when policy.lvs authorizes that key for the exact namespace and author component.',
    'Reject: missing KeyLocator, missing SignatureType, unknown type, or type/algorithm mismatch.',
    'Reject: a digest or HMAC signature presented for a namespace that requires publication authority.',
]

VERDICT = (
    'Do not unify DigestSha256 with certificate signatures as "authenticated". Digest is an '
    'integrity check, HMAC is a shared-secret membership check, and only a public-key signature '
    'bound by a certificate chain and a name policy establishes a publisher identity.'
)


def emit(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    line = '=' * 88
    print(line)
    print('NDN signature acceptance review: DigestSha256 vs HMAC vs public key')
    print(line)

    print('\n[1] What each signature type proves\n')
    for sig_type, info in report['proofs'].items():
        print(f'  {sig_type}  (SignatureType={info["type_value"]})')
        print(f'    proves       : {info["proves"]}')
        print(f'    signing key  : {info["signing_key"]}')
        print(f'    identity     : {info["identity"]}')
        print(f'    allowed scope: {info["scope"]}')
        print(f'    limitation   : {info["limitation"]}\n')

    print('[2] Packet classes generated for the same content\n')
    print(f'  {"label":<12}{"type":>5}  size  key locator')
    for row in report['packets']:
        print(f'  {row["label"]:<12}{str(row["signature_type"]):>5}  '
              f'{row["size"]:>4}  {row["key_locator"]}')

    print('\n[3] Verification matrix (PASS / FAIL)\n')
    print(f'  {"case":<40}{"naive":<8}{"strict":<9}{"lvs":<7}')
    print('  ' + '-' * 62)
    for row in report['matrix']:
        print(f'  {row["case"]:<40}{row["naive"]:<8}{row["strict"]:<9}{row["lvs"]:<7}')

    print('\n[4] Acceptance basis\n')
    for item in report['basis']:
        print(f'  - {item}')

    print('\n[5] Findings\n')
    for finding in report['findings']:
        print(f'  [{finding["severity"]}] {finding["id"]}: {finding["summary"]}')
        print(f'      {finding["detail"]}')

    print(f'\n  Verdict: {report["verdict"]}\n')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    with TemporaryDirectory() as tmpdir:
        mat = build_material(tmpdir)
        try:
            emit(run_review(mat), args.json)
        finally:
            mat.keychain.shutdown()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
