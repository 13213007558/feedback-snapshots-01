#!/usr/bin/env python

# Copyright 2026 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
build-fixtures.py: generate offline Sigstore trust material and DSSE bundles.

Everything here is synthesized locally: a CA, a CT log, a transparency log,
and the bundles that reference them. The result is a self-contained trust
configuration plus bundles that verify with `Verifier(trusted_root=...)`
without any network access.

The fixtures are committed; re-generate them (with new key material) using:

    python test/assets/offline-attestation/build-fixtures.py

...while running from the repository root. The generated material is only
intended for tests: the CA keys are written to disk in the clear.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import rekor_types
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.certificate_transparency import (
    LogEntryType,
    SignatureAlgorithm,
    Version,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from sigstore_models.bundle import v1 as bundle_v1
from sigstore_models.common import v1 as common_v1
from sigstore_models.rekor import v1 as rekor_v1
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.merkle import _hash_leaf
from sigstore._internal.sct import _pack_digitally_signed
from sigstore._utils import key_id, sha256_digest
from sigstore.dsse import Statement, StatementBuilder, Subject, _sign

HERE = Path(__file__).resolve().parent

# A fixed timestamp keeps the generated fixtures stable across runs.
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
ARTIFACT_NAME = "release.tar.gz"
ARTIFACT = b"offline attestation fixture artifact\n"
ARTIFACT_DIGEST = hashlib.sha256(ARTIFACT).hexdigest()
OTHER_DIGEST = hashlib.sha256(b"some other artifact\n").hexdigest()

SCT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

PREDICATE_V1 = "https://slsa.dev/provenance/v1"
PREDICATE_V02 = "https://slsa.dev/provenance/v0.2"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _der(tag: int, body: bytes) -> bytes:
    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        encoded = []
        while n:
            encoded.append(n & 0xFF)
            n >>= 8
        return bytes([0x80 | len(encoded)]) + bytes(reversed(encoded))

    return bytes([tag]) + length(len(body)) + body


def _spki(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pki() -> (
    tuple[
        ec.EllipticCurvePrivateKey,
        x509.Certificate,
        ec.EllipticCurvePrivateKey,
        x509.Certificate,
        ec.EllipticCurvePrivateKey,
    ]
):
    """
    Build a root CA and a Fulcio-style leaf certificate carrying an embedded SCT.
    """

    root_key = _ec_key()
    leaf_key = _ec_key()
    ct_key = _ec_key()

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Root")])
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    def leaf_builder() -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(root_name)
            .public_key(leaf_key.public_key())
            .serial_number(2)
            .not_valid_before(NOW - timedelta(minutes=10))
            .not_valid_after(NOW + timedelta(minutes=10))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    root_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name("offline@example.com")]),
                critical=True,
            )
        )

    # Sign a placeholder precertificate first: the SCT covers the TBS
    # certificate with the SCT list extension present but empty.
    placeholder = x509.UnrecognizedExtension(SCT_OID, b"\x04\x00")
    precert = (
        leaf_builder()
        .add_extension(placeholder, critical=False)
        .sign(root_key, hashes.SHA256())
    )

    # The library's own SCT packing helper computes the exact signed bytes.
    # `_pack_digitally_signed` only reads these attributes off the SCT, and
    # cryptography does not expose a public constructor.
    sct_fields = SimpleNamespace(
        version=Version.v1,
        log_id=key_id(ct_key.public_key()),
        timestamp=NOW,
        entry_type=LogEntryType.PRE_CERTIFICATE,
        signature=b"",
        extensions=b"",
        extension_bytes=b"",
        signature_hash_algorithm=hashes.SHA256(),
        signature_algorithm=SignatureAlgorithm.ECDSA,
    )
    signed = _pack_digitally_signed(
        sct_fields,
        precert,
        key_id(root.public_key()),  # type: ignore[arg-type]
    )
    signature = ct_key.sign(signed, ec.ECDSA(hashes.SHA256()))

    sct = (
        bytes([Version.v1.value])
        + bytes(key_id(ct_key.public_key()))
        + struct.pack("!Q", int(NOW.timestamp() * 1000))
        + b"\x00\x00"  # empty extensions
        + bytes([4, SignatureAlgorithm.ECDSA.value])  # sha256, ecdsa
        + struct.pack("!H", len(signature))
        + signature
    )
    sct_list = struct.pack("!H", len(sct)) + sct
    ext_value = _der(0x04, struct.pack("!H", len(sct_list)) + sct_list)
    leaf = (
        leaf_builder()
        .add_extension(x509.UnrecognizedExtension(SCT_OID, ext_value), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    (HERE / "root.pem").write_bytes(root.public_bytes(Encoding.PEM))
    (HERE / "leaf.pem").write_bytes(leaf.public_bytes(Encoding.PEM))

    return root_key, root, leaf_key, leaf, ct_key


def _statement(predicate_type: str, subjects: list[Subject]) -> Statement:
    predicate = json.loads(
        (
            HERE.parent / "integration" / "attest" / "slsa_predicate_v1_0.json"
        ).read_text()
    )
    if predicate_type == PREDICATE_V02:
        predicate = json.loads(
            (
                HERE.parent / "integration" / "attest" / "slsa_predicate_v0_2.json"
            ).read_text()
        )

    return (
        StatementBuilder()
        .subjects(subjects)
        .predicate_type(predicate_type)
        .predicate(predicate)
        .build()
    )


def _bundle(
    statement: Statement,
    leaf_key: ec.EllipticCurvePrivateKey,
    leaf: x509.Certificate,
    log_key: ec.EllipticCurvePrivateKey,
) -> tuple[bundle_v1.Bundle, dict]:
    envelope = _sign(leaf_key, statement)

    body = rekor_types.Dsse(
        api_version="0.0.1",
        kind="dsse",
        spec=rekor_types.dsse.DsseV001Schema2(
            signatures=[
                rekor_types.dsse.Signature(
                    signature=_b64(envelope.signature),
                    verifier=_b64(leaf.public_bytes(Encoding.PEM)),
                )
            ],
            envelope_hash=rekor_types.dsse.EnvelopeHash1(
                algorithm="sha256",
                value=sha256_digest(envelope.to_json().encode()).digest.hex(),
            ),
            payload_hash=rekor_types.dsse.PayloadHash1(
                algorithm="sha256",
                value=sha256_digest(envelope._inner.payload).digest.hex(),
            ),
        ),
    )
    body_bytes = body.model_dump_json(by_alias=True).encode()
    leaf_hash = _hash_leaf(body_bytes)

    log_id = key_id(log_key.public_key())
    note_header = f"offline.test\n1\n{_b64(leaf_hash)}\n"
    note_signature = log_key.sign(note_header.encode(), ec.ECDSA(hashes.SHA256()))
    note = (
        note_header
        + "\n— offline.test "
        + _b64(struct.pack(">4s", log_id[:4]) + note_signature)
        + "\n"
    )

    integrated_time = int(NOW.timestamp())
    set_payload = {
        "body": _b64(body_bytes),
        "integratedTime": integrated_time,
        "logID": log_id.hex(),
        "logIndex": 0,
    }
    set_signature = log_key.sign(rfc8785.dumps(set_payload), ec.ECDSA(hashes.SHA256()))

    entry = rekor_v1.TransparencyLogEntry(
        log_index="0",
        log_id=rekor_v1.LogId(key_id=_b64(log_id)),
        kind_version=rekor_v1.KindVersion(kind="dsse", version="0.0.1"),
        integrated_time=str(integrated_time),
        inclusion_promise=rekor_v1.InclusionPromise(
            signed_entry_timestamp=_b64(set_signature)
        ),
        inclusion_proof=rekor_v1.InclusionProof(
            log_index="0",
            root_hash=_b64(leaf_hash),
            tree_size="1",
            hashes=[],
            checkpoint=rekor_v1.Checkpoint(envelope=note),
        ),
        canonicalized_body=_b64(body_bytes),
    )

    inner = bundle_v1.Bundle(
        media_type="application/vnd.dev.sigstore.bundle+json;version=0.1",
        verification_material=bundle_v1.VerificationMaterial(
            x509_certificate_chain=bundle_v1.X509CertificateChain(
                certificates=[
                    common_v1.X509Certificate(
                        raw_bytes=_b64(leaf.public_bytes(Encoding.DER))
                    )
                ]
            ),
            tlog_entries=[entry],
        ),
        dsse_envelope=envelope._inner,
    )

    log_info = {
        "base_url": "https://offline.test",
        "public_key": _spki(log_key.public_key()),
        "log_id": log_id,
    }
    return inner, log_info


def _trusted_root(
    root: x509.Certificate,
    ct_key: ec.EllipticCurvePrivateKey,
    log_info: dict,
) -> trustroot_v1.TrustedRoot:
    def log_instance(
        base_url: str, key: bytes, kid: bytes
    ) -> trustroot_v1.TransparencyLogInstance:
        return trustroot_v1.TransparencyLogInstance(
            base_url=base_url,
            hash_algorithm=common_v1.HashAlgorithm.SHA2_256,
            public_key=common_v1.PublicKey(
                raw_bytes=_b64(key),
                key_details=common_v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                valid_for=common_v1.TimeRange(start=NOW - timedelta(days=1)),
            ),
            log_id=common_v1.LogId(key_id=_b64(kid)),
        )

    return trustroot_v1.TrustedRoot(
        media_type=TRUSTED_ROOT_MEDIA_TYPE,
        tlogs=[
            log_instance(
                log_info["base_url"], log_info["public_key"], log_info["log_id"]
            )
        ],
        certificate_authorities=[
            trustroot_v1.CertificateAuthority(
                subject=trustroot_v1.DistinguishedName(
                    organization="offline", common_name="offline"
                ),
                uri="https://offline.test",
                cert_chain=trustroot_v1.X509CertificateChain(
                    certificates=[
                        common_v1.X509Certificate(
                            raw_bytes=_b64(root.public_bytes(Encoding.DER))
                        )
                    ]
                ),
                valid_for=common_v1.TimeRange(start=NOW - timedelta(days=1)),
            )
        ],
        ctlogs=[
            log_instance(
                "https://ct.offline.test",
                _spki(ct_key.public_key()),
                key_id(ct_key.public_key()),
            )
        ],
        timestamp_authorities=[],
    )


def main() -> None:
    _, root, leaf_key, leaf, ct_key = _pki()
    log_key = _ec_key()

    matching = _statement(
        PREDICATE_V1, [Subject(name=ARTIFACT_NAME, digest={"sha256": ARTIFACT_DIGEST})]
    )
    matching_bundle, log_info = _bundle(matching, leaf_key, leaf, log_key)
    (HERE / "matching.bundle.json").write_text(matching_bundle.to_json())

    wrong_digest = _statement(
        PREDICATE_V1, [Subject(name=ARTIFACT_NAME, digest={"sha256": OTHER_DIGEST})]
    )
    wrong_digest_bundle, _ = _bundle(wrong_digest, leaf_key, leaf, log_key)
    (HERE / "wrong-digest.bundle.json").write_text(wrong_digest_bundle.to_json())

    unregistered = _statement(
        PREDICATE_V02, [Subject(name=ARTIFACT_NAME, digest={"sha256": ARTIFACT_DIGEST})]
    )
    unregistered_bundle, _ = _bundle(unregistered, leaf_key, leaf, log_key)
    (HERE / "unregistered-predicate.bundle.json").write_text(
        unregistered_bundle.to_json()
    )

    multi = _statement(
        PREDICATE_V1,
        [
            Subject(name="release.tar.gz", digest={"sha256": ARTIFACT_DIGEST}),
            Subject(name="docs.tar.gz", digest={"sha256": OTHER_DIGEST}),
        ],
    )
    multi_bundle, _ = _bundle(multi, leaf_key, leaf, log_key)
    (HERE / "multi-subject.bundle.json").write_text(multi_bundle.to_json())

    duplicate = _statement(
        PREDICATE_V1,
        [
            Subject(name="release.tar.gz", digest={"sha256": ARTIFACT_DIGEST}),
            Subject(name="release.tar.gz", digest={"sha256": ARTIFACT_DIGEST}),
        ],
    )
    duplicate_bundle, _ = _bundle(duplicate, leaf_key, leaf, log_key)
    (HERE / "duplicate-digest.bundle.json").write_text(duplicate_bundle.to_json())

    trusted_root = _trusted_root(root, ct_key, log_info)
    (HERE / "trusted-root.json").write_text(trusted_root.to_json())
    (HERE / "artifact.bin").write_bytes(ARTIFACT)

    manifest = {
        "artifact": "artifact.bin",
        "artifact_sha256": ARTIFACT_DIGEST,
        "other_sha256": OTHER_DIGEST,
        "accepted_predicate_type": PREDICATE_V1,
        "unaccepted_predicate_type": PREDICATE_V02,
        "identity": "offline@example.com",
        "generated_at": NOW.isoformat(),
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
