# Copyright 2025 The Sigstore Authors
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
Tests for the stable verification evidence summaries.

These tests run fully offline: the verifier is built from the staging trusted
root embedded in the package rather than from the local TUF cache.
"""

import base64
import hashlib
import json
import logging
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._utils import read_embedded
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import VerificationEvidence
from sigstore.verify.evidence import _policy_version
from sigstore.verify.policy import (
    AllOf,
    AnyOf,
    Identity,
    OIDCIssuer,
    UnsafeNoOp,
)
from sigstore.verify.verifier import Verifier

_STAGING_TUF_URL = "https://tuf-repo-cdn.sigstage.dev"


@pytest.fixture
def offline_verifier() -> Verifier:
    raw = read_embedded("trusted_root.json", _STAGING_TUF_URL)
    trusted_root = TrustedRoot(trustroot_v1.TrustedRoot.from_json(raw))
    return Verifier(trusted_root=trusted_root)


@pytest.fixture
def artifact_bundle(asset) -> tuple[bytes, Bundle]:
    contents = asset("bundle.txt").read_bytes()
    bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    return contents, bundle


@pytest.fixture(autouse=True)
def _quiet_unsafe_policy() -> Iterator[None]:
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_verify_artifact_without_evidence_keeps_return_none(
    offline_verifier, artifact_bundle
):
    contents, bundle = artifact_bundle
    assert offline_verifier.verify_artifact(contents, bundle, UnsafeNoOp()) is None


def test_evidence_is_stable_between_initial_and_offline_verification(
    offline_verifier, artifact_bundle
):
    contents, bundle = artifact_bundle

    # Initial verification at intake time.
    first = offline_verifier.verify_artifact(
        contents, bundle, UnsafeNoOp(), include_evidence=True
    )

    # A later offline review uses an independently constructed verifier but
    # the same fixed signing materials.
    raw = read_embedded("trusted_root.json", _STAGING_TUF_URL)
    review_verifier = Verifier(
        trusted_root=TrustedRoot(trustroot_v1.TrustedRoot.from_json(raw))
    )
    review = review_verifier.verify_artifact(
        contents, bundle, UnsafeNoOp(), include_evidence=True
    )

    assert isinstance(first, VerificationEvidence)
    assert isinstance(review, VerificationEvidence)
    assert first == review
    assert first.to_json() == review.to_json()


def test_evidence_contains_only_required_fields(offline_verifier, artifact_bundle):
    contents, bundle = artifact_bundle
    evidence = offline_verifier.verify_artifact(
        contents, bundle, UnsafeNoOp(), include_evidence=True
    )
    assert isinstance(evidence, VerificationEvidence)

    record = evidence.to_dict()
    assert set(record.keys()) == {"identifiers", "trusted_time", "policy_version"}

    identifiers = record["identifiers"]
    assert set(identifiers.keys()) == {
        "certificate_fingerprint_sha256",
        "transparency_log_id",
        "transparency_log_index",
        "artifact_digest_sha256",
    }
    # Fingerprints and digests are 32-byte hex strings, never key material.
    for name in (
        "certificate_fingerprint_sha256",
        "transparency_log_id",
        "artifact_digest_sha256",
    ):
        value = identifiers[name]
        assert isinstance(value, str)
        assert len(value) == 64
        assert int(value, 16) is not None
    assert isinstance(identifiers["transparency_log_index"], int)

    trusted_time = record["trusted_time"]
    assert len(trusted_time) >= 1
    assert set(trusted_time[0].keys()) == {"source", "time"}
    assert trusted_time[0]["source"] in {"timestamp_authority", "transparency_service"}
    # RFC 3339 UTC rendering.
    assert trusted_time[0]["time"].endswith("Z")

    assert record["policy_version"].startswith("sigstore-python-policy-v1:")


def test_evidence_identifiers_match_the_verified_materials(
    offline_verifier, artifact_bundle
):
    contents, bundle = artifact_bundle
    evidence = offline_verifier.verify_artifact(
        contents, bundle, UnsafeNoOp(), include_evidence=True
    )
    assert isinstance(evidence, VerificationEvidence)

    assert (
        evidence.identifiers["artifact_digest_sha256"]
        == hashlib.sha256(contents).hexdigest()
    )
    assert (
        evidence.identifiers["certificate_fingerprint_sha256"]
        == bundle.signing_certificate.fingerprint(hashes.SHA256()).hex()
    )
    assert (
        evidence.identifiers["transparency_log_id"]
        == bundle.log_entry._inner.log_id.key_id.hex()
    )
    assert evidence.identifiers["transparency_log_index"] == int(
        bundle.log_entry._inner.log_index
    )


def test_evidence_does_not_embed_certificate_or_artifact(
    offline_verifier, artifact_bundle
):
    contents, bundle = artifact_bundle
    evidence = offline_verifier.verify_artifact(
        contents, bundle, UnsafeNoOp(), include_evidence=True
    )
    assert isinstance(evidence, VerificationEvidence)

    encoded = evidence.to_json().encode()
    pem = bundle.signing_certificate.public_bytes(Encoding.PEM)
    der = bundle.signing_certificate.public_bytes(Encoding.DER)

    assert b"BEGIN CERTIFICATE" not in encoded
    assert base64.b64encode(pem) not in encoded
    assert base64.b64encode(der) not in encoded
    assert contents not in encoded
    assert base64.b64encode(bundle.signature) not in encoded


def test_failed_verification_produces_no_evidence(offline_verifier, artifact_bundle):
    _contents, bundle = artifact_bundle
    with pytest.raises(VerificationError):
        offline_verifier.verify_artifact(
            b"tampered artifact contents",
            bundle,
            UnsafeNoOp(),
            include_evidence=True,
        )


def test_policy_version_is_stable_and_sensitive_to_configuration():
    policy = Identity(identity="a@tny.town", issuer="https://github.com/login/oauth")
    same = Identity(identity="a@tny.town", issuer="https://github.com/login/oauth")
    assert _policy_version(policy) == _policy_version(same)
    assert _policy_version(policy) != _policy_version(Identity(identity="other"))
    assert _policy_version(policy) != _policy_version(UnsafeNoOp())
    assert _policy_version(OIDCIssuer("a")) != _policy_version(OIDCIssuer("b"))
    assert _policy_version(AllOf([policy])) != _policy_version(AnyOf([policy]))


def test_identity_policy_evidence_round_trip(offline_verifier, artifact_bundle):
    contents, bundle = artifact_bundle
    policy = Identity(identity="a@tny.town", issuer="https://github.com/login/oauth")
    evidence = offline_verifier.verify_artifact(
        contents, bundle, policy, include_evidence=True
    )
    assert isinstance(evidence, VerificationEvidence)
    assert evidence.policy_version == _policy_version(policy)
    # The canonical JSON is parseable and round-trips to the same record.
    assert json.loads(evidence.to_json()) == evidence.to_dict()


def test_dsse_evidence_omits_envelope_contents(offline_verifier, asset):
    bundle = Bundle.from_json(
        asset("a.dsse.staging-rekor-v2.txt.sigstore.json").read_bytes()
    )
    payload_type, payload, evidence = offline_verifier.verify_dsse(
        bundle, UnsafeNoOp(), include_evidence=True
    )
    assert payload_type == "application/vnd.in-toto+json"
    assert isinstance(evidence, VerificationEvidence)
    assert "dsse_pae_digest_sha256" in evidence.identifiers
    assert payload not in evidence.to_json().encode()
    assert b"BEGIN CERTIFICATE" not in evidence.to_json().encode()

    # Default DSSE return shape is unchanged.
    default_type, default_payload = offline_verifier.verify_dsse(bundle, UnsafeNoOp())
    assert (default_type, default_payload) == (payload_type, payload)
