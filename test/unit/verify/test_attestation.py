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
Tests for attestation-aware intake verification (`sigstore.verify.attestation`).

All fixtures under `test/assets/offline-attestation` are synthesized locally:
a CA, a CT log and a transparency log, along with DSSE bundles that reference
them. Verification therefore exercises the real certificate chain, SCT,
transparency log and DSSE checks without any network access.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from sigstore_models.common.v1 import HashAlgorithm

from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import AttestationVerifier, Verifier, policy
from sigstore.verify.attestation import (
    AttestationVerificationError,
    PredicateTypeNotAccepted,
    SubjectDigestMismatch,
    SubjectSelectionError,
)

FIXTURES = Path(__file__).parent.parent.parent / "assets" / "offline-attestation"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
ACCEPTED = MANIFEST["accepted_predicate_type"]
UNACCEPTED = MANIFEST["unaccepted_predicate_type"]


def _hashed(path: Path) -> Hashed:
    return Hashed(
        digest=hashlib.sha256(path.read_bytes()).digest(),
        algorithm=HashAlgorithm.SHA2_256,
    )


@pytest.fixture
def offline_verifier() -> Verifier:
    return Verifier(
        trusted_root=TrustedRoot.from_file(str(FIXTURES / "trusted-root.json"))
    )


@pytest.fixture
def intake(offline_verifier: Verifier) -> AttestationVerifier:
    return AttestationVerifier(offline_verifier, predicate_types=[ACCEPTED])


@pytest.fixture
def artifact() -> Hashed:
    return _hashed(FIXTURES / "artifact.bin")


def _bundle(name: str) -> Bundle:
    return Bundle.from_json((FIXTURES / f"{name}.bundle.json").read_bytes())


def test_only_matching_subject_and_predicate_is_admitted(
    intake: AttestationVerifier, artifact: Hashed
) -> None:
    """
    Two otherwise-normal attestations are offered to the same intake check.

    Only the one whose single subject covers the reported digest *and* whose
    predicate type is registered is admitted.
    """

    accepted = intake.verify(
        artifact=artifact,
        bundle=_bundle("matching"),
        policy=policy.UnsafeNoOp(),
    )
    assert accepted.predicate_type == ACCEPTED
    assert accepted.subject_index == 0
    assert accepted.subject.digest.root["sha256"] == MANIFEST["artifact_sha256"]
    assert accepted.predicate is not None

    # Same statement shape, same signer, but the declared digest is another
    # artifact: the signature verifies, the digest binding does not.
    with pytest.raises(SubjectDigestMismatch) as mismatch:
        intake.verify(
            artifact=artifact,
            bundle=_bundle("wrong-digest"),
            policy=policy.UnsafeNoOp(),
        )
    assert isinstance(mismatch.value, AttestationVerificationError)

    # A statement whose digest matches, but whose predicate type this service
    # has not registered, is also refused.
    with pytest.raises(PredicateTypeNotAccepted):
        intake.verify(
            artifact=artifact,
            bundle=_bundle("unregistered-predicate"),
            policy=policy.UnsafeNoOp(),
        )

    # The same statement is admissible for a service that registered that type.
    other_predicate = AttestationVerifier(
        intake._verifier, predicate_types=[UNACCEPTED]
    )
    other_predicate.verify(
        artifact=artifact,
        bundle=_bundle("unregistered-predicate"),
        policy=policy.UnsafeNoOp(),
    )


def test_verify_dsse_remains_unrestricted(
    offline_verifier: Verifier, artifact: Hashed
) -> None:
    """
    Existing `verify_dsse` users keep the old contract: the raw payload type and
    bytes, with no subject or predicate-type authorization applied.
    """

    for name in ("matching", "wrong-digest", "multi-subject"):
        payload_type, payload = offline_verifier.verify_dsse(
            _bundle(name), policy.UnsafeNoOp()
        )
        assert payload_type == "application/vnd.in-toto+json"
        assert payload.startswith(b"{")

    # `verify_dsse` does not care about digest binding or predicate type.
    offline_verifier.verify_dsse(_bundle("wrong-digest"), policy.UnsafeNoOp())


def test_multi_subject_requires_explicit_selection(
    intake: AttestationVerifier, artifact: Hashed
) -> None:
    bundle = _bundle("multi-subject")

    with pytest.raises(SubjectSelectionError, match="select one explicitly"):
        intake.verify(artifact=artifact, bundle=bundle, policy=policy.UnsafeNoOp())

    by_index = intake.verify(
        artifact=artifact,
        bundle=bundle,
        policy=policy.UnsafeNoOp(),
        subject=0,
    )
    assert by_index.subject_index == 0

    by_name = intake.verify(
        artifact=artifact,
        bundle=bundle,
        policy=policy.UnsafeNoOp(),
        subject="release.tar.gz",
    )
    assert by_name.subject_index == 0

    # Selecting the other subject is allowed, but it does not cover the
    # reported digest, so intake still refuses it.
    with pytest.raises(SubjectDigestMismatch):
        intake.verify(
            artifact=artifact,
            bundle=bundle,
            policy=policy.UnsafeNoOp(),
            subject=1,
        )


def test_duplicate_digest_requires_explicit_selection(
    intake: AttestationVerifier, artifact: Hashed
) -> None:
    bundle = _bundle("duplicate-digest")

    with pytest.raises(SubjectSelectionError):
        intake.verify(artifact=artifact, bundle=bundle, policy=policy.UnsafeNoOp())

    first = intake.verify(
        artifact=artifact,
        bundle=bundle,
        policy=policy.UnsafeNoOp(),
        subject=0,
    )
    assert first.subject_index == 0

    second = intake.verify(
        artifact=artifact,
        bundle=bundle,
        policy=policy.UnsafeNoOp(),
        subject=1,
    )
    assert second.subject_index == 1


@pytest.mark.parametrize("selector", [2, -1, "README", True])
def test_invalid_selectors_are_rejected(
    intake: AttestationVerifier, artifact: Hashed, selector: object
) -> None:
    with pytest.raises(SubjectSelectionError):
        intake.verify(
            artifact=artifact,
            bundle=_bundle("matching"),
            policy=policy.UnsafeNoOp(),
            subject=selector,  # type: ignore[arg-type]
        )


def test_empty_predicate_registration_is_rejected(offline_verifier: Verifier) -> None:
    with pytest.raises(ValueError):
        AttestationVerifier(offline_verifier, predicate_types=[])


def test_non_dsse_bundle_is_rejected(
    offline_verifier: Verifier, artifact: Hashed
) -> None:
    """
    A bundle that carries a plain message signature has no attestation to
    authorize, even though its certificate and log entry verify.
    """

    raw = json.loads((FIXTURES / "matching.bundle.json").read_text())
    raw["messageSignature"] = {"signature": raw["dsseEnvelope"]["payload"]}
    del raw["dsseEnvelope"]
    bundle = Bundle.from_json(json.dumps(raw))

    intake = AttestationVerifier(offline_verifier, predicate_types=[ACCEPTED])
    with pytest.raises(VerificationError, match="without a DSSE envelope"):
        intake.verify(artifact=artifact, bundle=bundle, policy=policy.UnsafeNoOp())


def test_unsupported_digest_algorithm_is_rejected(
    intake: AttestationVerifier,
) -> None:
    sha512 = Hashed(
        digest=hashlib.sha512(b"anything").digest(),
        algorithm=HashAlgorithm.SHA2_512,
    )

    with pytest.raises(VerificationError, match="unexpected digest algorithm"):
        intake.verify(
            artifact=sha512,
            bundle=_bundle("matching"),
            policy=policy.UnsafeNoOp(),
        )


def test_tampered_envelope_is_rejected_before_authorization(
    offline_verifier: Verifier, artifact: Hashed
) -> None:
    """
    Authorization never runs on a payload whose signature did not verify.
    """

    raw = json.loads((FIXTURES / "matching.bundle.json").read_text())
    # Flip one byte of the DSSE payload; the signature no longer matches.
    payload = raw["dsseEnvelope"]["payload"]
    raw["dsseEnvelope"]["payload"] = ("A" if payload[0] != "A" else "B") + payload[1:]
    tampered = Bundle.from_json(json.dumps(raw))

    intake = AttestationVerifier(offline_verifier, predicate_types=[ACCEPTED])
    with pytest.raises(VerificationError, match="DSSE"):
        intake.verify(
            artifact=artifact,
            bundle=tampered,
            policy=policy.UnsafeNoOp(),
        )


def test_malformed_statement_is_a_verification_error(
    offline_verifier: Verifier, artifact: Hashed
) -> None:
    """
    A signed DSSE envelope whose payload is not a valid in-toto statement is
    reported like any other verification failure, not as a parse error.
    """

    raw = json.loads((FIXTURES / "matching.bundle.json").read_text())
    # A valid signature over a payload that is not an in-toto statement:
    # re-encode the payload and leave the signature untouched.
    raw["dsseEnvelope"]["payload"] = base64.b64encode(b'{"not":"a statement"}').decode()
    bundle = Bundle.from_json(json.dumps(raw))

    intake = AttestationVerifier(offline_verifier, predicate_types=[ACCEPTED])
    with pytest.raises(VerificationError):
        intake.verify(artifact=artifact, bundle=bundle, policy=policy.UnsafeNoOp())


def test_result_exposes_selected_subject_only(
    intake: AttestationVerifier, artifact: Hashed
) -> None:
    result = intake.verify(
        artifact=artifact,
        bundle=_bundle("multi-subject"),
        policy=policy.UnsafeNoOp(),
        subject="release.tar.gz",
    )

    assert [s.name for s in result.subjects] == ["release.tar.gz", "docs.tar.gz"]
    assert result.subject.name == "release.tar.gz"
    assert result.subject_digest == artifact
    assert result.statement.predicate_type == ACCEPTED
