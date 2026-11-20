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
Attestation-aware verification for artifact intake.

`Verifier.verify_dsse` answers a narrow question: "is this envelope's
signature valid, and does it match the bundle?"  Services that admit
artifacts need more than that, because a valid signature over an in-toto
statement says nothing about *which* artifact the statement is about or
*what kind* of claim it makes.

This module layers those two authorization decisions on top of the existing
DSSE verification, without changing it:

* the statement must carry a subject whose digest matches the artifact being
  reported, and the caller must say which subject to select when the
  statement carries more than one;
* the statement's predicate type must be one the service has registered.

The cryptographic verification and the authorization decisions are kept
separate on purpose: `AttestationVerifier` only ever reports success after
`Verifier.verify_dsse` has succeeded, and callers that do not need either
authorization step can keep calling `verify_dsse` exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sigstore_models.common.v1 import HashAlgorithm

from sigstore import dsse
from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify.policy import VerificationPolicy
from sigstore.verify.verifier import Verifier

__all__ = [
    "AttestationVerificationError",
    "AttestationVerificationResult",
    "AttestationVerifier",
    "PredicateTypeNotAccepted",
    "SubjectDigestMismatch",
    "SubjectSelectionError",
    "SubjectSelector",
]


class AttestationVerificationError(VerificationError):
    """
    Base class for the authorization failures that are specific to
    attestation-aware verification.

    These are always raised *after* the underlying DSSE signature has been
    verified, so catching one of them never means the signature was bad.
    """


class SubjectDigestMismatch(AttestationVerificationError):
    """
    Raised when the verified statement does not contain a subject covering the
    artifact digest that was reported for intake.
    """


class SubjectSelectionError(AttestationVerificationError):
    """
    Raised when the subject to authorize cannot be determined unambiguously,
    or when an explicit selector does not match exactly one subject.
    """


class PredicateTypeNotAccepted(AttestationVerificationError):
    """
    Raised when the verified statement's predicate type is not one of the
    predicate types registered with the service.
    """


SubjectSelector = str | int
"""
How a caller selects one subject from a verified statement:

* an `int` is a zero-based index into the statement's subject list;
* a `str` selects by subject name, which must be unique within the statement.
"""


@dataclass(frozen=True)
class AttestationVerificationResult:
    """
    The outcome of a successful attestation-aware verification.

    An instance of this type is only ever produced after `Verifier.verify_dsse`
    has succeeded *and* the selected subject's digest and the statement's
    predicate type have both been authorized.
    """

    statement: dsse.Statement
    """
    The verified in-toto statement, parsed from the verified DSSE payload.
    """

    predicate_type: str
    """
    The statement's predicate type; guaranteed to be one of the accepted types.
    """

    subject: dsse.Subject
    """
    The single subject that was selected for this artifact.
    """

    subject_index: int
    """
    The zero-based position of `subject` in the statement's subject list.
    """

    subject_digest: Hashed
    """
    The artifact digest that `subject` was matched against.
    """

    @property
    def subjects(self) -> list[dsse.Subject]:
        """
        All subjects declared by the verified statement.
        """
        return self.statement.subjects

    @property
    def predicate(self) -> dict[str, Any] | None:
        """
        The statement's predicate, as declared by the signer.

        The predicate itself is opaque to `sigstore`: its contents are **not**
        verified. Treat it as untrusted input that has merely been bound to the
        verified subject and predicate type.
        """
        return self.statement._inner.predicate


class AttestationVerifier:
    """
    A reusable intake check for DSSE-enveloped build attestations.

    This wraps a `Verifier` and adds the two authorization decisions that
    artifact intake services need on top of signature verification: digest
    binding to a single selected subject, and predicate-type acceptance.

    Example:
    ```python
    from pathlib import Path

    from sigstore import hashes
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.attestation import AttestationVerifier
    from sigstore.verify.policy import Identity

    intake = AttestationVerifier(
        Verifier.production(),
        predicate_types=["https://slsa.dev/provenance/v1"],
    )

    report = Path("dist/thing-1.0.tar.gz")
    result = intake.verify(
        # `Hashed` is the digest the intake service recorded for this report.
        artifact=hashes.Hashed(
            algorithm=HashAlgorithm.SHA2_256,
            digest=hashlib.sha256(report.read_bytes()).digest(),
        ),
        bundle=Bundle.from_json(
            Path("dist/thing-1.0.tar.gz.sigstore.json").read_bytes()
        ),
        policy=Identity(
            identity="builder@example.com",
            issuer="https://token.actions.githubusercontent.com",
        ),
    )
    print(result.predicate_type, result.subject_index)
    ```
    """

    def __init__(
        self,
        verifier: Verifier,
        *,
        predicate_types: list[str] | tuple[str, ...] | set[str] | frozenset[str],
    ) -> None:
        """
        Create a new `AttestationVerifier`.

        `verifier` performs the cryptographic verification; it is used as-is,
        so callers keep control over the trust root and offline behavior.

        `predicate_types` is the set of predicate types the service has
        registered as acceptable for intake. It must be non-empty: an empty
        registration would silently accept nothing, which is almost certainly
        a configuration mistake rather than an intent.
        """
        if not predicate_types:
            raise ValueError("at least one accepted predicate type is required")

        self._verifier = verifier
        self._predicate_types = frozenset(str(t) for t in predicate_types)

    @property
    def predicate_types(self) -> frozenset[str]:
        """
        The predicate types this verifier accepts.
        """
        return self._predicate_types

    def verify(
        self,
        *,
        artifact: Hashed,
        bundle: Bundle,
        policy: VerificationPolicy,
        subject: SubjectSelector | None = None,
    ) -> AttestationVerificationResult:
        """
        Verify `bundle` and authorize it for the reported `artifact`.

        `artifact` is the digest of the artifact being reported for intake. Only
        pre-hashed inputs are accepted so that the digest checked here is
        exactly the digest the caller recorded, with no re-hashing ambiguity.

        `bundle` is the Sigstore bundle containing the DSSE envelope.

        `policy` is the `VerificationPolicy` (identity/issuer/etc.) to enforce,
        exactly as for `Verifier.verify_dsse`.

        `subject` selects the subject to authorize. It can be a zero-based
        index or a unique subject name. A statement with more than one subject
        **must** be disambiguated: if `subject` is `None` and the statement has
        several subjects, verification fails rather than guessing which one the
        service meant to admit.

        On success, returns an `AttestationVerificationResult`. On failure,
        raises `AttestationVerificationError` (digest/subject/predicate
        authorization) or any `VerificationError` raised by the underlying
        verifier (signature, certificate, transparency log, etc.).
        """

        # Step 1: cryptographic verification. This also returns the parsed
        # statement payload type, so we can reject non-in-toto envelopes
        # before attempting to parse them.
        payload_type, payload = self._verifier.verify_dsse(bundle=bundle, policy=policy)
        if payload_type != dsse.Envelope._TYPE:
            raise VerificationError(
                f"expected an in-toto DSSE payload, got payload type {payload_type!r}"
            )

        try:
            statement = dsse.Statement(payload)
        except Error as exc:
            # Normalize to `VerificationError` so intake callers have a single
            # failure type for "this signed payload is not usable".
            raise VerificationError(f"malformed in-toto statement: {exc}") from exc

        # Step 2: predicate-type authorization. Do this before subject
        # selection so that a statement about the wrong kind of claim is
        # rejected without any hint about which subjects it carries.
        predicate_type = statement.predicate_type
        if predicate_type not in self._predicate_types:
            raise PredicateTypeNotAccepted(
                f"attestation predicate type {predicate_type!r} is not accepted; "
                f"accepted types: {sorted(self._predicate_types)}"
            )

        # Step 3: digest binding, restricted to one selected subject.
        subject_index, selected = self._select_subject(
            statement, artifact, selector=subject
        )

        return AttestationVerificationResult(
            statement=statement,
            predicate_type=predicate_type,
            subject=selected,
            subject_index=subject_index,
            subject_digest=artifact,
        )

    def _select_subject(
        self,
        statement: dsse.Statement,
        digest: Hashed,
        *,
        selector: SubjectSelector | None,
    ) -> tuple[int, dsse.Subject]:
        """
        Resolve the statement's subject list to exactly one authorized subject.
        """

        subjects = statement.subjects

        if selector is None:
            # A statement with several subjects is ambiguous for intake even if
            # only one of them happens to carry the reported digest: the service
            # must state which subject it is admitting.
            if len(subjects) > 1:
                raise SubjectSelectionError(
                    f"in-toto statement has {len(subjects)} subjects; "
                    "select one explicitly by index or name"
                )

            selected = subjects[0]
            self._require_digest(selected, digest, selector=0)
            return 0, selected

        return self._select_explicit_subject(statement, digest, selector)

    def _select_explicit_subject(
        self,
        statement: dsse.Statement,
        digest: Hashed,
        selector: SubjectSelector,
    ) -> tuple[int, dsse.Subject]:
        """
        Resolve an explicitly requested subject and check it against `digest`.
        """

        subjects = statement.subjects

        if isinstance(selector, bool):
            # `bool` is a subclass of `int`; reject it rather than treating
            # `True`/`False` as indices 1/0.
            raise SubjectSelectionError("subject selector must be an index or name")

        if isinstance(selector, int):
            if selector < 0 or selector >= len(subjects):
                raise SubjectSelectionError(
                    f"subject index {selector} is out of range for a statement "
                    f"with {len(subjects)} subject(s)"
                )
            selected = subjects[selector]
            self._require_digest(selected, digest, selector=selector)
            return selector, selected

        if isinstance(selector, str):
            matches = [
                (index, candidate)
                for index, candidate in enumerate(subjects)
                if candidate.name == selector
            ]
            if not matches:
                raise SubjectSelectionError(
                    f"no subject named {selector!r} in in-toto statement"
                )
            if len(matches) > 1:
                raise SubjectSelectionError(
                    f"subject name {selector!r} is ambiguous: "
                    f"{len(matches)} subjects share it; select by index instead"
                )
            index, selected = matches[0]
            self._require_digest(selected, digest, selector=selector)
            return index, selected

        raise SubjectSelectionError("subject selector must be an index or name")

    @staticmethod
    def _require_digest(
        selected: dsse.Subject, digest: Hashed, *, selector: SubjectSelector
    ) -> None:
        """
        Ensure the explicitly selected subject declares the reported digest.
        """

        if digest.algorithm != HashAlgorithm.SHA2_256:
            raise VerificationError(f"unexpected digest algorithm: {digest.algorithm}")

        declared = selected.digest.root.get("sha256")
        if declared != digest.digest.hex():
            raise SubjectDigestMismatch(
                f"selected subject {selector!r} does not cover digest "
                f"{digest.digest.hex()}"
            )

    def __repr__(self) -> str:
        return f"AttestationVerifier(predicate_types={sorted(self._predicate_types)!r})"
