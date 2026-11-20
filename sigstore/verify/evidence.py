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
Stable evidence summaries produced by successful verifications.

An evidence summary records only the identifiers, sources of trusted time,
and policy version that a verification actually relied on. It never embeds
full certificates, signatures, or artifact contents, so it can be persisted
at intake time and compared again during a later offline review.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import hashes

from sigstore._internal.timestamp import TimestampVerificationResult
from sigstore.models import Bundle
from sigstore.verify.policy import (
    AllOf,
    AnyOf,
    Identity,
    UnsafeNoOp,
    VerificationPolicy,
)

# Prefix of the stable policy version string. Bump the embedded number if the
# policy descriptor layout or the evidence format changes in a breaking way.
_POLICY_VERSION_PREFIX = "sigstore-python-policy-v1"


@dataclass(frozen=True)
class TrustedTimeEvidence:
    """
    One source of trusted time that the verification established.

    `source` is the lower-cased name of a `TimestampSource` and `time` is the
    verified timestamp as a timezone-aware `datetime`.
    """

    source: str
    time: datetime


@dataclass(frozen=True)
class VerificationEvidence:
    """
    A stable, content-minimal summary of one successful verification.

    The summary contains exactly three groups of information:

    * `identifiers`: cryptographic identifiers (fingerprints and digests,
      never full certificates or artifact contents) for the verified
      materials;
    * `trusted_time`: the sources of trusted time the verification used;
    * `policy_version`: a stable version string identifying the exact
      verification policy configuration.

    Instances are only constructed after every verification step succeeds.
    """

    identifiers: dict[str, Any]
    trusted_time: tuple[TrustedTimeEvidence, ...]
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        """
        Return a plain, JSON-serializable representation of this evidence.
        """
        return {
            "identifiers": dict(self.identifiers),
            "trusted_time": [
                {"source": entry.source, "time": _format_time(entry.time)}
                for entry in self.trusted_time
            ],
            "policy_version": self.policy_version,
        }

    def to_json(self) -> str:
        """
        Return a canonical (RFC 8785) JSON encoding of this evidence.

        The encoding is deterministic: identical evidence always serializes
        to identical bytes, which makes two evidence records directly
        comparable as strings.
        """
        encoded: bytes = rfc8785.dumps(self.to_dict())
        return encoded.decode()


def _format_time(time: datetime) -> str:
    """
    Render a datetime as a stable UTC RFC 3339 string.
    """
    return time.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _policy_descriptor(policy: VerificationPolicy) -> dict[str, Any]:
    """
    Build a stable, content-based descriptor for a verification policy.

    Only the policy type and the values that constrain verification are
    recorded. The descriptor is hashed to derive the policy version, so any
    change in policy configuration yields a different policy version.
    """
    if isinstance(policy, UnsafeNoOp):
        return {"type": "UnsafeNoOp"}

    if isinstance(policy, Identity):
        descriptor: dict[str, Any] = {
            "type": "Identity",
            "identity": policy._identity,
        }
        if policy._issuer is not None:
            descriptor["issuer"] = policy._issuer._value
        return descriptor

    if isinstance(policy, AnyOf | AllOf):
        return {
            "type": type(policy).__name__,
            "children": [_policy_descriptor(child) for child in policy._children],
        }

    descriptor = {"type": type(policy).__name__}
    oid = getattr(type(policy), "oid", None)
    if oid is not None:
        descriptor["oid"] = oid.dotted_string
    value = getattr(policy, "_value", None)
    if value is not None:
        descriptor["value"] = value
    return descriptor


def _policy_version(policy: VerificationPolicy) -> str:
    """
    Derive a stable version string for the given verification policy.
    """
    descriptor = rfc8785.dumps(_policy_descriptor(policy))
    digest = hashlib.sha256(descriptor).hexdigest()
    return f"{_POLICY_VERSION_PREFIX}:{digest}"


def build_verification_evidence(
    *,
    bundle: Bundle,
    policy: VerificationPolicy,
    verified_timestamps: Sequence[TimestampVerificationResult],
    digest_identifier: tuple[str, str],
) -> VerificationEvidence:
    """
    Build a `VerificationEvidence` from the outputs of a completed verification.

    `digest_identifier` is a `(name, hex_digest)` pair naming the digest that
    the signature was actually verified against (for example, the artifact
    digest for `Verifier.verify_artifact`).

    Only fingerprints and digests are recorded: the signing certificate's
    DER/PEM bytes, the signature, and the artifact or envelope contents are
    deliberately excluded from the returned evidence.
    """
    log_entry = bundle.log_entry._inner
    digest_name, digest_value = digest_identifier

    identifiers: dict[str, Any] = {
        "certificate_fingerprint_sha256": bundle.signing_certificate.fingerprint(
            hashes.SHA256()
        ).hex(),
        "transparency_log_id": log_entry.log_id.key_id.hex(),
        "transparency_log_index": int(log_entry.log_index),
        digest_name: digest_value,
    }

    trusted_time = tuple(
        TrustedTimeEvidence(
            source=result.source.name.lower(),
            time=result.time,
        )
        for result in verified_timestamps
    )

    return VerificationEvidence(
        identifiers=identifiers,
        trusted_time=trusted_time,
        policy_version=_policy_version(policy),
    )
