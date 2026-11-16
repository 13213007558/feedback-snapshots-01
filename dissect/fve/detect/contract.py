"""Result contract for encrypted-volume detection.

The contract separates three things that are routinely conflated:

* :attr:`Conclusion.POSSIBLY_ENCRYPTED` - a statistical observation (high entropy, sector aligned
  size).  It never identifies a format.
* :attr:`Conclusion.HEADER_RECOGNIZED` - a specific format header was parsed and, where the format
  offers one, an integrity check over that header succeeded.
* :attr:`Conclusion.KEY_VERIFIED` - an authorized key cryptographically proved that it belongs to
  the volume (key unwrap / keyslot digest / authenticated header).

Three non-claims exist so that "we could not handle it" is never reported as "not encrypted":

* :attr:`Conclusion.UNSUPPORTED_FORMAT` - a format/container was recognized, but this build cannot
  process the variant.
* :attr:`Conclusion.NOT_ENCRYPTED` - positive evidence of a plaintext structure was found, so the
  data is not one of the supported full-volume encryption containers.
* :attr:`Conclusion.INCONCLUSIVE` - not enough bytes or no recognizable signal at all.

Only :attr:`Conclusion.KEY_VERIFIED` may be turned into an investigative fact ("this volume was
opened with the supplied key").  Everything else is a hypothesis with an explicit evidence trail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Format(str, Enum):
    """Formats this package knows how to look for."""

    BITLOCKER = "bitlocker"
    LUKS = "luks"
    VERACRYPT = "veracrypt"


class EvidenceKind(str, Enum):
    """Kinds of evidence, ordered from weakest to strongest."""

    ENTROPY = "entropy"
    TRUNCATED = "truncated"
    PLAINTEXT_STRUCTURE = "plaintext_structure"
    FORMAT_SIGNATURE = "format_signature"
    HEADER_STRUCTURE = "header_structure"
    HEADER_INTEGRITY = "header_integrity"
    KEY_CHECK = "key_check"


class Conclusion(str, Enum):
    """Outcome of a detection attempt.

    The first three are the documented "strength ladder".  The last three are explicit non-claims.
    """

    POSSIBLY_ENCRYPTED = "possibly_encrypted"
    HEADER_RECOGNIZED = "header_recognized"
    KEY_VERIFIED = "key_verified"
    UNSUPPORTED_FORMAT = "unsupported_format"
    NOT_ENCRYPTED = "not_encrypted"
    INCONCLUSIVE = "inconclusive"


class VerificationStatus(str, Enum):
    """Outcome of a key verification attempt."""

    VERIFIED = "verified"
    REJECTED = "rejected"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


#: Conclusions that assert something about a *specific* format.
FORMAT_CLAIMS = frozenset(
    {
        Conclusion.HEADER_RECOGNIZED,
        Conclusion.KEY_VERIFIED,
        Conclusion.UNSUPPORTED_FORMAT,
    }
)

#: Strength ordering, used to aggregate multiple candidates.
_RANK = {
    Conclusion.INCONCLUSIVE: 0,
    Conclusion.NOT_ENCRYPTED: 1,
    Conclusion.POSSIBLY_ENCRYPTED: 2,
    Conclusion.UNSUPPORTED_FORMAT: 3,
    Conclusion.HEADER_RECOGNIZED: 4,
    Conclusion.KEY_VERIFIED: 5,
}


@dataclass(frozen=True)
class Evidence:
    """A single, auditable observation."""

    kind: EvidenceKind
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "detail": self.detail, "data": self.data}


@dataclass
class Candidate:
    """A per-format hypothesis plus the evidence that supports it.

    ``format`` is ``None`` for generic candidates (for example "high entropy, format unknown").
    """

    conclusion: Conclusion
    format: Format | None
    evidence: list[Evidence] = field(default_factory=list)
    supported: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def has_format_claim(self) -> bool:
        return self.format is not None and self.conclusion in FORMAT_CLAIMS

    @property
    def rank(self) -> int:
        return _RANK[self.conclusion]

    def add(self, kind: EvidenceKind, detail: str, **data: Any) -> None:
        self.evidence.append(Evidence(kind, detail, data))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": self.format.value if self.format else None,
            "conclusion": self.conclusion.value,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.supported is not None:
            result["supported"] = self.supported
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class VerificationResult:
    """Result of an authorized-key check for one format."""

    format: Format
    status: VerificationStatus
    method: str | None = None
    detail: str = ""
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return self.status is VerificationStatus.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": self.format.value,
            "status": self.status.value,
            "detail": self.detail,
        }
        if self.method:
            result["method"] = self.method
        if self.error:
            result["error"] = self.error
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class DetectionResult:
    """Top level answer for one byte range of a stream."""

    conclusion: Conclusion
    format: Format | None
    candidates: list[Candidate] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
    plaintext_markers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    probe_errors: dict[str, str] = field(default_factory=dict)
    offset: int = 0
    size: int | None = None
    position_preserved: bool = True

    @property
    def ambiguous(self) -> bool:
        """Whether two or more formats make an equally strong format-level claim."""
        claims = {c.format for c in self.candidates if c.has_format_claim}
        return len(claims) > 1

    @property
    def key_verified(self) -> bool:
        return self.conclusion is Conclusion.KEY_VERIFIED

    @property
    def confirmed_format(self) -> Format | None:
        """The format, only when exactly one format reached header/key strength."""
        if self.ambiguous:
            return None
        return self.format

    def candidate_for(self, fmt: Format) -> Candidate | None:
        for candidate in self.candidates:
            if candidate.format is fmt:
                return candidate
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "conclusion": self.conclusion.value,
            "format": self.format.value if self.format else None,
            "confirmed_format": self.confirmed_format.value if self.confirmed_format else None,
            "ambiguous": self.ambiguous,
            "key_verified": self.key_verified,
            "offset": self.offset,
            "size": self.size,
            "position_preserved": self.position_preserved,
            "plaintext_markers": self.plaintext_markers,
            "candidates": [c.to_dict() for c in self.candidates],
            "verifications": [v.to_dict() for v in self.verifications],
            "warnings": self.warnings,
            "probe_errors": self.probe_errors,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def aggregate(
    candidates: list[Candidate],
    *,
    verifications: list[VerificationResult] | None = None,
    plaintext_markers: list[str] | None = None,
    warnings: list[str] | None = None,
    probe_errors: dict[str, str] | None = None,
    offset: int = 0,
    size: int | None = None,
    position_preserved: bool = True,
) -> DetectionResult:
    """Fold per-format candidates into a single conclusion.

    Rules:

    * A verified key wins, but a second verified format is reported as a conflict rather than
      silently choosing one.
    * Otherwise the strongest format claim wins.  Equal-strength claims from different formats set
      :attr:`DetectionResult.ambiguous` and leave ``format`` unset.
    * Entropy-only candidates never outrank a recognized header, and never identify a format.
    * Plaintext markers produce ``NOT_ENCRYPTED`` only when no format claim exists.
    """
    candidates = list(candidates)
    verifications = verifications or []
    plaintext_markers = plaintext_markers or []
    warnings = list(warnings or [])
    probe_errors = dict(probe_errors or {})

    for verification in verifications:
        if verification.verified:
            candidates.append(
                Candidate(
                    conclusion=Conclusion.KEY_VERIFIED,
                    format=verification.format,
                    evidence=[Evidence(EvidenceKind.KEY_CHECK, verification.detail or "key verified")],
                    supported=True,
                    details={"method": verification.method, **verification.details},
                )
            )

    def result(conclusion: Conclusion, fmt: Format | None) -> DetectionResult:
        return DetectionResult(
            conclusion=conclusion,
            format=fmt,
            candidates=candidates,
            verifications=verifications,
            plaintext_markers=plaintext_markers,
            warnings=warnings,
            probe_errors=probe_errors,
            offset=offset,
            size=size,
            position_preserved=position_preserved,
        )

    format_claims = [c for c in candidates if c.has_format_claim]
    verified = [c for c in format_claims if c.conclusion is Conclusion.KEY_VERIFIED]
    header_claims = [c for c in format_claims if c.conclusion is Conclusion.HEADER_RECOGNIZED]
    unsupported = [c for c in format_claims if c.conclusion is Conclusion.UNSUPPORTED_FORMAT]
    heuristic = [c for c in candidates if c.conclusion is Conclusion.POSSIBLY_ENCRYPTED]

    if len({c.format for c in verified}) > 1:
        warnings.append("multiple formats verified with different keys; refusing to pick one")
        return result(Conclusion.HEADER_RECOGNIZED, None)

    if verified:
        return result(Conclusion.KEY_VERIFIED, verified[0].format)

    if len({c.format for c in header_claims}) > 1:
        warnings.append("conflicting format headers; reporting header_recognized without a format")
        return result(Conclusion.HEADER_RECOGNIZED, None)

    if header_claims:
        return result(Conclusion.HEADER_RECOGNIZED, header_claims[0].format)

    if len({c.format for c in unsupported}) > 1:
        warnings.append("multiple unsupported formats recognized; refusing to pick one")
        return result(Conclusion.UNSUPPORTED_FORMAT, None)

    if unsupported:
        return result(Conclusion.UNSUPPORTED_FORMAT, unsupported[0].format)

    if heuristic:
        warnings.append("entropy alone cannot identify an encryption format; no format was claimed")
        return result(Conclusion.POSSIBLY_ENCRYPTED, None)

    if plaintext_markers:
        return result(Conclusion.NOT_ENCRYPTED, None)

    return result(Conclusion.INCONCLUSIVE, None)
