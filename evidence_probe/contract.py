"""Evidence-level contract for full-volume-encryption (FVE) detection.

The upstream evidence-ingestion service must never store a *guess* as a confirmed
investigative fact. To make that enforceable, every detector output is tagged with one
of the :class:`EvidenceLevel` values below. The levels are ordered by the strength of the
underlying evidence; a higher level strictly implies the evidence of all lower levels.

Design goals
------------
* Separate "looks random" from "has a recognisable format header" from "an authorised
  key actually decrypted it". These are fundamentally different claims.
* Keep conflicting candidates instead of collapsing them into a single verdict.
* Make the absence of evidence explicit (``INCONCLUSIVE``) and distinct from a positive
  claim that the data is plaintext/unencrypted.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class EvidenceLevel(enum.IntEnum):
    """Strength of evidence backing a detection candidate.

    The integer ordering is meaningful: ``L3 > L2 > L1 > L0``.
    """

    # No signal at all (e.g. empty input, unreadable header). This does NOT mean
    # "unencrypted"; it means there is insufficient data to make any claim.
    INCONCLUSIVE = 0

    # L1 - "could be encrypted data". Statistical / structural smell only
    # (high entropy, size divisible by sector size). No format-specific bytes.
    # A high-entropy ordinary file (compressed media, random data, an encrypted blob
    # of an unknown type) reaches exactly this level and nothing more.
    POSSIBLE_ENCRYPTED = 1

    # L2 - "a recognisable format header was parsed". A magic/GUID and structural
    # fields that the format parser accepts. This identifies the container format but
    # proves nothing about whether the caller can access its contents.
    HEADER_RECOGNIZED = 2

    # L3 - "authorised key verified". A supplied passphrase/key successfully performed
    # the format's own cryptographic verification (e.g. a decrypted VeraCrypt header
    # exposes the "VERA" magic, a LUKS volume key matches the stored digest, a BDE
    # FVEK is recovered). Only L3 may be recorded as a confirmed/accessible fact.
    KEY_VERIFIED = 3


# Human-facing labels required by the task wording.
LEVEL_LABELS: dict[EvidenceLevel, str] = {
    EvidenceLevel.INCONCLUSIVE: "inconclusive",
    EvidenceLevel.POSSIBLE_ENCRYPTED: "possible-encrypted",
    EvidenceLevel.HEADER_RECOGNIZED: "format-header-recognized",
    EvidenceLevel.KEY_VERIFIED: "key-verified",
}


@dataclass
class Evidence:
    """A single, auditable piece of evidence produced by a detector.

    :param detector: name of the detector that produced it (e.g. ``"luks_magic"``).
    :param level: evidence strength.
    :param detail: machine-readable facts (offsets, magic, entropy, parser version).
    :param supports_claim: the exact claim this evidence supports. A detector must never
        phrase a smell test as confirmation.
    """

    detector: str
    level: EvidenceLevel
    detail: dict[str, Any] = field(default_factory=dict)
    supports_claim: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "level": int(self.level),
            "level_label": LEVEL_LABELS[self.level],
            "supports_claim": self.supports_claim,
            "detail": self.detail,
        }


@dataclass
class Candidate:
    """A format candidate with the strongest evidence found *for that format*.

    Conflicting candidates are expected: a high-entropy LUKS volume is both a LUKS
    candidate (L2/L3 via its magic) and a generic VeraCrypt smell candidate (L1).
    They are reported side by side rather than merged.
    """

    format: str
    max_level: EvidenceLevel
    evidence: list[Evidence] = field(default_factory=list)
    key_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "max_level": int(self.max_level),
            "max_level_label": LEVEL_LABELS[self.max_level],
            "key_verified": self.key_verified,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class ProbeReport:
    """Aggregated result returned to the upstream service.

    :param candidates: all format candidates, strongest first. May contain conflicts.
    :param confirmed: formats that reached L3. This is the ONLY list the upstream
        service is allowed to persist as a confirmed investigative fact.
    :param position_preserved: whether every detector left the stream offset untouched.
    :param errors: non-fatal per-detector errors (truncated/unparseable headers). These
        downgrade a candidate, they are never silently turned into "unencrypted".
    """

    source: str
    size: int
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    position_preserved: bool = True

    @property
    def confirmed(self) -> list[Candidate]:
        return [c for c in self.candidates if c.max_level == EvidenceLevel.KEY_VERIFIED]

    @property
    def strongest_level(self) -> EvidenceLevel:
        if not self.candidates:
            return EvidenceLevel.INCONCLUSIVE
        return max(c.max_level for c in self.candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "size": self.size,
            "strongest_level": int(self.strongest_level),
            "strongest_level_label": LEVEL_LABELS[self.strongest_level],
            "position_preserved": self.position_preserved,
            "confirmed_formats": [c.format for c in self.report_confirmed()],
            "candidates": [c.to_dict() for c in sorted(self.candidates, key=lambda c: -int(c.max_level))],
            "errors": self.errors,
            "upstream_policy": (
                "Only entries in confirmed_formats (L3 key-verified) may be stored as "
                "confirmed facts; L1/L2 remain hypotheses."
            ),
        }

    def report_confirmed(self) -> list[Candidate]:
        return self.confirmed
