"""Aggregating probe: runs every detector, keeps conflicting candidates, optionally verifies."""

from __future__ import annotations

from typing import BinaryIO

from .contract import Candidate, EvidenceLevel, ProbeReport
from .detectors import ALL_DETECTORS, PositionDriftError
from .entropy import stream_size
from .verifiers import VerificationResult, verify_bde, verify_luks, verify_veracrypt

# Which L3 verifier can upgrade a recognised / hypothesised format.
_VERIFIERS = {
    "luks": verify_luks,
    "bitlocker": verify_bde,
    "veracrypt": verify_veracrypt,
}
_DETECTOR_FORMAT = {
    "luks_magic": "luks",
    "bde_guid": "bitlocker",
    "veracrypt_entropy_smell": "veracrypt",
}


def _candidate(candidates: dict[str, Candidate], fmt: str) -> Candidate:
    if fmt not in candidates:
        candidates[fmt] = Candidate(format=fmt, max_level=EvidenceLevel.INCONCLUSIVE)
    return candidates[fmt]


def probe(fh: BinaryIO, *, source: str = "stream", credentials: dict[str, str] | None = None) -> ProbeReport:
    """Run all detectors and return the full evidence report.

    :param credentials: optional mapping ``format -> passphrase``. When supplied for a
        candidate format, the matching verifier is run and L3 is added only on success.
    """
    credentials = credentials or {}
    size = stream_size(fh)
    report = ProbeReport(source=source, size=size)
    candidates: dict[str, Candidate] = {}

    for detector in ALL_DETECTORS:
        entry_offset = fh.tell()
        try:
            evidence = detector(fh)
        except PositionDriftError as exc:
            report.position_preserved = False
            report.errors.append({"detector": detector.__name__, "error": str(exc)})
            continue
        except Exception as exc:  # a detector must not kill the whole probe
            report.errors.append({"detector": detector.__name__, "error": f"{type(exc).__name__}: {exc}"})
            if fh.tell() != entry_offset:
                report.position_preserved = False
                fh.seek(entry_offset)
            continue

        if fh.tell() != entry_offset:
            report.position_preserved = False
            fh.seek(entry_offset)

        if evidence is None:
            continue
        fmt = _DETECTOR_FORMAT[evidence.detector]
        candidate = _candidate(candidates, fmt)
        candidate.evidence.append(evidence)
        candidate.max_level = max(candidate.max_level, evidence.level)

    # Optional L3 verification. Verification never lowers or fabricates a candidate.
    for fmt, passphrase in credentials.items():
        verifier = _VERIFIERS.get(fmt)
        if verifier is None:
            report.errors.append({"detector": f"verify_{fmt}", "error": "no verifier for format"})
            continue
        entry_offset = fh.tell()
        result: VerificationResult = verifier(fh, passphrase)
        if fh.tell() != entry_offset:
            report.position_preserved = False
            fh.seek(entry_offset)
        if result.verified and result.evidence is not None:
            candidate = _candidate(candidates, fmt)
            candidate.evidence.append(result.evidence)
            candidate.max_level = EvidenceLevel.KEY_VERIFIED
            candidate.key_verified = True
        elif result.error:
            report.errors.append({"detector": f"verify_{fmt}", "error": result.error})

    report.candidates = sorted(candidates.values(), key=lambda c: (-int(c.max_level), c.format))
    return report
