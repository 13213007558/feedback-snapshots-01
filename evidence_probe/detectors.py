"""Format detectors.

Each detector is a callable ``(fh) -> Evidence | None`` and MUST restore the stream
offset to what it was on entry, on every code path (including exceptions). Detectors
restore explicitly in a ``finally``; :func:`guarded` is a belt-and-braces invariant that
raises :class:`PositionDriftError` if a detector ever forgets.

Critical distinction encoded here:

* LUKS and BDE are identified by *magic/GUID parsing* -> L2.
* VeraCrypt has no on-disk magic in the encrypted header, so the library's
  ``is_veracrypt_volume`` is only a sector-size + entropy smell test -> L1. It can never
  produce L2 by itself and must never be promoted on entropy alone.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO

from dissect.fve.bde.bde import is_bde_volume
from dissect.fve.luks.luks import is_luks_volume
from dissect.fve.veracrypt.veracrypt import is_veracrypt_volume

from .contract import Evidence, EvidenceLevel
from .entropy import (
    SECTOR_SIZE,
    SMELL_SAMPLE_BYTES,
    VERACRYPT_ENTROPY_THRESHOLD,
    shannon_entropy,
    stream_size,
)

Detector = Callable[[BinaryIO], "Evidence | None"]


class PositionDriftError(RuntimeError):
    """Raised when a detector fails to return the stream to its original offset."""


def guarded(detector: Detector) -> Detector:
    """Assert the offset invariant. Detectors restore themselves; this catches regressions."""

    def wrapper(fh: BinaryIO) -> Evidence | None:
        start = fh.tell()
        try:
            return detector(fh)
        finally:
            if fh.tell() != start:
                fh.seek(start)
                raise PositionDriftError(f"{detector.__name__} left offset at {fh.tell()}, expected {start}")

    wrapper.__name__ = detector.__name__
    return wrapper


@guarded
def detect_luks(fh: BinaryIO) -> Evidence | None:
    start = fh.tell()
    try:
        try:
            recognized = is_luks_volume(fh)
        except EOFError:
            return None
        if not recognized:
            return None
        fh.seek(0)
        magic = fh.read(6)
        version_bytes = fh.read(2)
        version = 1 if magic == b"LUKS\xba\xbe" and version_bytes == b"\x00\x01" else 2
        return Evidence(
            detector="luks_magic",
            level=EvidenceLevel.HEADER_RECOGNIZED,
            detail={"magic": magic.hex(), "offset": 0, "luks_version_hint": version},
            supports_claim="LUKS container header parsed (format identified; not unlocked)",
        )
    finally:
        fh.seek(start)


@guarded
def detect_bde(fh: BinaryIO) -> Evidence | None:
    start = fh.tell()
    try:
        try:
            recognized = is_bde_volume(fh)
        except EOFError:
            # Empty / truncated input cannot hold a 512-byte boot sector: inconclusive,
            # never an "unencrypted" verdict.
            return None
        if not recognized:
            return None
        fh.seek(3)
        oem = fh.read(8)
        return Evidence(
            detector="bde_guid",
            level=EvidenceLevel.HEADER_RECOGNIZED,
            detail={"oem_signature": oem.decode("latin-1"), "offset": 3},
            supports_claim="BitLocker (BDE) boot sector GUID/OEM parsed (format identified; not unlocked)",
        )
    finally:
        fh.seek(start)


@guarded
def detect_veracrypt_smell(fh: BinaryIO) -> Evidence | None:
    """L1 smell test only.

    Reimplements the two predicates behind ``is_veracrypt_volume`` so each can be reported
    as separate evidence, and records the measured entropy. A positive result means "could
    be VeraCrypt / could be any high-entropy blob", never "is VeraCrypt".
    """
    start = fh.tell()
    try:
        size = stream_size(fh)
        sector_aligned = size % SECTOR_SIZE == 0
        fh.seek(0)
        sample = fh.read(SMELL_SAMPLE_BYTES)
        entropy = shannon_entropy(sample)
        try:
            library_says = is_veracrypt_volume(fh)
        except EOFError:
            library_says = False

        if not (sector_aligned and entropy > VERACRYPT_ENTROPY_THRESHOLD and library_says):
            return None

        return Evidence(
            detector="veracrypt_entropy_smell",
            level=EvidenceLevel.POSSIBLE_ENCRYPTED,
            detail={
                "entropy_first_4096": round(entropy, 4),
                "entropy_threshold": VERACRYPT_ENTROPY_THRESHOLD,
                "size_sector_aligned": sector_aligned,
                "size": size,
                "note": "No on-disk magic; entropy+alignment only. Also matches random/compressed data.",
            },
            supports_claim="high-entropy sector-aligned data that could be VeraCrypt (unverified hypothesis)",
        )
    finally:
        fh.seek(start)


ALL_DETECTORS: tuple[Detector, ...] = (detect_luks, detect_bde, detect_veracrypt_smell)
