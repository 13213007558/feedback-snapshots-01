"""Encrypted volume detection with an explicit evidence contract.

Use :func:`detect` to get a :class:`~dissect.fve.detect.contract.DetectionResult`.  The result never
confuses "high entropy" with "encrypted" and never reports an unsupported format as plaintext.

Example::

    from dissect.fve.detect import detect

    with open("volume.img", "rb") as fh:
        result = detect(fh)
        print(result.conclusion, result.confirmed_format)

    with open("volume.img", "rb") as fh:
        result = detect(fh, key_material={"passphrase": "hunter2"})
        if result.key_verified:
            print("cryptographically confirmed", result.format)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.fve.detect import probes
from dissect.fve.detect.contract import (
    FORMAT_CLAIMS,
    Candidate,
    Conclusion,
    DetectionResult,
    Evidence,
    EvidenceKind,
    Format,
    VerificationResult,
    VerificationStatus,
    aggregate,
)
from dissect.fve.detect.verify import verify_bde, verify_luks, verify_veracrypt

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import BinaryIO

    from dissect.util.stream import RelativeStream

__all__ = [
    "FORMAT_CLAIMS",
    "Candidate",
    "Conclusion",
    "DetectionResult",
    "Evidence",
    "EvidenceKind",
    "Format",
    "VerificationResult",
    "VerificationStatus",
    "detect",
    "detect_veracrypt",
]

#: Key material names each verifier understands.
BDE_KEY_MATERIAL = ("passphrase", "recovery_password", "bek", "external_key", "fvek")
LUKS_KEY_MATERIAL = ("passphrase", "key_file", "volume_key")
VERACRYPT_KEY_MATERIAL = ("passphrase", "header_key")

#: Key material that only makes sense for one format; used to warn about unused credentials.
BDE_SPECIFIC_MATERIAL = ("recovery_password", "bek", "external_key", "fvek")
LUKS_SPECIFIC_MATERIAL = ("key_file", "volume_key")

#: Per-format probe callables.
PROBES: dict[Format, Callable[..., Candidate]] = {
    Format.BITLOCKER: probes.probe_bde,
    Format.LUKS: probes.probe_luks,
    Format.VERACRYPT: probes.probe_veracrypt,
}


def detect(
    fh: BinaryIO,
    *,
    offset: int = 0,
    size: int | None = None,
    formats: "Iterator[Format | str] | None" = None,
    key_material: "Mapping[str, Any] | None" = None,
    veracrypt_is_system: bool = False,
    sample_size: int = probes.ENTROPY_SAMPLE_SIZE,
) -> DetectionResult:
    """Inspect ``fh`` and return an evidence-backed detection result.

    Args:
        fh: A seekable binary stream.  Its position is restored before returning.
        offset: Byte offset where the volume starts inside ``fh``.
        size: Optional length of the volume; defaults to the remaining stream length.
        formats: Restrict the probes that run (default: all supported formats).  Accepts ``Format``
            members or their string values.
        key_material: Optional authorized key material.  When given, matching formats are verified
            and a successful check can raise the result to ``KEY_VERIFIED``.
        veracrypt_is_system: Treat the VeraCrypt header as a system volume header at sector 62.
        sample_size: Number of bytes sampled for the entropy heuristic.

    Returns:
        A :class:`DetectionResult`.  ``position_preserved`` reports whether the stream position was
        restored, and is ``False`` (rather than raising) if restoration failed.
    """
    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")
    if size is not None and size < 0:
        raise ValueError(f"size must be non-negative or None, got {size}")

    try:
        start = fh.tell()
    except (OSError, ValueError):
        start = None

    position_preserved = True
    candidates: list[Candidate] = []
    probe_errors: dict[str, str] = {}
    verifications: list[VerificationResult] = []
    warnings: list[str] = []
    markers: list[str] = []
    resolved_size: int | None = size

    try:
        stream = _scoped_stream(fh, offset, size)
    except (OSError, ValueError) as exc:
        return DetectionResult(
            conclusion=Conclusion.INCONCLUSIVE,
            format=None,
            warnings=[f"stream is not seekable, cannot inspect it: {exc}"],
            probe_errors={"stream": f"{type(exc).__name__}: {exc}"},
            offset=offset,
            size=size,
            position_preserved=False,
        )

    try:
        selected = [_coerce_format(fmt) for fmt in formats] if formats is not None else list(PROBES)

        for fmt in selected:
            probe = PROBES.get(fmt)
            if probe is None:
                probe_errors[fmt.value] = "no probe registered"
                continue
            try:
                if fmt is Format.VERACRYPT:
                    candidate = probe(stream, is_system=veracrypt_is_system, sample_size=sample_size)
                else:
                    candidate = probe(stream)
                candidates.append(candidate)
            except Exception as exc:  # noqa: BLE001
                probe_errors[fmt.value] = f"{type(exc).__name__}: {exc}"
                candidates.append(Candidate(Conclusion.INCONCLUSIVE, fmt))

        try:
            markers = probes.probe_plaintext(stream)
        except Exception as exc:  # noqa: BLE001
            probe_errors["plaintext"] = f"{type(exc).__name__}: {exc}"
            markers = []

        if key_material:
            verifications, verify_warnings = _verify_all(
                fh, offset, size, candidates, key_material, veracrypt_is_system=veracrypt_is_system
            )
            warnings.extend(verify_warnings)

        if size is None:
            resolved_size = _stream_size(stream)
    finally:
        if start is not None:
            try:
                fh.seek(start)
            except (OSError, ValueError):
                position_preserved = False

    return aggregate(
        candidates,
        verifications=verifications,
        plaintext_markers=markers,
        warnings=warnings,
        probe_errors=probe_errors,
        offset=offset,
        size=resolved_size,
        position_preserved=position_preserved,
    )


def detect_veracrypt(
    fh: BinaryIO,
    *,
    passphrase: str | None = None,
    header_key: bytes | None = None,
    pim: int | None = None,
    is_system: bool = False,
) -> VerificationResult:
    """Convenience helper: try to prove a VeraCrypt volume with an authorized key.

    This is the only path that can legitimately produce a VeraCrypt conclusion, because VeraCrypt
    headers carry no plaintext signature.
    """
    material: dict[str, Any] = {}
    if header_key is not None:
        material["header_key"] = header_key
    if passphrase is not None:
        material["passphrase"] = passphrase
        if pim is not None:
            material["pim"] = pim
    start = fh.tell()
    try:
        return verify_veracrypt(fh, material, is_system=is_system)
    finally:
        fh.seek(start)


def _verify_all(
    fh: BinaryIO,
    offset: int,
    size: int | None,
    candidates: list[Candidate],
    material: "Mapping[str, Any]",
    *,
    veracrypt_is_system: bool,
) -> tuple[list[VerificationResult], list[str]]:
    """Run authorized-key verification against formats that both claim and can consume the key."""
    verifications: list[VerificationResult] = []
    warnings: list[str] = []

    claimed = {c.format for c in candidates if c.has_format_claim}

    bde_candidate = next((c for c in candidates if c.format is Format.BITLOCKER), None)
    if bde_candidate and bde_candidate.conclusion in (Conclusion.HEADER_RECOGNIZED, Conclusion.UNSUPPORTED_FORMAT):
        if any(key in material for key in BDE_KEY_MATERIAL):
            verifications.append(_run_verifier(verify_bde, fh, offset, size, material))
    elif any(key in material for key in BDE_SPECIFIC_MATERIAL) and Format.BITLOCKER not in claimed:
        warnings.append("BitLocker-specific key material supplied but no BitLocker header candidate was found")

    luks_candidate = next((c for c in candidates if c.format is Format.LUKS), None)
    if luks_candidate and luks_candidate.conclusion in (Conclusion.HEADER_RECOGNIZED, Conclusion.UNSUPPORTED_FORMAT):
        if any(key in material for key in LUKS_KEY_MATERIAL):
            verifications.append(_run_verifier(verify_luks, fh, offset, size, material))
    elif any(key in material for key in LUKS_SPECIFIC_MATERIAL) and Format.LUKS not in claimed:
        warnings.append("LUKS-specific key material supplied but no LUKS header candidate was found")

    # VeraCrypt has no plaintext header.  Only try it when no other format already claimed the
    # stream, so a confirmed BitLocker/LUKS volume does not gain a spurious rejected attempt.
    if not (claimed & {Format.BITLOCKER, Format.LUKS}) and any(
        key in material for key in VERACRYPT_KEY_MATERIAL
    ):
        verifications.append(
            _run_verifier(verify_veracrypt, fh, offset, size, material, is_system=veracrypt_is_system)
        )

    return verifications, warnings


def _run_verifier(
    verifier: "Callable[..., VerificationResult]",
    fh: BinaryIO,
    offset: int,
    size: int | None,
    material: "Mapping[str, Any]",
    **kwargs: Any,
) -> VerificationResult:
    """Run one verifier on a scoped view of ``fh``, restoring the view afterwards."""
    stream = _scoped_stream(fh, offset, size)
    try:
        return verifier(stream, material, **kwargs)
    finally:
        stream.seek(0)


def _coerce_format(fmt: Format | str) -> Format:
    if isinstance(fmt, Format):
        return fmt
    return Format(fmt)


def _scoped_stream(fh: BinaryIO, offset: int, size: int | None) -> BinaryIO:
    """Return a view of ``fh`` starting at ``offset``.

    The caller's stream is never closed, and views are cheap for ``offset == 0``.
    """
    if offset == 0:
        fh.seek(0)
        return fh
    from dissect.util.stream import RelativeStream

    stream: RelativeStream = RelativeStream(fh, offset, size)
    return stream


def _stream_size(fh: BinaryIO) -> int | None:
    size = getattr(fh, "size", None)
    if size is not None:
        return int(size)
    try:
        return fh.seek(0, 2)
    except (OSError, ValueError):
        return None
