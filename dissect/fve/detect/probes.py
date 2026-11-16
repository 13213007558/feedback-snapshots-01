"""Evidence-producing probes for the supported full volume encryption formats.

Every probe:

* reads only from the supplied stream and restores its original position, even on error,
* reports what it saw as :class:`~dissect.fve.detect.contract.Evidence` instead of a bare boolean,
* distinguishes ``not this format`` from ``this format, but unsupported``.

None of these probes performs key derivation by default: they are cheap and do not require secrets.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import struct
import zlib
from functools import wraps
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.fve.bde.c_bde import (
    BITLOCKER_SIGNATURE,
    CIPHER_MAP,
    EOW_INFORMATION_OFFSET_GUID,
    INFORMATION_OFFSET_GUID,
    FVE_KEY_TYPE,
    FVE_STATE,
    c_bde,
)
from dissect.fve.detect.contract import Candidate, Conclusion, EvidenceKind, Format
from dissect.fve.luks.c_luks import (
    LUKS2_MAGIC_1ST,
    LUKS2_MAGIC_2ND,
    SECONDARY_HEADER_OFFSETS,
    c_luks,
)
from dissect.fve.veracrypt.c_veracrypt import c_veracrypt

if TYPE_CHECKING:
    from collections.abc import Callable

#: Minimum bytes any probe will look at.
BOOT_SECTOR_SIZE = 512
#: Enough to cover a BitLocker information block with a small dataset.
BDE_READ_SIZE = 4096
#: LUKS2 primary header plus JSON area (the on-disk default ``hdr_size``).
LUKS2_MIN_HEADER_SIZE = 16 * 1024
#: VeraCrypt non-system volume header (salt + encrypted header).
VERACRYPT_HEADER_SIZE = 576
#: VeraCrypt system volume header sits at sector 62.
VERACRYPT_SYSTEM_HEADER_OFFSET = (63 - 1) * 512

#: Entropy thresholds.  Real encrypted payloads routinely exceed 7.9 bits/byte.
ENTROPY_THRESHOLD = 7.9
#: Number of bytes sampled for the entropy heuristic.
ENTROPY_SAMPLE_SIZE = 4096
#: A full volume encryption container's size is a multiple of 512.
VOLUME_SECTOR_SIZE = 512

#: Byte prefixes that indicate a plaintext filesystem or partition table rather than ciphertext.
PLAINTEXT_MARKERS = (
    b"NTFS    ",
    b"MSDOS5.0",
    b"EXFAT   ",
    b"ReFS    ",
    b"EFI PART",
)

#: Offset and length of the checksum field in the LUKS2 on-disk header.
LUKS2_CSUM_OFFSET = 0x1C0
LUKS2_CSUM_SIZE = 64

LUKS1_KEY_ENABLED = 0x00AC71F3


def _position_safe(fn: "Callable[..., Candidate]") -> "Callable[..., Candidate]":
    """Restore the stream position after a probe, including when the probe raises."""

    @wraps(fn)
    def wrapper(fh: BinaryIO, *args: object, **kwargs: object) -> Candidate:
        stored = fh.tell()
        try:
            return fn(fh, *args, **kwargs)
        finally:
            fh.seek(stored)

    return wrapper


def _read_at(fh: BinaryIO, offset: int, size: int) -> bytes:
    """Read ``size`` bytes at ``offset`` without relying on the caller's position."""
    fh.seek(offset)
    return fh.read(size)


def _stream_size(fh: BinaryIO) -> int | None:
    size = getattr(fh, "size", None)
    if size is not None:
        return int(size)
    try:
        return fh.seek(0, io.SEEK_END)
    except (OSError, ValueError):
        return None


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def plaintext_markers(buf: bytes) -> list[str]:
    """Return human readable markers for plaintext structures found in ``buf``."""
    found = []
    for marker in PLAINTEXT_MARKERS:
        if buf.startswith(marker):
            found.append(marker.rstrip(b"\x00").decode("latin-1"))
    if buf[3:11] == b"NTFS    " and "NTFS" not in found:
        found.append("NTFS")
    if buf[0x1fe:0x200] == b"\x55\xaa" and buf[0x1c2] in (0x07, 0x0B, 0x0C, 0xEE):
        found.append("MBR")
    return found


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


@_position_safe
def probe_bde(fh: BinaryIO) -> Candidate:
    """Probe for a BitLocker volume.

    BitLocker's boot sector either carries the ``-FVE-FS-`` OEM string or one of two Microsoft
    GUIDs that point at the FVE information blocks.  A GUID alone is not enough: the referenced
    information block must parse, carry the ``-FVE-FS-`` signature and pass its CRC32.
    """
    candidate = Candidate(Conclusion.INCONCLUSIVE, Format.BITLOCKER)

    buf = _read_at(fh, 0, BDE_READ_SIZE)
    if len(buf) < BOOT_SECTOR_SIZE:
        candidate.add(EvidenceKind.TRUNCATED, f"only {len(buf)} of {BOOT_SECTOR_SIZE} boot sector bytes available")
        return candidate

    sector = buf[:BOOT_SECTOR_SIZE]
    has_oem = sector[3:11] == BITLOCKER_SIGNATURE
    info_guid = sector.find(INFORMATION_OFFSET_GUID.bytes_le)
    eow_guid = sector.find(EOW_INFORMATION_OFFSET_GUID.bytes_le)

    if not has_oem and info_guid == -1 and eow_guid == -1:
        return candidate

    if has_oem:
        candidate.add(EvidenceKind.FORMAT_SIGNATURE, "boot sector OEM string equals -FVE-FS-", offset=3)
        candidate.details["boot_signature"] = "oem"
    if info_guid != -1:
        candidate.add(EvidenceKind.FORMAT_SIGNATURE, "BitLocker information offset GUID present", offset=info_guid)
        candidate.details["boot_signature"] = "information-guid"
    if eow_guid != -1:
        candidate.add(EvidenceKind.FORMAT_SIGNATURE, "BitLocker end-of-writes GUID present", offset=eow_guid)
        candidate.details["boot_signature"] = "eow-guid"

    # Enumerate the information offsets the boot sector advertises, defensively.
    try:
        boot = c_bde.BOOT_SECTOR(sector)
        sector_size = boot.Bpb.BytesPerSector
        if not _is_power_of_two(sector_size) or not (512 <= sector_size <= 4096):
            candidate.add(EvidenceKind.HEADER_STRUCTURE, f"implausible sector size {sector_size}")
            return candidate
        candidates: list[int] = []
        if eow_guid != -1:
            recognition = c_bde.FVE_EOW_GUID_RECOGNITION(sector[eow_guid:])
            candidates.extend(int(offset) for offset in recognition.InformationOffset if offset)
        elif info_guid != -1:
            recognition = c_bde.FVE_GUID_RECOGNITION(sector[info_guid:])
            candidates.extend(int(offset) for offset in recognition.InformationOffset if offset)
        else:
            candidates.append(int(boot.InformationLcn) * sector_size * boot.Bpb.SectorsPerCluster)
    except (EOFError, ValueError, struct.error) as exc:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, f"boot sector did not parse: {exc}")
        return candidate

    candidate.details["information_offsets"] = candidates
    if not candidates:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, "boot sector advertises no information offsets")
        return candidate

    valid_offsets = []
    checked = 0
    for offset in candidates[:3]:
        buf = _read_at(fh, offset, BDE_READ_SIZE)
        if len(buf) < 16:
            candidate.add(EvidenceKind.TRUNCATED, f"information block at 0x{offset:x} is not readable")
            continue
        signature = buf[:8]
        if signature != BITLOCKER_SIGNATURE:
            candidate.add(
                EvidenceKind.HEADER_STRUCTURE,
                f"no -FVE-FS- signature at advertised offset 0x{offset:x}",
                offset=offset,
            )
            continue
        checked += 1
        try:
            header = c_bde.FVE_INFORMATION(buf)
            header_size = int(header.HeaderSize)
            if header.Version >= 2:
                header_size <<= 4
            crc_offset = header_size
            validation_data = buf[crc_offset : crc_offset + 8]
            if len(validation_data) < 8:
                candidate.add(
                    EvidenceKind.TRUNCATED,
                    f"CRC32 validation record at 0x{offset + crc_offset:x} is beyond readable data",
                    offset=offset,
                )
                continue
            validation = c_bde.FVE_VALIDATION(validation_data)
            stored = int(validation.Crc32)
            calculated = zlib.crc32(buf[:header_size]) & 0xFFFFFFFF
            if stored != calculated:
                candidate.add(
                    EvidenceKind.HEADER_STRUCTURE,
                    f"information block CRC32 mismatch at 0x{offset:x}",
                    offset=offset,
                    stored=stored,
                    calculated=calculated,
                )
                continue
            candidate.add(
                EvidenceKind.HEADER_INTEGRITY,
                f"information block at 0x{offset:x} passed CRC32 validation",
                offset=offset,
                crc32=calculated,
            )
            valid_offsets.append(offset)
        except (EOFError, ValueError, struct.error) as exc:
            candidate.add(EvidenceKind.HEADER_STRUCTURE, f"information block at 0x{offset:x} did not parse: {exc}")
            continue

    if not valid_offsets:
        # A recognizable boot signature with no intact information block is only a signature
        # observation: the header itself could not be validated.  Do not promote it to header
        # strength, and do not call it plaintext either.
        candidate.details["information_blocks_valid"] = 0
        candidate.details["information_blocks_checked"] = checked
        candidate.details["partial"] = True
        candidate.conclusion = Conclusion.INCONCLUSIVE
        return candidate

    candidate.add(
        EvidenceKind.HEADER_STRUCTURE,
        f"{len(valid_offsets)} intact BitLocker information block(s)",
        offsets=valid_offsets,
    )
    candidate.details["information_blocks_valid"] = len(valid_offsets)
    candidate.details["information_blocks_checked"] = checked

    # Check whether this build can actually handle the announced FVEK type.
    try:
        info = c_bde.FVE_INFORMATION(_read_at(fh, valid_offsets[0], BDE_READ_SIZE))
        dataset = c_bde.FVE_DATASET(_read_at(fh, valid_offsets[0] + len(info), 64))
        fvek_type = int(dataset.FvekType)
        candidate.details["fvek_type"] = fvek_type
        state = int(info.CurrentState)
        candidate.details["state"] = state
        if fvek_type == int(FVE_KEY_TYPE.NONE) and state == int(FVE_STATE.DECRYPTED):
            candidate.add(
                EvidenceKind.HEADER_STRUCTURE,
                "BitLocker metadata reports a fully decrypted volume (no FVEK in use)",
                state=state,
            )
            candidate.details["encryption_state"] = "decrypted"
            candidate.supported = True
            candidate.conclusion = Conclusion.HEADER_RECOGNIZED
            return candidate
        supported = fvek_type in {int(k) for k in CIPHER_MAP}
        candidate.supported = supported
        if not supported:
            candidate.add(
                EvidenceKind.HEADER_STRUCTURE,
                f"FVEK type {fvek_type} has no cipher implementation in this build",
                fvek_type=fvek_type,
            )
            candidate.details["limitation"] = "implementation"
            return candidate
    except (EOFError, ValueError, struct.error) as exc:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, f"dataset header did not parse: {exc}")

    candidate.conclusion = Conclusion.HEADER_RECOGNIZED
    return candidate


def _luks1_structure(header: Any) -> tuple[bool, str]:
    cipher = bytes(header.cipherName).rstrip(b"\x00").decode("latin-1")
    mode = bytes(header.cipherMode).rstrip(b"\x00").decode("latin-1")
    hash_spec = bytes(header.hashSpec).rstrip(b"\x00").decode("latin-1")
    uuid = bytes(header.uuid).rstrip(b"\x00").decode("latin-1")
    key_bytes = int(header.keyBytes)
    payload_offset = int(header.payloadOffset)
    if not cipher or not mode or not hash_spec:
        return False, "empty cipher/mode/hash field"
    if not (16 <= key_bytes <= 128) or key_bytes % 8 != 0:
        return False, f"implausible key size {key_bytes}"
    if payload_offset < 2:
        return False, f"implausible payload offset {payload_offset}"
    if not uuid or len(uuid) != 36:
        return False, "uuid is not a 36 character string"
    return True, f"cipher={cipher}-{mode} hash={hash_spec} key_bytes={key_bytes}"


def _luks2_structure(buf: bytes, offset: int) -> tuple[bool, str, dict[str, object]]:
    details: dict[str, object] = {}
    if len(buf) < 4096:
        return False, "binary header truncated", details
    header = c_luks.luks2_hdr_disk(buf)
    version = int(header.version)
    if version != 2:
        return False, f"header version {version} is not 2", details
    hdr_size = int(header.hdr_size)
    if not (4096 <= hdr_size <= 4 * 1024 * 1024) or hdr_size % 4096 != 0:
        return False, f"implausible header size {hdr_size}", details
    if int(header.hdr_offset) != offset:
        return False, f"header offset field {header.hdr_offset} does not match {offset}", details
    algorithm = bytes(header.checksum_alg).rstrip(b"\x00").decode("latin-1")
    details["checksum_algorithm"] = algorithm
    if algorithm not in ("sha256", "sha512"):
        return False, f"unsupported checksum algorithm {algorithm!r}", details
    details["hdr_size"] = hdr_size
    return True, "", details


@_position_safe
def probe_luks(fh: BinaryIO) -> Candidate:
    """Probe for LUKS1/LUKS2.

    A magic string alone is a weak observation.  Strength is only assigned after the binary header
    fields are plausible *and*, for LUKS2, the header checksum over the binary header plus JSON
    area verifies and the JSON metadata parses.
    """
    candidate = Candidate(Conclusion.INCONCLUSIVE, Format.LUKS)
    size = _stream_size(fh) or 0
    primary = _read_at(fh, 0, min(LUKS2_MIN_HEADER_SIZE, max(size, 0)))
    if len(primary) < 6:
        candidate.add(EvidenceKind.TRUNCATED, f"only {len(primary)} bytes available, need 6 for a LUKS magic")
        return candidate

    primary_magic = primary[:6]
    secondary_offset = None
    secondary = b""
    for offset in SECONDARY_HEADER_OFFSETS:
        if offset >= size:
            break
        buf = _read_at(fh, offset, 6)
        if buf == LUKS2_MAGIC_2ND:
            secondary_offset = offset
            secondary = _read_at(fh, offset, 4096)
            break

    if primary_magic not in (LUKS2_MAGIC_1ST, LUKS2_MAGIC_2ND) and secondary_offset is None:
        return candidate

    if primary_magic == LUKS2_MAGIC_2ND:
        candidate.add(EvidenceKind.FORMAT_SIGNATURE, "secondary LUKS2 magic at offset 0", offset=0)
        candidate.details["magic"] = "secondary-at-0"
    elif primary_magic == LUKS2_MAGIC_1ST:
        candidate.add(EvidenceKind.FORMAT_SIGNATURE, "LUKS magic at offset 0", magic=primary_magic.decode("latin-1"))
        candidate.details["magic"] = "primary"
    else:
        candidate.add(
            EvidenceKind.FORMAT_SIGNATURE,
            f"secondary LUKS2 magic at 0x{secondary_offset:x}",
            offset=secondary_offset,
        )
        candidate.details["magic"] = "secondary"

    if secondary_offset is not None:
        candidate.details["secondary_header_offset"] = secondary_offset

    version = int.from_bytes(primary[6:8], "big") if len(primary) >= 8 else 0
    if candidate.details["magic"] == "secondary":
        version = int.from_bytes(secondary[6:8], "big") if len(secondary) >= 8 else 0

    if version not in (1, 2):
        candidate.add(
            EvidenceKind.HEADER_STRUCTURE,
            f"LUKS magic present but version field is {version} (expected 1 or 2); not a valid header",
            version=version,
        )
        # Magic without a plausible header stays an explicit non-claim.
        return candidate

    candidate.details["version"] = version

    if version == 1:
        if len(primary) < 1024:
            candidate.add(
                EvidenceKind.TRUNCATED,
                f"LUKS1 header truncated: only {len(primary)} of 1024 bytes available; structure cannot be validated",
                available=len(primary),
                required=1024,
            )
            candidate.details["partial"] = True
            return candidate
        header = c_luks.luks_phdr(primary[:1024])
        ok, reason = _luks1_structure(header)
        if not ok:
            candidate.add(EvidenceKind.HEADER_STRUCTURE, f"LUKS1 header rejected: {reason}")
            return candidate
        candidate.add(EvidenceKind.HEADER_STRUCTURE, f"LUKS1 header fields plausible: {reason}")
        active = [i for i, keyblock in enumerate(header.keyblock) if int(keyblock.active) == LUKS1_KEY_ENABLED]
        candidate.details["active_keyslots"] = active
        candidate.conclusion = Conclusion.HEADER_RECOGNIZED
        candidate.supported = True
        return candidate

    # LUKS2
    target_offset = 0 if candidate.details["magic"] in ("primary", "secondary-at-0") else secondary_offset
    buf = primary if target_offset == 0 else secondary
    if len(buf) < 4096:
        candidate.add(
            EvidenceKind.TRUNCATED,
            f"LUKS2 binary header truncated: only {len(buf)} of 4096 bytes available",
            available=len(buf),
            required=4096,
        )
        candidate.details["partial"] = True
        return candidate

    ok, reason, details = _luks2_structure(buf, target_offset)
    candidate.details.update(details)
    if not ok:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, f"LUKS2 header rejected: {reason}")
        return candidate

    hdr_size = int(details["hdr_size"])
    header_bytes = _read_at(fh, target_offset, hdr_size)
    if len(header_bytes) < hdr_size:
        candidate.add(
            EvidenceKind.TRUNCATED,
            f"LUKS2 header/JSON area truncated: {len(header_bytes)} of {hdr_size} bytes; checksum cannot be verified",
            offset=target_offset,
            available=len(header_bytes),
            required=hdr_size,
        )
        candidate.details["partial"] = True
        return candidate

    algorithm = str(details["checksum_algorithm"])
    header_obj = c_luks.luks2_hdr_disk(header_bytes)
    digest_size = hashlib.new(algorithm).digest_size
    stored_checksum = bytes(header_obj.csum)[:digest_size]

    # The checksum covers the binary header and the JSON area with the csum field zeroed.
    # csum sits at offset 0x1C0 in the on-disk header (after label, checksum_alg, salt, uuid,
    # subsystem, hdr_offset and their padding).
    zeroed = bytearray(header_bytes)
    zeroed[LUKS2_CSUM_OFFSET : LUKS2_CSUM_OFFSET + LUKS2_CSUM_SIZE] = b"\x00" * LUKS2_CSUM_SIZE
    calculated = hashlib.new(algorithm, bytes(zeroed)).digest()

    if calculated != stored_checksum:
        candidate.add(
            EvidenceKind.HEADER_STRUCTURE,
            "LUKS2 header checksum mismatch",
            stored=stored_checksum.hex(),
            calculated=calculated.hex(),
        )
        return candidate

    candidate.add(
        EvidenceKind.HEADER_INTEGRITY,
        f"LUKS2 {algorithm} header checksum valid over binary header and JSON area",
        offset=target_offset,
        algorithm=algorithm,
    )

    json_offset = 4096
    json_area = header_bytes[json_offset:hdr_size]
    try:
        metadata = json.loads(json_area.rstrip(b"\x00").decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, f"LUKS2 JSON metadata did not parse: {exc}")
        return candidate
    if not isinstance(metadata, dict) or "keyslots" not in metadata or "segments" not in metadata:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, "LUKS2 JSON metadata lacks keyslots/segments")
        return candidate
    candidate.add(
        EvidenceKind.HEADER_STRUCTURE,
        "LUKS2 JSON metadata parsed",
        keyslots=sorted(metadata.get("keyslots", {})),
        segments=sorted(metadata.get("segments", {})),
    )
    candidate.conclusion = Conclusion.HEADER_RECOGNIZED

    unsupported_reason = _luks2_unsupported(metadata)
    candidate.details["keyslots"] = sorted(metadata.get("keyslots", {}))
    if unsupported_reason:
        candidate.add(EvidenceKind.HEADER_STRUCTURE, unsupported_reason)
        candidate.supported = False
        limitation = "environment" if "Argon2 implementation" in unsupported_reason else "implementation"
        candidate.details["limitation"] = limitation
    else:
        candidate.supported = True
    return candidate


def _luks2_unsupported(metadata: dict) -> str | None:
    """Return a reason string when the LUKS2 metadata uses features this build cannot unlock."""
    for slot_id, slot in metadata.get("keyslots", {}).items():
        kdf = (slot or {}).get("kdf") or {}
        if kdf.get("type") in ("argon2i", "argon2id"):
            from dissect.fve.crypto import argon2

            if not argon2.HAS_ARGON2:
                return f"keyslot {slot_id} uses {kdf.get('type')} but no Argon2 implementation is available"
    for slot_id, slot in metadata.get("keyslots", {}).items():
        encryption = ((slot or {}).get("area") or {}).get("encryption") or ""
        if encryption and not _cipher_supported(encryption):
            return f"keyslot {slot_id} uses unsupported keyslot cipher {encryption}"
    for segment_id, segment in metadata.get("segments", {}).items():
        encryption = (segment or {}).get("encryption") or ""
        if encryption and not _cipher_supported(encryption):
            return f"segment {segment_id} uses unsupported cipher {encryption}"
    return None


def _cipher_supported(spec: str) -> bool:
    from dissect.fve.crypto import parse_cipher_spec

    try:
        name, mode, _key_size, _iv, _options = parse_cipher_spec(spec, key_size_hint=256)
    except ValueError:
        return False
    return name == "aes" and mode in ("ecb", "cbc", "xts")


@_position_safe
def probe_veracrypt(fh: BinaryIO, *, is_system: bool = False, sample_size: int = ENTROPY_SAMPLE_SIZE) -> Candidate:
    """Probe for VeraCrypt.

    There is no plaintext magic to look for: the header is encrypted.  A VeraCrypt claim can only
    come from decrypting the header with an authorized key.  Short of that, this probe returns a
    *generic* high entropy candidate: ``format`` stays ``None`` even when the bytes are consistent
    with a VeraCrypt layout, so entropy can never be reported as a VeraCrypt identification.
    """
    candidate = Candidate(Conclusion.INCONCLUSIVE, None)
    size = _stream_size(fh)
    header_offset = VERACRYPT_SYSTEM_HEADER_OFFSET if is_system else 0
    buf = _read_at(fh, header_offset, VERACRYPT_HEADER_SIZE)
    if is_system:
        candidate.details["header_offset"] = header_offset

    sector_aligned = size is None or size % VOLUME_SECTOR_SIZE == 0
    candidate.details["sector_aligned"] = sector_aligned

    sample = buf[:sample_size] if len(buf) >= sample_size else _read_at(fh, header_offset, sample_size)
    bits = shannon_entropy(sample)
    candidate.details["entropy_bits_per_byte"] = round(bits, 3)
    candidate.details["entropy_sample_bytes"] = len(sample)

    if len(sample) < sample_size:
        candidate.add(
            EvidenceKind.TRUNCATED,
            f"only {len(sample)} of {sample_size} bytes available for an entropy sample",
        )
        if len(sample) >= 64 and bits > ENTROPY_THRESHOLD:
            candidate.add(
                EvidenceKind.ENTROPY,
                f"high entropy ({bits:.3f} bits/byte) in a short ({len(sample)} byte) sample; no format claim possible",
                bits_per_byte=round(bits, 3),
            )
            candidate.conclusion = Conclusion.POSSIBLY_ENCRYPTED
        return candidate

    if bits <= ENTROPY_THRESHOLD:
        candidate.add(EvidenceKind.ENTROPY, f"low entropy ({bits:.3f} bits/byte) in the first {sample_size} bytes")
        return candidate

    candidate.add(
        EvidenceKind.ENTROPY,
        f"high entropy ({bits:.3f} bits/byte); compatible with ciphertext but also with compressed or random data",
        bits_per_byte=round(bits, 3),
    )
    candidate.conclusion = Conclusion.POSSIBLY_ENCRYPTED

    if not sector_aligned:
        # High entropy but clearly not a VeraCrypt container layout.
        candidate.add(
            EvidenceKind.HEADER_STRUCTURE,
            f"stream size {size} is not a multiple of {VOLUME_SECTOR_SIZE}; not a VeraCrypt container layout",
            size=size,
        )
        return candidate

    has_header_shape = _looks_like_veracrypt_header(buf)
    if has_header_shape:
        candidate.add(
            EvidenceKind.HEADER_STRUCTURE,
            "first 576 bytes have the layout of a VeraCrypt salt+header (no plaintext signature)",
            entropy=round(bits, 3),
        )
        candidate.details["header_shape"] = True
    return candidate


def _looks_like_veracrypt_header(buf: bytes) -> bool:
    """Heuristic only: VeraCrypt has no plaintext magic, so this must never become a format claim."""
    if len(buf) < VERACRYPT_HEADER_SIZE:
        return False
    salt, header = buf[:64], buf[64:VERACRYPT_HEADER_SIZE]
    salt_bits = shannon_entropy(salt)
    header_bits = shannon_entropy(header)
    return salt_bits > ENTROPY_THRESHOLD and header_bits > ENTROPY_THRESHOLD


@_position_safe
def probe_plaintext(fh: BinaryIO) -> list[str]:
    """Return plaintext structure markers in the first sector."""
    buf = _read_at(fh, 0, BOOT_SECTOR_SIZE)
    return plaintext_markers(buf) if buf else []
