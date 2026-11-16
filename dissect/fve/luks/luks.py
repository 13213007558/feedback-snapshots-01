from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.fve.crypto import argon2, create_cipher
from dissect.fve.crypto.dmcrypt import CryptStream
from dissect.fve.luks import af
from dissect.fve.luks.c_luks import (
    LUKS2_MAGIC_1ST,
    LUKS2_MAGIC_2ND,
    SECONDARY_HEADER_OFFSETS,
    c_luks,
)
from dissect.fve.luks.metadata import Metadata

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.fve.luks.metadata import Digest, Keyslot, Segment


class LUKS:
    """LUKS disk encryption.

    A volume can be a single file-like object containing both the LUKS header (including the keyslot areas) and the
    encrypted payload, or a detached header combined with a separate data image. With a detached header, all header
    and keyslot offsets are resolved against the header source, while encrypted segments are read from the data
    source.

    Args:
        fh: File-like object containing the LUKS header. If ``data_fh`` is not given, this object must also contain
            the encrypted payload (the historical single-file usage).
        data_fh: Optional file-like object containing only the encrypted payload. When given, the header is read from
            ``fh`` (or ``header_fh``) and the payload from this object.
        header_fh: Optional explicit header source for the detached layout. Mutually exclusive with ``fh``.

    Raises:
        ValueError: If the inputs are ambiguous or invalid, or the header cannot be parsed.
        EOFError: If the header, keyslot or payload source is truncated.

    References:
        - https://gitlab.com/cryptsetup/cryptsetup
        - https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf
    """

    def __init__(
        self,
        fh: BinaryIO | None = None,
        data_fh: BinaryIO | None = None,
        *,
        header_fh: BinaryIO | None = None,
    ):
        header_source, data_source = self._resolve_sources(fh, data_fh, header_fh)

        self.detached = data_fh is not None or header_fh is not None
        self.header_fh = header_source
        self.data_fh = data_source
        # Historically the single input is exposed as `fh`, keep doing so for compatibility
        self.fh = header_source

        self._header_label = "detached header" if self.detached else "volume"
        self._data_label = "data image" if self.detached else "volume"

        if self.detached:
            _ensure_seekable_readable(self.header_fh, self._header_label)
            _ensure_seekable_readable(self.data_fh, self._data_label)

        self.header = None
        self.header1 = None
        self.header2 = None

        first_offset, second_offset, version = find_luks_headers(self.header_fh)
        if version is None:
            raise ValueError(f"Not a LUKS volume in {self._header_label}")

        if version == 1:
            header_struct = c_luks.luks_phdr
        elif version == 2:
            header_struct = c_luks.luks2_hdr_disk
        else:
            raise ValueError(f"Unsupported LUKS version: {version}")

        if first_offset is not None:
            self.header1 = self._read_header(header_struct, first_offset, "header")
            self.header = self.header1

        if second_offset is not None:
            self.header2 = self._read_header(header_struct, second_offset, "secondary header")

        self.header = self.header2 or self.header1

        # LUKS1
        self.cipher_name = None
        self.cipher_mode = None
        self.hash_spec = None

        # LUKS2
        self.label = None
        self.checksum_algorithm = None
        self.metadata, self.metadata1, self.metadata2 = None, None, None

        if self.header.version != 1:
            # LUKS2 metadata lives in the JSON area directly following each binary header
            if self.header1 is not None:
                self.metadata1 = Metadata.from_json(self._read_json_area(self.header1, first_offset, "header"))

            if self.header2 is not None:
                try:
                    json_area2 = self._read_json_area(self.header2, second_offset, "secondary header")
                except EOFError:
                    if self.header1 is None:
                        raise
                    # A primary header with an incomplete secondary header is still usable
                    self.header2 = None
                else:
                    self.metadata2 = Metadata.from_json(json_area2)

            # Keep the historical preference for the primary metadata, falling back to the secondary header
            self.header = self.header2 or self.header1
            self.metadata = self.metadata1 or self.metadata2

        self.uuid = UUID(self.header.uuid.strip(b"\x00").decode())

        if self.header.version == 1:
            # LUKS1
            self.metadata = Metadata.from_luks1_header(self.header)
        else:
            # LUKS2
            self.label = self.header.label.strip(b"\x00").decode()
            self.checksum_algorithm = self.header.checksum_alg.strip(b"\x00").decode()

        if self.detached:
            # Validate both sources up front so truncated input is diagnosed before any unlock is attempted
            self._validate_header_source()
            self._validate_data_source()

        self._active_volume_key = None
        self._active_keyslot_id = None

    @staticmethod
    def _resolve_sources(
        fh: BinaryIO | None, data_fh: BinaryIO | None, header_fh: BinaryIO | None
    ) -> tuple[BinaryIO, BinaryIO]:
        """Resolve the header and data sources from the supported call styles."""
        if header_fh is not None:
            if fh is not None:
                raise ValueError("Cannot combine `fh` and `header_fh`")
            if data_fh is None:
                raise ValueError("Both `header_fh` and `data_fh` are required for a detached header")
            return header_fh, data_fh

        if fh is None:
            if data_fh is not None:
                raise ValueError("Both `header_fh` (or `fh`) and `data_fh` are required for a detached header")
            raise ValueError("No LUKS header source provided")

        if data_fh is None:
            return fh, fh

        return fh, data_fh

    def _read_header(self, header_struct: type, offset: int, source: str) -> object:
        """Read a LUKS header structure, translating truncation into a source-aware error."""
        try:
            self.header_fh.seek(offset)
            return header_struct(self.header_fh)
        except EOFError as exc:
            raise EOFError(f"Truncated LUKS {source} at offset {offset:#x} in {self._header_label}") from exc
        except (OSError, ValueError) as exc:
            raise EOFError(f"Unable to read LUKS {source} at offset {offset:#x} from {self._header_label}") from exc

    def _read_json_area(self, header: object, hdr_offset: int | None, source: str) -> str:
        """Read and decode the JSON area that follows a LUKS2 binary header."""
        size = header.hdr_size - 4096
        if size < 0:
            raise ValueError(f"Invalid LUKS2 {source} size ({header.hdr_size:#x}) in {self._header_label}")

        offset = header.hdr_offset if hdr_offset is None else hdr_offset

        try:
            self.header_fh.seek(offset + 4096)
            data = self.header_fh.read(size)
        except (OSError, ValueError) as exc:
            raise EOFError(f"Unable to read LUKS2 {source} JSON area from {self._header_label}") from exc

        if len(data) != size:
            raise EOFError(
                f"Truncated LUKS2 {source} JSON area in {self._header_label} "
                f"(expected {size} bytes at offset {offset + 4096:#x}, got {len(data)})"
            )

        return data.rstrip(b"\x00").decode()

    def _validate_header_source(self) -> None:
        """Validate that the detached header source contains all keyslot areas."""
        header_size = _source_size(self.header_fh, self._header_label)

        for keyslot_id, keyslot in self.metadata.keyslots.items():
            area = keyslot.area
            if area is None:
                raise ValueError(f"Keyslot {keyslot_id} has no area in {self._header_label}")

            material_size = keyslot_material_size(keyslot)
            _check_header_range(keyslot_id, area.offset, material_size, header_size, self._header_label)

            if area.size is not None:
                if area.size < material_size:
                    raise ValueError(
                        f"Keyslot {keyslot_id} area is too small for its key material in {self._header_label} "
                        f"(declared {area.size} bytes, need {material_size})"
                    )
                _check_header_range(keyslot_id, area.offset, area.size, header_size, self._header_label)

    def _validate_data_source(self) -> None:
        """Validate that the detached data image can hold every encrypted segment."""
        data_size = _source_size(self.data_fh, self._data_label)

        for segment_id, segment in self.metadata.segments.items():
            offset = segment.offset or 0
            if offset < 0:
                raise ValueError(f"Invalid segment {segment_id} offset ({offset:#x}) in {self._data_label}")

            if offset > data_size:
                raise EOFError(
                    f"Truncated LUKS {self._data_label}: segment {segment_id} offset {offset:#x} "
                    f"is beyond the {data_size:#x} byte data image"
                )

            if isinstance(segment.size, int):
                if segment.size < 0:
                    raise ValueError(f"Invalid segment {segment_id} size ({segment.size:#x}) in {self._data_label}")
                if offset + segment.size > data_size:
                    raise EOFError(
                        f"Truncated LUKS {self._data_label}: segment {segment_id} range "
                        f"({offset:#x}+{segment.size:#x}) extends beyond the {data_size:#x} byte data image"
                    )
            else:
                sector_size = segment.sector_size or 512
                if offset % sector_size or (data_size - offset) % sector_size:
                    raise EOFError(
                        f"Truncated LUKS {self._data_label}: segment {segment_id} range "
                        f"({data_size - offset:#x} bytes at {offset:#x}) is not a multiple of the "
                        f"{sector_size} byte sector size"
                    )

    @property
    def unlocked(self) -> bool:
        return self._active_volume_key is not None

    @property
    def keyslots(self) -> dict[int, Keyslot]:
        return self.metadata.keyslots

    def unlock(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume with the volume encryption key."""
        if not self._verify_volume_key(key, keyslot):
            raise ValueError(f"Invalid volume key for keyslot {keyslot}")
        self._active_volume_key = key
        self._active_keyslot_id = keyslot

    def unlock_with_key_file(self, path: Path, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        with path.open("rb") as fh:
            self.unlock_with_key_fh(fh, offset, size, keyslot)

    def unlock_with_key_fh(self, fh: BinaryIO, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        fh.seek(offset)
        self._unlock_passphrase(fh.read(size), keyslot)

    def unlock_with_passphrase(self, passphrase: str | bytes, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        if isinstance(passphrase, str):
            self._unlock_passphrase(passphrase.encode(), keyslot)
        else:
            self._unlock_passphrase(passphrase, keyslot)

    def _unlock_passphrase(self, passphrase: bytes, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        keyslots = (
            [(keyslot, self.metadata.keyslots[keyslot])] if keyslot is not None else self.metadata.keyslots.items()
        )

        idx = None
        vk = None
        errors = []
        for idx, keyslot in keyslots:
            try:
                key = derive_passphrase_key(passphrase, keyslot)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                vk = self._unlock_volume_key(key, idx)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                self.unlock(vk, idx)
                break
            except ValueError:
                continue
        else:
            if errors:
                msg = "\n".join(f"{idx}: {exc}" for idx, exc in errors)
                raise ValueError(f"No valid keyslot found, but there were errors for the following keyslots:\n{msg}")
            raise ValueError("No valid keyslot found")

    def _unlock_volume_key(self, key: bytes, keyslot: int) -> bytes:
        """Unlock the volume key using the given encryption key and keyslot."""
        keyslot_obj = self.metadata.keyslots[keyslot]

        length = keyslot_material_size(keyslot_obj)
        area = self._read_keyslot_area(keyslot_obj.area.offset, length, keyslot)

        cipher = create_cipher(keyslot_obj.area.encryption, key, keyslot_obj.area.key_size * 8)
        return af.merge(
            cipher.decrypt(area),
            keyslot_obj.key_size,
            keyslot_obj.af.stripes,
            keyslot_obj.af.hash,
        )

    def _read_keyslot_area(self, offset: int, length: int, keyslot: int) -> bytes:
        """Read key material for a keyslot, enforcing the bounds of the header source."""
        label = self._header_label
        size = _source_size(self.header_fh, label)
        _check_header_range(keyslot, offset, length, size, label)

        try:
            self.header_fh.seek(offset)
            data = self.header_fh.read(length)
        except (OSError, ValueError) as exc:
            raise EOFError(f"Unable to read keyslot {keyslot} area from {label}") from exc

        if len(data) != length:
            raise EOFError(
                f"Truncated LUKS {label}: keyslot {keyslot} area "
                f"({offset:#x}+{length:#x}) returned only {len(data)} bytes"
            )

        return data

    def _read_segment_area(self, segment: Segment) -> tuple[int, int | str]:
        """Determine and validate the readable range of a segment in the data source."""
        offset = segment.offset or 0

        if offset < 0:
            raise ValueError(f"Invalid segment offset ({offset:#x}) in {self._data_label}")

        if not self.detached:
            # Preserve the historical single-file behavior; CryptStream resolves "dynamic" itself
            return offset, segment.size

        sector_size = segment.sector_size or 512
        data_size = _source_size(self.data_fh, self._data_label)

        if offset > data_size:
            raise EOFError(
                f"Truncated LUKS {self._data_label}: segment offset {offset:#x} "
                f"is beyond the {data_size:#x} byte data image"
            )

        if isinstance(segment.size, int):
            size = segment.size
            if size < 0:
                raise ValueError(f"Invalid segment size ({size:#x}) in {self._data_label}")
            if offset + size > data_size:
                raise EOFError(
                    f"Truncated LUKS {self._data_label}: segment range ({offset:#x}+{size:#x}) "
                    f"extends beyond the {data_size:#x} byte data image"
                )
        else:
            size = data_size - offset
            if size % sector_size:
                raise EOFError(
                    f"Truncated LUKS {self._data_label}: segment range ({size:#x} bytes at {offset:#x}) "
                    f"is not a multiple of the {sector_size} byte sector size"
                )

        return offset, size

    def _verify_volume_key(self, key: bytes, keyslot: int) -> bool:
        """Verify the given key for the given keyslot."""
        digest = self.find_digest(keyslot)
        if digest.type == "pbkdf2":
            result = hashlib.pbkdf2_hmac(digest.hash, key, digest.salt, digest.iterations, len(digest.digest))
        else:
            # Only the pbkdf2 type is supported in LUKS2
            raise NotImplementedError(f"Unsupported digest algorithm: {digest.type}")

        return result == digest.digest

    def find_digest(self, keyslot: int) -> Digest:
        """Find digest metadata corresponding to the given keyslot."""
        digests = [digest for digest in self.metadata.digests.values() if keyslot in digest.keyslots]
        if not digests:
            raise ValueError(f"No digest found for keyslot {keyslot}")

        return digests[0]

    def find_segment(self, keyslot: int) -> Segment:
        """Find segment metadata corresponding to the given keyslot."""
        digest = self.find_digest(keyslot)
        segments = [segment for segment_id, segment in self.metadata.segments.items() if segment_id in digest.segments]
        if not segments:
            raise ValueError(f"No segment found for keyslot {keyslot}")

        if len(segments) > 1:
            raise NotImplementedError(f"Keyslot {keyslot} has more than one segment")

        return segments[0]

    def open(self) -> CryptStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")

        # Technically LUKS supports multiple segments, but practically it only ever has one
        # Don't bother with supporting multiple segments for now
        segment = self.find_segment(self._active_keyslot_id)
        offset, size = self._read_segment_area(segment)

        return CryptStream(
            self.data_fh,
            segment.encryption,
            self._active_volume_key,
            self.metadata.keyslots[self._active_keyslot_id].key_size * 8,
            offset,
            size,
            segment.iv_tweak or 0,
            segment.sector_size or 512,
        )


def keyslot_material_size(keyslot: Keyslot) -> int:
    """Return the amount of encrypted key material stored for a keyslot."""
    if keyslot.af is not None and keyslot.af.stripes:
        return keyslot.key_size * keyslot.af.stripes
    if keyslot.area is not None and keyslot.area.size is not None:
        return keyslot.area.size
    return keyslot.key_size


def _source_size(fh: BinaryIO, source: str) -> int:
    """Return the total size of a file-like object without disturbing its position."""
    try:
        position = fh.tell()
        size = fh.seek(0, io.SEEK_END)
    except (AttributeError, OSError, ValueError):
        # Some streams cannot seek to the end but do expose a meaningful size
        size = getattr(fh, "size", None)
        if isinstance(size, int):
            return size
        raise ValueError(f"Cannot determine size of {source}: file-like object is not seekable") from None

    if position is None or size is None:
        raise ValueError(f"Cannot determine size of {source}: file-like object is not seekable")

    fh.seek(position)
    return int(size)


def _ensure_seekable_readable(fh: BinaryIO, source: str) -> None:
    """Validate that a source can be used for random access without taking ownership of it."""
    for attr in ("seek", "tell", "read"):
        if not callable(getattr(fh, attr, None)):
            raise ValueError(f"LUKS {source} must be a readable, seekable file-like object")

    if getattr(fh, "closed", False):
        raise ValueError(f"LUKS {source} is closed")

    try:
        fh.seek(0, io.SEEK_CUR)
    except (OSError, ValueError) as exc:
        raise ValueError(f"LUKS {source} must be a readable, seekable file-like object") from exc


def _check_header_range(keyslot_id: int, offset: int, length: int, size: int, label: str) -> None:
    """Validate that a keyslot area completely fits inside the header source."""
    if offset < 0 or length < 0:
        raise ValueError(f"Invalid keyslot {keyslot_id} area in {label}")

    if offset + length > size:
        raise EOFError(
            f"Truncated LUKS {label}: keyslot {keyslot_id} area "
            f"({offset:#x}+{length:#x}) extends beyond the {size:#x} byte header source"
        )


def derive_passphrase_key(passphrase: bytes, keyslot: Keyslot) -> bytes:
    """Derive a key from a passphrase with the given keyslot KDF information.

    Args:
        passphrase: The passphrase to derive a key from.
        keyslot: The keyslot to use for the derivation.
    """
    kdf = keyslot.kdf

    if kdf.type == "pbkdf2":
        return hashlib.pbkdf2_hmac(kdf.hash, passphrase, kdf.salt, kdf.iterations, keyslot.key_size)

    if kdf.type.startswith("argon2"):
        return argon2.hash_secret_raw(passphrase, kdf.salt, kdf.time, kdf.memory, kdf.cpus, keyslot.key_size, kdf.type)

    raise NotImplementedError(f"Unsupported kdf algorithm: {kdf.type}")


def find_luks_headers(fh: BinaryIO) -> tuple[int | None, int | None, int | None]:
    stored_position = fh.tell()

    fh.seek(0)
    first_header = None
    second_header = None
    version = None

    if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_1ST:
        first_header = 0
        version = int.from_bytes(fh.read(2), "big")

    for offset in SECONDARY_HEADER_OFFSETS:
        fh.seek(offset)
        if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_2ND:
            second_header = offset
            version = int.from_bytes(fh.read(2), "big")
            break

    fh.seek(stored_position)
    return first_header, second_header, version


def is_luks_volume(fh: BinaryIO) -> bool:
    """Return whether the file-like object is a LUKS volume."""
    _, _, version = find_luks_headers(fh)
    return version is not None
