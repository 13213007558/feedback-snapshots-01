from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING

import pytest

from dissect.fve.luks.luks import LUKS
from tests.luks._layout import HEADER_SIZE, OTHER_PLAINTEXT, PAYLOAD_OFFSET, Layout, build_luks1, build_luks2

if TYPE_CHECKING:
    from pathlib import Path

BUILDERS = [
    pytest.param(build_luks1, id="luks1"),
    pytest.param(build_luks2, id="luks2"),
]


def _read(luks: LUKS) -> bytes:
    stream = luks.open()
    try:
        return stream.read()
    finally:
        stream.close()


def _required_header_size(layout: Layout) -> int:
    """Return the exact number of header bytes needed to hold all keyslot material."""
    parsed = LUKS(io.BytesIO(layout.header))
    return max(
        keyslot.area.offset + keyslot.key_size * keyslot.af.stripes for keyslot in parsed.metadata.keyslots.values()
    )


def _metadata_json(header: bytes) -> str:
    return header[4096:HEADER_SIZE].rstrip(b"\x00").decode()


def _rewrite_metadata(header: bytes, metadata: dict) -> bytes:
    """Rewrite the JSON area and checksum of both LUKS2 headers in a header blob."""
    blob = bytearray(header)

    for header_offset in range(0, HEADER_SIZE * 2, HEADER_SIZE):
        primary = bytearray(blob[header_offset : header_offset + HEADER_SIZE])
        json_area = json.dumps(metadata, separators=(",", ":")).encode()
        primary[4096:HEADER_SIZE] = json_area.ljust(HEADER_SIZE - 4096, b"\x00")
        primary[448:512] = b"\x00" * 64
        checksum = hashlib.sha256(primary).digest()
        primary[448:512] = checksum + b"\x00" * (64 - len(checksum))
        blob[header_offset : header_offset + HEADER_SIZE] = primary

    return bytes(blob)


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_matches_single_file(build: object) -> None:
    """A detached layout must decrypt to the same plaintext as the equivalent single-file layout."""
    layout: Layout = build()

    single = LUKS(io.BytesIO(layout.single))
    single.unlock_with_passphrase(layout.passphrase)
    assert _read(single) == layout.plaintext

    header_fh = io.BytesIO(layout.header)
    data_fh = io.BytesIO(layout.data)
    detached = LUKS(header_fh, data_fh)
    detached.unlock_with_passphrase(layout.passphrase)
    assert _read(detached) == layout.plaintext

    assert not header_fh.closed
    assert not data_fh.closed


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_keyword_header(build: object) -> None:
    """The explicit ``header_fh``/``data_fh`` keyword form must behave identically."""
    layout: Layout = build()

    detached = LUKS(header_fh=io.BytesIO(layout.header), data_fh=io.BytesIO(layout.data))
    detached.unlock_with_passphrase(layout.passphrase)

    assert _read(detached) == layout.plaintext


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_does_not_close_caller_handles(build: object, tmp_path: Path) -> None:
    """Handles owned by the caller must stay open after setup, unlock, reading and validation failures."""
    layout: Layout = build()
    header_path = tmp_path / "header.bin"
    data_path = tmp_path / "data.bin"
    header_path.write_bytes(layout.header)
    data_path.write_bytes(layout.data)

    header_fh = header_path.open("rb")
    data_fh = data_path.open("rb")
    try:
        luks = LUKS(header_fh, data_fh)
        luks.unlock_with_passphrase(layout.passphrase)
        assert _read(luks) == layout.plaintext

        assert not header_fh.closed
        assert not data_fh.closed
    finally:
        header_fh.close()
        data_fh.close()

    # A truncated header must also leave the caller's handles open
    header_fh = tmp_path.joinpath("truncated.bin").open("wb+")
    header_fh.write(layout.header[: _required_header_size(layout) - 1])
    header_fh.seek(0)
    data_fh = data_path.open("rb")
    try:
        with pytest.raises(EOFError):
            LUKS(header_fh, data_fh)
        assert not header_fh.closed
        assert not data_fh.closed
    finally:
        header_fh.close()
        data_fh.close()


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_truncated_header(build: object) -> None:
    """Truncating the header source must be reported against the header source, not the data image."""
    layout: Layout = build()

    header_fh = io.BytesIO(layout.header[: _required_header_size(layout) - 1])
    data_fh = io.BytesIO(layout.data)
    with pytest.raises(EOFError) as exc_info:
        LUKS(header_fh, data_fh)

    message = str(exc_info.value)
    assert "detached header" in message
    assert "data image" not in message

    assert not header_fh.closed
    assert not data_fh.closed


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_truncated_data(build: object) -> None:
    """Truncating the data image must be reported against the data source, not the header."""
    layout: Layout = build()

    header_fh = io.BytesIO(layout.header)
    data_fh = io.BytesIO(layout.data[:-1])
    with pytest.raises(EOFError) as exc_info:
        LUKS(header_fh, data_fh)

    message = str(exc_info.value)
    assert "data image" in message
    assert "detached header" not in message

    assert not header_fh.closed
    assert not data_fh.closed


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_swapped_sources(build: object) -> None:
    """Swapping the header and data sources must be diagnosed against the header source."""
    layout: Layout = build()
    # A detached data image normally has no LUKS header at offset 0
    data_image = bytearray(layout.data)
    data_image[: len(layout.header)] = b"\x00" * len(layout.header)

    header_fh = io.BytesIO(bytes(data_image))
    data_fh = io.BytesIO(layout.header)

    with pytest.raises(ValueError) as exc_info:
        LUKS(header_fh, data_fh)

    assert "detached header" in str(exc_info.value)
    assert not header_fh.closed
    assert not data_fh.closed


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_keyslot_never_read_from_data(build: object) -> None:
    """Key material missing from the header source must not be recovered from the data image."""
    layout: Layout = build()

    # Drop the keyslot area from the header source, but provide a data image that still has the original bytes at
    # the keyslot coordinates. A cross-source read must never stitch these together into usable key material.
    header_fh = io.BytesIO(layout.header[:4096])
    data_fh = io.BytesIO(layout.single)

    with pytest.raises((EOFError, ValueError)):
        LUKS(header_fh, data_fh)

    # Truncate by one byte inside the required keyslot extent
    header_fh = io.BytesIO(layout.header[: _required_header_size(layout) - 1])
    data_fh = io.BytesIO(layout.single)
    with pytest.raises(EOFError) as exc_info:
        LUKS(header_fh, data_fh)

    assert "detached header" in str(exc_info.value)
    assert not header_fh.closed
    assert not data_fh.closed


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_keyslot_material_comes_from_header(build: object) -> None:
    """Key material must be read from the header source even if the data image has other bytes there."""
    layout: Layout = build()

    header_fh = io.BytesIO(layout.header)
    # Destroy the keyslot area in the data image copy of the same coordinates
    data_image = bytearray(layout.data)
    data_image[: len(layout.header)] = b"\xff" * len(layout.header)
    data_fh = io.BytesIO(bytes(data_image))

    luks = LUKS(header_fh, data_fh)
    luks.unlock_with_passphrase(layout.passphrase)

    assert _read(luks) == layout.plaintext


def test_detached_payload_only_data_image() -> None:
    """With a detached header the segment offset is relative to the data image, not the header source."""
    layout: Layout = build_luks2()
    payload = layout.data[PAYLOAD_OFFSET:]

    metadata = json.loads(_metadata_json(layout.header))
    metadata["segments"]["0"]["offset"] = "0"
    header = _rewrite_metadata(layout.header, metadata)

    luks = LUKS(io.BytesIO(header), io.BytesIO(payload))
    luks.unlock_with_passphrase(layout.passphrase)

    assert _read(luks) == layout.plaintext


@pytest.mark.parametrize("build", BUILDERS)
def test_detached_swapped_data_images(build: object) -> None:
    """A data image from another volume must not decrypt to either volume's plaintext.

    LUKS payloads are not authenticated, so the error is visible as garbage output rather than an exception. The
    important part is that the header source still contributes only its own keyslot material and that neither
    volume's plaintext is presented as valid.
    """
    layout: Layout = build()
    other: Layout = build(plaintext=OTHER_PLAINTEXT)
    assert other.volume_key != layout.volume_key

    luks = LUKS(io.BytesIO(layout.header), io.BytesIO(other.data))
    luks.unlock_with_passphrase(layout.passphrase)
    plaintext = _read(luks)

    assert plaintext != layout.plaintext
    assert plaintext != other.plaintext


def test_detached_uses_secondary_header() -> None:
    """A detached header with a damaged primary header must fall back to the secondary header."""
    layout: Layout = build_luks2()

    header = bytearray(layout.header)
    header[:6] = b"\x00" * 6  # wipe the primary magic

    luks = LUKS(io.BytesIO(bytes(header)), io.BytesIO(layout.data))
    luks.unlock_with_passphrase(layout.passphrase)

    assert luks.header is luks.header2
    assert _read(luks) == layout.plaintext


def test_detached_ambiguous_arguments() -> None:
    """Ambiguous source combinations must be rejected before any parsing."""
    layout: Layout = build_luks1()

    with pytest.raises(ValueError, match="header_fh"):
        LUKS(io.BytesIO(layout.header), header_fh=io.BytesIO(layout.header), data_fh=io.BytesIO(layout.data))

    with pytest.raises(ValueError, match="data_fh"):
        LUKS(header_fh=io.BytesIO(layout.header))

    # A single positional handle is the legacy single-file form and must remain accepted
    legacy = LUKS(io.BytesIO(layout.header))
    assert not legacy.detached

    with pytest.raises(ValueError, match="data_fh"):
        LUKS(data_fh=io.BytesIO(layout.data))

    with pytest.raises(ValueError, match="header"):
        LUKS()


def test_detached_rejects_closed_source() -> None:
    """Closed handles must be rejected without being reopened or closed again."""
    layout: Layout = build_luks1()

    header_fh = io.BytesIO(layout.header)
    data_fh = io.BytesIO(layout.data)
    data_fh.close()

    with pytest.raises(ValueError, match="data image"):
        LUKS(header_fh, data_fh)

    assert not header_fh.closed


def test_detached_rejects_non_seekable_source() -> None:
    """Non-seekable sources cannot be used for random access and must be rejected clearly."""
    layout: Layout = build_luks1()

    class NonSeekable(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def readinto(self, buffer: bytearray) -> int:
            return 0

    with pytest.raises(ValueError, match="seekable"):
        LUKS(io.BytesIO(layout.header), NonSeekable())


def test_detached_rejects_keyslot_area_smaller_than_material() -> None:
    """A keyslot that declares less room than its anti-forensic stripes need must be rejected."""
    layout: Layout = build_luks2()
    metadata = json.loads(_metadata_json(layout.header))
    metadata["keyslots"]["0"]["area"]["size"] = "1"

    with pytest.raises(ValueError, match="too small"):
        LUKS(
            io.BytesIO(_rewrite_metadata(layout.header, metadata)),
            io.BytesIO(layout.data),
        )
