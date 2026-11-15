"""Integrity guarantees of TIBX encrypted reads, layer by layer.

Every archive and key here is synthetic and self-made: the password-wrapped data key in
the keymap, AES-CBC data segments and AES-GCM data segments. Page envelopes carry their
format CRC-32C, but that is not a MAC and the read path does not check it, so no test here
treats a CRC-valid modified page as evidence of integrity.

The tests pin what each layer actually promises:

* the password wrap is confidentiality-only -- no MAC; acceptance is PKCS#7 padding and
  key length after an AES-CBC unwrap,
* CBC segments are confidentiality-only -- the IV is unauthenticated and PKCS#7 padding is
  only a framing check,
* GCM segments are authenticated -- the tag covers the IV and ciphertext,
* a truncated encrypted segment fails visibly.

Positives assert the exact plaintext bytes. Negatives assert a specific exception at the
public read entry, naming the segment and its page; none accepts an empty or zero-filled
result in place of an error.
"""

from __future__ import annotations

import io
import random
import sys
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from dissect.archive.tibx.c_tibx import (
    ENVELOPE_SIZE,
    SEGMENT_HEADER_OFFSET,
    SEGMENT_PAYLOAD_OFFSET,
    TLV_KEYMAP,
    WRAPPED_KEY_HEADER_SIZE,
    c_tibx,
)
from dissect.archive.tibx.crypto import (
    DataKey,
    _blob_is_well_formed,
    _keymap_blob,
    _pkcs7_unpad,
    _scan_offsets,
    decrypt_segment,
    has_password_wrapped_key,
    unwrap_data_key,
)
from dissect.archive.tibx.exception import CorruptArchiveError, InvalidPasswordError
from dissect.archive.tibx.lsm import LsmSuperBlock, iter_memtree_cells, read_archive_header
from dissect.archive.tibx.map import load_segment_index
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import Segment, read_compressed
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    PAGE,
    Cell,
    ExtentSpec,
    arch_header_page,
    blank_page,
    build_lsm_archive,
    finalize,
    lsb,
    variable_cells,
)

if TYPE_CHECKING:
    from dissect.archive.tibx.lsm import ArchiveHeader

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

PASSWORD = b"self-made-password"
DATA_KEY = bytes(range(32))  # what the genuine keymap wraps
OTHER_KEY = bytes([0x5A]) * 32  # a structurally valid but different key
VOLUME_ID = 10

CBC_ALG = 3  # AES-256-CBC segment cipher
GCM_ALG = 7  # AES-256-GCM segment cipher
CBC_HEADER = len(c_tibx.segment_cbc_header)
GCM_HEADER = len(c_tibx.segment_gcm_header)


class SegmentLocation(NamedTuple):
    """Where one segment lives, per the segment_map."""

    segment_id: int
    page: int
    page_count: int


def _open(archive: bytes) -> TIBX:
    return TIBX(io.BytesIO(archive))


def _header(archive: bytes) -> ArchiveHeader:
    return read_archive_header(PageStore(io.BytesIO(archive)))


def _location(archive: bytes) -> SegmentLocation:
    store = PageStore(io.BytesIO(archive))
    index = load_segment_index(store, read_archive_header(store))
    segment_id = next(iter(index))
    locator = index[segment_id]
    return SegmentLocation(segment_id, locator.page_offset, locator.page_count)


def _segment(archive: bytes) -> Segment:
    """The parsed header of the archive's one segment."""
    location = _location(archive)
    store = PageStore(io.BytesIO(archive))
    return Segment(store.read_run(location.page, 1)[0], location.page)


def _flip(archive: bytes, offset: int, xor: int = 0xFF) -> bytes:
    """``archive`` with payload ``offset`` (from the segment payload's start) XORed."""
    data = bytearray(archive)
    base = _location(archive).page * PAGE + SEGMENT_PAYLOAD_OFFSET
    data[base + offset] ^= xor
    return bytes(data)


def _rewrite_segment_header(archive: bytes, **fields: Any) -> bytes:
    """``archive`` with the segment header fields replaced and the page CRC repaired."""
    location = _location(archive)
    data = bytearray(archive)
    start = location.page * PAGE
    page = bytearray(data[start : start + PAGE])
    header = c_tibx.segment_header(bytes(page[SEGMENT_HEADER_OFFSET:]))
    for name, value in fields.items():
        setattr(header, name, value)
    page[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    data[start : start + PAGE] = finalize(page)
    return bytes(data)


def _install_cbc_segment(
    archive: bytes, plaintext: bytes, *, compression: c_tibx.ComprAlg, length: int | None = None
) -> bytes:
    """``archive``'s one segment replaced by a CBC segment of ``plaintext``, padding valid.

    The segment is re-framed exactly as the format frames one (header page plus as many
    continuation pages as the ciphertext needs), with every page CRC-valid: everything a
    reader can check -- framing, padding and codec output -- agrees.
    """
    location = _location(archive)
    iv = bytes(range(16))
    pad = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad]) * pad
    ciphertext = AES.new(DATA_KEY, AES.MODE_CBC, iv).encrypt(padded)
    blob = c_tibx.segment_cbc_header(iv=iv).dumps() + ciphertext

    page = bytearray(blank_page(c_tibx.PageType.DATA))
    header = c_tibx.segment_header(
        magic=b"SE",
        version=0,
        length=len(plaintext) if length is None else length,
        zlength=len(blob),
        key_id=1,
        compression=compression,
        cache_level=0,
    )
    page[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    take = min(len(blob), PAGE - SEGMENT_PAYLOAD_OFFSET)
    page[SEGMENT_PAYLOAD_OFFSET : SEGMENT_PAYLOAD_OFFSET + take] = blob[:take]
    pages = [finalize(page)]

    position = take
    while position < len(blob):
        continuation = bytearray(blank_page(c_tibx.PageType.DATA))
        chunk = blob[position : position + PAGE - ENVELOPE_SIZE]
        continuation[ENVELOPE_SIZE : ENVELOPE_SIZE + len(chunk)] = chunk
        pages.append(finalize(continuation))
        position += len(chunk)

    start = location.page * PAGE
    end = (location.page + location.page_count) * PAGE
    return archive[:start] + b"".join(pages) + archive[end:]


def _wrap(key: bytes, salt: bytes, *, iter_log2: int = 10, alg: int = CBC_ALG, password: bytes = PASSWORD) -> bytes:
    """One password-wrapped key blob: header || AES-256-CBC(PKCS#7 padded key)."""
    kek = PBKDF2(password, salt, dkLen=32, count=1 << iter_log2, hmac_hash_module=SHA256)
    pad = 16 - len(key) % 16
    padded = key + bytes([pad]) * pad
    wrapped = AES.new(kek, AES.MODE_CBC, b"\x00" * 16).encrypt(padded)
    return c_tibx.wrapped_key(format=1, alg=alg, iter_log2=iter_log2, _reserved=0, salt=salt).dumps() + wrapped


def _rebuild_with_keymap(base: bytes, keymap_blob: bytes) -> bytes:
    """``base`` with its TLV[7] keymap mem-tree replaced by ``keymap_blob``."""
    header = _header(base)
    keymap = lsb(0, 0, memtree_cells=[Cell(b"", b"")], memtree_blob=keymap_blob, memtree_encoding=0)
    slots = {index: header.tlv[index].payload for index in (1, 2)}
    slots[TLV_KEYMAP] = keymap
    return arch_header_page(slots) + base[PAGE:]


def _variable_cells(cells: list[Cell]) -> bytes:
    """The compact cell stream of the builder's variable-length encoding."""
    return variable_cells(cells)


def _valid_candidates(blob: bytes) -> list[int]:
    """Offsets at which a password-wrapped key parses structurally -- no password involved."""
    return [offset for offset in _scan_offsets(blob) if blob[offset] == 1 and _blob_is_well_formed(blob, offset)]


# --- The password-wrapped key ------------------------------------------------


def test_password_wrap_roundtrip_yields_the_exact_key() -> None:
    archive = build_lsm_archive([ExtentSpec(VOLUME_ID, 0, b"x" * 64)], password=PASSWORD, alg=CBC_ALG)

    data_key = unwrap_data_key(_header(archive), PASSWORD)

    assert data_key.alg == CBC_ALG
    assert data_key.key == DATA_KEY
    assert not data_key.gcm


def test_keymap_with_multiple_key_like_candidates_finds_the_real_one() -> None:
    # Two complete candidates: same format byte, known algorithm, plausible iteration
    # exponent, non-empty AES-block-multiple wrapped key. Only the genuine one decrypts
    # to its algorithm's key length with valid PKCS#7, so the scanner must not stop at the
    # first structurally valid blob.
    base = build_lsm_archive([ExtentSpec(VOLUME_ID, 0, b"A" * 64)], password=PASSWORD, alg=CBC_ALG)
    decoy_header = _wrap(OTHER_KEY, b"\x00" * 16)[:WRAPPED_KEY_HEADER_SIZE]
    genuine = _wrap(DATA_KEY, bytes(range(100, 116)))
    blob = b"\x00\x00" + decoy_header + b"\x00" * 12 + genuine

    assert _valid_candidates(blob) == [2, 34]

    archive = _rebuild_with_keymap(base, blob)
    assert _valid_candidates(_keymap_blob(_header(archive))) == [2, 34]

    data_key = unwrap_data_key(_header(archive), PASSWORD)
    assert data_key.key == DATA_KEY

    tibx = _open(archive)
    assert tibx.password_protected
    tibx.unlock(PASSWORD)
    assert tibx.streams()[0].read(0, 64) == b"A" * 64


def test_modified_wrapped_key_is_accepted_without_authentication() -> None:
    # The wrap has no MAC. Replacing its ciphertext with a blob that wraps a different
    # key leaves every check the format makes satisfied, and the replacement is returned
    # as "the" key. Key recovery therefore proves nothing about the blob's integrity.
    base = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, b"A" * 64)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    blob = _header(base).tree(TLV_KEYMAP).memtree_payload
    offset = _valid_candidates(blob)[0]
    header = c_tibx.wrapped_key(blob[offset:])
    salt = bytes(header.salt)

    # Keep the genuine header and salt; swap only the wrapped bytes.
    replacement = _wrap(OTHER_KEY, salt, iter_log2=header.iter_log2)[WRAPPED_KEY_HEADER_SIZE:]
    modified = blob[: offset + WRAPPED_KEY_HEADER_SIZE] + replacement
    assert len(modified) == len(blob)  # same shape, still parsable

    archive = _rebuild_with_keymap(base, modified)
    assert has_password_wrapped_key(_header(archive))

    recovered = unwrap_data_key(_header(archive), PASSWORD)
    assert recovered.key == OTHER_KEY  # accepted, not rejected: no authentication

    # And with CBC the segment read happily returns the plaintext under that other key.
    tibx = _open(archive)
    tibx.unlock(PASSWORD)
    out = tibx.streams()[0].read(0, 64)
    assert len(out) == 64
    assert out != b""
    assert out != b"A" * 64


def test_modified_wrapped_key_then_gcm_still_rejects_the_segments() -> None:
    # The wrap is accepted without authentication, but the GCM data it claims to unlock is
    # authenticated: substituting the wrapped key yields a key that cannot open the data,
    # and the public read says so instead of returning altered plaintext.
    base = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, b"A" * 64)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    blob = _header(base).tree(TLV_KEYMAP).memtree_payload
    offset = _valid_candidates(blob)[0]
    header = c_tibx.wrapped_key(blob[offset:])
    salt = bytes(header.salt)

    modified = (
        blob[: offset + WRAPPED_KEY_HEADER_SIZE]
        + _wrap(OTHER_KEY, salt, iter_log2=header.iter_log2)[WRAPPED_KEY_HEADER_SIZE:]
    )
    archive = _rebuild_with_keymap(base, modified)
    assert unwrap_data_key(_header(archive), PASSWORD).key == OTHER_KEY

    location = _location(archive)
    tibx = _open(archive)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: segment failed AES-GCM authentication",
    ):
        tibx.read_segment(location.segment_id)


def test_wrong_password_is_an_invalid_password_not_an_integrity_error() -> None:
    archive = build_lsm_archive([ExtentSpec(VOLUME_ID, 0, b"A" * 64)], password=PASSWORD, alg=CBC_ALG)
    with pytest.raises(InvalidPasswordError, match="wrong password"):
        unwrap_data_key(_header(archive), b"not-the-password")


def test_pkcs7_unpad_is_a_framing_check_only() -> None:
    # A one-bit change that leaves a valid padding byte pattern is accepted by the unpad:
    # padding validity is not a MAC.
    valid = b"K" * 15 + bytes([1])
    modified = b"K" * 14 + b"L" + bytes([1])
    assert _pkcs7_unpad(valid) == b"K" * 15
    assert _pkcs7_unpad(modified) == b"K" * 14 + b"L"
    assert len(valid) % 16 == len(modified) % 16 == 0


# --- AES-CBC data segments ----------------------------------------------------


@pytest.mark.parametrize(
    ("compression", "algorithm"),
    [
        (c_tibx.ComprAlg.NONE, CBC_ALG),
        (c_tibx.ComprAlg.ZSTD, CBC_ALG),
        (c_tibx.ComprAlg.NONE, GCM_ALG),
        (c_tibx.ComprAlg.ZSTD, GCM_ALG),
    ],
    ids=["cbc-stored", "cbc-zstd", "gcm-stored", "gcm-zstd"],
)
def test_encrypted_roundtrip_returns_exact_plaintext(compression: c_tibx.ComprAlg, algorithm: int) -> None:
    content = b"self-made secret bytes, one small segment 0123456789" * 3
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=compression, password=PASSWORD, alg=algorithm
    )

    tibx = _open(archive)
    assert tibx.encrypted
    tibx.unlock(PASSWORD)
    assert tibx.streams()[0].read(0, len(content)) == content
    assert tibx.read_segment(_location(archive).segment_id) == content


def test_cbc_modified_iv_changes_the_first_block_only() -> None:
    # The CBC IV is not authenticated. Flipping it changes the first plaintext block and
    # leaves the rest -- including the padding -- intact, so the segment still reads.
    content = b"R" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    tampered = _flip(archive, 5)  # inside the 16-byte IV

    tibx = _open(tampered)
    tibx.unlock(PASSWORD)
    out = tibx.streams()[0].read(0, len(content))

    assert len(out) == len(content)
    assert out != content
    assert out[16:] == content[16:]  # only the first plaintext block changed


def test_cbc_valid_padding_does_not_authenticate_modified_content() -> None:
    # Changing a non-final ciphertext block leaves the final padding block untouched, so
    # PKCS#7 stays valid and the stored plaintext keeps its declared length. The altered
    # bytes are returned as data: padding correctness is not authentication.
    content = b"C" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    tampered = _flip(archive, CBC_HEADER + 5)  # first ciphertext block

    tibx = _open(tampered)
    tibx.unlock(PASSWORD)
    out = tibx.streams()[0].read(0, len(content))

    assert len(out) == len(content)  # not an empty or short "success"
    assert out != content
    assert out != b""
    # The untouched final block still carries the original bytes and valid padding.
    assert out[-16:] == b"C" * 16


def test_cbc_fabricated_plaintext_with_valid_padding_is_returned() -> None:
    # A whole segment can be re-framed by someone who knows the key. The page is
    # CRC-valid, the padding is PKCS#7-correct, the header's length matches, and the read
    # succeeds with the fabricated bytes. Every CBC "check" passes; none authenticates.
    original = b"L" * 4830  # 3 pages: forces a real continuation layout
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, original)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    fabricated = random.Random(1).randbytes(len(original))
    forged = _install_cbc_segment(archive, fabricated, compression=c_tibx.ComprAlg.NONE, length=len(original))

    tibx = _open(forged)
    tibx.unlock(PASSWORD)
    out = tibx.streams()[0].read(0, len(original))
    assert out == fabricated


def test_cbc_valid_padding_over_zstd_frame_is_returned() -> None:
    # The same holds when the codec is real: a valid zstd frame of different content,
    # encrypted with valid CBC padding, decompresses successfully to the altered bytes.
    original = b"M" * 4096
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, original)], compression=c_tibx.ComprAlg.ZSTD, password=PASSWORD, alg=CBC_ALG
    )
    altered = zstd.compress(b"N" * 4096)
    forged = _install_cbc_segment(archive, altered, compression=c_tibx.ComprAlg.ZSTD, length=4096)

    tibx = _open(forged)
    tibx.unlock(PASSWORD)
    assert tibx.streams()[0].read(0, 4096) == b"N" * 4096


# --- Encrypted LSM cell streams -----------------------------------------------


def test_encrypted_lsm_stream_inherits_the_segment_cipher_guarantees() -> None:
    # LSM cell streams are framed exactly like SE segments (same decrypt_segment), so they
    # inherit the archive cipher's guarantees: GCM rejects tampering, CBC does not.
    cells = [Cell(b"key", b"value")]
    blob = _variable_cells(cells)

    def framed(alg: int, ciphertext: bytes, cell_list: list[Cell], iv: bytes, tag: bytes = b"") -> bytes:
        header = c_tibx.segment_gcm_header(iv=iv, tag=tag) if alg == GCM_ALG else c_tibx.segment_cbc_header(iv=iv)
        return lsb(0, 0, memtree_cells=cell_list, memtree_blob=header.dumps() + ciphertext, memtree_encoding=0x80)

    # GCM: every modified component is rejected.
    iv = bytes(range(16))
    ciphertext, tag = AES.new(DATA_KEY, AES.MODE_GCM, nonce=iv).encrypt_and_digest(blob)
    superblock = LsmSuperBlock(framed(GCM_ALG, ciphertext, cells, iv, tag), tlv_index=0)
    assert [(cell.key, cell.value) for cell in iter_memtree_cells(superblock, DataKey(alg=GCM_ALG, key=DATA_KEY))] == [
        (b"key", b"value")
    ]

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0xFF
    with pytest.raises(CorruptArchiveError, match="AES-GCM authentication"):
        iter_memtree_cells(
            LsmSuperBlock(framed(GCM_ALG, ciphertext, cells, iv, bytes(bad_tag)), tlv_index=0),
            DataKey(alg=GCM_ALG, key=DATA_KEY),
        )

    # CBC: a modified cell stream that still frames and pads validly is decoded rather
    # than rejected. The LSM layer adds no authentication of its own.
    iv = bytes(range(16))
    altered_cells = [Cell(b"other", b"value")]
    altered = _variable_cells(altered_cells)
    pad = 16 - len(altered) % 16
    cbc = AES.new(DATA_KEY, AES.MODE_CBC, iv).encrypt(altered + bytes([pad]) * pad)
    superblock = LsmSuperBlock(framed(CBC_ALG, cbc, altered_cells, iv), tlv_index=0)
    decoded = iter_memtree_cells(superblock, DataKey(alg=CBC_ALG, key=DATA_KEY))
    assert [cell.key for cell in decoded] == [b"other"]  # altered data, not an error


def test_public_read_error_names_the_segment_and_keeps_the_cause() -> None:
    # Errors from the segment layer speak of pages; a public read must say which segment
    # they belong to, and keep the original failure chained rather than replacing it.
    content = b"S" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    truncated = _rewrite_segment_header(archive, zlength=_segment(archive).zlength - 32)
    location = _location(truncated)

    tibx = _open(truncated)
    tibx.unlock(PASSWORD)
    with pytest.raises(CorruptArchiveError) as excinfo:
        tibx.read_segment(location.segment_id)
    message = str(excinfo.value)
    assert message.startswith(f"segment {location.segment_id} at page {location.page}: ")
    assert isinstance(excinfo.value.__cause__, CorruptArchiveError)


def test_cbc_truncated_ciphertext_fails_at_public_read() -> None:
    # Two ciphertext blocks are cut from the header's zlength; the segment decodes short.
    # The public read raises, naming the segment and page -- not a zero-filled result.
    content = b"F" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    truncated = _rewrite_segment_header(archive, zlength=_segment(archive).zlength - 32)
    location = _location(truncated)

    tibx = _open(truncated)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: .*decoded 48 bytes, expected 64",
    ):
        tibx.read_segment(location.segment_id)


# --- AES-GCM data segments ----------------------------------------------------


@pytest.mark.parametrize("field", ["iv", "tag", "ciphertext-first", "ciphertext-last"])
def test_gcm_rejects_every_modified_component(field: str) -> None:
    content = b"G" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    offsets = {"iv": 0, "tag": 16, "ciphertext-first": GCM_HEADER, "ciphertext-last": GCM_HEADER + len(content) - 1}
    offset = offsets[field]
    tampered = _flip(archive, offset)
    location = _location(tampered)

    tibx = _open(tampered)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: segment failed AES-GCM authentication",
    ):
        tibx.read_segment(location.segment_id)


def test_volume_read_propagates_segment_errors_instead_of_zero_filling() -> None:
    # TibxVolume.read zero-fills only genuinely sparse ranges. A damaged encrypted segment
    # must surface as an error, not be padded with zeros to the requested length. Note
    # that this asks only for length and no more: the zero-fill fallbacks are for absent
    # extents, never for a segment that failed to decrypt.
    content = b"T" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=CBC_ALG
    )
    truncated = _rewrite_segment_header(archive, zlength=_segment(archive).zlength - 32)
    location = _location(truncated)

    tibx = _open(truncated)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: ",
    ):
        tibx.streams()[0].read(0, len(content))


def test_gcm_header_truncation_is_a_framing_error_not_success() -> None:
    # Fewer bytes than iv+tag cannot yield plaintext. Through the public read this must
    # be a "too short" error naming the segment, never an empty success.
    content = b"H" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    truncated = _rewrite_segment_header(archive, zlength=GCM_HEADER - 1)
    location = _location(truncated)

    tibx = _open(truncated)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: encrypted segment payload too short: 31 bytes",
    ):
        tibx.read_segment(location.segment_id)


def test_gcm_truncated_ciphertext_fails_authentication() -> None:
    content = b"I" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    truncated = _rewrite_segment_header(archive, zlength=_segment(archive).zlength - 16)
    location = _location(truncated)

    tibx = _open(truncated)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: segment failed AES-GCM authentication",
    ):
        tibx.read_segment(location.segment_id)


# --- Truncated encrypted segments ---------------------------------------------


@pytest.mark.parametrize("algorithm", [CBC_ALG, GCM_ALG], ids=["cbc", "gcm"])
@pytest.mark.parametrize("keep_pages", [1, 2], ids=["header-only", "one-continuation"])
def test_physically_truncated_encrypted_segment_never_returns_bytes(algorithm: int, keep_pages: int) -> None:
    # Incompressible data forces a multi-page segment; cutting the file inside it must
    # raise at the public read, naming the segment and its page.
    content = random.Random(0).randbytes(9000)
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=algorithm
    )
    location = _location(archive)
    assert location.page_count > keep_pages

    cut = archive[: (location.page + keep_pages) * PAGE]
    tibx = _open(cut)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: .*runs off the end of the archive",
    ):
        tibx.read_segment(location.segment_id)


# --- Codec success is not authentication --------------------------------------


def test_gcm_tag_tamper_is_rejected_before_any_plaintext() -> None:
    # Even when the ciphertext is untouched, a modified tag means no plaintext at all --
    # not a short read and not the original bytes.
    content = b"O" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    # The GCM payload is iv||tag||ciphertext; flip a tag byte without touching either other.
    tampered = _flip(archive, 16 + 3)
    location = _location(tampered)

    tibx = _open(tampered)
    tibx.unlock(PASSWORD)
    with pytest.raises(
        CorruptArchiveError,
        match=rf"segment {location.segment_id} at page {location.page}: segment failed AES-GCM authentication",
    ):
        tibx.streams()[0].read(0, len(content))


def test_segment_helper_reports_gcm_tag_failure_without_plaintext() -> None:
    # Directly at the helper, a bad tag yields the authentication error; there is no
    # return value a caller could mistake for an empty plaintext.
    content = b"P" * 64
    archive = build_lsm_archive(
        [ExtentSpec(VOLUME_ID, 0, content)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=GCM_ALG
    )
    data_key = unwrap_data_key(_header(archive), PASSWORD)
    location = _location(archive)
    store = PageStore(io.BytesIO(archive))
    segment = Segment(store.read_run(location.page, 1)[0], location.page)
    payload = read_compressed(store, segment)
    tampered = bytearray(payload)
    tampered[16] ^= 0xFF
    with pytest.raises(CorruptArchiveError, match="AES-GCM authentication"):
        decrypt_segment(bytes(tampered), data_key)
