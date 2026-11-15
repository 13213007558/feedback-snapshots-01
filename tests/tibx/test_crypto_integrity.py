"""Integrity guarantees of an encrypted TIBX archive -- regression tests.

These tests pin down, per crypto layer, what is and is not authenticated, using only
self-built keys and small hand-crafted payloads. The point is that most of the pipeline
is *not* authenticated:

* the password-wrapped data key is plain AES-CBC + PKCS#7, with no MAC -- a tampered wrap
  can keep valid padding and still parse to a length-correct key;
* CBC data segments (alg 1-3) carry no tag, so altered ciphertext decrypts -- downstream
  codec/length checks are damage detection, not authentication, and a stored segment can be
  silently wrong;
* only GCM data segments (alg 5-7) carry an AES-GCM tag that binds the bytes to the key.

Positive cases assert the exact plaintext bytes; negative cases assert a raised error (never
an empty or partial read that could masquerade as success). End-to-end cases go through the
public :class:`~dissect.archive.tibx.tibx.TIBX` read entry and check that the error names the
damaged segment's page.
"""

from __future__ import annotations

import io

import pytest

from dissect.archive.tibx.c_tibx import SEGMENT_GCM_HEADER_SIZE, c_tibx
from dissect.archive.tibx.crypto import DataKey, decrypt_segment, unwrap_data_key
from dissect.archive.tibx.exception import CorruptArchiveError, InvalidPasswordError
from dissect.archive.tibx.lsm import read_archive_header
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    PAGE,
    SEGMENT_HEADER_OFFSET,
    SEGMENT_PAYLOAD_OFFSET,
    Cell,
    ExtentSpec,
    arch_header_page,
    build_lsm_archive,
    finalize,
    lsb,
    wrap_data_key,
)

PASSWORD = b"dissect"
DATA_KEY = bytes(range(32))
# Small, distinctive content: 60 bytes so the NONE segment is not block-aligned and the
# CBC path really exercises PKCS#7 rather than a whole-block edge case.
CONTENT = b"integrity-checked payload, every single byte must come back!"
assert len(CONTENT) == 60  # not block-aligned, so the CBC path really exercises PKCS#7

# The single DATA segment of every build_lsm_archive here sits right after the ARCH page.
SEGMENT_PAGE = 1


def _header(archive: bytes):
    return read_archive_header(PageStore(io.BytesIO(archive)))


def _rebuild_keymap(base: bytes, keymap_blob: bytes) -> bytes:
    """``base`` with its TLV[7] keymap mem-tree replaced by ``keymap_blob`` (CRC re-stamped)."""
    header = _header(base)
    keymap = lsb(0, 0, memtree_cells=[Cell(b"", b"")], memtree_blob=keymap_blob, memtree_encoding=0)
    slots = {i: header.tlv[i].payload for i in (1, 2)}
    slots[7] = keymap
    return arch_header_page(slots) + base[PAGE:]


def _segment_payload_offset(arc: bytes | bytearray, in_payload: int) -> int:
    """Archive byte offset of byte ``in_payload`` of the segment on the first DATA page."""
    return PAGE + SEGMENT_PAYLOAD_OFFSET + in_payload


def _flip(arc: bytes, offset: int) -> bytes:
    damaged = bytearray(arc)
    damaged[offset] ^= 0x01
    return bytes(damaged)


def _read_public(archive: bytes, password: bytes | None = PASSWORD) -> bytes:
    """The public read entry: unlock (when given a password) then read the whole stream."""
    tibx = TIBX(io.BytesIO(archive))
    if password is not None:
        tibx.unlock(password)
    return tibx.streams()[0].read(0, len(CONTENT))


# --------------------------------------------------------------------------- #
# Layer 1: the password-wrapped data key -- no MAC, padding/length are the gate
# --------------------------------------------------------------------------- #


def test_wrapped_key_roundtrip_recovers_exact_key_bytes() -> None:
    # Positive case: the unwrapped key must be byte-for-byte the key the segments use.
    archive = build_lsm_archive([ExtentSpec(10, 0, CONTENT)], password=PASSWORD)
    data_key = unwrap_data_key(_header(archive), PASSWORD)
    assert data_key == DataKey(alg=3, key=DATA_KEY)


def test_wrong_password_is_rejected_not_silently_misread() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, CONTENT)], password=PASSWORD)
    with pytest.raises(InvalidPasswordError):
        unwrap_data_key(_header(archive), b"not the password")


def test_tampered_wrapped_key_with_valid_padding_yields_a_wrong_key() -> None:
    # The wrap has no MAC. Flipping a byte in the *first* ciphertext block garbles the first
    # plaintext block but leaves the last block's PKCS#7 pad untouched, so the tampered blob
    # still unwraps -- to a different, length-correct key. A correct password and a valid pad
    # therefore do not authenticate the keymap; this pins that boundary so nobody later treats
    # a successful unwrap as integrity verification.
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    salt = bytes(range(16))
    kek = PBKDF2(PASSWORD, salt, dkLen=32, count=1 << 12, hmac_hash_module=SHA256)
    wrapped = AES.new(kek, AES.MODE_CBC, b"\x00" * 16).encrypt(DATA_KEY + bytes([16]) * 16)
    header = c_tibx.wrapped_key(format=1, alg=3, iter_log2=12, _reserved=0, salt=salt).dumps()
    blob = bytearray(b"\x00\x00" + header + wrapped)

    from dissect.archive.tibx.crypto import _try_unwrap

    assert _try_unwrap(bytes(blob), 2, PASSWORD) == DataKey(3, DATA_KEY)
    blob[2 + 20] ^= 0x01  # first byte of wrapped ciphertext: padding block stays intact
    tampered_key = _try_unwrap(bytes(blob), 2, PASSWORD)
    assert tampered_key is not None
    assert tampered_key.key != DATA_KEY
    assert len(tampered_key.key) == 32  # accepted purely on pad + declared key length


def test_tampered_wrapped_key_breaking_padding_is_rejected() -> None:
    # The more usual outcome of keymap damage -- the last block's pad no longer validates --
    # is an explicit InvalidPasswordError, never a returned key.
    base = build_lsm_archive([ExtentSpec(10, 0, CONTENT)], password=PASSWORD)
    blob = bytearray(_header(base).tree(7).memtree_payload)
    blob[-1] ^= 0x01  # last wrapped byte: last decrypted block, where the PKCS#7 pad lives
    archive = _rebuild_keymap(base, bytes(blob))

    with pytest.raises(InvalidPasswordError):
        unwrap_data_key(_header(archive), PASSWORD)


def test_keymap_with_two_key_shaped_candidates_picks_the_password_one() -> None:
    # Two structurally valid password-wrapped blobs in one keymap: a decoy under another
    # password and the real one. Detection stays true, the scan must not settle for the decoy,
    # the decoy's password must not unlock anything, and the real key still reads exact bytes.
    decoy_key = bytes(range(100, 132))
    base = build_lsm_archive([ExtentSpec(10, 0, CONTENT)], password=PASSWORD)
    keymap_blob = wrap_data_key(decoy_key, b"other-password", alg=3) + wrap_data_key(
        DATA_KEY, PASSWORD, alg=3
    )
    archive = _rebuild_keymap(base, keymap_blob)

    header = _header(archive)
    assert TIBX(io.BytesIO(archive)).password_protected
    assert unwrap_data_key(header, PASSWORD).key == DATA_KEY
    with pytest.raises(InvalidPasswordError):
        unwrap_data_key(header, b"other-password")
    assert _read_public(archive) == CONTENT


# --------------------------------------------------------------------------- #
# Layer 2: CBC data segments -- confidentiality without authentication
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("alg", [1, 2, 3], ids=["aes128", "aes192", "aes256"])
def test_cbc_segment_roundtrip_returns_exact_plaintext(alg: int) -> None:
    # Positive case at the unit boundary: decrypt reproduces the stored bytes and the
    # caller's PKCS#7 strip leaves exactly the plaintext.
    from Crypto.Cipher import AES

    key = bytes(range(16 if alg == 1 else 24 if alg == 2 else 32))
    iv = bytes(range(16))
    pad = 16 - len(CONTENT) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(CONTENT + bytes([pad]) * pad)
    payload = iv + ciphertext

    decrypted = decrypt_segment(payload, DataKey(alg, key))
    assert decrypted[: len(CONTENT)] == CONTENT
    assert decrypted.endswith(bytes([pad]) * pad)  # padding is the caller's job, not a check


def test_cbc_tampered_ciphertext_with_valid_padding_is_not_authenticated() -> None:
    # The decisive CBC case, through the public read entry: flip a ciphertext byte in the
    # first block of a *stored* segment. The last block's PKCS#7 pad stays valid, so the
    # crypto layer raises nothing and the read returns the same number of bytes -- with the
    # first block garbled. This is the guarantee boundary in its plainest form: a successful
    # decrypt and a correct length do not authenticate CBC content, so readers must not treat
    # them as one. The test pins that the wrong bytes (not an error, and not b"") come back.
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=3
    )
    damaged = _flip(archive, _segment_payload_offset(archive, 16))  # skip the 16-byte IV

    out = _read_public(damaged)
    assert len(out) == len(CONTENT)  # no truncation, no empty-content masquerade
    assert out != CONTENT  # the damage is silently delivered
    # CBC locality: the flip corrupts its own plaintext block wholesale and XORs into the
    # next block's same-offset byte -- nothing beyond those two blocks, and no error raised.
    assert out[32:] == CONTENT[32:]


def test_cbc_silent_bitflip_returns_wrong_bytes_not_empty_ones() -> None:
    # Same flip, demonstrated at the crypto boundary: CBC hands back garbled plaintext with no
    # error and a still-valid pad. The read must not hide this by swallowing the failure and
    # returning b"" -- it returns the wrong bytes, which is exactly why CBC is unauthenticated.
    from Crypto.Cipher import AES

    iv = bytes(range(16))
    pad = 16 - len(CONTENT) % 16
    ciphertext = AES.new(DATA_KEY, AES.MODE_CBC, iv).encrypt(CONTENT + bytes([pad]) * pad)
    payload = bytearray(iv + ciphertext)
    payload[16] ^= 0x01

    out = decrypt_segment(bytes(payload), DataKey(3, DATA_KEY))
    assert out != CONTENT + bytes([pad]) * pad  # content changed...
    assert out[-pad:] == bytes([pad]) * pad  # ...while the padding still validates
    assert len(out) == len(CONTENT) + pad  # nothing was truncated or emptied


def test_cbc_compressed_tamper_fails_as_codec_error_not_authentication() -> None:
    # With a real codec, garbled plaintext normally fails to decompress. That is a codec
    # error catching damage, not the cipher authenticating it: the message must not claim
    # authentication and must locate the segment through the public read entry.
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.ZSTD, password=PASSWORD, alg=3
    )
    damaged = _flip(archive, _segment_payload_offset(archive, 16))

    with pytest.raises(CorruptArchiveError) as exc_info:
        _read_public(damaged)
    message = str(exc_info.value).lower()
    assert "authentication" not in message
    assert "zstd" in message or f"page {SEGMENT_PAGE}" in message


def test_cbc_truncated_segment_payload_is_rejected_and_located() -> None:
    # A truncated encrypted segment (header zlength shortened into the ciphertext) must not
    # decrypt a partial block and pass it off as the segment. CBC drops the trailing
    # sub-block silently at the cipher boundary, so the stored length check has to catch it.
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=3
    )
    damaged = bytearray(archive)
    page = bytearray(damaged[PAGE : 2 * PAGE])
    header = c_tibx.segment_header(bytes(page[SEGMENT_HEADER_OFFSET:]))
    header.zlength -= 8  # cut half a block off the ciphertext
    page[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    damaged = damaged[:PAGE] + finalize(page) + damaged[2 * PAGE :]

    with pytest.raises(CorruptArchiveError, match=f"page {SEGMENT_PAGE}"):
        _read_public(bytes(damaged))


# --------------------------------------------------------------------------- #
# Layer 3: GCM data segments -- authenticated encryption
# --------------------------------------------------------------------------- #


def test_gcm_segment_roundtrip_returns_exact_plaintext() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, CONTENT)], password=PASSWORD, alg=7)
    assert _read_public(archive) == CONTENT


def test_gcm_tampered_tag_is_rejected_and_located_via_public_entry() -> None:
    # Flip a tag byte: the tag covers the ciphertext, so verification fails before any
    # plaintext is returned. The error must name the damaged segment, and no read of the
    # stream can succeed (the segment is never cached as plaintext).
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=7
    )
    damaged = _flip(archive, _segment_payload_offset(archive, 16))  # IV(16) then tag[0]

    with pytest.raises(CorruptArchiveError) as exc_info:
        _read_public(damaged)
    message = str(exc_info.value)
    assert "AES-GCM authentication" in message
    assert f"page {SEGMENT_PAGE}" in message  # located to the damaged segment


def test_gcm_tampered_ciphertext_is_rejected() -> None:
    # A flipped ciphertext byte invalidates the tag just as a tag flip does.
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=7
    )
    damaged = _flip(archive, _segment_payload_offset(archive, SEGMENT_GCM_HEADER_SIZE))

    with pytest.raises(CorruptArchiveError, match="AES-GCM authentication"):
        _read_public(damaged)


def test_gcm_truncated_segment_is_an_authentication_failure() -> None:
    # Shortening zlength drops tag-protected ciphertext bytes: the tag no longer matches, so
    # this is an authentication failure -- unlike CBC, truncation cannot silently shrink data.
    archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=7
    )
    damaged = bytearray(archive)
    page = bytearray(damaged[PAGE : 2 * PAGE])
    header = c_tibx.segment_header(bytes(page[SEGMENT_HEADER_OFFSET:]))
    header.zlength -= 4
    page[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    damaged = damaged[:PAGE] + finalize(page) + damaged[2 * PAGE :]

    with pytest.raises(CorruptArchiveError) as exc_info:
        _read_public(bytes(damaged))
    message = str(exc_info.value)
    assert "AES-GCM authentication" in message
    assert f"page {SEGMENT_PAGE}" in message


def test_gcm_payload_shorter_than_its_header_is_rejected() -> None:
    # Framing-level truncation (not enough bytes for IV+tag) is a corruption error naming the
    # segment, distinct from a tag mismatch, and never an empty plaintext.
    from Crypto.Cipher import AES

    iv = bytes(range(16))
    ciphertext, tag = AES.new(DATA_KEY, AES.MODE_GCM, nonce=iv).encrypt_and_digest(CONTENT)
    payload = iv + tag + ciphertext

    with pytest.raises(CorruptArchiveError, match="payload too short"):
        decrypt_segment(payload[: SEGMENT_GCM_HEADER_SIZE - 1], DataKey(7, DATA_KEY))


def test_failure_is_not_swallowed_into_empty_content() -> None:
    # Cross-cutting guard: neither a GCM tag failure nor a CBC codec failure may be turned
    # into an empty/silent read. The public entry raises for both, on both ciphers.
    gcm_archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.NONE, password=PASSWORD, alg=7
    )
    gcm_damaged = _flip(gcm_archive, _segment_payload_offset(gcm_archive, 16))
    with pytest.raises(CorruptArchiveError):
        _read_public(gcm_damaged)

    cbc_archive = build_lsm_archive(
        [ExtentSpec(10, 0, CONTENT)], compression=c_tibx.ComprAlg.ZSTD, password=PASSWORD, alg=3
    )
    cbc_damaged = _flip(cbc_archive, _segment_payload_offset(cbc_archive, 16))
    with pytest.raises(CorruptArchiveError):
        _read_public(cbc_damaged)
