from __future__ import annotations

import contextlib
import gzip
import struct
from binascii import crc32
from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.fve.bde import bde, c_bde, is_bde_volume
from dissect.fve.bde.information import KeyDatum
from dissect.fve.bde.key import derive_user_key, stretch
from dissect.fve.exception import InvalidHeaderError, InvalidIntegrityError
from tests._util import absolute_path, open_file, open_file_gz


def _read_gz(name: str) -> bytes:
    with absolute_path(name).open("rb") as fh:
        return gzip.decompress(fh.read())


def _verify_crypto_stream(bde_obj: bde.BDE) -> None:
    stream = bde_obj.open()
    assert stream.read(512)[3:11] == b"NTFS    "

    # 0x2000 is outside the Vista plain text and the default Bitlocker 2 virtualized region
    stream.seek(0x2000)
    assert stream.read(512)[:8] == b"FILE0\x00\x03\x00"


def _verify_passphrase_crypto(test_file: BinaryIO, passphrase: str, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase(passphrase)
    assert bde_obj.unlocked

    assert isinstance(bde_obj._fvek_datum, KeyDatum)
    assert isinstance(bde_obj._fvek, bytes)
    assert isinstance(bde_obj._vmk_datum, KeyDatum)
    assert isinstance(bde_obj._vmk, bytes)

    _verify_crypto_stream(bde_obj)


def _verify_recovery_password_crypto(
    test_file: BinaryIO, recovery_password: str, fvek_type: c_bde.FVE_KEY_TYPE
) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password(recovery_password)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_bek_crypto(test_file: BinaryIO, bek_file: BinaryIO, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_bek()
    bde_obj.unlock_with_bek(bek_file)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_external_key_crypto(test_file: BinaryIO, external_key: str, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    bde_obj.unlock_with_external_key(bytes.fromhex(external_key))
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_raw_key_crypto(test_file: BinaryIO, raw_key: bytes, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    bde_obj.unlock_with_fvek(raw_key)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def test_bde_basic(bde_aes_128: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_aes_128)

    assert bde_obj.sector_size == 512
    assert bde_obj.version == 2

    assert len(bde_obj._available_information) == len(bde_obj._valid_information) == 3

    dataset = bde_obj.information.dataset
    assert len(dataset.data) == 4
    assert bde_obj.description() == "DESKTOP-QNI1MMF TestVolume 10/8/2021"

    assert bde_obj.reserved_regions() == [(69504, 128), (69632, 16), (84528, 128), (99544, 128)]


def test_bde_decrypted(bde_decrypted: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_decrypted)

    assert bde_obj.decrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.DECRYPTED
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert not stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


def test_bde_suspended(bde_suspended: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_suspended)

    assert bde_obj.has_clear_key()
    bde_obj.unlock_with_clear_key()

    stream = bde_obj.open()
    assert stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


@pytest.mark.parametrize(
    ("test_file", "passphrase", "key_type"),
    [
        ("_data/bde/aes_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128),
        ("_data/bde/aes_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256),
        ("_data/bde/aes_128_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER),
        ("_data/bde/aes_256_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER),
        ("_data/bde/aes-xts_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_128),
        ("_data/bde/aes-xts_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_256),
    ],
)
def test_bde_passphrase(test_file: str, passphrase: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_passphrase_crypto(fh, passphrase, key_type)


@pytest.mark.parametrize(
    ("test_file", "recovery", "key_type"),
    [
        (
            "_data/bde/recovery_password.bin.gz",
            "284867-596541-514998-422114-660297-261613-215424-199408",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_recovery(test_file: str, recovery: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_recovery_password_crypto(fh, recovery, key_type)


@pytest.mark.parametrize(
    ("test_file", "bek_file", "key_type"),
    [
        (
            "_data/bde/recovery_key.bin.gz",
            "_data/bde/recovery_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/startup_key.bin.gz",
            "_data/bde/startup_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_bek(test_file: str, bek_file: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
        contextlib.contextmanager(open_file)(bek_file) as bek_fh,
    ):
        _verify_bek_crypto(fh, bek_fh, key_type)


@pytest.mark.parametrize(
    ("test_file", "external_key", "key_type"),
    [
        (
            "_data/bde/recovery_key.bin.gz",
            "48a608e5cd6f2112e4b390e38a086a5ec62a1a014afaf092c9117630deecd805",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/startup_key.bin.gz",
            "7a70ca1ab390e00daf4d72c217c42bf67a39db94d76214733ae56acb1c5dd814",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_external_key(test_file: str, external_key: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
    ):
        _verify_external_key_crypto(fh, external_key, key_type)


@pytest.mark.parametrize(
    ("test_file", "raw_key", "key_type"),
    [
        (
            "_data/bde/aes_128.bin.gz",
            "84c3a3157e5f21dee140005220bc940e",
            c_bde.FVE_KEY_TYPE.AES_128,
        ),
        (
            "_data/bde/aes_256.bin.gz",
            "dd3885ef9948c8dc6ad1b54a6c4a4b6fb74b44d1d9775ac7ed186c35f1b59022",
            c_bde.FVE_KEY_TYPE.AES_256,
        ),
        (
            "_data/bde/aes_128_diffuser.bin.gz",
            "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b",
            c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER,
        ),
        (
            "_data/bde/aes_256_diffuser.bin.gz",
            "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71ba272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f",
            c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER,
        ),
        (
            "_data/bde/aes-xts_128.bin.gz",
            "4eb949c473f0edfc379ad041670ddb9c4da0abdb4482a2c8bb47250493aa1ed5",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/aes-xts_256.bin.gz",
            "c74002df41f5eadeee2549fc009233a2a510726ce08736aba2f84a52ac6e7bbc56b8a824a4dc26cf9c4c2926386319d17427998e045ebfdc789e328e0dc97da4",
            c_bde.FVE_KEY_TYPE.AES_XTS_256,
        ),
    ],
)
def test_bde_raw_key(test_file: str, raw_key: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    """Test BDE unlocking using a FVEK key."""
    key = bytes.fromhex(raw_key)

    # Test if unlocking with valid FVEK works
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_raw_key_crypto(fh, key, key_type)

    # Test if unlocking with invalid FVEK fails
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
        pytest.raises(ValueError, match="Unable to unlock with FVEK, no plaintext filesystem found"),
    ):
        _verify_raw_key_crypto(fh, len(key) * b"\x00", key_type)


def test_bde_vista(bde_vista: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_vista)

    assert bde_obj.version == 1

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    bde_obj.fh.seek(0)

    patched_sector = bytearray(bde_obj.fh.read(512))
    bde_sector = stream.read(512)

    patched_sector[0x03:0x0B] = b"NTFS    "
    patched_sector[0x38:0x40] = struct.pack("<Q", bde_obj.information.header.Mft2StartLcn)

    assert bde_sector == patched_sector


def test_bde_win7_partial(bde_win7_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_win7_partial)

    assert bde_obj.version == 2

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("131450-120197-153989-250338-511368-495572-680944-381546")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(bde_obj.information.state_offset - 512, 1024)) == [
        (stream.RUN_ENCRYPTED, 2234023, 1),
        (stream.RUN_PLAIN, 2234024, 1),
    ]


def test_bde_eow_partial(bde_eow_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_eow_partial)

    assert bde_obj.version == 2
    assert bde_obj.eow_information

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase("password12!@")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(0x2202000, 0x800000 * 33)) == [
        (0, 69648, 233328),
        (2, 302976, 128),
        (0, 303104, 98304),
        (3, 401408, 135040),
        (2, 536448, 128),
        (3, 536576, 73744),
    ]


def test_is_bde_volume(bde_aes_128: BinaryIO) -> None:
    assert is_bde_volume(bde_aes_128)


def test_bde_wrong_keys() -> None:
    """Test that wrong keys raise a sensible error message."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_128.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        with pytest.raises(ValueError, match="Unable to unlock with given passphrase"):
            bde_obj.unlock_with_passphrase("wrongpassword")

        with pytest.raises(ValueError, match="Unable to unlock with given recovery password"):
            bde_obj.unlock_with_recovery_password("000000-000000-000000-000000-000000-000000-000000-000000")

    with (
        contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh,
        contextlib.contextmanager(open_file)("_data/bde/startup_key.bek") as bek_fh,
    ):
        bde_obj = bde.BDE(fh)

        with pytest.raises(ValueError, match="Unable to unlock with BEK"):
            bde_obj.unlock_with_bek(bek_fh)


def _corrupt_information_buffer(raw: bytes) -> BytesIO:
    """Return a copy whose Information buffer is tampered with while the outer CRC32 stays valid.

    The flipped byte lives in the trailing padding of the Information buffer: it is covered by
    both the CRC32 and the authenticated SHA256 integrity digest, but is not part of any datum
    and is not inside an AES-CCM ciphertext. Recomputing only the outer CRC32 therefore produces
    a volume with a valid checksum but a mismatching inner integrity digest.
    """
    buf = bytearray(raw)
    probe = bde.BDE(BytesIO(raw))
    info = probe.information
    information_offset = info.offset
    validation_offset = information_offset + info.size

    # The dataset starts right after the FVE_INFORMATION header; its Size leaves a small,
    # parser-invisible padding tail that is still part of the hashed Information buffer.
    tail_offset = information_offset + len(c_bde.c_bde.FVE_INFORMATION) + info.dataset.header.Size
    buf[tail_offset] ^= 0xFF

    new_crc = crc32(bytes(buf[information_offset : information_offset + info.size])) & 0xFFFFFFFF
    # FVE_VALIDATION layout: USHORT Size, USHORT Version, ULONG Crc32
    struct.pack_into("<I", buf, validation_offset + 4, new_crc)
    return BytesIO(buf)


def _corrupt_integrity_datum_mac(raw: bytes) -> BytesIO:
    """Return a copy whose integrity datum MAC is corrupted while the outer CRC32 stays valid.

    The integrity datum sits after the FVE_VALIDATION structure and is not part of the hashed
    Information buffer, so corrupting its MAC keeps the outer CRC valid but makes the AES-CCM
    authenticated decryption of the integrity datum fail.
    """
    buf = bytearray(raw)
    probe = bde.BDE(BytesIO(raw))
    info = probe.information
    validation_offset = info.offset + info.size

    integrity_offset = validation_offset + len(c_bde.c_bde.FVE_VALIDATION)
    # FVE_DATUM header (8 bytes) followed by FVE_NONCE (12 bytes), then the 16-byte MAC
    mac_offset = integrity_offset + len(c_bde.c_bde.FVE_DATUM) + len(c_bde.c_bde.FVE_NONCE)
    buf[mac_offset] ^= 0x01
    return BytesIO(buf)


def _decrypted_vmk(bde_obj: bde.BDE, passphrase: str) -> KeyDatum:
    user_key = derive_user_key(passphrase)
    vmk = next(bde_obj.information.dataset.find_passphrase_vmk())
    aes_key = stretch(user_key, vmk.stretch_key(None).salt)
    return vmk.decrypt(aes_key)


@pytest.mark.parametrize(
    "corruptor",
    [_corrupt_information_buffer, _corrupt_integrity_datum_mac],
    ids=["digest_mismatch", "auth_decrypt_failure"],
)
def test_bde_integrity_failure_rejected_at_public_entrypoints(corruptor) -> None:
    """A valid outer CRC32 must not unlock a volume that fails the inner integrity check."""
    raw = _read_gz("_data/bde/aes_128.bin.gz")

    corrupted = corruptor(raw)
    bde_obj = bde.BDE(corrupted)

    # The outer checksum is deliberately kept valid, proving the rejection comes from the
    # cryptographic integrity check rather than the CRC32.
    assert bde_obj.information.is_valid()
    assert not bde_obj.unlocked

    vmk = _decrypted_vmk(bde_obj, "password12!@")

    # The low-level entry point, exercised with the correctly derived VMK.
    with pytest.raises(InvalidIntegrityError):
        bde_obj.unlock(vmk)
    assert not bde_obj.unlocked

    # The passphrase entry point must report metadata corruption, never a wrong passphrase.
    with pytest.raises(InvalidIntegrityError):
        bde_obj.unlock_with_passphrase("password12!@")
    assert not bde_obj.unlocked

    # A failed unlock must not leave an openable, half-unlocked volume behind.
    with pytest.raises(ValueError, match="Volume is locked"):
        bde_obj.open()


def test_bde_integrity_failure_not_misreported_as_wrong_credential() -> None:
    """Corruption diagnostics must not be rewritten into a generic 'wrong key/password' error."""
    raw = _read_gz("_data/bde/aes_128.bin.gz")

    # A genuine wrong passphrase still raises the existing, distinct ValueError.
    good = bde.BDE(BytesIO(raw))
    with pytest.raises(ValueError, match="Unable to unlock with given passphrase"):
        good.unlock_with_passphrase("wrongpassword")
    assert not good.unlocked

    # Metadata corruption raises InvalidIntegrityError, a distinct type from ValueError so it can
    # never be confused with the wrong-passphrase failure exercised above.
    corrupted = bde.BDE(_corrupt_information_buffer(raw))
    with pytest.raises(InvalidIntegrityError):
        corrupted.unlock_with_passphrase("password12!@")
    assert not corrupted.unlocked


def test_bde_external_key_integrity_failure_propagates() -> None:
    """The external key path must surface integrity corruption instead of swallowing it."""
    raw = _read_gz("_data/bde/recovery_key.bin.gz")

    external_key = bytes.fromhex("48a608e5cd6f2112e4b390e38a086a5ec62a1a014afaf092c9117630deecd805")
    corrupted = bde.BDE(_corrupt_information_buffer(raw))

    with pytest.raises(InvalidIntegrityError):
        corrupted.unlock_with_external_key(external_key)
    assert not corrupted.unlocked


def test_bde_valid_sample_still_unlocks_after_corruption_rejection() -> None:
    """Rejecting a corrupted copy must not affect an independently parsed, valid sample."""
    raw = _read_gz("_data/bde/aes_128.bin.gz")

    # First, a corrupted instance is rejected through the public entry point.
    corrupted = bde.BDE(_corrupt_information_buffer(raw))
    with pytest.raises(InvalidIntegrityError):
        corrupted.unlock_with_passphrase("password12!@")
    assert not corrupted.unlocked

    # A fresh, independent instance of the unmodified sample still reads the original plaintext.
    valid = bde.BDE(BytesIO(raw))
    valid.unlock_with_passphrase("password12!@")
    assert valid.unlocked

    stream = valid.open()
    assert stream.read(512)[3:11] == b"NTFS    "
    stream.seek(0x2000)
    assert stream.read(512)[:8] == b"FILE0\x00\x03\x00"


def test_bde_legacy_volume_without_integrity_datum_uses_crc() -> None:
    """Legacy (version 1) volumes have no integrity datum and keep relying on the CRC32."""
    raw = _read_gz("_data/bde/vista.bin.gz")
    legacy = bde.BDE(BytesIO(raw))

    assert legacy.version == 1
    assert legacy.information.validation.integrity_check is None

    legacy.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")
    assert legacy.unlocked
    assert legacy.open().read(512)[3:11] == b"NTFS    "

    # Without an integrity datum the CRC32 is the only guard. Recompute it after tampering so the
    # volume still parses, then confirm the legacy path cannot detect the change: this documents
    # that old formats genuinely lack the stronger authenticated check (CRC-only), while modern
    # volumes are protected by the integrity datum tests above.
    info = legacy.information
    tampered = bytearray(raw)
    tampered[info.offset + 0x80] ^= 0xFF
    fixed_crc = crc32(bytes(tampered[info.offset : info.offset + info.size])) & 0xFFFFFFFF
    validation_offset = info.offset + info.size
    struct.pack_into("<I", tampered, validation_offset + 4, fixed_crc)

    legacy_tampered = bde.BDE(BytesIO(tampered))
    assert legacy_tampered.information.is_valid()
    assert legacy_tampered.information.validation.integrity_check is None

    # With a valid CRC the legacy integrity entry point passes (it has no authenticated digest to
    # compare against); a failed CRC instead raises InvalidIntegrityError.
    legacy_tampered.information.check_integrity(b"\x00" * 32)

    info_broken = bde.BDE(BytesIO(bytearray(raw))).information
    info_broken._valid_checksum = False
    with pytest.raises(InvalidIntegrityError, match="CRC32 validation failed"):
        info_broken.check_integrity(b"\x00" * 32)

    # A genuinely broken CRC (left unfixed) is rejected up front as an invalid information block.
    broken = bytearray(raw)
    broken[info.offset + 0x80] ^= 0xFF
    with pytest.raises(InvalidHeaderError):
        bde.BDE(BytesIO(broken))
