from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable

import pytest
from Crypto.Cipher import AES, ARC4

from dissect.database.ese.ntds.c_pek import c_pek
from dissect.database.ese.ntds.pek import AUTHENTICATOR, PEK
from dissect.database.ese.ntds.util import ATTRIBUTE_ENCODE_DECODE_MAP, _decode_pwd_history, _pek_decrypt

# ---------------------------------------------------------------------------
# Self-contained fixtures: every syskey, PEK key and plaintext below is made
# up for this module and carries a recognizable "SENTINEL" marker so that any
# leak through an exception message or repr can be detected mechanically.
# ---------------------------------------------------------------------------

PEK_V2 = c_pek.PEK_PRE_2012R2_VERSION
PEK_V3 = c_pek.PEK_2016_TP4_VERSION
ALL_VERSIONS = (PEK_V2, PEK_V3)

SYSKEY = b"SENTINEL-SYSKEY!"
WRONG_SYSKEY = b"SENTINEL-WRONG!!"
PEK_KEY_1 = b"SENTINEL-PEK-K1!"
PEK_KEY_2 = b"SENTINEL-PEK-K2!"
PLAINTEXT_1 = b"SENTINEL-PLAIN-1"
PLAINTEXT_2 = b"SENTINEL-PLAIN-2"

KEY_ID_1 = 1001
KEY_ID_2 = 2002
UNKNOWN_KEY_ID = 9999

SALT = b"fedcba9876543210"
IV = b"0123456789abcdef"

SECRET_MARKERS = (SYSKEY, WRONG_SYSKEY, PEK_KEY_1, PEK_KEY_2, PLAINTEXT_1, PLAINTEXT_2)

PEK_LIST_HEADER_SIZE = 24
AES_ATTRIBUTE_HEADER_SIZE = 28


def _rc4_crypt(data: bytes, key: bytes, salt: bytes | None, iterations: int) -> bytes:
    """Independent re-implementation of the NTDS RC4 routine, used to build fixtures."""
    ctx = hashlib.md5(key)
    if salt is not None:
        for _ in range(iterations):
            ctx.update(salt)
    return ARC4.new(ctx.digest()).encrypt(data)


def _aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Independent AES-CBC encryption helper, mirroring the zero padding used by NTDS."""
    padded = data + b"\x00" * (-len(data) % 16)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)


def _clear_pek_list(keys: dict[int, bytes]) -> bytes:
    result = AUTHENTICATOR.bytes_le + struct.pack("<QII", 0, next(iter(keys)), len(keys))
    for key_id, key in keys.items():
        result += struct.pack("<I", key_id) + key
    return result


def make_pek_list(
    version: int,
    syskey: bytes = SYSKEY,
    keys: dict[int, bytes] | None = None,
    *,
    salt: bytes = SALT,
) -> bytes:
    """Build a synthetic encrypted PEK list blob for the given PEK version."""
    if keys is None:
        keys = {KEY_ID_1: PEK_KEY_1, KEY_ID_2: PEK_KEY_2}

    clear_list = _clear_pek_list(keys)
    if version == PEK_V2:
        encrypted = _rc4_crypt(clear_list, syskey, salt, 1000)
    elif version == PEK_V3:
        encrypted = _aes_encrypt(clear_list, syskey, salt)
    else:
        encrypted = b"\x00" * 32

    return struct.pack("<II", version, 0) + salt + encrypted


def make_rc4_blob(key_id: int, plaintext: bytes, key: bytes, *, salt: bytes | None = None) -> bytes:
    """Build a synthetic RC4 (optionally salted) encrypted attribute blob."""
    if salt is None:
        body = _rc4_crypt(plaintext, key, None, 0)
        return struct.pack("<HHI", c_pek.PEK_ENCRYPTION, 0, key_id) + body

    body = _rc4_crypt(plaintext, key, salt, 1)
    return struct.pack("<HHI", c_pek.PEK_ENCRYPTION_WITH_SALT, 0, key_id) + salt + body


def make_aes_blob(
    key_id: int,
    plaintext: bytes,
    key: bytes,
    iv: bytes = IV,
    *,
    declared_length: int | None = None,
) -> bytes:
    """Build a synthetic AES encrypted attribute blob, optionally with a forged length field."""
    body = _aes_encrypt(plaintext, key, iv)
    length = len(plaintext) if declared_length is None else declared_length
    return struct.pack("<HHI", c_pek.PEK_ENCRYPTION_WITH_AES, 0, key_id) + iv + struct.pack("<I", length) + body


def assert_no_secret_marker(text: str) -> None:
    """Assert that a rendered exception/object representation hides every fixture secret."""
    for marker in SECRET_MARKERS:
        assert marker.decode() not in text


class _FakeDatabase:
    """Minimal database stand-in exposing only the ``pek`` attribute the decoders need."""

    def __init__(self, pek: PEK | None):
        self.pek = pek


@pytest.fixture
def unlocked_pek() -> Callable[[int], PEK]:
    def _make(version: int) -> PEK:
        pek = PEK(make_pek_list(version))
        pek.unlock(SYSKEY)
        assert pek.unlocked
        return pek

    return _make


# ---------------------------------------------------------------------------
# Positive cases: a correct unlock and explicit multi-KeyId selection.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_unlock_synthetic_pek_list(version: int) -> None:
    """A well-formed PEK list unlocks and exposes exactly the embedded keys."""
    pek = PEK(make_pek_list(version))
    assert pek.version == version
    assert not pek.unlocked

    pek.unlock(SYSKEY)

    assert pek.unlocked
    assert pek.keys == {KEY_ID_1: PEK_KEY_1, KEY_ID_2: PEK_KEY_2}


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_decrypt_roundtrip_all_algorithms(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """All three supported attribute encryption algorithms round-trip exact plaintexts."""
    pek = unlocked_pek(version)

    rc4_blob = make_rc4_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)
    salted_blob = make_rc4_blob(KEY_ID_2, PLAINTEXT_2, PEK_KEY_2, salt=SALT)
    aes_blob = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)

    assert pek.decrypt(rc4_blob) == PLAINTEXT_1
    assert pek.decrypt(salted_blob) == PLAINTEXT_2
    assert pek.decrypt(aes_blob) == PLAINTEXT_1


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_multi_key_id_selection(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """Decryption selects the key by KeyId, not by list position, and returns exact values."""
    pek = unlocked_pek(version)

    blob_key_1 = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)
    blob_key_2 = make_aes_blob(KEY_ID_2, PLAINTEXT_2, PEK_KEY_2)

    assert pek.decrypt(blob_key_1) == PLAINTEXT_1
    assert pek.decrypt(blob_key_2) == PLAINTEXT_2

    # The same ciphertext labelled with the other KeyId must not be accepted as PLAINTEXT_1,
    # proving key selection is driven by the KeyId field rather than a default/first key.
    mislabelled = bytearray(blob_key_1)
    struct.pack_into("<I", mislabelled, 4, KEY_ID_2)
    assert pek.decrypt(bytes(mislabelled)) != PLAINTEXT_1


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_decrypt_through_attribute_read_path(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """The registered attribute decoder path propagates successful decryption unchanged."""
    pek = unlocked_pek(version)
    assert ATTRIBUTE_ENCODE_DECODE_MAP["unicodePwd"][1] is _pek_decrypt

    blob = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)
    db = _FakeDatabase(pek)

    assert _pek_decrypt(db, blob) == PLAINTEXT_1
    assert _decode_pwd_history(db, [blob]) == [PLAINTEXT_1]

    # A locked or absent PEK leaves the raw encrypted value untouched instead of faking success
    locked = PEK(make_pek_list(version))
    assert _pek_decrypt(_FakeDatabase(locked), blob) == blob
    assert _pek_decrypt(_FakeDatabase(None), blob) == blob


def test_locked_pek_rejects_decrypt_and_keys() -> None:
    """Using a locked PEK through the public API raises instead of returning data."""
    pek = PEK(make_pek_list(PEK_V3))

    with pytest.raises(RuntimeError, match="PEK is not unlocked"):
        _ = pek.keys
    with pytest.raises(RuntimeError, match="PEK is not unlocked"):
        pek.decrypt(make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1))


# ---------------------------------------------------------------------------
# Negative cases: unlock path (PEK list corruption and wrong syskey).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_wrong_syskey_rejected(version: int) -> None:
    """A wrong syskey fails the authenticator check and leaves the PEK locked."""
    pek = PEK(make_pek_list(version))

    with pytest.raises(ValueError, match="Invalid PEK authenticator after unlocking") as exc_info:
        pek.unlock(WRONG_SYSKEY)

    assert not pek.unlocked
    assert_no_secret_marker(str(exc_info.value))
    assert_no_secret_marker(repr(exc_info.value))

    # The failure must not poison the PEK: the correct syskey still unlocks it afterwards
    pek.unlock(SYSKEY)
    assert pek.unlocked
    assert pek.keys[KEY_ID_1] == PEK_KEY_1


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_wrong_syskey_distinguished_from_format_corruption(version: int) -> None:
    """Wrong-password failures and structural format failures raise distinct exception types."""
    pek = PEK(make_pek_list(version))
    with pytest.raises(ValueError, match="Invalid PEK authenticator"):
        pek.unlock(WRONG_SYSKEY)

    # Truncated structure cannot even be parsed and surfaces as EOFError, not an authenticator error
    with pytest.raises(EOFError):
        PEK(make_pek_list(version)[:4])

    # An unknown PEK version is a NotImplementedError of its own
    with pytest.raises(NotImplementedError, match="Unsupported PEK version"):
        PEK(make_pek_list(99)).unlock(SYSKEY)


def test_unsupported_pek_version_rejected() -> None:
    """A PEK list with an unknown version is refused and never marked as unlocked."""
    pek = PEK(make_pek_list(99))

    with pytest.raises(NotImplementedError, match="Unsupported PEK version: 99") as exc_info:
        pek.unlock(SYSKEY)

    assert not pek.unlocked
    assert_no_secret_marker(str(exc_info.value))


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_truncated_pek_list_rejected(version: int) -> None:
    """Truncated PEK lists either fail parsing or fail the authenticator, never unlock."""
    # Header cut off mid-structure: construction itself must fail
    with pytest.raises(EOFError):
        PEK(make_pek_list(version)[: PEK_LIST_HEADER_SIZE - 1])

    # Intact header but no encrypted body: unlock must reject on the authenticator
    pek = PEK(make_pek_list(version)[:PEK_LIST_HEADER_SIZE])
    with pytest.raises(ValueError, match="Invalid PEK authenticator after unlocking"):
        pek.unlock(SYSKEY)
    assert not pek.unlocked


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_corrupted_pek_list_ciphertext_rejected(version: int) -> None:
    """Bit-level corruption of the encrypted PEK list cannot produce a successful unlock."""
    blob = bytearray(make_pek_list(version))
    # Corrupt the first ciphertext byte so the 16-byte authenticator itself is damaged,
    # regardless of RC4 stream alignment or AES zero padding at the tail.
    blob[PEK_LIST_HEADER_SIZE] ^= 0x01
    pek = PEK(bytes(blob))

    with pytest.raises(ValueError, match="Invalid PEK authenticator after unlocking") as exc_info:
        pek.unlock(SYSKEY)

    assert not pek.unlocked
    assert_no_secret_marker(str(exc_info.value))
    assert_no_secret_marker(repr(pek))


# ---------------------------------------------------------------------------
# Negative cases: encrypted attribute / decrypt path.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_unknown_key_id_rejected(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """A blob referencing a KeyId absent from the PEK list raises a KeyError naming that id."""
    pek = unlocked_pek(version)
    blob = make_aes_blob(UNKNOWN_KEY_ID, PLAINTEXT_1, PEK_KEY_1)

    with pytest.raises(KeyError, match=str(UNKNOWN_KEY_ID)) as exc_info:
        pek.decrypt(blob)

    message = str(exc_info.value)
    assert str(UNKNOWN_KEY_ID) in message
    # The diagnostic must not hint at valid KeyIds or any fixture secret
    assert str(KEY_ID_1) not in message
    assert str(KEY_ID_2) not in message
    assert_no_secret_marker(message)

    # The same rejection must propagate through the attribute read path
    with pytest.raises(KeyError, match=str(UNKNOWN_KEY_ID)):
        _pek_decrypt(_FakeDatabase(pek), blob)


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_truncated_aes_blob_rejected(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """Truncated AES attribute blobs are refused instead of returning partial plaintext."""
    pek = unlocked_pek(version)

    # Header itself truncated: parsing fails before any crypto happens
    with pytest.raises(EOFError):
        pek.decrypt(make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)[: AES_ATTRIBUTE_HEADER_SIZE - 1])

    valid = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)

    # No ciphertext body at all
    empty_body = valid[:AES_ATTRIBUTE_HEADER_SIZE]
    with pytest.raises(ValueError, match="Truncated AES encrypted data") as exc_info:
        pek.decrypt(empty_body)
    assert_no_secret_marker(str(exc_info.value))

    # Ciphertext cut in the middle of a block: a relaxed implementation would silently zero-pad
    # and hand back garbage; pin the exact rejection so removing the guard fails this test loudly.
    partial_body = valid[: AES_ATTRIBUTE_HEADER_SIZE + 9]
    with pytest.raises(ValueError, match="expected a whole number of 16-byte blocks, got 9 bytes"):
        pek.decrypt(partial_body)

    # Under no rejection scenario may a fixture plaintext be returned
    for damaged in (empty_body, partial_body):
        with pytest.raises((ValueError, EOFError)):
            pek.decrypt(damaged)


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_declared_length_out_of_bounds_rejected(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """A declared plaintext length beyond the decrypted bytes is rejected, not silently truncated."""
    pek = unlocked_pek(version)
    honest_blob = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1)
    assert pek.decrypt(honest_blob) == PLAINTEXT_1

    decrypted_size = len(PLAINTEXT_1)
    for forged_length in (decrypted_size + 1, 1_000_000):
        forged = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1, declared_length=forged_length)
        with pytest.raises(ValueError, match="Declared AES plaintext length") as exc_info:
            pek.decrypt(forged)

        message = str(exc_info.value)
        assert str(forged_length) in message
        assert str(decrypted_size) in message
        assert_no_secret_marker(message)

    # A relaxed length check that just slices would return 16 bytes instead of raising; assert the
    # damaged blob can never be mistaken for the genuine recovery result.
    forged = make_aes_blob(KEY_ID_1, PLAINTEXT_1, PEK_KEY_1, declared_length=decrypted_size + 1)
    with pytest.raises(ValueError, match="Declared AES plaintext length") as exc_info:
        pek.decrypt(forged)
    assert PLAINTEXT_1 not in exc_info.value.args
    assert PLAINTEXT_2 not in exc_info.value.args


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_unknown_algorithm_rejected(version: int, unlocked_pek: Callable[[int], PEK]) -> None:
    """An unknown AlgorithmId is refused without touching the fixture plaintext."""
    pek = unlocked_pek(version)
    blob = struct.pack("<HHI", 0x77, 0, KEY_ID_1) + b"some-opaque-payload"

    with pytest.raises(NotImplementedError, match="Unsupported PEK encryption algorithm: 119") as exc_info:
        pek.decrypt(blob)

    assert_no_secret_marker(str(exc_info.value))


# ---------------------------------------------------------------------------
# Cross-cutting: no fixture secret may surface in errors or object reprs.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_errors_and_reprs_hide_fixture_secrets(version: int) -> None:
    """Every failure path and PEK representation must stay free of SENTINEL material."""
    pek = PEK(make_pek_list(version))

    # Pre-unlock repr only contains ciphertext structures
    assert_no_secret_marker(repr(pek))

    failures: list[Exception] = []

    try:
        pek.unlock(WRONG_SYSKEY)
    except ValueError as exc:
        failures.append(exc)

    try:
        PEK(make_pek_list(99)).unlock(SYSKEY)
    except NotImplementedError as exc:
        failures.append(exc)

    try:
        PEK(make_pek_list(version)[:4])
    except EOFError as exc:
        failures.append(exc)

    damaged = bytearray(make_pek_list(version))
    damaged[PEK_LIST_HEADER_SIZE] ^= 0x01
    try:
        PEK(bytes(damaged)).unlock(SYSKEY)
    except ValueError as exc:
        failures.append(exc)

    # Repr after a failed unlock still must not expose key/plaintext markers
    assert_no_secret_marker(repr(pek))
    # Every corruption scenario above must have been captured rather than swallowed or mis-raised
    expected_failure_types = [ValueError, NotImplementedError, EOFError, ValueError]
    assert [type(exc) for exc in failures] == expected_failure_types

    for exc in failures:
        assert_no_secret_marker(str(exc))
        assert_no_secret_marker(repr(exc))
