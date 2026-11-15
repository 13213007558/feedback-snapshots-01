from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, Any

import pytest

from dissect.database.ese.ntds.c_pek import c_pek
from dissect.database.ese.ntds.pek import (
    AUTHENTICATOR,
    PEK,
    PEKError,
    PEKFormatError,
    PEKUnlockError,
    UnknownPEKKey,
    UnsupportedPEKAlgorithm,
    UnsupportedPEKVersion,
)
from dissect.database.ese.ntds.schema import AttributeEntry
from dissect.database.ese.ntds.util import _pek_decrypt, decode_value

if TYPE_CHECKING:
    from collections.abc import Callable

try:
    from Crypto.Cipher import AES, ARC4

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="pycryptodome is not installed")

SYSKEY = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
WRONG_SYSKEY = bytes.fromhex("ffeeddccbbaa99887766554433221100")
PEK_KEY_A = bytes.fromhex("00112233445566778899aabbccddeeff")
PEK_KEY_B = bytes.fromhex("ffeeddccbbaa99887766554433221100")
SALT = bytes.fromhex("102030405060708090a0b0c0d0e0f000")
IV = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

PLAINTEXT_A = b"FIXTURE-PLAINTEXT-ALPHA!"
PLAINTEXT_B = b"FIXTURE-PLAINTEXT-BETA!!"
PLAINTEXT_C = b"FIXTURE-PLAINTEXT-GAMMA!"
PLAINTEXT_D = b"FIXTURE-PLAINTEXT-DELTA!"

SECRETS = (
    SYSKEY.hex(),
    WRONG_SYSKEY.hex(),
    PEK_KEY_A.hex(),
    PEK_KEY_B.hex(),
    repr(PEK_KEY_A),
    repr(PEK_KEY_B),
    PLAINTEXT_A.decode(),
    PLAINTEXT_B.decode(),
    PLAINTEXT_C.decode(),
    PLAINTEXT_D.decode(),
)


def _assert_no_fixture_leak(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, "error or repr output contains fixture key or plaintext material"


def _assert_rejected(
    func: Callable[[], Any],
    exc_type: type[BaseException],
    reason: str,
    *,
    must_include: tuple[str, ...] = (),
) -> BaseException:
    """Assert that ``func`` is rejected for a specific, named reason.

    This intentionally checks more than "an exception happened": the exception type, the machine-readable
    reason and the diagnostic details are all asserted. If a length or key selection check is loosened,
    this fails on the specific criterion instead of silently accepting a bogus result.
    """
    try:
        func()
    except exc_type as e:
        exc = e
    except Exception as e:
        pytest.fail(f"expected {exc_type.__name__} ({reason!r}), got {type(e).__name__}")
    else:
        pytest.fail(f"expected {exc_type.__name__} ({reason!r}), but the call returned a result")

    assert isinstance(exc, PEKError)
    assert exc.reason == reason
    message = str(exc)
    for fragment in must_include:
        assert fragment in message, f"expected {fragment!r} in rejection message for reason {reason!r}"
    _assert_no_fixture_leak(message)
    _assert_no_fixture_leak(repr(exc))
    _assert_no_fixture_leak(repr(exc.args))
    return exc


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def _aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs7_pad(data))


def _rc4_crypt(data: bytes, key: bytes, salt: bytes | None, iterations: int) -> bytes:
    ctx = hashlib.md5(key)
    if salt is not None:
        for _ in range(iterations):
            ctx.update(salt)
    return ARC4.new(ctx.digest()).encrypt(data)


def _clear_pek_list(
    keys: list[tuple[int, bytes]],
    *,
    current_key: int = 1,
    count: int | None = None,
    authenticator: bytes = AUTHENTICATOR.bytes_le,
) -> bytes:
    if count is None:
        count = len(keys)

    data = authenticator + struct.pack("<QII", 0, current_key, count)
    for key_id, key in keys:
        data += struct.pack("<I", key_id) + key
    return data


def _encrypted_pek_list(clear: bytes, version: int, syskey: bytes = SYSKEY, *, pad: bool = True) -> bytes:
    salt = SALT
    if version == c_pek.PEK_2016_TP4_VERSION:
        if pad:
            ciphertext = _aes_encrypt(clear, syskey, salt)
        else:
            assert len(clear) % 16 == 0
            ciphertext = AES.new(syskey, AES.MODE_CBC, salt).encrypt(clear)
    elif version == c_pek.PEK_PRE_2012R2_VERSION:
        ciphertext = _rc4_crypt(clear, syskey, salt, 1000)
    else:
        ciphertext = b"\x00" * 16
    return struct.pack("<II", version, 0) + salt + ciphertext


def _unlocked_pek(
    version: int = c_pek.PEK_2016_TP4_VERSION,
    keys: list[tuple[int, bytes]] | None = None,
    *,
    syskey: bytes = SYSKEY,
) -> PEK:
    if keys is None:
        keys = [(1, PEK_KEY_A), (2, PEK_KEY_B)]

    pek = PEK(_encrypted_pek_list(_clear_pek_list(keys), version))
    pek.unlock(syskey)
    return pek


def _aes_attribute(
    key_id: int,
    plaintext: bytes,
    key: bytes,
    *,
    declared_length: int | None = None,
    iv: bytes = IV,
    ciphertext: bytes | None = None,
) -> bytes:
    if ciphertext is None:
        ciphertext = _aes_encrypt(plaintext, key, iv)
    if declared_length is None:
        declared_length = len(plaintext)
    return (
        struct.pack("<HHI", c_pek.PEK_ENCRYPTION_WITH_AES, 0, key_id)
        + iv
        + struct.pack("<I", declared_length)
        + ciphertext
    )


def _rc4_attribute(key_id: int, plaintext: bytes, key: bytes, *, salted: bool, salt: bytes = SALT) -> bytes:
    if salted:
        return (
            struct.pack("<HHI", c_pek.PEK_ENCRYPTION_WITH_SALT, 0, key_id) + salt + _rc4_crypt(plaintext, key, salt, 1)
        )
    return struct.pack("<HHI", c_pek.PEK_ENCRYPTION, 0, key_id) + _rc4_crypt(plaintext, key, None, 0)


def _decrypt_with_public_attribute_path(pek: PEK, value: bytes, attribute: str = "unicodePwd") -> bytes:
    schema = AttributeEntry(
        dnt=-1,
        id=-1,
        name=attribute,
        column="ATTk0",
        syntax=10,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
    )

    class _StubDatabase:
        def __init__(self, pek: PEK) -> None:
            self.pek = pek

    return decode_value(_StubDatabase(pek), schema, value)


@pytest.mark.parametrize("version", [c_pek.PEK_PRE_2012R2_VERSION, c_pek.PEK_2016_TP4_VERSION])
def test_unlock_and_key_selection_positive(version: int) -> None:
    pek = _unlocked_pek(version)
    assert pek.unlocked
    assert not isinstance(pek, Exception)
    assert pek.version == version
    assert pek.keys == {1: PEK_KEY_A, 2: PEK_KEY_B}

    if version == c_pek.PEK_2016_TP4_VERSION:
        value_a = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)
        value_b = _aes_attribute(2, PLAINTEXT_B, PEK_KEY_B)
    else:
        value_a = _rc4_attribute(1, PLAINTEXT_A, PEK_KEY_A, salted=True)
        value_b = _rc4_attribute(2, PLAINTEXT_B, PEK_KEY_B, salted=False)

    assert pek.decrypt(value_a) == PLAINTEXT_A
    assert pek.decrypt(value_b) == PLAINTEXT_B
    assert _decrypt_with_public_attribute_path(pek, value_a) == PLAINTEXT_A
    assert _decrypt_with_public_attribute_path(pek, value_b) == PLAINTEXT_B


@pytest.mark.parametrize("version", [0, 1, 4, 0xFFFFFFFF])
def test_unsupported_pek_version(version: int) -> None:
    pek = PEK(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A)]), version))

    _assert_rejected(
        lambda: pek.unlock(SYSKEY),
        UnsupportedPEKVersion,
        "unsupported-version",
        must_include=(str(version),),
    )
    assert not pek.unlocked
    assert pek.decrypted is None
    _assert_no_fixture_leak(repr(pek))


@pytest.mark.parametrize("version", [c_pek.PEK_PRE_2012R2_VERSION, c_pek.PEK_2016_TP4_VERSION])
def test_wrong_syskey_is_an_unlock_error(version: int) -> None:
    pek = PEK(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A), (2, PEK_KEY_B)]), version))

    _assert_rejected(lambda: pek.unlock(WRONG_SYSKEY), PEKUnlockError, "authenticator", must_include=("authenticator",))
    assert not pek.unlocked
    assert pek.decrypted is None

    # A failed unlock must not expose keys or a partially decrypted list.
    with pytest.raises(RuntimeError, match="PEK is not unlocked"):
        _ = pek.keys
    with pytest.raises(RuntimeError, match="PEK is not unlocked"):
        pek.decrypt(_aes_attribute(1, PLAINTEXT_A, PEK_KEY_A))

    # A subsequent correct syskey must still work, and must not be affected by the failed attempt.
    pek.unlock(SYSKEY)
    assert pek.unlocked
    assert pek.keys == {1: PEK_KEY_A, 2: PEK_KEY_B}


def test_failed_unlock_does_not_leave_a_successful_recovery_state() -> None:
    pek = PEK(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A)]), c_pek.PEK_2016_TP4_VERSION))

    assert not pek.unlocked
    assert _pek_decrypt(type("DB", (), {"pek": pek})(), _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)) != PLAINTEXT_A

    with pytest.raises(PEKUnlockError):
        pek.unlock(WRONG_SYSKEY)

    assert not pek.unlocked
    encrypted_value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)
    # Locked attributes are returned verbatim by the public attribute path, but must never look like plaintext.
    assert _pek_decrypt(type("DB", (), {"pek": pek})(), encrypted_value) == encrypted_value


@pytest.mark.parametrize("version", [c_pek.PEK_PRE_2012R2_VERSION, c_pek.PEK_2016_TP4_VERSION])
def test_tampered_pek_ciphertext_is_rejected(version: int) -> None:
    raw = bytearray(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A), (2, PEK_KEY_B)]), version))
    # Flip a bit in the first ciphertext block, after the 24-byte header.
    raw[24] ^= 0xFF
    pek = PEK(bytes(raw))

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKUnlockError, "authenticator", must_include=("authenticator",))
    assert not pek.unlocked


@pytest.mark.parametrize("size", [0, 1, 8, 23])
def test_truncated_encrypted_pek_list(size: int) -> None:
    raw = _encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A)]), c_pek.PEK_2016_TP4_VERSION)[:size]

    def _construct() -> PEK:
        return PEK(raw)

    _assert_rejected(_construct, PEKFormatError, "pek-list-truncated", must_include=(str(size), "24"))


@pytest.mark.parametrize("version", [c_pek.PEK_PRE_2012R2_VERSION, c_pek.PEK_2016_TP4_VERSION])
def test_encrypted_pek_list_without_ciphertext(version: int) -> None:
    raw = struct.pack("<II", version, 0) + SALT
    pek = PEK(raw)

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKFormatError, "pek-ciphertext-empty")
    assert not pek.unlocked


def test_aes_pek_ciphertext_must_be_block_aligned() -> None:
    raw = struct.pack("<II", c_pek.PEK_2016_TP4_VERSION, 0) + SALT + b"\x00" * 17
    pek = PEK(raw)

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKFormatError, "aes-alignment", must_include=("17",))


@pytest.mark.parametrize(
    ("clear", "reason", "must_include"),
    [
        (_clear_pek_list([(1, PEK_KEY_A), (2, PEK_KEY_B)], count=3), "pek-count-overflow", ("3", "2")),
        (_clear_pek_list([(1, PEK_KEY_A)], count=0), "pek-count-empty", ()),
        (
            _clear_pek_list([(1, PEK_KEY_A), (1, PEK_KEY_B)], count=2),
            "pek-duplicate-key-id",
            ("duplicate",),
        ),
    ],
)
def test_corrupt_clear_pek_list_counts(clear: bytes, reason: str, must_include: tuple[str, ...]) -> None:
    pek = PEK(_encrypted_pek_list(clear, c_pek.PEK_2016_TP4_VERSION))

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKFormatError, reason, must_include=must_include)
    assert not pek.unlocked
    assert pek.decrypted is None


def test_truncated_clear_pek_list() -> None:
    clear = AUTHENTICATOR.bytes_le
    pek = PEK(_encrypted_pek_list(clear, c_pek.PEK_2016_TP4_VERSION, pad=False))

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKFormatError, "clear-pek-list-truncated", must_include=("16", "32"))


def test_clear_pek_list_with_wrong_authenticator() -> None:
    clear = _clear_pek_list([(1, PEK_KEY_A), (2, PEK_KEY_B)], authenticator=b"\x00" * 16)
    pek = PEK(_encrypted_pek_list(clear, c_pek.PEK_2016_TP4_VERSION))

    _assert_rejected(lambda: pek.unlock(SYSKEY), PEKUnlockError, "authenticator", must_include=("authenticator",))
    assert not pek.unlocked


@pytest.mark.parametrize("version", [c_pek.PEK_PRE_2012R2_VERSION, c_pek.PEK_2016_TP4_VERSION])
def test_unknown_key_id_does_not_fall_back_to_another_key(version: int) -> None:
    pek = _unlocked_pek(version, keys=[(1, PEK_KEY_A), (2, PEK_KEY_B)])

    if version == c_pek.PEK_2016_TP4_VERSION:
        value = _aes_attribute(0xDEADBEEF, PLAINTEXT_A, PEK_KEY_A)
    else:
        value = _rc4_attribute(0xDEADBEEF, PLAINTEXT_A, PEK_KEY_A, salted=True)

    _assert_rejected(
        lambda: pek.decrypt(value),
        UnknownPEKKey,
        "unknown-key",
        must_include=(str(0xDEADBEEF),),
    )
    # Compatibility with callers that catch KeyError, while still exposing the specific reason.
    assert issubclass(UnknownPEKKey, KeyError)


@pytest.mark.parametrize("size", [0, 1, 7, 8, 17, 27])
def test_truncated_aes_attribute_header(size: int) -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)[:size]

    reason = "attribute-header-truncated" if size < 8 else "attribute-aes-truncated"

    _assert_rejected(lambda: pek.decrypt(value), PEKFormatError, reason)


def test_aes_attribute_without_ciphertext() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, ciphertext=b"")

    _assert_rejected(lambda: pek.decrypt(value), PEKFormatError, "attribute-aes-empty")


def test_declared_length_exceeds_ciphertext() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, declared_length=len(PLAINTEXT_A) + 16)

    _assert_rejected(
        lambda: pek.decrypt(value),
        PEKFormatError,
        "attribute-length-overflow",
        must_include=(str(len(PLAINTEXT_A) + 16), "32"),
    )


def test_declared_length_out_of_bounds() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, declared_length=0xFFFFFFFF)

    _assert_rejected(
        lambda: pek.decrypt(value),
        PEKFormatError,
        "attribute-length-overflow",
        must_include=(str(0xFFFFFFFF),),
    )


def test_declared_length_does_not_match_padding() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, declared_length=len(PLAINTEXT_A) - 8)

    _assert_rejected(
        lambda: pek.decrypt(value),
        PEKFormatError,
        "attribute-length-mismatch",
        must_include=(str(len(PLAINTEXT_A) - 8), str(len(PLAINTEXT_A))),
    )


def test_zero_declared_length() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, declared_length=0)

    _assert_rejected(lambda: pek.decrypt(value), PEKFormatError, "attribute-length-empty")


def test_aes_attribute_must_be_block_aligned() -> None:
    pek = _unlocked_pek()
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)[:28] + b"\x00" * 17

    _assert_rejected(lambda: pek.decrypt(value), PEKFormatError, "attribute-aes-alignment", must_include=("17",))


def test_aes_attribute_with_invalid_padding() -> None:
    pek = _unlocked_pek()
    # 32 bytes of plaintext with a zero padding byte, so the final block is not valid PKCS#7.
    ciphertext = AES.new(PEK_KEY_A, AES.MODE_CBC, IV).encrypt(PLAINTEXT_A + b"\x00" * (32 - len(PLAINTEXT_A)))
    value = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, ciphertext=ciphertext)

    _assert_rejected(lambda: pek.decrypt(value), PEKFormatError, "attribute-aes-padding")


def test_truncated_salted_attribute_header() -> None:
    pek = _unlocked_pek(version=c_pek.PEK_PRE_2012R2_VERSION)
    value = _rc4_attribute(1, PLAINTEXT_A, PEK_KEY_A, salted=True)

    for size in (8, 15, 23):
        _assert_rejected(lambda size=size: pek.decrypt(value[:size]), PEKFormatError, "attribute-salt-truncated")


def test_unsupported_attribute_algorithm() -> None:
    pek = _unlocked_pek()
    value = struct.pack("<HHI", 0x12, 0, 1) + b"\x00" * 16

    _assert_rejected(
        lambda: pek.decrypt(value),
        UnsupportedPEKAlgorithm,
        "unsupported-algorithm",
        must_include=(str(0x12),),
    )


def test_public_attribute_read_path_rejects_corrupt_attributes() -> None:
    pek = _unlocked_pek()

    bad_length = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A, declared_length=0xFFFFFFFF)
    _assert_rejected(
        lambda: _decrypt_with_public_attribute_path(pek, bad_length),
        PEKFormatError,
        "attribute-length-overflow",
    )

    bad_key = _aes_attribute(0xDEADBEEF, PLAINTEXT_A, PEK_KEY_A)
    _assert_rejected(
        lambda: _decrypt_with_public_attribute_path(pek, bad_key),
        UnknownPEKKey,
        "unknown-key",
    )

    truncated = _aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)[:20]
    _assert_rejected(
        lambda: _decrypt_with_public_attribute_path(pek, truncated),
        PEKFormatError,
        "attribute-aes-truncated",
    )

    history_entry = _aes_attribute(2, PLAINTEXT_B, PEK_KEY_B, declared_length=len(PLAINTEXT_B) + 16)
    _assert_rejected(
        lambda: _decrypt_with_public_attribute_path(pek, [history_entry], attribute="ntPwdHistory"),
        PEKFormatError,
        "attribute-length-overflow",
    )


def test_rejection_reasons_are_internally_distinguishable() -> None:
    pek = _unlocked_pek()

    wrong_syskey = PEK(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A)]), c_pek.PEK_2016_TP4_VERSION))
    wrong_syskey_error = _assert_rejected(lambda: wrong_syskey.unlock(WRONG_SYSKEY), PEKUnlockError, "authenticator")

    format_error = _assert_rejected(
        lambda: pek.decrypt(_aes_attribute(1, PLAINTEXT_A, PEK_KEY_A)[:20]),
        PEKFormatError,
        "attribute-aes-truncated",
    )

    unknown_key_error = _assert_rejected(
        lambda: pek.decrypt(_aes_attribute(3, PLAINTEXT_A, PEK_KEY_A)),
        UnknownPEKKey,
        "unknown-key",
    )

    # Wrong credentials and malformed data can be told apart, while neither is reported as a successful recovery.
    assert wrong_syskey_error.reason != format_error.reason
    assert wrong_syskey_error.reason != unknown_key_error.reason
    assert format_error.reason != unknown_key_error.reason
    assert not isinstance(wrong_syskey_error, PEKFormatError)


def test_repr_does_not_leak_key_material() -> None:
    pek = PEK(_encrypted_pek_list(_clear_pek_list([(1, PEK_KEY_A), (2, PEK_KEY_B)]), c_pek.PEK_2016_TP4_VERSION))

    _assert_no_fixture_leak(repr(pek))
    _assert_no_fixture_leak(str(pek))

    pek.unlock(SYSKEY)
    rendered = repr(pek)
    _assert_no_fixture_leak(rendered)
    assert "unlocked=True" in rendered
    assert "keys=2" in rendered
