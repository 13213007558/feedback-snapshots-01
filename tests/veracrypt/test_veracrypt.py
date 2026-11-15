from __future__ import annotations

import warnings
from io import BytesIO

import pytest
from dissect.util.stream import MappingStream

from dissect.fve.veracrypt.key import (
    Pkcs5HmacSha256,
    Pkcs5HmacSha256_Boot,
    Pkcs5HmacSha512,
    Pkcs5HmacSha512_Boot,
)
from dissect.fve.veracrypt.veracrypt import VeraCrypt, is_veracrypt_volume
from tests._util import absolute_path


@pytest.mark.parametrize(
    ("mode", "type", "value", "valid"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_text_passphrase",
            "password",
            True,
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_text_passphrase",
            "invalid-password",
            False,
            id="aes256-sha512-passphrase-invalid",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_text_passphrase",
            "password",
            True,
            id="aes256-sha256-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "5c20ecc54e499c16306781f9b300df9688ecc9221d4d9cc62af91466eed82646b3f26c3d4c647438b2b6da10ad256f29de8dca90aee8224e69621c39df3d81a7"
            ),
            True,
            id="aes256-sha512-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            bytes.fromhex(
                "964a320efd767801d19ab7585a1f3c000f491799979f4515b1f3b6860f244b6cd4c0482d0f6c8605f129f7ca74f06e18a624ed043d474a6c0d2452d0a5181022"
            ),
            True,
            id="aes256-sha256-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            b"\x00" * 64,
            False,
            id="aes256-sha256-header-key-invalid",
        ),
    ],
)
def test_veracrypt_file_container(mode: str, type: str, value: str | bytes, valid: bool) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (amd64, Windows) file-based container."""
    file = absolute_path(f"_data/veracrypt/{mode}.hc")
    assert is_veracrypt_volume(file.open("rb"))

    vc = VeraCrypt(file.open("rb"))
    assert not vc.unlocked
    assert not vc.is_system

    if not valid:
        with pytest.raises(ValueError, match=r"^Unable to decrypt using provided (passphrase|header keys)$"):
            getattr(vc, type)(value)
        return

    getattr(vc, type)(value)
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"

    stream = vc.open()
    assert b"FAT12" in stream.read(512)


@pytest.mark.parametrize(
    ("mode", "type", "value"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_text_passphrase",
            "password",
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "9b390d357149246a1ef0766d9b327dbb422631211f6ef37f722238d4a2b5fcaf9361c57d774c386baf806c4cb5097ee455997363a65c3eb684e8bc9ad3ee11e6"
            ),
            id="aes256-sha512-header-key",
        ),
    ],
)
def test_veracrypt_system_partition(mode: str, type: str, value: str) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (64-bit, Windows) system partition."""
    # Mock Disk and Volume and prepare stream with correct offsets.
    file = absolute_path(f"_data/veracrypt/{mode}.system")

    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=BytesIO(file.read_bytes() + (64 * b"\x01")))

    vc = VeraCrypt(stream, is_system=True)  # type: ignore
    getattr(vc, type)(value)

    assert vc.is_system
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"
    assert vc.cipher == "aes-xts-256-plain64"
    assert vc.version == 5
    assert vc.client_version == 267
    assert vc.size == 0xFC4600000  # 63 GB


def _open_container(mode: str) -> VeraCrypt:
    file = absolute_path(f"_data/veracrypt/{mode}.hc")
    return VeraCrypt(file.open("rb"))


def _open_system() -> VeraCrypt:
    file = absolute_path("_data/veracrypt/aes256-sha512.system")
    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=BytesIO(file.read_bytes() + (64 * b"\x01")))
    return VeraCrypt(stream, is_system=True)  # type: ignore


@pytest.mark.parametrize(
    ("mode", "expected_kdf"),
    [
        ("aes256-sha512", Pkcs5HmacSha512),
        ("aes256-sha256", Pkcs5HmacSha256),
    ],
)
def test_unlock_with_text_passphrase_records_contract(mode: str, expected_kdf: type) -> None:
    """Text entry point uses UTF-8 and records the KDF and iteration count actually used."""
    vc = _open_container(mode)
    vc.unlock_with_text_passphrase("password")

    assert vc.unlocked
    assert vc.passphrase_encoding == "utf-8"
    assert vc.kdf is expected_kdf
    assert vc.kdf_iterations == 500_000
    assert b"FAT12" in vc.open().read(512)


def test_unlock_with_raw_passphrase_uses_bytes_verbatim() -> None:
    """Raw entry point feeds the exact byte sequence without any encoding step."""
    vc = _open_container("aes256-sha512")
    vc.unlock_with_raw_passphrase("password".encode("utf-8"))

    assert vc.unlocked
    assert vc.passphrase_encoding == "raw bytes"
    assert vc.kdf is Pkcs5HmacSha512
    assert vc.kdf_iterations == 500_000


def test_text_and_raw_entry_points_are_equivalent_for_utf8() -> None:
    text_vc = _open_container("aes256-sha256")
    raw_vc = _open_container("aes256-sha256")

    text_vc.unlock_with_text_passphrase("password")
    raw_vc.unlock_with_raw_passphrase(b"password")

    assert text_vc.unlocked and raw_vc.unlocked
    assert text_vc.header.master_keys == raw_vc.header.master_keys


def test_entry_points_reject_wrong_types() -> None:
    vc = _open_container("aes256-sha512")
    with pytest.raises(TypeError):
        vc.unlock_with_text_passphrase(b"password")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        vc.unlock_with_raw_passphrase("password")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        vc.unlock_with_passphrase(123)  # type: ignore[arg-type]


def test_legacy_entry_point_keeps_latin1_semantics() -> None:
    """The legacy str path must keep latin-1 byte semantics and warn about them."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        vc = _open_container("aes256-sha512")
        vc.unlock_with_passphrase("password")

    assert vc.unlocked
    assert vc.passphrase_encoding == "latin-1 (legacy)"
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_legacy_bytes_input_is_passed_through_without_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        vc = _open_container("aes256-sha512")
        vc.unlock_with_passphrase(b"password")
    assert vc.unlocked
    assert vc.passphrase_encoding == "raw bytes (legacy passthrough)"


def test_system_partition_uses_boot_kdf_candidates() -> None:
    vc = _open_system()
    vc.unlock_with_text_passphrase("password")

    assert vc.unlocked
    assert vc.is_system
    assert vc.kdf is Pkcs5HmacSha512_Boot
    assert vc.kdf_iterations == 500_000


@pytest.mark.parametrize("pim", [0, -1, 2**31])
def test_invalid_pim_raises_before_derivation(pim: int, monkeypatch: pytest.MonkeyPatch) -> None:
    import dissect.fve.veracrypt.key as keymod

    def boom(*args, **kwargs):
        raise AssertionError("PBKDF2 must not run for invalid PIM input")

    monkeypatch.setattr(keymod.hashlib, "pbkdf2_hmac", boom)

    vc = _open_container("aes256-sha512")
    with pytest.raises(ValueError):
        vc.unlock_with_text_passphrase("password", pim)
    assert not vc.unlocked


def test_system_pim_below_minimum_is_rejected() -> None:
    vc = _open_system()
    with pytest.raises(ValueError, match=r"minimum PIM of"):
        vc.unlock_with_text_passphrase("password", 1)
