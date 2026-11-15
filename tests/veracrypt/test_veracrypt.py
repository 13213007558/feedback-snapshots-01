from __future__ import annotations

import hashlib
from io import BytesIO
from typing import TYPE_CHECKING

import pytest
from dissect.util.stream import MappingStream

from dissect.fve.veracrypt.veracrypt import VeraCrypt, is_veracrypt_volume
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def _system_stream(file: Path) -> MappingStream:
    """Mock Disk and Volume and prepare stream with correct offsets."""
    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=BytesIO(file.read_bytes() + (64 * b"\x01")))
    return stream


@pytest.mark.parametrize(
    ("mode", "type", "value", "valid"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "invalid-password",
            False,
            id="aes256-sha512-passphrase-invalid",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_password",
            b"password",
            True,
            id="aes256-sha512-password-bytes",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha256-passphrase",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_password",
            b"password",
            True,
            id="aes256-sha256-password-bytes",
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
        with pytest.raises(ValueError, match=r"^Unable to decrypt using provided (password|header keys)$"):
            getattr(vc, type)(value)
        return

    getattr(vc, type)(value)
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"

    stream = vc.open()
    assert b"FAT12" in stream.read(512)


@pytest.mark.parametrize(
    ("mode", "kdf", "iterations"),
    [
        pytest.param("aes256-sha512", "pkcs5-hmac-sha512", 500_000, id="aes256-sha512"),
        pytest.param("aes256-sha256", "pkcs5-hmac-sha256", 500_000, id="aes256-sha256"),
    ],
)
def test_veracrypt_file_container_records_parameters(mode: str, kdf: str, iterations: int) -> None:
    """Test that unlocking records the actually used encoding, KDF and iteration parameters."""
    file = absolute_path(f"_data/veracrypt/{mode}.hc")

    # Raw bytes entry point: no encoding is recorded.
    vc = VeraCrypt(file.open("rb"))
    vc.unlock_with_password(b"password")
    assert vc.unlocked
    assert vc.kdf == kdf
    assert vc.iterations == iterations
    assert vc.pim is None
    assert vc.password_encoding is None

    # Text passphrase entry point: explicit encoding is recorded.
    vc = VeraCrypt(file.open("rb"))
    vc.unlock_with_passphrase("password", encoding="utf-8")
    assert vc.unlocked
    assert vc.kdf == kdf
    assert vc.iterations == iterations
    assert vc.pim is None
    assert vc.password_encoding == "utf-8"

    # Legacy call without encoding keeps the old latin-1 byte semantics.
    vc = VeraCrypt(file.open("rb"))
    vc.unlock_with_passphrase("password")
    assert vc.unlocked
    assert vc.password_encoding == "latin-1"


@pytest.mark.parametrize(
    ("pim", "exception"),
    [
        pytest.param(-1, ValueError, id="negative"),
        pytest.param(65_536, ValueError, id="out-of-range"),
        pytest.param("485", TypeError, id="string"),
    ],
)
def test_veracrypt_invalid_pim_rejected_before_derivation(
    monkeypatch: pytest.MonkeyPatch, pim: object, exception: type[Exception]
) -> None:
    """Test that invalid PIM values are rejected before any expensive key derivation runs."""
    file = absolute_path("_data/veracrypt/aes256-sha512.hc")
    vc = VeraCrypt(file.open("rb"))

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("key derivation must not run on invalid PIM")

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", _fail)
    with pytest.raises(exception):
        vc.unlock_with_passphrase("password", pim=pim)  # type: ignore[arg-type]
    assert not vc.unlocked


@pytest.mark.parametrize(
    ("mode", "type", "value"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_password",
            b"password",
            id="aes256-sha512-password-bytes",
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
def test_veracrypt_system_partition(mode: str, type: str, value: str | bytes) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (64-bit, Windows) system partition."""
    file = absolute_path(f"_data/veracrypt/{mode}.system")

    vc = VeraCrypt(_system_stream(file), is_system=True)  # type: ignore[arg-type]
    getattr(vc, type)(value)

    assert vc.is_system
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"
    assert vc.cipher == "aes-xts-256-plain64"
    assert vc.version == 5
    assert vc.client_version == 267
    assert vc.size == 0xFC4600000  # 63 GB


def test_veracrypt_system_partition_records_parameters() -> None:
    """Test that a system volume unlocks with an applicable (system) KDF candidate."""
    file = absolute_path("_data/veracrypt/aes256-sha512.system")

    vc = VeraCrypt(_system_stream(file), is_system=True)  # type: ignore[arg-type]
    vc.unlock_with_password(b"password")

    assert vc.unlocked
    assert vc.kdf == "pkcs5-hmac-sha512"
    assert vc.iterations == 500_000
    assert vc.pim is None
    assert vc.password_encoding is None
