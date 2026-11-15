from __future__ import annotations

import pytest

from dissect.fve.veracrypt.key import (
    BOOT_KEY_DERIVATIONS,
    DEFAULT_ITERATIONS,
    DEFAULT_ITERATIONS_BOOT,
    KEY_DERIVATIONS,
    PIM_MAXIMUM,
    Pkcs5HmacSha256,
    Pkcs5HmacSha256_Boot,
    Pkcs5HmacSha512,
    Pkcs5HmacSha512_Boot,
    validate_pim,
)

SALT = b"\x01" * 64


@pytest.mark.parametrize(
    ("pim", "is_system", "valid"),
    [
        (None, False, True),
        (None, True, True),
        (0, False, False),
        (0, True, False),
        (-1, False, False),
        (-98, True, False),
        (1, False, True),
        (1, True, False),
        (97, True, False),
        (98, True, True),
        (PIM_MAXIMUM, False, True),
        (PIM_MAXIMUM + 1, False, False),
    ],
)
def test_validate_pim(pim: int | None, is_system: bool, valid: bool) -> None:
    if valid:
        validate_pim(pim, is_system=is_system)
    else:
        with pytest.raises(ValueError):
            validate_pim(pim, is_system=is_system)


@pytest.mark.parametrize(
    ("kdf", "pim", "expected"),
    [
        (Pkcs5HmacSha512, None, DEFAULT_ITERATIONS),
        (Pkcs5HmacSha256, None, DEFAULT_ITERATIONS),
        (Pkcs5HmacSha512, 1, 16_000),
        (Pkcs5HmacSha256, 7, 22_000),
        (Pkcs5HmacSha512_Boot, None, DEFAULT_ITERATIONS),
        (Pkcs5HmacSha256_Boot, None, DEFAULT_ITERATIONS_BOOT),
        (Pkcs5HmacSha512_Boot, 98, 98 * 2_048),
        (Pkcs5HmacSha256_Boot, 98, 98 * 2_048),
    ],
)
def test_iteration_contract(kdf: type, pim: int | None, expected: int) -> None:
    assert kdf(b"passphrase", SALT).iterations(pim) == expected


def test_validate_pim_rejects_non_integer_types() -> None:
    for pim in (True, False, 1.0, "1", b"1"):
        with pytest.raises(TypeError):
            validate_pim(pim)


@pytest.mark.parametrize("kdf", (*KEY_DERIVATIONS, *BOOT_KEY_DERIVATIONS))
@pytest.mark.parametrize("pim", [0, -1, PIM_MAXIMUM + 1])
def test_derive_rejects_invalid_pim_before_pbkdf2(kdf: type, pim: int, monkeypatch: pytest.MonkeyPatch) -> None:
    import dissect.fve.veracrypt.key as keymod

    def boom(*args, **kwargs):
        raise AssertionError("PBKDF2 must not run for invalid PIM input")

    monkeypatch.setattr(keymod.hashlib, "pbkdf2_hmac", boom)
    with pytest.raises(ValueError):
        kdf(b"passphrase", SALT).derive(pim)


def test_derive_rejects_pim_below_system_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    import dissect.fve.veracrypt.key as keymod

    def boom(*args, **kwargs):
        raise AssertionError("PBKDF2 must not run for invalid PIM input")

    monkeypatch.setattr(keymod.hashlib, "pbkdf2_hmac", boom)
    with pytest.raises(ValueError):
        Pkcs5HmacSha512_Boot(b"passphrase", SALT).derive(1)


def test_kdf_only_accepts_raw_bytes() -> None:
    with pytest.raises(TypeError):
        Pkcs5HmacSha512("text", SALT)
    with pytest.raises(TypeError):
        Pkcs5HmacSha512(b"passphrase", "not-bytes")


def test_long_passphrase_is_prehashed() -> None:
    # Passphrases longer than the hash block size are reduced to a digest first.
    long_passphrase = b"a" * 200
    kdf = Pkcs5HmacSha512(long_passphrase, SALT)
    assert len(kdf.passphrase) == 64
