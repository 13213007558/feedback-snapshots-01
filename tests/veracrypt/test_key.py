from __future__ import annotations

import hashlib

import pytest

from dissect.fve.veracrypt.key import (
    KEY_DERIVATIONS,
    MAX_PIM,
    SYSTEM_KEY_DERIVATIONS,
    KeyDerivation,
    Pkcs5HmacSha256,
    Pkcs5HmacSha256_Boot,
    Pkcs5HmacSha512,
    normalize_pim,
)


@pytest.mark.parametrize(
    ("pim", "expected"),
    [
        pytest.param(None, None, id="omitted"),
        pytest.param(0, None, id="zero-is-default"),
        pytest.param(1, 1, id="one"),
        pytest.param(MAX_PIM, MAX_PIM, id="max"),
    ],
)
def test_normalize_pim_valid(pim: int | None, expected: int | None) -> None:
    assert normalize_pim(pim) == expected


@pytest.mark.parametrize(
    ("pim", "exception", "match"),
    [
        pytest.param(-1, ValueError, "must not be negative", id="negative"),
        pytest.param(MAX_PIM + 1, ValueError, "must not exceed", id="out-of-range"),
        pytest.param("485", TypeError, "must be an integer", id="string"),
        pytest.param(1.5, TypeError, "must be an integer", id="float"),
        pytest.param(True, TypeError, "must be an integer", id="bool"),
    ],
)
def test_normalize_pim_invalid(pim: object, exception: type[Exception], match: str) -> None:
    with pytest.raises(exception, match=match):
        normalize_pim(pim)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("Kdf", "pim", "expected"),
    [
        pytest.param(Pkcs5HmacSha512, None, 500_000, id="sha512-default"),
        pytest.param(Pkcs5HmacSha512, 0, 500_000, id="sha512-zero"),
        pytest.param(Pkcs5HmacSha512, 485, 500_000, id="sha512-pim-485"),
        pytest.param(Pkcs5HmacSha256, None, 500_000, id="sha256-default"),
        pytest.param(Pkcs5HmacSha256, 1, 16_000, id="sha256-pim-1"),
        pytest.param(Pkcs5HmacSha256_Boot, None, 200_000, id="sha256-boot-default"),
        pytest.param(Pkcs5HmacSha256_Boot, 1, 2048, id="sha256-boot-pim-1"),
        pytest.param(Pkcs5HmacSha256_Boot, 98, 200_704, id="sha256-boot-pim-98"),
    ],
)
def test_iterations(Kdf: type[KeyDerivation], pim: int | None, expected: int) -> None:
    kdf = Kdf(b"password", b"saltsalt")
    assert kdf.iterations(normalize_pim(pim)) == expected


@pytest.mark.parametrize(
    ("Kdf", "pim", "expected"),
    [
        pytest.param(
            Pkcs5HmacSha512,
            None,
            "c34a17c8b0fdb3fe4261fe22805059e5df16c0cf4e40908e51d1c941d08ff716"
            "3f9ced5e7c93cacb4f82ce3326db36d7cd5a066181347492fc1b64c95930317c",
            id="sha512-default",
        ),
        pytest.param(
            Pkcs5HmacSha256,
            1,
            "5c0e3b5f827195133373b1ae74b4787642ba6fe38521bcf78e15afddf75050b5"
            "972b0267c2b989d524ad835cec622d5b14b8d2cdcc862a6f476cacda1dd0245b",
            id="sha256-pim-1",
        ),
        pytest.param(
            Pkcs5HmacSha256_Boot,
            1,
            "e20d39de58669d829bc202e3c6614e26a17ebc347290e82644ccaf73b193c86f"
            "b082ca5610772b83ce84193a044393a152f6c9d055f372994fe8950f2f118834",
            id="sha256-boot-pim-1",
        ),
    ],
)
def test_derive_known_answer(Kdf: type[KeyDerivation], pim: int | None, expected: str) -> None:
    """Short known-answer vectors for password b"password" and salt b"saltsalt"."""
    assert Kdf(b"password", b"saltsalt").derive(pim) == bytes.fromhex(expected)


def test_derive_matches_pbkdf2_hmac() -> None:
    """Derived keys must match a plain ``hashlib.pbkdf2_hmac`` call for the same parameters."""
    salt = b"saltsalt"
    for Kdf in (Pkcs5HmacSha512, Pkcs5HmacSha256, Pkcs5HmacSha256_Boot):
        for pim in (None, 1, 485):
            kdf = Kdf(b"password", salt)
            assert kdf.derive(pim) == hashlib.pbkdf2_hmac(
                Kdf.__hash__, b"password", salt, kdf.iterations(normalize_pim(pim)), dklen=64
            )


def test_derive_long_password_matches_pbkdf2_hmac() -> None:
    """Passwords longer than the hash block size derive exactly like ``hashlib.pbkdf2_hmac``."""
    password = bytes(range(256))
    kdf = Pkcs5HmacSha512(password, b"saltsalt")
    assert kdf.derive() == hashlib.pbkdf2_hmac("sha512", password, b"saltsalt", 500_000, dklen=64)


def test_key_derivation_rejects_text_password() -> None:
    with pytest.raises(TypeError, match="Password must be bytes"):
        Pkcs5HmacSha512("password", b"saltsalt")  # type: ignore[arg-type]


def test_kdf_candidates() -> None:
    """File containers and system volumes use different, applicable KDF candidate sets."""
    assert Pkcs5HmacSha256_Boot not in KEY_DERIVATIONS
    assert Pkcs5HmacSha256 not in SYSTEM_KEY_DERIVATIONS
    assert Pkcs5HmacSha512 in KEY_DERIVATIONS
    assert Pkcs5HmacSha512 in SYSTEM_KEY_DERIVATIONS
