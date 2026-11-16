"""Byte-exact, independent decryption and HMAC integrity verification.

The decryption here is a from-scratch MS-OFFCRYPTO implementation; msoffcrypto
is never used to read the container it wrote. A passing row proves the file is
a genuine Agile-encrypted Office artifact that restores the original package
bytes exactly.
"""

import pytest

from .fixtures import PASSWORD, encrypt_fixture, make_payload
from .independent_crypto import decrypt_container
from .matrix import matrix_entries
from .runner import run_row

REGULAR_ROWS = [(label, size) for label, size, region, mini in matrix_entries() if not mini]
MINI_ROWS = [(label, size) for label, size, region, mini in matrix_entries() if mini]


@pytest.mark.parametrize("label,size", REGULAR_ROWS, ids=lambda v: v)
def test_regular_rows_restore_exact_plaintext(label, size):
    payload = make_payload(size)
    result = decrypt_container(encrypt_fixture(payload), PASSWORD)
    assert result.password_verified
    assert result.integrity_ok
    assert result.plaintext == payload
    assert len(result.plaintext) == size


@pytest.mark.parametrize("label,size", REGULAR_ROWS, ids=lambda v: v)
def test_runner_marks_regular_rows_fully_ok(label, size):
    row = run_row(label, size, "regular", False)
    assert row.fully_ok
    assert row.bytes_restored and row.integrity_ok and row.password_ok


@pytest.mark.parametrize("label,size", MINI_ROWS, ids=lambda v: v)
def test_mini_rows_cannot_restore_plaintext(label, size):
    # Documents the consequence of the mini-stream defect: even a correct
    # password cannot recover the original package bytes for these sizes.
    payload = make_payload(size)
    result = decrypt_container(encrypt_fixture(payload), PASSWORD)
    assert result.password_verified  # password derivation itself is sound
    assert not result.integrity_ok or result.plaintext != payload


def test_wrong_password_is_rejected():
    blob = encrypt_fixture(make_payload(64_000))
    result = decrypt_container(blob, "definitely-wrong-password")
    assert not result.password_verified
