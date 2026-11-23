# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for aws_encryption_sdk.file_delivery."""
import io
import os

import pytest
from mock import MagicMock, patch

import aws_encryption_sdk.file_delivery as file_delivery
from aws_encryption_sdk.file_delivery import (
    DeliveryAbortedError,
    DeliveryError,
    DeliveryStatus,
    DeliveryVerificationError,
    DeliveryWriteError,
    VerifiedFileDelivery,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class FakeDecryptor(object):
    def __init__(self, chunks, header=None, footer=True, error=None):
        self._chunks = list(chunks)
        self._error = error
        self.header = header if header is not None else MagicMock()
        self.header.algorithm.is_signing.return_value = True
        self.closed = False
        if footer:
            self.footer = MagicMock()

    def read(self, size=-1):
        if self._error is not None:
            raise self._error
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self):
        self.closed = True


def _build(tmp_path, decryptor, destination="out.bin", **kwargs):
    with patch("aws_encryption_sdk.file_delivery._build_decryptor", return_value=decryptor):
        return VerifiedFileDelivery(
            source=io.BytesIO(b"ciphertext"),
            destination=str(tmp_path / destination),
            key_provider=MagicMock(),
            **kwargs
        )


def test_commit_writes_plaintext_and_cleans_staging(tmp_path):
    decryptor = FakeDecryptor([b"abc", b"def"])
    delivery = _build(tmp_path, decryptor)

    result = delivery.commit()

    assert result.status is DeliveryStatus.COMMITTED
    assert result.bytes_written == 6
    assert result.signed and result.signature_verified
    assert (tmp_path / "out.bin").read_bytes() == b"abcdef"
    assert delivery.staging_discarded
    assert decryptor.closed


def test_close_before_commit_records_aborted(tmp_path):
    decryptor = FakeDecryptor([b"abc"])
    delivery = _build(tmp_path, decryptor)

    result = delivery.close()

    assert result.status is DeliveryStatus.ABORTED
    assert result.aborted
    assert not (tmp_path / "out.bin").exists()
    assert delivery.staging_discarded


def test_commit_after_close_raises(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([b"abc"]))
    delivery.close()

    with pytest.raises(DeliveryAbortedError):
        delivery.commit()


def test_verification_error_leaves_no_file(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([b"abc"], footer=False))

    with pytest.raises(DeliveryVerificationError):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert not (tmp_path / "out.bin").exists()
    assert delivery.staging_discarded


def test_read_error_wrapped_and_cleaned(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([], error=OSError("boom")))

    with pytest.raises(DeliveryVerificationError):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert delivery.result.error is not None
    assert not (tmp_path / "out.bin").exists()


def test_commit_after_failure_raises_delivery_error(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([], error=OSError("boom")))
    with pytest.raises(DeliveryVerificationError):
        delivery.commit()

    with pytest.raises(DeliveryError):
        delivery.commit()


def test_publish_failure_is_write_error_and_cleans_up(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([b"abc"]))

    with patch("aws_encryption_sdk.file_delivery._publish", side_effect=OSError("disk full")):
        with pytest.raises(DeliveryWriteError):
            delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert sorted(os.listdir(str(tmp_path))) == []
    assert delivery.staging_discarded


def test_commit_is_idempotent(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([b"abc"]))
    first = delivery.commit()
    second = delivery.commit()
    assert first is second


def test_unsigned_message_reports_no_signature(tmp_path):
    decryptor = FakeDecryptor([b"abc"])
    decryptor.header.algorithm.is_signing.return_value = False
    delivery = _build(tmp_path, decryptor)

    result = delivery.commit()

    assert not result.signed and not result.signature_verified


def test_staging_rolls_over_with_zero_memory_limit(tmp_path):
    delivery = _build(tmp_path, FakeDecryptor([b"abc"]), staging_memory_limit=0)
    assert delivery.staging_on_disk
    delivery.close()


def test_invalid_arguments_rejected(tmp_path):
    with pytest.raises(ValueError):
        _build(tmp_path, FakeDecryptor([]), destination=".")
    with pytest.raises(ValueError):
        _build(tmp_path, FakeDecryptor([]), staging_memory_limit=-1)
    with pytest.raises(ValueError):
        _build(tmp_path, FakeDecryptor([]), staging_dir=str(tmp_path / "missing"))


def test_copy_stream_uses_bounded_chunks():
    class Source(object):
        def __init__(self, chunks):
            self._chunks = list(chunks)
            self.sizes = []

        def read(self, size):
            self.sizes.append(size)
            return self._chunks.pop(0) if self._chunks else b""

    destination = io.BytesIO()
    source = Source([b"a" * 5, b"b" * 5])
    copied = file_delivery._copy_stream(source, destination, chunk_size=2)
    assert copied == 10
    assert destination.getvalue() == b"a" * 5 + b"b" * 5
    assert all(size == 2 for size in source.sizes)
