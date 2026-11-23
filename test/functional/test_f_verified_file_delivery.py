# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for verified, atomic streaming decryption delivery."""
import io
import os

import attr
import pytest

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.file_delivery import (
    DeliveryAbortedError,
    DeliveryStatus,
    DeliveryVerificationError,
    DeliveryWriteError,
)
from aws_encryption_sdk.identifiers import Algorithm, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.defaults import FRAME_LENGTH
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]

PLAINTEXT = b"archive-record:" + b"0123456789abcdef" * 64  # 1037 bytes, several frames
SIGNED_ALGORITHM = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
UNSIGNED_ALGORITHM = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
STATIC_KEY = b"0123456789abcdef0123456789abcdef"


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    static_key = attr.ib()


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "local-static"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self.config.static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def build_key_provider():
    provider = StaticRawMasterKeyProvider(static_key=STATIC_KEY)
    provider.add_master_key(b"archive-key")
    return provider


def encrypt(client, key_provider, plaintext=PLAINTEXT, algorithm=SIGNED_ALGORITHM, frame_length=FRAME_LENGTH):
    ciphertext, _header = client.encrypt(
        source=plaintext,
        key_provider=key_provider,
        algorithm=algorithm,
        frame_length=frame_length,
    )
    return ciphertext


class NoSeekReader(object):
    """Non-rewindable reader that only offers ``read``."""

    def __init__(self, data):
        self._buffer = io.BytesIO(data)
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        return self._buffer.read(size)

    def seekable(self):
        return False

    def seek(self, *args, **kwargs):
        raise OSError("seek is not supported")

    def tell(self):
        raise OSError("tell is not supported")


class FailingAfter(object):
    """Reader that returns ``prefix`` then raises (simulates a broken user read)."""

    def __init__(self, data, keep):
        self._data = data
        self._keep = keep
        self._position = 0

    def read(self, size=-1):
        if self._position >= self._keep:
            raise OSError("simulated read failure")
        end = len(self._data) if size is None or size < 0 else min(len(self._data), self._position + size)
        end = min(end, self._keep)
        chunk = self._data[self._position:end]
        self._position = end
        return chunk


def directory_entries(directory):
    return sorted(os.listdir(directory))


@pytest.fixture
def client():
    return aws_encryption_sdk.EncryptionSDKClient()


@pytest.fixture
def key_provider():
    return build_key_provider()


def test_commit_publishes_complete_plaintext_once(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"

    result = client.decrypt_to_file(
        source=NoSeekReader(ciphertext),
        destination=str(destination),
        key_provider=key_provider,
    ).commit()

    assert result.status is DeliveryStatus.COMMITTED
    assert result.committed
    assert result.bytes_written == len(PLAINTEXT)
    assert result.signed and result.signature_verified
    assert destination.read_bytes() == PLAINTEXT
    assert directory_entries(str(tmp_path)) == ["record.bin"]


def test_unsigned_message_is_delivered_without_signature(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider, algorithm=UNSIGNED_ALGORITHM)
    destination = tmp_path / "unsigned.bin"

    result = client.decrypt_to_file(
        source=NoSeekReader(ciphertext), destination=str(destination), key_provider=key_provider
    ).commit()

    assert result.committed
    assert not result.signed and not result.signature_verified
    assert destination.read_bytes() == PLAINTEXT


def test_existing_stream_entry_points_still_serve_callers(client, key_provider):
    ciphertext = encrypt(client, key_provider)
    with client.stream(mode="d", source=io.BytesIO(ciphertext), key_provider=key_provider) as decryptor:
        streamed = decryptor.read()
    assert streamed == PLAINTEXT


def test_truncated_message_publishes_nothing(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"
    truncated = ciphertext[:-40]  # remove part of the footer / final frame tag

    delivery = client.decrypt_to_file(
        source=NoSeekReader(truncated), destination=str(destination), key_provider=key_provider
    )
    with pytest.raises((DeliveryVerificationError, SerializationError)):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert not destination.exists()
    assert directory_entries(str(tmp_path)) == []


def test_bad_signature_publishes_nothing(client, key_provider, tmp_path):
    ciphertext = bytearray(encrypt(client, key_provider))
    ciphertext[-1] ^= 0xFF  # corrupt the footer signature
    destination = tmp_path / "record.bin"

    delivery = client.decrypt_to_file(
        source=NoSeekReader(bytes(ciphertext)), destination=str(destination), key_provider=key_provider
    )
    with pytest.raises((DeliveryVerificationError, SerializationError)):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert not destination.exists()
    assert directory_entries(str(tmp_path)) == []


def test_read_failure_mid_message_publishes_nothing(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"

    # First frame (and part of the header) is readable; the rest fails.
    delivery = client.decrypt_to_file(
        source=FailingAfter(ciphertext, keep=len(ciphertext) // 3),
        destination=str(destination),
        key_provider=key_provider,
    )
    with pytest.raises(DeliveryVerificationError):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert not destination.exists()
    assert directory_entries(str(tmp_path)) == []


def test_receiver_write_failure_leaves_no_partial_file(client, key_provider, tmp_path, monkeypatch):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"

    def broken_replace(src, dst):
        raise OSError("simulated receiver failure")

    monkeypatch.setattr(os, "replace", broken_replace)
    delivery = client.decrypt_to_file(
        source=NoSeekReader(ciphertext), destination=str(destination), key_provider=key_provider
    )
    with pytest.raises(DeliveryWriteError):
        delivery.commit()

    assert delivery.status is DeliveryStatus.FAILED
    assert not destination.exists()
    assert directory_entries(str(tmp_path)) == []


def test_close_before_commit_is_aborted_not_committed(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"

    with client.decrypt_to_file(
        source=NoSeekReader(ciphertext), destination=str(destination), key_provider=key_provider
    ) as delivery:
        delivery.header  # noqa: B018 - header read is allowed before commit

    assert delivery.status is DeliveryStatus.ABORTED
    assert delivery.result.aborted
    assert not delivery.result.committed
    assert not destination.exists()
    assert directory_entries(str(tmp_path)) == []


def test_aborted_delivery_cannot_be_committed(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"
    delivery = client.decrypt_to_file(
        source=NoSeekReader(ciphertext), destination=str(destination), key_provider=key_provider
    )
    delivery.close()

    with pytest.raises(DeliveryAbortedError):
        delivery.commit()
    assert not destination.exists()


def test_commit_is_idempotent_on_success(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"
    delivery = client.decrypt_to_file(
        source=NoSeekReader(ciphertext), destination=str(destination), key_provider=key_provider
    )

    first = delivery.commit()
    second = delivery.commit()

    assert first is second
    assert destination.read_bytes() == PLAINTEXT
    assert directory_entries(str(tmp_path)) == ["record.bin"]


@pytest.mark.parametrize("memory_limit", [0, 64])
def test_bounded_staging_handles_large_message(client, key_provider, tmp_path, memory_limit):
    plaintext = b"x" * (FRAME_LENGTH * 8 + 17)
    ciphertext = encrypt(client, key_provider, plaintext=plaintext)
    destination = tmp_path / "large.bin"

    delivery = client.decrypt_to_file(
        source=NoSeekReader(ciphertext),
        destination=str(destination),
        key_provider=key_provider,
        staging_memory_limit=memory_limit,
    )
    result = delivery.commit()

    assert result.committed
    assert result.bytes_written == len(plaintext)
    assert destination.read_bytes() == plaintext


def test_two_records_same_first_segment_success_and_failure(client, key_provider, tmp_path):
    """Both records start with the same plaintext prefix; only the good one publishes."""
    first = encrypt(client, key_provider)
    second = encrypt(client, key_provider)
    assert first != second
    destination = tmp_path / "record.bin"

    good = client.decrypt_to_file(
        source=NoSeekReader(first), destination=str(destination), key_provider=key_provider
    )
    bad = client.decrypt_to_file(
        source=NoSeekReader(second[:-32]), destination=str(destination), key_provider=key_provider
    )

    # Neither delivery has published anything before commit.
    assert directory_entries(str(tmp_path)) == []
    assert good.staged_bytes == 0 and bad.staged_bytes == 0

    assert good.commit().committed
    assert destination.read_bytes() == PLAINTEXT
    assert directory_entries(str(tmp_path)) == ["record.bin"]

    with pytest.raises((DeliveryVerificationError, SerializationError)):
        bad.commit()

    # The failed delivery must not add a temporary version for consumers to see,
    # and the committed file must remain exactly as the good delivery left it.
    assert bad.status is DeliveryStatus.FAILED
    assert directory_entries(str(tmp_path)) == ["record.bin"]
    assert destination.read_bytes() == PLAINTEXT


def test_oversized_staging_is_not_left_behind_after_failure(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    destination = tmp_path / "record.bin"
    delivery = client.decrypt_to_file(
        source=NoSeekReader(ciphertext[:-40]),
        destination=str(destination),
        key_provider=key_provider,
        staging_memory_limit=0,
    )
    with pytest.raises((DeliveryVerificationError, SerializationError)):
        delivery.commit()

    assert delivery.staging_discarded
    assert directory_entries(str(tmp_path)) == []


def test_staging_directory_removed_after_failure_and_abort(client, key_provider, tmp_path):
    ciphertext = encrypt(client, key_provider)
    staging_root = tmp_path / "staging"
    staging_root.mkdir()
    destination = tmp_path / "record.bin"

    failing = client.decrypt_to_file(
        source=NoSeekReader(ciphertext[:-40]),
        destination=str(destination),
        key_provider=key_provider,
        staging_dir=str(staging_root),
        staging_memory_limit=0,
    )
    with pytest.raises((DeliveryVerificationError, SerializationError)):
        failing.commit()
    assert directory_entries(str(staging_root)) == []
    assert not destination.exists()

    aborted = client.decrypt_to_file(
        source=NoSeekReader(ciphertext),
        destination=str(destination),
        key_provider=key_provider,
        staging_dir=str(staging_root),
    )
    aborted.header  # noqa: B018
    aborted.close()
    assert directory_entries(str(staging_root)) == []
    assert not destination.exists()


def test_non_framed_large_message_is_delivered_bounded(client, key_provider, tmp_path):
    plaintext = b"n" * (5 * 1024 * 1024 + 3)
    ciphertext = encrypt(client, key_provider, plaintext=plaintext, frame_length=0)
    destination = tmp_path / "unframed.bin"
    staging_root = tmp_path / "staging"
    staging_root.mkdir()

    result = client.decrypt_to_file(
        source=NoSeekReader(ciphertext),
        destination=str(destination),
        key_provider=key_provider,
        staging_dir=str(staging_root),
        staging_memory_limit=1024,
    ).commit()

    assert result.committed
    assert result.bytes_written == len(plaintext)
    assert destination.read_bytes() == plaintext
    assert directory_entries(str(staging_root)) == []
