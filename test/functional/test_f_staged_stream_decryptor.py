# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional test suite for aws_encryption_sdk.staged_streaming_client.StagedStreamDecryptor"""
import io
import os
import secrets

import attr
import pytest

import aws_encryption_sdk
from aws_encryption_sdk import StagedStreamDecryptor
from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.identifiers import (
    Algorithm,
    CommitmentPolicy,
    EncryptionKeyType,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    static_key = attr.ib()


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "test-static"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self.config.static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


@pytest.fixture
def key_provider():
    provider = StaticRawMasterKeyProvider(static_key=secrets.token_bytes(32))
    provider.add_master_key(b"key")
    return provider


@pytest.fixture
def client():
    return aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )


@pytest.fixture
def signed_ciphertext(client, key_provider):
    plaintext = b"staged-archive-payload" * 200
    ciphertext, _ = client.encrypt(
        source=plaintext,
        key_provider=key_provider,
        frame_length=256,
        algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    )
    return plaintext, ciphertext


def build_staged(client, ciphertext, key_provider, staging_dir, spool_size):
    return client.stream(
        mode="decrypt-staged",
        source=io.BytesIO(ciphertext),
        key_provider=key_provider,
        staging_spool_size=spool_size,
        staging_dir=staging_dir,
    )


def test_stream_returns_staged_decryptor(client, key_provider, signed_ciphertext):
    _, ciphertext = signed_ciphertext
    with client.stream(
        mode="decrypt-staged", source=io.BytesIO(ciphertext), key_provider=key_provider
    ) as staged:
        assert isinstance(staged, StagedStreamDecryptor)
        staged.read()


def test_roundtrip_releases_plaintext_only_after_authentication(client, key_provider, signed_ciphertext):
    plaintext, ciphertext = signed_ciphertext
    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        assert staged.authenticated is False
        assert staged.read() == plaintext
        assert staged.authenticated is True


def test_no_data_before_first_read(client, key_provider, signed_ciphertext):
    plaintext, ciphertext = signed_ciphertext
    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        # The header is available, but no plaintext has been published yet.
        assert staged.header is not None
        assert staged.tell() == 0
        assert staged.authenticated is False
        first = staged.read(32)
        assert first == plaintext[:32]
        assert staged.read() == plaintext[32:]


def test_spills_to_disk_beyond_threshold_and_cleans_up(client, key_provider, signed_ciphertext, tmp_path):
    plaintext, ciphertext = signed_ciphertext
    staging_dir = str(tmp_path)
    with build_staged(client, ciphertext, key_provider, staging_dir, 256) as staged:
        assert staged.staging_on_disk is False
        assert staged.staging_path is None
        staged.read()
        assert staged.staging_on_disk is True
        staging_path = staged.staging_path
        assert staging_path is not None
        assert os.path.dirname(staging_path) == staging_dir
        assert os.path.exists(staging_path)
    assert not os.path.exists(staging_path)
    assert os.listdir(staging_dir) == []


def test_message_under_threshold_stays_in_memory(client, key_provider, tmp_path):
    plaintext = b"tiny"
    ciphertext, _ = client.encrypt(source=plaintext, key_provider=key_provider)
    with build_staged(client, ciphertext, key_provider, str(tmp_path), 4096) as staged:
        staged.read()
        assert staged.staging_on_disk is False
        assert staged.staging_path is None
    assert os.listdir(str(tmp_path)) == []


def test_truncated_message_releases_nothing_and_cleans_up(client, key_provider, signed_ciphertext, tmp_path):
    _, ciphertext = signed_ciphertext
    truncated = ciphertext[: len(ciphertext) // 2]
    staging_dir = str(tmp_path)
    with pytest.raises(SerializationError):
        with build_staged(client, truncated, key_provider, staging_dir, 256) as staged:
            staged.read()
    assert staged.authenticated is False
    assert os.listdir(staging_dir) == []


def test_bad_signature_releases_nothing_and_cleans_up(client, key_provider, signed_ciphertext, tmp_path):
    plaintext, ciphertext = signed_ciphertext
    # Locate the footer signature from a successful parse, then tamper with it.
    with client.stream(mode="d", source=io.BytesIO(ciphertext), key_provider=key_provider) as probe:
        probe.read()
        signature_length = len(probe.footer.signature)
    signature_offset = len(ciphertext) - signature_length
    tampered = bytearray(ciphertext)
    tampered[signature_offset + signature_length // 2] ^= 0xFF

    staging_dir = str(tmp_path)
    with pytest.raises(Exception):
        with build_staged(client, bytes(tampered), key_provider, staging_dir, 256) as staged:
            staged.read()
    assert staged.authenticated is False
    assert os.listdir(staging_dir) == []


def test_interruption_before_reading_cleans_up(client, key_provider, signed_ciphertext, tmp_path):
    _, ciphertext = signed_ciphertext
    staging_dir = str(tmp_path)
    staged = build_staged(client, ciphertext, key_provider, staging_dir, 256)
    # Caller abandons the stream without ever reading any publishable data.
    with pytest.raises(SerializationError):
        staged.close()
    assert staged.closed is True
    assert os.listdir(staging_dir) == []


def test_non_framed_message_roundtrip(client, key_provider, tmp_path):
    plaintext = b"non-framed archive contents" * 50
    ciphertext, _ = client.encrypt(source=plaintext, key_provider=key_provider, frame_length=0)
    with build_staged(client, ciphertext, key_provider, str(tmp_path), 128) as staged:
        assert staged.read() == plaintext
        assert staged.authenticated is True


def test_iteration_and_readlines_block_until_authenticated(client, key_provider, signed_ciphertext):
    plaintext, ciphertext = signed_ciphertext
    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        chunks = list(staged)
    assert b"".join(chunks) == plaintext

    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        assert b"".join(staged.readlines()) == plaintext


def test_read_after_close_raises(client, key_provider, signed_ciphertext):
    _, ciphertext = signed_ciphertext
    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        staged.read()
    with pytest.raises(ValueError):
        staged.read()


def test_invalid_construction_arguments(client, key_provider, signed_ciphertext):
    _, ciphertext = signed_ciphertext
    with pytest.raises(ValueError):
        StagedStreamDecryptor(
            staging_spool_size=-1, source=io.BytesIO(ciphertext), key_provider=key_provider
        )
    with pytest.raises(ValueError):
        StagedStreamDecryptor(
            staging_dir="/no/such/directory/should/exist",
            source=io.BytesIO(ciphertext),
            key_provider=key_provider,
        )


def test_write_operations_rejected(client, key_provider, signed_ciphertext):
    _, ciphertext = signed_ciphertext
    with build_staged(client, ciphertext, key_provider, None, 10 * 1024 * 1024) as staged:
        assert staged.writable() is False
        with pytest.raises(NotImplementedError):
            staged.write(b"data")
        with pytest.raises(NotImplementedError):
            staged.seek(0)
        staged.read()
