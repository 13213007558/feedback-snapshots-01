# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for the configurable message header byte budget."""
import io
import struct

import attr
import pytest

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import MaxHeaderLengthExceeded
from aws_encryption_sdk.identifiers import (
    Algorithm,
    CommitmentPolicy,
    ContentType,
    EncryptionKeyType,
    ObjectType,
    SerializationVersion,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.formatting import header_length
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_header
from aws_encryption_sdk.internal.formatting.serialize import serialize_header
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo, MessageHeader

pytestmark = [pytest.mark.functional, pytest.mark.local]

RAW_KEY = b"01234567890123456789012345678901"
KEY_ID = b"archive-key"
PROVIDER_ID = "raw"


@attr.s(hash=False)
class _RawKeyProviderConfig(MasterKeyProviderConfig):
    pass


class _LocalRawKeyProvider(RawMasterKeyProvider):
    provider_id = PROVIDER_ID
    _config_class = _RawKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=RAW_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def _key_provider():
    provider = _LocalRawKeyProvider()
    provider.add_master_key(KEY_ID)
    return provider


class _CountingMaterialsManager(CryptoMaterialsManager):
    """CMM that records whether decryption materials were requested."""

    def __init__(self):
        self._inner = DefaultCryptoMaterialsManager(master_key_provider=_key_provider())
        self.decrypt_materials_calls = 0

    def get_encryption_materials(self, request):
        return self._inner.get_encryption_materials(request)

    def decrypt_materials(self, request):
        self.decrypt_materials_calls += 1
        return self._inner.decrypt_materials(request)


class _ShortReadStream(io.BytesIO):
    """Returns at most a few bytes per read to exercise partial header reads."""

    def __init__(self, data, max_chunk=3):
        super(_ShortReadStream, self).__init__(data)
        self._max_chunk = max_chunk

    def read(self, size=-1):
        if size is None or size < 0:
            size = self._max_chunk
        return super(_ShortReadStream, self).read(min(size, self._max_chunk))


def _algorithm_cases():
    return (
        (Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256, CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT),
        (Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY, CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT),
    )


def _make_archive(algorithm, commitment_policy, plaintext, frame_length):
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=commitment_policy)
    ciphertext, header = client.encrypt(
        source=plaintext,
        key_provider=_key_provider(),
        algorithm=algorithm,
        frame_length=frame_length,
        encryption_context={"purpose": "archive"},
    )
    return ciphertext, header


def _decrypt(source, max_header_length=None):
    cmm = _CountingMaterialsManager()
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        max_header_length=max_header_length,
    )
    plaintext, header = client.decrypt(source=source, materials_manager=cmm)
    return plaintext, header, cmm


@pytest.mark.parametrize("algorithm, commitment_policy", _algorithm_cases())
@pytest.mark.parametrize("frame_length", (0, 1024))
def test_exact_header_budget_allows_archive(algorithm, commitment_policy, frame_length):
    plaintext = b"archive body " * 500
    ciphertext, header = _make_archive(algorithm, commitment_policy, plaintext, frame_length)
    budget = header_length(header)

    decrypted, decrypt_header, cmm = _decrypt(ciphertext, max_header_length=budget)

    assert decrypted == plaintext
    assert decrypt_header.encryption_context == {"purpose": "archive"}
    assert cmm.decrypt_materials_calls == 1


@pytest.mark.parametrize("algorithm, commitment_policy", _algorithm_cases())
def test_header_one_byte_over_budget_rejected_before_key_request(algorithm, commitment_policy):
    ciphertext, header = _make_archive(algorithm, commitment_policy, b"small body", 1024)
    budget = header_length(header) - 1
    cmm = _CountingMaterialsManager()
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        max_header_length=budget,
    )

    with pytest.raises(MaxHeaderLengthExceeded) as excinfo:
        client.decrypt(source=ciphertext, materials_manager=cmm)

    assert "{} > {}".format(header_length(header), budget) in str(excinfo.value)
    assert cmm.decrypt_materials_calls == 0


@pytest.mark.parametrize("algorithm, commitment_policy", _algorithm_cases())
@pytest.mark.parametrize("max_chunk", (1, 2, 3, 7))
def test_short_read_header_budget(algorithm, commitment_policy, max_chunk):
    plaintext = b"archive body " * 100
    ciphertext, header = _make_archive(algorithm, commitment_policy, plaintext, 512)
    budget = header_length(header)

    plaintext_out, _, cmm = _decrypt(_ShortReadStream(ciphertext, max_chunk), max_header_length=budget)
    assert plaintext_out == plaintext
    assert cmm.decrypt_materials_calls == 1

    cmm = _CountingMaterialsManager()
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        max_header_length=budget - 1,
    )
    with pytest.raises(MaxHeaderLengthExceeded):
        client.decrypt(source=_ShortReadStream(ciphertext, max_chunk), materials_manager=cmm)
    assert cmm.decrypt_materials_calls == 0


@pytest.mark.parametrize("algorithm, commitment_policy", _algorithm_cases())
def test_valid_archive_with_header_over_budget_is_rejected(algorithm, commitment_policy):
    """A legitimately produced archive whose header exceeds the budget is rejected."""
    encryption_context = {"archive-metadata-{}".format(i): "v" * 64 for i in range(20)}
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=commitment_policy)
    ciphertext, header = client.encrypt(
        source=b"valid body",
        key_provider=_key_provider(),
        algorithm=algorithm,
        frame_length=1024,
        encryption_context=encryption_context,
    )
    full_header_length = header_length(header)
    budget = full_header_length // 2

    cmm = _CountingMaterialsManager()
    decrypt_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        max_header_length=budget,
    )
    with pytest.raises(MaxHeaderLengthExceeded):
        decrypt_client.decrypt(source=ciphertext, materials_manager=cmm)

    assert cmm.decrypt_materials_calls == 0

    # The same archive decrypts once the budget accommodates its header.
    plaintext, decrypt_header, cmm = _decrypt(ciphertext, max_header_length=full_header_length)
    assert plaintext == b"valid body"
    assert decrypt_header.encryption_context == encryption_context
    assert cmm.decrypt_materials_calls == 1


@pytest.mark.parametrize("algorithm, commitment_policy", _algorithm_cases())
def test_body_larger_than_header_budget_still_streams(algorithm, commitment_policy):
    """A body larger than the header budget must still decrypt."""
    plaintext = b"x" * (16 * 1024)
    ciphertext, header = _make_archive(algorithm, commitment_policy, plaintext, 1024)
    budget = header_length(header)

    assert len(ciphertext) > budget * 10

    decryptor = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        max_header_length=budget,
    ).stream(
        mode="d",
        source=io.BytesIO(ciphertext),
        materials_manager=_CountingMaterialsManager(),
    )
    with decryptor:
        chunks = []
        while True:
            chunk = decryptor.read(256)
            if not chunk:
                break
            chunks.append(chunk)
    assert b"".join(chunks) == plaintext


def test_explicit_decryptor_config_accepts_header_budget():
    ciphertext, header = _make_archive(
        Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        b"body",
        0,
    )
    config = aws_encryption_sdk.streaming_client.DecryptorConfig(
        source=ciphertext,
        key_provider=_key_provider(),
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        max_header_length=header_length(header),
    )
    decryptor = aws_encryption_sdk.StreamDecryptor(config=config)
    with decryptor:
        assert decryptor.read() == b"body"


def test_config_rejects_non_positive_header_budget():
    with pytest.raises(ValueError) as excinfo:
        aws_encryption_sdk.EncryptionSDKClient(max_header_length=0)
    excinfo.match("max_header_length cannot be less than 1")


def _synthetic_header(version, *, encryption_context, encrypted_data_key_length):
    algorithm = (
        Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        if version == SerializationVersion.V2
        else Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
    )
    key_info = struct.pack(">II", 128, algorithm.iv_len) + b"\x00" * algorithm.iv_len
    return MessageHeader(
        version=version,
        type=ObjectType.CUSTOMER_AE_DATA if version == SerializationVersion.V1 else None,
        algorithm=algorithm,
        message_id=b"m" * algorithm.message_id_length(),
        encryption_context=encryption_context,
        encrypted_data_keys={
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=PROVIDER_ID, key_info=key_info),
                encrypted_data_key=b"k" * encrypted_data_key_length,
            )
        },
        content_type=ContentType.FRAMED_DATA,
        content_aad_length=0 if version == SerializationVersion.V1 else None,
        header_iv_length=algorithm.iv_len if version == SerializationVersion.V1 else None,
        frame_length=1024,
        commitment_key=b"c" * 32 if algorithm.algorithm_suite_data_length() else None,
    )


@pytest.mark.parametrize("version", (SerializationVersion.V1, SerializationVersion.V2))
def test_large_but_valid_synthetic_header_rejected_at_budget(version):
    header = _synthetic_header(version, encryption_context={}, encrypted_data_key_length=64)
    serialized_header = serialize_header(header)
    full_length = len(serialized_header) + (
        header.algorithm.auth_len
        if version == SerializationVersion.V2
        else header.algorithm.iv_len + header.algorithm.auth_len
    )

    parsed, raw = deserialize_header(io.BytesIO(serialized_header), max_header_length=full_length)
    assert raw == serialized_header

    with pytest.raises(MaxHeaderLengthExceeded):
        deserialize_header(io.BytesIO(serialized_header), max_header_length=full_length - 1)


class _RecordingStream(io.BytesIO):
    """Records the largest read request so tests can show a field was never fetched."""

    def __init__(self, data):
        super(_RecordingStream, self).__init__(data)
        self.largest_request = 0

    def read(self, size=-1):
        if size is not None and size > self.largest_request:
            self.largest_request = size
        return super(_RecordingStream, self).read(size)


@pytest.mark.parametrize("version", (SerializationVersion.V1, SerializationVersion.V2))
def test_budget_rejected_using_declared_field_length_before_reading_it(version):
    """An oversized declared encryption-context length is rejected without its bytes being read."""
    header = _synthetic_header(version, encryption_context={}, encrypted_data_key_length=16)
    serialized_header = bytearray(serialize_header(header))

    # Locate the encryption context length field and declare an enormous context.
    if version == SerializationVersion.V1:
        offset = 1 + 1 + 2 + 16  # version, type, algorithm, message id
    else:
        offset = 1 + 2 + 32  # version, algorithm, 32-byte message id
    struct.pack_into(">H", serialized_header, offset, 0xFFFF)

    source = _RecordingStream(bytes(serialized_header))
    with pytest.raises(MaxHeaderLengthExceeded) as excinfo:
        deserialize_header(source, max_header_length=200)

    # Only the length field itself was consumed; the declared payload was never requested.
    assert source.tell() == offset + 2
    assert source.largest_request < 0xFFFF


@pytest.mark.parametrize("version", (SerializationVersion.V1, SerializationVersion.V2))
def test_truncated_header_reports_serialization_error(version):
    header = _synthetic_header(version, encryption_context={}, encrypted_data_key_length=32)
    serialized_header = serialize_header(header)

    with pytest.raises(aws_encryption_sdk.exceptions.SerializationError):
        deserialize_header(io.BytesIO(serialized_header[:-10]), max_header_length=4096)
