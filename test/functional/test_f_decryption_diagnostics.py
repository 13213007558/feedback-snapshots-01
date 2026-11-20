# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for opt-in, redacted decryption failure diagnostics."""
import attr
import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.diagnostics import (
    DecryptionFailureCategory,
    DecryptionFailurePhase,
    safe_decryption_diagnostic,
)
from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError,
    CustomMaximumValueExceeded,
    DecryptKeyError,
    SerializationError,
)
from aws_encryption_sdk.identifiers import Algorithm, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.internal.formatting import header_length
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]

SENSITIVE_EC_KEY = "deployment"
SENSITIVE_EC_VALUE = "secret-tenant-施工-do-not-log"
PLAINTEXT = b"archive record contents"


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    wrapping_algorithm = attr.ib()
    encryption_key_type = attr.ib()
    key_bytes = attr.ib(default=None)


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Local fake provider backed by static key bytes; never contacts the network."""

    provider_id = "ProviderName"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=self.config.wrapping_algorithm,
            wrapping_key=self.config.key_bytes,
            wrapping_key_type=self.config.encryption_key_type,
        )


class UnavailableMaterialProvider(StaticRawMasterKeyProvider):
    """Fake provider that can encrypt but has no material available at decrypt time."""

    def decrypt_data_key_from_list(self, encrypted_data_keys, algorithm, encryption_context):
        root_error = IOError("material store unavailable for {!r}".format(SENSITIVE_EC_VALUE))
        raise DecryptKeyError(
            "provider could not load material for {!r}".format(SENSITIVE_EC_VALUE)
        ) from root_error


def _provider(key_bytes):
    provider = StaticRawMasterKeyProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=key_bytes,
    )
    provider.add_master_key("KeyId")
    return provider


def _unavailable_provider(key_bytes):
    provider = UnavailableMaterialProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=key_bytes,
    )
    provider.add_master_key("KeyId")
    return provider


def _client(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT):
    return aws_encryption_sdk.EncryptionSDKClient(commitment_policy=commitment_policy)


def _encrypt(client, provider, algorithm=None):
    ciphertext, header = client.encrypt(
        source=PLAINTEXT,
        key_provider=provider,
        encryption_context={SENSITIVE_EC_KEY: SENSITIVE_EC_VALUE},
        algorithm=algorithm,
    )
    return ciphertext, header


def _assert_redacted(diagnostic):
    rendered = "{} {}".format(diagnostic, diagnostic.as_dict())
    assert SENSITIVE_EC_KEY not in rendered
    assert SENSITIVE_EC_VALUE not in rendered
    assert "secret" not in rendered


def test_configuration_rejection_keeps_original_exception():
    # Non-committing message, then a decryptor that requires committed messages.
    encrypt_client = _client(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    ciphertext, _ = _encrypt(
        encrypt_client, _provider(b"\x01" * 32), algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
    )

    with pytest.raises(ActionNotAllowedError) as excinfo:
        _client().decrypt(source=ciphertext, key_provider=_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.CONFIGURATION
    assert diagnostic.category is DecryptionFailureCategory.CONFIGURATION_REJECTED
    _assert_redacted(diagnostic)


def test_materials_unavailable_from_fake_provider(tmp_path):
    """Local file plus a fake provider with no material: classify as unavailable."""
    client = _client()
    ciphertext, _ = _encrypt(client, _provider(b"\x01" * 32))
    ciphertext_path = tmp_path / "archive-record.ct"
    ciphertext_path.write_bytes(ciphertext)

    with ciphertext_path.open("rb") as ciphertext_file:
        with pytest.raises(DecryptKeyError) as excinfo:
            client.decrypt(source=ciphertext_file, key_provider=_unavailable_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.GET_DECRYPTION_MATERIALS
    assert diagnostic.category is DecryptionFailureCategory.MATERIALS_UNAVAILABLE
    # Local troubleshooting detail is still available on the original exception chain.
    assert SENSITIVE_EC_VALUE in str(excinfo.value)
    assert "material store unavailable" in str(excinfo.value.__cause__)
    _assert_redacted(diagnostic)


def test_integrity_failure_from_local_file(tmp_path):
    """Local file with a tampered frame body: classify as an integrity failure."""
    client = _client()
    ciphertext, header = _encrypt(client, _provider(b"\x01" * 32))
    body_content_start = header_length(header) + 4 + header.algorithm.iv_len + 1
    tampered = bytearray(ciphertext)
    tampered[body_content_start] ^= 0x01

    ciphertext_path = tmp_path / "tampered-record.ct"
    ciphertext_path.write_bytes(bytes(tampered))

    with ciphertext_path.open("rb") as ciphertext_file:
        with pytest.raises(InvalidTag) as excinfo:
            client.decrypt(source=ciphertext_file, key_provider=_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.DECRYPT_BODY
    assert diagnostic.category is DecryptionFailureCategory.INTEGRITY_FAILED
    _assert_redacted(diagnostic)


def test_provider_tag_failure_is_integrity_not_unavailable():
    """A wrapped-key authentication failure is an integrity failure, not missing material."""
    client = _client()
    ciphertext, _ = _encrypt(client, _provider(b"\x01" * 32))

    with pytest.raises(InvalidTag) as excinfo:
        client.decrypt(source=ciphertext, key_provider=_provider(b"\x02" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.GET_DECRYPTION_MATERIALS
    assert diagnostic.category is DecryptionFailureCategory.INTEGRITY_FAILED


def test_header_authorization_failure_is_integrity_and_keeps_cause():
    client = _client()
    ciphertext, header = _encrypt(client, _provider(b"\x01" * 32))
    # The header authentication tag follows the serialized header body.
    header_auth_tag_index = header_length(header) - 1
    tampered = bytearray(ciphertext)
    tampered[header_auth_tag_index] ^= 0x01

    with pytest.raises(SerializationError) as excinfo:
        client.decrypt(source=bytes(tampered), key_provider=_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.VERIFY_HEADER
    assert diagnostic.category is DecryptionFailureCategory.INTEGRITY_FAILED
    # The original root cause for local debugging is preserved.
    assert isinstance(excinfo.value.__cause__, InvalidTag)
    _assert_redacted(diagnostic)


def test_signature_failure_is_integrity():
    client = _client()
    ciphertext, _ = _encrypt(client, _provider(b"\x01" * 32))
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01

    with pytest.raises(InvalidSignature) as excinfo:
        client.decrypt(source=bytes(tampered), key_provider=_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.phase is DecryptionFailurePhase.VERIFY_SIGNATURE
    assert diagnostic.category is DecryptionFailureCategory.INTEGRITY_FAILED
    _assert_redacted(diagnostic)


def test_existing_except_clauses_continue_to_work():
    encrypt_client = _client(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    ciphertext, _ = _encrypt(
        encrypt_client, _provider(b"\x01" * 32), algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
    )
    claimed_original_type = False

    try:
        _client().decrypt(source=ciphertext, key_provider=_provider(b"\x01" * 32))
    except ActionNotAllowedError:
        claimed_original_type = True

    assert claimed_original_type


def test_malformed_message_is_not_reported_as_integrity_failure():
    client = _client()
    ciphertext, _ = _encrypt(client, _provider(b"\x01" * 32))

    with pytest.raises(SerializationError) as excinfo:
        client.decrypt(source=ciphertext[:3], key_provider=_provider(b"\x01" * 32))

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.category is DecryptionFailureCategory.MALFORMED_MESSAGE
    _assert_redacted(diagnostic)


def test_custom_maximum_value_is_reported_as_configuration_rejection():
    client = _client()
    ciphertext, _ = _encrypt(client, _provider(b"\x01" * 32))

    with pytest.raises(CustomMaximumValueExceeded) as excinfo:
        client.decrypt(
            source=ciphertext,
            key_provider=_provider(b"\x01" * 32),
            max_body_length=1,
        )

    diagnostic = safe_decryption_diagnostic(excinfo.value)
    assert diagnostic.category is DecryptionFailureCategory.CONFIGURATION_REJECTED
    _assert_redacted(diagnostic)
