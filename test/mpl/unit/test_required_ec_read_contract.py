# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the archive read service decryption path.

The archive read service has two sources of decryption materials:

* the legacy ``RawMasterKeyProvider`` / ``DefaultCryptoMaterialsManager`` for
  plaintext legacy files, and
* an MPL required encryption context CMM backed by a local raw AES keyring for
  messages whose business context is authenticated but not stored in the
  message header.

Existing regression tests only assert whether a decrypt succeeds. These tests
pin the contract that the business-supplied required encryption context is
visible at each of the three distinct steps of a framed and a non-framed read:

1. the decryption materials request handed to the materials manager,
2. the header authentication check, and
3. the plaintext bytes returned to the caller.

Two error classes must stay distinguishable: a disallowed (wrong or missing)
application context is rejected by the materials layer as an
``AWSEncryptionSDKClientError`` before any plaintext exists, while a message
whose packet bytes are corrupted fails the authentication checks with a
``SerializationError`` (header) or ``InvalidTag`` (body).

All key material and message content is generated locally; no network access
or AWS service is required.
"""
import io
import secrets

import attr
import pytest
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    AesWrappingAlg,
    CreateDefaultCryptographicMaterialsManagerInput,
    CreateRawAesKeyringInput,
    CreateRequiredEncryptionContextCMMInput,
)
from cryptography.exceptions import InvalidTag

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import (
    AWSEncryptionSDKClientError,
    SerializationError,
)
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_header
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.materials_managers.mpl.cmm import CryptoMaterialsManagerFromMPL

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Business context required by the keyring/CMM on every read. The value is not
# written to the message header; it is only covered by the header signature.
REQUIRED_CONTEXT_KEY = "archive-tenant"
ALLOWED_CONTEXT = {REQUIRED_CONTEXT_KEY: "tenant-a"}
DISALLOWED_CONTEXT = {REQUIRED_CONTEXT_KEY: "tenant-b"}
# Encryption context entry that is stored in the visible message header.
STORED_CONTEXT = {"archive-class": "cold-storage"}

FRAME_LENGTHS = {
    "framed": 2048,
    "non_framed": 0,
}


class RecordingMaterialsManager(CryptoMaterialsManagerFromMPL):
    """MPL CMM wrapper that records the decryption materials requests it sees."""

    def __init__(self, mpl_cmm):
        super().__init__(mpl_cmm=mpl_cmm)
        self.decryption_materials_requests = []

    def decrypt_materials(self, request):
        self.decryption_materials_requests.append(request)
        return super().decrypt_materials(request)


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    wrapping_algorithm = attr.ib()
    encryption_key_type = attr.ib()
    key_bytes = attr.ib()


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Legacy materials manager fixture: serves one ephemeral local wrapping key."""

    provider_id = "legacy-archive-provider"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=self.config.wrapping_algorithm,
            wrapping_key=self.config.key_bytes,
            wrapping_key_type=self.config.encryption_key_type,
        )


@pytest.fixture
def client():
    return aws_encryption_sdk.EncryptionSDKClient()


@pytest.fixture
def archive_plaintext():
    # Large enough to span multiple frames on the framed read path.
    return secrets.token_bytes(6000)


@pytest.fixture
def required_ec_cmm():
    """Required encryption context CMM over a raw AES keyring with a temp key."""
    mpl_client = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
    keyring = mpl_client.create_raw_aes_keyring(
        CreateRawAesKeyringInput(
            key_namespace="archive-key-namespace",
            key_name="archive-key-name",
            wrapping_key=secrets.token_bytes(32),
            wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16,
        )
    )
    default_cmm = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(keyring=keyring)
    )
    return mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm,
            required_encryption_context_keys=[REQUIRED_CONTEXT_KEY],
        )
    )


@pytest.fixture
def archived_messages(client, required_ec_cmm, archive_plaintext):
    """One required-EC message per framing mode, plus their parsed header objects."""
    messages = {}
    full_encryption_context = dict(STORED_CONTEXT, **ALLOWED_CONTEXT)
    for label, frame_length in FRAME_LENGTHS.items():
        ciphertext, header = client.encrypt(
            source=archive_plaintext,
            materials_manager=required_ec_cmm,
            encryption_context=full_encryption_context,
            frame_length=frame_length,
        )
        parsed_header, raw_header = deserialize_header(io.BytesIO(ciphertext), None)
        messages[label] = {
            "ciphertext": ciphertext,
            "header": header,
            "parsed_header": parsed_header,
            "raw_header_length": len(raw_header),
        }
    return messages


def _streamed_read(client, ciphertext, materials_manager, encryption_context):
    """Drive the streaming read path one chunk at a time and collect plaintext."""
    decryptor = client.stream(
        mode="d",
        source=io.BytesIO(ciphertext),
        materials_manager=materials_manager,
        encryption_context=encryption_context,
    )
    emitted = []
    with decryptor:
        while True:
            chunk = decryptor.read(64)
            if not chunk:
                break
            emitted.append(chunk)
    return b"".join(emitted), decryptor.header


def _with_flipped_byte(ciphertext, offset):
    corrupted = bytearray(ciphertext)
    corrupted[offset] ^= 0xFF
    return bytes(corrupted)


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_required_EC_message_WHEN_read_with_allowed_context_THEN_context_reaches_materials_header_and_plaintext(
    client, archived_messages, required_ec_cmm, archive_plaintext, framing
):
    message = archived_messages[framing]
    recording_cmm = RecordingMaterialsManager(required_ec_cmm)

    # Step 3 (returned content) is exercised via the streaming read path.
    plaintext, decrypt_header = _streamed_read(
        client,
        message["ciphertext"],
        recording_cmm,
        ALLOWED_CONTEXT,
    )

    # Step 1: the business context must travel on the decryption materials
    # request as the reproduced encryption context, while the header-borne
    # context only carries the stored entries.
    assert len(recording_cmm.decryption_materials_requests) == 1
    materials_request = recording_cmm.decryption_materials_requests[0]
    assert materials_request.reproduced_encryption_context == ALLOWED_CONTEXT
    assert materials_request.encryption_context == decrypt_header.encryption_context
    assert REQUIRED_CONTEXT_KEY not in materials_request.encryption_context
    assert STORED_CONTEXT.items() <= materials_request.encryption_context.items()

    # Step 2: the header authenticated successfully (no exception) and exposes
    # the same visible fields that were serialized on encrypt.
    assert decrypt_header.encryption_context == message["header"].encryption_context
    assert decrypt_header.content_type == message["parsed_header"].content_type
    assert decrypt_header.frame_length == message["parsed_header"].frame_length
    assert decrypt_header.algorithm == message["parsed_header"].algorithm
    assert decrypt_header.message_id == message["parsed_header"].message_id
    assert REQUIRED_CONTEXT_KEY not in decrypt_header.encryption_context

    # Step 3: the caller receives the original archive bytes.
    assert plaintext == archive_plaintext


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_two_reads_of_same_message_WHEN_only_context_differs_THEN_disallowed_read_fails_before_plaintext(
    client, archived_messages, required_ec_cmm, archive_plaintext, framing
):
    message = archived_messages[framing]
    allowed_cmm = RecordingMaterialsManager(required_ec_cmm)
    disallowed_cmm = RecordingMaterialsManager(required_ec_cmm)

    # The allowed read succeeds and exposes the visible header contract.
    allowed_plaintext, allowed_header = _streamed_read(
        client, message["ciphertext"], allowed_cmm, ALLOWED_CONTEXT
    )
    assert allowed_plaintext == archive_plaintext

    # The disallowed read presents the same packet and sees identical visible
    # header fields; only the application context supplied to the read differs.
    with pytest.raises(AWSEncryptionSDKClientError):
        decryptor = client.stream(
            mode="d",
            source=io.BytesIO(message["ciphertext"]),
            materials_manager=disallowed_cmm,
            encryption_context=DISALLOWED_CONTEXT,
        )
        with decryptor:
            # The failure is raised while preparing the message on the first
            # read, before any body byte can be returned to the caller.
            decryptor.read(64)

    # Step 1 contract for the failing read: the disallowed context did reach
    # the materials request, and the request header context is the same
    # visible context the successful read received.
    assert len(disallowed_cmm.decryption_materials_requests) == 1
    disallowed_request = disallowed_cmm.decryption_materials_requests[0]
    assert disallowed_request.reproduced_encryption_context == DISALLOWED_CONTEXT
    assert disallowed_request.encryption_context == allowed_header.encryption_context

    # The failing read terminates at the materials layer (step 1/2), so no
    # plaintext is ever emitted and the header never passes authentication.
    assert not hasattr(decryptor, "footer")
    # The successful read proves the packet itself is intact; only the context
    # distinguishes the two outcomes.
    assert allowed_header.encryption_context == message["header"].encryption_context


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_required_EC_message_WHEN_read_without_context_THEN_materials_layer_rejects_before_plaintext(
    client, archived_messages, required_ec_cmm, framing
):
    message = archived_messages[framing]
    recording_cmm = RecordingMaterialsManager(required_ec_cmm)

    with pytest.raises(AWSEncryptionSDKClientError):
        decryptor = client.stream(
            mode="d",
            source=io.BytesIO(message["ciphertext"]),
            materials_manager=recording_cmm,
        )
        with decryptor:
            decryptor.read(64)

    # Missing context is rejected by the required EC CMM inside the materials
    # request, and no body content is returned.
    assert len(recording_cmm.decryption_materials_requests) == 1
    assert recording_cmm.decryption_materials_requests[0].reproduced_encryption_context is None
    assert not hasattr(decryptor, "footer")


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_corrupted_header_auth_WHEN_allowed_context_read_THEN_raises_SerializationError(
    client, archived_messages, required_ec_cmm, framing
):
    message = archived_messages[framing]
    # The header authentication block immediately follows the raw header.
    corrupted_ciphertext = _with_flipped_byte(message["ciphertext"], message["raw_header_length"])
    recording_cmm = RecordingMaterialsManager(required_ec_cmm)

    with pytest.raises(SerializationError, match="Header authorization failed"):
        decryptor = client.stream(
            mode="d",
            source=io.BytesIO(corrupted_ciphertext),
            materials_manager=recording_cmm,
            encryption_context=ALLOWED_CONTEXT,
        )
        with decryptor:
            decryptor.read(64)

    # The materials step succeeded with the allowed context; the packet is
    # rejected one step later at header authentication, without plaintext.
    assert len(recording_cmm.decryption_materials_requests) == 1
    assert recording_cmm.decryption_materials_requests[0].reproduced_encryption_context == ALLOWED_CONTEXT
    assert not hasattr(decryptor, "footer")


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_corrupted_body_WHEN_read_with_allowed_context_THEN_InvalidTag_distinct_from_context_failure(
    client, archived_messages, required_ec_cmm, framing
):
    message = archived_messages[framing]
    header = message["parsed_header"]
    # Skip header, header auth (IV + tag) and the body framing/IV prefix so the
    # flipped byte lands inside the encrypted body.
    body_offset = (
        message["raw_header_length"]
        + header.algorithm.iv_len
        + header.algorithm.auth_len
        + 10
    )
    corrupted_ciphertext = _with_flipped_byte(message["ciphertext"], body_offset)

    with pytest.raises(InvalidTag):
        decryptor = client.stream(
            mode="d",
            source=io.BytesIO(corrupted_ciphertext),
            materials_manager=required_ec_cmm,
            encryption_context=ALLOWED_CONTEXT,
        )
        with decryptor:
            decryptor.read(64)

    # The authenticated body tag fails before any plaintext is released.
    assert not hasattr(decryptor, "footer")


@pytest.mark.parametrize("framing", tuple(FRAME_LENGTHS))
def test_GIVEN_legacy_plaintext_file_WHEN_read_through_legacy_materials_manager_THEN_read_succeeds_without_context(
    client, archive_plaintext, framing
):
    # Success control: a normal stored file encrypted and decrypted through the
    # legacy RawMasterKeyProvider, which has no required encryption context.
    legacy_provider = StaticRawMasterKeyProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=secrets.token_bytes(32),
    )
    legacy_provider.add_master_key(b"legacy-archive-key-id")

    ciphertext, encrypt_header = client.encrypt(
        source=archive_plaintext,
        key_provider=legacy_provider,
        encryption_context=STORED_CONTEXT,
        frame_length=FRAME_LENGTHS[framing],
    )

    # The legacy path neither accepts nor needs reproduced application context.
    plaintext, decrypt_header = client.decrypt(
        source=ciphertext,
        key_provider=legacy_provider,
    )

    assert plaintext == archive_plaintext
    assert decrypt_header.encryption_context == encrypt_header.encryption_context
    assert STORED_CONTEXT.items() <= decrypt_header.encryption_context.items()
    assert REQUIRED_CONTEXT_KEY not in decrypt_header.encryption_context
