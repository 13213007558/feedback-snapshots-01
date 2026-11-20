# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for staged algorithm suite policies.

These tests use the local raw AES test key already used by the functional suite
and exercise both the one-shot (``encrypt``/``decrypt``) and streaming
(``stream``) APIs, mirroring an archive service progressively tightening the
algorithm suites it accepts.
"""
import io
import os
import warnings

import pytest

import aws_encryption_sdk
from aws_encryption_sdk import AlgorithmSuiteStage, CommitmentPolicy
from aws_encryption_sdk.algorithm_suite_policy import (
    ALGORITHM_SUITE_STAGE_CONFIGS,
    AlgorithmSuiteStageConfig,
    algorithm_suite_stage_config,
)
from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import Algorithm, EncryptionKeyType, WrappingAlgorithm

from .test_f_aws_encryption_sdk_client import VALUES as CLIENT_VALUES
from .test_f_aws_encryption_sdk_client import fake_kms_client, fake_kms_key_provider
from .test_f_commitment import StaticRawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]

PLAINTEXT = b"archive payload that must never leak into an unapproved write"
HARDENED = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
COMMITTING_UNSIGNED = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
LEGACY = Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
LEGACY_UNSIGNED = Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256


def _provider():
    provider = StaticRawMasterKeyProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=b"\x00" * 32,
    )
    provider.add_master_key("KeyId")
    return provider


def _client(stage, commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT):
    return aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=commitment_policy,
        algorithm_suite_stage=stage,
    )


def _migration_reader(stage):
    """A client that can both write committed messages and still read legacy ones."""
    return _client(stage, commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)


def _encrypt_to_file(client, path, algorithm=None):
    """Encrypt via the streaming API, creating the file only once approved output exists.

    This is the pattern an archive service should use: only publish a file once the
    SDK has produced ciphertext.  If the stage rejects the write, no chunk is ever
    yielded and the destination file is never created.
    """
    kwargs = {}
    if algorithm is not None:
        kwargs["algorithm"] = algorithm
    ciphertext_file = None
    try:
        with client.stream(mode="e", source=io.BytesIO(PLAINTEXT), key_provider=_provider(), **kwargs) as encryptor:
            for chunk in encryptor:
                if ciphertext_file is None:
                    ciphertext_file = open(path, "wb")
                ciphertext_file.write(chunk)
    finally:
        if ciphertext_file is not None:
            ciphertext_file.close()


def _decrypt_file(client, path):
    with open(path, "rb") as ciphertext_file:
        with client.stream(mode="d", source=ciphertext_file, key_provider=_provider()) as decryptor:
            return decryptor.read()


def _assert_no_file_created(call, path):
    with pytest.raises(ActionNotAllowedError):
        call()
    assert not os.path.exists(path)


def test_stage_configs_are_declared_centrally():
    """Every stage is declared once and exposes consistent write/read approvals."""
    for stage in AlgorithmSuiteStage:
        config = algorithm_suite_stage_config(stage)
        assert config is ALGORITHM_SUITE_STAGE_CONFIGS[stage]
        assert config.stage is stage
        assert config.default_encrypt_suite in config.encrypt_suites
        assert set(config.encrypt_suites) <= set(config.decrypt_suites)

    assert algorithm_suite_stage_config(None) is None


def test_stage_config_rejects_inconsistent_declarations():
    with pytest.raises(ValueError):
        AlgorithmSuiteStageConfig(
            stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
            encrypt_suites=(HARDENED,),
            decrypt_suites=(LEGACY,),
            default_encrypt_suite=LEGACY,
        )
    with pytest.raises(TypeError):
        aws_encryption_sdk.EncryptionSDKClient(algorithm_suite_stage="not-a-stage")
    with pytest.raises(ValueError):
        algorithm_suite_stage_config("read-legacy-write-committed")


def test_client_config_accepts_stage():
    """The client config carries the declared stage through to streaming clients."""
    config = aws_encryption_sdk.EncryptionSDKClientConfig(
        algorithm_suite_stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED
    )
    client = aws_encryption_sdk.EncryptionSDKClient(config=config)
    assert client.config.algorithm_suite_stage is AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED
    assert client.config.commitment_policy is CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT


def test_stage_cannot_be_overridden_per_call():
    """The stage, like other policy settings, is only configurable on the client config."""
    client = _client(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _, header = client.encrypt(
            source=PLAINTEXT,
            key_provider=_provider(),
            algorithm_suite_stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
        )
    assert any("Invalid keyword argument 'algorithm_suite_stage'" in str(warning.message) for warning in caught)
    assert header.algorithm is HARDENED


def test_oneshot_stage_one_reads_legacy_and_writes_committed(tmp_path):
    """Stage 1: legacy may be read, but only committing suites may be written."""
    stage = AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED
    client = _migration_reader(stage)

    for algorithm in (HARDENED, COMMITTING_UNSIGNED):
        ciphertext, header = client.encrypt(source=PLAINTEXT, key_provider=_provider(), algorithm=algorithm)
        assert header.algorithm == algorithm
        assert client.decrypt(source=ciphertext, key_provider=_provider())[0] == PLAINTEXT

    for algorithm in (LEGACY, LEGACY_UNSIGNED, Algorithm.AES_256_GCM_IV12_TAG16):
        with pytest.raises(ActionNotAllowedError):
            client.encrypt(source=PLAINTEXT, key_provider=_provider(), algorithm=algorithm)

    # And a legacy message written by an older client is still readable.
    legacy_writer = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    legacy_ciphertext, _ = legacy_writer.encrypt(source=PLAINTEXT, key_provider=_provider(), algorithm=LEGACY)
    assert client.decrypt(source=legacy_ciphertext, key_provider=_provider())[0] == PLAINTEXT


@pytest.mark.parametrize("stage", list(AlgorithmSuiteStage))
def test_default_writes_use_the_stage_default_suite(stage):
    """Both one-shot and streaming writes without an explicit suite use the stage default."""
    client = _migration_reader(stage)

    _, header = client.encrypt(source=PLAINTEXT, key_provider=_provider())
    assert header.algorithm is HARDENED

    with client.stream(mode="e", source=io.BytesIO(PLAINTEXT), key_provider=_provider()) as encryptor:
        b"".join(encryptor)
        assert encryptor.header.algorithm is HARDENED


@pytest.mark.parametrize("stage", list(AlgorithmSuiteStage))
def test_streaming_unapproved_suite_never_produces_a_file(stage, tmp_path):
    """No stage will write a file for a suite that stage does not approve."""
    path = tmp_path / "ciphertext.bin"
    approved = algorithm_suite_stage_config(stage).encrypt_suites
    for algorithm in Algorithm:
        if algorithm in approved:
            continue
        _assert_no_file_created(
            lambda algorithm=algorithm: _encrypt_to_file(_client(stage), path, algorithm=algorithm),
            path,
        )


def test_streaming_stage_one_defaults_to_approved_suite_and_reads_legacy(tmp_path):
    """Stage 1 streaming: default writes are approved, legacy files remain readable."""
    stage = AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED
    client = _migration_reader(stage)
    new_path = tmp_path / "stage1.ct"
    _encrypt_to_file(client, new_path)
    assert os.path.getsize(new_path) > 0
    assert _decrypt_file(client, new_path) == PLAINTEXT

    # Legacy files created by an older, more permissive client remain readable.
    legacy_path = tmp_path / "legacy.ct"
    legacy_writer = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    _encrypt_to_file(legacy_writer, legacy_path, algorithm=LEGACY)
    assert _decrypt_file(client, legacy_path) == PLAINTEXT


def test_streaming_stage_two_rejects_unsigned_commitment_writes(tmp_path):
    """Stage 2: writes are restricted to the hardened suite, reads still allow legacy."""
    stage = AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED
    client = _migration_reader(stage)
    path = tmp_path / "stage2.ct"
    _assert_no_file_created(
        lambda: _encrypt_to_file(_client(stage), path, algorithm=COMMITTING_UNSIGNED),
        path,
    )

    _encrypt_to_file(client, path)
    assert _decrypt_file(client, path) == PLAINTEXT

    legacy_path = tmp_path / "legacy.ct"
    legacy_writer = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    _encrypt_to_file(legacy_writer, legacy_path, algorithm=LEGACY_UNSIGNED)
    assert _decrypt_file(client, legacy_path) == PLAINTEXT


def test_streaming_hardened_stage_rejects_legacy_reads(tmp_path):
    """After migration, legacy messages are no longer readable."""
    permissive = _migration_reader(AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED)
    legacy_path = tmp_path / "legacy.ct"
    legacy_writer = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    _encrypt_to_file(legacy_writer, legacy_path, algorithm=LEGACY)

    hardened = _migration_reader(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED)
    with pytest.raises(ActionNotAllowedError):
        _decrypt_file(hardened, legacy_path)

    hardened_path = tmp_path / "hardened.ct"
    _encrypt_to_file(hardened, hardened_path)
    assert _decrypt_file(hardened, hardened_path) == PLAINTEXT

    # And stage 1 can still read everything the hardened stage writes.
    assert _decrypt_file(permissive, hardened_path) == PLAINTEXT


def test_streaming_stage_survives_cached_materials_from_shared_cache(tmp_path):
    """A shared caching CMM cannot smuggle a suite that the stage forbids."""
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=10)
    legacy_ccmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=_provider(), cache=cache, max_age=3600.0, max_messages_encrypted=5
    )
    permissive = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    permissive.encrypt(source=PLAINTEXT, materials_manager=legacy_ccmm, algorithm=LEGACY)

    shared_ccmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=_provider(), cache=cache, max_age=3600.0, max_messages_encrypted=5
    )
    stage_client = _migration_reader(AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED)
    ciphertext, header = stage_client.encrypt(source=PLAINTEXT, materials_manager=shared_ccmm)
    assert header.algorithm == HARDENED
    assert stage_client.decrypt(source=ciphertext, key_provider=_provider())[0] == PLAINTEXT


def test_pre_existing_legacy_message_readable_during_migration_only():
    """A real pre-existing legacy message is readable during migration, not after it."""
    region = "us-west-2"
    key_info = "arn:aws:kms:us-west-2:249645522726:key/d1720f4e-953b-44bb-b9dd-fc8b9d0baa5f"
    mock_kms_client = fake_kms_client()
    mock_kms_client.decrypt.return_value = {"Plaintext": CLIENT_VALUES["provided"]["key"], "KeyId": key_info}
    provider = fake_kms_key_provider()
    provider._regional_clients[region] = mock_kms_client
    provider.add_master_key(key_info)

    migration_client = _migration_reader(AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED)
    plaintext, header = migration_client.decrypt(source=CLIENT_VALUES["provided"]["ciphertext"], key_provider=provider)
    assert plaintext == CLIENT_VALUES["provided"]["plaintext"]
    assert not header.algorithm.is_committing()

    hardened = _migration_reader(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED)
    with pytest.raises(ActionNotAllowedError):
        hardened.decrypt(source=CLIENT_VALUES["provided"]["ciphertext"], key_provider=provider)


def test_oneshot_hardened_stage_rejects_legacy_reads():
    legacy_writer = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    legacy_ciphertext, _ = legacy_writer.encrypt(source=PLAINTEXT, key_provider=_provider(), algorithm=LEGACY)

    hardened = _migration_reader(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED)
    with pytest.raises(ActionNotAllowedError):
        hardened.decrypt(source=legacy_ciphertext, key_provider=_provider())
