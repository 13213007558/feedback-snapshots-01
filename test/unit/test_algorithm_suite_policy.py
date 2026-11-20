# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for aws_encryption_sdk.algorithm_suite_policy."""
import pytest
from mock import MagicMock

from aws_encryption_sdk.algorithm_suite_policy import (
    ALGORITHM_SUITE_STAGE_CONFIGS,
    AlgorithmSuiteStage,
    AlgorithmSuiteStageConfig,
    algorithm_suite_stage_config,
    validate_algorithm_suite_stage_on_decrypt,
    validate_algorithm_suite_stage_on_encrypt,
)
from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import Algorithm

pytestmark = [pytest.mark.unit, pytest.mark.local]

HARDENED = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
SIGNED_COMMITTING = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
LEGACY = Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384


def test_all_stages_have_a_single_central_declaration():
    assert set(ALGORITHM_SUITE_STAGE_CONFIGS) == set(AlgorithmSuiteStage)
    for stage, config in ALGORITHM_SUITE_STAGE_CONFIGS.items():
        assert config.stage is stage


@pytest.mark.parametrize(
    "stage, expected_encrypt, expected_decrypt",
    (
        (
            AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
            (SIGNED_COMMITTING, HARDENED),
            tuple(Algorithm),
        ),
        (AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED, (HARDENED,), tuple(Algorithm)),
        (AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED, (HARDENED,), (HARDENED,)),
    ),
)
def test_stage_contents_match_declared_policy(stage, expected_encrypt, expected_decrypt):
    config = algorithm_suite_stage_config(stage)
    assert config.encrypt_suites == expected_encrypt
    assert config.decrypt_suites == expected_decrypt
    assert config.default_encrypt_suite == HARDENED


def test_none_stage_disables_enforcement():
    assert algorithm_suite_stage_config(None) is None
    validate_algorithm_suite_stage_on_encrypt(None, None)
    validate_algorithm_suite_stage_on_encrypt(None, LEGACY)
    validate_algorithm_suite_stage_on_decrypt(None, LEGACY)


def test_unknown_stage_rejected():
    with pytest.raises(ValueError):
        algorithm_suite_stage_config("not-a-stage")


def test_suite_ids_in_errors_use_supported_suites():
    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_algorithm_suite_stage_on_decrypt(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED, LEGACY)
    assert "0x0378" in str(excinfo.value)
    assert "0x0578" in str(excinfo.value)


def test_stage_config_requires_algorithm_members():
    with pytest.raises(TypeError):
        AlgorithmSuiteStageConfig(
            stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
            encrypt_suites=(MagicMock(),),
            decrypt_suites=(HARDENED,),
            default_encrypt_suite=HARDENED,
        )


def test_stage_config_default_suite_must_be_approved():
    with pytest.raises(ValueError):
        AlgorithmSuiteStageConfig(
            stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
            encrypt_suites=(HARDENED,),
            decrypt_suites=(HARDENED,),
            default_encrypt_suite=LEGACY,
        )


def test_validate_on_encrypt_allows_approved_suite():
    validate_algorithm_suite_stage_on_encrypt(AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED, HARDENED)
    validate_algorithm_suite_stage_on_encrypt(AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED, SIGNED_COMMITTING)


@pytest.mark.parametrize("stage", list(AlgorithmSuiteStage))
def test_validate_on_encrypt_rejects_legacy_suite(stage):
    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_algorithm_suite_stage_on_encrypt(stage, LEGACY)
    excinfo.match("Cannot encrypt with algorithm suite 0x0378 at algorithm suite stage")


def test_validate_on_encrypt_rejects_hardened_unsigned_suite_at_hardened_stage():
    with pytest.raises(ActionNotAllowedError):
        validate_algorithm_suite_stage_on_encrypt(
            AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED, SIGNED_COMMITTING
        )


def test_validate_on_decrypt_matches_stage_read_rules():
    validate_algorithm_suite_stage_on_decrypt(AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED, LEGACY)
    validate_algorithm_suite_stage_on_decrypt(AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED, LEGACY)
    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_algorithm_suite_stage_on_decrypt(AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED, LEGACY)
    excinfo.match("Cannot decrypt a message with algorithm suite 0x0378 at algorithm suite stage")
