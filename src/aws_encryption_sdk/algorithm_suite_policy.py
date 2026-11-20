# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Central declarations of staged algorithm suite policies.

These policies are intended for services that need to tighten the algorithm
suites they accept over time.  Each stage declares, in one place:

* the algorithm suites that may be used for new writes, and
* the algorithm suites that may still be read.

A typical migration uses the stages in order:

1. :attr:`AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED` allows every suite
   the SDK supports to be read while restricting new writes to committing
   suites.
2. :attr:`AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED` keeps reading legacy
   messages while restricting new writes to the hardened suite.
3. :attr:`AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED` restricts both
   reads and writes to the hardened suite once migration is complete.

These stages are independent of, and applied in addition to,
:class:`aws_encryption_sdk.identifiers.CommitmentPolicy`.  For example,
reading non-committing messages still requires a commitment policy that allows
it.
"""
from enum import Enum

import attr

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import Algorithm


class AlgorithmSuiteStage(Enum):
    """Named stages of a progressive algorithm suite migration.

    :param str value: Stable identifier for the stage
    """

    READ_LEGACY_WRITE_COMMITTED = "read-legacy-write-committed"
    READ_LEGACY_WRITE_HARDENED = "read-legacy-write-hardened"
    READ_HARDENED_WRITE_HARDENED = "read-hardened-write-hardened"


@attr.s(frozen=True, hash=True)
class AlgorithmSuiteStageConfig:
    """Algorithm suites approved for writes and reads at a migration stage.

    :param stage: Stage described by this configuration
    :type stage: AlgorithmSuiteStage
    :param tuple encrypt_suites: Algorithm suites approved for new writes
    :param tuple decrypt_suites: Algorithm suites approved for reads
    :param algorithm default_encrypt_suite: Suite used for writes when the
        caller does not request one
    """

    stage = attr.ib(validator=attr.validators.instance_of(AlgorithmSuiteStage))
    encrypt_suites = attr.ib(converter=tuple)
    decrypt_suites = attr.ib(converter=tuple)
    default_encrypt_suite = attr.ib(validator=attr.validators.instance_of(Algorithm))

    def __attrs_post_init__(self):
        """Validates that all declared suites are supported and consistent."""
        for suite in self.encrypt_suites + self.decrypt_suites:
            if not isinstance(suite, Algorithm):
                raise TypeError("Algorithm suite stage configurations may only contain Algorithm members")
        if self.default_encrypt_suite not in self.encrypt_suites:
            raise ValueError("default_encrypt_suite must be approved for encryption by the same stage")

    def allows_encrypt(self, algorithm):
        """Returns whether the provided suite may be used for new writes."""
        return algorithm in self.encrypt_suites

    def allows_decrypt(self, algorithm):
        """Returns whether the provided suite may be read."""
        return algorithm in self.decrypt_suites


_COMMITTING_SUITES = (
    Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
    Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
)
_HARDENED_SUITE = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
_ALL_SUITES = tuple(Algorithm)

#: The single, central declaration of all built-in migration stages.
ALGORITHM_SUITE_STAGE_CONFIGS = {
    AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED: AlgorithmSuiteStageConfig(
        stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_COMMITTED,
        encrypt_suites=_COMMITTING_SUITES,
        decrypt_suites=_ALL_SUITES,
        default_encrypt_suite=_HARDENED_SUITE,
    ),
    AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED: AlgorithmSuiteStageConfig(
        stage=AlgorithmSuiteStage.READ_LEGACY_WRITE_HARDENED,
        encrypt_suites=(_HARDENED_SUITE,),
        decrypt_suites=_ALL_SUITES,
        default_encrypt_suite=_HARDENED_SUITE,
    ),
    AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED: AlgorithmSuiteStageConfig(
        stage=AlgorithmSuiteStage.READ_HARDENED_WRITE_HARDENED,
        encrypt_suites=(_HARDENED_SUITE,),
        decrypt_suites=(_HARDENED_SUITE,),
        default_encrypt_suite=_HARDENED_SUITE,
    ),
}


def algorithm_suite_stage_config(stage):
    """Returns the central configuration for the provided stage.

    :param stage: Stage to look up, or ``None`` to disable stage enforcement
    :type stage: AlgorithmSuiteStage or None
    :returns: Stage configuration, or ``None``
    :rtype: AlgorithmSuiteStageConfig or None
    """
    if stage is None:
        return None
    try:
        return ALGORITHM_SUITE_STAGE_CONFIGS[stage]
    except KeyError as error:
        raise ValueError("Unknown algorithm suite stage: {}".format(stage)) from error


def _suite_ids(suites):
    """Formats algorithm suite IDs for use in error messages."""
    return ", ".join("0x{algorithm_id:04x}".format(algorithm_id=suite.algorithm_id) for suite in suites)


def validate_algorithm_suite_stage_on_encrypt(stage, algorithm):
    """Validates that a suite is approved for writes at the provided stage.

    :param stage: Stage to enforce, or ``None`` to skip enforcement
    :type stage: AlgorithmSuiteStage or None
    :param algorithm: Algorithm suite to validate, or ``None`` if not yet selected
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm or None
    :raises ActionNotAllowedError: if the suite is not approved for writes
    """
    config = algorithm_suite_stage_config(stage)
    if config is None or algorithm is None or config.allows_encrypt(algorithm):
        return
    raise ActionNotAllowedError(
        "Cannot encrypt with algorithm suite 0x{algorithm_id:04x} at algorithm suite stage '{stage}'. "
        "Approved encryption suites: {approved}.".format(
            algorithm_id=algorithm.algorithm_id,
            stage=config.stage.value,
            approved=_suite_ids(config.encrypt_suites),
        )
    )


def validate_algorithm_suite_stage_on_decrypt(stage, algorithm):
    """Validates that a suite is approved for reads at the provided stage.

    :param stage: Stage to enforce, or ``None`` to skip enforcement
    :type stage: AlgorithmSuiteStage or None
    :param algorithm: Algorithm suite to validate
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :raises ActionNotAllowedError: if the suite is not approved for reads
    """
    config = algorithm_suite_stage_config(stage)
    if config is None or config.allows_decrypt(algorithm):
        return
    raise ActionNotAllowedError(
        "Cannot decrypt a message with algorithm suite 0x{algorithm_id:04x} at algorithm suite stage "
        "'{stage}'. Approved decryption suites: {approved}.".format(
            algorithm_id=algorithm.algorithm_id,
            stage=config.stage.value,
            approved=_suite_ids(config.decrypt_suites),
        )
    )
