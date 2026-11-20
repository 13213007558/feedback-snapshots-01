# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.diagnostics"""
import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from aws_encryption_sdk.diagnostics import (
    DecryptionFailureCategory,
    DecryptionFailureDiagnostic,
    DecryptionFailurePhase,
    _category_for_phase,
    _record_decryption_diagnostic,
    safe_decryption_diagnostic,
)
from aws_encryption_sdk.exceptions import DecryptKeyError, SerializationError

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_diagnostic_contains_only_enums():
    diagnostic = DecryptionFailureDiagnostic(
        phase=DecryptionFailurePhase.DECRYPT_BODY,
        category=DecryptionFailureCategory.INTEGRITY_FAILED,
    )

    assert diagnostic.as_dict() == {"phase": "decrypt_body", "category": "integrity_failed"}
    assert str(diagnostic) == "phase=decrypt_body category=integrity_failed"


def test_diagnostic_is_immutable_and_validates_enum_values():
    diagnostic = DecryptionFailureDiagnostic(
        phase=DecryptionFailurePhase.PARSE_HEADER,
        category=DecryptionFailureCategory.MALFORMED_MESSAGE,
    )
    with pytest.raises(Exception):
        diagnostic.phase = DecryptionFailurePhase.UNKNOWN
    with pytest.raises(TypeError):
        DecryptionFailureDiagnostic(phase="parse_header", category=DecryptionFailureCategory.MALFORMED_MESSAGE)


@pytest.mark.parametrize(
    "phase, error, expected",
    (
        (
            DecryptionFailurePhase.CONFIGURATION,
            DecryptKeyError("boom"),
            DecryptionFailureCategory.CONFIGURATION_REJECTED,
        ),
        (DecryptionFailurePhase.PARSE_HEADER, SerializationError("boom"), DecryptionFailureCategory.MALFORMED_MESSAGE),
        (
            DecryptionFailurePhase.GET_DECRYPTION_MATERIALS,
            DecryptKeyError("boom"),
            DecryptionFailureCategory.MATERIALS_UNAVAILABLE,
        ),
        (DecryptionFailurePhase.GET_DECRYPTION_MATERIALS, InvalidTag(), DecryptionFailureCategory.INTEGRITY_FAILED),
        (DecryptionFailurePhase.VERIFY_HEADER, SerializationError("boom"), DecryptionFailureCategory.INTEGRITY_FAILED),
        (DecryptionFailurePhase.DECRYPT_BODY, InvalidTag(), DecryptionFailureCategory.INTEGRITY_FAILED),
        (DecryptionFailurePhase.DECRYPT_BODY, SerializationError("boom"), DecryptionFailureCategory.MALFORMED_MESSAGE),
        (DecryptionFailurePhase.VERIFY_SIGNATURE, InvalidSignature(), DecryptionFailureCategory.INTEGRITY_FAILED),
        (DecryptionFailurePhase.UNKNOWN, RuntimeError("boom"), DecryptionFailureCategory.UNCLASSIFIED),
    ),
)
def test_category_for_phase(phase, error, expected):
    assert _category_for_phase(phase, error) is expected


def test_record_diagnostic_does_not_change_exception():
    error = DecryptKeyError("sensitive detail")
    _record_decryption_diagnostic(error, DecryptionFailurePhase.GET_DECRYPTION_MATERIALS)

    assert type(error) is DecryptKeyError
    assert str(error) == "sensitive detail"
    assert error.__cause__ is None
    assert safe_decryption_diagnostic(error) == DecryptionFailureDiagnostic(
        phase=DecryptionFailurePhase.GET_DECRYPTION_MATERIALS,
        category=DecryptionFailureCategory.MATERIALS_UNAVAILABLE,
    )


def test_record_diagnostic_keeps_innermost_phase():
    error = DecryptKeyError("boom")
    _record_decryption_diagnostic(error, DecryptionFailurePhase.PARSE_HEADER)
    _record_decryption_diagnostic(error, DecryptionFailurePhase.GET_DECRYPTION_MATERIALS)

    assert safe_decryption_diagnostic(error).phase is DecryptionFailurePhase.PARSE_HEADER


def test_safe_decryption_diagnostic_walks_cause_chain():
    root = InvalidTag()
    _record_decryption_diagnostic(root, DecryptionFailurePhase.DECRYPT_BODY)
    wrapper = SerializationError("wrapped")
    wrapper.__cause__ = root

    assert safe_decryption_diagnostic(wrapper).category is DecryptionFailureCategory.INTEGRITY_FAILED


def test_safe_decryption_diagnostic_handles_cycles_and_foreign_exceptions():
    first = RuntimeError("first")
    second = RuntimeError("second")
    first.__cause__ = second
    second.__cause__ = first

    assert safe_decryption_diagnostic(first) is None
    assert safe_decryption_diagnostic("not an exception") is None


def test_sdk_exception_exposes_opt_in_diagnostic_property():
    error = DecryptKeyError("boom")
    assert error.diagnostic is None

    _record_decryption_diagnostic(error, DecryptionFailurePhase.GET_DECRYPTION_MATERIALS)

    # The original type and message are unchanged; the property is an opt-in view.
    assert type(error) is DecryptKeyError
    assert str(error) == "boom"
    assert error.diagnostic == DecryptionFailureDiagnostic(
        phase=DecryptionFailurePhase.GET_DECRYPTION_MATERIALS,
        category=DecryptionFailureCategory.MATERIALS_UNAVAILABLE,
    )
