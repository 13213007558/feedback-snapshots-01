# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Safe, opt-in diagnostics for decryption failures.

Monitoring systems often need to distinguish a rejection caused by configuration
from a transient inability to obtain cryptographic materials and from a failed
integrity check.  The exception types alone do not always make that distinction
(the same exception can be raised at different points in the decrypt flow), and
the exception messages may contain sensitive values such as encryption context
entries or key material.

This module provides a small immutable value object containing only a phase and
a category.  It never contains encryption context values, data keys, wrapped
keys, or exception messages, so it is safe to hand to monitoring.  Callers opt
in by reading it from the original exception with
:func:`safe_decryption_diagnostic`; the original exception type, message,
traceback, and ``__cause__`` chain are left untouched for local troubleshooting.
"""
from __future__ import division

from contextlib import contextmanager
from enum import Enum

import attr
from cryptography.exceptions import InvalidSignature, InvalidTag

from aws_encryption_sdk.exceptions import ActionNotAllowedError, CustomMaximumValueExceeded, SerializationError


class DecryptionFailurePhase(Enum):
    """The decrypt operation phase in which a failure occurred."""

    CONFIGURATION = "configuration"
    PARSE_HEADER = "parse_header"
    GET_DECRYPTION_MATERIALS = "get_decryption_materials"
    VERIFY_HEADER = "verify_header"
    DECRYPT_BODY = "decrypt_body"
    VERIFY_SIGNATURE = "verify_signature"
    UNKNOWN = "unknown"


class DecryptionFailureCategory(Enum):
    """The safe, monitoring-oriented category of a decryption failure."""

    CONFIGURATION_REJECTED = "configuration_rejected"
    MATERIALS_UNAVAILABLE = "materials_unavailable"
    INTEGRITY_FAILED = "integrity_failed"
    MALFORMED_MESSAGE = "malformed_message"
    UNCLASSIFIED = "unclassified"


@attr.s(frozen=True, slots=True)
class DecryptionFailureDiagnostic(object):
    """A redacted description of a decryption failure.

    Instances contain only enum values.  In particular they do not contain the
    encryption context, plaintext or encrypted data keys, wrapping keys, or the
    message from the underlying exception.

    .. versionadded:: 4.1.0

    :param phase: Phase of the decrypt operation that failed
    :type phase: aws_encryption_sdk.diagnostics.DecryptionFailurePhase
    :param category: Safe category describing the failure
    :type category: aws_encryption_sdk.diagnostics.DecryptionFailureCategory
    """

    phase = attr.ib(validator=attr.validators.instance_of(DecryptionFailurePhase))
    category = attr.ib(validator=attr.validators.instance_of(DecryptionFailureCategory))

    def as_dict(self):
        """Return a monitoring-friendly representation containing only strings.

        :rtype: dict
        """
        return {"phase": self.phase.value, "category": self.category.value}

    def __str__(self):
        """Return a redacted human-readable description."""
        return "phase={phase} category={category}".format(
            phase=self.phase.value, category=self.category.value
        )


_PHASE_TO_CATEGORY = {
    DecryptionFailurePhase.CONFIGURATION: DecryptionFailureCategory.CONFIGURATION_REJECTED,
    DecryptionFailurePhase.PARSE_HEADER: DecryptionFailureCategory.MALFORMED_MESSAGE,
    DecryptionFailurePhase.GET_DECRYPTION_MATERIALS: DecryptionFailureCategory.MATERIALS_UNAVAILABLE,
    DecryptionFailurePhase.VERIFY_HEADER: DecryptionFailureCategory.INTEGRITY_FAILED,
    DecryptionFailurePhase.DECRYPT_BODY: DecryptionFailureCategory.INTEGRITY_FAILED,
    DecryptionFailurePhase.VERIFY_SIGNATURE: DecryptionFailureCategory.INTEGRITY_FAILED,
    DecryptionFailurePhase.UNKNOWN: DecryptionFailureCategory.UNCLASSIFIED,
}


def _category_for_phase(phase, error):
    """Return the safe category for a phase and the error raised in that phase."""
    if phase is DecryptionFailurePhase.CONFIGURATION:
        return DecryptionFailureCategory.CONFIGURATION_REJECTED
    if phase is DecryptionFailurePhase.GET_DECRYPTION_MATERIALS:
        # Providers normally surface an inability to procure material as one of
        # the SDK's key errors.  A tag or signature failure while unwrapping an
        # encrypted data key, however, means the key itself failed authentication.
        if isinstance(error, (InvalidTag, InvalidSignature)):
            return DecryptionFailureCategory.INTEGRITY_FAILED
        if isinstance(error, (ActionNotAllowedError, CustomMaximumValueExceeded)):
            return DecryptionFailureCategory.CONFIGURATION_REJECTED
        if isinstance(error, SerializationError):
            return DecryptionFailureCategory.MALFORMED_MESSAGE
        return DecryptionFailureCategory.MATERIALS_UNAVAILABLE
    if phase is DecryptionFailurePhase.DECRYPT_BODY:
        # Authentication tag failures are integrity failures; structural
        # deserialization failures in the body are malformed messages.
        if isinstance(error, (ActionNotAllowedError, CustomMaximumValueExceeded)):
            return DecryptionFailureCategory.CONFIGURATION_REJECTED
        if isinstance(error, SerializationError) and not isinstance(error, InvalidTag):
            return DecryptionFailureCategory.MALFORMED_MESSAGE
        return DecryptionFailureCategory.INTEGRITY_FAILED
    return _PHASE_TO_CATEGORY[phase]


def _record_decryption_diagnostic(error, phase):
    """Attach a redacted diagnostic to an exception without changing the exception.

    The first (innermost) phase recorded wins, so callers that catch and
    re-raise at an outer layer do not overwrite a more precise diagnostic.

    :param error: Exception to annotate
    :param phase: Phase in which the failure occurred
    :type phase: aws_encryption_sdk.diagnostics.DecryptionFailurePhase
    """
    if error is None or getattr(error, "_decryption_diagnostic", None) is not None:
        return
    diagnostic = DecryptionFailureDiagnostic(phase=phase, category=_category_for_phase(phase, error))
    try:
        setattr(error, "_decryption_diagnostic", diagnostic)
    except (AttributeError, TypeError):  # pragma: no cover - defensive for exotic exception types
        # Some exception implementations may disallow attributes.  In that
        # case callers simply do not get a diagnostic; behavior is unchanged.
        pass


@contextmanager
def decryption_failure_phase(phase):
    """Record the decrypt phase for any exception raised inside the context.

    This context manager does not swallow or transform exceptions; it only
    annotates them.  The innermost phase wins, so wrapping outer phases do not
    overwrite a more specific inner one.

    :param phase: Phase in which failures should be classified
    :type phase: aws_encryption_sdk.diagnostics.DecryptionFailurePhase
    """
    try:
        yield
    except Exception as error:
        _record_decryption_diagnostic(error, phase)
        raise


def safe_decryption_diagnostic(error):
    """Return a redacted decryption diagnostic for an exception, if available.

    This function walks the exception's ``__cause__``/``__context__`` chain
    looking for a diagnostic recorded by the SDK.  It is safe to call with any
    exception, including exceptions from other libraries.  It does not inspect
    or return exception messages.

    Reading the diagnostic is opt-in: callers that do not call this function
    continue to receive exactly the same exception types and messages as before
    and can keep using their existing ``except`` clauses.

    .. versionadded:: 4.1.0

    :param error: Exception raised while decrypting
    :type error: BaseException
    :returns: Safe diagnostic, or ``None`` if none was recorded
    :rtype: aws_encryption_sdk.diagnostics.DecryptionFailureDiagnostic or None
    """
    if not isinstance(error, BaseException):
        return None

    seen = set()
    current = error
    while isinstance(current, BaseException):
        identifier = id(current)
        if identifier in seen:
            break
        seen.add(identifier)

        diagnostic = getattr(current, "_decryption_diagnostic", None)
        if isinstance(diagnostic, DecryptionFailureDiagnostic):
            return diagnostic

        current = current.__cause__ if current.__cause__ is not None else current.__context__

    return None


__all__ = (
    "DecryptionFailureCategory",
    "DecryptionFailureDiagnostic",
    "DecryptionFailurePhase",
    "decryption_failure_phase",
    "safe_decryption_diagnostic",
)
