"""Opt-in, log-safe diagnostics for JWT validation failures.

Gateways typically convert PyJWT exceptions into structured log records, but
log platforms often have a broader audience than the token's claims.  This
module provides a *diagnostic mode* that classifies a validation failure
(signature, claims, key service, token type) without ever exposing the raw
token or claim values.

Diagnostic mode is disabled by default (production-safe).  Enable it either
programmatically::

    from jwt import diagnostics

    diagnostics.set_diagnostics_enabled(True)

or via the ``PYJWT_DIAGNOSTICS`` environment variable (``1``/``true``/``yes``/
``on``) before the process starts.

Usage at the logging site::

    try:
        jwt.decode(token, key, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        logger.warning("jwt validation failed", extra=diagnostics.describe_exception(exc))

The returned record contains only the exception type name and, when
diagnostic mode is enabled, a coarse ``category``.  It never includes the
exception message, the token, or any claim values.
"""

from __future__ import annotations

import os

from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidSubjectError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
)

__all__ = [
    "CATEGORY_CLAIMS",
    "CATEGORY_KEY_SERVICE",
    "CATEGORY_SIGNATURE",
    "CATEGORY_TOKEN_TYPE",
    "CATEGORY_UNKNOWN",
    "classify_exception",
    "describe_exception",
    "diagnostics_enabled",
    "set_diagnostics_enabled",
]

#: Failure of the cryptographic signature or algorithm checks.
CATEGORY_SIGNATURE = "signature"
#: Failure of a registered claim / condition check (exp, nbf, iss, aud, ...).
CATEGORY_CLAIMS = "claims"
#: Failure originating from the key service (JWKS directory) or key material.
CATEGORY_KEY_SERVICE = "key_service"
#: Failure indicating the input is not a well-formed token of the expected type.
CATEGORY_TOKEN_TYPE = "token_type"
#: Failure that does not map to any known category.
CATEGORY_UNKNOWN = "unknown"

# Ordered: subclasses must be matched before their base classes.
_CATEGORY_RULES: tuple[tuple[tuple[type[Exception], ...], str], ...] = (
    ((InvalidSignatureError, InvalidAlgorithmError), CATEGORY_SIGNATURE),
    (
        (
            ExpiredSignatureError,
            ImmatureSignatureError,
            InvalidAudienceError,
            InvalidIssuerError,
            InvalidIssuedAtError,
            InvalidSubjectError,
            InvalidJTIError,
            MissingRequiredClaimError,
        ),
        CATEGORY_CLAIMS,
    ),
    (
        (PyJWKClientError, PyJWKError, PyJWKSetError, InvalidKeyError),
        CATEGORY_KEY_SERVICE,
    ),
    ((DecodeError, InvalidTokenError), CATEGORY_TOKEN_TYPE),
)

_ENABLED_VALUES = {"1", "true", "yes", "on"}

_enabled = os.environ.get("PYJWT_DIAGNOSTICS", "").strip().lower() in _ENABLED_VALUES


def set_diagnostics_enabled(enabled: bool) -> None:
    """Enable or disable diagnostic mode (disabled by default)."""
    global _enabled
    _enabled = bool(enabled)


def diagnostics_enabled() -> bool:
    """Return whether diagnostic mode is currently enabled."""
    return _enabled


def classify_exception(exc: BaseException) -> str:
    """Return the failure category for *exc*.

    The classification is derived solely from the exception type, so it is
    safe to compute and log regardless of diagnostic mode; gating happens in
    :func:`describe_exception`.
    """
    for exc_types, category in _CATEGORY_RULES:
        if isinstance(exc, exc_types):
            return category
    return CATEGORY_UNKNOWN


def describe_exception(exc: BaseException) -> dict[str, str]:
    """Build a log-safe structured record for *exc*.

    Always includes ``error_type`` (the exception class name).  Adds the
    failure ``category`` only when diagnostic mode is enabled.  Never
    includes the exception message, the token, or claim values.
    """
    record = {"error_type": type(exc).__name__}
    if _enabled:
        record["category"] = classify_exception(exc)
    return record
