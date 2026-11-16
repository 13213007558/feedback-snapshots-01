"""Scoped example: caching a credential list keyed on decrypted CTAP Info fields.

The package deliberately keeps every layer separate so the trust boundary stays
visible:

* :mod:`trust`   - error taxonomy and labels saying *why* a value is trusted
* :mod:`pinuv2`  - pinUvAuthProtocol v2 primitives and the Info-field KDF
* :mod:`software_device` - a self-contained CTAP authenticator simulation
* :mod:`cred_cache` - the bounded cache and its refresh/invalidation rules

Nothing here treats successfully decrypted CBC bytes as proof of device
identity.  See ``README.md`` for the full trust and lifecycle analysis.
"""

from .trust import (
    AuthenticityError,
    CacheMiss,
    DecodedValue,
    MissingFieldError,
    TrustedBinding,
    TrustLabel,
    UnparseableFieldError,
)

__all__ = [
    "AuthenticityError",
    "CacheMiss",
    "DecodedValue",
    "MissingFieldError",
    "TrustLabel",
    "TrustedBinding",
    "UnparseableFieldError",
]
