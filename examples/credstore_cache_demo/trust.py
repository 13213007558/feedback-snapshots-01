"""Trust labels and the three-way error taxonomy.

A central point of this example is that *decryption is not authentication*.
The encrypted Info fields (``encIdentifier`` / ``encCredStoreState``) are
AES-CBC without an embedded MAC, so a routine that "decrypts successfully"
only proves that some key produced bytes with plausible framing - it does not
prove those bytes came from a particular authenticator.

The authenticity guarantee comes from somewhere else entirely: the CTAP
channel's PIN/UV authentication (the HMAC the authenticator checks on each
management command), which in turn only exists because the caller established
a trusted connection and a token with the right permissions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MissingFieldError(LookupError):
    """The Info object does not carry the encrypted field at all.

    This is a capability/negotiation outcome, not a security failure: older or
    smaller authenticators are allowed to omit ``encIdentifier`` /
    ``encCredStoreState``.  Callers must fall back to a fresh enumeration.
    """


class UnparseableFieldError(ValueError):
    """The field is present but its framing or padding cannot be decoded.

    Examples: ciphertext shorter than one block, missing IV, invalid PKCS#7
    padding.  This distinguishes "malformed bytes" from "absent field" and
    from "the surrounding proof of authenticity failed".
    """


class AuthenticityError(PermissionError):
    """Proof of authenticity for the surrounding session could not be made.

    Raised when the upper-layer binding (trusted connection, token generation,
    permission set) cannot be established or no longer matches.  A value that
    *decrypts* may still be unusable if this check fails.  The two facts are
    reported independently on purpose.
    """


class CacheMiss(LookupError):
    """No cached entry matches the current binding and decoded freshness hints.

    This is a control-flow outcome rather than a security failure: the caller
    should perform a fresh, authenticated enumeration and repopulate the cache.
    """


class TrustLabel(str, Enum):
    """Where a value's trust actually comes from.

    ``DECODED_ONLY`` values are the raw output of the CBC decryption: usable as
    opaque cache keys, never as an authenticated device identity.
    ``SESSION_AUTHENTICATED`` values are only trustworthy for the lifetime of
    the bound connection and token generation.
    """

    DECODED_ONLY = "decoded-only"
    SESSION_AUTHENTICATED = "session-authenticated"


@dataclass(frozen=True)
class TrustedBinding:
    """Facts the *upper layer* asserts about the current device connection.

    None of these can be derived from the encrypted bytes.  The caller (the
    process that opened the transport, ran user verification and obtained the
    persistent PIN/UV token) supplies them, and the cache treats them as the
    sole source of authenticated context.

    :param connection_id: Stable handle of the transport connection the caller
        itself confirmed (for example a USB HID path plus a getInfo round trip).
    :param token_generation: Monotonic generation of the persistent PIN/UV
        auth token in use; incremented whenever the token is (re)issued.
    :param permissions: Permission bit set the token was minted with; the
        credential management permission must be present.
    """

    connection_id: str
    token_generation: int
    permissions: int


@dataclass(frozen=True)
class DecodedValue:
    """Bytes produced by decryption, paired with an explicit trust label.

    Wrapping the raw bytes forces every consumer to look at the label instead
    of treating ``value`` as an authenticated identifier by default.
    """

    value: bytes
    label: TrustLabel
    source_field: str

    @property
    def is_authenticated(self) -> bool:
        return self.label is TrustLabel.SESSION_AUTHENTICATED
