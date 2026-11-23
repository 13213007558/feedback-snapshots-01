"""
Pseudonymization helpers for the configurable de-identification retention policy.

Direct identifiers (username, IP address and user agent) are replaced with a
deterministic keyed HMAC digest before they are persisted.  Because the digest
is deterministic, records belonging to the same real account keep correlating
with each other across the failure window even though the direct identifier is
no longer stored.

The HMAC key is deployment specific and is never written to the database, so
the digests cannot be reversed or brute forced by an attacker who only has
access to the audit data.
"""

from hashlib import new as hash_new
from hmac import new as hmac_new
from typing import Optional

from django.utils.encoding import force_bytes

from axes.conf import settings

# Shown in the admin and exports in place of identifiers that the viewer is
# not permitted to see or that have been removed from the record.
REDACTED = "[redacted]"

# Field names that hold direct identifiers and the domain separators used when
# hashing them so that identical values in different columns never collide.
IDENTIFIER_FIELDS = ("username", "ip_address", "user_agent")
HASH_IDENTIFIER_FIELDS = tuple(f"{field}_hash" for field in IDENTIFIER_FIELDS)
_HASH_DOMAINS = {
    "username": b"axes.username",
    "ip_address": b"axes.ip_address",
    "user_agent": b"axes.user_agent",
}


def hash_identifier(value: Optional[str], field_name: str) -> Optional[str]:
    """
    Return the deterministic keyed digest for *value* or ``None`` for ``None``.

    The same plaintext value always maps to the same digest for a given field,
    which is what allows failure windows to keep working after the direct
    identifiers are removed.  Different fields use distinct domain separators to
    prevent cross-field collisions.
    """

    if value is None:
        return None

    digestmod = settings.AXES_DEIDENTIFY_HASH_ALGORITHM
    domain = _HASH_DOMAINS[field_name]
    digest = hmac_new(
        force_bytes(settings.AXES_DEIDENTIFY_SECRET_KEY),
        domain + b"\x00" + force_bytes(value),
        digestmod,
    ).hexdigest()
    return f"{field_name}:{digest}"


def digest_available() -> bool:
    """Whether the configured hash algorithm is importable in this runtime."""

    try:
        hash_new(settings.AXES_DEIDENTIFY_HASH_ALGORITHM)
    except ValueError:
        return False
    return True
