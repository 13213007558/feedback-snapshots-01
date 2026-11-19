"""Per-field retention (absolute time-to-live) support.

Some session fields (for example a contact detail kept only long enough to
fill a form) must be removed after a short, fixed delay that starts when the
field is written. Ordinary reads and backend/session renewal must not extend
that delay. The expiry bookkeeping lives next to the session payload so it
survives serialization in every backend.
"""

from datetime import timedelta as TimeDelta
from typing import Any, Dict, Mapping, Optional, Union

# Reserved session key holding the per-field expiry timestamps. It is injected
# by the session interface immediately before persistence and stripped right
# after loading, so application code never sees it.
FIELD_EXPIRY_KEY = "_field_expiry"

Lifetime = Union[int, float, TimeDelta]


def normalize_field_ttl(
    field_ttl: Optional[Mapping[str, Lifetime]],
) -> Dict[str, int]:
    """Validate and normalize the per-field TTL configuration.

    :param field_ttl: mapping of session key to lifetime, expressed as a number
        of seconds or a :class:`datetime.timedelta`.
    :returns: mapping of session key to a whole number of seconds.
    """
    if field_ttl is None:
        return {}
    if not isinstance(field_ttl, Mapping):
        raise TypeError(
            "SESSION_FIELD_TTL must be a mapping of session key to lifetime, "
            f"got {type(field_ttl).__name__!r}."
        )

    normalized: Dict[str, int] = {}
    for key, lifetime in field_ttl.items():
        if key == FIELD_EXPIRY_KEY:
            raise ValueError(
                f"{FIELD_EXPIRY_KEY!r} is reserved for per-field TTL bookkeeping "
                "and cannot be used as a session key."
            )
        if isinstance(lifetime, TimeDelta):
            seconds = int(lifetime.total_seconds())
        elif isinstance(lifetime, (int, float)):
            seconds = int(lifetime)
        else:
            raise TypeError(
                f"TTL for session key {key!r} must be an int, float or "
                f"timedelta, got {type(lifetime).__name__!r}."
            )
        if seconds <= 0:
            raise ValueError(
                f"TTL for session key {key!r} must be greater than zero, got {seconds}."
            )
        normalized[key] = seconds
    return normalized


def stamp_field_expiry(
    key: str,
    now: float,
    field_ttl: Mapping[str, int],
    field_expiry: Dict[str, float],
) -> None:
    """Record or clear the absolute expiry of a field being written.

    Only keys present in ``field_ttl`` are tracked. The timestamp is computed
    from the write moment (``now``) and is never recomputed on read or on
    backend renewal, so the retention is absolute.
    """
    if key in field_ttl:
        field_expiry[key] = now + field_ttl[key]


def purge_expired_fields(
    data: Dict[str, Any],
    now: float,
    field_expiry: Dict[str, float],
) -> set:
    """Remove fields whose absolute expiry is in the past.

    :returns: the set of removed session keys.
    """
    expired = {
        key for key, expires_at in field_expiry.items() if expires_at <= now
    }
    for key in expired:
        # Missing keys are harmless: the field may have been deleted earlier.
        data.pop(key, None)
        field_expiry.pop(key, None)
    return expired
