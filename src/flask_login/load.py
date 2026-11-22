"""Auditable results of the user-loading process.

Flask-Login restores the current user from a number of places: the Flask
session, the "remember me" cookie or a custom request loader. When that
restoration fails the application needs to know *where* it tried to load the
user from and *why* it failed, without exposing credentials or other internal
identity details to the outside world.

The objects in this module provide that audit trail. They deliberately carry
only identifiers and categorical reasons -- never a raw cookie, a password, an
authorization header or an exception message -- so they are safe to hand to an
event collector.

.. versionadded:: 0.7.0
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LoadSource(str, Enum):
    """Where an attempt to restore the user came from.

    The values are stable strings so they can be serialised directly into log
    records and event payloads.
    """

    #: The user id stored in the Flask session.
    SESSION = "session"

    #: The signed "remember me" cookie.
    REMEMBER_COOKIE = "remember_cookie"

    #: A custom :meth:`LoginManager.request_loader` callback.
    REQUEST = "request"


class LoadFailureReason(str, Enum):
    """Why a user could not be restored.

    These categories answer the support question "is the account disabled, has
    the record expired, or is the user directory failing?" while keeping the
    detail level appropriate for an audit log.
    """

    #: No user id / credential was available to load from the given source
    #: (for example a malformed or unreadable "remember me" cookie).
    NO_IDENTIFIER = "no_identifier"

    #: The directory had no record for the identifier, or the record is no
    #: longer valid (deleted, expired or otherwise retired).
    NOT_FOUND = "not_found"

    #: The account exists but is not active and therefore cannot be used.
    DISABLED = "disabled"

    #: The user directory could not answer because of a transient failure;
    #: the request may succeed if it is retried.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class LoadResult:
    """The outcome of a single user-restoration attempt.

    Instances are immutable and free of secrets, so they can be stored on
    ``flask.g`` for the duration of the request or forwarded to an event
    collector. They never contain the raw "remember me" cookie, a password, an
    authorization header or an exception message.

    :ivar success: Whether a usable, active user was loaded.
    :ivar source: Where the user was loaded, or attempted to be loaded, from.
    :ivar reason: The categorical failure reason. ``None`` on success or when
        no source was attempted at all (an anonymous request).
    :ivar user: The loaded user on success, otherwise ``None``.
    :ivar user_id: The identifier used for the lookup. This is the id stored in
        the session or decoded from a signed cookie -- never the cookie value
        itself. May be ``None`` when no identifier was available.
    :ivar retryable: Whether the caller may reasonably retry, typically because
        the directory was temporarily unavailable.
    """

    success: bool
    source: Optional[LoadSource] = None
    reason: Optional[LoadFailureReason] = None
    user: object = None
    user_id: Optional[str] = None
    retryable: bool = False

    @classmethod
    def anonymous(cls):
        """Build the result for a request with no restoration attempt."""
        return cls(success=False)

    @classmethod
    def loaded(cls, source, user, user_id):
        """Build a successful result."""
        return cls(success=True, source=source, user=user, user_id=user_id)

    @classmethod
    def failed(cls, source, reason, user_id=None, retryable=False):
        """Build a failed result carrying only a categorical reason."""
        return cls(
            success=False,
            source=source,
            reason=reason,
            user_id=user_id,
            retryable=retryable,
        )
