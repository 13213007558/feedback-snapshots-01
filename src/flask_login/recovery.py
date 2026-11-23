from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from enum import Enum


class RecoverySource(str, Enum):
    """The places Flask-Login may consult while restoring a login.

    The members are intentionally coarse: they identify *where* a login was
    attempted, never any of the data used to make the attempt.
    """

    #: The Flask session (the ``_user_id`` key).
    SESSION = "session"

    #: The signed "remember me" cookie.
    REMEMBER_COOKIE = "remember_cookie"

    #: The application-provided request loader (header/API key, ...).
    REQUEST = "request"


class RecoveryReason(str, Enum):
    """The limited set of outcomes a login recovery can end in.

    Only these categories are exposed to applications and audit collectors,
    so failure details from a user directory never leak into a record.
    """

    #: A user object was successfully loaded and adopted.
    SUCCESS = "success"

    #: The directory positively confirmed that the account no longer exists.
    INVALID = "invalid"

    #: The directory could not answer this time and the request may be retried.
    UNAVAILABLE = "unavailable"

    #: A loader returned ``None`` without positively confirming anything.
    NO_USER = "no_user"

    #: There was no session, cookie or request identity to recover from.
    NO_CREDENTIALS = "no_credentials"


class UserDirectoryError(Exception):
    """Base class for outcomes a user directory reports explicitly.

    A directory raises one of the subclasses instead of returning ``None``
    when it can distinguish a permanently invalid account from a temporary
    outage. The message carried by these exceptions is never included in a
    :class:`RecoveryResult` or emitted by an audit signal.
    """


class UserNotFound(UserDirectoryError):
    """Raised by a loader to confirm the account is permanently invalid."""


class UserDirectoryUnavailable(UserDirectoryError):
    """Raised by a loader to report a temporary directory outage."""


@dataclass(frozen=True)
class RecoveryResult:
    """The sanitized outcome of a single request's login recovery.

    The object only contains :class:`RecoverySource` and
    :class:`RecoveryReason` categories. It deliberately holds no cookie
    values, user identifiers, credentials or directory exception text, so it
    is safe to hand directly to an audit collector.
    """

    #: Every source that was consulted, in the order it was tried.
    sources: tuple[RecoverySource, ...] = ()

    #: The source that produced the adopted user, or ``None`` on failure.
    source: RecoverySource | None = None

    #: The final, single outcome for the whole request.
    reason: RecoveryReason = RecoveryReason.NO_CREDENTIALS

    #: The reason reported by each consulted source, keyed by its source.
    reasons: dict[RecoverySource, RecoveryReason] = field(default_factory=dict)
