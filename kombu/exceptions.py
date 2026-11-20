"""Exceptions."""

from __future__ import annotations

from socket import timeout as TimeoutError
from types import TracebackType
from typing import TYPE_CHECKING, TypeVar

from amqp import ChannelError, ConnectionError, ResourceError

if TYPE_CHECKING:
    from kombu.asynchronous.http import Response

__all__ = (
    'reraise', 'KombuError', 'OperationalError', 'BatchPublishError',
    'NotBoundError', 'MessageStateError', 'TimeoutError',
    'LimitExceeded', 'ConnectionLimitExceeded',
    'ChannelLimitExceeded', 'ConnectionError', 'ChannelError',
    'VersionMismatch', 'SerializerNotInstalled', 'ResourceError',
    'SerializationError', 'EncodeError', 'DecodeError', 'HttpError',
    'InconsistencyError', 'ReplyNotAllowedError',
)

BaseExceptionType = TypeVar('BaseExceptionType', bound=BaseException)


def reraise(
    tp: type[BaseExceptionType],
    value: BaseExceptionType,
    tb: TracebackType | None = None
) -> BaseExceptionType:
    """Reraise exception."""
    if value.__traceback__ is not tb:
        raise value.with_traceback(tb)
    raise value


class KombuError(Exception):
    """Common subclass for all Kombu exceptions."""


class OperationalError(KombuError):
    """Recoverable message transport connection error."""


class BatchPublishError(KombuError):
    """Batch publication failed with an uncertain delivery outcome."""


class SerializationError(KombuError):
    """Failed to serialize/deserialize content."""


class EncodeError(SerializationError):
    """Cannot encode object."""


class DecodeError(SerializationError):
    """Cannot decode object."""


class NotBoundError(KombuError):
    """Trying to call channel dependent method on unbound entity."""


class MessageStateError(KombuError):
    """The message has already been acknowledged."""


class LimitExceeded(KombuError):
    """Limit exceeded."""


class ConnectionLimitExceeded(LimitExceeded):
    """Maximum number of simultaneous connections exceeded."""


class ChannelLimitExceeded(LimitExceeded):
    """Maximum number of simultaneous channels exceeded."""


class VersionMismatch(KombuError):
    """Library dependency version mismatch."""


class SerializerNotInstalled(KombuError):
    """Support for the requested serialization type is not installed."""


class ContentDisallowed(SerializerNotInstalled):
    """Consumer does not allow this content-type."""


class ReplyNotAllowedError(KombuError):
    """Reply destination is not permitted by the configured reply policy.

    Raised before anything is published, so an unapproved ``reply_to``
    never reaches the broker.  Only the offending destination name is
    included in the message; the original request is deliberately omitted
    to avoid leaking its contents through error reports or logs.
    """

    def __init__(self, reply_to, allowed=None):
        self.reply_to = reply_to
        self.allowed = allowed
        if allowed is None:
            message = (
                f'Replying to {reply_to!r} is not allowed: no reply '
                f'destinations are permitted.'
            )
        else:
            message = (
                f'Replying to {reply_to!r} is not allowed. '
                f'Permitted reply destinations: {sorted(allowed)!r}.'
            )
        super().__init__(message)


class InconsistencyError(ConnectionError):
    """Data or environment has been found to be inconsistent.

    Depending on the cause it may be possible to retry the operation.
    """


class HttpError(Exception):
    """HTTP Client Error."""

    def __init__(
        self,
        code: int,
        message: str | None = None,
        response: Response | None = None
    ) -> None:
        self.code = code
        self.message = message
        self.response = response
        super().__init__(code, message, response)

    def __str__(self) -> str:
        return 'HTTP {0.code}: {0.message}'.format(self)
