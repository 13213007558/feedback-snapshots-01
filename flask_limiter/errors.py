"""errors and exceptions."""

from __future__ import annotations

from flask.wrappers import Response
from werkzeug import exceptions

from ._identity import MissingIdentity
from ._limits import RuntimeLimit


class RateLimitExceeded(exceptions.TooManyRequests):
    """Exception raised when a rate limit is hit."""

    def __init__(self, limit: RuntimeLimit, response: Response | None = None) -> None:
        """
        :param limit: The actual rate limit that was hit. This is used to construct the default
         response message
        :param response: Optional pre constructed response. If provided it will be rendered by
         flask instead of the default error response of :class:`~werkzeug.exceptions.HTTPException`
        """
        self.limit = limit
        self.response = response
        if limit.error_message:
            description = (
                limit.error_message if not callable(limit.error_message) else limit.error_message()
            )
        else:
            description = str(limit.limit)
        super().__init__(description=description, response=response)


class MissingIdentityError(exceptions.HTTPException):
    """
    Raised when a limit uses the ``reject`` missing identity policy.

    Anonymous requests are rejected with ``401`` and requests whose identity
    could not be confirmed are rejected with ``503``.
    """

    code = 401

    def __init__(
        self,
        reason: MissingIdentity,
        limit: RuntimeLimit | None = None,
        description: str | None = None,
    ) -> None:
        self.reason = reason
        self.limit = limit
        super().__init__(description=description or self.description)


class AnonymousIdentityRejected(MissingIdentityError):
    """Raised for anonymous requests when the missing identity policy is ``reject``."""

    code = 401
    description = "Authentication required."


class UnconfirmedIdentityRejected(MissingIdentityError):
    """
    Raised when the identity service cannot confirm an identity and the missing
    identity policy is ``reject``.
    """

    code = 503
    description = "Identity could not be confirmed."


def missing_identity_error(
    reason: MissingIdentity,
    limit: RuntimeLimit | None = None,
) -> MissingIdentityError:
    if reason is MissingIdentity.UNCONFIRMED:
        return UnconfirmedIdentityRejected(reason, limit)

    return AnonymousIdentityRejected(reason, limit)
