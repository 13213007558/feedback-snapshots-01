"""errors and exceptions."""

from __future__ import annotations

from flask.wrappers import Response
from werkzeug import exceptions

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
        elif not limit.expose_headers:
            # The limit is intentionally not disclosed to the client (for example an
            # internal budget). Fall back to the generic 429 description instead of
            # rendering the limit's amount and window.
            description = exceptions.TooManyRequests.description
        else:
            description = str(limit.limit)
        super().__init__(description=description, response=response)
