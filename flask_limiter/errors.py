"""errors and exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask.wrappers import Response
from werkzeug import exceptions

from ._limits import RuntimeLimit

if TYPE_CHECKING:
    from ._extension import RequestLimit


class RateLimitExceeded(exceptions.TooManyRequests):
    """Exception raised when a rate limit is hit."""

    def __init__(
        self,
        limit: RuntimeLimit,
        response: Response | None = None,
        *,
        limits: list[RequestLimit] | None = None,
    ) -> None:
        """
        :param limit: The actual rate limit that was hit. This is used to construct the default
         response message
        :param response: Optional pre constructed response. If provided it will be rendered by
         flask instead of the default error response of :class:`~werkzeug.exceptions.HTTPException`
        :param limits: All the rate limits evaluated for the request, including the ones that
         were not breached. This is used to report the state of the other dimensions of a
         multi-dimensional limit.
        """
        self.limit = limit
        self.response = response
        self.limits = limits or []
        if limit.error_message:
            description = (
                limit.error_message if not callable(limit.error_message) else limit.error_message()
            )
        elif limit.dimension:
            description = f"{limit.dimension}: {limit.limit}"
        else:
            description = str(limit.limit)
        super().__init__(description=description, response=response)

    @property
    def breached_limits(self) -> list[RequestLimit]:
        """
        The rate limits that were actually exhausted by the request.

        For a multi-dimensional declaration this normally contains the single dimension that
        rejected the request; with :paramref:`~flask_limiter.Limiter.fail_on_first_breach`
        disabled it can contain several dimensions of the same rule.
        """

        return [request_limit for request_limit in self.limits if request_limit.breached]

    @property
    def rejected_rule(self) -> str | None:
        """Name of the rule declaration that rejected the request (if any)."""

        return self.limit.rule_name or self.limit.rule_id

    @property
    def rejected_dimension(self) -> str | None:
        """Name of the dimension that rejected the request (``None`` for plain limits)."""

        return self.limit.dimension

    def remaining_for(self, dimension: str) -> int | None:
        """
        Remaining allowance of the evaluated limit for ``dimension``.

        Returns ``None`` when the dimension was not evaluated for this request (for
        example because the request's project was not authorized).
        """

        for request_limit in self.limits:
            if request_limit.dimension == dimension:
                return request_limit.remaining

        return None

    def remaining_by_dimension(self) -> dict[str, int]:
        """
        Remaining allowance for every evaluated dimension of the rejected rule.

        Dimensions that were skipped for this request (for example because the project
        was not authorized) are absent instead of reporting a misleading allowance.
        """

        return {
            request_limit.dimension: request_limit.remaining
            for request_limit in self.limits
            if request_limit.dimension is not None
        }
