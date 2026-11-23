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
        :param limits: The rate limits evaluated for this request, including budgets that had
         enough allowance. This lets a joint admission rejection report the state of the
         other budgets that participated in the decision.
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
        """The limits that were actually exhausted by the request."""

        return [request_limit for request_limit in self.limits if request_limit.breached]

    @property
    def rejected_rule(self) -> str | None:
        """Name (or generated id) of the joint admission declaration that rejected the request."""

        return self.limit.rule_name or self.limit.rule_id

    @property
    def rejected_dimension(self) -> str | None:
        """Name of the budget dimension that rejected the request (``None`` for plain limits)."""

        return self.limit.dimension

    def remaining_for(self, dimension: str) -> int | None:
        """
        Remaining allowance of the evaluated budget for ``dimension``.

        When a dimension declares several windows (``2/minute; 10/hour``) the smallest
        remaining allowance among them is reported: that is the value that decides
        whether the next request can pass. ``None`` means the dimension was not
        evaluated for this request (for example an unauthorized project).
        """
        remaining = [
            request_limit.remaining
            for request_limit in self.limits
            if request_limit.dimension == dimension
        ]

        return min(remaining) if remaining else None

    def reset_at_for(self, dimension: str) -> int | None:
        """
        Timestamp at which the rejected ``dimension`` becomes usable again.

        With several windows the earliest reset that restores any allowance is
        reported. ``None`` means the dimension was not evaluated for this request.
        """
        candidates = [
            request_limit for request_limit in self.limits if request_limit.dimension == dimension
        ]

        if not candidates:
            return None

        exhausted = [request_limit for request_limit in candidates if request_limit.remaining == 0]

        return min(
            (request_limit.reset_at for request_limit in (exhausted or candidates)),
        )

    def remaining_by_dimension(self) -> dict[str, int]:
        """
        Remaining allowance for every evaluated dimension of the rejected rule.

        Dimensions that were skipped for this request are absent instead of reporting a
        misleading allowance.
        """
        dimensions = {
            request_limit.dimension
            for request_limit in self.limits
            if request_limit.dimension is not None
        }

        remaining: dict[str, int] = {}

        for dimension in dimensions:
            value = self.remaining_for(dimension)
            if value is not None:
                remaining[dimension] = value

        return remaining

    def reset_at_by_dimension(self) -> dict[str, int]:
        """Reset timestamp for every dimension evaluated by the rejected rule."""

        dimensions = {
            request_limit.dimension
            for request_limit in self.limits
            if request_limit.dimension is not None
        }
        reset_at: dict[str, int] = {}

        for dimension in dimensions:
            value = self.reset_at_for(dimension)
            if value is not None:
                reset_at[dimension] = value

        return reset_at
