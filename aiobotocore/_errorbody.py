"""Bounds on how much of a failed response body an API call will read.

Error responses are parsed before the retry decision is made, so a service
that returns a very large error body can make the client buffer it in full
even though only the status code and a small prefix are useful.  A
:class:`ErrorBodyBudget` caps the body bytes read for one API call; the same
budget is reused across retries, so retrying cannot multiply the allowance.
Successful responses never consult it: streaming downloads keep their normal
unbounded throughput.
"""

from __future__ import annotations

from ._constants import DEFAULT_ERROR_BODY_LIMIT

__all__ = (
    'DEFAULT_ERROR_BODY_LIMIT',
    'ErrorBodyBudget',
    'error_body_budget_for_context',
)


class ErrorBodyBudget:
    """Cumulative byte budget for error bodies within one API call.

    ``limit=None`` disables the bound.  A fresh budget is created for each API
    call and stored in the request context, so every retry of that call draws
    from the same remaining allowance.
    """

    def __init__(self, limit: int | None = DEFAULT_ERROR_BODY_LIMIT):
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
        ):
            raise ValueError(
                f'error body limit must be a non-negative int or None, '
                f'got {limit!r}'
            )
        self.limit = limit
        self.remaining = limit
        # Cumulative bytes consumed by this API call across all attempts.
        self.consumed = 0

    @property
    def unlimited(self) -> bool:
        return self.limit is None

    def consume(self, amount: int) -> None:
        self.consumed += amount
        if self.remaining is not None:
            self.remaining = max(0, self.remaining - amount)


def error_body_budget_for_context(
    context: dict | None, default: int | None = DEFAULT_ERROR_BODY_LIMIT
) -> ErrorBodyBudget:
    """Return the budget shared by this API call, creating it if needed.

    The configured limit travels in the request context's client config.  A
    session used directly (without an endpoint-created context) falls back to
    ``default``.
    """
    if context is None:
        return ErrorBodyBudget(default)

    budget = context.get('error_body_budget')
    if budget is None:
        client_config = context.get('client_config')
        # An explicit ``error_body_limit=None`` on the config means unlimited,
        # so only fall back to ``default`` when the config has no such option.
        if client_config is not None and hasattr(
            client_config, 'error_body_limit'
        ):
            limit = client_config.error_body_limit
        else:
            limit = default
        budget = ErrorBodyBudget(limit)
        context['error_body_budget'] = budget
    return budget
