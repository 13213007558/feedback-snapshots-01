"""Shared per-request traversal budget for load operations.

A traversal budget bounds how many field nodes a single load request may
visit. Nested schemas and collection fields (``List``, ``Dict``, ``Tuple``)
all draw from the same budget, so a single limit controls the total
validation work for one request, regardless of how the data is shaped.

.. warning::
    This module is treated as private API.
    Users should not need to use this module directly.
"""

from __future__ import annotations

import contextvars
import typing

from marshmallow.exceptions import ValidationError

_CURRENT_BUDGET: contextvars.ContextVar[TraversalBudget | None] = (
    contextvars.ContextVar("traversal_budget", default=None)
)


class TraversalBudgetExceeded(ValidationError):
    """Raised when the traversal budget for a load request is exhausted."""


class TraversalBudget:
    """A shared, per-request budget for traversal during deserialization.

    Each deserialized field node consumes one unit. When the budget is
    exhausted, :exc:`TraversalBudgetExceeded` is raised and no further
    validators are invoked for the request.
    """

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("Traversal budget limit must be >= 0.")
        self.limit = limit
        self.remaining = limit
        self._token: contextvars.Token | None = None

    @property
    def exceeded(self) -> bool:
        """Whether the budget has been used up."""
        return self.remaining < 0

    def consume(self, amount: int = 1) -> None:
        """Consume ``amount`` units, raising once the budget is exhausted."""
        self.remaining -= amount
        if self.remaining < 0:
            raise TraversalBudgetExceeded(f"Traversal budget of {self.limit} exceeded.")

    def __enter__(self) -> TraversalBudget:
        self._token = _CURRENT_BUDGET.set(self)
        return self

    def __exit__(self, *args, **kwargs) -> None:
        _CURRENT_BUDGET.reset(typing.cast("contextvars.Token", self._token))
        self._token = None


def current_budget() -> TraversalBudget | None:
    """Return the budget active for the current load request, if any."""
    return _CURRENT_BUDGET.get()
