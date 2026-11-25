"""Concurrency budgets for long-running queries."""

from __future__ import annotations

import itertools
import threading
import time
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from types import TracebackType
from typing import Any


__all__ = [
    "BudgetSnapshot",
    "ConcurrencyBudget",
    "QueryBudget",
    "QueryBudgetCancelled",
    "QueryBudgetError",
    "QueryBudgetExceeded",
    "QueryBudgetTimeout",
    "QueryLease",
]


class QueryBudgetError(RuntimeError):
    """Base class for query budget failures."""


class QueryBudgetExceeded(QueryBudgetError):
    """Raised when a budget has no capacity and acquisition cannot wait."""


class QueryBudgetTimeout(QueryBudgetExceeded):
    """Raised when waiting for budget capacity times out."""


class QueryBudgetCancelled(QueryBudgetError):
    """Raised when an acquisition is cancelled before receiving a lease."""


def _validate_limit(value: int | None, name: str) -> int | None:
    """Validate a concurrency limit."""
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer or None")

    return value


@dataclass(frozen=True)
class BudgetSnapshot:
    """An immutable point-in-time view of a :class:`QueryBudget`."""

    association_id: Hashable | None
    association_limit: int | None
    association_active: int
    association_waiting: int
    server_limit: int | None
    server_active: int
    server_waiting: int

    @property
    def association_available(self) -> int | None:
        """Return unused association capacity, or ``None`` if unlimited."""
        if self.association_limit is None:
            return None

        return self.association_limit - self.association_active

    @property
    def server_available(self) -> int | None:
        """Return unused server-wide capacity, or ``None`` if unlimited."""
        if self.server_limit is None:
            return None

        return self.server_limit - self.server_active

    def available(self) -> dict[str, int | None]:
        """Return the available association and server capacity."""
        return {
            "association": self.association_available,
            "server": self.server_available,
        }


class QueryLease:
    """An acquired unit of concurrency budget."""

    __slots__ = (
        "_budget",
        "association_id",
        "query_id",
        "_released",
        "_snapshot",
    )

    def __init__(
        self,
        budget: QueryBudget,
        association_id: Hashable,
        query_id: Hashable,
    ) -> None:
        self._budget = budget
        self.association_id = association_id
        self.query_id = query_id
        self._released = False
        self._snapshot: BudgetSnapshot | None = None

    @property
    def released(self) -> bool:
        """Return ``True`` if the lease has been released."""
        return self._released

    @property
    def snapshot(self) -> BudgetSnapshot | None:
        """Return the snapshot recorded when the lease was released."""
        return self._snapshot

    def release(self) -> BudgetSnapshot | None:
        """Release the lease and restore its budget capacity."""
        return self._budget._release(self)

    def __enter__(self) -> QueryLease:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class QueryBudget:
    """Hierarchical per-association and server-wide query budgets.

    A lease is active only when capacity exists under both limits. Releasing a
    lease updates both counts atomically and wakes waiting acquirers.
    """

    def __init__(
        self,
        association_limit: int | None = None,
        server_limit: int | None = None,
        *,
        per_association: int | None = None,
        server_wide: int | None = None,
        global_limit: int | None = None,
    ) -> None:
        if association_limit is None:
            association_limit = per_association

        if server_limit is None:
            server_limit = server_wide

        if server_limit is None:
            server_limit = global_limit

        self.association_limit = _validate_limit(
            association_limit, "association_limit"
        )
        self.server_limit = _validate_limit(server_limit, "server_limit")

        self._condition = threading.Condition(threading.RLock())
        self._query_ids = itertools.count(1)

        self._server_active = 0
        self._server_waiting = 0
        self._association_active: dict[Hashable, int] = {}
        self._association_waiting: dict[Hashable, int] = {}
        self._owners: dict[Hashable, Hashable] = {}

    def acquire(
        self,
        association_id: Hashable | None = "default",
        query_id: Hashable | None = None,
        *,
        block: bool = True,
        timeout: float | None = None,
        cancel_check: Callable[[], bool] | None = None,
        poll_interval: float = 0.01,
    ) -> QueryLease:
        """Acquire one association and one server-wide budget slot."""
        if association_id is None:
            association_id = "default"

        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(
                timeout, (int, float)
            ):
                raise ValueError("timeout must be a number or None")
            if timeout < 0:
                raise ValueError("timeout must be non-negative")

        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or poll_interval <= 0
        ):
            raise ValueError("poll_interval must be a positive number")

        if not block:
            timeout = 0

        if cancel_check is not None and cancel_check():
            raise QueryBudgetCancelled("Query was cancelled before admission")

        deadline = None if timeout is None else time.monotonic() + timeout

        with self._condition:
            if query_id is None:
                query_id = next(self._query_ids)

            if query_id in self._owners:
                raise ValueError(f"query_id {query_id!r} already owns a lease")

            while not self._can_acquire_locked(association_id):
                if not block:
                    raise QueryBudgetExceeded("Query concurrency budget is full")

                self._server_waiting += 1
                self._association_waiting[association_id] = (
                    self._association_waiting.get(association_id, 0) + 1
                )
                try:
                    if cancel_check is not None:
                        wait_time = poll_interval
                        if deadline is not None:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise QueryBudgetTimeout(
                                    "Timed out waiting for query budget"
                                )
                            wait_time = min(wait_time, remaining)
                        self._condition.wait(wait_time)
                    elif deadline is None:
                        self._condition.wait()
                    else:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise QueryBudgetTimeout(
                                "Timed out waiting for query budget"
                            )
                        self._condition.wait(remaining)
                finally:
                    self._server_waiting -= 1
                    association_waiting = (
                        self._association_waiting.get(association_id, 1) - 1
                    )
                    if association_waiting <= 0:
                        self._association_waiting.pop(association_id, None)
                    else:
                        self._association_waiting[association_id] = (
                            association_waiting
                        )

                if cancel_check is not None and cancel_check():
                    raise QueryBudgetCancelled(
                        "Query was cancelled while waiting for budget"
                    )

                if (
                    deadline is not None
                    and time.monotonic() >= deadline
                    and not self._can_acquire_locked(association_id)
                ):
                    raise QueryBudgetTimeout(
                        "Timed out waiting for query budget"
                    )

            self._server_active += 1
            self._association_active[association_id] = (
                self._association_active.get(association_id, 0) + 1
            )
            self._owners[query_id] = association_id

        return QueryLease(self, association_id, query_id)

    def lease(
        self,
        association_id: Hashable | None = "default",
        query_id: Hashable | None = None,
        **kwargs: Any,
    ) -> QueryLease:
        """Alias for :meth:`acquire`, intended for context-manager use."""
        return self.acquire(association_id, query_id, **kwargs)

    def try_acquire(
        self,
        association_id: Hashable | None = "default",
        query_id: Hashable | None = None,
    ) -> QueryLease:
        """Acquire a lease without waiting."""
        return self.acquire(association_id, query_id, block=False)

    def _can_acquire_locked(self, association_id: Hashable) -> bool:
        """Return whether both budgets currently have capacity."""
        association_active = self._association_active.get(association_id, 0)
        association_ok = (
            self.association_limit is None
            or association_active < self.association_limit
        )
        server_ok = (
            self.server_limit is None
            or self._server_active < self.server_limit
        )
        return association_ok and server_ok

    def _release(self, lease: QueryLease) -> BudgetSnapshot | None:
        """Release a lease and wake waiting acquirers."""
        with self._condition:
            if lease._released:
                return lease._snapshot

            association_id = lease.association_id
            if self._owners.get(lease.query_id) != association_id:
                raise RuntimeError("Query lease does not own active budget slot")

            self._server_active -= 1
            association_active = (
                self._association_active.get(association_id, 1) - 1
            )
            if association_active <= 0:
                self._association_active.pop(association_id, None)
            else:
                self._association_active[association_id] = association_active

            del self._owners[lease.query_id]
            lease._released = True
            snapshot = self._snapshot_locked(association_id)
            lease._snapshot = snapshot
            self._condition.notify_all()
            return snapshot

    def snapshot(
        self, association_id: Hashable | None = "default"
    ) -> BudgetSnapshot:
        """Return an immutable snapshot for ``association_id``."""
        if association_id is None:
            association_id = "default"

        with self._condition:
            return self._snapshot_locked(association_id)

    def _snapshot_locked(self, association_id: Hashable) -> BudgetSnapshot:
        return BudgetSnapshot(
            association_id=association_id,
            association_limit=self.association_limit,
            association_active=self._association_active.get(association_id, 0),
            association_waiting=self._association_waiting.get(
                association_id, 0
            ),
            server_limit=self.server_limit,
            server_active=self._server_active,
            server_waiting=self._server_waiting,
        )

    def available(
        self, association_id: Hashable | None = "default"
    ) -> dict[str, int | None]:
        """Return available association and server capacity."""
        return self.snapshot(association_id).available()

    def active_count(self, association_id: Hashable | None = None) -> int:
        """Return active leases for one association, or globally."""
        with self._condition:
            if association_id is None:
                return self._server_active

            return self._association_active.get(association_id, 0)


ConcurrencyBudget = QueryBudget
QueryConcurrencyBudget = QueryBudget
