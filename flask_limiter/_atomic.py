from __future__ import annotations

import dataclasses
import threading
import time
import weakref
from typing import Protocol, runtime_checkable

from limits import RateLimitItem, WindowStats
from limits.errors import ConfigurationError
from limits.storage import MemoryStorage, Storage
from limits.strategies import RateLimiter, SlidingWindowCounterRateLimiter

from ._typing import Sequence

__all__ = [
    "AtomicBudget",
    "AtomicReservationError",
    "AtomicReservationStorage",
    "ReservationResult",
    "atomic_backend_for",
    "require_atomic_backend",
]


@dataclasses.dataclass(frozen=True)
class AtomicBudget:
    """A single budget that must be reserved together with its peers."""

    item: RateLimitItem
    identifiers: tuple[str, ...]
    cost: int = 1

    @property
    def key(self) -> str:
        return self.item.key_for(*self.identifiers)


@dataclasses.dataclass(frozen=True)
class ReservationResult:
    """Outcome and (post-decision) window state for one budget."""

    key: str
    granted: bool
    window: WindowStats


@runtime_checkable
class AtomicReservationStorage(Protocol):
    """Storage contract required by grouped admission rules."""

    def reserve_many(self, budgets: Sequence[AtomicBudget]) -> list[ReservationResult]:
        """Atomically reserve every budget or none of them."""
        ...


class AtomicReservationError(RuntimeError):
    """Raised when a storage transaction could not be completed atomically."""


@dataclasses.dataclass
class _Snapshot:
    counters: dict[str, int | None]
    expirations: dict[str, float | None]
    events: dict[str, list[object] | None]


class _MemoryAtomicBackend:
    """
    All-or-nothing reservations on top of :class:`limits.storage.MemoryStorage`.

    The whole transaction is serialized per storage instance and additionally takes the
    per-key locks used by the storage, so ordinary (single key) hits cannot interleave
    with a grouped decision. A snapshot of every involved key is restored if a write
    fails, which also covers storage failures injected between writes.
    """

    _guards: weakref.WeakKeyDictionary[MemoryStorage, threading.RLock] = weakref.WeakKeyDictionary()
    _guards_lock = threading.Lock()

    def __init__(self, storage: MemoryStorage, strategy: RateLimiter) -> None:
        self.storage = storage
        self.strategy = strategy
        with self._guards_lock:
            self._guard = self._guards.setdefault(storage, threading.RLock())

    def _keys_for(self, budget: AtomicBudget, now: float) -> set[str]:
        key = budget.key
        keys = {key}

        if isinstance(self.strategy, SlidingWindowCounterRateLimiter):
            previous, current = MemoryStorage.sliding_window_keys(
                key, budget.item.get_expiry(), now
            )
            keys.update((previous, current))

        return keys

    def _snapshot(self, keys: set[str]) -> _Snapshot:
        return _Snapshot(
            counters={key: self.storage.storage.get(key) for key in keys},
            expirations={key: self.storage.expirations.get(key) for key in keys},
            events={
                key: list(self.storage.events[key]) if key in self.storage.events else None
                for key in keys
            },
        )

    def _restore(self, snapshot: _Snapshot) -> None:
        for key, value in snapshot.counters.items():
            if value is None:
                self.storage.storage.pop(key, None)
            else:
                self.storage.storage[key] = value

        for key, value in snapshot.expirations.items():
            if value is None:
                self.storage.expirations.pop(key, None)
            else:
                self.storage.expirations[key] = value

        for key, events in snapshot.events.items():
            if events is None:
                self.storage.events.pop(key, None)
            else:
                self.storage.events[key] = events

    def _window(self, budget: AtomicBudget, now: float) -> WindowStats:
        stats = self.strategy.get_window_stats(budget.item, *budget.identifiers)
        reset, remaining = stats

        # A rejected request that never started a window should advertise the end of
        # the window it would have used instead of "now".
        if reset <= now:
            reset = now + budget.item.get_expiry()

        return WindowStats(reset, max(0, remaining))

    def reserve_many(self, budgets: Sequence[AtomicBudget]) -> list[ReservationResult]:
        budgets = list(budgets)
        if not budgets:
            return []

        now = time.time()
        locks = {key for budget in budgets for key in self._keys_for(budget, now)}

        with self._guard:
            acquired = [self.storage.locks[key] for key in sorted(locks)]
            for lock in acquired:
                lock.acquire()

            try:
                affordable = [
                    self.strategy.test(budget.item, *budget.identifiers, cost=budget.cost)
                    for budget in budgets
                ]

                if not all(affordable):
                    return [
                        ReservationResult(
                            budget.key,
                            granted,
                            self._window(budget, now),
                        )
                        for budget, granted in zip(budgets, affordable, strict=True)
                    ]

                snapshot = self._snapshot(locks)
                try:
                    for budget in budgets:
                        if not self.strategy.hit(
                            budget.item, *budget.identifiers, cost=budget.cost
                        ):
                            raise AtomicReservationError(
                                f"Budget {budget.key} could not be reserved atomically"
                            )
                except BaseException:
                    self._restore(snapshot)
                    raise

                return [
                    ReservationResult(budget.key, True, self._window(budget, now))
                    for budget in budgets
                ]
            finally:
                for lock in reversed(acquired):
                    lock.release()


class _ProtocolAtomicBackend:
    """Adapter for third party storages implementing :class:`AtomicReservationStorage`."""

    def __init__(self, storage: AtomicReservationStorage) -> None:
        self.storage = storage

    def reserve_many(self, budgets: Sequence[AtomicBudget]) -> list[ReservationResult]:
        return self.storage.reserve_many(budgets)


def atomic_backend_for(
    storage: Storage, strategy: RateLimiter
) -> _MemoryAtomicBackend | _ProtocolAtomicBackend | None:
    """
    Return an atomic reservation backend for ``storage`` or ``None`` when the storage
    cannot provide all-or-nothing multi-budget reservations.
    """

    if isinstance(storage, MemoryStorage):
        return _MemoryAtomicBackend(storage, strategy)

    if isinstance(storage, AtomicReservationStorage):
        return _ProtocolAtomicBackend(storage)

    return None


def require_atomic_backend(
    storage: Storage, strategy: RateLimiter
) -> _MemoryAtomicBackend | _ProtocolAtomicBackend:
    backend = atomic_backend_for(storage, strategy)

    if backend is None:
        raise ConfigurationError(
            "Grouped admission rules require a storage backend with atomic "
            "multi-budget reservation support. The built-in memory:// storage "
            "supports it; the configured storage "
            f"{storage.__class__.__name__} does not. Use memory:// or provide a "
            "storage implementing AtomicReservationStorage.reserve_many()."
        )

    return backend
