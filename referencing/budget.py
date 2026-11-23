"""
Per-validation resource budgets for reference resolution.

A budget bounds the work that a single validation request may cause while
resolving JSON references. Three independent kinds of work are metered, each
matching a real step of the resolution process:

* :class:`WorkKind.REFERENCE` -- following a ``$ref`` (one resolver lookup)
* :class:`WorkKind.BRANCH` -- crawling a newly discovered subresource, i.e.
  expanding a schema's branches
* :class:`WorkKind.RETRIEVAL` -- an on-demand fetch of a resource that was not
  already present

Budgets follow the *resolution process*, not a particular function call. The
active budget is held in a :class:`contextvars.ContextVar`, so it survives
nested resolution -- including a nested resolver returning to its parent and
continuing to look up further references -- and propagates across
``await`` points. Each request gets its own :class:`Budget`, so two concurrent
requests never share a balance, while the underlying (in-memory) resources are
freely reused across requests.

Reusing a resource is deliberately cheap: a shared subresource is crawled once
and a fetched resource is retrieved once, after which further references to it
only consume the (per-lookup) reference budget.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from enum import Enum
from threading import Lock
from typing import TYPE_CHECKING, Any

import attrs

from referencing._core import (
    Registry,
    Resolver,
    Resource,
    _fail_to_retrieve,
)
from referencing.typing import URI

if TYPE_CHECKING:
    from referencing._core import Resolved

#: Sentinel meaning a particular kind of work is not budgeted.
UNLIMITED = -1


class WorkKind(Enum):
    """
    The kinds of resolution work a budget may place a limit on.
    """

    #: Following a single ``$ref`` via a resolver lookup.
    REFERENCE = "reference"

    #: Crawling one newly discovered subresource (expanding a branch).
    BRANCH = "branch"

    #: Fetching one resource on demand because it is not already present.
    RETRIEVAL = "retrieval"


@attrs.frozen
class BudgetExceeded(Exception):
    """
    A budget limit was reached while doing resolution work.

    The :attr:`kind` records *which* kind of work hit its limit so callers can
    distinguish a reference, branch-expansion, or on-demand retrieval failure.
    """

    kind: WorkKind
    limit: int
    used: int
    detail: str

    def __str__(self) -> str:
        return (
            f"resource budget exceeded for {self.kind.value!r} work: "
            f"limit={self.limit}, used={self.used} ({self.detail})"
        )


class ReferenceBudgetExceeded(BudgetExceeded):
    """Raised when too many ``$ref`` lookups are followed."""


class BranchBudgetExceeded(BudgetExceeded):
    """Raised when too many subresources are crawled (branches expanded)."""


class RetrievalBudgetExceeded(BudgetExceeded):
    """Raised when too many resources are fetched on demand."""


_EXCEEDED: dict[WorkKind, type[BudgetExceeded]] = {
    WorkKind.REFERENCE: ReferenceBudgetExceeded,
    WorkKind.BRANCH: BranchBudgetExceeded,
    WorkKind.RETRIEVAL: RetrievalBudgetExceeded,
}


@attrs.frozen
class BudgetLimits:
    """
    The per-request upper bounds for each kind of resolution work.

    A limit of :data:`UNLIMITED` (the default) means that kind of work is not
    bounded.
    """

    references: int = UNLIMITED
    branches: int = UNLIMITED
    retrievals: int = UNLIMITED

    def for_kind(self, kind: WorkKind) -> int:
        """Return the configured limit for the given kind of work."""
        return {
            WorkKind.REFERENCE: self.references,
            WorkKind.BRANCH: self.branches,
            WorkKind.RETRIEVAL: self.retrievals,
        }[kind]


class Budget:
    """
    A per-request, concurrency-safe tally of resolution work.

    Two budgets created for two requests are fully independent: charging one
    never affects the balance of the other, even when both run concurrently and
    resolve against the same shared resources.
    """

    def __init__(self, limits: BudgetLimits, name: str = "request") -> None:
        self.limits = limits
        self.name = name
        self._used: dict[WorkKind, int] = {
            kind: 0 for kind in WorkKind
        }
        self._lock = Lock()

    def used(self, kind: WorkKind) -> int:
        """Return how many units of the given kind have been charged."""
        with self._lock:
            return self._used[kind]

    def remaining(self, kind: WorkKind) -> int | None:
        """Return remaining units, or ``None`` when this kind is unlimited."""
        limit = self.limits.for_kind(kind)
        if limit == UNLIMITED:
            return None
        return limit - self.used(kind)

    def snapshot(self) -> dict[WorkKind, int]:
        """Return an immutable copy of the usage so far, by work kind."""
        with self._lock:
            return dict(self._used)

    def charge(self, kind: WorkKind, detail: str, amount: int = 1) -> None:
        """
        Charge ``amount`` units of ``kind`` against this budget.

        Raises the matching :class:`BudgetExceeded` subclass if the charge
        would cross the configured limit. The charge is atomic: on failure no
        units are consumed.
        """
        limit = self.limits.for_kind(kind)
        with self._lock:
            current = self._used[kind]
            if limit != UNLIMITED and current + amount > limit:
                raise _EXCEEDED[kind](
                    kind=kind,
                    limit=limit,
                    used=current,
                    detail=detail,
                )
            self._used[kind] = current + amount


_ACTIVE: ContextVar[Budget | None] = ContextVar("active_budget", default=None)


def current_budget() -> Budget | None:
    """Return the budget active in this context, if any."""
    return _ACTIVE.get()


@contextmanager
def budget_scope(budget: Budget) -> Iterator[Budget]:
    """
    Run resolution work with ``budget`` as the active per-request budget.

    The budget is stored in a :class:`~contextvars.ContextVar`, so nested
    resolvers -- and any ``await`` boundaries -- keep seeing the same budget.
    Restoring the previous value on exit makes nested or sequential
    scopes safe.
    """
    token: Token[Budget | None] = _ACTIVE.set(budget)
    try:
        yield budget
    finally:
        _ACTIVE.reset(token)


class CachingRetriever:
    """
    A retriever with a shared in-memory cache and per-request retrieval
    billing.

    The cache is shared across every request that uses the same instance, so a
    resource fetched for one request is reused by the next without another
    fetch (and without another retrieval charge). Only an actual cache miss
    invokes the wrapped retriever and bills the active budget.
    """

    def __init__(self, retrieve: Callable[[URI], Resource[Any]]) -> None:
        self._retrieve = retrieve
        self._cache: dict[URI, Resource[Any]] = {}
        self._lock = Lock()

    def __call__(self, uri: URI) -> Resource[Any]:
        with self._lock:
            cached = self._cache.get(uri)
        if cached is not None:
            # A cache hit reuses an already-fetched resource: it performs no
            # on-demand work and must never consume retrieval budget.
            return cached

        # Only a *successful* fetch is billable on-demand work. If the wrapped
        # retriever raises (e.g. the resource does not exist), no unit is
        # charged and the registry converts that into its normal error.
        resource = self._retrieve(uri)

        budget = current_budget()
        if budget is not None:
            budget.charge(
                WorkKind.RETRIEVAL,
                detail=f"on-demand fetch of {uri!r}",
            )

        with self._lock:
            existing = self._cache.get(uri)
            if existing is not None:
                return existing
            self._cache[uri] = resource
        return resource


_INSTALLED = False


def _install_branch_meter() -> None:
    """
    Charge the active budget whenever crawling discovers a subresource.

    ``Resource.subresources`` is only consumed by ``Registry.crawl``, so each
    yielded subresource corresponds to one branch-expansion step of the real
    resolution process. It is a no-op when no budget is active, leaving the
    ordinary recursion model untouched.
    """
    global _INSTALLED
    if _INSTALLED:
        return

    original = Resource.subresources

    def metered(self: Resource[Any]) -> Iterator[Resource[Any]]:
        budget = current_budget()
        for subresource in original(self):
            if budget is not None:
                budget.charge(
                    WorkKind.BRANCH,
                    detail=(
                        "crawling subresource "
                        f"{subresource.id() or '<no id>'!r}"
                    ),
                )
            yield subresource

    Resource.subresources = metered  # type: ignore[method-assign]
    _INSTALLED = True


class BudgetedResolver:
    """
    A resolver wrapper that bills each ``$ref`` lookup to the active budget.

    It delegates to the underlying immutable :class:`Resolver`, preserving its
    normal recursive resolution (including evolving registries and base URIs as
    nested resources are entered). Branch and retrieval charging happens deeper
    in the registry/retriever via the active budget, so a nested resolver
    returning to its parent keeps the same budget throughout.
    """

    def __init__(self, resolver: Resolver[Any]) -> None:
        self._resolver = resolver

    def lookup(self, ref: URI) -> Resolved[Any]:
        """Resolve ``ref``, charging one reference unit first."""
        budget = current_budget()
        if budget is not None:
            budget.charge(
                WorkKind.REFERENCE,
                detail=f"following $ref {ref!r}",
            )
        resolved = self._resolver.lookup(ref)
        return resolved

    def in_subresource(self, resource: Resource[Any]) -> BudgetedResolver:
        """Enter a subresource, wrapping the evolved resolver."""
        return BudgetedResolver(self._resolver.in_subresource(resource))

    @property
    def resolver(self) -> Resolver[Any]:
        """The underlying immutable resolver."""
        return self._resolver


def make_budgeted_registry(
    retrieve: Callable[[URI], Resource[Any]] | None = None,
) -> tuple[Registry[Any], CachingRetriever]:
    """
    Build a registry wired to the active-budget machinery.

    The returned registry keeps the library's normal in-memory and recursive
    behavior; the only addition is that branch expansion (crawl) and on-demand
    retrieval are billed to the active :class:`Budget`. Resources already added
    to the registry are reused directly and never trigger a retrieval.
    """
    _install_branch_meter()
    if retrieve is None:
        caching = CachingRetriever(_fail_to_retrieve)
    elif isinstance(retrieve, CachingRetriever):
        # Reuse an existing cache instead of double-wrapping (which would
        # otherwise bill a single fetch more than once).
        caching = retrieve
    else:
        caching = CachingRetriever(retrieve)
    registry: Registry[Any] = Registry(retrieve=caching)
    return registry, caching


def budgeted_resolver(
    registry: Registry[Any], base_uri: URI = ""
) -> BudgetedResolver:
    """Return a reference-billing resolver backed by ``registry``."""
    return BudgetedResolver(registry.resolver(base_uri=base_uri))
