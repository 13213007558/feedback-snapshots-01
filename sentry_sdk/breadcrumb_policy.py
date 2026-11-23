"""Per-scope breadcrumb retention policy.

Hosted SDK integrations need to bound the amount of breadcrumbs kept for a
piece of work by *business scope*, independently of the process-wide
``max_breadcrumbs`` option:

* Breadcrumbs recorded on behalf of external requests default to a short
  trail.
* Approved diagnostic code may temporarily raise the allowance inside a
  nested diagnostic scope.
* The same policy governs breadcrumbs produced by the logging integration.

The policy only ever *restricts* retention. The client-wide
``max_breadcrumbs`` option remains the hard upper limit; raising a scope's
allowance can never restore breadcrumbs that were already evicted (from this
scope or a parent scope) and never pulls breadcrumbs back from a parent.
"""

from contextlib import contextmanager
from typing import TYPE_CHECKING

from sentry_sdk.consts import (
    DEFAULT_DIAGNOSTIC_MAX_BREADCRUMBS,
    DEFAULT_EXTERNAL_REQUEST_MAX_BREADCRUMBS,
)
from sentry_sdk.utils import capture_internal_exceptions

if TYPE_CHECKING:
    from typing import Any, Generator, Optional

    from sentry_sdk.scope import Scope

# Provenance recorded on every retained breadcrumb so events can explain
# which policy tier and scope produced each entry.
PROVENANCE_DATA_KEY = "sentry.breadcrumb.policy"

POLICY_SOURCE_DEFAULT = "default"
POLICY_SOURCE_EXTERNAL_REQUEST = "external_request"
POLICY_SOURCE_DIAGNOSTIC = "diagnostic"

# Reason used on the client report entry recorded when the per-scope policy
# (rather than the global ``max_breadcrumbs`` cap) evicts a breadcrumb.
BREADCRUMB_POLICY_DROP_REASON = "breadcrumb_policy_overflow"


class BreadcrumbRetentionPolicy:
    """Retention state attached to a single :class:`sentry_sdk.Scope`.

    Each scope owns an independent policy instance. Forking a scope snapshots
    the current allowance and observation counters (so a nested diagnostic
    scope starts from its parent's tier and can report what the parent had
    already dropped) but never copies evicted breadcrumb entries: the buffer
    itself belongs to the scope that created it and a wider quota can never
    pull dropped entries back from a parent.
    """

    __slots__ = (
        "_external_request_limit",
        "_diagnostic_limit",
        "_source",
        "_allowance",
        "_n_evicted",
        "_n_policy_changes",
    )

    def __init__(
        self,
        external_request_limit: "Optional[int]" = None,
        diagnostic_limit: "Optional[int]" = None,
    ) -> None:
        self._external_request_limit = (
            DEFAULT_EXTERNAL_REQUEST_MAX_BREADCRUMBS
            if external_request_limit is None
            else external_request_limit
        )
        self._diagnostic_limit = (
            DEFAULT_DIAGNOSTIC_MAX_BREADCRUMBS
            if diagnostic_limit is None
            else diagnostic_limit
        )
        self._source: str = POLICY_SOURCE_DEFAULT
        self._allowance: "Optional[int]" = None
        self._n_evicted: int = 0
        self._n_policy_changes: int = 0

    def __copy__(self) -> "BreadcrumbRetentionPolicy":
        rv = BreadcrumbRetentionPolicy(
            external_request_limit=self._external_request_limit,
            diagnostic_limit=self._diagnostic_limit,
        )
        rv._source = self._source
        rv._allowance = self._allowance
        rv._n_evicted = self._n_evicted
        rv._n_policy_changes = self._n_policy_changes
        return rv

    def __eq__(self, other: "object") -> bool:
        if not isinstance(other, BreadcrumbRetentionPolicy):
            return NotImplemented
        return (
            self._external_request_limit == other._external_request_limit
            and self._diagnostic_limit == other._diagnostic_limit
            and self._source == other._source
            and self._allowance == other._allowance
            and self._n_evicted == other._n_evicted
            and self._n_policy_changes == other._n_policy_changes
        )

    @property
    def source(self) -> str:
        return self._source

    @property
    def n_evicted(self) -> int:
        """Number of breadcrumbs evicted from the owning scope by this policy."""
        return self._n_evicted

    @property
    def n_policy_changes(self) -> int:
        """Number of times the allowance was tightened or raised on this scope."""
        return self._n_policy_changes

    def requested_limit(self) -> "Optional[int]":
        """The allowance this scope currently requests, before the global cap."""
        if self._source == POLICY_SOURCE_EXTERNAL_REQUEST:
            return self._external_request_limit
        if self._source == POLICY_SOURCE_DIAGNOSTIC:
            return self._diagnostic_limit
        return self._allowance

    def effective_limit(self, global_limit: int) -> int:
        """Effective retention, clamped to the client-wide hard cap."""
        requested = self.requested_limit()
        if requested is None:
            return global_limit
        return max(0, min(requested, global_limit))

    def apply_tier(self, source: str, allowance: "Optional[int]") -> None:
        self._source = source
        self._allowance = allowance
        self._n_policy_changes += 1

    def mark_evicted(self, quantity: int = 1) -> None:
        self._n_evicted += quantity

    def provenance(self, global_limit: int) -> "dict[str, Any]":
        """Observation payload attached to every retained breadcrumb."""
        return {
            "source": self._source,
            "requested_limit": self.requested_limit(),
            "effective_limit": self.effective_limit(global_limit),
            "global_limit": global_limit,
            "evicted_in_scope": self._n_evicted,
        }


def set_external_request_breadcrumb_limit(scope: "Scope", limit: int) -> None:
    """Tighten ``scope`` to the short trail used for external requests."""
    policy = scope._breadcrumb_policy
    policy._external_request_limit = limit
    policy.apply_tier(POLICY_SOURCE_EXTERNAL_REQUEST, limit)
    scope._enforce_breadcrumb_policy()


def set_breadcrumb_limit(scope: "Scope", limit: int) -> None:
    """Set an explicit, custom allowance on ``scope``."""
    policy = scope._breadcrumb_policy
    policy.apply_tier(POLICY_SOURCE_DEFAULT, limit)
    scope._enforce_breadcrumb_policy()


@contextmanager
def diagnostic_breadcrumbs(
    scope: "Scope", limit: "Optional[int]" = None
) -> "Generator[Scope, None, None]":
    """Temporarily run approved diagnostic code with a larger allowance.

    On exit the previous tier is restored. Raising the allowance inside the
    block does not bring back breadcrumbs evicted earlier, and restoring the
    tighter tier on exit re-evicts overflowing entries.
    """
    policy = scope._breadcrumb_policy
    previous_source = policy._source
    previous_allowance = policy._allowance
    previous_diagnostic_limit = policy._diagnostic_limit

    if limit is not None:
        policy._diagnostic_limit = limit
    policy.apply_tier(POLICY_SOURCE_DIAGNOSTIC, policy._diagnostic_limit)
    try:
        # Entering the wider diagnostic tier must not re-trim entries the
        # forked scope inherited from its parent: those entries already fit
        # the parent's quota and a raised allowance never backfills, but it
        # also must not double-evict. Subsequent add_breadcrumb calls enforce
        # the diagnostic quota; on exit the restored tight tier re-evicts.
        yield scope
    finally:
        policy._diagnostic_limit = previous_diagnostic_limit
        policy.apply_tier(previous_source, previous_allowance)
        with capture_internal_exceptions():
            scope._enforce_breadcrumb_policy()


def apply_external_request_policy(limit: "Optional[int]" = None) -> None:
    """Apply the short external-request trail to the current isolation scope.

    Breadcrumbs added through :func:`sentry_sdk.add_breadcrumb` (including the
    ones produced by the logging integration) are stored on the isolation
    scope, so the policy is applied there.
    """
    from sentry_sdk.scope import Scope

    scope = Scope.get_isolation_scope()
    if limit is not None:
        scope._breadcrumb_policy._external_request_limit = limit
    scope._breadcrumb_policy.apply_tier(
        POLICY_SOURCE_EXTERNAL_REQUEST,
        scope._breadcrumb_policy._external_request_limit,
    )
    scope._enforce_breadcrumb_policy()


def apply_breadcrumb_limit(limit: int) -> None:
    """Apply an explicit breadcrumb allowance to the current isolation scope."""
    from sentry_sdk.scope import Scope

    set_breadcrumb_limit(Scope.get_isolation_scope(), limit)


@contextmanager
def diagnostic_breadcrumbs_scope(
    limit: "Optional[int]" = None,
) -> "Generator[Scope, None, None]":
    """Run the wrapped code in a nested diagnostic scope with a larger quota.

    Both the isolation and current scopes are forked. Breadcrumbs added inside
    the block (including logging-integration breadcrumbs) therefore live on
    the forked isolation scope and never bleed into the parent task; on exit
    the original scopes and the previous, tighter tier are restored.
    """
    from sentry_sdk.scope import isolation_scope

    with isolation_scope() as scope:
        with diagnostic_breadcrumbs(scope, limit):
            yield scope
