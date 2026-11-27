"""Explicit target approval for service authentication requests.

Services authenticate requests by talking to the Hub API.  The address used
for that exchange carries identity material (service tokens, user tokens and
OAuth client secrets), so it must be selected from an explicit allow-list of
approved targets.

Two separate concepts are modelled here:

``approved`` targets
    Origins that may receive authentication material.

``candidates``
    Ordered origins considered when selecting a target.  Candidates that are
    not approved are *health-check only*: they may be probed, but they never
    receive credentials.

Approval is checked every time a target is selected, including when a cached
selection is reused and when a request is retried, so a stale connection can
never lend permission to a target that is no longer approved.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, Sequence
from urllib.parse import urlparse, urlunparse

from tornado.web import HTTPError
from traitlets import Bool, List, Unicode
from traitlets.config import LoggingConfigurable

_DEFAULT_PORTS = {"http": 80, "https": 443}
_UNIX_SCHEME = "http+unix"

logger = logging.getLogger(__name__)


class TargetPolicyError(HTTPError):
    """Base class for target selection failures."""


class TargetNotApproved(TargetPolicyError):
    """No approved target could be selected.

    The request is refused locally: no authentication material is sent
    anywhere.  Status 403 distinguishes this from a network failure (503).
    """

    def __init__(self, approved=(), skipped=()):
        self.approved = tuple(approved)
        self.skipped = tuple(skipped)
        approved_text = ", ".join(self.approved) or "none"
        msg = (
            "No approved authentication target is available "
            f"(approved: {approved_text})"
        )
        if self.skipped:
            msg += "; skipped unapproved candidates: " + ", ".join(self.skipped)
        super().__init__(403, msg)


class TargetUnavailable(TargetPolicyError):
    """Every approved target failed at the transport level.

    Status 503 distinguishes this from insufficient approval (403).
    """

    def __init__(self, targets, errors=None):
        self.targets = tuple(targets)
        self.errors = dict(errors or {})
        msg = "Failed to reach any approved authentication target: " + (
            ", ".join(self.targets) or "none"
        )
        super().__init__(503, msg)


@dataclass
class AuthCallRecord:
    """Audit record for one authentication-related target interaction.

    ``outcome`` is one of ``success``, ``http-error``, ``network-error``,
    ``not-approved`` or ``health-check``.  Records for unapproved targets are
    written without ever contacting them.
    """

    category: str
    target: str
    outcome: str
    method: str = "GET"
    url: str = ""
    status: int | None = None
    approval: str = "approved"
    timestamp: float = field(default_factory=time.time)


def normalize_target(url: str) -> str:
    """Return the canonical origin of *url* used for approval checks.

    Only scheme, host and (non-default) port are significant.  Credentials,
    paths and query strings do not participate in approval, so they cannot be
    used to smuggle an identity exchange to a different origin.
    """
    if not url:
        raise ValueError("empty target URL")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        raise ValueError(f"target URL has no scheme: {url!r}")

    if scheme == _UNIX_SCHEME:
        if not parsed.netloc:
            raise ValueError(f"unix-socket target has no socket path: {url!r}")
        return f"{scheme}://{parsed.netloc}"

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"target URL has no host: {url!r}")
    port = parsed.port
    default_port = _DEFAULT_PORTS.get(scheme)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        netloc += f":{port}"
    return f"{scheme}://{netloc}"


def replace_origin(url: str, target: str) -> str:
    """Return *url* with its scheme/netloc replaced by *target*.

    The path, query and fragment of *url* are preserved.  This is how an
    approved target is applied to a concrete API endpoint without allowing a
    target's own path to influence which endpoint is called.
    """
    parsed = urlparse(url)
    replacement = urlparse(target)
    return urlunparse(
        parsed._replace(scheme=replacement.scheme, netloc=replacement.netloc)
    )


def origin_list(urls: Iterable[str], *, strict: bool = False) -> list[str]:
    """Normalize an iterable of URLs, preserving order and de-duplicating.

    Invalid entries are skipped with a warning unless ``strict`` is set, so a
    typo in one candidate cannot crash authentication for the whole service.
    Invalid entries are never treated as approved.
    """
    seen = set()
    result = []
    for url in urls:
        try:
            target = normalize_target(url)
        except ValueError as e:
            if strict:
                raise
            logger.warning("Ignoring invalid authentication target %r: %s", url, e)
            continue
        if target not in seen:
            seen.add(target)
            result.append(target)
    return result


class TargetPolicy(LoggingConfigurable):
    """Ordered, explicitly approved targets for authenticated requests.

    The policy caches the most recently selected target together with a
    *generation* counter.  Any trust configuration change bumps the
    generation and clears the cached selection, so an old cached connection
    cannot authorise a different target after the allow-list changes.
    """

    approved = List(Unicode(), help="Origins allowed to receive identity material.")
    candidates = List(Unicode(), help="Ordered candidate origins.")
    use_cache = Bool(
        True, help="Reuse the selected target until the trust configuration changes."
    )

    _generation = 0
    _cached: tuple[int, str] | None = None
    last_skipped: tuple[str, ...] = ()
    _configured: tuple[tuple[str, ...], tuple[str, ...]] | None = None

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def cached_target(self) -> str | None:
        if not self.use_cache or self._cached is None:
            return None
        generation, target = self._cached
        if generation != self._generation:
            return None
        return target

    def set_config(
        self,
        approved: Sequence[str],
        candidates: Sequence[str] | None = None,
    ) -> bool:
        """Replace the trust configuration, invalidating cached selection.

        Returns True if the configuration changed (and the cache was cleared).
        """
        new_approved = origin_list(approved)
        new_candidates = origin_list(candidates if candidates else new_approved)
        configured = (tuple(new_approved), tuple(new_candidates))
        if configured == self._configured:
            # configuration is unchanged: keep the effective candidate order,
            # including any demotions applied after a failed connection
            return False
        first_config = self._configured is None
        self._configured = configured
        self.approved = new_approved
        self.candidates = new_candidates
        self.invalidate()
        # the initial configuration is not a *change*: nothing was cached yet
        return not first_config

    def invalidate(self) -> None:
        """Forget the cached connection target (e.g. after it went stale)."""
        self._generation += 1
        self._cached = None
        self.last_skipped = ()

    def demote(self, target: str) -> None:
        """Move *target* to the end of the candidate order.

        Called after a cached connection fails, so a retry rotates to the next
        candidate instead of immediately re-selecting the failed one.
        """
        target = normalize_target(target)
        if target in self.candidates:
            self.candidates = [t for t in self.candidates if t != target] + [target]
        self.invalidate()

    def is_approved(self, target: str) -> bool:
        try:
            normalized = normalize_target(target)
        except ValueError:
            return False
        return normalized in self.approved

    def ordered_candidates(self) -> list[str]:
        """Candidates in preference order, followed by unlisted approvals."""
        seen = set()
        ordered = []
        for target in list(self.candidates) + list(self.approved):
            if target not in seen:
                seen.add(target)
                ordered.append(target)
        return ordered

    def health_check_targets(self) -> list[str]:
        """Candidates that are configured but not approved for authentication."""
        return [t for t in self.ordered_candidates() if t not in self.approved]

    def health_check_only_origin(self, target: str) -> bool:
        """True if *target* may be probed but must never receive credentials."""
        try:
            normalized = normalize_target(target)
        except ValueError:
            return False
        return normalized in self.ordered_candidates() and normalized not in self.approved

    def select(self, exclude: Iterable[str] = ()) -> str:
        """Select the next approved target.

        Re-validates a cached selection against the *current* approval list,
        then walks candidates in order, skipping unapproved ones.  Raises
        :class:`TargetNotApproved` when no approved target remains.
        """
        excluded = set(origin_list(exclude))
        cached = self.cached_target
        if cached is not None and cached not in excluded:
            # Re-check the cache against the live allow-list: a cached
            # connection to a target that was since removed must not be used.
            if cached in self.approved:
                self.last_skipped = ()
                return cached
            self.invalidate()

        skipped = []
        for target in self.ordered_candidates():
            if target in excluded:
                continue
            if target not in self.approved:
                skipped.append(target)
                continue
            self.last_skipped = tuple(skipped)
            self._cached = (self._generation, target)
            return target

        self.last_skipped = tuple(skipped)
        raise TargetNotApproved(
            approved=self.approved,
            skipped=self.last_skipped,
        )
