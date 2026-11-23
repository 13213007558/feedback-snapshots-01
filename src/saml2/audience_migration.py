#!/usr/bin/env python
#
"""
Time bounded migration of the SAML audience restriction.

Some Identity Providers only support IdP initiated single sign on: the user
starts at the IdP and is redirected to the portal without the portal first
choosing a brand entry.  When such a portal moves from a single audience
identifier to two brand entries those IdPs have to be reconfigured one by one.

The classes in this module make that transition explicit:

* :class:`AudienceMigrationPolicy` describes, per brand entry and per issuer,
  which audiences are temporarily accepted while the migration window is open.
* Once the window ends the policy automatically tightens back to only the
  audience of the entry that received the assertion.
* The outcome of an evaluation is captured in an immutable
  :class:`AudienceMigrationDecision` which is stored on the response and reused
  when the session is established, so the decision stays stable even if the
  wall clock moves between validation and session creation.

The policy never loosens SP initiated logins.  Those are still required to be
associated with the outstanding authentication request and only the audience of
the receiving entry is relevant for them.
"""

import calendar
import logging
import time

from saml2 import time_util


logger = logging.getLogger(__name__)


def _normalize(value):
    """Audience and issuer identifiers are compared as stripped strings."""
    if value is None:
        return ""
    return value.strip()


class Clock:
    """Source of the current time used by the migration policy.

    The default implementation reads the real wall clock.  Tests (or callers
    that need deterministic behaviour) can replace ``now`` with a callable
    returning a UTC :class:`time.struct_time`.
    """

    def __init__(self, now=None):
        if now is None:
            now = time.gmtime
        self._now = now

    def now(self):
        """Return the current time as a UTC ``time.struct_time``."""
        return self._now()


def _to_struct_time(value):
    """Accept either a SAML time string, an epoch int or a struct_time."""
    if value is None:
        return None
    if isinstance(value, time.struct_time):
        return value
    if isinstance(value, (int, float)):
        return time.gmtime(value)
    return time_util.str_to_time(value)


class MigrationWindow:
    """The half-open interval ``[start, end)`` during which migration is open.

    Both bounds are optional.  A missing start means the window is open from
    the beginning of time and a missing end means it never closes automatically.
    """

    def __init__(self, start=None, end=None, clock=None):
        self.start = _to_struct_time(start)
        self.end = _to_struct_time(end)
        self.clock = clock or Clock()

    def is_open(self, at=None):
        """Return True if the window covers ``at`` (defaults to now)."""
        current = at or self.clock.now()

        if self.start is not None and calendar.timegm(current) < calendar.timegm(self.start):
            return False
        if self.end is not None and calendar.timegm(current) >= calendar.timegm(self.end):
            return False
        return True


class AudienceEntry:
    """One brand entry of the portal.

    :param entity_id: The audience / entityID of this entry.
    :param legacy_audiences: Audiences accepted in addition to ``entity_id``
        while the migration window is open.
    :param issuers: Issuer entityIDs for which the legacy audiences are
        accepted.  An empty set means any issuer may use the legacy audiences
        during the window.
    """

    def __init__(self, entity_id, legacy_audiences=None, issuers=None):
        self.entity_id = _normalize(entity_id)
        self.legacy_audiences = {_normalize(item) for item in (legacy_audiences or []) if _normalize(item)}
        self.issuers = {_normalize(item) for item in (issuers or []) if _normalize(item)}

    def issuer_allowed(self, issuer):
        if not self.issuers:
            return True
        return _normalize(issuer) in self.issuers

    def allowed_audiences(self, issuer, window_open):
        """Audiences accepted for ``issuer`` given the window state."""
        allowed = {self.entity_id}
        if window_open and self.issuer_allowed(issuer):
            allowed.update(self.legacy_audiences)
        return allowed


class AudienceMigrationDecision:
    """Immutable record of a single audience evaluation.

    The object is intentionally hashable and free of live references so that it
    can be attached to the response and later handed to session establishment
    without re-evaluating the (possibly now closed) migration window.
    """

    def __init__(
        self,
        accepted,
        entry_entity_id,
        issuer,
        matched_audiences=None,
        window_open=False,
        used_legacy_audience=False,
        reason="",
    ):
        self.accepted = bool(accepted)
        self.entry_entity_id = _normalize(entry_entity_id)
        self.issuer = _normalize(issuer)
        self.matched_audiences = frozenset(_normalize(item) for item in (matched_audiences or []))
        self.window_open = bool(window_open)
        self.used_legacy_audience = bool(used_legacy_audience)
        self.reason = reason

    def as_dict(self):
        """Stable representation embedded in the session information."""
        return {
            "accepted": self.accepted,
            "entry_entity_id": self.entry_entity_id,
            "issuer": self.issuer,
            "matched_audiences": sorted(self.matched_audiences),
            "window_open": self.window_open,
            "used_legacy_audience": self.used_legacy_audience,
            "reason": self.reason,
        }

    def __eq__(self, other):
        if not isinstance(other, AudienceMigrationDecision):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    def __repr__(self):
        return f"AudienceMigrationDecision({self.as_dict()!r})"


def _assertion_audiences(conditions):
    """Yield ``(restriction_index, [audience, ...])`` for the conditions."""
    for index, restriction in enumerate(conditions.audience_restriction or []):
        audiences = [_normalize(aud.text) for aud in restriction.audience if aud.text and _normalize(aud.text)]
        yield index, audiences


class AudienceMigrationPolicy:
    """Evaluates audience restrictions against the brand entry migration plan.

    Configuration dictionary (the ``audience_migration`` SP option)::

        {
            "window": {"start": "...", "end": "..."},
            "entries": {
                "<entry entityID>": {
                    "legacy_audiences": ["<old audience>", ...],
                    "issuers": ["<idp entityID>", ...],
                },
                ...
            },
        }

    The policy is only consulted when an ``entries`` mapping is present.  When
    the receiving entry is unknown to the policy it behaves exactly like the
    classic single audience check.
    """

    def __init__(self, config=None, clock=None):
        config = config or {}
        window_conf = config.get("window", {}) or {}
        self.clock = clock or Clock()
        self.window = MigrationWindow(
            start=window_conf.get("start"),
            end=window_conf.get("end"),
            clock=self.clock,
        )
        self.entries = self._build_entries(config.get("entries", {}) or {})

    @staticmethod
    def _build_entries(entries_conf):
        entries = {}
        for entity_id, spec in entries_conf.items():
            spec = spec or {}
            entry = AudienceEntry(
                entity_id=entity_id,
                legacy_audiences=spec.get("legacy_audiences", []),
                issuers=spec.get("issuers", []),
            )
            entries[entry.entity_id] = entry
        return entries

    @property
    def enabled(self):
        return bool(self.entries)

    def window_is_open(self, at=None):
        return self.window.is_open(at=at)

    def evaluate(self, conditions, entry_entity_id, issuer):
        """Evaluate the audience restrictions for one delivered assertion.

        :param conditions: The ``saml.Conditions`` of the assertion.
        :param entry_entity_id: The brand entry that received the assertion.
        :param issuer: The entityID of the asserting IdP.
        :returns: An :class:`AudienceMigrationDecision`.
        """
        entry_entity_id = _normalize(entry_entity_id)
        issuer = _normalize(issuer)

        entry = self.entries.get(entry_entity_id)
        if entry is None:
            return self._classic_decision(conditions, entry_entity_id, issuer)

        if not conditions or not conditions.audience_restriction:
            return AudienceMigrationDecision(
                accepted=True,
                entry_entity_id=entry_entity_id,
                issuer=issuer,
                window_open=self.window_is_open(),
                reason="no audience restriction present",
            )

        window_open = self.window_is_open()
        allowed = entry.allowed_audiences(issuer, window_open)

        matched = set()
        for _index, audiences in _assertion_audiences(conditions):
            if not audiences:
                # An empty AudienceRestriction can never be satisfied.
                return AudienceMigrationDecision(
                    accepted=False,
                    entry_entity_id=entry_entity_id,
                    issuer=issuer,
                    matched_audiences=matched,
                    window_open=window_open,
                    reason="empty AudienceRestriction",
                )
            restriction_matches = [aud for aud in audiences if aud in allowed]
            if not restriction_matches:
                logger.warning(
                    "Audience restriction rejected for entry '%s' issuer '%s' "
                    "(window_open=%s); audiences=%s allowed=%s",
                    entry_entity_id,
                    issuer,
                    window_open,
                    audiences,
                    sorted(allowed),
                )
                return AudienceMigrationDecision(
                    accepted=False,
                    entry_entity_id=entry_entity_id,
                    issuer=issuer,
                    matched_audiences=matched,
                    window_open=window_open,
                    reason="no allowed audience in AudienceRestriction",
                )
            matched.update(restriction_matches)

        used_legacy = any(aud != entry_entity_id for aud in matched)
        return AudienceMigrationDecision(
            accepted=True,
            entry_entity_id=entry_entity_id,
            issuer=issuer,
            matched_audiences=matched,
            window_open=window_open,
            used_legacy_audience=used_legacy,
            reason="legacy audience" if used_legacy else "entry audience",
        )

    def _classic_decision(self, conditions, entry_entity_id, issuer):
        """Fall back to the historical single-audience semantics."""
        window_open = self.window_is_open()
        if not conditions or not conditions.audience_restriction:
            return AudienceMigrationDecision(
                accepted=True,
                entry_entity_id=entry_entity_id,
                issuer=issuer,
                window_open=window_open,
                reason="no audience restriction present",
            )

        for _index, audiences in _assertion_audiences(conditions):
            if entry_entity_id in audiences:
                return AudienceMigrationDecision(
                    accepted=True,
                    entry_entity_id=entry_entity_id,
                    issuer=issuer,
                    matched_audiences=[entry_entity_id],
                    window_open=window_open,
                    reason="entry audience",
                )
        return AudienceMigrationDecision(
            accepted=False,
            entry_entity_id=entry_entity_id,
            issuer=issuer,
            window_open=window_open,
            reason="no allowed audience in AudienceRestriction",
        )
