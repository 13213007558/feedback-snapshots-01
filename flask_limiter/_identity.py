"""Missing identity handling for rate limit key functions."""

from __future__ import annotations

import enum
from collections.abc import Mapping

from flask import request
from limits.errors import ConfigurationError


class MissingIdentity(enum.Enum):
    """
    Distinguishable results a key function can return when it cannot provide a
    confirmed identity for the current request.

    Returning one of these values (instead of ``None`` or ``""``) tells the
    extension *why* no key is available so that the endpoint policy can decide
    how to proceed.
    """

    #: The request legitimately has no identity (for example an anonymous route).
    ANONYMOUS = "anonymous"

    #: The identity could not be confirmed (for example an identity service
    #: outage or an ambiguous/expired credential).
    UNCONFIRMED = "unconfirmed"

    #: Alias for :attr:`UNCONFIRMED`.
    UNAVAILABLE = "unconfirmed"

    #: Alias for :attr:`UNCONFIRMED`.
    UNKNOWN = "unconfirmed"


class MissingIdentityPolicy(enum.Enum):
    """Action to take for a limit when the key function reports a missing identity."""

    #: Do not evaluate this limit. The request continues normally.
    SKIP = "skip"

    #: Evaluate the limit against a reserved bucket derived from the missing
    #: identity reason and the client address. This bucket can never collide
    #: with a confirmed identity and is never shared with another account.
    TRACK = "track"

    #: Reject the request. Anonymous requests result in ``401`` and
    #: unconfirmed identities result in ``503``.
    REJECT = "reject"

    #: Alias for :attr:`SKIP`.
    IGNORE = "skip"

    #: Alias for :attr:`TRACK`.
    BUCKET = "track"

    #: Alias for :attr:`REJECT`.
    DENY = "reject"


#: Prefix used for the reserved buckets of unconfirmed/anonymous requests.
#: A confirmed identity whose key starts with this prefix is never treated as
#: a missing identity bucket because missing identities are only derived from
#: :class:`MissingIdentity` results, never from arbitrary strings.
MISSING_IDENTITY_KEY_PREFIX = "__flask_limiter_missing_identity__"


def is_missing_identity(value: object) -> bool:
    """Return whether ``value`` is one of the :class:`MissingIdentity` values."""

    return isinstance(value, MissingIdentity)


def is_policy_spec(value: object) -> bool:
    """
    Return whether ``value`` looks like a missing identity policy specification.

    This lets the decorator API accept a bare policy as its first argument
    (``@limiter.missing_identity_policy("reject")``) in addition to the
    ``(obj, policy)`` form.
    """

    return isinstance(value, (MissingIdentityPolicy, str, Mapping, frozenset))


def missing_identity_key(reason: MissingIdentity) -> str:
    """
    Build the reserved bucket key for a request whose identity is missing.

    The reason is part of the key so that genuinely anonymous requests and
    requests whose identity could not be confirmed never share a bucket. The
    client address is included to avoid one client exhausting a bucket shared
    by every unconfirmed request.
    """

    address = request.remote_addr or "unknown"

    return f"{MISSING_IDENTITY_KEY_PREFIX}:{reason.value}:{address}"


_ACTION_ALIASES: dict[str, MissingIdentityPolicy] = {
    "skip": MissingIdentityPolicy.SKIP,
    "ignore": MissingIdentityPolicy.SKIP,
    "allow": MissingIdentityPolicy.TRACK,
    "anonymous": MissingIdentityPolicy.TRACK,
    "bucket": MissingIdentityPolicy.TRACK,
    "track": MissingIdentityPolicy.TRACK,
    "reject": MissingIdentityPolicy.REJECT,
    "deny": MissingIdentityPolicy.REJECT,
    "unauthenticated": MissingIdentityPolicy.REJECT,
}

_REASON_ALIASES: dict[str, MissingIdentity] = {
    "anonymous": MissingIdentity.ANONYMOUS,
    "unconfirmed": MissingIdentity.UNCONFIRMED,
    "unavailable": MissingIdentity.UNCONFIRMED,
    "unknown": MissingIdentity.UNCONFIRMED,
}

# A normalized policy is either a single action that applies to every missing
# reason, or a frozen mapping of per-reason actions. Frozen values keep limit
# definitions hashable.
NormalizedPolicy = MissingIdentityPolicy | frozenset[tuple[MissingIdentity, MissingIdentityPolicy]]


def _action(value: MissingIdentityPolicy | str) -> MissingIdentityPolicy:
    if isinstance(value, MissingIdentityPolicy):
        return value

    if isinstance(value, str):
        action = _ACTION_ALIASES.get(value.lower())

        if action:
            return action

    raise ConfigurationError(
        f"Invalid missing identity policy {value!r}. "
        f"Expected one of {sorted(_ACTION_ALIASES)} or a MissingIdentityPolicy."
    )


def _reason(value: MissingIdentity | str) -> MissingIdentity:
    if isinstance(value, MissingIdentity):
        return value

    if isinstance(value, str):
        reason = _REASON_ALIASES.get(value.lower())

        if reason:
            return reason

    raise ConfigurationError(
        f"Invalid missing identity reason {value!r}. "
        f"Expected one of {sorted(_REASON_ALIASES)} or a MissingIdentity."
    )


def normalize_policy(
    policy: (
        MissingIdentityPolicy
        | str
        | Mapping[MissingIdentity | str, MissingIdentityPolicy | str]
        | NormalizedPolicy
        | None
    ),
) -> NormalizedPolicy | None:
    """
    Validate and normalize a policy specification so it remains hashable when
    stored on :class:`~flask_limiter.Limit` definitions.
    """

    if policy is None:
        return None

    if isinstance(policy, MissingIdentityPolicy):
        return policy

    if isinstance(policy, frozenset):
        return policy

    if isinstance(policy, str):
        return _action(policy)

    if isinstance(policy, Mapping):
        return frozenset({(_reason(reason), _action(action)) for reason, action in policy.items()})

    raise ConfigurationError(
        f"Invalid missing identity policy {policy!r}. Expected a policy name, "
        "a MissingIdentityPolicy or a mapping of missing reasons to policies."
    )


def resolve_policy(
    reason: MissingIdentity,
    *policies: NormalizedPolicy | None,
) -> MissingIdentityPolicy:
    """
    Resolve the action for ``reason`` from the first policy that specifies it.

    This allows endpoint configuration to override the extension default while
    falling back to it for reasons the endpoint did not configure.
    """

    for policy in policies:
        if policy is None:
            continue

        if isinstance(policy, MissingIdentityPolicy):
            return policy

        for configured_reason, action in policy:
            if configured_reason is reason:
                return action

    return MissingIdentityPolicy.SKIP
