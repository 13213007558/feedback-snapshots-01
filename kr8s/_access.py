# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
"""Access policy for discovered Kubernetes resources.

Kubernetes discovery can advertise several versions of the same resource name.
This module keeps two decisions separate for every ``(group, version, resource)``
tuple:

* whether the version is **visible** (may be shown by the service catalog or by
  :meth:`kr8s.Api.api_resources`), and
* which request **verbs** are approved for that exact version.

Separating the decisions means a newly discovered version can be listed without
implicitly becoming requestable, and two versions that share a resource name can
have different approvals.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

__all__ = [
    "ALL_VERBS",
    "AccessDecision",
    "AccessPolicy",
    "AccessRule",
    "split_api_version",
]

ALL_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
    }
)
"""Verbs understood by Kubernetes discovery and RBAC."""

_VERB_ALIASES = {
    "read": frozenset({"get", "list", "watch"}),
    "write": frozenset({"create", "update", "patch", "delete", "deletecollection"}),
    "all": ALL_VERBS,
    "*": ALL_VERBS,
}


def split_api_version(api_version: str) -> tuple[str, str]:
    """Split an API version into ``(group, version)``.

    Core API versions such as ``v1`` have an empty group. Grouped versions such
    as ``apps/v1`` return ``("apps", "v1")``.

    Args:
        api_version: A Kubernetes API version string.

    Returns:
        A tuple of ``(group, version)``.
    """
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        return group, version
    return "", api_version


def _normalise_verbs(verbs) -> frozenset[str]:
    """Normalise a verb declaration into a concrete set of verbs."""
    if verbs is None:
        return ALL_VERBS
    if isinstance(verbs, str):
        verbs = [verbs]
    normalised: set[str] = set()
    for verb in verbs:
        key = str(verb).strip().lower()
        if not key:
            continue
        normalised.update(_VERB_ALIASES.get(key, frozenset({key})))
    return frozenset(normalised)


@dataclass(frozen=True)
class AccessRule:
    """An approval for one resource version.

    Attributes:
        visible: Whether the resource version may be shown in discovery output.
        verbs: The request verbs approved for this exact resource version.
    """

    visible: bool = True
    verbs: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def permissive(cls) -> AccessRule:
        """Return a rule that allows visibility and every request verb."""
        return cls(visible=True, verbs=ALL_VERBS)

    @classmethod
    def display_only(cls) -> AccessRule:
        """Return a rule that allows visibility but no requests."""
        return cls(visible=True, verbs=frozenset())


@dataclass(frozen=True)
class AccessDecision:
    """The result of checking a single request or display decision.

    Attributes:
        verb: The request verb being checked (``""`` for visibility checks).
        resource: The plural resource name.
        group: The API group, empty for the core group.
        version: The API version.
        visible: Whether the resource version may be displayed.
        allowed: Whether the request verb is approved.
        approved_verbs: Every verb approved for this resource version.
        reason: A human readable explanation, empty when allowed.
    """

    verb: str
    resource: str
    group: str
    version: str
    visible: bool
    allowed: bool
    approved_verbs: frozenset[str] = field(default_factory=frozenset)
    reason: str = ""

    @property
    def api_version(self) -> str:
        """Return the full ``group/version`` (or ``version``) string."""
        return f"{self.group}/{self.version}" if self.group else self.version

    @property
    def name(self) -> str:
        """Return the fully qualified resource name."""
        return f"{self.resource}.{self.group}" if self.group else self.resource

    def explain(self) -> str:
        """Return a human readable explanation of the decision."""
        if self.reason:
            return self.reason
        if self.allowed:
            if self.verb:
                if self.visible:
                    return (
                        f"Resource '{self.name}/{self.version}' is visible in discovery "
                        f"and approved for '{self.verb}' requests."
                    )
                return (
                    f"Resource '{self.name}/{self.version}' is not visible in discovery "
                    f"but is approved for '{self.verb}' requests."
                )
            return (
                f"Resource '{self.name}/{self.version}' is visible in discovery. "
                f"Approved verbs: {', '.join(sorted(self.approved_verbs)) or 'none'}."
            )
        if self.verb:
            return f"Resource '{self.name}/{self.version}' is not approved for '{self.verb}' requests."
        return f"Resource '{self.name}/{self.version}' is not visible in discovery."

    def __bool__(self) -> bool:
        return self.allowed


def _denied_visibility_reason(
    resource: str, group: str, version: str, approved_verbs: frozenset[str]
) -> str:
    name = f"{resource}.{group}" if group else resource
    return (
        f"Resource '{name}/{version}' is not visible in discovery and has not "
        f"been approved for requests. Approved verbs: "
        f"{', '.join(sorted(approved_verbs)) or 'none'}."
    )


def _denied_request_reason(
    verb: str,
    resource: str,
    group: str,
    version: str,
    approved_verbs: frozenset[str],
) -> str:
    name = f"{resource}.{group}" if group else resource
    approved = ", ".join(sorted(approved_verbs)) or "none"
    return (
        f"Resource '{name}/{version}' is visible in discovery but is not approved "
        f"for '{verb}' requests. Approved verbs: {approved}. "
        "This version may be displayed, but these requests are not approved; "
        "use an approved version or grant this version explicitly."
    )


class AccessPolicy:
    """Per-resource-version approvals used by kr8s discovery and requests.

    An empty policy is permissive and leaves kr8s behaviour unchanged. As soon
    as a rule is added for a resource name, that resource name becomes governed:
    every version of it that has no matching rule is denied. This is what stops
    a newly discovered version of the same resource from inheriting the approvals
    of an older version.

    Rules are matched by ``(group, version, resource)``. Wildcards are supported
    for any component. The exact rule wins, followed by progressively broader
    wildcard rules.
    """

    def __init__(self, default_allow: bool = True) -> None:
        """Create an empty policy.

        Args:
            default_allow: Whether resources with no applicable rule are allowed.
                The default is ``True`` so adding a policy is backwards
                compatible. Set this to ``False`` (or use
                :meth:`AccessPolicy.deny_by_default`) for a strict allowlist.
        """
        self._default = (
            AccessRule.permissive()
            if default_allow
            else AccessRule(visible=False, verbs=frozenset())
        )
        self._governed = AccessRule(visible=False, verbs=frozenset())
        self._rules: dict[tuple[str, str, str], AccessRule] = {}
        self._lock = threading.RLock()

    @classmethod
    def permissive(cls) -> AccessPolicy:
        """Return a policy that allows every discovered resource and verb."""
        return cls(default_allow=True)

    @classmethod
    def deny_by_default(cls) -> AccessPolicy:
        """Return a policy that only allows explicitly approved resources."""
        return cls(default_allow=False)

    @property
    def enabled(self) -> bool:
        """Whether the policy can deny anything."""
        with self._lock:
            return bool(self._rules) or self._default != AccessRule.permissive()

    def set_rule(
        self,
        resource: str,
        *,
        group: str = "",
        version: str = "",
        visible: bool = True,
        verbs=None,
    ) -> AccessRule:
        """Set the approval for one resource version.

        Args:
            resource: The plural resource name, or ``"*"`` for every resource.
            group: The API group, empty for the core group, or ``"*"``.
            version: The API version, or ``"*"``. A full ``group/version`` value
                is also accepted when ``group`` is omitted.
            visible: Whether the version may be shown in discovery output.
            verbs: Approved request verbs. ``None`` approves every verb, a string
                or iterable names individual verbs. ``"read"``, ``"write"`` and
                ``"all"`` are accepted as aliases.

        Returns:
            The stored rule.
        """
        group, version = _normalise_target(group, version)
        rule = AccessRule(visible=bool(visible), verbs=_normalise_verbs(verbs))
        with self._lock:
            self._rules[(group, version, resource.lower())] = rule
        return rule

    def allow(
        self,
        resource: str,
        *,
        group: str = "",
        version: str = "",
        verbs=None,
        visible: bool = True,
    ) -> AccessRule:
        """Approve a resource version for display and the given verbs.

        Args:
            resource: The plural resource name, or ``"*"``.
            group: The API group, empty for the core group, or ``"*"``.
            version: The API version, or ``"*"``.
            verbs: Approved verbs. Defaults to every verb.
            visible: Whether the version may also be displayed.

        Returns:
            The stored rule.
        """
        return self.set_rule(
            resource,
            group=group,
            version=version,
            visible=visible,
            verbs=verbs,
        )

    def allow_display(
        self, resource: str, *, group: str = "", version: str = ""
    ) -> AccessRule:
        """Allow a version to be displayed, without approving any requests.

        Args:
            resource: The plural resource name, or ``"*"``.
            group: The API group, empty for the core group, or ``"*"``.
            version: The API version, or ``"*"``.

        Returns:
            The stored rule.
        """
        return self.set_rule(
            resource, group=group, version=version, visible=True, verbs=()
        )

    def deny(self, resource: str, *, group: str = "", version: str = "") -> AccessRule:
        """Hide a resource version and approve no requests for it.

        Args:
            resource: The plural resource name, or ``"*"``.
            group: The API group, empty for the core group, or ``"*"``.
            version: The API version, or ``"*"``.

        Returns:
            The stored rule.
        """
        return self.set_rule(
            resource, group=group, version=version, visible=False, verbs=()
        )

    def remove_rule(self, resource: str, *, group: str = "", version: str = "") -> None:
        """Remove an explicit rule, falling back to broader rules or the default.

        Args:
            resource: The plural resource name.
            group: The API group.
            version: The API version.
        """
        group, version = _normalise_target(group, version)
        with self._lock:
            self._rules.pop((group, version, resource.lower()), None)

    def rule_for(
        self, resource: str, *, group: str = "", version: str = ""
    ) -> AccessRule:
        """Return the effective rule for a resource version.

        Args:
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            The matching rule. Unmatched resources use the policy default. Once
            a rule for the resource name exists, a version that has no matching
            rule is denied so a newly discovered version cannot inherit access.
        """
        resource = resource.lower()
        group, version = _normalise_target(group, version)
        with self._lock:
            for key in (
                (group, version, resource),
                (group, version, "*"),
                (group, "*", resource),
                (group, "*", "*"),
                ("*", version, resource),
                ("*", version, "*"),
                ("*", "*", resource),
                ("*", "*", "*"),
            ):
                if key in self._rules:
                    return self._rules[key]
            if any(key[2] in (resource, "*") for key in self._rules):
                return self._governed
            return self._default

    def check(
        self, verb: str, resource: str, *, group: str = "", version: str = ""
    ) -> AccessDecision:
        """Check one request verb against the exact resource version.

        Args:
            verb: The request verb (``get``, ``list``, ``create``, ...).
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            An :class:`AccessDecision`; ``decision.allowed`` tells whether the
            request may be sent.
        """
        verb = str(verb).strip().lower()
        group, version = _normalise_target(group, version)
        rule = self.rule_for(resource, group=group, version=version)
        allowed = verb in rule.verbs
        if allowed:
            reason = ""
        elif rule.visible:
            reason = _denied_request_reason(verb, resource, group, version, rule.verbs)
        else:
            reason = _denied_visibility_reason(resource, group, version, rule.verbs)
        return AccessDecision(
            verb=verb,
            resource=resource.lower(),
            group=group,
            version=version,
            visible=rule.visible,
            allowed=allowed,
            approved_verbs=rule.verbs,
            reason=reason,
        )

    def check_visibility(
        self, resource: str, *, group: str = "", version: str = ""
    ) -> AccessDecision:
        """Check whether a resource version may be displayed.

        Args:
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            An :class:`AccessDecision` whose ``allowed`` and ``visible`` fields
            both report the display decision.
        """
        group, version = _normalise_target(group, version)
        rule = self.rule_for(resource, group=group, version=version)
        if rule.visible:
            reason = ""
        else:
            reason = _denied_visibility_reason(resource, group, version, rule.verbs)
        return AccessDecision(
            verb="",
            resource=resource.lower(),
            group=group,
            version=version,
            visible=rule.visible,
            allowed=rule.visible,
            approved_verbs=rule.verbs,
            reason=reason,
        )

    def is_visible(self, resource: str, *, group: str = "", version: str = "") -> bool:
        """Return whether a resource version may be displayed.

        Args:
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            ``True`` when the version may be displayed.
        """
        return self.check_visibility(resource, group=group, version=version).allowed

    def allows(
        self, verb: str, resource: str, *, group: str = "", version: str = ""
    ) -> bool:
        """Return whether a request verb is approved.

        Args:
            verb: The request verb.
            resource: The plural resource name.
            group: The API group, empty for the core group.
            version: The API version.

        Returns:
            ``True`` when the request may be sent.
        """
        return self.check(verb, resource, group=group, version=version).allowed

    def filter_resources(self, resources: list[dict]) -> list[dict]:
        """Filter discovery entries to those approved for display.

        The policy is applied every time this method is called, so cached
        discovery results always reflect the current approvals. Entries are not
        mutated.

        Args:
            resources: Raw discovery entries from the Kubernetes API.

        Returns:
            A new list containing only visible discovery entries.
        """
        visible = []
        for resource in resources:
            group, version = split_api_version(resource.get("version", ""))
            if self.is_visible(resource.get("name", ""), group=group, version=version):
                visible.append(resource)
        return visible


def _normalise_target(group: str, version: str) -> tuple[str, str]:
    """Normalise a group/version pair, accepting ``group/version`` in version."""
    group = (group or "").lower()
    version = (version or "").lower()
    if version and "/" in version:
        version_group, version = version.split("/", 1)
        group = group or version_group.lower()
    return group, version
