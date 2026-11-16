"""Logical registry views on top of the physical ``dissect.regf`` parser.

``dissect.regf`` itself only understands what is stored in a hive: key nodes,
subkey indexes and values.  It has no notion of a Windows registry view, no
``Wow6432Node`` rewriting and no symbolic link dereferencing.  This module
keeps that separation explicit:

* :func:`resolve_physical` performs an unambiguous, hive-relative lookup.
* :func:`resolve_view` applies caller supplied :class:`RedirectionRule` objects.
  Rules are external data, not hardcoded Windows behavior, because the exact
  redirection/shared-key set depends on the Windows version, the operating
  system architecture and the bitness of the process performing the lookup.

A logical lookup never silently falls back to the other view.  A miss is
reported as :attr:`LookupStatus.NOT_FOUND_IN_VIEW`, with any key found in
another view attached as :class:`ViewEvidence`.  If a rule needs context that
the caller did not provide, the result is :attr:`LookupStatus.NEEDS_CONTEXT`
and ``required_context`` names the missing fields.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.regf.exceptions import RegistryKeyNotFoundError, RegistryValueNotFoundError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from dissect.regf.regf import KeyNode, RegistryHive


class LookupMode(str, Enum):
    """How a lookup addressed the hive.

    ``PHYSICAL`` is the default: a hive-relative path resolved as stored.
    ``EXPLICIT_PHYSICAL`` is the same traversal, but the caller deliberately
    named a physical subtree such as ``Wow6432Node``; no view rule may be
    applied to it.  ``LOGICAL`` resolves through a caller supplied view policy.
    """

    PHYSICAL = "physical"
    EXPLICIT_PHYSICAL = "explicit_physical"
    LOGICAL = "logical"


class ViewKind(str, Enum):
    """Registry views that a caller can request from a logical lookup."""

    NATIVE = "native"
    WOW32 = "wow32"


class LookupStatus(str, Enum):
    """Outcome of a lookup.

    ``NOT_FOUND`` is only used for physical lookups: the bytes at the requested
    path are absent.  Logical lookups use ``NOT_FOUND_IN_VIEW`` so a caller
    cannot mistake a view miss for proof that the machine has no such setting.
    """

    FOUND = "found"
    NOT_FOUND = "not_found"
    NOT_FOUND_IN_VIEW = "not_found_in_view"
    NEEDS_CONTEXT = "needs_context"
    OUT_OF_SCOPE = "out_of_scope"
    RULE_CONFLICT = "rule_conflict"
    INVALID_PATH = "invalid_path"


KNOWN_OS_ARCHES = frozenset({"x86", "amd64", "arm64"})
CONTEXT_FIELDS = ("os_arch", "process_bits", "os_version", "hive_role", "control_set")
HIVE_ROOT_PREFIXES = frozenset(
    {
        "hklm",
        "hkey_local_machine",
        "hkcu",
        "hkey_current_user",
        "hku",
        "hkey_users",
    }
)


@dataclass(frozen=True, slots=True)
class LookupContext:
    """Facts about the system whose registry view is being reconstructed.

    Every field is optional.  A rule declares which fields it needs; missing
    fields are reported in :attr:`LookupResult.required_context` instead of
    being replaced by a default.
    """

    os_arch: str | None = None
    """Operating system architecture: ``x86``, ``amd64`` or ``arm64``."""

    process_bits: int | None = None
    """Bitness of the process that would perform the lookup: ``32`` or ``64``."""

    os_version: tuple[int, int] | None = None
    """Windows NT version, for example ``(10, 0)``."""

    hive_role: str | None = None
    """Hive identity such as ``SYSTEM`` or ``SOFTWARE``.

    This is external evidence: :attr:`RegistryHive.filename` comes from the
    hive base block and can be edited or truncated, so it is not used as proof.
    """

    control_set: str | None = None
    """Resolved current control set, for example ``ControlSet001``."""

    source: str = ""
    """Free-form provenance for the context values."""

    def has(self, field: str) -> bool:
        """Return whether *field* was supplied with a non-``None`` value."""
        if field not in CONTEXT_FIELDS:
            raise ValueError(f"unknown context field {field!r}")
        return getattr(self, field) is not None

    def missing(self, required: frozenset[str] | tuple[str, ...]) -> tuple[str, ...]:
        """Return the required fields that are not available, sorted."""
        return tuple(sorted(field for field in required if not self.has(field)))

    def validation_error(self) -> str | None:
        """Return a description of an invalid supplied value, if any."""
        if self.os_arch is not None and self.os_arch.casefold() not in KNOWN_OS_ARCHES:
            return f"unrecognized os_arch {self.os_arch!r}; expected one of {sorted(KNOWN_OS_ARCHES)}"
        if self.process_bits is not None and self.process_bits not in (32, 64):
            return f"unrecognized process_bits {self.process_bits!r}; expected 32 or 64"
        if self.os_version is not None and (
            len(self.os_version) != 2 or not all(isinstance(part, int) for part in self.os_version)
        ):
            return f"unrecognized os_version {self.os_version!r}; expected a (major, minor) integer pair"
        return None


@dataclass(frozen=True, slots=True)
class RedirectionRule:
    """One externally supplied rule describing a view-specific path rewrite.

    ``logical_prefix`` is the path a caller asks for.  For a matching view the
    suffix is appended to ``target_prefix``.  ``shared_prefixes`` lists
    subpaths below ``logical_prefix`` that this rule must *not* rewrite; a more
    specific rule can still cover them.
    """

    name: str
    logical_prefix: str
    target_prefix: str
    views: frozenset[ViewKind] = frozenset({ViewKind.WOW32})
    shared_prefixes: tuple[str, ...] = ()
    requires: frozenset[str] = frozenset()
    os_arch: frozenset[str] = frozenset()
    process_bits: int | None = None
    min_os_version: tuple[int, int] | None = None
    max_os_version: tuple[int, int] | None = None
    source: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "logical_prefix", _clean_prefix(self.logical_prefix))
        object.__setattr__(self, "target_prefix", _clean_prefix(self.target_prefix))
        object.__setattr__(self, "shared_prefixes", tuple(_clean_prefix(item) for item in self.shared_prefixes))
        object.__setattr__(self, "views", frozenset(ViewKind(item) for item in self.views))
        object.__setattr__(self, "os_arch", frozenset(item.casefold() for item in self.os_arch))
        object.__setattr__(self, "requires", frozenset(self.requires))

        if not self.logical_prefix:
            raise ValueError(f"rule {self.name!r} has an empty logical_prefix")
        if not self.name:
            raise ValueError("a rule needs a name")

    @property
    def required_context(self) -> frozenset[str]:
        """Context fields needed to decide whether this rule applies."""
        required = set(self.requires)
        if self.os_arch:
            required.add("os_arch")
        if self.process_bits is not None:
            required.add("process_bits")
        if self.min_os_version is not None or self.max_os_version is not None:
            required.add("os_version")
        return frozenset(required)


class UnmatchedPolicy(str, Enum):
    """What to do when no rule covers a logical path."""

    OUT_OF_SCOPE = "out_of_scope"
    PASSTHROUGH = "passthrough"


@dataclass(frozen=True, slots=True)
class RedirectionPolicy:
    """An externally supplied set of rules for one hive role."""

    name: str
    rules: tuple[RedirectionRule, ...]
    hive_roles: frozenset[str] = frozenset({"SOFTWARE"})
    unmatched: UnmatchedPolicy = UnmatchedPolicy.OUT_OF_SCOPE
    source: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "hive_roles", frozenset(role.upper() for role in self.hive_roles))
        object.__setattr__(self, "unmatched", UnmatchedPolicy(self.unmatched))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RedirectionPolicy:
        """Build a policy from a JSON-compatible mapping."""
        rules = []
        for item in data.get("rules", []):
            raw = dict(item)
            for key in ("views", "requires", "os_arch", "shared_prefixes"):
                if key in raw and raw[key] is not None:
                    raw[key] = tuple(raw[key])
            for key in ("min_os_version", "max_os_version"):
                if raw.get(key) is not None:
                    raw[key] = tuple(raw[key])
            rules.append(RedirectionRule(**raw))
        return cls(
            name=data["name"],
            rules=tuple(rules),
            hive_roles=frozenset(data.get("hive_roles", ["SOFTWARE"])),
            unmatched=UnmatchedPolicy(data.get("unmatched", UnmatchedPolicy.OUT_OF_SCOPE)),
            source=data.get("source", ""),
        )


def load_policy(path: str | Path) -> RedirectionPolicy:
    """Load a redirection policy from a JSON file."""
    with Path(path).open("r", encoding="utf-8") as fh:
        return RedirectionPolicy.from_dict(json.load(fh))


@dataclass(frozen=True, slots=True)
class ViewEvidence:
    """A key that exists at a physical path relevant to another view."""

    view: str
    physical_path: str
    key: KeyNode


@dataclass(frozen=True, slots=True)
class LookupResult:
    """Result of a physical or logical lookup."""

    requested_path: str
    mode: LookupMode
    view: ViewKind
    status: LookupStatus
    physical_path: str | None = None
    key: KeyNode | None = None
    rules_applied: tuple[str, ...] = ()
    required_context: tuple[str, ...] = ()
    alternatives: tuple[ViewEvidence, ...] = ()
    notes: tuple[str, ...] = ()
    policy: str | None = None
    policy_source: str | None = None

    @property
    def found(self) -> bool:
        """Return whether the requested view contains the key."""
        return self.status is LookupStatus.FOUND


@dataclass(frozen=True, slots=True)
class ControlSetResolution:
    """Result of resolving ``CurrentControlSet`` from a SYSTEM hive."""

    status: LookupStatus
    control_set: str | None = None
    select_key: KeyNode | None = None
    notes: tuple[str, ...] = ()
    required_context: tuple[str, ...] = ()


def resolve_physical(hive: RegistryHive, path: str) -> LookupResult:
    """Look up *path* exactly as stored in *hive*, without applying any rules.

    This is the default query.  A path that deliberately names a physical
    subtree such as ``Wow6432Node`` is resolved literally and reported as
    :attr:`LookupMode.EXPLICIT_PHYSICAL`; it is never redirected a second time.
    """
    normalized, error = _normalize_path(path)
    if error is not None:
        return LookupResult(
            requested_path=path,
            mode=LookupMode.PHYSICAL,
            view=ViewKind.NATIVE,
            status=LookupStatus.INVALID_PATH,
            notes=(error,),
        )

    mode = LookupMode.EXPLICIT_PHYSICAL if _contains_wow6432node(normalized) else LookupMode.PHYSICAL
    notes: tuple[str, ...] = ()
    if mode is LookupMode.EXPLICIT_PHYSICAL:
        notes = ("The path names a physical Wow6432Node subtree; it is resolved literally.",)

    key = _open_key(hive, normalized)
    if key is None:
        return LookupResult(
            requested_path=path,
            mode=mode,
            view=ViewKind.NATIVE,
            status=LookupStatus.NOT_FOUND,
            physical_path=normalized,
            notes=notes + ("The physical key is absent from this hive; this says nothing about other hives.",),
        )

    return LookupResult(
        requested_path=path,
        mode=mode,
        view=ViewKind.NATIVE,
        status=LookupStatus.FOUND,
        physical_path=key.path,
        key=key,
        notes=notes,
    )


def resolve_view(
    hive: RegistryHive,
    path: str,
    *,
    view: ViewKind | str,
    policy: RedirectionPolicy,
    context: LookupContext,
) -> LookupResult:
    """Look up *path* in a logical *view* using caller supplied *policy*.

    ``ViewKind.NATIVE`` never rewrites a path; it exists so callers can use one
    result type for both views.  ``ViewKind.WOW32`` applies only matching rules
    from *policy*.  Missing context yields ``NEEDS_CONTEXT``; a path that no
    rule covers yields ``OUT_OF_SCOPE`` and is never guessed to be shared.
    """
    try:
        resolved_view = ViewKind(view)
    except ValueError as exc:
        raise ValueError(f"unknown registry view {view!r}") from exc

    normalized, error = _normalize_path(path)
    if error is not None:
        return LookupResult(
            requested_path=path,
            mode=LookupMode.LOGICAL,
            view=resolved_view,
            status=LookupStatus.INVALID_PATH,
            notes=(error,),
            policy=policy.name,
            policy_source=policy.source,
        )

    base = {
        "requested_path": path,
        "mode": LookupMode.LOGICAL,
        "view": resolved_view,
        "policy": policy.name,
        "policy_source": policy.source,
    }

    if resolved_view is ViewKind.NATIVE:
        key = _open_key(hive, normalized)
        status = LookupStatus.FOUND if key is not None else LookupStatus.NOT_FOUND_IN_VIEW
        alternatives = _alternatives_for_native(hive, normalized, policy, context)
        notes = []
        if key is None:
            notes.append("Not found in the native view of this hive; this is not proof of absence on the machine.")
        if alternatives:
            notes.append("The requested key exists in another view; see alternatives.")
        return LookupResult(
            **base,
            status=status,
            physical_path=key.path if key is not None else normalized,
            key=key,
            alternatives=alternatives,
            notes=tuple(notes),
        )

    if context.hive_role is None:
        return LookupResult(
            **base,
            status=LookupStatus.NEEDS_CONTEXT,
            required_context=("hive_role",),
            notes=("The policy is scoped to a hive role, but the hive role was not supplied.",),
        )

    if context.hive_role.upper() not in policy.hive_roles:
        return LookupResult(
            **base,
            status=LookupStatus.OUT_OF_SCOPE,
            notes=(
                f"Policy {policy.name!r} covers hive roles {sorted(policy.hive_roles)}, "
                f"not {context.hive_role!r}. Supply a policy for this hive.",
            ),
        )

    if _contains_wow6432node(normalized):
        return LookupResult(
            **base,
            status=LookupStatus.RULE_CONFLICT,
            physical_path=normalized,
            notes=(
                "The requested path already names a Wow6432Node subtree. "
                "Logical view rewriting is not applied to explicit physical paths; "
                "use open() or resolve_physical() instead.",
            ),
        )

    try:
        match = _match_rule(normalized, resolved_view, policy)
    except _RuleConflictError as exc:
        return LookupResult(
            **base,
            status=LookupStatus.RULE_CONFLICT,
            physical_path=normalized,
            rules_applied=tuple(exc.names),
            notes=(
                "Multiple rules with the same specificity select different physical paths "
                f"for this query: {exc.names}. Resolve the policy before querying.",
            ),
        )

    if match is not None and match.shared:
        key = _open_key(hive, normalized)
        status = LookupStatus.FOUND if key is not None else LookupStatus.NOT_FOUND_IN_VIEW
        return LookupResult(
            **base,
            status=status,
            physical_path=key.path if key is not None else normalized,
            key=key,
            notes=(
                f"Rule {match.rule.name!r} marks this subtree as shared between views, "
                "so the physical key is used as-is.",
            ),
        )

    if match is None:
        if policy.unmatched is UnmatchedPolicy.PASSTHROUGH:
            key = _open_key(hive, normalized)
            status = LookupStatus.FOUND if key is not None else LookupStatus.NOT_FOUND_IN_VIEW
            return LookupResult(
                **base,
                status=status,
                physical_path=key.path if key is not None else normalized,
                key=key,
                notes=("No rule matched; the policy explicitly declares unmatched paths as passthrough.",),
            )
        return LookupResult(
            **base,
            status=LookupStatus.OUT_OF_SCOPE,
            physical_path=normalized,
            notes=(
                "No rule in the policy covers this path. "
                "Supply a rule for this subtree or query the physical path explicitly.",
            ),
        )

    rule, remainder = match.rule, match.remainder
    evaluation = _evaluate_rule(rule, context)
    if evaluation.applies is None:
        notes = list(evaluation.notes)
        if not notes:
            notes.append(f"Rule {rule.name!r} needs additional context to decide whether it applies.")
        return LookupResult(
            **base,
            status=LookupStatus.NEEDS_CONTEXT,
            physical_path=normalized,
            rules_applied=(rule.name,),
            required_context=evaluation.missing,
            notes=tuple(notes),
        )

    if not evaluation.applies:
        key = _open_key(hive, normalized)
        status = LookupStatus.FOUND if key is not None else LookupStatus.NOT_FOUND_IN_VIEW
        return LookupResult(
            **base,
            status=status,
            physical_path=key.path if key is not None else normalized,
            key=key,
            notes=evaluation.notes
            + (f"Rule {rule.name!r} does not apply; this view resolves to the native path.",),
        )

    target = _join(rule.target_prefix, remainder)
    key = _open_key(hive, target)
    status = LookupStatus.NOT_FOUND_IN_VIEW if key is None else LookupStatus.FOUND

    alternatives = _alternatives_for_wow32(hive, normalized, target)
    notes = []
    if key is None:
        notes.append(
            "Not found at the physical path selected by the rule for this view; "
            "this is not proof that the machine has no such configuration."
        )
    if alternatives:
        notes.append("The requested key exists in another view; see alternatives.")
    notes.extend(evaluation.notes)

    return LookupResult(
        **base,
        status=status,
        physical_path=key.path if key is not None else target,
        key=key,
        rules_applied=(rule.name,),
        alternatives=alternatives,
        notes=tuple(notes),
    )


def resolve_current_control_set(hive: RegistryHive) -> ControlSetResolution:
    """Resolve ``CurrentControlSet`` using evidence from the same SYSTEM hive.

    The bool value names a control set; a symlink key is only reported when it
    is present, because ``dissect.regf`` does not dereference ``KEY.SYM_LINK``
    or ``REG_LINK`` values.
    """
    notes = []
    symlink = _open_key(hive, "CurrentControlSet")
    if symlink is not None:
        notes.append(
            "CurrentControlSet exists as a key, but dissect.regf does not dereference "
            "symbolic links; Select\\Current is used as the evidence instead."
        )

    select = _open_key(hive, "Select")
    if select is None:
        return ControlSetResolution(
            status=LookupStatus.NEEDS_CONTEXT,
            notes=tuple(notes)
            + ("This hive has no Select key; another hive or offline evidence is required.",),
            required_context=("Select\\Current",),
        )

    try:
        value = select.value("Current")
    except RegistryValueNotFoundError:
        return ControlSetResolution(
            status=LookupStatus.NEEDS_CONTEXT,
            select_key=select,
            notes=tuple(notes) + ("Select has no Current value.",),
            required_context=("Select\\Current",),
        )

    if value.type != 4:
        return ControlSetResolution(
            status=LookupStatus.NEEDS_CONTEXT,
            select_key=select,
            notes=tuple(notes) + (f"Select\\Current has type {value.type}, expected REG_DWORD.",),
            required_context=("Select\\Current",),
        )

    number = value.value
    if not isinstance(number, int) or number <= 0:
        return ControlSetResolution(
            status=LookupStatus.NEEDS_CONTEXT,
            select_key=select,
            notes=tuple(notes) + (f"Select\\Current has an unusable value {number!r}.",),
            required_context=("Select\\Current",),
        )

    name = f"ControlSet{number:03d}"
    target = _open_key(hive, name)
    if target is None:
        return ControlSetResolution(
            status=LookupStatus.NOT_FOUND,
            select_key=select,
            notes=tuple(notes) + (f"Select\\Current names {name!r}, but that key is absent from this hive.",),
        )

    notes.append(f"Select\\Current={number} identifies {name!r}; the key is present in this hive.")
    return ControlSetResolution(status=LookupStatus.FOUND, control_set=name, select_key=select, notes=tuple(notes))


def _normalize_path(path: str) -> tuple[str, str | None]:
    if not isinstance(path, str):
        return "", "path must be a string"

    stripped = path.strip("\\")
    if not stripped:
        return "", None

    parts = [part for part in stripped.split("\\") if part]
    if not parts:
        return "", None

    first = parts[0].casefold()
    if first in HIVE_ROOT_PREFIXES:
        return "", (
            "path is absolute; dissect.regf addresses a single hive, so supply a hive-relative path. "
            "Mapping HKLM/HKCU to a hive requires external evidence."
        )
    if first == "registry" and len(parts) > 1 and parts[1].casefold() == "machine":
        return "", "path is an NT registry path; supply a hive-relative path instead."

    return "\\".join(parts), None


def _clean_prefix(prefix: str) -> str:
    return "\\".join(part for part in prefix.strip("\\").split("\\") if part)


def _join(prefix: str, remainder: str) -> str:
    if not prefix:
        return remainder
    if not remainder:
        return prefix
    return f"{prefix}\\{remainder}"


def _contains_wow6432node(path: str) -> bool:
    return any(part.casefold() == "wow6432node" for part in path.split("\\") if part)


def _open_key(hive: RegistryHive, path: str) -> KeyNode | None:
    node = hive.root()
    if not path:
        return node

    for part in path.split("\\"):
        found = None
        try:
            found = node.subkey(part)
        except RegistryKeyNotFoundError:
            wanted = part.casefold()
            found = next((subkey for subkey in node.subkeys() if subkey.name.casefold() == wanted), None)

        if found is None:
            return None
        node = found

    return node


def _remainder_of(path: str, prefix: str) -> str | None:
    if len(path) == len(prefix) and path.casefold() == prefix.casefold():
        return ""
    if path[: len(prefix)].casefold() != prefix.casefold():
        return None
    if path[len(prefix) : len(prefix) + 1] != "\\":
        return None
    return path[len(prefix) + 1 :]


def _is_shared(remainder: str, shared_prefixes: tuple[str, ...]) -> bool:
    current = remainder.casefold()
    return any(current == item.casefold() or current.startswith(f"{item.casefold()}\\") for item in shared_prefixes)


def _match_rule(path: str, view: ViewKind, policy: RedirectionPolicy) -> _RuleMatch | None:
    candidates: list[_RuleMatch] = []

    for rule in policy.rules:
        if view not in rule.views:
            continue

        remainder = _remainder_of(path, rule.logical_prefix)
        if remainder is None:
            continue

        shared = bool(remainder) and _is_shared(remainder, rule.shared_prefixes)
        candidates.append(_RuleMatch(rule, remainder, shared))

    if not candidates:
        return None

    longest = max(len(item.rule.logical_prefix) for item in candidates)
    best = [item for item in candidates if len(item.rule.logical_prefix) == longest]
    targets = {item.rule.target_prefix.casefold() for item in best}
    if len(targets) > 1:
        names = sorted(item.rule.name for item in best)
        raise _RuleConflictError(names)

    return best[0]


@dataclass(frozen=True, slots=True)
class _RuleMatch:
    rule: RedirectionRule
    remainder: str
    shared: bool = False


class _RuleConflictError(Exception):
    def __init__(self, names: list[str]):
        super().__init__(names)
        self.names = names


@dataclass(frozen=True, slots=True)
class _RuleEvaluation:
    applies: bool | None
    missing: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


def _evaluate_rule(rule: RedirectionRule, context: LookupContext) -> _RuleEvaluation:
    missing = context.missing(rule.required_context)
    if missing:
        return _RuleEvaluation(applies=None, missing=missing)

    error = context.validation_error()
    if error is not None:
        return _RuleEvaluation(applies=None, notes=(error,))

    if rule.os_arch and context.os_arch.casefold() not in rule.os_arch:
        return _RuleEvaluation(
            applies=False,
            notes=(f"Rule {rule.name!r} targets os_arch={sorted(rule.os_arch)}, got {context.os_arch!r}.",),
        )

    if rule.process_bits is not None and context.process_bits != rule.process_bits:
        return _RuleEvaluation(
            applies=False,
            notes=(
                f"Rule {rule.name!r} targets a {rule.process_bits}-bit process, "
                f"got {context.process_bits!r}; the view is not redirected.",
            ),
        )

    if rule.min_os_version is not None and context.os_version < rule.min_os_version:
        return _RuleEvaluation(
            applies=False,
            notes=(
                f"Rule {rule.name!r} requires Windows {rule.min_os_version[0]}.{rule.min_os_version[1]} "
                f"or newer, got {context.os_version!r}.",
            ),
        )

    if rule.max_os_version is not None and context.os_version > rule.max_os_version:
        return _RuleEvaluation(
            applies=False,
            notes=(
                f"Rule {rule.name!r} applies up to Windows {rule.max_os_version[0]}.{rule.max_os_version[1]}, "
                f"got {context.os_version!r}.",
            ),
        )

    return _RuleEvaluation(applies=True)


def _alternatives_for_wow32(hive: RegistryHive, native_path: str, resolved_path: str) -> tuple[ViewEvidence, ...]:
    if native_path.casefold() == resolved_path.casefold():
        return ()
    key = _open_key(hive, native_path)
    if key is None:
        return ()
    return (ViewEvidence(view=ViewKind.NATIVE.value, physical_path=key.path, key=key),)


def _alternatives_for_native(
    hive: RegistryHive, native_path: str, policy: RedirectionPolicy, context: LookupContext
) -> tuple[ViewEvidence, ...]:
    try:
        match = _match_rule(native_path, ViewKind.WOW32, policy)
    except _RuleConflictError:
        return ()
    if match is None:
        return ()

    rule, remainder = match.rule, match.remainder
    evaluation = _evaluate_rule(rule, context)
    if not evaluation.applies:
        return ()

    target = _join(rule.target_prefix, remainder)
    key = _open_key(hive, target)
    if key is None:
        return ()
    return (ViewEvidence(view=ViewKind.WOW32.value, physical_path=key.path, key=key),)
