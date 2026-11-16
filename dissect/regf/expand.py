"""Offline expansion of ``REG_EXPAND_SZ`` registry values.

Registry values of type ``REG_EXPAND_SZ`` contain references to environment
variables (``%NAME%``). Expanding them with the environment of the analysis
machine yields paths that belong to the analyst's machine, not to the
investigated system. This module provides :class:`ExpansionContext`, an
explicit offline expansion context whose environment comes from a specified
SYSTEM hive and/or user hive (NTUSER.DAT), or from caller-provided captured
values. The host environment is never consulted.

Explainable rules
-----------------
Layering:
    Machine variables (from the SYSTEM hive) form the base layer. User
    variables (from a user hive or captured values) override machine variables
    with the same name, except for *merge variables* (default: ``Path``),
    where the effective value is ``machine + ";" + user`` -- mirroring how
    Windows merges the user ``Path`` into the system ``Path``.
Casing:
    Variable names are case-insensitive (Windows semantics). Lookups are
    performed on the uppercased name; records keep the casing of the source
    that defined them.
Expansion:
    Only text known to be ``REG_EXPAND_SZ`` is expanded. ``REG_SZ`` text is
    returned verbatim, both at the top level and when a ``REG_SZ`` environment
    value is substituted into another expansion. Unknown variables are left
    verbatim and reported as *unresolved*. Nested references are expanded
    recursively with a bounded depth and a bounded number of substitutions;
    circular references are detected and left verbatim. A report is only
    ``complete`` when nothing was left pending, so a partial result can never
    be mistaken for a fully resolved path.
Provenance:
    Every substitution is recorded as an :class:`ExpansionStep` with the
    variable as written, the source layer and the origin of the value, so
    each result can be traced back step by step. The raw registry data is
    never modified and remains available through ``KeyValue.value`` /
    ``KeyValue.data``.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.regf.c_regf import REG_EXPAND_SZ, REG_SZ
from dissect.regf.exceptions import (
    Error,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)

if TYPE_CHECKING:
    from dissect.regf.regf import KeyValue, RegistryHive

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))

TOKEN_PATTERN = re.compile(r"%([^%]+)%")

MACHINE = "machine"
USER = "user"
MERGED = "merged"

RESOLVED = "resolved"
UNRESOLVED = "unresolved"
CYCLE = "cycle"
LIMIT = "limit"

DEFAULT_MERGE_VARIABLES = ("PATH",)
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_STEPS = 1024

ENVIRONMENT_KEY = "Control\\Session Manager\\Environment"
USER_ENVIRONMENT_KEY = "Environment"
USER_VOLATILE_ENVIRONMENT_KEY = "Volatile Environment"


@dataclass
class VariableRecord:
    """A single environment variable definition with its provenance."""

    name: str
    """The variable name with the casing of the defining source."""

    value: str
    """The raw (unexpanded) value as found in the source."""

    source: str
    """The layer that defined the variable: ``machine``, ``user`` or ``merged``."""

    origin: str
    """Human-readable origin, e.g. a hive key path or ``caller-provided captured values``."""

    expandable: bool = True
    """Whether the value may itself be scanned for nested ``%NAME%`` references.

    ``REG_EXPAND_SZ`` values are expandable, ``REG_SZ`` values are literal.
    """

    merged_from: tuple[VariableRecord, VariableRecord] | None = None
    """For merged variables, the ``(machine, user)`` records they were merged from."""


@dataclass
class ExpansionStep:
    """One step in the expansion of a text, for step-by-step provenance."""

    depth: int
    """Nesting depth at which the variable was referenced (0 = top-level text)."""

    variable: str
    """The variable name as written in the text (original casing)."""

    status: str
    """``resolved``, ``unresolved``, ``cycle`` or ``limit``."""

    source: str | None = None
    """The layer the value came from (``machine``, ``user`` or ``merged``)."""

    origin: str | None = None
    """Human-readable origin of the substituted value."""

    replacement: str | None = None
    """The raw value that was substituted for the variable."""


@dataclass
class ExpansionReport:
    """The result of expanding a text, with full provenance.

    The report never pretends to be a finished path: ``complete`` is only
    ``True`` when no variable was left unresolved, no cycle was detected and
    no expansion limit was hit. The original text is kept in ``raw`` so the
    raw registry data can always be traced back.
    """

    raw: str
    """The original text, exactly as found in the registry."""

    value: str
    """The resulting text, possibly still containing unresolved ``%NAME%`` references."""

    expanded: bool
    """Whether expansion was attempted (``False`` for non-``REG_EXPAND_SZ`` text)."""

    complete: bool
    """Whether nothing was left pending (no unresolved variables, cycles or limits)."""

    steps: list[ExpansionStep] = field(default_factory=list)
    """Every substitution attempt, in order, with its provenance."""

    unresolved: list[str] = field(default_factory=list)
    """Names of variables that could not be resolved, in order of first appearance."""

    cycles: list[str] = field(default_factory=list)
    """Names of variables involved in a circular reference."""

    notes: list[str] = field(default_factory=list)
    """Additional remarks, e.g. why a value was not expanded."""

    sources: list[str] = field(default_factory=list)
    """Description of the environment layers of the context used."""

    def explain(self) -> str:
        """Render a human-readable, step-by-step explanation of this expansion."""
        lines = [
            f"raw:      {self.raw}",
            f"value:    {self.value}",
            f"expanded: {self.expanded}",
            f"complete: {self.complete}",
        ]
        if self.sources:
            lines.append("context:")
            lines.extend(f"  - {source}" for source in self.sources)
        if self.steps:
            lines.append("steps:")
            for index, step in enumerate(self.steps, 1):
                prefix = f"  {index}. depth {step.depth}: %{step.variable}%"
                if step.status == RESOLVED:
                    lines.append(f"{prefix} <- {step.replacement!r} [{step.source}: {step.origin}]")
                elif step.status == UNRESOLVED:
                    lines.append(f"{prefix} unresolved (not present in context; left verbatim)")
                elif step.status == CYCLE:
                    lines.append(f"{prefix} circular reference detected [{step.source}: {step.origin}]; left verbatim")
                else:
                    lines.append(f"{prefix} expansion limit reached; left verbatim")
        if self.unresolved:
            lines.append(f"unresolved: {', '.join(self.unresolved)}")
        if self.cycles:
            lines.append(f"cycles: {', '.join(self.cycles)}")
        lines.extend(f"note: {note}" for note in self.notes)
        return "\n".join(lines)


@dataclass
class _ExpansionState:
    steps: list[ExpansionStep] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    cycles: list[str] = field(default_factory=list)
    limited: bool = False
    count: int = 0


class ExpansionContext:
    """An explicit, offline environment for expanding ``REG_EXPAND_SZ`` text.

    The environment is built exclusively from the layers added to this
    context -- a SYSTEM hive, a user hive and/or caller-provided captured
    values. The host process environment is never consulted as a fallback.

    Args:
        merge_variables: Names (case-insensitive) for which a user value does
            not override the machine value but is appended to it with a ``;``
            separator. Defaults to ``("PATH",)``, mirroring Windows.
        max_depth: Maximum nesting depth for recursive expansion.
        max_steps: Maximum total number of substitutions per expansion.
    """

    def __init__(
        self,
        *,
        merge_variables: Iterable[str] = DEFAULT_MERGE_VARIABLES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_steps: int = DEFAULT_MAX_STEPS,
    ):
        self._machine: dict[str, VariableRecord] = {}
        self._user: dict[str, VariableRecord] = {}
        self._merge_variables = {name.upper() for name in merge_variables}
        self.max_depth = max_depth
        self.max_steps = max_steps
        self.sources: list[str] = []

    @classmethod
    def from_hives(
        cls,
        system_hive: RegistryHive | None = None,
        user_hive: RegistryHive | None = None,
        *,
        control_set: str | int | None = None,
        **kwargs,
    ) -> ExpansionContext:
        """Build a context from a SYSTEM hive and optionally a user hive (NTUSER.DAT).

        The machine layer is read from
        ``<ControlSet>\\Control\\Session Manager\\Environment`` of the SYSTEM
        hive, where the control set defaults to the one selected by
        ``Select\\Current``. The user layer is read from the ``Environment``
        key of the user hive, with ``Volatile Environment`` (captured at
        logon) taking precedence over it.
        """
        context = cls(**kwargs)

        if system_hive is not None:
            control_set = _normalize_control_set(system_hive, control_set)
            key_path = f"{control_set}\\{ENVIRONMENT_KEY}"
            context.add_machine(_environment_records(system_hive, key_path, MACHINE, "SYSTEM hive"))

        if user_hive is not None:
            records = _environment_records(user_hive, USER_ENVIRONMENT_KEY, USER, "user hive")
            records += _environment_records(
                user_hive, USER_VOLATILE_ENVIRONMENT_KEY, USER, "user hive (volatile)"
            )
            context.add_user(records)

        return context

    @classmethod
    def from_values(
        cls,
        machine: Mapping[str, str] | Iterable[VariableRecord] | None = None,
        user: Mapping[str, str] | Iterable[VariableRecord] | None = None,
        *,
        expandable: bool = True,
        **kwargs,
    ) -> ExpansionContext:
        """Build a context from caller-provided captured values.

        Args:
            machine: Captured machine environment values.
            user: Captured per-user environment values.
            expandable: Whether the captured values may contain nested
                ``%NAME%`` references that should be expanded recursively.
                Pass ``False`` for values that were captured already expanded.
        """
        context = cls(**kwargs)
        if machine:
            context.add_machine(machine, expandable=expandable)
        if user:
            context.add_user(user, expandable=expandable)
        return context

    def add_machine(
        self,
        values: Mapping[str, str] | Iterable[VariableRecord],
        *,
        origin: str = "caller-provided captured values",
        expandable: bool = True,
    ) -> None:
        """Add or replace machine-layer variables."""
        records = _normalize_records(values, MACHINE, origin, expandable)
        self._machine.update(records)
        self._register_sources(records.values(), MACHINE)

    def add_user(
        self,
        values: Mapping[str, str] | Iterable[VariableRecord],
        *,
        origin: str = "caller-provided captured values",
        expandable: bool = True,
    ) -> None:
        """Add or replace user-layer variables (these override machine variables)."""
        records = _normalize_records(values, USER, origin, expandable)
        self._user.update(records)
        self._register_sources(records.values(), USER)

    def _register_sources(self, records: Iterable[VariableRecord], source: str) -> None:
        counts: dict[str, int] = {}
        for record in records:
            counts[record.origin] = counts.get(record.origin, 0) + 1
        for origin, count in counts.items():
            self.sources.append(f"{source}: {origin} ({count} variables)")

    def _lookup(self, key: str) -> VariableRecord | None:
        """Resolve an uppercased variable name to its effective record.

        User values override machine values, except for merge variables where
        the effective value is ``machine + ";" + user``.
        """
        machine_record = self._machine.get(key)
        user_record = self._user.get(key)

        if machine_record is not None and user_record is not None:
            if key in self._merge_variables:
                return VariableRecord(
                    name=user_record.name,
                    value=f"{machine_record.value};{user_record.value}",
                    source=MERGED,
                    origin=f"{machine_record.origin} + {user_record.origin}",
                    expandable=machine_record.expandable or user_record.expandable,
                    merged_from=(machine_record, user_record),
                )
            return user_record

        return user_record if user_record is not None else machine_record

    def snapshot(self) -> dict[str, VariableRecord]:
        """Return the effective variables (keyed by uppercased name) after layering."""
        keys = set(self._machine) | set(self._user)
        return {key: self._lookup(key) for key in sorted(keys)}

    def expand(self, text: str, *, value_type: int = REG_EXPAND_SZ) -> ExpansionReport:
        """Expand ``%NAME%`` references in ``text`` using this context.

        ``value_type`` must be the registry type the text was read from; only
        ``REG_EXPAND_SZ`` text is expanded, anything else is returned verbatim.
        """
        if not isinstance(text, str):
            raise Error(f"Can only expand text values, got {type(text).__name__}")

        if value_type != REG_EXPAND_SZ:
            return ExpansionReport(
                raw=text,
                value=text,
                expanded=False,
                complete=True,
                notes=[f"value type {value_type} is not REG_EXPAND_SZ; text returned verbatim"],
                sources=list(self.sources),
            )

        state = _ExpansionState()
        value = self._expand_text(text, stack=(), depth=0, state=state)
        complete = not (state.unresolved or state.cycles or state.limited)

        return ExpansionReport(
            raw=text,
            value=value,
            expanded=True,
            complete=complete,
            steps=state.steps,
            unresolved=_unique(state.unresolved),
            cycles=_unique(state.cycles),
            notes=["expansion limit reached; result is partial"] if state.limited else [],
            sources=list(self.sources),
        )

    def expand_value(self, key_value: KeyValue) -> ExpansionReport:
        """Expand a :class:`~dissect.regf.regf.KeyValue` according to its registry type.

        Only ``REG_EXPAND_SZ`` values are expanded; ``REG_SZ`` and all other
        types are returned verbatim. The raw registry data remains available
        on the ``KeyValue`` itself.
        """
        raw = key_value.value
        if not isinstance(raw, str):
            raise Error(f"Cannot expand non-string value {key_value.name!r} of type {key_value.type}")
        return self.expand(raw, value_type=key_value.type)

    def _expand_text(self, text: str, stack: tuple[str, ...], depth: int, state: _ExpansionState) -> str:
        def replace(match: re.Match) -> str:
            name = match.group(1)
            key = name.upper()
            record = self._lookup(key)

            if record is None:
                state.steps.append(ExpansionStep(depth, name, UNRESOLVED))
                state.unresolved.append(name)
                return match.group(0)

            if key in stack:
                state.steps.append(ExpansionStep(depth, name, CYCLE, record.source, record.origin))
                state.cycles.append(name)
                return match.group(0)

            if state.count >= self.max_steps or (record.expandable and depth + 1 >= self.max_depth):
                state.steps.append(ExpansionStep(depth, name, LIMIT, record.source, record.origin))
                state.limited = True
                return match.group(0)

            state.count += 1
            state.steps.append(ExpansionStep(depth, name, RESOLVED, record.source, record.origin, record.value))

            if not record.expandable:
                # Literal (REG_SZ) value: substituted as-is, never re-scanned.
                return record.value

            return self._expand_text(record.value, stack + (key,), depth + 1, state)

        return TOKEN_PATTERN.sub(replace, text)


def _normalize_records(
    values: Mapping[str, str] | Iterable[VariableRecord],
    source: str,
    origin: str,
    expandable: bool,
) -> dict[str, VariableRecord]:
    if isinstance(values, Mapping):
        items = values.items()
    else:
        items = values

    records = {}
    for item in items:
        if isinstance(item, VariableRecord):
            record = item
        else:
            name, value = item
            record = VariableRecord(str(name), str(value), source, origin, expandable)
        records[record.name.upper()] = record

    return records


def _normalize_control_set(hive: RegistryHive, control_set: str | int | None) -> str:
    if isinstance(control_set, int):
        return f"ControlSet{control_set:03d}"
    if isinstance(control_set, str):
        return control_set

    try:
        current = hive.open("Select").value("Current").value
        if isinstance(current, int) and current > 0:
            return f"ControlSet{current:03d}"
    except (RegistryKeyNotFoundError, RegistryValueNotFoundError):
        pass

    log.warning("Unable to determine the current control set, falling back to ControlSet001")
    return "ControlSet001"


def _environment_records(hive: RegistryHive, key_path: str, source: str, label: str) -> list[VariableRecord]:
    origin = f"{label}: {key_path}"

    try:
        key = hive.open(key_path)
    except RegistryKeyNotFoundError:
        log.warning("Environment key %r not found in %s", key_path, label)
        return []

    records = []
    for value in key.values():
        if value.type not in (REG_SZ, REG_EXPAND_SZ):
            log.debug("Skipping non-string environment value %r of type %d", value.name, value.type)
            continue
        records.append(
            VariableRecord(
                name=value.name,
                value=value.value,
                source=source,
                origin=origin,
                expandable=value.type == REG_EXPAND_SZ,
            )
        )

    return records


def _unique(names: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for name in names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result
