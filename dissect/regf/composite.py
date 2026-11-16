"""Offline composite registry views across machine and user hives.

A Windows registry is stored on disk as separate hive files.  The logical names
``HKEY_LOCAL_MACHINE\\SYSTEM``, ``HKEY_LOCAL_MACHINE\\SOFTWARE`` and
``HKEY_CURRENT_USER`` only exist after a caller explicitly says which hives to
mount and, for ``CurrentControlSet``, which ``Select`` evidence to trust.

This module implements that composition without consulting the registry of the
machine running the analysis:

* every mount is an explicit :class:`dissect.regf.regf.RegistryHive` object;
* ``CurrentControlSet`` is resolved from the SYSTEM hive's own ``Select`` key
  and nothing else;
* ``Current``, ``Default`` and ``LastKnownGood`` are separate pointers and are
  never used as fallbacks for each other;
* user-relative paths such as ``HKEY_CURRENT_USER`` require an unambiguous
  user context when more than one user hive is mounted;
* every returned key keeps the source hive, the physical key path inside that
  hive and the selection evidence that was used to reach it.

Views are immutable.  :meth:`RegistryView.with_user` and
:meth:`RegistryView.with_control_set` return a new view, so handles obtained
from an earlier view keep their original provenance and continue to read the
same hive.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from dissect.regf.exceptions import (
    ControlSetNotFoundError,
    Error,
    MissingContextError,
    MountNotFoundError,
    RegistryKeyNotFoundError,
    UserContextError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from dissect.regf.regf import KeyNode, KeyValue, RegistryHive

__all__ = [
    "CompositeRegistry",
    "CompositeRegistryView",
    "ControlSetSelection",
    "HiveSource",
    "RegistryKey",
    "RegistryValue",
    "RegistryView",
]

ROLE_SYSTEM = "SYSTEM"
ROLE_SOFTWARE = "SOFTWARE"
ROLE_USER = "USER"

SYSTEM_MOUNT = "\\REGISTRY\\MACHINE\\SYSTEM"
SOFTWARE_MOUNT = "\\REGISTRY\\MACHINE\\SOFTWARE"

CONTROL_SET_POINTERS = {
    "CURRENT": "Current",
    "DEFAULT": "Default",
    "LASTKNOWNGOOD": "LastKnownGood",
}

CONTROL_SET_ALIASES = {
    "CURRENTCONTROLSET": ("CurrentControlSet", "Current"),
    "DEFAULTCONTROLSET": ("DefaultControlSet", "Default"),
    "LASTKNOWNGOODCONTROLSET": ("LastKnownGoodControlSet", "LastKnownGood"),
}

USER_ALIASES = {"CURRENT_USER", "CURRENTUSER", "HKCU", "HKEY_CURRENT_USER"}
_ROOT_PREFIXES = {
    "REGISTRY",
    "HKLM",
    "HKEY_LOCAL_MACHINE",
    "HKCU",
    "HKEY_CURRENT_USER",
    "HKU",
    "HKEY_USERS",
}

TYPE_NAMES = {
    0x0: "REG_NONE",
    0x1: "REG_SZ",
    0x2: "REG_EXPAND_SZ",
    0x3: "REG_BINARY",
    0x4: "REG_DWORD",
    0x5: "REG_DWORD_BIG_ENDIAN",
    0x6: "REG_LINK",
    0x7: "REG_MULTI_SZ",
    0x8: "REG_RESOURCE_LIST",
    0x9: "REG_FULL_RESOURCE_DESCRIPTOR",
    0xA: "REG_RESOURCE_REQUIREMENTS_LIST",
    0xB: "REG_QWORD",
}


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _segments(path: str) -> tuple[str, ...]:
    path = path.strip().replace("/", "\\")
    return tuple(part for part in path.split("\\") if part)


def _join_path(prefix: str, parts: tuple[str, ...]) -> str:
    if not prefix:
        return "\\".join(parts)
    return "\\".join((prefix, *parts))


def _format_control_set(value: int | str) -> str:
    if isinstance(value, bool):
        raise Error(f"Invalid control set number {value!r}")

    if isinstance(value, int):
        if value < 0:
            raise Error(f"Invalid control set number {value!r}")
        return f"ControlSet{value:03d}"

    text = value.strip()
    if text.isdigit():
        return f"ControlSet{int(text):03d}"
    if text.lower().startswith("controlset") and text[10:].isdigit():
        return f"ControlSet{int(text[10:]):03d}"
    raise Error(f"Invalid control set name {value!r}; expected ControlSetNNN or a number")


@dataclass(frozen=True)
class HiveSource:
    """An explicitly mounted hive and the offline mount point it came from."""

    role: str
    """``SYSTEM``, ``SOFTWARE`` or ``USER``."""

    identifier: str
    """``SYSTEM``, ``SOFTWARE`` or the user SID (or caller label) for a user hive."""

    mount_path: str
    """The virtual registry path this hive was mounted at."""

    hive: RegistryHive
    """The original hive object supplied by the caller."""

    @property
    def filename(self) -> str:
        """The hive file name recorded in the base block, if present."""
        return self.hive.filename

    @property
    def name(self) -> str:
        """Alias for :attr:`identifier`."""
        return self.identifier

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "identifier": self.identifier,
            "mount_path": self.mount_path,
            "filename": self.filename,
        }


@dataclass(frozen=True)
class ControlSetSelection:
    """The evidence that selected one physical control set for a logical alias."""

    alias: str
    """Logical name requested by the caller, e.g. ``CurrentControlSet``."""

    control_set: str
    """Physical control set key that was selected, e.g. ``ControlSet001``."""

    pointer: str | None = None
    """The Select value name used (``Current``, ``Default`` or ``LastKnownGood``)."""

    value: int | None = None
    """The raw integer stored in that Select value."""

    source: HiveSource | None = None
    """The SYSTEM hive that supplied the Select evidence."""

    select_key_path: str = "Select"
    """The key path inside the SYSTEM hive where the pointer was read."""

    explicit: bool = False
    """True when the control set came from explicit context instead of a Select value."""

    physical: bool = False
    """True when this is a physical ``ControlSetNNN`` path rather than an alias."""

    @property
    def selected_control_set(self) -> str:
        """Alias for :attr:`control_set`."""
        return self.control_set

    @property
    def physical_control_set(self) -> str:
        """Alias for :attr:`control_set`, emphasising the physical key."""
        return self.control_set

    @property
    def logical_alias(self) -> str:
        """Alias for :attr:`alias`."""
        return self.alias

    @property
    def select_value(self) -> int | None:
        """Alias for :attr:`value`."""
        return self.value

    @property
    def source_hive(self) -> RegistryHive | None:
        """The original hive object that supplied the evidence, if any."""
        return self.source.hive if self.source is not None else None

    @property
    def source_filename(self) -> str | None:
        """The base-block file name of the source hive, if any."""
        return self.source.filename if self.source is not None else None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "alias": self.alias,
            "pointer": self.pointer,
            "value": self.value,
            "control_set": self.control_set,
            "select_key_path": self.select_key_path,
            "explicit": self.explicit,
            "physical": self.physical,
        }
        if self.source is not None:
            result["source"] = self.source.to_dict()
        return result


class RegistryValue:
    """A registry value with the provenance of the key that contains it."""

    def __init__(self, key: RegistryKey, value: KeyValue):
        self._key = key
        self._value = value

    @property
    def key(self) -> RegistryKey:
        return self._key

    @property
    def node(self) -> KeyValue:
        return self._value

    @property
    def raw(self) -> KeyValue:
        return self._value

    @property
    def name(self) -> str:
        return self._value.name

    @property
    def type(self) -> int:
        return self._value.type

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self._value.type, f"REG_UNKNOWN_{self._value.type:#x}")

    @property
    def size(self) -> int:
        return self._value.size

    @property
    def data(self) -> bytes:
        return self._value.data

    @property
    def value(self) -> int | str | list[str] | bytes:
        return self._value.value

    @property
    def is_big_value(self) -> bool:
        return self._value.is_big_value

    @property
    def hive(self) -> RegistryHive:
        return self._key.hive

    @property
    def source(self) -> HiveSource:
        return self._key.source

    @property
    def selection(self) -> ControlSetSelection | None:
        return self._key.selection

    @property
    def logical_path(self) -> str:
        return self._key.logical_path

    @property
    def physical_key_path(self) -> str:
        return self._key.physical_path

    def to_dict(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "type": self.type,
            "type_name": self.type_name,
            "value": _jsonable(self.value),
            "data": {"hex": self.data.hex()},
            "logical_key_path": self.logical_path,
            "physical_key_path": self.physical_key_path,
            "hive": self.source.to_dict(),
        }
        if self.selection is not None:
            result["selection"] = self.selection.to_dict()
        return result

    def __repr__(self) -> str:
        return f"<RegistryValue {self.name}={self.value!r} {self.physical_key_path}>"


class RegistryKey:
    """A key reached through a :class:`RegistryView`.

    The wrapped :class:`~dissect.regf.regf.KeyNode` is available through
    :attr:`node`.  :attr:`path` and :attr:`physical_path` are the path inside
    the source hive; :attr:`logical_path` is the path as requested, including
    any logical alias such as ``CurrentControlSet``.
    """

    def __init__(
        self,
        view: RegistryView,
        node: KeyNode,
        logical_path: str,
        source: HiveSource,
        selection: ControlSetSelection | None,
    ):
        self._view = view
        self._node = node
        self._logical_path = logical_path
        self._source = source
        self._selection = selection

    @property
    def view(self) -> RegistryView:
        return self._view

    @property
    def node(self) -> KeyNode:
        return self._node

    @property
    def key(self) -> KeyNode:
        return self._node

    @property
    def raw(self) -> KeyNode:
        return self._node

    @property
    def hive(self) -> RegistryHive:
        return self._source.hive

    @property
    def source(self) -> HiveSource:
        return self._source

    @property
    def hive_source(self) -> HiveSource:
        return self._source

    @property
    def source_hive(self) -> RegistryHive:
        """The original hive object this key was read from."""
        return self._source.hive

    @property
    def source_filename(self) -> str:
        """The base-block file name of the source hive."""
        return self._source.filename

    @property
    def selection(self) -> ControlSetSelection | None:
        return self._selection

    @property
    def control_set_selection(self) -> ControlSetSelection | None:
        return self._selection

    @property
    def name(self) -> str:
        return self._node.name

    @property
    def path(self) -> str:
        """Physical key path inside the source hive."""
        return self._node.path

    @property
    def physical_path(self) -> str:
        """Physical key path inside the source hive."""
        return self._node.path

    @property
    def physical_key_path(self) -> str:
        """Alias for :attr:`physical_path`."""
        return self._node.path

    @property
    def logical_path(self) -> str:
        """Path as requested, preserving logical aliases and user roots."""
        return self._logical_path

    @property
    def requested_path(self) -> str:
        """Alias for :attr:`logical_path`."""
        return self._logical_path

    @property
    def physical_control_set(self) -> str | None:
        """The physical control set key containing this key, if any."""
        if self._source.role != ROLE_SYSTEM:
            return None

        first = self._node.path.split("\\", 1)[0]
        return first if RegistryView._looks_like_control_set(first) else None

    @property
    def control_set(self) -> str | None:
        """The control set in effect for this key, physical or selected."""
        if self._selection is not None:
            return self._selection.control_set
        return self.physical_control_set

    @property
    def class_name(self) -> str | None:
        return self._node.class_name

    @property
    def timestamp(self) -> Any:
        return self._node.timestamp

    def subkeys(self) -> Iterator[RegistryKey]:
        for subkey in self._node.subkeys():
            yield RegistryKey(
                self._view,
                subkey,
                _join_path(self._logical_path, (subkey.name,)),
                self._source,
                self._selection,
            )

    def subkey(self, name: str) -> RegistryKey:
        subkey = self._node.subkey(name)
        return RegistryKey(
            self._view,
            subkey,
            _join_path(self._logical_path, (subkey.name,)),
            self._source,
            self._selection,
        )

    def open(self, path: str) -> RegistryKey:
        """Open ``path`` relative to this key, or delegate a fully rooted path.

        Paths starting with ``\\`` or a multi-token registry root such as
        ``HKLM`` or ``HKEY_LOCAL_MACHINE`` are resolved against the view, so
        ``key.open("HKLM\\SOFTWARE\\...")`` is equivalent to
        ``key.view.open(...)``.  A single leading token is always treated as a
        child name, because a key may legitimately be named ``SYSTEM``.
        """
        parts = _segments(path)
        if not parts:
            return self

        if path.strip().startswith("\\") or (len(parts) > 1 and parts[0].upper() in _ROOT_PREFIXES):
            return self._view.open(path)

        node = self._node
        logical = self._logical_path
        for part in parts:
            node = node.subkey(part)
            logical = _join_path(logical, (node.name,))

        return RegistryKey(self._view, node, logical, self._source, self._selection)

    def values(self) -> Iterator[RegistryValue]:
        for value in self._node.values():
            yield RegistryValue(self, value)

    def value(self, name: str) -> RegistryValue:
        return RegistryValue(self, self._node.value(name))

    def to_dict(self, *, include_values: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "logical_path": self._logical_path,
            "physical_path": self._node.path,
            "physical_control_set": self.physical_control_set,
            "hive": self._source.to_dict(),
        }
        if self._selection is not None:
            result["selection"] = self._selection.to_dict()
        if include_values:
            result["values"] = [value.to_dict() for value in self.values()]
        return result

    @property
    def provenance(self) -> dict[str, Any]:
        """Machine-readable expansion of this handle's source and selection."""
        return self.to_dict()

    def expand(self, *, include_values: bool = True) -> dict[str, Any]:
        """Expand this handle to the source hive, physical path and selection evidence."""
        return self.to_dict(include_values=include_values)

    def __repr__(self) -> str:
        return f"<RegistryKey {self._logical_path!r} from {self._source.role}:{self._node.path!r}>"


class RegistryView:
    """An immutable, explicitly mounted view over one or more registry hives.

    :param system: The SYSTEM hive, required for ``CurrentControlSet`` and any
        ``ControlSetNNN`` path.
    :param software: The SOFTWARE hive mounted at ``HKEY_LOCAL_MACHINE\\SOFTWARE``.
    :param users: Mapping of user SID (or caller label) to NTUSER hive.
    :param user: Explicit user context for ``HKEY_CURRENT_USER`` queries.  It
        must match one of the keys in ``users``.
    :param control_set: Explicit physical control set (``ControlSet001`` or the
        integer ``1``) used when resolving the ``CurrentControlSet`` alias.
        This is the only way to resolve that alias when the SYSTEM hive has no
        usable ``Select\\Current`` evidence.  It never stands in for
        ``Select\\Default`` or ``Select\\LastKnownGood``.
    """

    def __init__(
        self,
        system: RegistryHive | None = None,
        software: RegistryHive | None = None,
        users: Mapping[str, RegistryHive] | None = None,
        *,
        user: str | None = None,
        control_set: int | str | None = None,
    ):
        self._system = system
        self._software = software
        self._users: dict[str, RegistryHive] = {}

        if users:
            seen: set[str] = set()
            for identifier, hive in users.items():
                if not isinstance(identifier, str) or not identifier.strip():
                    raise Error("A user hive requires a non-empty SID or label")
                folded = identifier.strip().casefold()
                if folded in seen:
                    raise Error(f"Duplicate user hive for {identifier!r} (user labels are case-insensitive)")
                seen.add(folded)
                self._users[identifier.strip()] = hive

        self._user = self._match_user(user) if user is not None else None
        if user is not None and self._user is None:
            available = ", ".join(self._users) or "none"
            raise UserContextError(f"No user hive mounted for {user!r}; available users: {available}")

        self._control_set = _format_control_set(control_set) if control_set is not None else None
        if self._control_set is not None and system is not None:
            self._require_control_set(self._control_set)

    @classmethod
    def from_hives(
        cls,
        system: RegistryHive | None = None,
        software: RegistryHive | None = None,
        users: Mapping[str, RegistryHive] | None = None,
        *,
        user: str | None = None,
        control_set: int | str | None = None,
    ) -> RegistryView:
        """Construct a view with the same arguments as the class itself."""
        return cls(system=system, software=software, users=users, user=user, control_set=control_set)

    @property
    def system(self) -> RegistryHive | None:
        return self._system

    @property
    def software(self) -> RegistryHive | None:
        return self._software

    @property
    def users(self) -> Mapping[str, RegistryHive]:
        return MappingProxyType(self._users)

    @property
    def user(self) -> str | None:
        return self._user

    @property
    def control_set(self) -> str | None:
        return self._control_set

    @property
    def mounts(self) -> Mapping[str, HiveSource]:
        """The explicit mount points and the hive each one resolves to."""
        mounts: dict[str, HiveSource] = {}
        if self._system is not None:
            mounts[SYSTEM_MOUNT] = self._system_source()
        if self._software is not None:
            mounts[SOFTWARE_MOUNT] = self._software_source()
        for identifier, hive in self._users.items():
            mounts[f"\\REGISTRY\\USER\\{identifier}"] = HiveSource(
                ROLE_USER, identifier, f"\\REGISTRY\\USER\\{identifier}", hive
            )
        return MappingProxyType(mounts)

    def to_dict(self) -> dict[str, Any]:
        """Return the explicit mounts and context of this view."""
        return {
            "mounts": {path: source.to_dict() for path, source in self.mounts.items()},
            "user": self._user,
            "control_set": self._control_set,
        }

    def with_user(self, user: str | None, hive: RegistryHive | None = None) -> RegistryView:
        """Return a new view with a different user context.

        ``hive`` optionally mounts an additional NTUSER hive under ``user``;
        an existing identifier is replaced for the new view only.  The current
        view and all handles obtained from it are unchanged.
        """
        users = dict(self._users)
        if hive is not None:
            if not user:
                raise UserContextError("Mounting a user hive requires a non-empty SID or label")
            users[user.strip()] = hive

        return RegistryView(
            system=self._system,
            software=self._software,
            users=users,
            user=user,
            control_set=self._control_set,
        )

    def with_user_hive(self, identifier: str, hive: RegistryHive) -> RegistryView:
        """Return a new view with ``hive`` mounted for ``identifier``."""
        return self.with_user(identifier, hive)

    def with_control_set(self, control_set: int | str | None) -> RegistryView:
        """Return a new view with an explicit physical control set."""
        return RegistryView(
            system=self._system,
            software=self._software,
            users=self._users,
            user=self._user,
            control_set=control_set,
        )

    def with_current_control_set(self, control_set: int | str | None) -> RegistryView:
        """Alias for :meth:`with_control_set`."""
        return self.with_control_set(control_set)

    def select_control_set(self, pointer: str = "Current") -> ControlSetSelection:
        """Read one Select pointer from the SYSTEM hive.

        Only the requested pointer is read.  If it is absent, malformed or
        points to a control set that does not exist, an exception is raised;
        no other pointer is tried as a fallback.
        """
        canonical = CONTROL_SET_POINTERS.get(pointer.strip().upper())
        if canonical is None:
            raise MissingContextError(
                f"Unknown Select pointer {pointer!r}; expected one of: Current, Default, LastKnownGood"
            )

        source = self._system_source()
        try:
            select_key = source.hive.open("Select")
        except RegistryKeyNotFoundError as exc:
            raise MissingContextError(
                "SYSTEM hive has no Select key; CurrentControlSet cannot be resolved without explicit "
                "control set context"
            ) from exc

        for value in select_key.values():
            if value.name.casefold() != canonical.casefold():
                continue

            if not isinstance(value.value, int) or isinstance(value.value, bool):
                raise MissingContextError(
                    f"Select\\{canonical} has non-integer value {value.value!r}; refusing to guess a control set"
                )

            if not 0 <= value.value <= 999:
                raise MissingContextError(
                    f"Select\\{canonical} has out-of-range value {value.value!r}; refusing to guess a control set"
                )

            control_set = self._require_control_set(f"ControlSet{value.value:03d}")
            return ControlSetSelection(
                alias=canonical,
                control_set=control_set,
                pointer=canonical,
                value=value.value,
                source=source,
            )

        raise MissingContextError(
            f"SYSTEM\\Select has no {canonical} value; refusing to substitute another Select pointer"
        )

    @property
    def current_control_set(self) -> str:
        """The physical control set in effect for ``CurrentControlSet``."""
        if self._control_set is not None:
            return self._require_control_set(self._control_set)
        return self.select_control_set("Current").control_set

    @property
    def current_control_set_evidence(self) -> ControlSetSelection:
        """The full evidence behind :attr:`current_control_set`."""
        if self._control_set is not None:
            return ControlSetSelection(
                alias="CurrentControlSet",
                control_set=self._require_control_set(self._control_set),
                source=self._system_source(),
                explicit=True,
            )
        return self.select_control_set("Current")

    def open(self, path: str) -> RegistryKey:
        """Open a hive-qualified or explicitly rooted registry path.

        Supported roots include ``HKLM\\SYSTEM``, ``HKLM\\SOFTWARE``,
        ``HKEY_CURRENT_USER``, ``HKU\\<SID>``, ``\\REGISTRY\\MACHINE\\...`` and
        the shorthand ``SYSTEM\\...`` and ``SOFTWARE\\...``.  Bare paths that
        do not identify a mounted hive are rejected rather than guessed.
        """
        source, parts, logical_path, selection = self._resolve(path)
        node = source.hive.root()

        for part in parts:
            node = node.subkey(part)

        return RegistryKey(self, node, logical_path, source, selection)

    def get(self, path: str) -> RegistryKey:
        """Alias for :meth:`open`."""
        return self.open(path)

    def resolve(self, path: str) -> RegistryKey:
        """Alias for :meth:`open`, emphasising alias resolution."""
        return self.open(path)

    def _resolve(self, path: str) -> tuple[HiveSource, tuple[str, ...], str, ControlSetSelection | None]:
        original = _segments(path)
        if not original:
            raise MountNotFoundError("Registry path is empty; a hive-qualified path is required")

        upper = tuple(part.upper() for part in original)
        index = 0

        if upper[0] == "REGISTRY":
            index = 1
            if index >= len(original):
                raise MountNotFoundError("\\REGISTRY requires MACHINE or USER after it")
            if upper[index] == "MACHINE":
                index += 1
                return self._machine(original, upper, index)
            if upper[index] == "USER":
                index += 1
                return self._user_path(original, index)
            raise MountNotFoundError(f"Unsupported registry root \\REGISTRY\\{original[index]}")

        if upper[0] in ("HKLM", "HKEY_LOCAL_MACHINE"):
            return self._machine(original, upper, 1)

        if upper[0] in ("HKCU", "HKEY_CURRENT_USER"):
            source = self._user_source(None)
            return source, original[1:], "\\".join(original), None

        if upper[0] in ("HKU", "HKEY_USERS"):
            return self._user_path(original, 1)

        if upper[0] == "SYSTEM":
            source = self._system_source()
            parts, selection = self._apply_control_set_alias(original, upper, 1)
            return source, parts, "\\".join(original), selection

        if upper[0] == "SOFTWARE":
            return self._software_source(), original[1:], "\\".join(original), None

        if upper[0] in ("USER", "NTUSER"):
            return self._user_path(original, 1)

        if upper[0] in CONTROL_SET_ALIASES or upper[0] == "SELECT" or self._looks_like_control_set(original[0]):
            source = self._system_source()
            parts, selection = self._apply_control_set_alias(original, upper, 0)
            return source, parts, "\\".join(original), selection

        raise MountNotFoundError(
            f"Path {path!r} does not identify an explicitly mounted hive; prefix it with SYSTEM\\, SOFTWARE\\ "
            "or HKEY_CURRENT_USER\\ (bare paths are never guessed)"
        )

    def _machine(
        self,
        original: tuple[str, ...],
        upper: tuple[str, ...],
        index: int,
    ) -> tuple[HiveSource, tuple[str, ...], str, ControlSetSelection | None]:
        if index >= len(original):
            raise MountNotFoundError("HKEY_LOCAL_MACHINE requires SYSTEM or SOFTWARE after it")

        branch = upper[index]
        if branch == "SYSTEM":
            source = self._system_source()
            parts, selection = self._apply_control_set_alias(original, upper, index + 1)
            return source, parts, "\\".join(original), selection

        if branch == "SOFTWARE":
            return self._software_source(), original[index + 1 :], "\\".join(original), None

        raise MountNotFoundError(
            f"Unsupported HKEY_LOCAL_MACHINE branch {original[index]!r}; only SYSTEM and SOFTWARE are mounted"
        )

    def _user_path(
        self, original: tuple[str, ...], index: int
    ) -> tuple[HiveSource, tuple[str, ...], str, ControlSetSelection | None]:
        if index >= len(original):
            raise UserContextError("HKEY_USERS requires a user SID or CURRENT_USER")

        label = original[index]
        source = self._user_source(label)
        return source, original[index + 1 :], "\\".join(original), None

    def _apply_control_set_alias(
        self,
        original: tuple[str, ...],
        upper: tuple[str, ...],
        index: int,
    ) -> tuple[tuple[str, ...], ControlSetSelection | None]:
        if index >= len(original):
            return (), None

        alias_info = CONTROL_SET_ALIASES.get(upper[index])
        if alias_info is None:
            if not self._looks_like_control_set(original[index]):
                return original[index:], None

            # A physical control set path was requested. Preserve it as an
            # explicit selection rather than pretending no control set exists.
            source = self._system_source()
            control_set = self._require_control_set(original[index])
            selection = ControlSetSelection(
                alias=control_set,
                control_set=control_set,
                source=source,
                explicit=True,
                physical=True,
            )
            return (control_set, *original[index + 1 :]), selection

        alias, pointer = alias_info
        source = self._system_source()

        if self._control_set is not None and pointer == "Current":
            control_set = self._require_control_set(self._control_set)
            selection = ControlSetSelection(
                alias=alias,
                control_set=control_set,
                source=source,
                explicit=True,
            )
        else:
            evidence = self.select_control_set(pointer)
            selection = ControlSetSelection(
                alias=alias,
                control_set=evidence.control_set,
                pointer=evidence.pointer,
                value=evidence.value,
                source=evidence.source,
                select_key_path=evidence.select_key_path,
            )

        return (selection.control_set, *original[index + 1 :]), selection

    def _system_source(self) -> HiveSource:
        if self._system is None:
            raise MissingContextError("No SYSTEM hive is mounted; SYSTEM paths and CurrentControlSet are unavailable")
        return HiveSource(ROLE_SYSTEM, "SYSTEM", SYSTEM_MOUNT, self._system)

    def _software_source(self) -> HiveSource:
        if self._software is None:
            raise MissingContextError("No SOFTWARE hive is mounted; HKEY_LOCAL_MACHINE\\SOFTWARE is unavailable")
        return HiveSource(ROLE_SOFTWARE, "SOFTWARE", SOFTWARE_MOUNT, self._software)

    def _user_source(self, label: str | None) -> HiveSource:
        identifier = self._resolve_user(label)
        return HiveSource(ROLE_USER, identifier, f"\\REGISTRY\\USER\\{identifier}", self._users[identifier])

    def _resolve_user(self, label: str | None) -> str:
        if label is not None and label.strip().upper() not in USER_ALIASES:
            identifier = self._match_user(label)
            if identifier is None:
                available = ", ".join(self._users) or "none"
                raise UserContextError(f"No user hive mounted for {label!r}; available users: {available}")
            return identifier

        if self._user is not None:
            return self._user

        if len(self._users) == 1:
            return next(iter(self._users))

        if not self._users:
            raise UserContextError("No user hive is mounted; HKEY_CURRENT_USER cannot be resolved")

        available = ", ".join(self._users)
        raise UserContextError(
            f"Multiple user hives are mounted ({available}); provide an explicit user SID or use "
            "RegistryView.with_user() / the user= argument"
        )

    def _match_user(self, label: str | None) -> str | None:
        if label is None:
            return None

        folded = label.strip().casefold()
        for identifier in self._users:
            if identifier.casefold() == folded:
                return identifier
        return None

    def _require_control_set(self, name: str) -> str:
        source = self._system_source()
        needle = name.casefold()
        for subkey in source.hive.root().subkeys():
            if subkey.name.casefold() == needle:
                return subkey.name

        available = ", ".join(
            subkey.name for subkey in source.hive.root().subkeys() if self._looks_like_control_set(subkey.name)
        )
        raise ControlSetNotFoundError(
            f"{name!r} is not present in the SYSTEM hive; available control sets: {available or 'none'}. "
            "No other Select pointer or host registry is used as a fallback"
        )

    @staticmethod
    def _looks_like_control_set(name: str) -> bool:
        return len(name) == 13 and name[:10].casefold() == "controlset" and name[10:].isdigit()


# Descriptive aliases for callers that prefer an explicit name.
CompositeRegistryView = RegistryView
CompositeRegistry = RegistryView
