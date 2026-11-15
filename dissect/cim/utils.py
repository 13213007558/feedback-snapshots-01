from __future__ import annotations

import re
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.cim.c_cim import c_cim
from dissect.cim.exceptions import Error, InvalidObjectPathError, ReferenceNotFoundError

if TYPE_CHECKING:
    from dissect.cim.cim import Namespace


class ObjectPath(NamedTuple):
    hostname: str
    namespace: str | None
    class_: str
    instance: dict[str, str]


# CIM identifiers (class and property names) are a letter or underscore followed by letters, digits and underscores.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Namespace separators are only structural outside of quoted property values.
_NAMESPACE_SEPARATORS = "/\\"
_QUOTE_CHARS = "\"'"


def is_xp_mapping(h: c_cim.mapping_header | c_cim.mapping_header_xp) -> bool:
    if h.signature != 0xABCD:
        raise Error("Invalid mapping file signature")

    if h.mapping_entry_count < h.physical_page_count // 10:
        return True

    return bool(hasattr(h, "first_id") and hasattr(h, "second_id") and h.first_id - 1 != h.second_id)


def find_current_mapping(mappings: list[BinaryIO]) -> tuple[bool, BinaryIO]:
    map_header = c_cim.mapping_header
    type_xp = None
    current = None
    max_version = 0

    for m in mappings:
        m.seek(0)
        mh = map_header(m)
        m.seek(0)

        if type_xp is None:
            type_xp = is_xp_mapping(mh)
            if type_xp:
                map_header = c_cim.mapping_header_xp
                mh = map_header(m)
                m.seek(0)

        if mh.version > max_version:
            current = m
            max_version = mh.version

    return type_xp, current


def parse_object_path(object_path: str, ns: Namespace | None = None) -> ObjectPath:
    """Given a textual query string, parse it into an object path that we can query.

    Supported schemas::

        cimv2 --> namespace
        //./root/cimv2 --> namespace
        //HOSTNAME/root/cimv2 --> namespace
        winmgmts://./root/cimv2 --> namespace
        Win32_Service --> class
        //./root/cimv2:Win32_Service --> class
        Win32_Service.Name='Beep' --> instance
        //./root/cimv2:Win32_Service.Name="Beep" --> instance
        //./root/cimv2:Win32_Service.Name="Beep",SystemCreationClassName="ComputerSystem" --> instance

    Namespaces can be separated by either ``/`` or ``\\``. Backslashes inside quoted property values are not
    namespace separators and are preserved, so Windows and UNC paths survive parsing unchanged. A delimiter inside
    a quoted value is escaped by doubling it (``""``/``''``) or, when the value continues afterwards, by a backslash.
    Parsing does not touch the database; only ambiguous relative paths are resolved against ``ns``.

    Args:
        object_path: the textual query string.
        ns: optional namespace used to resolve relative paths.

    Returns:
        ObjectPath: a path we can use to query.

    Raises:
        InvalidObjectPathError: if the object path is malformed. The exception contains the offending character
            position and a description of the syntax problem.
    """
    if not isinstance(object_path, str):
        raise TypeError("object_path should be a string")

    o_object_path = object_path
    start, end = _trim(object_path, 0, len(object_path))
    if start == end:
        raise InvalidObjectPathError("empty object path", o_object_path, start)

    pos = start
    if object_path[pos : pos + len("winmgmts:")].lower() == "winmgmts:":
        pos += len("winmgmts:")
        pos, _ = _trim(object_path, pos, end)

    hostname = "localhost"
    rooted = False

    if object_path.startswith("//", pos) or object_path.startswith("\\\\", pos):
        rooted = True
        pos += 2

        separator = _find_unquoted(object_path, _NAMESPACE_SEPARATORS, pos, end)
        if separator == -1:
            raise InvalidObjectPathError("missing namespace path after host", o_object_path, pos)

        host_start, host_end = _trim(object_path, pos, separator)
        if host_start == host_end:
            raise InvalidObjectPathError("missing host name", o_object_path, pos)

        _reject_quotes(object_path, host_start, host_end, "unexpected quote in host name")
        hostname = _normalize_host(object_path[host_start:host_end])
        pos = separator + 1
        while pos < end and object_path[pos] in _NAMESPACE_SEPARATORS:
            pos += 1
    elif object_path.startswith("./", pos) or object_path.startswith(".\\", pos):
        # An explicit local host with a relative path, e.g. ./root/cimv2.
        rooted = True
        pos += 2
        while pos < end and object_path[pos] in _NAMESPACE_SEPARATORS:
            pos += 1
    elif pos < end and object_path[pos] in _NAMESPACE_SEPARATORS:
        # A single leading separator denotes an absolute local path without a host, e.g. /root/cimv2.
        rooted = True
        pos += 1
        while pos < end and object_path[pos] in _NAMESPACE_SEPARATORS:
            pos += 1

    if pos >= end:
        raise InvalidObjectPathError("missing namespace path", o_object_path, pos)

    colon = _find_unquoted(object_path, ":", pos, end)
    dot = _find_unquoted(object_path, ".", pos, end)

    # A colon only separates the namespace from the class if it appears before the first class separator. This keeps
    # unquoted values such as ``Class.Name=C:/path`` intact. Quoted values are skipped by _find_unquoted.
    if colon != -1 and (dot == -1 or colon < dot):
        namespace_start, namespace_end = _trim(object_path, pos, colon)
        if namespace_start == namespace_end:
            raise InvalidObjectPathError("missing namespace before class", o_object_path, colon)

        namespace = _normalize_namespace(o_object_path, namespace_start, namespace_end)
        class_start = colon + 1
        class_start, class_end = _trim(o_object_path, class_start, end)
        if class_start == class_end:
            raise InvalidObjectPathError("missing class name after namespace", o_object_path, class_start)

        return _parse_class_path(o_object_path, class_start, end, hostname, namespace)

    if rooted:
        # Without a colon, a rooted path is normally a namespace path. When it contains class or key syntax and no
        # namespace separator it is instead a class or instance path (e.g. ``./Class.Name="x"``). A rooted path
        # containing both remains the ambiguous case documented above and is treated as a namespace path.
        if (dot != -1 or _find_unquoted(object_path, "=", pos, end) != -1) and not _has_namespace_separator(
            object_path, pos, end
        ):
            return _parse_class_path(object_path, pos, end, hostname, ns.name if ns is not None else None)

        return ObjectPath(hostname, _normalize_namespace(o_object_path, pos, end), "", {})

    if dot != -1 or _find_unquoted(object_path, "=", pos, end) != -1:
        # Class and instance paths can be parsed without a namespace; querying them will require one later.
        return _parse_class_path(o_object_path, pos, end, hostname, ns.name if ns is not None else None)

    value_start, value_end = _trim(o_object_path, pos, end)
    if value_end == value_start:
        raise InvalidObjectPathError("empty object path", o_object_path, value_start)

    if ns is None:
        if _has_namespace_separator(o_object_path, value_start, value_end):
            return ObjectPath(hostname, _normalize_namespace(o_object_path, value_start, value_end), "", {})

        # A bare name can be a class path; querying it requires a namespace, but parsing does not.
        return ObjectPath(hostname, None, _validate_identifier(o_object_path, value_start, value_end, "class"), {})

    return _resolve_relative(o_object_path, ns, value_start, value_end)


def parse_instance_keys(keys: str) -> dict[str, str]:
    """Parse a textual instance key list into a dictionary.

    This accepts the same syntax as the key part of an object path, for example::

        Name="Beep",SystemCreationClassName="Win32_ComputerSystem"

    Values are unquoted and unescaped. Use this when matching a full instance identity, not to parse a complete
    object path. Property names are validated and must be unique (case-insensitively).

    Args:
        keys: the textual key list, without a leading ``Class.``.

    Returns:
        A dictionary mapping property names to their (unquoted) values.

    Raises:
        InvalidObjectPathError: if the key list is malformed.
    """
    if not isinstance(keys, str):
        raise TypeError("keys should be a string")

    start, end = _trim(keys, 0, len(keys))
    if start == end:
        raise InvalidObjectPathError("empty instance key list", keys, start)

    return _parse_instance_keys(keys, start, end)


def _parse_class_path(object_path: str, start: int, end: int, hostname: str, namespace: str | None) -> ObjectPath:
    dot = _find_unquoted(object_path, ".", start, end)
    if dot == -1:
        equals = _find_unquoted(object_path, "=", start, end)
        if equals != -1:
            raise InvalidObjectPathError(
                "instance path must separate the class and keys with a '.'", object_path, equals
            )

        class_start, class_end = _trim(object_path, start, end)
        class_name = _validate_identifier(object_path, class_start, class_end, "class")
        return ObjectPath(hostname, namespace, class_name, {})

    class_start, class_end = _trim(object_path, start, dot)
    class_name = _validate_identifier(object_path, class_start, class_end, "class")

    keys_start, keys_end = _trim(object_path, dot + 1, end)
    if keys_start == keys_end:
        raise InvalidObjectPathError("missing instance key after class", object_path, keys_start)

    return ObjectPath(hostname, namespace, class_name, _parse_instance_keys(object_path, keys_start, keys_end))


def _parse_instance_keys(object_path: str, start: int, end: int) -> dict[str, str]:
    instance: dict[str, str] = {}
    pos = start

    while True:
        pos, _ = _trim(object_path, pos, end)
        if pos >= end:
            raise InvalidObjectPathError("empty instance key", object_path, pos)

        name_start = pos
        while pos < end and object_path[pos] not in "=," and not object_path[pos].isspace():
            if object_path[pos] in _QUOTE_CHARS:
                raise InvalidObjectPathError("unexpected quote in property name", object_path, pos)
            pos += 1

        name_end = pos
        pos, _ = _trim(object_path, pos, end)
        name = _validate_identifier(object_path, name_start, name_end, "property")

        folded = name.casefold()
        if any(existing.casefold() == folded for existing in instance):
            raise InvalidObjectPathError(f"duplicate property {name!r}", object_path, name_start)

        if pos >= end or object_path[pos] != "=":
            raise InvalidObjectPathError("missing '=' after property name", object_path, pos)

        pos += 1
        pos, _ = _trim(object_path, pos, end)
        if pos >= end:
            raise InvalidObjectPathError(f"missing value for property {name!r}", object_path, end)

        if object_path[pos] in _QUOTE_CHARS:
            value, pos = _scan_quoted(object_path, pos)
            pos, _ = _trim(object_path, pos, end)

            if pos < end and object_path[pos] != ",":
                raise InvalidObjectPathError("unexpected character after quoted value", object_path, pos)
        else:
            value_start = pos
            while pos < end and object_path[pos] != ",":
                if object_path[pos] in _QUOTE_CHARS:
                    raise InvalidObjectPathError("unexpected quote in unquoted value", object_path, pos)
                pos += 1

            value_end = pos
            value_start, value_end = _trim(object_path, value_start, value_end)
            if value_start == value_end:
                raise InvalidObjectPathError(f"missing value for property {name!r}", object_path, value_start)
            value = object_path[value_start:value_end]

        instance[name] = value

        if pos >= end:
            return instance

        # At this point the character must be the separator.
        pos += 1
        if _trim(object_path, pos, end)[0] >= end:
            raise InvalidObjectPathError("empty instance key", object_path, pos)


def _resolve_relative(object_path: str, ns: Namespace, start: int, end: int) -> ObjectPath:
    name = object_path[start:end]

    _reject_quotes(object_path, start, end, "unexpected quote in name")

    if _has_namespace_separator(object_path, start, end):
        normalized = _normalize_namespace(object_path, start, end)
        if normalized.split("\\", 1)[0].lower() == _root_namespace_name(ns):
            # A path such as ``root/cimv2`` is absolute; keep it as-is instead of nesting it under the current
            # namespace.
            return ObjectPath("localhost", normalized, "", {})

        try:
            target = ns.namespace(normalized)
        except IndexError:
            raise InvalidObjectPathError(f"unknown namespace {normalized!r}", object_path, start) from None
        return ObjectPath("localhost", target.name, "", {})

    try:
        target = ns.namespace(name)
    except IndexError:
        pass
    else:
        return ObjectPath("localhost", target.name, "", {})

    try:
        ns.class_(name)
    except (IndexError, ReferenceNotFoundError):
        raise InvalidObjectPathError(f"unknown namespace or class {name!r}", object_path, start) from None
    return ObjectPath("localhost", ns.name, name, {})


def _scan_quoted(object_path: str, start: int) -> tuple[str, int]:
    """Scan a quoted value and return its unescaped contents and the position after the closing quote.

    A delimiter is escaped either by doubling it (``''`` or ``""``, the WMI convention) or by a backslash when the
    value continues after it. Backslashes are otherwise literal, so values such as ``C:\\Windows\\System32``,
    UNC paths ``\\\\server\\share`` and values ending in a backslash are preserved exactly.
    """
    quote = object_path[start]
    parts = []
    i = start + 1

    while i < len(object_path):
        char = object_path[i]

        if char == "\\":
            run_start = i
            while i < len(object_path) and object_path[i] == "\\":
                i += 1

            count = i - run_start
            if i < len(object_path) and object_path[i] == quote:
                if count % 2 == 1 and _has_unescaped_quote(object_path, i + 1, quote):
                    # The backslash escapes this delimiter; the quoted value continues after it. Pairs of
                    # backslashes before the escaping one remain literal.
                    parts.append("\\" * (count // 2))
                    parts.append(quote)
                    i += 1
                    continue

                # Otherwise every backslash is literal, including one immediately before the closing delimiter.
                parts.append("\\" * count)
                return "".join(parts), i + 1

            parts.append("\\" * count)
            continue

        if char == quote:
            if i + 1 < len(object_path) and object_path[i + 1] == quote:
                # Doubled delimiter, e.g. 'O''Brien' or "a""b".
                parts.append(quote)
                i += 2
                continue

            return "".join(parts), i + 1

        parts.append(char)
        i += 1

    raise InvalidObjectPathError("unterminated quoted string", object_path, start)


def _has_unescaped_quote(object_path: str, start: int, quote: str) -> bool:
    i = start
    while i < len(object_path):
        if object_path[i] == "\\":
            i += 2
            continue

        if object_path[i] == quote:
            if i + 1 < len(object_path) and object_path[i + 1] == quote:
                i += 2
                continue
            return True
        i += 1
    return False


def _find_unquoted(object_path: str, targets: str, start: int = 0, end: int | None = None) -> int:
    """Find the first character in ``targets`` outside of quoted values."""
    if end is None:
        end = len(object_path)

    i = start
    while i < end:
        char = object_path[i]

        if char in _QUOTE_CHARS:
            try:
                _, i = _scan_quoted(object_path, i)
            except InvalidObjectPathError:
                # The quoted value is broken, so no structural delimiter after it can be trusted. Leave the precise
                # syntax error to the class and key parser.
                return -1
            continue

        if char in targets:
            return i
        i += 1

    return -1


def _normalize_namespace(object_path: str, start: int, end: int) -> str:
    value_start, value_end = _trim(object_path, start, end)

    _reject_quotes(object_path, value_start, value_end, "unexpected quote in namespace path")

    parts = [part.strip() for part in re.split(r"[/\\]+", object_path[value_start:value_end]) if part.strip()]
    if not parts:
        raise InvalidObjectPathError("empty namespace path", object_path, value_start)

    return "\\".join(parts)


def _reject_quotes(object_path: str, start: int, end: int, reason: str) -> None:
    for i in range(start, end):
        if object_path[i] in _QUOTE_CHARS:
            raise InvalidObjectPathError(reason, object_path, i)


def _has_namespace_separator(object_path: str, start: int, end: int) -> bool:
    return _find_unquoted(object_path, _NAMESPACE_SEPARATORS, start, end) != -1


def _validate_identifier(object_path: str, start: int, end: int, kind: str) -> str:
    value = object_path[start:end]
    if not value:
        raise InvalidObjectPathError(f"missing {kind} name", object_path, start)

    if _IDENTIFIER_RE.match(value):
        return value

    for index, char in enumerate(value):
        if char.isdigit() and index == 0:
            raise InvalidObjectPathError(f"invalid character in {kind} name", object_path, start + index)
        if not (char.isascii() and (char.isalnum() or char == "_")):
            raise InvalidObjectPathError(f"invalid character in {kind} name", object_path, start + index)

    raise InvalidObjectPathError(f"invalid {kind} name", object_path, start)


def _normalize_host(host: str) -> str:
    if host == "." or host.lower() == "localhost":
        return "localhost"
    return host


def _root_namespace_name(ns: Namespace) -> str:
    name = ns.name.split("\\", 1)[0]
    return name.lower()


def _trim(value: str, start: int, end: int) -> tuple[int, int]:
    while start < end and value[start].isspace():
        start += 1
    while end > start and value[end - 1].isspace():
        end -= 1
    return start, end
