from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.cim.c_cim import c_cim
from dissect.cim.exceptions import (
    Error,
    InvalidInstancePathError,
    ObjectPathSyntaxError,
)

if TYPE_CHECKING:
    from dissect.cim.cim import Namespace


class ObjectPath(NamedTuple):
    hostname: str
    namespace: str
    class_: str
    instance: dict[str, str]


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


def _find_unquoted(text: str, chars: str, path: str, start: int = 0) -> int:
    """Return the index of the first unquoted character in ``chars``, or -1."""
    quote = None
    escaped = False

    for i, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in chars:
            return i

    if quote is not None:
        raise ObjectPathSyntaxError(f"Unterminated {quote} quote", path, start + len(text))

    return -1


def _split_unquoted(text: str, separators: str, path: str, start: int = 0) -> tuple[list[str], list[int]]:
    """Split ``text`` on unquoted characters from ``separators``."""
    parts = []
    positions = [start]
    quote = None
    escaped = False
    piece_start = 0

    for i, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in separators:
            parts.append(text[piece_start:i])
            positions.append(start + i + 1)
            piece_start = i + 1

    if quote is not None:
        raise ObjectPathSyntaxError(f"Unterminated {quote} quote", path, start + len(text))

    parts.append(text[piece_start:])
    return parts, positions


def parse_instance_keys(text: str, path: str, start: int) -> dict[str, str]:
    """Parse ``Key=Value`` pairs, honouring quoting and escapes."""
    if not text.strip():
        raise InvalidInstancePathError("Empty instance key list", path, start)

    keys: dict[str, str] = {}
    parts, positions = _split_unquoted(text, ",;", path, start)

    for index, part in enumerate(parts):
        offset = positions[index]
        entry = part.strip()
        offset += len(part) - len(part.lstrip())

        if not entry:
            raise InvalidInstancePathError("Empty key entry", path, positions[index])

        name, sep, value = entry.partition("=")
        if not sep:
            raise InvalidInstancePathError(f"Key {name!r} has no value", path, offset)

        name = name.strip()
        if not name:
            raise InvalidInstancePathError("Empty key name", path, offset)
        if any(char in name for char in "\"' \t\r\n"):
            raise InvalidInstancePathError(f"Invalid key name {name!r}", path, offset)
        if name in keys:
            raise InvalidInstancePathError(f"Duplicate key {name!r}", path, offset)

        value = value.strip()
        value_start = offset + entry.find("=") + 1
        if not value:
            raise InvalidInstancePathError(f"Key {name!r} has an empty value", path, value_start)

        if value[0] in "\"'":
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise InvalidInstancePathError(
                    f"Unterminated {quote} quote in key {name!r}", path, value_start + len(value)
                )
            value = _unescape_quoted(value[1:-1], quote, path, value_start + 1)
        elif value.count('"') % 2 or value.count("'") % 2:
            raise InvalidInstancePathError(f"Unbalanced quote in value for key {name!r}", path, value_start)

        keys[name] = value

    if not keys:
        raise InvalidInstancePathError("Empty instance key list", path, start)

    return keys


def _unescape_quoted(value: str, quote: str, path: str, start: int) -> str:
    """Resolve backslash escapes inside a quoted key value.

    Only the enclosing quote character is special inside the value; the other
    quote flavour is ordinary data. A backslash always escapes the next char.
    """
    result = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 >= len(value):
                raise InvalidInstancePathError("Trailing backslash escape in quoted value", path, start + i)
            result.append(value[i + 1])
            i += 2
            continue
        if char == quote:
            raise InvalidInstancePathError(
                f"Unescaped {char} quote inside quoted value; use \\{char} to include it literally", path, start + i
            )
        result.append(char)
        i += 1
    return "".join(result)


def _parse_rooted(text: str, path: str) -> tuple[str, str]:
    """Split a rooted path into its host and remaining path."""
    if text.startswith("//"):
        rest = text[2:]
        separator = rest.find("/")
    else:
        rest = text[2:]
        separator = rest.find("\\")

    if separator == -1:
        raise ObjectPathSyntaxError("Rooted object path has no namespace", path, 0)

    hostname = rest[:separator] or "."
    return ("localhost" if hostname == "." else hostname), rest[separator + 1 :]


def parse_hostname(object_path: str) -> str | None:
    """Return the hostname of a rooted object path, without parsing its keys.

    Returns ``None`` for relative paths. This intentionally inspects only the
    syntactic prefix so a remote host can be rejected with an explicit
    ``UnsupportedHostError`` even if the rest of the path is malformed.
    """
    if not isinstance(object_path, str):
        return None

    text = object_path.strip().removeprefix("winmgmts:").strip()
    if text.startswith("//"):
        return text[2:].split("/", 1)[0] or "."
    if text.startswith("\\\\"):
        return text[2:].split("\\", 1)[0] or "."

    return None


def parse_object_path(object_path: str, ns: Namespace | None = None) -> ObjectPath:
    """Given a textual query string, parse it into an object path that we can query.

    Supported schemas::

        cimv2 --> namespace
        //./root/cimv2 --> namespace
        //HOSTNAME/root/cimv2 --> namespace
        \\\\.\\root\\cimv2 --> namespace
        winmgmts://./root/cimv2 --> namespace
        Win32_Service --> class
        //./root/cimv2:Win32_Service --> class
        Win32_Service.Name='Beep' --> instance
        //./root/cimv2:Win32_Service.Name="Beep" --> instance

    Instance keys are comma separated ``Name=Value`` pairs. Values may be quoted
    with either single or double quotes, in which case commas, equals signs,
    colons, semicolons and backslashes are literal data instead of path syntax.
    Inside a quoted value a backslash escapes the next character. Namespace
    separators are only recognised outside quotes, so backslashes in key values
    are preserved exactly.

    Relative paths are resolved against ``ns``. Rooted paths (``//.`` or
    ``\\\\.\\``) always describe a local path. A remote hostname is parsed into
    an :class:`ObjectPath` but querying it raises :class:`UnsupportedHostError`;
    this module never performs a network request.

    Args:
        object_path: the textual query string.
        ns: namespace to resolve relative paths against.

    Returns:
        A path we can use to query.

    Raises:
        ObjectPathSyntaxError: if the path is malformed.
    """
    if not isinstance(object_path, str):
        raise TypeError("object_path must be a string")

    path = object_path
    text = object_path.strip()
    if not text:
        raise ObjectPathSyntaxError("Empty object path", path, 0)

    text = text.removeprefix("winmgmts:")
    text = text.strip()
    if not text:
        raise ObjectPathSyntaxError("Empty object path", path, 0)

    hostname = "localhost"
    namespace = ns.name if ns else None
    is_rooted = text.startswith(("//", "\\\\"))

    if is_rooted:
        hostname, text = _parse_rooted(text, path)

    # Split the optional namespace from the class/instance part. Only an
    # unquoted colon before the first dot is a namespace separator; a colon in
    # an unquoted key value (for example a drive letter) is data.
    colon = _find_unquoted(text, ":", path)
    dot = _find_unquoted(text, ".", path)
    separator = colon if colon != -1 and (dot == -1 or colon < dot) else -1

    if separator != -1:
        explicit_namespace = text[:separator].strip()
        if not explicit_namespace:
            raise ObjectPathSyntaxError("Empty namespace", path, 0)
        if any(char in explicit_namespace for char in "\"'"):
            raise ObjectPathSyntaxError(f"Invalid namespace {explicit_namespace!r}", path, 0)
        namespace = explicit_namespace
        text = text[separator + 1 :]
        if not text.strip():
            raise ObjectPathSyntaxError("Class or instance part is empty", path, separator + 1)

    # Rooted paths without a class are namespace paths: ``//./root/cimv2``.
    if separator == -1 and is_rooted and dot == -1:
        if any(char in text for char in "\"'"):
            raise ObjectPathSyntaxError(f"Invalid namespace {text!r}", path, 0)
        return ObjectPath(hostname, text.replace("/", "\\"), "", {})

    # The remaining text is ``Class`` or ``Class.Key=Value,...``. A dot only
    # separates the class from keys when it is unquoted.
    dot = _find_unquoted(text, ".", path, separator + 1 if separator != -1 else 0)

    # An absolute local namespace path such as ``root\cimv2``. A class name can
    # never contain an unquoted backslash, so this is unambiguous.
    if separator == -1 and dot == -1 and "\\" in text:
        return ObjectPath(hostname, text.replace("/", "\\"), "", {})

    class_name = (text[:dot] if dot != -1 else text).strip()
    class_start = separator + 1 if separator != -1 else 0
    if not class_name:
        raise ObjectPathSyntaxError("Empty class name", path, class_start)
    if any(char in class_name for char in "=,'\"/\\ "):
        raise ObjectPathSyntaxError(f"Invalid class name {class_name!r}", path, class_start)

    instance = {}
    if dot != -1:
        if not namespace:
            raise ObjectPathSyntaxError("Instance path has no namespace", path, 0)
        instance = parse_instance_keys(text[dot + 1 :], path, dot + 1)
    elif separator == -1:
        # A path without a class is normally a namespace. Absolute local paths
        # use backslashes; relative ones are resolved against ``ns``.
        relative = text.replace("/", "\\")
        if ns is None:
            if "\\" in relative:
                return ObjectPath(hostname, relative, "", {})
            raise Error("Relative query but no namespace")

        try:
            ns.namespace(relative)
        except IndexError:
            # Not a child namespace, so it must be a class in ``ns``.
            namespace = ns.name
        else:
            return ObjectPath(hostname, ns.name + "\\" + relative, "", {})

    if namespace is None:
        raise ObjectPathSyntaxError("No namespace in object path", path, 0)

    return ObjectPath(hostname, namespace.replace("/", "\\"), class_name, instance)
