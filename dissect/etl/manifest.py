from __future__ import annotations

import importlib
import importlib.resources
import io
import types
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from string import Formatter
from typing import TYPE_CHECKING, BinaryIO

from defusedxml import ElementTree

from dissect import cstruct
from dissect.etl.exceptions import InvalidPayloadError, InvalidTemplateError, ManifestNotFoundError

if TYPE_CHECKING:
    from uuid import UUID

MODPATH = "dissect.etl.manifests"

STRUCT_FMT = """
struct {name} {{
{fields}
}};
"""

CLASS_FMT = """
from uuid import UUID
from collections import namedtuple

from dissect import cstruct
from dissect.cstruct import BaseType, MetaType, Structure
from dissect.etl.manifest import FieldDeclaration, validate_payload

Structure._calc_offsets = lambda _: None
Keyword = namedtuple('Keyword', ['name', 'message', 'mask'])
Task = namedtuple('Task', ['name', 'message', 'value'])
Event = namedtuple('Event', ['symbol', 'value', 'version', 'opcode', 'level', 'task', 'keywords', 'template'])


class VariableType(BaseType):
    type: MetaType
    size: int

    @classmethod
    def as_64bit(cls):
        raise NotImplementedError()

    @classmethod
    def as_32bit(cls):
        raise NotImplementedError()

    @classmethod
    def _read(cls, stream, context=None):
        return cls.type._read(stream, context)

    @classmethod
    def _read_0(cls, stream, context=None):
        return cls.type._read_0(stream, context)

    @classmethod
    def _write(cls, stream, data):
        return cls.type._write(stream, data)


class EtwPointer(VariableType):
    @classmethod
    def as_64bit(cls):
        if cls.size == 8:
            return
        cls.size = 8
        cls.type = cls.cs.uint64

    @classmethod
    def as_32bit(cls):
        if cls.size == 4:
            return
        cls.size = 4
        cls.type = cls.cs.uint32


class UserSID_blob(VariableType):
    @classmethod
    def as_64bit(cls):
        if cls.size == 16:
            return
        cls.size = 16
        cls.type = cls.cs.char[16]

    @classmethod
    def as_32bit(cls):
        if cls.size == 8:
            return
        cls.size = 8
        cls.type = cls.cs.char[8]


PROVIDER_NAME = {provider_name!r}
PROVIDER_GUID = UUID({provider_guid!r})
PROVIDER_SYMBOL = {provider_symbol!r}

c_parser = cstruct.cstruct()
c_parser.add_custom_type("EtwPointer", EtwPointer)
c_parser.add_custom_type("UserSID_blob", UserSID_blob)
c_parser.load(\"\"\"
struct SYSTEMTIME {{
    WORD    wYear;
    WORD    wMonth;
    WORD    wDayOfWeek;
    WORD    wDay;
    WORD    wHour;
    WORD    wMinute;
    WORD    wSecond;
    WORD    wMilliseconds;
}};

struct UserSID {{
    uint8 revision;
    uint8 subAuthorityCount;
    char authority[6];
    uint32 subAuthorities[subAuthorityCount];
}};

struct SID {{
    UserSID_blob    blob;
    UserSID         sid;
}};

{templates}
\"\"\")

STRINGS = {{
{strings}
}}

KEYWORDS = {{
{keywords}
}}

EVENTS = {{
{events}
}}

TEMPLATE_FIELDS = {{
{template_fields}
}}
"""

FIELD_MAP = {
    "AnsiString": "char {name}[]",
    "Binary": "char {name}[]",
    "Boolean": "uint8 {name}",
    "FILETIME": "uint64 {name}",
    "GUID": "char {name}[16]",
    "HexInt32": "uint32 {name}",
    "HexInt64": "uint64 {name}",
    "IPAddrV4": "uint32 {name}",
    "IPAddrV6": "char {name}[16]",
    "Pointer": "EtwPointer {name}",
    "SInt8": "int8 {name}",
    "SInt16": "int16 {name}",
    "SInt32": "int32 {name}",
    "SInt64": "int64 {name}",
    "SizeT": "uint32 {name}",
    "Struct": "KAPUT",
    "String": "char {name}[]",
    "SYSTEMTIME": "SYSTEMTIME {name}",
    "SID": "SID {name}",
    "WString": "wchar {name}[]",
    "UnicodeString": "wchar {name}[]",
}

# Base cstruct type (without any array suffix) for the variable length inTypes.  Without a count, length or max
# attribute these decode as null terminated strings; with a declaration they become bounded arrays.
BASE_TYPE_MAP = {
    "AnsiString": "char",
    "Binary": "char",
    "String": "char",
    "WString": "wchar",
    "UnicodeString": "wchar",
}

CACHE: dict[UUID, types.ModuleType] = {}

c_parser = cstruct.cstruct()

# Sizes in bytes of the scalar inTypes that can carry a count or length declaration.  ``None`` marks the
# pointer-sized types, whose size depends on the pointer size of the trace that produced the event.
SCALAR_SIZES: dict[str, int | None] = {
    "AnsiString": 1,
    "Binary": 1,
    "Boolean": 1,
    "FILETIME": 8,
    "GUID": 16,
    "HexInt32": 4,
    "HexInt64": 8,
    "IPAddrV4": 4,
    "IPAddrV6": 16,
    "Pointer": None,
    "SInt8": 1,
    "SInt16": 2,
    "SInt32": 4,
    "SInt64": 8,
    "SizeT": 4,
    "String": 1,
    "UInt8": 1,
    "UInt16": 2,
    "UInt32": 4,
    "UInt64": 8,
    "Int8": 1,
    "Int16": 2,
    "Int32": 4,
    "Int64": 8,
    "Float": 4,
    "Double": 8,
    "WChar": 2,
    "WString": 2,
    "UnicodeString": 2,
}

# inTypes that decode as a UTF-16 (wchar) string.  Their ``length`` is expressed in bytes and needs dividing by
# the character width, while ``count`` is already a number of characters.
WCHAR_TYPES = frozenset({"UnicodeString", "WString"})


@dataclass(frozen=True)
class FieldDeclaration:
    """Description of a single template field needed to validate count and length declarations.

    Args:
        name: The field name.
        in_type: The manifest ``inType`` of the field, without the ``win:`` prefix.
        element_size: Size in bytes of one element, or ``None`` for pointer-sized elements.
        is_wchar: Whether the field decodes as a UTF-16 (wchar) value.
        count_ref: Name of the preceding integer field holding the element count, if any.
        fixed_count: Literal element count from the ``max`` attribute, if any.
        length_ref: Name of the preceding integer field holding the byte length, if any.
        fixed_length: Literal byte length from the ``length`` attribute, if any.
    """

    name: str
    in_type: str
    element_size: int | None
    is_wchar: bool
    count_ref: str | None = None
    fixed_count: int | None = None
    length_ref: str | None = None
    fixed_length: int | None = None

    @property
    def is_declared(self) -> bool:
        """Whether the field carries any count or length declaration."""
        return any((self.count_ref, self.fixed_count is not None, self.length_ref, self.fixed_length is not None))

    def declared_bytes(self, values: dict[str, int], pointer_size: int) -> int:
        """Resolve the number of bytes this declaration consumes inside an event.

        Args:
            values: The field values decoded before this field.
            pointer_size: Pointer size in bytes of the trace being decoded.

        Returns:
            The number of bytes consumed by the declared field.
        """
        element_size = pointer_size if self.element_size is None else self.element_size

        if self.count_ref is not None:
            return values[self.count_ref] * element_size

        if self.fixed_count is not None:
            return self.fixed_count * element_size

        if self.length_ref is not None:
            return values[self.length_ref]

        return self.fixed_length or 0


def _scalar_element_size(in_type: str) -> int | None:
    if in_type.lower() in c_parser.typedefs:
        resolved = c_parser.resolve(in_type.lower())
        return None if resolved.dynamic else resolved.size
    return SCALAR_SIZES.get(in_type)


def _build_field(
    template_name: str,
    field: ElementTree,
    field_names: set[str],
) -> tuple[str, FieldDeclaration | None]:
    """Translate a manifest ``data`` element into a cstruct field line and a declaration descriptor.

    The ``count`` attribute expresses a number of elements (characters for string types), while the ``length``
    attribute always expresses a number of bytes.  The ``max`` attribute is a fixed element count.

    Raises:
        InvalidTemplateError: If the count or length declaration references an unknown or later field.
    """
    fattr = field.attrib
    fname = fattr["name"]
    ftype = fattr["inType"].split(":")[1]

    has_declaration = any(attr in fattr for attr in ("count", "length", "max"))
    if has_declaration and ftype in BASE_TYPE_MAP:
        # Strip the null terminated suffix so the declaration can provide a bounded array instead.
        line = f"{BASE_TYPE_MAP[ftype]} {{name}}"
    elif ftype.lower() in c_parser.typedefs:
        line = f"{ftype.lower()} {{name}}"
    else:
        line = FIELD_MAP[ftype]

    is_wchar = ftype in WCHAR_TYPES
    declaration = FieldDeclaration(
        name=fname,
        in_type=ftype,
        element_size=_scalar_element_size(ftype),
        is_wchar=is_wchar,
    )

    count_ref = fattr.get("count")
    length_ref = fattr.get("length")
    fixed_max = fattr.get("max")

    if count_ref is not None:
        if count_ref.isdigit():
            line = f"{line}[{int(count_ref)}]"
            declaration = replace(declaration, fixed_count=int(count_ref))
        else:
            _require_preceding(template_name, fname, "count", count_ref, field_names)
            # count always expresses a number of elements, which is exactly what a cstruct subscript expects
            line = f"{line}[{count_ref}]"
            declaration = replace(declaration, count_ref=count_ref)
    elif length_ref is not None:
        if length_ref.isdigit():
            byte_length = int(length_ref)
            if is_wchar and byte_length % 2:
                raise InvalidTemplateError(
                    f"Template {template_name!r} field {fname!r}: wchar byte length {byte_length} does not cover a "
                    "whole number of UTF-16 characters"
                )
            expression = str(byte_length // 2) if is_wchar else str(byte_length)
            line = f"{line}[{expression}]"
            declaration = replace(declaration, fixed_length=byte_length)
        else:
            _require_preceding(template_name, fname, "length", length_ref, field_names)
            # length is expressed in bytes; wchar arrays count elements, so divide by the character width
            expression = f"{length_ref} / 2" if is_wchar else length_ref
            line = f"{line}[{expression}]"
            declaration = replace(declaration, length_ref=length_ref)
    elif fixed_max is not None:
        line = f"{line}[{fixed_max}]"
        declaration = replace(declaration, fixed_count=int(fixed_max))

    return line.format(name=fname), declaration if declaration.is_declared else None


def _require_preceding(
    template_name: str,
    field_name: str,
    attribute: str,
    reference: str,
    field_names: set[str],
) -> None:
    """Ensure a count or length reference points at an earlier field in the same template.

    Because a field can only reference fields that appear before it, a reference chain can never point back at
    itself, which rules out both forward references and cyclic dependencies in a single check.
    """
    if reference not in field_names:
        raise InvalidTemplateError(
            f"Template {template_name!r} field {field_name!r}: {attribute} references {reference!r}, which is not "
            "a preceding field; forward references and cyclic dependencies are not allowed"
        )


def validate_payload(
    struct_type: type,
    declarations: list[FieldDeclaration],
    payload: bytes | memoryview,
    pointer_size: int,
    event_label: str,
) -> None:
    """Validate that a payload can satisfy every count/length declaration before decoding.

    The walk mirrors cstruct's sequential field order. Statically sized scalar fields are read from the payload so
    their values become available as count/length references, while declared fields resolve their size from those
    preceding values and merely advance the offset. A declaration that would read past the end of the payload is
    rejected with the offending field and event, instead of surfacing as a low level EOF later on.

    Args:
        struct_type: The generated cstruct structure type of the template.
        declarations: The count/length descriptors of the declared fields, in template order.
        payload: The raw event payload.
        pointer_size: Pointer size in bytes of the trace being decoded.
        event_label: Human readable identifier of the event, used in error messages.

    Raises:
        InvalidPayloadError: If a declaration consumes more bytes than the payload holds.
    """
    stream = io.BytesIO(payload)
    declared = {declaration.name: declaration for declaration in declarations}
    values: dict[str, int] = {}
    payload_size = len(payload)

    for field in struct_type.__fields__:
        name = field._name
        declaration = declared.get(name)
        offset = stream.tell()

        if declaration is not None:
            size = declaration.declared_bytes(values, pointer_size)
            if size < 0:
                raise InvalidPayloadError(
                    f"{event_label}: field {name!r} has a negative count/length declaration ({size} bytes)"
                )
            if declaration.is_wchar and size % 2:
                raise InvalidPayloadError(
                    f"{event_label}: field {name!r} declares {size} bytes, which is not a whole number of "
                    "UTF-16 characters"
                )
            if offset + size > payload_size:
                raise InvalidPayloadError(
                    f"{event_label}: field {name!r} declares {size} bytes but only {payload_size - offset} bytes "
                    "remain in the payload"
                )
            stream.seek(size, io.SEEK_CUR)
            continue

        field_type = field.type
        if field_type.dynamic:
            # Undeclared variable length field (e.g. a null terminated string); no upfront bound to check.
            return

        size = pointer_size if field_type.size is None else field_type.size
        if offset + size > payload_size:
            raise InvalidPayloadError(
                f"{event_label}: field {name!r} needs {size} bytes but only {payload_size - offset} bytes remain "
                "in the payload"
            )
        values[name] = int(field_type._read(stream, values))


def lookup(guid: UUID) -> types.ModuleType:
    global CACHE

    try:
        return CACHE[guid]
    except KeyError:
        pass

    try:
        mod = importlib.import_module(f"{MODPATH}.{{{guid}}}")
    except ImportError:
        pass
    else:
        CACHE[guid] = mod
        return mod

    try:
        mod = compile_xml(guid, get_resource_string(f"manifests/xml/{{{guid}}}.xml"))
    except IOError:
        pass
    else:
        CACHE[guid] = mod
        return mod

    raise ManifestNotFoundError(guid)


def compile_file(guid: UUID, path: str) -> types.ModuleType:
    return compile_xml(guid, Path(path).read_text())


def compile_xml(guid: UUID, s: str) -> types.ModuleType:
    generated = generate_from_xml(s)
    # print generated
    code = compile(generated, f"<manifest {guid}>", "exec")
    module = types.ModuleType(str(guid))
    exec(code, module.__dict__)
    return module


def generate_from_file(path: str) -> str:
    return generate_from_xml(Path(path).read_text())


def generate_from_xml(s: str) -> str:
    e = ElementTree.fromstring(s)
    formatter = Formatter()

    strings = [
        "    '{id}': '{value}',".format(**string.attrib)
        for string in e.iter("{http://schemas.microsoft.com/win/2004/08/events}string")
    ]

    keywords = []
    for keyword in e.iter("{http://schemas.microsoft.com/win/2004/08/events}keyword"):
        attr = keyword.attrib
        attr["message"] = attr["message"].split(".")[1][:-1]
        keywords.append("    '{name}': Keyword('{name}', STRINGS['{message}'], {mask}),".format(**attr))

    templates = []
    template_registry = []
    for template in e.iter("{http://schemas.microsoft.com/win/2004/08/events}template"):
        sname = template.attrib["tid"]

        if sname.startswith("0x"):
            sname = sname.replace("0x", "NULLx")

        fields = []
        declarations: list[FieldDeclaration] = []
        field_names: set[str] = set()
        for field in template:
            line, declaration = _build_field(sname, field, field_names)
            fields.append(line)
            field_names.add(field.attrib["name"])
            if declaration is not None:
                declarations.append(declaration)

        templates.append(
            STRUCT_FMT.format(
                name=sname,
                fields="\n".join([f"    {field};" for field in fields]),
            )
        )
        if declarations:
            template_registry.append(f"    {sname!r}: (")
            template_registry.extend(f"        {declaration!r}," for declaration in declarations)
            template_registry.append("    ),")

    events = []
    for event in e.iter("{http://schemas.microsoft.com/win/2004/08/events}event"):
        attr = defaultdict(lambda: None)
        attr.update(event.attrib)

        if not attr["template"]:
            continue

        if attr["template"].startswith("0x"):
            attr["template"] = attr["template"].replace("0x", "NULLx")

        events.append(
            formatter.vformat(
                "    ({value}, {version}): Event('{symbol}', {value}, {version}, {opcode!r}, "
                "{level!r}, {task!r}, {keyword!r}, c_parser.{template}),",
                (),
                attr,
            )
        )

    provider = next(e.iter("{http://schemas.microsoft.com/win/2004/08/events}provider"))

    return CLASS_FMT.format(
        provider_name=provider.attrib["name"],
        provider_guid=provider.attrib["guid"],
        provider_symbol=provider.attrib.get("symbol"),
        templates="\n".join(templates),
        template_fields="\n".join(template_registry),
        strings="\n".join(strings),
        keywords="\n".join(keywords),
        events="\n".join(events),
    )


def get_resource_string(path: str) -> str:
    return _get_resource_path(path).read_text()


def get_resource_stream(path: str) -> BinaryIO:
    return _get_resource_path(path).open("rb")


def _get_resource_path(path: str) -> Path:
    root = importlib.resources.files(__package__) if __package__ else Path(__file__).parent
    fpath = root.joinpath(path)

    if not fpath.exists():
        raise IOError(f"Can't find resource {path}")

    return fpath
