from __future__ import annotations

import importlib
import importlib.resources
import types
from collections import defaultdict
from pathlib import Path
from string import Formatter
from typing import TYPE_CHECKING, BinaryIO

from defusedxml import ElementTree

from dissect import cstruct
from dissect.etl.exceptions import ManifestNotFoundError

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
from dissect.cstruct import BaseType, MetaType
from dissect.cstruct import Structure as _HostStructure


class ManifestStructure(_HostStructure):
    \"\"\"Structure base class local to this manifest module.

    ETW templates intentionally contain variable length fields. Older dissect.cstruct releases
    exposed an overridable ``_calc_offsets`` hook that this project used to disable offset
    calculation for those templates. That hook no longer exists, and patching the imported
    ``Structure`` class mutated global state for every other cstruct parser in the process.

    Instead we derive a private base class and only shadow the hook here. Manifest structures
    never escape this module, so the host ``dissect.cstruct`` package is left untouched.
    \"\"\"

    @staticmethod
    def _calc_offsets(*args, **kwargs):
        return None


class ManifestParser(cstruct.cstruct):
    \"\"\"cstruct parser that keeps all structures bound to :class:`ManifestStructure`.\"\"\"

    def _make_struct(self, name, fields, *, align=False, anonymous=False, base=None):
        # ``base`` is only passed by cstruct internals for unions, which must keep using
        # their own base class. Everything else is rooted at ManifestStructure.
        return super()._make_struct(name, fields, align=align, anonymous=anonymous, base=base or ManifestStructure)

    def refresh_offsets(self):
        \"\"\"Recompute offsets of every manifest structure after a pointer width change.\"\"\"
        for type_ in list(self.typedefs.values()):
            if not isinstance(type_, type) or not issubclass(type_, _HostStructure):
                continue

            # ``commit`` treats existing offsets as leading, so clear them first.
            for field in type_.__fields__:
                field.offset = None
            type_.commit()


Keyword = namedtuple('Keyword', ['name', 'message', 'mask'])
Task = namedtuple('Task', ['name', 'message', 'value'])
Event = namedtuple('Event', ['symbol', 'value', 'version', 'opcode', 'level', 'task', 'keywords', 'template'])


class VariableType(BaseType):
    type: MetaType
    size: int

    @classmethod
    def _set_width(cls, size, type_):
        if cls.size == size:
            return
        cls.size = size
        cls.type = type_
        cls._refresh_offsets()

    @classmethod
    def _refresh_offsets(cls):
        # ``cls.cs`` is only present on the parser-bound copy of this class, not on the
        # plain class defined below. When it is, ask the parser to recompute structure
        # offsets because a field width just changed.
        parser = getattr(cls, "cs", None)
        refresh = getattr(parser, "refresh_offsets", None)
        if refresh is not None:
            refresh()

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
        cls._set_width(8, cls.cs.uint64)

    @classmethod
    def as_32bit(cls):
        cls._set_width(4, cls.cs.uint32)


class UserSID_blob(VariableType):
    @classmethod
    def as_64bit(cls):
        cls._set_width(16, cls.cs.char[16])

    @classmethod
    def as_32bit(cls):
        cls._set_width(8, cls.cs.char[8])


PROVIDER_NAME = {provider_name!r}
PROVIDER_GUID = UUID({provider_guid!r})
PROVIDER_SYMBOL = {provider_symbol!r}

c_parser = ManifestParser()
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
"""

FIELD_MAP = {
    "Boolean": "uint8 {name}",
    "GUID": "char {name}[16]",
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

CACHE: dict[UUID, types.ModuleType] = {}

c_parser = cstruct.cstruct()


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
    for template in e.iter("{http://schemas.microsoft.com/win/2004/08/events}template"):
        sname = template.attrib["tid"]

        if sname.startswith("0x"):
            sname = sname.replace("0x", "NULLx")

        fields = []
        for field in template:
            fattr = field.attrib
            fname = fattr["name"]
            ftype = fattr["inType"].split(":")[1]

            if ftype.lower() in c_parser.typedefs:
                ctype = ftype.lower()
                line = f"{ctype} {{name}}"
            else:
                line = FIELD_MAP[ftype]

            if "max" in fattr:
                line = "{}[{}]".format(line, fattr["max"])

            fields.append(line.format(name=fname))

        templates.append(
            STRUCT_FMT.format(
                name=sname,
                fields="\n".join([f"    {field};" for field in fields]),
            )
        )

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
