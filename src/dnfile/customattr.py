# -*- coding: utf-8 -*-
"""
Static interpretation of .NET CustomAttribute payloads.

This module reads metadata that ``dnfile`` already parsed and decodes the
limited set of types permitted in custom attribute blobs (ECMA-335 II.23.3).
It never loads the analyzed assembly and never creates an instance of the
attribute class: the only inputs are table rows and the raw ``#Blob`` bytes.

Copyright (c) 2020-2024 MalwareFrank
"""
import enum as _enum
import struct as _struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

MAX_TYPE_DEPTH = 32
MAX_ARRAY_ELEMENTS = 1_000_000

PROVENANCE = {
    "assembly_loaded": False,
    "attribute_instantiated": False,
    "analyzed_file_imported": False,
    "executed_analyzed_code": False,
    "source": "dnfile metadata tables and raw #Blob bytes only",
}


def get_provenance() -> Dict[str, Any]:
    """Return a copy of the static-read provenance statement."""
    return dict(PROVENANCE)


class InterpretationStatus(str, _enum.Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INDETERMINATE = "indeterminate"


PRIMITIVES = {
    0x02: ("System.Boolean", "?", 1),
    0x03: ("System.Char", "H", 2),
    0x04: ("System.SByte", "b", 1),
    0x05: ("System.Byte", "B", 1),
    0x06: ("System.Int16", "h", 2),
    0x07: ("System.UInt16", "H", 2),
    0x08: ("System.Int32", "i", 4),
    0x09: ("System.UInt32", "I", 4),
    0x0A: ("System.Int64", "q", 8),
    0x0B: ("System.UInt64", "Q", 8),
    0x0C: ("System.Single", "f", 4),
    0x0D: ("System.Double", "d", 8),
}

INTEGER_FORMATS = frozenset(("b", "B", "h", "H", "i", "I", "q", "Q"))

#: Argument types this decoder interprets. Anything else is reported as indeterminate.
SUPPORTED_ARGUMENT_TYPES = {
    "System.Boolean": "1 byte, only 0x00/0x01 accepted",
    "System.Char": "2 bytes, UTF-16 code unit",
    "System.SByte": "1 byte signed",
    "System.Byte": "1 byte unsigned",
    "System.Int16": "2 bytes signed",
    "System.UInt16": "2 bytes unsigned",
    "System.Int32": "4 bytes signed",
    "System.UInt32": "4 bytes unsigned",
    "System.Int64": "8 bytes signed",
    "System.UInt64": "8 bytes unsigned",
    "System.Single": "4 bytes IEEE-754",
    "System.Double": "8 bytes IEEE-754",
    "System.String": "SerString (UTF-8, 0xFF = null)",
    "System.Type": "SerString holding the type name",
    "System.Object": "boxing type tag followed by a primitive, string or enum value",
    "enum": "underlying type taken from a local TypeDef value__ field signature",
    "SZARRAY": "uint32 element count; 0xFFFFFFFF = null, 0 = empty array",
}

ELEMENT_NAMES = {
    0x01: "ELEMENT_TYPE_VOID",
    0x02: "ELEMENT_TYPE_BOOLEAN",
    0x03: "ELEMENT_TYPE_CHAR",
    0x04: "ELEMENT_TYPE_I1",
    0x05: "ELEMENT_TYPE_U1",
    0x06: "ELEMENT_TYPE_I2",
    0x07: "ELEMENT_TYPE_U2",
    0x08: "ELEMENT_TYPE_I4",
    0x09: "ELEMENT_TYPE_U4",
    0x0A: "ELEMENT_TYPE_I8",
    0x0B: "ELEMENT_TYPE_U8",
    0x0C: "ELEMENT_TYPE_R4",
    0x0D: "ELEMENT_TYPE_R8",
    0x0E: "ELEMENT_TYPE_STRING",
    0x11: "ELEMENT_TYPE_VALUETYPE",
    0x12: "ELEMENT_TYPE_CLASS",
    0x1C: "ELEMENT_TYPE_OBJECT",
    0x1D: "ELEMENT_TYPE_SZARRAY",
    0x50: "ELEMENT_TYPE_TYPE",
    0x55: "ELEMENT_TYPE_ENUM",
}


class _DecodeError(Exception):
    def __init__(self, reason: str, offset: Optional[int] = None):
        super().__init__(reason)
        self.reason = reason
        self.offset = offset


class _BlobReader:
    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.pos = 0
        self.base = base

    @property
    def remaining(self) -> int:
        return max(0, len(self.data) - self.pos)

    def tell(self) -> int:
        return self.base + self.pos

    def read(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise _DecodeError(
                "unexpected-end-of-blob: wanted %d byte(s) at offset 0x%x, have %d"
                % (size, self.tell(), self.remaining),
                self.tell(),
            )
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def read_u8(self) -> int:
        return _struct.unpack("<B", self.read(1))[0]

    def read_u16(self) -> int:
        return _struct.unpack("<H", self.read(2))[0]

    def read_u32(self) -> int:
        return _struct.unpack("<I", self.read(4))[0]

    def read_compressed(self) -> int:
        start = self.tell()
        first = self.read_u8()
        if first & 0x80 == 0:
            return first
        if first & 0x40 == 0:
            second = self.read_u8()
            return ((first & 0x3F) << 8) | second
        if first & 0x20 == 0:
            rest = self.read(3)
            return ((first & 0x1F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        raise _DecodeError("invalid-compressed-int: leading byte 0x%02x" % first, start)

    def read_ser_string(self) -> Optional[str]:
        # ECMA-335 II.23.3: 0xFF denotes null, otherwise a compressed length
        # followed by UTF-8 bytes. Invalid UTF-8 is an error, never null.
        start = self.tell()
        if self.remaining and self.data[self.pos] == 0xFF:
            self.pos += 1
            return None
        size = self.read_compressed()
        raw = self.read(size)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise _DecodeError("invalid-utf8-in-serstring: %s" % e, start)


@dataclass
class SignatureType:
    kind: str
    element_type: Optional[int]
    display: str
    primitive: Optional[str] = None
    size: Optional[int] = None
    ref_table: Optional[str] = None
    ref_row: Optional[int] = None
    ref_name: Optional[str] = None
    external: Optional[bool] = None
    element: Optional["SignatureType"] = None


@dataclass
class SignatureParameter:
    position: int
    type: SignatureType
    display: str


@dataclass
class ParsedSignature:
    calling_convention: int
    generic_count: int
    return_type: SignatureType
    parameters: List[SignatureParameter]
    raw: bytes
    basis: str


@dataclass
class ConstructorSignature:
    token: str
    kind: str
    name: Optional[str]
    declaring_type: Optional[str]
    declaring_assembly: Optional[str]
    external: Optional[bool]
    blob: Optional[bytes]
    blob_rva: Optional[int]
    signature_hex: str
    param_count: Optional[int]
    return_type: Optional[str]
    parameters: List[str]
    status: InterpretationStatus
    reason: Optional[str]
    basis: str


@dataclass
class AttributeArgument:
    kind: str
    position: int
    name: Optional[str]
    declared_type: str
    value: Any
    status: InterpretationStatus
    basis: List[str]
    offset: int
    reason: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CustomAttributeInterpretation:
    parent: Optional[str]
    constructor: ConstructorSignature
    fixed_args: List[AttributeArgument]
    named_args: List[AttributeArgument]
    status: InterpretationStatus
    diagnostics: List[str]
    blob: Optional[bytes]
    blob_rva: Optional[int]
    consumed: int
    trailing: bytes
    provenance: Dict[str, Any]


def _heap_bytes(item: Any) -> Optional[bytes]:
    if item is None:
        return None
    if isinstance(item, (bytes, bytearray)):
        return bytes(item)
    value = getattr(item, "value", None)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    value_bytes = getattr(item, "value_bytes", None)
    if callable(value_bytes):
        try:
            result = value_bytes()
        except (IndexError, TypeError, ValueError):
            return None
        if isinstance(result, (bytes, bytearray)):
            return bytes(result)
    return None


def _row_string(row: Any, attr: str) -> Optional[str]:
    value = getattr(row, attr, None)
    if value is None:
        return None
    # HeapItemString exposes the decoded text as .value and keeps .value None
    # when the underlying bytes were not valid UTF-8.
    if hasattr(value, "value") and not isinstance(value, (bytes, bytearray)):
        value = getattr(value, "value")
        if value is None:
            return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return str(value)


def _get_table(tables: Any, name: str) -> Any:
    if tables is None:
        return None
    table = getattr(tables, name, None)
    if table is not None:
        return table
    for candidate in getattr(tables, "tables_list", None) or []:
        if getattr(candidate, "name", None) == name:
            return candidate
    return None


def _get_row(table: Any, row_index: Optional[int]) -> Any:
    if table is None or row_index is None or row_index < 1:
        return None
    num_rows = getattr(table, "num_rows", None)
    if num_rows is not None and row_index > num_rows:
        return None
    getter = getattr(table, "get_with_row_index", None)
    if callable(getter):
        try:
            return getter(row_index)
        except (IndexError, KeyError, TypeError, ValueError):
            return None
    rows = getattr(table, "rows", None) or []
    if row_index <= len(rows):
        return rows[row_index - 1]
    return None


def _index_row(index: Any) -> Any:
    if index is None:
        return None
    row = getattr(index, "row", None)
    if row is not None:
        return row
    return _get_row(getattr(index, "table", None), getattr(index, "row_index", None))


def _token(table_name: str, row_index: int) -> str:
    return "%s#%d" % (table_name, row_index)


def _full_type_name(row: Any) -> str:
    namespace = _row_string(row, "TypeNamespace") or ""
    name = _row_string(row, "TypeName") or "<unknown>"
    return "%s.%s" % (namespace, name) if namespace else name


def _scope_info(resolution_scope: Any, tables: Any, depth: int = 0) -> Tuple[Optional[str], Optional[bool], Optional[str]]:
    """Return (display name, external, assembly name) for a TypeRef scope chain."""
    if resolution_scope is None or depth > MAX_TYPE_DEPTH:
        return None, None, None
    table = getattr(resolution_scope, "table", None)
    row = getattr(resolution_scope, "row", None)
    if table is None or row is None:
        return None, None, None
    table_name = getattr(table, "name", None)
    if table_name == "AssemblyRef":
        name = _row_string(row, "Name")
        return name, True, name
    if table_name == "ModuleRef":
        name = _row_string(row, "Name")
        return name, True, None
    if table_name == "Module":
        name = _row_string(row, "Name")
        return name, False, None
    if table_name == "TypeRef":
        # Nested type: the outer type's scope determines the assembly, but the
        # outer type name is not an assembly name, so do not report it as one.
        _display, external, assembly = _scope_info(
            getattr(row, "ResolutionScope", None), tables, depth + 1
        )
        return None, external, assembly
    return None, None, None


def _resolve_type_token(token: int, tables: Any) -> Optional[SignatureType]:
    tag = token & 0x03
    row_index = token >> 2
    if row_index < 1:
        return None
    table_name = ("TypeDef", "TypeRef", "TypeSpec")[tag]
    table = _get_table(tables, table_name)
    row = _get_row(table, row_index)
    if row is None:
        return None

    if table_name == "TypeSpec":
        return SignatureType(
            kind="typespec",
            element_type=None,
            display="<TypeSpec#%d>" % row_index,
            ref_table=table_name,
            ref_row=row_index,
        )

    display = _full_type_name(row)
    external: Optional[bool] = False
    scope_name = None
    if table_name == "TypeRef":
        scope_name, external, assembly = _scope_info(getattr(row, "ResolutionScope", None), tables)
        # For a nested TypeRef the scope is another type, so name the assembly instead.
        scope_label = scope_name or assembly
        if scope_label:
            display = "%s [%s]" % (display, scope_label)

    return SignatureType(
        kind="valuetype" if table_name == "TypeDef" else "class",
        element_type=None,
        display=display,
        ref_table=table_name,
        ref_row=row_index,
        ref_name=_full_type_name(row),
        external=external,
    )


def _parse_signature_type(
    reader: _BlobReader, tables: Any, depth: int = 0, allow_void: bool = False
) -> SignatureType:
    if depth > MAX_TYPE_DEPTH:
        raise _DecodeError("type-nesting-too-deep", reader.tell())

    start = reader.tell()
    element_type = reader.read_u8()
    if element_type == 0x01:
        if not allow_void:
            raise _DecodeError("ELEMENT_TYPE_VOID is not a valid parameter type", start)
        return SignatureType("void", element_type, "System.Void")
    if element_type in PRIMITIVES:
        display, fmt, size = PRIMITIVES[element_type]
        return SignatureType("primitive", element_type, display, primitive=fmt, size=size)
    if element_type == 0x0E:
        return SignatureType("string", element_type, "System.String")
    if element_type == 0x50:
        return SignatureType("type", element_type, "System.Type")
    if element_type == 0x1C:
        return SignatureType("object", element_type, "System.Object")
    if element_type == 0x1D:
        element = _parse_signature_type(reader, tables, depth + 1)
        return SignatureType(
            "array", element_type, "SZARRAY<%s>" % element.display, element=element
        )
    if element_type in (0x11, 0x12):
        token = reader.read_compressed()
        resolved = _resolve_type_token(token, tables)
        if resolved is None:
            raise _DecodeError(
                "unresolved-type-token: 0x%x (tag=%d row=%d)" % (token, token & 3, token >> 2),
                start,
            )
        resolved.element_type = element_type
        if element_type == 0x11:
            resolved.kind = "valuetype"
            resolved.display = "enum " + resolved.display
        else:
            resolved.kind = "class"
            resolved.display = "class " + resolved.display
        return resolved
    if element_type in (0x1F, 0x20):
        # Custom modifiers: skip the TypeDefOrRef token and read the modified type.
        reader.read_compressed()
        return _parse_signature_type(reader, tables, depth + 1)

    name = ELEMENT_NAMES.get(element_type, "element 0x%02x" % element_type)
    raise _DecodeError("unsupported-signature-element: %s" % name, start)


def _read_ser_string_with_basis(reader: _BlobReader) -> Tuple[Optional[str], str]:
    start = reader.tell()
    value = reader.read_ser_string()
    if value is None:
        basis = "null SerString at blob offset 0x%x" % start
    else:
        basis = "SerString (%d byte(s)) at blob offset 0x%x" % (len(value.encode("utf-8")), start)
    return value, basis


def _parse_method_signature(blob: bytes, tables: Any) -> ParsedSignature:
    reader = _BlobReader(blob)
    calling_convention = reader.read_u8()
    generic_count = 0
    if calling_convention & 0x10:
        generic_count = reader.read_compressed()
    param_count = reader.read_compressed()
    return_type = _parse_signature_type(reader, tables, allow_void=True)
    parameters: List[SignatureParameter] = []
    for i in range(param_count):
        param_type = _parse_signature_type(reader, tables)
        parameters.append(SignatureParameter(i, param_type, param_type.display))
    if reader.remaining:
        raise _DecodeError(
            "signature-trailing-bytes: %d byte(s) after %d param(s)" % (reader.remaining, param_count),
            reader.tell(),
        )
    basis = (
        "method signature from #Blob (%d byte(s)): calling_convention=0x%02x, "
        "generic_count=%d, param_count=%d, return=%s"
        % (len(blob), calling_convention, generic_count, param_count, return_type.display)
    )
    if generic_count:
        raise _DecodeError("generic-constructor-signature: generic_count=%d" % generic_count, 0)
    return ParsedSignature(calling_convention, generic_count, return_type, parameters, blob, basis)


def _row_index_of(index: Any) -> Optional[int]:
    return getattr(index, "row_index", None)


def _find_declaring_typedef(methoddef_index: int, tables: Any) -> Tuple[Optional[str], Optional[int]]:
    typedefs = _get_table(tables, "TypeDef")
    if typedefs is None:
        return None, None
    rows = getattr(typedefs, "rows", None) or []
    for i, row in enumerate(rows, start=1):
        if row is None:
            continue
        for index in getattr(row, "MethodList", None) or []:
            if _row_index_of(index) == methoddef_index:
                return _full_type_name(row), i
    return None, None


def _current_assembly_name(tables: Any) -> Optional[str]:
    assembly = _get_table(tables, "Assembly")
    if assembly is None:
        return None
    row = _get_row(assembly, 1)
    return _row_string(row, "Name") if row is not None else None


def _constructor_source(ctor_row: Any, ctor_table_name: str, ctor_index: int, tables: Any) -> Tuple[Optional[str], Optional[str], Optional[bool], Optional[str]]:
    """Return (declaring_type, assembly, external, source_reason)."""
    if ctor_table_name == "MethodDef":
        name, _index = _find_declaring_typedef(ctor_index, tables)
        if name is None:
            return None, None, False, "local MethodDef but declaring TypeDef was not found"
        return name, _current_assembly_name(tables), False, None

    if ctor_table_name == "MemberRef":
        cls = getattr(ctor_row, "Class", None)
        table = getattr(cls, "table", None) if cls is not None else None
        row = getattr(cls, "row", None) if cls is not None else None
        if table is None or row is None:
            return None, None, None, "MemberRef.Class coded index could not be resolved"
        table_name = getattr(table, "name", None)
        if table_name == "TypeRef":
            display = _full_type_name(row)
            scope, external, assembly = _scope_info(getattr(row, "ResolutionScope", None), tables)
            if scope:
                display = "%s [%s]" % (display, scope)
            return display, assembly, external, None
        if table_name == "TypeDef":
            return _full_type_name(row), _current_assembly_name(tables), False, None
        if table_name == "ModuleRef":
            return None, None, True, "MemberRef.Class is a ModuleRef (%s), not a type" % (_row_string(row, "Name") or "<unknown>")
        if table_name == "TypeSpec":
            return None, None, None, "MemberRef.Class is a TypeSpec; declaring type cannot be named statically"
        if table_name == "MethodDef":
            return None, None, None, "MemberRef.Class is a MethodDef; declaring type is ambiguous"
        return None, None, None, "unsupported MemberRef.Class table: %s" % table_name

    return None, None, None, "unsupported constructor table: %s" % ctor_table_name


def _resolve_constructor(row: Any, tables: Any) -> ConstructorSignature:
    ctor = getattr(row, "Type", None)
    table = getattr(ctor, "table", None) if ctor is not None else None
    row_index = getattr(ctor, "row_index", None) if ctor is not None else None

    if ctor is None:
        return ConstructorSignature(
            token="<missing>", kind="none", name=None, declaring_type=None,
            declaring_assembly=None, external=None, blob=None, blob_rva=None,
            signature_hex="", param_count=None, return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="CustomAttribute.Type is missing",
            basis="constructor not resolved",
        )
    if table is None:
        return ConstructorSignature(
            token="CustomAttributeType#%s" % row_index, kind="unresolved", name=None,
            declaring_type=None, declaring_assembly=None, external=None,
            blob=None, blob_rva=None, signature_hex="", param_count=None,
            return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="CustomAttributeType coded index resolves to an Unused/absent table; constructor is not unique",
            basis="constructor not resolved",
        )

    table_name = getattr(table, "name", None) or "?"
    ctor_row = _get_row(table, row_index)
    if ctor_row is None:
        return ConstructorSignature(
            token=_token(table_name, row_index or 0), kind=table_name, name=None,
            declaring_type=None, declaring_assembly=None, external=None,
            blob=None, blob_rva=None, signature_hex="", param_count=None,
            return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="constructor row %s is out of range" % _token(table_name, row_index or 0),
            basis="constructor not resolved",
        )

    name = _row_string(ctor_row, "Name")
    signature_item = getattr(ctor_row, "Signature", None)
    blob = _heap_bytes(signature_item)
    blob_rva = getattr(signature_item, "rva", None)
    signature_hex = blob.hex(" ") if blob else ""
    token = _token(table_name, row_index or 0)
    declaring_type, assembly, external, source_reason = _constructor_source(
        ctor_row, table_name, row_index or 0, tables
    )

    if blob is None or not blob:
        return ConstructorSignature(
            token=token, kind=table_name, name=name, declaring_type=declaring_type,
            declaring_assembly=assembly, external=external, blob=blob,
            blob_rva=blob_rva, signature_hex=signature_hex, param_count=None,
            return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="constructor signature blob is unavailable",
            basis="constructor signature not resolved",
        )

    if name not in (".ctor", ".cctor"):
        return ConstructorSignature(
            token=token, kind=table_name, name=name, declaring_type=declaring_type,
            declaring_assembly=assembly, external=external, blob=blob,
            blob_rva=blob_rva, signature_hex=signature_hex, param_count=None,
            return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="constructor Type points to %s::%s, which is not .ctor/.cctor" % (declaring_type or "<unknown>", name),
            basis="constructor signature not used",
        )

    try:
        parsed = _parse_method_signature(blob, tables)
    except _DecodeError as e:
        return ConstructorSignature(
            token=token, kind=table_name, name=name, declaring_type=declaring_type,
            declaring_assembly=assembly, external=external, blob=blob,
            blob_rva=blob_rva, signature_hex=signature_hex, param_count=None,
            return_type=None, parameters=[],
            status=InterpretationStatus.INDETERMINATE,
            reason="constructor signature unreadable: %s" % e.reason,
            basis="constructor signature blob = %s" % signature_hex,
        )

    status = InterpretationStatus.COMPLETE
    reason = None
    if source_reason:
        status = InterpretationStatus.PARTIAL
        reason = source_reason
    if name != ".ctor":
        status = InterpretationStatus.PARTIAL
        reason = reason or "static constructor signature (%s) is unusual for a custom attribute" % name

    basis = "%s %s; signature #Blob%s = %s" % (
        token,
        parsed.basis,
        (" @RVA 0x%x" % blob_rva) if blob_rva is not None else "",
        signature_hex,
    )
    return ConstructorSignature(
        token=token, kind=table_name, name=name, declaring_type=declaring_type,
        declaring_assembly=assembly, external=external, blob=blob,
        blob_rva=blob_rva, signature_hex=signature_hex,
        param_count=len(parsed.parameters),
        return_type=parsed.return_type.display,
        parameters=[p.display for p in parsed.parameters],
        status=status, reason=reason, basis=basis,
    )


def _enum_underlying_type(
    sig_type: SignatureType, tables: Any, visited: Sequence[str], depth: int
) -> Tuple[SignatureType, Any, str]:
    if sig_type.kind != "valuetype":
        raise _DecodeError("non-enum class argument: %s" % sig_type.display)
    if sig_type.ref_table != "TypeDef":
        raise _DecodeError(
            "external-enum-underlying-unknown: %s (assembly not loaded)" % sig_type.display
        )
    if depth > MAX_TYPE_DEPTH:
        raise _DecodeError("type-nesting-too-deep", None)

    key = _token("TypeDef", sig_type.ref_row or 0)
    if key in visited:
        raise _DecodeError("recursive-enum-type: %s" % " -> ".join(list(visited) + [key]))
    typedef = _get_table(tables, "TypeDef")
    row = _get_row(typedef, sig_type.ref_row)
    if row is None:
        raise _DecodeError("enum TypeDef row not found: %s" % key)

    value_field = None
    for index in getattr(row, "FieldList", None) or []:
        field_row = _index_row(index)
        if field_row is not None and _row_string(field_row, "Name") == "value__":
            value_field = field_row
            break
    if value_field is None:
        raise _DecodeError("TypeDef %s has no value__ field; not an enum" % key)

    field_sig = _heap_bytes(getattr(value_field, "Signature", None))
    if not field_sig:
        raise _DecodeError("enum %s value__ field signature is unavailable" % key)
    reader = _BlobReader(field_sig)
    if reader.read_u8() != 0x06:
        raise _DecodeError("enum %s value__ field signature does not start with FIELD (0x06)" % key)
    underlying = _parse_signature_type(reader, tables, depth + 1)
    if reader.remaining:
        raise _DecodeError("enum %s value__ field signature has %d trailing byte(s)" % (key, reader.remaining))
    if underlying.kind in ("valuetype", "class"):
        return _enum_underlying_type(underlying, tables, list(visited) + [key], depth + 1)
    if underlying.kind != "primitive" or underlying.primitive not in INTEGER_FORMATS:
        raise _DecodeError(
            "recursive-or-invalid-enum-underlying: %s.value__ -> %s" % (key, underlying.display)
        )

    basis = "enum underlying type from %s.value__ field signature %s -> %s" % (
        key, field_sig.hex(" "), underlying.display
    )
    return underlying, row, basis


def _constant_scalar(type_code: Optional[int], data: bytes) -> Any:
    if type_code is None or type_code not in PRIMITIVES:
        return None
    _display, fmt, size = PRIMITIVES[type_code]
    if len(data) < size:
        return None
    raw = data[:size]
    if fmt == "?":
        return raw[0] != 0
    if fmt == "H":
        return _struct.unpack("<H", raw)[0]
    try:
        return _struct.unpack("<" + fmt, raw)[0]
    except _struct.error:
        return None


def _enum_members(typedef_row: Any, tables: Any, type_code: Optional[int] = None) -> Dict[int, List[str]]:
    constants = _get_table(tables, "Constant")
    if constants is None:
        return {}
    by_field: Dict[int, Any] = {}
    for constant in getattr(constants, "rows", None) or []:
        if constant is None:
            continue
        parent = getattr(constant, "Parent", None)
        parent_table = getattr(parent, "table", None)
        parent_index = getattr(parent, "row_index", None)
        if parent_table is not None and getattr(parent_table, "name", None) == "Field" and parent_index:
            by_field[parent_index] = constant

    members: Dict[int, List[str]] = {}
    for index in getattr(typedef_row, "FieldList", None) or []:
        field_index = _row_index_of(index)
        field_row = _index_row(index)
        if field_index is None or field_row is None:
            continue
        name = _row_string(field_row, "Name")
        if not name or name == "value__":
            continue
        constant = by_field.get(field_index)
        if constant is None:
            continue
        # Only name members whose Constant.Type matches the enum's underlying type.
        if type_code is not None and getattr(constant, "Type", None) != type_code:
            continue
        value = _constant_scalar(getattr(constant, "Type", None), _heap_bytes(getattr(constant, "Value", None)) or b"")
        if isinstance(value, int):
            members.setdefault(value, []).append(name)
    return members


def _enum_scalar(
    underlying: SignatureType, reader: _BlobReader, tables: Any, typedef_row: Any, basis: List[str]
) -> Tuple[Any, Dict[str, Any]]:
    fmt = underlying.primitive
    size = underlying.size or 0
    raw = reader.read(size)
    if fmt == "H":
        value = _struct.unpack("<H", raw)[0]
    else:
        value = _struct.unpack("<" + str(fmt), raw)[0]
    extra: Dict[str, Any] = {"enum_underlying": underlying.display, "enum_member": None}
    members = _enum_members(typedef_row, tables, underlying.element_type)
    names = members.get(value)
    if names:
        extra["enum_member"] = names[0] if len(names) == 1 else names
        basis.append("enum member name(s) from Constant table: %s = %s" % (value, ", ".join(names)))
    elif members:
        extra["enum_member_unmatched"] = True
    return value, extra


def _resolve_enum_by_name(name: str, tables: Any) -> SignatureType:
    if tables is None:
        raise _DecodeError("enum type name %r cannot be resolved without metadata tables" % name)
    wanted = name.replace("+", "/")
    matches: List[SignatureType] = []
    for table_name in ("TypeDef", "TypeRef"):
        table = _get_table(tables, table_name)
        rows = getattr(table, "rows", None) or []
        for i, row in enumerate(rows, start=1):
            if row is None:
                continue
            full = _full_type_name(row).replace("+", "/")
            short = _row_string(row, "TypeName") or ""
            if full == wanted or short == wanted:
                external = None
                if table_name == "TypeRef":
                    _scope, external, _assembly = _scope_info(getattr(row, "ResolutionScope", None), tables)
                matches.append(SignatureType(
                    kind="valuetype", element_type=0x55,
                    display=("enum [%s]" % table_name) + full,
                    ref_table=table_name, ref_row=i, ref_name=full, external=external,
                ))
    if not matches:
        raise _DecodeError("unknown-enum-type-name: %s" % name)
    if len(matches) > 1:
        local = [m for m in matches if m.ref_table == "TypeDef"]
        if len(local) == 1:
            return local[0]
        labels = ", ".join("%s#%d" % (m.ref_table, m.ref_row) for m in matches)
        raise _DecodeError("ambiguous-enum-type-name: %s matches %s" % (name, labels))
    return matches[0]


def _parse_field_or_prop_type(reader: _BlobReader, tables: Any, depth: int = 0) -> SignatureType:
    if depth > MAX_TYPE_DEPTH:
        raise _DecodeError("type-nesting-too-deep", reader.tell())
    start = reader.tell()
    element_type = reader.read_u8()
    if element_type == 0x55:
        name = reader.read_ser_string()
        if not name:
            raise _DecodeError("empty enum type name in named argument", start)
        enum_type = _resolve_enum_by_name(name, tables)
        enum_type.display = "enum %s" % name
        return enum_type
    if element_type == 0x1D:
        element = _parse_field_or_prop_type(reader, tables, depth + 1)
        return SignatureType("array", element_type, "SZARRAY<%s>" % element.display, element=element)
    if element_type in PRIMITIVES:
        display, fmt, size = PRIMITIVES[element_type]
        return SignatureType("primitive", element_type, display, primitive=fmt, size=size)
    if element_type == 0x0E:
        return SignatureType("string", element_type, "System.String")
    if element_type == 0x50:
        return SignatureType("type", element_type, "System.Type")
    if element_type == 0x1C:
        return SignatureType("object", element_type, "System.Object")
    name = ELEMENT_NAMES.get(element_type, "element 0x%02x" % element_type)
    raise _DecodeError("unsupported-named-argument-type: %s" % name, start)


def _decode_value(
    sig_type: SignatureType,
    reader: _BlobReader,
    tables: Any,
    basis: List[str],
    visited: Sequence[str],
    depth: int,
    path: str,
    type_basis: Optional[str] = None,
) -> Tuple[Any, Dict[str, Any]]:
    if depth > MAX_TYPE_DEPTH:
        raise _DecodeError("type-nesting-too-deep", reader.tell())

    if sig_type.kind == "primitive":
        if sig_type.primitive == "?":
            value = reader.read_u8()
            if value not in (0, 1):
                raise _DecodeError("invalid-boolean-value: 0x%02x" % value, reader.tell() - 1)
            return bool(value), {}
        size = sig_type.size or 0
        offset = reader.tell()
        raw = reader.read(size)
        if sig_type.primitive == "H":
            return _struct.unpack("<H", raw)[0], {}
        value = _struct.unpack("<" + str(sig_type.primitive), raw)[0]
        if sig_type.primitive == "f" and value != value:
            basis.append("%s: NaN at payload offset 0x%x" % (path, offset))
        return value, {}

    if sig_type.kind in ("string", "type"):
        value, string_basis = _read_ser_string_with_basis(reader)
        basis.append("%s: %s" % (path, string_basis))
        return value, {}

    if sig_type.kind == "object":
        inner = _parse_field_or_prop_type(reader, tables, depth + 1)
        if inner.kind in ("object", "array"):
            raise _DecodeError("invalid-boxed-type: %s" % inner.display, reader.tell())
        value, extra = _decode_value(
            inner, reader, tables, basis, visited, depth + 1, path + ".boxed", type_basis
        )
        extra = dict(extra)
        extra["boxed_type"] = inner.display
        basis.append("%s: boxed value type %s declared in payload" % (path, inner.display))
        return value, extra

    if sig_type.kind == "array":
        count_offset = reader.tell()
        count = reader.read_u32()
        if count == 0xFFFFFFFF:
            basis.append("%s: null SZARRAY (count = 0xFFFFFFFF) at offset 0x%x" % (path, count_offset))
            return None, {"array": True, "null": True, "count": None, "element_type": sig_type.element.display if sig_type.element else None}
        if count > MAX_ARRAY_ELEMENTS:
            raise _DecodeError("array-too-large: %d element(s)" % count, count_offset)
        if sig_type.element is None:
            raise _DecodeError("array element type missing", count_offset)
        values = []
        for i in range(count):
            value, _extra = _decode_value(
                sig_type.element, reader, tables, basis, visited, depth + 1,
                "%s[%d]" % (path, i), type_basis,
            )
            values.append(value)
        basis.append(
            "%s: SZARRAY<%s> count=%d from payload offset 0x%x"
            % (path, sig_type.element.display, count, count_offset)
        )
        return values, {"array": True, "null": False, "count": count, "element_type": sig_type.element.display}

    if sig_type.kind in ("valuetype", "class"):
        if sig_type.element_type != 0x11:
            raise _DecodeError(
                "unsupported-class-argument: %s (only enums are interpreted)" % sig_type.display,
                reader.tell(),
            )
        if type_basis:
            basis.append(
                "declared type %s from %s" % (sig_type.display, type_basis)
            )
        underlying, typedef_row, enum_basis = _enum_underlying_type(sig_type, tables, visited, depth + 1)
        basis.append(enum_basis)
        value, extra = _enum_scalar(underlying, reader, tables, typedef_row, basis)
        extra["enum_type"] = sig_type.display
        return value, extra

    raise _DecodeError("unsupported-value-type: %s" % sig_type.display, reader.tell())


def _indeterminate_argument(
    kind: str, position: int, name: Optional[str], declared_type: str,
    basis: List[str], offset: int, reason: str,
) -> AttributeArgument:
    return AttributeArgument(
        kind=kind, position=position, name=name, declared_type=declared_type,
        value=None, status=InterpretationStatus.INDETERMINATE,
        basis=list(basis), offset=offset, reason=reason,
    )


def _decode_payload(
    ctor: ConstructorSignature,
    signature: ParsedSignature,
    blob: bytes,
    tables: Any,
    blob_rva: Optional[int],
    parent: Optional[str],
) -> CustomAttributeInterpretation:
    result = CustomAttributeInterpretation(
        parent=parent,
        constructor=ctor,
        fixed_args=[],
        named_args=[],
        status=InterpretationStatus.COMPLETE,
        diagnostics=[],
        blob=blob,
        blob_rva=blob_rva,
        consumed=0,
        trailing=b"",
        provenance=get_provenance(),
    )
    reader = _BlobReader(blob)
    try:
        prolog = reader.read_u16()
    except _DecodeError as e:
        result.status = InterpretationStatus.INDETERMINATE
        result.diagnostics.append("bad-prolog: %s" % e.reason)
        return result
    if prolog != 0x0001:
        result.status = InterpretationStatus.INDETERMINATE
        result.diagnostics.append("bad-prolog: expected 0x0001, found 0x%04x" % prolog)
        return result

    failure: Optional[_DecodeError] = None
    for param in signature.parameters:
        start = reader.tell()
        basis = [
            "fixed argument %d takes its declared type from ctor-signature %s param[%d] -> %s"
            % (param.position, ctor.token, param.position, param.display)
        ]
        try:
            value, extra = _decode_value(
                param.type, reader, tables, basis, (), 0, "fixed[%d]" % param.position,
                type_basis=ctor.basis,
            )
            result.fixed_args.append(AttributeArgument(
                kind="fixed", position=param.position, name=None,
                declared_type=param.display, value=value,
                status=InterpretationStatus.COMPLETE, basis=basis,
                offset=start, extra=extra,
            ))
        except _DecodeError as e:
            failure = e
            result.fixed_args.append(_indeterminate_argument(
                "fixed", param.position, None, param.display, basis, start, e.reason
            ))
            break

    if failure is not None:
        result.status = InterpretationStatus.PARTIAL
        result.diagnostics.append(
            "fixed argument decoding stopped at offset 0x%x: %s" % (failure.offset or reader.tell(), failure.reason)
        )
        for param in signature.parameters[len(result.fixed_args):]:
            result.fixed_args.append(_indeterminate_argument(
                "fixed", param.position, None, param.display,
                ["not decoded after an earlier fixed-argument error"], reader.tell(),
                "skipped-after-earlier-error",
            ))
        result.consumed = reader.pos
        result.trailing = blob[reader.pos:]
        return result

    named_count_offset = reader.tell()
    try:
        named_count = reader.read_u16()
    except _DecodeError as e:
        result.status = InterpretationStatus.PARTIAL
        result.diagnostics.append("named-argument count unreadable at offset 0x%x: %s" % (named_count_offset, e.reason))
        result.consumed = reader.pos
        result.trailing = blob[reader.pos:]
        return result

    for i in range(named_count):
        start = reader.tell()
        try:
            kind_byte = reader.read_u8()
            if kind_byte == 0x53:
                arg_kind = "field"
            elif kind_byte == 0x54:
                arg_kind = "property"
            else:
                raise _DecodeError("unknown-named-argument-kind: 0x%02x" % kind_byte, start)
            type_offset = reader.tell()
            arg_type = _parse_field_or_prop_type(reader, tables)
            name = reader.read_ser_string()
            if not name:
                raise _DecodeError("empty named-argument name", reader.tell())
            basis = [
                "named-%s %r type from payload at offset 0x%x -> %s"
                % (arg_kind, name, type_offset, arg_type.display)
            ]
            value_offset = reader.tell()
            value, extra = _decode_value(
                arg_type, reader, tables, basis, (), 0, "named[%d]" % i
            )
            extra = dict(extra)
            extra["named_kind"] = arg_kind
            result.named_args.append(AttributeArgument(
                kind="named", position=i, name=name,
                declared_type=arg_type.display, value=value,
                status=InterpretationStatus.COMPLETE, basis=basis,
                offset=value_offset, extra=extra,
            ))
        except _DecodeError as e:
            result.status = InterpretationStatus.PARTIAL
            result.diagnostics.append(
                "named argument %d decoding stopped at offset 0x%x: %s" % (i, e.offset or reader.tell(), e.reason)
            )
            result.named_args.append(_indeterminate_argument(
                "named", i, None, "<unknown>",
                ["named-argument type/name/value could not be decoded"],
                start, e.reason,
            ))
            for skipped in range(i + 1, named_count):
                result.named_args.append(_indeterminate_argument(
                    "named", skipped, None, "<unknown>",
                    ["not decoded after an earlier named-argument error"],
                    reader.tell(), "skipped-after-earlier-error",
                ))
            result.consumed = reader.pos
            result.trailing = blob[reader.pos:]
            return result

    result.consumed = reader.pos
    if reader.remaining:
        result.trailing = blob[reader.pos:]
        result.status = InterpretationStatus.PARTIAL
        result.diagnostics.append(
            "trailing-bytes: %d byte(s) after the declared fixed and named arguments at offset 0x%x: %s"
            % (len(result.trailing), reader.tell(), result.trailing.hex(" "))
        )

    if result.status == InterpretationStatus.COMPLETE and ctor.status != InterpretationStatus.COMPLETE:
        result.status = ctor.status

    return result


def decode_custom_attribute(row: Any, tables: Any = None) -> CustomAttributeInterpretation:
    """
    Statically decode one CustomAttribute row.

    ``row`` is a dnfile ``CustomAttributeRow`` (or a compatible row-like
    object). ``tables`` is the ``MetaDataTables`` object, required for enum
    resolution. No assembly is loaded and the attribute is never instantiated.
    """
    parent = None
    parent_index = getattr(row, "Parent", None)
    parent_table = getattr(parent_index, "table", None)
    if parent_table is not None:
        parent = _token(getattr(parent_table, "name", "?"), getattr(parent_index, "row_index", 0) or 0)

    value_item = getattr(row, "Value", None)
    blob = _heap_bytes(value_item)
    blob_rva = getattr(value_item, "rva", None)
    ctor = _resolve_constructor(row, tables)

    if blob is None:
        return CustomAttributeInterpretation(
            parent=parent, constructor=ctor, fixed_args=[], named_args=[],
            status=InterpretationStatus.INDETERMINATE,
            diagnostics=["CustomAttribute.Value blob is unavailable"],
            blob=blob, blob_rva=blob_rva, consumed=0, trailing=b"",
            provenance=get_provenance(),
        )

    if ctor.status == InterpretationStatus.INDETERMINATE:
        return CustomAttributeInterpretation(
            parent=parent, constructor=ctor, fixed_args=[], named_args=[],
            status=InterpretationStatus.INDETERMINATE,
            diagnostics=["constructor unresolved: %s" % ctor.reason],
            blob=blob, blob_rva=blob_rva, consumed=0, trailing=b"",
            provenance=get_provenance(),
        )

    try:
        parsed = _parse_method_signature(ctor.blob or b"", tables)
    except _DecodeError as e:
        return CustomAttributeInterpretation(
            parent=parent, constructor=ctor, fixed_args=[], named_args=[],
            status=InterpretationStatus.INDETERMINATE,
            diagnostics=["constructor signature unreadable: %s" % e.reason],
            blob=blob, blob_rva=blob_rva, consumed=0, trailing=b"",
            provenance=get_provenance(),
        )

    result = _decode_payload(ctor, parsed, blob, tables, blob_rva, parent)
    if ctor.reason and result.status == InterpretationStatus.COMPLETE:
        result.status = InterpretationStatus.PARTIAL
    if ctor.reason:
        result.diagnostics.append("constructor source note: %s" % ctor.reason)
    return result


def decode_custom_attributes(pe: Any) -> List[CustomAttributeInterpretation]:
    """Decode all CustomAttribute rows of a dnfile ``dnPE`` object."""
    net = getattr(pe, "net", None)
    tables = getattr(net, "mdtables", None)
    if tables is None:
        return []
    table = _get_table(tables, "CustomAttribute")
    if table is None:
        return []
    return [decode_custom_attribute(row, tables) for row in getattr(table, "rows", None) or [] if row is not None]


def format_interpretation(result: CustomAttributeInterpretation, index: Optional[int] = None) -> str:
    """Render an interpretation as human-readable text for reversers."""
    prefix = "CustomAttribute[%d]" % index if index is not None else "CustomAttribute"
    lines = [
        "%s parent=%s" % (prefix, result.parent or "<unknown>"),
        "  ctor: %s %s::%s external=%s status=%s"
        % (
            result.constructor.token,
            result.constructor.declaring_type or "<unknown>",
            result.constructor.name or "<unknown>",
            result.constructor.external,
            result.constructor.status.value,
        ),
        "  signature-basis: %s" % result.constructor.basis,
    ]
    if result.constructor.reason:
        lines.append("  ctor-reason: %s" % result.constructor.reason)
    lines.append("  result: %s" % result.status.value)
    for arg in result.fixed_args:
        lines.append("  fixed[%d]: type=%s value=%r status=%s"
                     % (arg.position, arg.declared_type, arg.value, arg.status.value))
        if arg.extra.get("enum_member") is not None:
            lines.append("    enum-member: %s" % arg.extra["enum_member"])
        if arg.extra.get("enum_member_unmatched"):
            lines.append("    enum-member: <no Constant table member for this value>")
        if arg.reason:
            lines.append("    reason: %s" % arg.reason)
        for basis in arg.basis:
            lines.append("    basis: %s" % basis)
    for arg in result.named_args:
        label = "%s[%d] name=%s" % (arg.extra.get("named_kind", "named"), arg.position, arg.name)
        lines.append("  %s: type=%s value=%r status=%s"
                     % (label, arg.declared_type, arg.value, arg.status.value))
        if arg.extra.get("enum_member") is not None:
            lines.append("    enum-member: %s" % arg.extra["enum_member"])
        if arg.extra.get("enum_member_unmatched"):
            lines.append("    enum-member: <no Constant table member for this value>")
        if arg.reason:
            lines.append("    reason: %s" % arg.reason)
        for basis in arg.basis:
            lines.append("    basis: %s" % basis)
    lines.append("  payload: %d byte(s), consumed=%d, trailing=%d"
                 % (len(result.blob or b""), result.consumed, len(result.trailing)))
    if result.trailing:
        lines.append("  trailing-bytes: %s" % result.trailing.hex(" "))
    for diagnostic in result.diagnostics:
        lines.append("  diagnostic: %s" % diagnostic)
    lines.append("  provenance: assembly_loaded=%s attribute_instantiated=%s analyzed_file_imported=%s"
                 % (result.provenance["assembly_loaded"], result.provenance["attribute_instantiated"],
                    result.provenance["analyzed_file_imported"]))
    return "\n".join(lines)
