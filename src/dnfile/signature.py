# -*- coding: utf-8 -*-
"""
Read-only interpretation of CLR metadata signatures.

Signatures are stored as blob heap entries (see ECMA-335 II.23.2) and describe
method prototypes, fields, and local variables.  This module interprets the
blob grammar only.  It never loads the CLR and never executes or instantiates
the assembly being inspected.

Where a type reference is present, the raw TypeDefOrRef coded index is linked
back to its metadata table (TypeDef, TypeRef, or TypeSpec) when a metadata
tables object is supplied.  A missing table or row is reported, not guessed.

Malformed input is not repaired.  Truncated or unsupported elements become
:class:`UnsupportedType` nodes that retain the bytes from the element's start,
the unread remainder, and the structural path at which parsing stopped.
"""
from typing import Any, Dict, List, Union, Optional

from . import utils

__all__ = (
    "MetadataToken",
    "TypeSignature",
    "UnsupportedType",
    "MethodSignature",
    "FieldSignature",
    "LocalSignature",
    "UnsupportedSignature",
    "ParsedSignature",
    "parse_signature",
    "parse_method_signature",
    "parse_field_signature",
    "parse_local_signature",
    "parse_row_signature",
    "row_signature_evidence",
    "signature_summary",
)


####
# ECMA-335 II.23.1.16 element types.
ELEMENT_TYPES = {
    0x01: "VOID",
    0x02: "BOOLEAN",
    0x03: "CHAR",
    0x04: "I1",
    0x05: "U1",
    0x06: "I2",
    0x07: "U2",
    0x08: "I4",
    0x09: "U4",
    0x0A: "I8",
    0x0B: "U8",
    0x0C: "R4",
    0x0D: "R8",
    0x0E: "STRING",
    0x0F: "PTR",
    0x10: "BYREF",
    0x11: "VALUETYPE",
    0x12: "CLASS",
    0x13: "VAR",
    0x14: "ARRAY",
    0x15: "GENERICINST",
    0x16: "TYPEDBYREF",
    0x18: "INTPTR",
    0x19: "UINTPTR",
    0x1B: "FNPTR",
    0x1C: "OBJECT",
    0x1D: "SZARRAY",
    0x1E: "MVAR",
    0x1F: "CMOD_REQD",
    0x20: "CMOD_OPT",
    0x21: "INTERNAL",
    0x41: "SENTINEL",
    0x45: "PINNED",
}

# Element types that stand alone, with no following bytes.
SIMPLE_ELEMENT_TYPES = frozenset((
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x16, 0x18, 0x19, 0x1C,
))

CALLING_CONVENTIONS = {
    0x00: "DEFAULT",
    0x01: "C",
    0x02: "STDCALL",
    0x03: "THISCALL",
    0x04: "FASTCALL",
    0x05: "VARARG",
    0x06: "FIELD",
    0x07: "LOCALSIG",
    0x08: "PROPERTY",
    0x09: "UNMANAGED",
    0x0A: "GENERICINST",
    0x0B: "NATIVEVARARG",
}

METHOD_CALLING_CONVENTIONS = frozenset((
    "DEFAULT", "C", "STDCALL", "THISCALL", "FASTCALL", "VARARG", "UNMANAGED", "NATIVEVARARG",
))

TYPE_DEF_OR_REF_TABLES = ("TypeDef", "TypeRef", "TypeSpec")
TYPE_DEF_OR_REF_NUMBERS = (2, 1, 27)


class MetadataToken(object):
    """A TypeDefOrRef coded index, optionally resolved to its metadata table.

    ``value`` is always the raw coded index read from the blob.  ``table_name``
    and ``row_index`` are derived arithmetically from the tag; when ``row`` is
    None, ``resolution`` explains whether no table was supplied, the table was
    missing, or the row was out of range.
    """

    tag_bits = 2
    table_names = TYPE_DEF_OR_REF_TABLES

    def __init__(self, value: int, mdtables=None):
        self.value = value
        self.tag = value & 0x03
        self.table_name: Optional[str] = None
        self.table_number: Optional[int] = None
        self.row_index = value >> self.tag_bits
        self.table = None
        self.row = None
        if self.tag >= len(self.table_names):
            # TypeDefOrRef uses two tag bits but only three tags are defined.
            self.resolution = "invalid-tag"
            return
        self.table_name = self.table_names[self.tag]
        self.table_number = TYPE_DEF_OR_REF_NUMBERS[self.tag]
        self.resolution = "unresolved"
        self._resolve(mdtables)

    def _resolve(self, mdtables):
        if self.row_index == 0:
            self.resolution = "null-token"
            return
        if mdtables is None:
            return
        table = getattr(mdtables, self.table_name, None)
        if table is None:
            self.resolution = "table-missing"
            return
        self.table = table
        try:
            row = table.get_with_row_index(self.row_index)
        except (IndexError, TypeError):
            self.resolution = "row-missing"
            return
        if row is None:
            self.resolution = "row-missing"
            return
        self.row = row
        self.resolution = "resolved"

    @property
    def resolved(self) -> bool:
        return self.resolution == "resolved"

    @property
    def name(self) -> Optional[str]:
        """Best-effort namespace-qualified name of the referenced type.

        TypeSpec rows describe constructed types rather than names, so no
        name is invented for them.
        """
        row = self.row
        if row is None or self.table_name == "TypeSpec":
            return None
        namespace = str(getattr(row, "TypeNamespace", "") or "")
        name = str(getattr(row, "TypeName", "") or "")
        if not name:
            return None
        return f"{namespace}.{name}" if namespace else name

    def __repr__(self) -> str:
        return (
            f"MetadataToken(value=0x{self.value:x}, table={self.table_name!r}, "
            f"row={self.row_index}, resolution={self.resolution!r})"
        )

    def __str__(self) -> str:
        if self.name:
            return self.name
        return f"token({self.table_name}, row {self.row_index})"


class TypeSignature(object):
    """A structurally interpreted type, retaining the bytes it consumed.

    When a prefix element such as PTR or SZARRAY contains something that could
    not be interpreted, the node is still returned with a structured wrapper;
    ``incomplete`` and ``failure_path`` point at the uninterpreted subtree so
    callers do not have to synthesise a replacement type.
    """

    def __init__(
        self,
        element_type: str,
        *,
        raw: bytes = b"",
        path: str = "",
        number: Optional[int] = None,
        token: Optional[MetadataToken] = None,
        inner: Optional["TypeSignature"] = None,
        arguments: Optional[List["TypeSignature"]] = None,
        generic_kind: Optional[str] = None,
        array_rank: Optional[int] = None,
        array_sizes: Optional[List[int]] = None,
        array_lower_bounds: Optional[List[int]] = None,
        signature: Optional["MethodSignature"] = None,
        pinned: bool = False,
    ):
        self.element_type = element_type
        self.raw = raw
        self.path = path
        self.number = number
        self.token = token
        self.inner = inner
        self.arguments = arguments
        self.generic_kind = generic_kind
        self.array_rank = array_rank
        self.array_sizes = array_sizes
        self.array_lower_bounds = array_lower_bounds
        self.signature = signature
        self.pinned = pinned

    @property
    def unparsed(self) -> Optional["UnsupportedType"]:
        return _find_unsupported(self)

    @property
    def incomplete(self) -> bool:
        return self.unparsed is not None

    @property
    def failure_path(self) -> Optional[str]:
        node = self.unparsed
        return node.path if node is not None else None

    @property
    def kind(self) -> str:
        return "type"

    @property
    def is_reference_type_hint(self) -> Optional[bool]:
        """Whether the signature syntax says ``class`` rather than ``valuetype``.

        This is a syntactic hint only.  A TypeDef token may still describe a
        value type when the signature used the CLASS element type, so callers
        must not treat it as a runtime kind.
        """
        if self.element_type == "CLASS":
            return True
        if self.element_type in ("VALUETYPE", "BOOLEAN", "CHAR", "I1", "U1", "I2", "U2", "I4", "U4", "I8", "U8", "R4", "R8", "INTPTR", "UINTPTR", "TYPEDBYREF"):
            return False
        if self.element_type == "GENERICINST" and self.generic_kind in ("CLASS", "VALUETYPE"):
            return self.generic_kind == "CLASS"
        return None

    def to_programmer_string(self) -> str:
        et = self.element_type
        simple = {
            "VOID": "void",
            "BOOLEAN": "bool",
            "CHAR": "char",
            "I1": "sbyte",
            "U1": "byte",
            "I2": "short",
            "U2": "ushort",
            "I4": "int",
            "U4": "uint",
            "I8": "long",
            "U8": "ulong",
            "R4": "float",
            "R8": "double",
            "STRING": "string",
            "OBJECT": "object",
            "INTPTR": "native int",
            "UINTPTR": "native uint",
            "TYPEDBYREF": "typedref",
        }
        if et in simple:
            return simple[et]
        if et == "VAR":
            return f"!{self.number}"
        if et == "MVAR":
            return f"!!{self.number}"
        if et == "PTR":
            return f"{self.inner.to_programmer_string()}*" if self.inner else "*"
        if et == "BYREF":
            return f"{self.inner.to_programmer_string()}&" if self.inner else "&"
        if et == "SZARRAY":
            return f"{self.inner.to_programmer_string()}[]" if self.inner else "[]"
        if et == "ARRAY":
            base = self.inner.to_programmer_string() if self.inner else "?"
            dims = "," * max((self.array_rank or 1) - 1, 0)
            text = f"{base}[{dims}]"
            if self.array_sizes or self.array_lower_bounds:
                text += f"(sizes={self.array_sizes}, lower={self.array_lower_bounds})"
            return text
        if et in ("CLASS", "VALUETYPE"):
            prefix = "class" if et == "CLASS" else "valuetype"
            name = self.token.name if self.token else None
            return f"{prefix} {name}" if name else f"{prefix} {self.token}"
        if et == "GENERICINST":
            name = self.token.name if self.token else None
            kind = (self.generic_kind or "CLASS").lower()
            args = ", ".join(argument.to_programmer_string() for argument in (self.arguments or []))
            target = name if name else self.token
            nested = f"{target}<{args}>"
            if not args:
                return f"{kind} {target}"
            return nested if self.token is not None and self.token.table_name == "TypeDef" else f"{kind} {nested}"
        if et in ("CMOD_REQD", "CMOD_OPT"):
            modifier = "modreq" if et == "CMOD_REQD" else "modopt"
            name = self.token.name if self.token else None
            target = name if name else self.token
            inner = self.inner.to_programmer_string() if self.inner else "?"
            return f"{modifier}({target}) {inner}"
        if et == "PINNED":
            return f"pinned {self.inner.to_programmer_string()}" if self.inner else "pinned"
        if et == "FNPTR":
            return f"method {self.signature.to_programmer_string()}" if self.signature else "method *"
        if et == "SENTINEL":
            return "..."
        return et.lower()

    def __repr__(self) -> str:
        return f"TypeSignature(element_type={self.element_type!r}, path={self.path!r})"

    def __str__(self) -> str:
        return self.to_programmer_string()


class UnsupportedType(TypeSignature):
    """A type element that could not be interpreted.

    ``raw`` is every byte from the element's first byte to the end of the blob.
    ``consumed`` is the structurally recognised prefix (normally empty when the
    failure happened at the element's first byte), and ``remaining`` is the
    unread tail.  No placeholder type is invented for either part.
    """

    def __init__(
        self,
        raw: bytes,
        path: str,
        reason: str,
        *,
        element_byte: Optional[int] = None,
        consumed: bytes = b"",
    ):
        super().__init__("UNKNOWN", raw=raw, path=path)
        self.reason = reason
        self.element_byte = element_byte
        self.consumed = consumed
        self.remaining = raw[len(consumed):]

    @property
    def kind(self) -> str:
        return "unsupported-type"

    @property
    def unparsed(self) -> "UnsupportedType":
        return self

    @property
    def incomplete(self) -> bool:
        return True

    @property
    def failure_path(self) -> str:
        return self.path

    def to_programmer_string(self) -> str:
        return f"<unsupported: {self.reason}>"

    def __repr__(self) -> str:
        return f"UnsupportedType(path={self.path!r}, reason={self.reason!r}, raw={self.raw.hex()!r})"


class MethodSignature(object):
    kind = "method"

    def __init__(
        self,
        calling_convention: str,
        has_this: bool,
        explicit_this: bool,
        generic_param_count: int,
        return_type: TypeSignature,
        parameters: List[TypeSignature],
        *,
        raw: bytes = b"",
        signature_flags: int = 0,
        sentinel_index: Optional[int] = None,
        declared_parameter_count: Optional[int] = None,
        incomplete: bool = False,
        failure_path: Optional[str] = None,
    ):
        self.calling_convention = calling_convention
        self.has_this = has_this
        self.explicit_this = explicit_this
        self.generic_param_count = generic_param_count
        self.return_type = return_type
        self.parameters = parameters
        self.raw = raw
        self.signature_flags = signature_flags
        self.sentinel_index = sentinel_index
        self.declared_parameter_count = declared_parameter_count if declared_parameter_count is not None else len(parameters)
        self.incomplete = incomplete
        self.failure_path = failure_path
        self.trailing = b""

    @property
    def parameter_count(self) -> int:
        """Number of parameters declared by the blob (SENTINEL excluded)."""
        return self.declared_parameter_count

    @property
    def interpreted_parameter_count(self) -> int:
        """Number of parameters successfully interpreted before any failure."""
        return len(self.parameters)

    def to_programmer_string(self, name: Optional[str] = None) -> str:
        ret = self.return_type.to_programmer_string() if self.return_type is not None else "?"
        parameter_text = [parameter.to_programmer_string() for parameter in self.parameters]
        if self.sentinel_index is not None:
            parameter_text.insert(min(self.sentinel_index, len(parameter_text)), "...")
        params = ", ".join(parameter_text)
        if self.incomplete:
            # Annotate the failure; the omitted parameters were never read.
            suffix = f" <incomplete at {self.failure_path}>"
        else:
            suffix = ""
        body = f"{ret} {name}({params})" if name else f"{ret}({params})"
        prefix = []
        if self.has_this:
            prefix.append("instance")
        if self.explicit_this:
            prefix.append("explicit")
        if self.generic_param_count:
            prefix.append(f"generic<{self.generic_param_count}>")
        if self.calling_convention not in ("DEFAULT", ""):
            prefix.append(self.calling_convention.lower())
        text = " ".join(prefix + [body]) if prefix else body
        if self.trailing:
            text += f" <unparsed {self.trailing.hex()}>"
        return text + suffix

    def __repr__(self) -> str:
        return (
            f"MethodSignature(calling_convention={self.calling_convention!r}, has_this={self.has_this!r}, "
            f"generic_param_count={self.generic_param_count!r}, return_type={self.return_type!r}, "
            f"parameters={self.parameters!r}, incomplete={self.incomplete!r})"
        )

    def __str__(self) -> str:
        return self.to_programmer_string()


class FieldSignature(object):
    kind = "field"

    def __init__(self, field_type: TypeSignature, *, raw: bytes = b"", incomplete: bool = False, failure_path: Optional[str] = None):
        self.field_type = field_type
        self.raw = raw
        self.incomplete = incomplete
        self.failure_path = failure_path
        self.trailing = b""

    def to_programmer_string(self, name: Optional[str] = None) -> str:
        text = f"{self.field_type.to_programmer_string()} {name}" if name else self.field_type.to_programmer_string()
        if self.trailing:
            text += f" <unparsed {self.trailing.hex()}>"
        return text

    def __repr__(self) -> str:
        return f"FieldSignature(field_type={self.field_type!r}, incomplete={self.incomplete!r})"


class LocalSignature(object):
    kind = "locals"

    def __init__(self, locals_: List[TypeSignature], *, raw: bytes = b"", incomplete: bool = False, failure_path: Optional[str] = None):
        self.locals = locals_
        self.raw = raw
        self.incomplete = incomplete
        self.failure_path = failure_path
        self.trailing = b""

    def to_programmer_string(self) -> str:
        text = "locals(" + ", ".join(local.to_programmer_string() for local in self.locals) + ")"
        if self.trailing:
            text += f" <unparsed {self.trailing.hex()}>"
        return text

    def __repr__(self) -> str:
        return f"LocalSignature(locals={self.locals!r}, incomplete={self.incomplete!r})"


class UnsupportedSignature(object):
    """Whole-blob failure; preserves the entire original blob and path."""

    def __init__(self, raw: bytes, reason: str, path: str = "", calling_convention: Optional[str] = None):
        self.raw = raw
        self.reason = reason
        self.path = path
        self.calling_convention = calling_convention

    @property
    def kind(self) -> str:
        return "unsupported"

    @property
    def incomplete(self) -> bool:
        return True

    def to_programmer_string(self) -> str:
        return f"<unsupported signature: {self.reason}>"

    def __repr__(self) -> str:
        return f"UnsupportedSignature(reason={self.reason!r}, path={self.path!r}, raw={self.raw.hex()!r})"


ParsedSignature = Union[MethodSignature, FieldSignature, LocalSignature, UnsupportedSignature]


def _find_unsupported(node) -> Optional[UnsupportedType]:
    """Depth-first search for the first uninterpreted type in a subtree."""
    if isinstance(node, UnsupportedType):
        return node
    if node is None:
        return None
    found = _find_unsupported(getattr(node, "inner", None))
    if found is not None:
        return found
    for argument in getattr(node, "arguments", None) or []:
        found = _find_unsupported(argument)
        if found is not None:
            return found
    signature = getattr(node, "signature", None)
    if signature is not None:
        found = _find_unsupported(getattr(signature, "return_type", None))
        if found is not None:
            return found
        for parameter in getattr(signature, "parameters", None) or []:
            found = _find_unsupported(parameter)
            if found is not None:
                return found
    return None


class _SignatureError(Exception):
    def __init__(self, reason: str, path: str):
        super().__init__(reason)
        self.reason = reason
        self.path = path


class _Truncated(_SignatureError):
    pass


class _Malformed(_SignatureError):
    pass


def _decode_compressed_signed(value: int, size: int) -> int:
    """ECMA-335 II.23.2 signed compressed integers are rotated right by one.

    The encoded field widths are 7, 14, and 29 bits (the 4-byte form spends
    three leading bits identifying its length).
    """
    bits = 29 if size == 4 else size * 7
    rotated = ((value >> 1) | ((value & 1) << (bits - 1))) & ((1 << bits) - 1)
    if rotated & (1 << (bits - 1)):
        rotated -= 1 << bits
    return rotated


class _SignatureReader(object):
    #: Prevent a crafted blob from exhausting the Python call stack.
    max_type_depth = 64

    def __init__(self, raw: bytes, mdtables=None):
        self.raw = bytes(raw or b"")
        self.offset = 0
        self.mdtables = mdtables
        self.depth = 0

    def remaining(self) -> bytes:
        return self.raw[self.offset:]

    def eof(self) -> bool:
        return self.offset >= len(self.raw)

    def read_byte(self, path: str) -> int:
        if self.eof():
            raise _Truncated("unexpected end of signature blob", path)
        value = self.raw[self.offset]
        self.offset += 1
        return value

    def read_compressed_u32(self, path: str, signed: bool = False) -> int:
        data = self.remaining()
        if not data:
            raise _Truncated("unexpected end of signature blob while reading compressed integer", path)
        first = data[0]
        if first & 0x80 == 0:
            size = 1
        elif first & 0x40 == 0:
            size = 2
        elif first & 0x20 == 0:
            size = 4
        else:
            raise _Malformed(f"invalid compressed integer leading byte 0x{first:02x}", path)
        if len(data) < size:
            raise _Truncated(
                f"truncated compressed integer: need {size} bytes, have {len(data)}",
                path,
            )
        result = utils.read_compressed_int(data[:size])
        if result is None:
            raise _Malformed(f"invalid compressed integer at offset 0x{self.offset:x}", path)
        value, _ = result
        self.offset += size
        return _decode_compressed_signed(value, size) if signed else value

    def read_token(self, path: str) -> MetadataToken:
        value = self.read_compressed_u32(path)
        if value & 0x03 >= len(TYPE_DEF_OR_REF_TABLES):
            raise _Malformed(f"invalid TypeDefOrRef coded index: 0x{value:x} (tag 3 is undefined)", path)
        return MetadataToken(value, self.mdtables)

    def _unsupported(self, start: int, path: str, reason: str, element_byte: Optional[int] = None) -> UnsupportedType:
        return UnsupportedType(
            raw=self.raw[start:],
            path=path,
            reason=reason,
            element_byte=element_byte,
            consumed=self.raw[start:self.offset],
        )

    def read_type(self, path: str) -> TypeSignature:
        if self.depth >= self.max_type_depth:
            start = self.offset
            return UnsupportedType(
                raw=self.raw[start:],
                path=path,
                reason=f"signature nesting exceeds {self.max_type_depth} levels",
            )
        self.depth += 1
        try:
            return self._read_type(path)
        finally:
            self.depth -= 1

    def _read_type(self, path: str) -> TypeSignature:
        start = self.offset
        try:
            element = self.read_byte(path)
        except _Truncated as error:
            return self._unsupported(start, error.path, error.reason)

        name = ELEMENT_TYPES.get(element)
        if element in SIMPLE_ELEMENT_TYPES:
            return TypeSignature(name, raw=self.raw[start:self.offset], path=path)

        try:
            if element == 0x0F:  # PTR
                inner = self.read_type(path + ".inner")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, inner=inner)
            if element == 0x10:  # BYREF
                inner = self.read_type(path + ".inner")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, inner=inner)
            if element in (0x11, 0x12):  # VALUETYPE, CLASS
                token = self.read_token(path + ".token")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, token=token)
            if element in (0x13, 0x1E):  # VAR, MVAR
                number = self.read_compressed_u32(path + ".number")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, number=number)
            if element == 0x14:  # ARRAY
                return self._read_array(start, name, path)
            if element == 0x15:  # GENERICINST
                kind_byte = self.read_byte(path + ".class-or-valuetype")
                if kind_byte == 0x11:
                    generic_kind = "VALUETYPE"
                elif kind_byte == 0x12:
                    generic_kind = "CLASS"
                else:
                    return self._unsupported(
                        start,
                        path + ".class-or-valuetype",
                        f"generic instance has invalid class/valuetype marker 0x{kind_byte:02x}",
                        element_byte=kind_byte,
                    )
                token = self.read_token(path + ".token")
                count = self.read_compressed_u32(path + ".argument-count")
                arguments: List[TypeSignature] = []
                for index in range(count):
                    arguments.append(self.read_type(f"{path}.argument[{index}]"))
                return TypeSignature(
                    name,
                    raw=self.raw[start:self.offset],
                    path=path,
                    token=token,
                    arguments=arguments,
                    generic_kind=generic_kind,
                )
            if element == 0x1B:  # FNPTR
                method = self.read_method_signature(path + ".signature")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, signature=method)
            if element == 0x1D:  # SZARRAY
                inner = self.read_type(path + ".inner")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, inner=inner)
            if element in (0x1F, 0x20):  # CMOD_REQD, CMOD_OPT
                token = self.read_token(path + ".modifier")
                inner = self.read_type(path + ".inner")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, token=token, inner=inner)
            if element == 0x45:  # PINNED
                inner = self.read_type(path + ".inner")
                return TypeSignature(name, raw=self.raw[start:self.offset], path=path, inner=inner, pinned=True)
        except _SignatureError as error:
            return self._unsupported(start, error.path, error.reason, element_byte=element)

        if element == 0x21:
            reason = "INTERNAL element type is not valid in metadata signatures"
        elif element == 0x41:
            reason = "SENTINEL is only valid in a vararg method parameter list"
        else:
            reason = f"unsupported element type 0x{element:02x}"
        return self._unsupported(start, path, reason, element_byte=element)

    def _read_array(self, start: int, name: str, path: str) -> TypeSignature:
        inner = self.read_type(path + ".inner")
        rank = self.read_compressed_u32(path + ".rank")
        size_count = self.read_compressed_u32(path + ".size-count")
        if size_count > rank:
            return self._unsupported(
                start,
                path + ".size-count",
                f"array declares {size_count} sizes for rank {rank}",
            )
        sizes = [self.read_compressed_u32(f"{path}.size[{i}]") for i in range(size_count)]
        lower_count = self.read_compressed_u32(path + ".lower-bound-count")
        if lower_count > rank:
            return self._unsupported(
                start,
                path + ".lower-bound-count",
                f"array declares {lower_count} lower bounds for rank {rank}",
            )
        lower_bounds = [
            self.read_compressed_u32(f"{path}.lower-bound[{i}]", signed=True)
            for i in range(lower_count)
        ]
        if rank == 0:
            return self._unsupported(
                start,
                path + ".rank",
                "array rank cannot be zero",
            )
        return TypeSignature(
            name,
            raw=self.raw[start:self.offset],
            path=path,
            inner=inner,
            array_rank=rank,
            array_sizes=sizes,
            array_lower_bounds=lower_bounds,
        )

    def read_method_signature(self, path: str = "$") -> MethodSignature:
        flags = self.read_byte(path + ".flags")
        convention = CALLING_CONVENTIONS.get(flags & 0x0F)
        if convention not in METHOD_CALLING_CONVENTIONS:
            raise _Malformed(f"not a method calling convention: 0x{flags & 0x0F:02x}", path + ".flags")
        generic_param_count = 0
        if flags & 0x10:
            generic_param_count = self.read_compressed_u32(path + ".generic-param-count")
        parameter_count = self.read_compressed_u32(path + ".parameter-count")
        return_type = self.read_type(path + ".return")
        parameters: List[TypeSignature] = []
        sentinel_index = None
        first_unsupported = _find_unsupported(return_type)
        incomplete = first_unsupported is not None
        failure_path = first_unsupported.path if first_unsupported is not None else None
        index = 0
        while not incomplete and index < parameter_count:
            param_path = f"{path}.parameter[{index}]"
            if self.raw[self.offset:self.offset + 1] == b"\x41":
                if convention != "VARARG":
                    raise _Malformed("SENTINEL in a non-vararg method signature", param_path)
                self.offset += 1
                sentinel_index = index
                if index == parameter_count - 1 and self.eof():
                    raise _Malformed("SENTINEL at the end of a vararg parameter list", param_path)
                continue
            param = self.read_type(param_path)
            parameters.append(param)
            if not incomplete:
                first_unsupported = _find_unsupported(param)
                if first_unsupported is not None:
                    incomplete = True
                    failure_path = first_unsupported.path
            index += 1
        return MethodSignature(
            convention,
            has_this=bool(flags & 0x20),
            explicit_this=bool(flags & 0x40),
            generic_param_count=generic_param_count,
            return_type=return_type,
            parameters=parameters,
            raw=self.raw,
            signature_flags=flags & 0xF0,
            sentinel_index=sentinel_index,
            declared_parameter_count=parameter_count,
            incomplete=incomplete,
            failure_path=failure_path,
        )

    def read_field_signature(self, path: str = "$") -> FieldSignature:
        flags = self.read_byte(path + ".flags")
        convention = CALLING_CONVENTIONS.get(flags & 0x0F)
        if convention != "FIELD":
            raise _Malformed(f"not a field calling convention: 0x{flags & 0x0F:02x}", path + ".flags")
        field_type = self.read_type(path + ".field")
        first_unsupported = _find_unsupported(field_type)
        return FieldSignature(
            field_type,
            raw=self.raw,
            incomplete=first_unsupported is not None,
            failure_path=first_unsupported.path if first_unsupported is not None else None,
        )

    def read_local_signature(self, path: str = "$") -> LocalSignature:
        flags = self.read_byte(path + ".flags")
        convention = CALLING_CONVENTIONS.get(flags & 0x0F)
        if convention != "LOCALSIG":
            raise _Malformed(f"not a local variable calling convention: 0x{flags & 0x0F:02x}", path + ".flags")
        count = self.read_compressed_u32(path + ".local-count")
        locals_: List[TypeSignature] = []
        incomplete = False
        failure_path = None
        for index in range(count):
            local = self.read_type(f"{path}.local[{index}]")
            locals_.append(local)
            first_unsupported = _find_unsupported(local)
            if first_unsupported is not None:
                incomplete = True
                failure_path = first_unsupported.path
                break
        return LocalSignature(locals_, raw=self.raw, incomplete=incomplete, failure_path=failure_path)


def _as_bytes(blob) -> bytes:
    if blob is None:
        return b""
    if hasattr(blob, "value_bytes"):
        return bytes(blob.value_bytes())
    if isinstance(blob, (bytes, bytearray, memoryview)):
        return bytes(blob)
    if hasattr(blob, "value"):
        return bytes(blob.value)
    return bytes(blob)


####
# public helpers


def parse_signature(blob, mdtables=None, path: str = "$") -> ParsedSignature:
    """Interpret a signature blob, choosing the kind from its first byte."""
    raw = _as_bytes(blob)
    if not raw:
        return UnsupportedSignature(raw, "empty signature blob", path=path)
    convention = CALLING_CONVENTIONS.get(raw[0] & 0x0F)
    reader = _SignatureReader(raw, mdtables)
    try:
        if convention in METHOD_CALLING_CONVENTIONS:
            parsed = reader.read_method_signature(path)
            parsed.trailing = reader.remaining()
            return parsed
        if convention == "FIELD":
            parsed = reader.read_field_signature(path)
            parsed.trailing = reader.remaining()
            return parsed
        if convention == "LOCALSIG":
            parsed = reader.read_local_signature(path)
            parsed.trailing = reader.remaining()
            return parsed
    except _SignatureError as error:
        return UnsupportedSignature(
            raw,
            error.reason,
            path=error.path or path,
            calling_convention=convention,
        )
    return UnsupportedSignature(
        raw,
        f"unsupported signature kind 0x{raw[0]:02x}",
        path=path,
        calling_convention=convention,
    )


def parse_method_signature(blob, mdtables=None, path: str = "$") -> Union[MethodSignature, UnsupportedSignature]:
    raw = _as_bytes(blob)
    reader = _SignatureReader(raw, mdtables)
    try:
        parsed = reader.read_method_signature(path)
        parsed.trailing = reader.remaining()
        return parsed
    except _SignatureError as error:
        return UnsupportedSignature(raw, error.reason, path=error.path or path)


def parse_field_signature(blob, mdtables=None, path: str = "$") -> Union[FieldSignature, UnsupportedSignature]:
    raw = _as_bytes(blob)
    reader = _SignatureReader(raw, mdtables)
    try:
        parsed = reader.read_field_signature(path)
        parsed.trailing = reader.remaining()
        return parsed
    except _SignatureError as error:
        return UnsupportedSignature(raw, error.reason, path=error.path or path)


def parse_local_signature(blob, mdtables=None, path: str = "$") -> Union[LocalSignature, UnsupportedSignature]:
    raw = _as_bytes(blob)
    reader = _SignatureReader(raw, mdtables)
    try:
        parsed = reader.read_local_signature(path)
        parsed.trailing = reader.remaining()
        return parsed
    except _SignatureError as error:
        return UnsupportedSignature(raw, error.reason, path=error.path or path)


def parse_row_signature(row, kind: Optional[str] = None) -> ParsedSignature:
    """Interpret the ``Signature`` blob of a metadata table row.

    The row's table supplies the metadata context used to resolve type tokens.
    The grammar is selected from the blob's first byte, which is the only
    reliable discriminator for tables such as StandAloneSig that hold both
    local-variable and method signatures.
    """
    signature = getattr(row, "Signature", None)
    table = getattr(row, "_table", None)
    mdtables = getattr(table, "_mdtables", None) if table is not None else None
    table_name = getattr(table, "name", None)
    path = kind
    if path is None:
        path = {
            "MethodDef": "method",
            "Field": "field",
            "MemberRef": "methodref",
            "StandAloneSig": "standalonesig",
        }.get(table_name, "signature")
    return parse_signature(signature, mdtables, path=path)


def row_signature_evidence(row) -> Dict[str, Any]:
    """Return the raw metadata token and blob evidence for a row signature."""
    table = getattr(row, "_table", None)
    row_index = getattr(row, "_row_index", None)
    signature = getattr(row, "Signature", None)
    table_name = getattr(table, "name", None)
    table_number = getattr(table, "number", None)
    token = None
    if table_number is not None and row_index is not None:
        token = (table_number << 24) | row_index
    blob_index = None
    if getattr(row, "struct", None) is not None:
        blob_index = getattr(row.struct, "Signature_BlobIndex", None)
    blob = _as_bytes(signature)
    return {
        "table": table_name,
        "table_number": table_number,
        "row_index": row_index,
        "token": token,
        "token_hex": f"0x{token:08x}" if token is not None else None,
        "blob_index": blob_index,
        "blob": blob,
        "blob_hex": blob.hex(),
        "blob_rva": getattr(signature, "rva", None),
    }


def signature_summary(row) -> Dict[str, Any]:
    """Structured representation plus raw evidence for a metadata row."""
    evidence = row_signature_evidence(row)
    parsed = parse_row_signature(row)
    evidence["parsed"] = parsed
    evidence["parsed_kind"] = parsed.kind
    return evidence
