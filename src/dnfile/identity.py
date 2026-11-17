# -*- coding: utf-8 -*-
"""
Read-only structural identity comparison for .NET metadata.

This module never loads or executes an assembly.  It opens each input with
dnfile only to parse metadata, records the file digest before parsing, and
reports mappings with the original token, table, row number, and file offset
on both sides.

Identity rules
--------------

TypeDef
    namespace + full nesting chain + generic-parameter signature.
    The bare type name is never sufficient.

MethodDef
    owning TypeDef + method name + structured signature (calling convention,
    return type, parameter types, generic arity) + generic-parameter names.
    Same-name overloads therefore never merge.

TypeDefOrRef values inside signatures
    resolved to the referenced type's semantic identity.  Raw tokens and heap
    offsets are deliberately not part of an identity: row renumbering or a
    different blob/string location does not, by itself, change identity.

Matching
    Only a unique one-to-one semantic match is a confirmed mapping.  Anything
    with multiple equally plausible partners is emitted as an ambiguous
    candidate set, separately from confirmed mappings and genuine changes.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple, Iterable, Optional, Sequence
from dataclasses import field, dataclass

import dnfile
from dnfile.utils import read_compressed_int

# ECMA-335 II.23.1.16 element types used by signatures.
ELEMENT_TYPE_END = 0x00
ELEMENT_TYPE_VOID = 0x01
ELEMENT_TYPE_BOOLEAN = 0x02
ELEMENT_TYPE_CHAR = 0x03
ELEMENT_TYPE_I1 = 0x04
ELEMENT_TYPE_U1 = 0x05
ELEMENT_TYPE_I2 = 0x06
ELEMENT_TYPE_U2 = 0x07
ELEMENT_TYPE_I4 = 0x08
ELEMENT_TYPE_U4 = 0x09
ELEMENT_TYPE_I8 = 0x0A
ELEMENT_TYPE_U8 = 0x0B
ELEMENT_TYPE_R4 = 0x0C
ELEMENT_TYPE_R8 = 0x0D
ELEMENT_TYPE_STRING = 0x0E
ELEMENT_TYPE_PTR = 0x0F
ELEMENT_TYPE_BYREF = 0x10
ELEMENT_TYPE_VALUETYPE = 0x11
ELEMENT_TYPE_CLASS = 0x12
ELEMENT_TYPE_VAR = 0x13
ELEMENT_TYPE_ARRAY = 0x14
ELEMENT_TYPE_GENERICINST = 0x15
ELEMENT_TYPE_TYPEDBYREF = 0x16
ELEMENT_TYPE_I = 0x18
ELEMENT_TYPE_U = 0x19
ELEMENT_TYPE_FNPTR = 0x1B
ELEMENT_TYPE_OBJECT = 0x1C
ELEMENT_TYPE_SZARRAY = 0x1D
ELEMENT_TYPE_MVAR = 0x1E
ELEMENT_TYPE_CMOD_REQD = 0x1F
ELEMENT_TYPE_CMOD_OPT = 0x20
ELEMENT_TYPE_SENTINEL = 0x41
ELEMENT_TYPE_PINNED = 0x45

_PRIMITIVE_ELEMENT_TYPES = {
    ELEMENT_TYPE_VOID: "void",
    ELEMENT_TYPE_BOOLEAN: "bool",
    ELEMENT_TYPE_CHAR: "char",
    ELEMENT_TYPE_I1: "int8",
    ELEMENT_TYPE_U1: "uint8",
    ELEMENT_TYPE_I2: "int16",
    ELEMENT_TYPE_U2: "uint16",
    ELEMENT_TYPE_I4: "int32",
    ELEMENT_TYPE_U4: "uint32",
    ELEMENT_TYPE_I8: "int64",
    ELEMENT_TYPE_U8: "uint64",
    ELEMENT_TYPE_R4: "float32",
    ELEMENT_TYPE_R8: "float64",
    ELEMENT_TYPE_STRING: "string",
    ELEMENT_TYPE_TYPEDBYREF: "typedref",
    ELEMENT_TYPE_I: "native int",
    ELEMENT_TYPE_U: "native uint",
    ELEMENT_TYPE_OBJECT: "object",
}

# Bits of the method signature calling-convention byte.
_CALLCONV_MASK = 0x0F
_CALLCONV_GENERIC = 0x10
_CALLCONV_HASTHIS = 0x20
_CALLCONV_EXPLICITTHIS = 0x40

_CALLCONV_NAMES = {
    0x00: "default",
    0x01: "cdecl",
    0x02: "stdcall",
    0x03: "thiscall",
    0x04: "fastcall",
    0x05: "vararg",
}

_TABLE_NUMBERS = {
    "Module": 0x00,
    "TypeRef": 0x01,
    "TypeDef": 0x02,
    "Field": 0x04,
    "MethodDef": 0x06,
    "Param": 0x08,
    "InterfaceImpl": 0x09,
    "MemberRef": 0x0A,
    "CustomAttribute": 0x0C,
    "StandAloneSig": 0x11,
    "TypeSpec": 0x1B,
    "Assembly": 0x20,
    "AssemblyRef": 0x23,
    "ModuleRef": 0x1A,
    "NestedClass": 0x29,
    "GenericParam": 0x2A,
}

# TypeDefOrRef coded index (2 tag bits).
_TYPEDEFORREF_TABLES = ("TypeDef", "TypeRef", "TypeSpec")


class IdentityError(Exception):
    """Raised when an input cannot be parsed as a .NET module."""


class SignatureError(Exception):
    """Raised when a metadata signature cannot be decoded."""


@dataclass(frozen=True)
class Ref:
    """A resolved metadata row reference.

    ``name`` optionally carries a human-readable scope (for example an
    AssemblyRef's name).  Row numbers and tokens are provenance, not identity.
    """

    table: str
    rid: int
    token: Optional[int] = None
    name: str = ""


@dataclass(frozen=True)
class TypeIdentity:
    """Semantic identity of a TypeDef, TypeRef, or TypeSpec."""

    kind: str
    namespace: str
    name: str
    nesting: Tuple[str, ...] = ()
    generic_params: Tuple[str, ...] = ()
    constraints: Tuple[str, ...] = ()
    scope: Optional[Ref] = None
    type_spec: Optional[str] = None

    @property
    def display(self) -> str:
        parts = []
        if self.namespace:
            parts.append(self.namespace)
        parts.extend(self.nesting)
        parts.append(self.name)
        text = ".".join(parts)
        if self.generic_params:
            params = []
            for i, name in enumerate(self.generic_params):
                if i < len(self.constraints) and self.constraints[i]:
                    params.append(name + " : " + self.constraints[i])
                else:
                    params.append(name)
            text += "<" + ", ".join(params) + ">"
        if self.type_spec:
            text += "[" + self.type_spec + "]"
        return text

    def key(self) -> Tuple[Any, ...]:
        # Nesting depth/order is meaningful.
        #
        # A TypeRef is qualified by its scope assembly, not by the TypeRef row
        # number or heap offset.  Two same-named types from different
        # assemblies must not collapse into one identity, while a scope row
        # moving during a re-layout still matches.
        scope_key = None
        if self.kind == "typeref" and self.scope is not None:
            scope_key = self.scope.name
        return (
            self.kind,
            self.namespace,
            self.name,
            tuple(self.nesting),
            tuple(self.generic_params),
            tuple(self.constraints),
            self.type_spec,
            scope_key,
        )


@dataclass(frozen=True)
class MethodIdentity:
    owner: Optional[TypeIdentity]
    name: str
    signature: str
    generic_params: Tuple[str, ...] = ()
    constraints: Tuple[str, ...] = ()

    @property
    def display(self) -> str:
        owner = self.owner.display if self.owner else "<unknown-type>"
        text = "{0}::{1}{2}".format(owner, self.name, self.signature)
        if self.generic_params:
            text += "<" + ", ".join(self.generic_params) + ">"
        return text

    def key(self) -> Tuple[Any, ...]:
        return (
            self.owner.key() if self.owner else None,
            self.name,
            self.signature,
            tuple(self.generic_params),
            tuple(self.constraints),
        )


@dataclass
class RowRecord:
    """A metadata row with identity and enough provenance to re-find it."""

    table: str
    rid: int
    token: int
    file_offset: Optional[int]
    identity: Any
    name: str = ""
    namespace: str = ""
    raw_signature: bytes = b""
    signature: Optional[str] = None
    owner: Optional[Ref] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def label(self) -> str:
        if isinstance(self.identity, MethodIdentity):
            return self.identity.display
        if isinstance(self.identity, TypeIdentity):
            return self.identity.display
        return self.name

    def evidence(self, side: "Side") -> Dict[str, Any]:
        return {
            "sha256": side.digest,
            "table": self.table,
            "rid": self.rid,
            "token": "0x{0:08x}".format(self.token),
            "file_offset": self.file_offset,
        }


@dataclass
class Side:
    """Identity data collected from one input file."""

    path: str
    digest: str
    size: int
    types: Dict[int, RowRecord]
    type_refs: Dict[int, TypeIdentity]
    methods: Dict[int, RowRecord]
    fields: Dict[int, RowRecord]
    module_name: Optional[str]
    warnings: List[str]

@dataclass
class Mapping:
    left: RowRecord
    right: RowRecord
    reason: str
    changes: Tuple[str, ...] = ()

    def to_dict(self, left: Side, right: Side) -> Dict[str, Any]:
        return {
            "identity": self.left.label(),
            "right_identity": self.right.label(),
            "reason": self.reason,
            "changes": list(self.changes),
            "left": dict(self.left.evidence(left), identity=self.left.label(),
                         name=self.left.name, signature=self.left.signature),
            "right": dict(self.right.evidence(right), identity=self.right.label(),
                          name=self.right.name, signature=self.right.signature),
        }


@dataclass
class Ambiguity:
    """Unmatched rows that cannot be assigned one-to-one."""

    kind: str
    left: Tuple[RowRecord, ...]
    right: Tuple[RowRecord, ...]
    reason: str

    def to_dict(self, left: Side, right: Side) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "left": [dict(r.evidence(left), identity=r.label(), name=r.name, signature=r.signature) for r in self.left],
            "right": [dict(r.evidence(right), identity=r.label(), name=r.name, signature=r.signature) for r in self.right],
        }


@dataclass
class Comparison:
    left: Side
    right: Side
    type_mappings: List[Mapping] = field(default_factory=list)
    type_changes: List[Mapping] = field(default_factory=list)
    method_mappings: List[Mapping] = field(default_factory=list)
    method_changes: List[Mapping] = field(default_factory=list)
    ambiguities: List[Ambiguity] = field(default_factory=list)
    removed_types: List[RowRecord] = field(default_factory=list)
    added_types: List[RowRecord] = field(default_factory=list)
    removed_methods: List[RowRecord] = field(default_factory=list)
    added_methods: List[RowRecord] = field(default_factory=list)
    naive_token_summary: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not (
            self.type_changes
            or self.method_changes
            or self.ambiguities
            or self.removed_types
            or self.added_types
            or self.removed_methods
            or self.added_methods
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "left": _side_dict(self.left),
            "right": _side_dict(self.right),
            "types": {
                "confirmed": [m.to_dict(self.left, self.right) for m in self.type_mappings],
                "changed": [m.to_dict(self.left, self.right) for m in self.type_changes],
                "removed": [dict(r.evidence(self.left), identity=r.label(), name=r.name) for r in self.removed_types],
                "added": [dict(r.evidence(self.right), identity=r.label(), name=r.name) for r in self.added_types],
            },
            "methods": {
                "confirmed": [m.to_dict(self.left, self.right) for m in self.method_mappings],
                "changed": [m.to_dict(self.left, self.right) for m in self.method_changes],
                "removed": [dict(r.evidence(self.left), identity=r.label(), name=r.name, signature=r.signature) for r in self.removed_methods],
                "added": [dict(r.evidence(self.right), identity=r.label(), name=r.name, signature=r.signature) for r in self.added_methods],
            },
            "ambiguous": [a.to_dict(self.left, self.right) for a in self.ambiguities],
            "naive_token_comparison": self.naive_token_summary,
            "notes": list(self.notes),
            "clean": self.is_clean,
        }

    def render(self) -> str:
        return _render_text(self)


def _side_dict(side: Side) -> Dict[str, Any]:
    return {
        "path": side.path,
        "sha256": side.digest,
        "size": side.size,
        "module_name": side.module_name,
        "type_defs": len(side.types),
        "type_refs": len(side.type_refs),
        "methods": len(side.methods),
        "fields": len(side.fields),
        "warnings": list(side.warnings),
    }


def file_digest(path: str) -> Tuple[str, int]:
    """Return SHA-256 and byte size of the file, before any parse."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _row_file_offset(row: Any) -> Optional[int]:
    struct = getattr(row, "struct", None)
    if struct is None:
        return None
    offset = getattr(struct, "__file_offset__", None)
    if offset is not None:
        return int(offset)
    fn = getattr(struct, "get_file_offset", None)
    if callable(fn):
        try:
            value = fn()
        except Exception:
            return None
        if value is not None:
            return int(value)
    return None


def _get_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    if not isinstance(value, str) and hasattr(value, "value"):
        inner = value.value
        if isinstance(inner, bytes):
            return inner.decode("utf-8", errors="backslashreplace")
        if isinstance(inner, str):
            return inner
    return str(value)


def _get_blob(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    raw = getattr(value, "value", None)
    if isinstance(raw, bytes):
        return raw
    fn = getattr(value, "value_bytes", None)
    if callable(fn):
        try:
            out = fn()
        except Exception:
            return b""
        if isinstance(out, bytes):
            return out
    return b""


def _token_for(table: str, rid: int) -> int:
    return ((_TABLE_NUMBERS.get(table, 0) << 24) | (rid & 0xFFFFFF))


def _coded_table(coded: int, tables: Sequence[str], tag_bits: int = 2) -> Tuple[str, int]:
    tag = coded & ((1 << tag_bits) - 1)
    rid = coded >> tag_bits
    if tag >= len(tables):
        return "<invalid>", rid
    return tables[tag], rid


class _Cursor:
    """Bounds-checked reader for metadata signature blobs."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def peek(self) -> int:
        if self.eof():
            raise SignatureError("unexpected end of signature")
        return self.data[self.pos]

    def u1(self) -> int:
        if self.eof():
            raise SignatureError("unexpected end of signature")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def compressed(self) -> int:
        result = read_compressed_int(self.data[self.pos:])
        if result is None:
            raise SignatureError("invalid compressed integer")
        value, size = result
        self.pos += size
        return value

    def compressed_signed(self) -> int:
        """Read an ECMA-335 II.23.2 compressed signed integer."""
        if self.eof():
            raise SignatureError("unexpected end of signature")
        first = self.data[self.pos]
        if first & 0x80 == 0:
            # 1 byte: 7 bits, with the sign in bit 6
            self.pos += 1
            return (first >> 2) & 0x1F if first & 0x40 else first >> 2
        if first & 0x40 == 0:
            # 2 bytes: 14 bits, sign in bit 13
            if self.pos + 2 > len(self.data):
                raise SignatureError("truncated compressed signed integer")
            value = ((first & 0x3F) << 8) | self.data[self.pos + 1]
            self.pos += 2
            return value >> 1 if not (value & 0x2000) else -(value >> 1) - 1
        if first & 0x20 == 0:
            # 4 bytes: 29 bits, sign in bit 28
            if self.pos + 4 > len(self.data):
                raise SignatureError("truncated compressed signed integer")
            value = ((first & 0x1F) << 24) | (self.data[self.pos + 1] << 16)
            value |= (self.data[self.pos + 2] << 8) | self.data[self.pos + 3]
            self.pos += 4
            return value >> 1 if not (value & 0x10000000) else -(value >> 1) - 1
        raise SignatureError("invalid compressed signed integer")


class _SignatureParser:
    """Decode signatures into text containing semantic type names only.

    ``references`` records the logical TypeDef/TypeRef targets seen while
    parsing.  The comparison uses this skeleton to tell a genuine signature
    change from a signature whose only difference is that a referenced type's
    identity changed.
    """

    def __init__(self, resolve_type: Any, resolve_ref: Any = None, skeleton: bool = False):
        self.resolve_type = resolve_type
        self.resolve_ref = resolve_ref
        self.skeleton = skeleton
        self.references: List[Tuple[str, int]] = []

    def parse_method(self, data: bytes) -> str:
        self.references = []
        return self._parse_method(_Cursor(data))

    def _parse_method(self, cur: "_Cursor") -> str:
        header = cur.u1()
        base = header & _CALLCONV_MASK
        if base not in _CALLCONV_NAMES:
            raise SignatureError("not a method signature: 0x{0:02x}".format(header))
        flags = [_CALLCONV_NAMES[base]]
        if header & _CALLCONV_GENERIC:
            flags.append("generic")
        if header & _CALLCONV_HASTHIS:
            flags.append("instance")
        if header & _CALLCONV_EXPLICITTHIS:
            flags.append("explicit")
        generic_count = cur.compressed() if header & _CALLCONV_GENERIC else 0
        param_count = cur.compressed()
        ret = self.parse_type(cur)
        params = [self.parse_type(cur) for _ in range(param_count)]
        if not cur.eof():
            raise SignatureError("trailing bytes in method signature")
        prefix = "[" + " ".join(flags) + "]"
        if generic_count:
            prefix += "<" + str(generic_count) + ">"
        return prefix + "({0})->{1}".format(", ".join(params), ret)

    def parse_field(self, data: bytes) -> str:
        self.references = []
        cur = _Cursor(data)
        header = cur.u1()
        if header & _CALLCONV_MASK != 0x06:
            raise SignatureError("not a field signature: 0x{0:02x}".format(header))
        text = self.parse_type(cur)
        if not cur.eof():
            raise SignatureError("trailing bytes in field signature")
        return text

    def parse_property(self, data: bytes) -> str:
        cur = _Cursor(data)
        header = cur.u1()
        if header & _CALLCONV_MASK != 0x08:
            raise SignatureError("not a property signature: 0x{0:02x}".format(header))
        param_count = cur.compressed()
        ret = self.parse_type(cur)
        params = [self.parse_type(cur) for _ in range(param_count)]
        if not cur.eof():
            raise SignatureError("trailing bytes in property signature")
        return "({0})->{1}".format(", ".join(params), ret)

    def parse_type(self, cur: _Cursor) -> str:
        modifiers: List[str] = []
        while True:
            element = cur.peek()
            if element == ELEMENT_TYPE_CMOD_REQD:
                cur.u1()
                modifiers.append("modreq(" + self._type_def_or_ref(cur) + ")")
            elif element == ELEMENT_TYPE_CMOD_OPT:
                cur.u1()
                modifiers.append("modopt(" + self._type_def_or_ref(cur) + ")")
            elif element == ELEMENT_TYPE_PINNED:
                cur.u1()
                modifiers.append("pinned")
            elif element == ELEMENT_TYPE_SENTINEL:
                cur.u1()
                modifiers.append("sentinel")
            else:
                break
        element = cur.u1()
        if element in _PRIMITIVE_ELEMENT_TYPES:
            text = _PRIMITIVE_ELEMENT_TYPES[element]
        elif element == ELEMENT_TYPE_PTR:
            text = self.parse_type(cur) + "*"
        elif element == ELEMENT_TYPE_BYREF:
            text = self.parse_type(cur) + "&"
        elif element == ELEMENT_TYPE_VALUETYPE:
            text = "valuetype " + self._type_def_or_ref(cur)
        elif element == ELEMENT_TYPE_CLASS:
            text = "class " + self._type_def_or_ref(cur)
        elif element == ELEMENT_TYPE_VAR:
            text = "!" + str(cur.compressed())
        elif element == ELEMENT_TYPE_MVAR:
            text = "!!" + str(cur.compressed())
        elif element == ELEMENT_TYPE_SZARRAY:
            text = self.parse_type(cur) + "[]"
        elif element == ELEMENT_TYPE_ARRAY:
            text = self._array(cur)
        elif element == ELEMENT_TYPE_GENERICINST:
            text = self._generic_inst(cur)
        elif element == ELEMENT_TYPE_FNPTR:
            text = "fnptr " + self._parse_method(cur)
        elif element == ELEMENT_TYPE_END:
            raise SignatureError("unexpected end element type")
        else:
            raise SignatureError("unknown element type 0x{0:02x}".format(element))
        if modifiers:
            text += " " + " ".join(modifiers)
        return text

    def _array(self, cur: _Cursor) -> str:
        element = self.parse_type(cur)
        rank = cur.compressed()
        if rank == 0:
            raise SignatureError("array rank must be positive")
        sizes = [cur.compressed() for _ in range(cur.compressed())]
        bounds = [cur.compressed_signed() for _ in range(cur.compressed())]
        suffix = "," * (rank - 1)
        if sizes or bounds:
            suffix += ";" + ",".join(str(s) for s in sizes)
            suffix += ";" + ",".join(str(b) for b in bounds)
        return "{0}[{1}]".format(element, suffix)

    def _generic_inst(self, cur: _Cursor) -> str:
        kind = cur.peek()
        if kind not in (ELEMENT_TYPE_CLASS, ELEMENT_TYPE_VALUETYPE):
            raise SignatureError("invalid generic instance kind")
        kind_text = self.parse_type(cur)
        count = cur.compressed()
        args = [self.parse_type(cur) for _ in range(count)]
        return "{0}<{1}>".format(kind_text, ", ".join(args))

    def _type_def_or_ref(self, cur: _Cursor) -> str:
        coded = cur.compressed()
        if self.resolve_ref is not None:
            table, rid = _coded_table(coded, _TYPEDEFORREF_TABLES)
            index = len(self.references)
            self.references.append((table, rid))
            if self.skeleton:
                return "@{0}".format(index)
        return self.resolve_type(coded)


class _Model:
    """Parsed metadata exposed through a small, stable API."""

    def __init__(self, pe: Any):
        self.pe = pe
        net = getattr(pe, "net", None)
        self.md = getattr(net, "mdtables", None)
        if self.md is None:
            raise IdentityError("no CLR metadata tables")
        self.typedef_rows = list(getattr(self.md, "TypeDef", []) or [])
        self.typeref_rows = list(getattr(self.md, "TypeRef", []) or [])
        self.method_rows = list(getattr(self.md, "MethodDef", []) or [])
        self.field_rows = list(getattr(self.md, "Field", []) or [])
        self.nested: Dict[int, int] = {}
        nested_table = getattr(self.md, "NestedClass", None)
        if nested_table is not None:
            for row in nested_table:
                if row is None:
                    continue
                try:
                    self.nested[int(row.NestedClass.row_index)] = int(row.EnclosingClass.row_index)
                except (AttributeError, TypeError, ValueError):
                    continue
        self._method_owner = self._build_method_owner_map()

    def row_at(self, table: str, rid: int) -> Any:
        t = getattr(self.md, table, None)
        if t is None or rid < 1:
            return None
        try:
            return t[rid - 1]
        except IndexError:
            return None

    @staticmethod
    def _full_name(row: Any) -> Tuple[str, str]:
        return (
            _get_string(getattr(row, "TypeNamespace", "")),
            _get_string(getattr(row, "TypeName", "")),
        )

    def type_chain(self, rid: int) -> Tuple[Tuple[str, ...], int]:
        """Return outer-to-inner enclosing type names and the chain root."""
        chain: List[str] = []
        seen = set()
        current = rid
        while current in self.nested:
            if current in seen:
                break
            seen.add(current)
            parent = self.nested[current]
            parent_row = self.row_at("TypeDef", parent)
            if parent_row is None:
                break
            _, parent_name = self._full_name(parent_row)
            chain.insert(0, parent_name)
            current = parent
        return tuple(chain), current

    def generic_params_with_numbers(self, owner_table: str, owner_rid: int) -> Tuple[Tuple[int, str], ...]:
        table = getattr(self.md, "GenericParam", None)
        if table is None:
            return ()
        found: List[Tuple[int, str]] = []
        for fallback, row in enumerate(table):
            if row is None:
                continue
            owner = getattr(row, "Owner", None)
            if owner is None or getattr(getattr(owner, "table", None), "name", None) != owner_table:
                continue
            if int(getattr(owner, "row_index", -1)) != owner_rid:
                continue
            number = int(getattr(row, "Number", fallback))
            found.append((number, _get_string(getattr(row, "Name", ""))))
        found.sort(key=lambda item: item[0])
        return tuple(found)

    def generic_params(self, owner_table: str, owner_rid: int) -> Tuple[str, ...]:
        return tuple(name for _, name in self.generic_params_with_numbers(owner_table, owner_rid))

    def constraint_refs(self, owner_table: str, owner_rid: int) -> Tuple[Tuple[int, int], ...]:
        table = getattr(self.md, "GenericParamConstraint", None)
        if table is None:
            return ()
        found: List[Tuple[int, int]] = []
        for row in table:
            if row is None:
                continue
            owner = getattr(row, "Owner", None)
            if owner is None or getattr(getattr(owner, "table", None), "name", None) != "GenericParam":
                continue
            gp = self.row_at("GenericParam", int(getattr(owner, "row_index", 0)))
            if gp is None:
                continue
            gp_owner = getattr(gp, "Owner", None)
            if gp_owner is None or getattr(getattr(gp_owner, "table", None), "name", None) != owner_table:
                continue
            if int(getattr(gp_owner, "row_index", -1)) != owner_rid:
                continue
            found.append((int(getattr(gp, "Number", 0)), int(getattr(row.struct, "Constraint_CodedIndex", 0))))
        found.sort(key=lambda item: item[0])
        return tuple(found)

    def _build_method_owner_map(self) -> Dict[int, int]:
        """Assign methods to types using MethodList ranges.

        ECMA-335 defines MethodList as the start of a run that ends where the
        next TypeDef's run starts.  TypeDefs with zero methods may repeat the
        same start index; sorting is stable and the final table bound closes
        the last run.  This also handles the common case where a trailing
        TypeDef has an empty MethodList.
        """
        owner: Dict[int, int] = {}
        method_total = len(self.method_rows)
        ranges: List[Tuple[int, int]] = []
        for rid, typedef in enumerate(self.typedef_rows, start=1):
            if typedef is None:
                continue
            start = int(getattr(typedef.struct, "MethodList_Index", 0) or 0)
            if start < 1:
                continue
            ranges.append((start, rid))
        ranges.sort()
        for index, (start, rid) in enumerate(ranges):
            end = ranges[index + 1][0] if index + 1 < len(ranges) else method_total + 1
            for method_rid in range(start, min(end, method_total + 1)):
                owner[method_rid] = rid
        return owner

    def method_owner(self, rid: int) -> Optional[int]:
        return self._method_owner.get(rid)


class SideBuilder:
    """Collect identities and provenance from one read-only parse."""

    def __init__(self, path: str):
        self.path = path
        self.digest, self.size = file_digest(path)
        self.notes: List[str] = []
        try:
            self.pe = dnfile.dnPE(path)
        except Exception as e:
            raise IdentityError("failed to parse {0}: {1}".format(path, e))
        if getattr(self.pe, "net", None) is None:
            raise IdentityError("not a .NET module: {0}".format(path))
        self.model = _Model(self.pe)
        self.type_identities: Dict[int, TypeIdentity] = {}
        self.type_rows: Dict[int, RowRecord] = {}
        self.type_refs: Dict[int, TypeIdentity] = {}
        self.method_rows: Dict[int, RowRecord] = {}
        self.field_rows: Dict[int, RowRecord] = {}
        self._build_types()
        self._build_type_refs()
        self._build_fields()
        self._build_methods()
        for warning in getattr(self.pe, "get_warnings", lambda: [])():
            self.notes.append(str(warning))

    def resolve_coded_type(self, coded: int) -> str:
        table, rid = _coded_table(coded, _TYPEDEFORREF_TABLES, tag_bits=2)
        if rid < 1:
            return "<null>"
        if table == "TypeDef":
            identity = self.type_identities.get(rid)
            return identity.display if identity else "<invalid-TypeDef-{0}>".format(rid)
        if table == "TypeRef":
            identity = self.build_type_ref(rid)
            return identity.display if identity else "<invalid-TypeRef-{0}>".format(rid)
        if table == "TypeSpec":
            identity = self._build_type_spec(rid)
            return "<invalid-TypeSpec-{0}>".format(rid) if identity is None else identity.display
        return "<invalid-{0}-{1}>".format(table, rid)

    def _build_types(self) -> None:
        # First pass: name, nesting, and generic parameter names.  Generic
        # constraints can refer to other TypeDefs, so they are resolved only
        # after every TypeDef has a provisional identity.
        provisional: Dict[int, TypeIdentity] = {}
        for rid in range(1, len(self.model.typedef_rows) + 1):
            row = self.model.row_at("TypeDef", rid)
            if row is None:
                continue
            namespace, name = self.model._full_name(row)
            nesting, _ = self.model.type_chain(rid)
            generic = self.model.generic_params("TypeDef", rid)
            provisional[rid] = TypeIdentity(
                kind="typedef",
                namespace=namespace,
                name=name,
                nesting=nesting,
                generic_params=generic,
            )
        self.type_identities.update(provisional)

        for rid, base in provisional.items():
            row = self.model.row_at("TypeDef", rid)
            assert row is not None
            constraints = self._constraint_texts("TypeDef", rid, len(base.generic_params))
            identity = TypeIdentity(
                kind=base.kind,
                namespace=base.namespace,
                name=base.name,
                nesting=base.nesting,
                generic_params=base.generic_params,
                constraints=constraints,
            )
            self.type_identities[rid] = identity
            self.type_rows[rid] = RowRecord(
                table="TypeDef",
                rid=rid,
                token=_token_for("TypeDef", rid),
                file_offset=_row_file_offset(row),
                identity=identity,
                name=base.name,
                namespace=base.namespace,
                extra={"generic_constraints": constraints},
            )

    def _constraint_texts(self, owner_table: str, owner_rid: int, generic_count: int) -> Tuple[str, ...]:
        """Return one constraint string per generic parameter, aligned by Number."""
        per_number: Dict[int, List[str]] = {}
        for number, coded in self.model.constraint_refs(owner_table, owner_rid):
            per_number.setdefault(number, []).append(self.resolve_coded_type(coded))
        return tuple(
            ", ".join(sorted(per_number.get(i, [])))
            for i in range(generic_count)
        )

    def _build_type_refs(self) -> None:
        for rid in range(1, len(self.model.typeref_rows) + 1):
            identity = self.build_type_ref(rid)
            if identity is not None:
                self.type_refs[rid] = identity

    def _build_type_spec(self, rid: int) -> Optional[TypeIdentity]:
        cache: Dict[int, Optional[TypeIdentity]] = self.__dict__.setdefault("_type_spec_cache", {})
        if rid in cache:
            return cache[rid]
        # Guard against a malformed TypeSpec that refers to itself.
        cache[rid] = None
        row = self.model.row_at("TypeSpec", rid)
        if row is None:
            return None
        raw = _get_blob(getattr(row, "Signature", b""))
        try:
            text = _SignatureParser(self.resolve_coded_type).parse_type(_Cursor(raw))
        except SignatureError:
            text = "invalid:" + raw.hex()
        identity = TypeIdentity(
            kind="typespec",
            namespace="",
            name="TypeSpec",
            type_spec=text,
            scope=Ref("TypeSpec", rid, _token_for("TypeSpec", rid)),
        )
        cache[rid] = identity
        return identity

    def build_type_ref(self, rid: int) -> Optional[TypeIdentity]:
        cached = self.type_refs.get(rid)
        if cached is not None:
            return cached
        row = self.model.row_at("TypeRef", rid)
        if row is None:
            return None
        namespace, name = self.model._full_name(row)
        scope = getattr(row, "ResolutionScope", None)
        scope_ref: Optional[Ref] = None
        scope_table = getattr(getattr(scope, "table", None), "name", None)
        scope_rid = int(getattr(scope, "row_index", 0) or 0)
        if scope_table == "TypeRef" and scope_rid:
            parent = self.build_type_ref(scope_rid)
            if parent is not None:
                namespace = parent.namespace
                nesting = parent.nesting + (parent.name,)
                # A nested TypeRef inherits the assembly/module scope of its
                # enclosing type.
                scope_ref = parent.scope
            else:
                nesting = ()
                scope_ref = Ref("TypeRef", scope_rid, _token_for("TypeRef", scope_rid))
        else:
            nesting = ()
            if scope_table and scope_rid:
                scope_ref = Ref(scope_table, scope_rid, _token_for(scope_table, scope_rid))
                if scope_table in ("AssemblyRef", "ModuleRef", "Module"):
                    scope_row = self.model.row_at(scope_table, scope_rid)
                    scope_name = _get_string(getattr(scope_row, "Name", None)) if scope_row is not None else ""
                    if scope_name:
                        scope_ref = Ref(scope_table, scope_rid, scope_ref.token, scope_name)
        identity = TypeIdentity(
            kind="typeref",
            namespace=namespace,
            name=name,
            nesting=nesting,
            scope=scope_ref,
        )
        self.type_refs[rid] = identity
        return identity

    def _build_fields(self) -> None:
        parser = _SignatureParser(self.resolve_coded_type, self.resolve_coded_type)
        for rid in range(1, len(self.model.field_rows) + 1):
            row = self.model.row_at("Field", rid)
            if row is None:
                continue
            raw = _get_blob(getattr(row, "Signature", b""))
            try:
                text = parser.parse_field(raw)
                references = tuple(parser.references)
                skeleton_parser = _SignatureParser(self.resolve_coded_type, self.resolve_coded_type, skeleton=True)
                skeleton = skeleton_parser.parse_field(raw)
            except SignatureError as e:
                text = "<invalid:{0}>".format(e)
                references = ()
                skeleton = text
                self.notes.append("Field {0} signature undecodable: {1}".format(rid, e))
            self.field_rows[rid] = RowRecord(
                table="Field",
                rid=rid,
                token=_token_for("Field", rid),
                file_offset=_row_file_offset(row),
                identity=text,
                name=_get_string(getattr(row, "Name", "")),
                raw_signature=raw,
                signature=text,
                extra={"signature_refs": references, "signature_skeleton": skeleton},
            )

    def _parse_method_signatures(self, raw: bytes) -> Tuple[str, Tuple[Tuple[str, int], ...], str]:
        parser = _SignatureParser(self.resolve_coded_type, self.resolve_coded_type)
        text = parser.parse_method(raw)
        refs = tuple(parser.references)
        skeleton_parser = _SignatureParser(self.resolve_coded_type, self.resolve_coded_type, skeleton=True)
        skeleton = skeleton_parser.parse_method(raw)
        return text, refs, skeleton

    def _build_methods(self) -> None:
        for rid in range(1, len(self.model.method_rows) + 1):
            row = self.model.row_at("MethodDef", rid)
            if row is None:
                continue
            name = _get_string(getattr(row, "Name", ""))
            raw = _get_blob(getattr(row, "Signature", b""))
            try:
                signature, references, skeleton = self._parse_method_signatures(raw)
            except SignatureError as e:
                signature = "<invalid:{0}>".format(e)
                references = ()
                skeleton = signature
                self.notes.append("MethodDef {0} signature undecodable: {1}".format(rid, e))
            owner_rid = self.model.method_owner(rid)
            owner = self.type_identities.get(owner_rid) if owner_rid else None
            generic = self.model.generic_params("MethodDef", rid)
            constraints = self._constraint_texts("MethodDef", rid, len(generic))
            identity = MethodIdentity(
                owner=owner,
                name=name,
                signature=signature,
                generic_params=generic,
                constraints=constraints,
            )
            self.method_rows[rid] = RowRecord(
                table="MethodDef",
                rid=rid,
                token=_token_for("MethodDef", rid),
                file_offset=_row_file_offset(row),
                identity=identity,
                name=name,
                raw_signature=raw,
                signature=signature,
                owner=Ref("TypeDef", owner_rid, _token_for("TypeDef", owner_rid)) if owner_rid else None,
                extra={
                    "signature_refs": references,
                    "signature_skeleton": skeleton,
                    "rva": int(getattr(row, "Rva", 0) or 0),
                    "impl_flags": int(getattr(row.struct, "ImplFlags", 0) or 0),
                    "flags": int(getattr(row.struct, "Flags", 0) or 0),
                },
            )

    def side(self) -> Side:
        module_name = None
        module_table = getattr(self.model.md, "Module", None)
        if module_table is not None and len(module_table):
            module_name = _get_string(getattr(module_table[0], "Name", None))
        return Side(
            path=self.path,
            digest=self.digest,
            size=self.size,
            types=self.type_rows,
            type_refs=self.type_refs,
            methods=self.method_rows,
            fields=self.field_rows,
            module_name=module_name,
            warnings=self.notes,
        )


def _index_by_identity(records: Iterable[RowRecord]) -> Dict[Any, List[RowRecord]]:
    index: Dict[Any, List[RowRecord]] = {}
    for record in records:
        index.setdefault(record.identity.key(), []).append(record)
    return index


def _method_key(record: RowRecord, canonical_owner: Optional[Dict[int, Any]] = None) -> Tuple[Any, ...]:
    identity = record.identity
    assert isinstance(identity, MethodIdentity)
    if canonical_owner is not None and record.owner is not None:
        owner_key = canonical_owner.get(record.owner.rid)
        if owner_key is not None:
            return (owner_key, identity.name, identity.signature, identity.generic_params, identity.constraints)
    return identity.key()


def _index_methods(
    records: Iterable[RowRecord],
    canonical_owner: Optional[Dict[int, Any]] = None,
) -> Dict[Any, List[RowRecord]]:
    index: Dict[Any, List[RowRecord]] = {}
    for record in records:
        index.setdefault(_method_key(record, canonical_owner), []).append(record)
    return index


def _unique_pairs(
    left_index: Dict[Any, List[RowRecord]],
    right_index: Dict[Any, List[RowRecord]],
    kind: str,
) -> Tuple[List[Mapping], List[RowRecord], List[RowRecord], List[Ambiguity]]:
    """Match rows whose full identity is identical on both sides."""
    mappings: List[Mapping] = []
    ambiguous: List[Ambiguity] = []
    used_left = set()
    used_right = set()
    for key in sorted(left_index.keys() & right_index.keys(), key=repr):
        left_rows = left_index[key]
        right_rows = right_index[key]
        if len(left_rows) == 1 and len(right_rows) == 1:
            mappings.append(Mapping(left_rows[0], right_rows[0], "unique identity match"))
            used_left.add(id(left_rows[0]))
            used_right.add(id(right_rows[0]))
        else:
            ambiguous.append(
                Ambiguity(
                    kind=kind,
                    left=tuple(left_rows),
                    right=tuple(right_rows),
                    reason=(
                        "the same identity occurs {0} time(s) on the left and {1} time(s) "
                        "on the right; a one-to-one mapping would be a guess"
                    ).format(len(left_rows), len(right_rows)),
                )
            )
            used_left.update(id(r) for r in left_rows)
            used_right.update(id(r) for r in right_rows)
    left_only = [r for rows in left_index.values() for r in rows if id(r) not in used_left]
    right_only = [r for rows in right_index.values() for r in rows if id(r) not in used_right]
    return mappings, left_only, right_only, ambiguous


def _weak_key(record: RowRecord, canonical_owner: Optional[Dict[int, Any]] = None) -> Tuple[Any, ...]:
    """A conservative key used only to propose a changed identity.

    Generic constraints are deliberately excluded: a constraint change is an
    identity change to report, not a reason to stop matching the method.
    """
    identity = record.identity
    if isinstance(identity, MethodIdentity):
        owner_key: Any = None
        if record.owner is not None:
            if canonical_owner is not None:
                owner_key = canonical_owner.get(record.owner.rid, ("unpaired", record.owner.rid))
            else:
                owner_key = record.owner.rid
        return ("method", owner_key, identity.name, len(identity.generic_params))
    if isinstance(identity, TypeIdentity):
        # For a type change, the declared name is the strongest stable anchor.
        # Namespace and nesting are deliberately not in this key: if they
        # change, the record is reported as a changed identity, not a new one.
        return ("type", identity.name)
    return ("other",)


def _pair_changes(
    left_only: Sequence[RowRecord],
    right_only: Sequence[RowRecord],
    kind: str,
    canonical_owner: Optional[Dict[int, Any]] = None,
    allow_subject_change: bool = False,
) -> Tuple[List[Mapping], List[RowRecord], List[RowRecord], List[Ambiguity]]:
    """Pair changed identities only when exactly one candidate exists.

    ``allow_subject_change`` is used for TypeDefs: a unique same-name type may
    have moved namespace or nesting, and is reported as a changed identity with
    that fact called out.  A same-name type that also differs in all of
    namespace, nesting, and generic arity is treated as a different type.
    Methods never use this fallback because a same-name method in a different
    type is not the same method.
    """
    changes: List[Mapping] = []
    ambiguities: List[Ambiguity] = []
    remaining_left = list(left_only)
    remaining_right = list(right_only)

    def propose(subject_fn, require_compatible_type=False):
        nonlocal remaining_left, remaining_right, changes
        made_progress = True
        while made_progress:
            made_progress = False
            for left in list(remaining_left):
                left_key = subject_fn(left)
                left_group = [r for r in remaining_left if subject_fn(r) == left_key]
                right_group = [r for r in remaining_right if subject_fn(r) == left_key]
                if len(left_group) != 1 or len(right_group) != 1:
                    continue
                right = right_group[0]
                if require_compatible_type and not _compatible_type_subject(left, right):
                    continue
                changes.append(
                    Mapping(
                        left,
                        right,
                        "unique subject match; identity changed ({0})".format(_change_kind(left, right)),
                        _change_fields(left, right),
                    )
                )
                remaining_left.remove(left)
                remaining_right.remove(right)
                made_progress = True

    # Same declared subject (owner+name+arity for methods; name for types).
    # Type changes must also share namespace, nesting, or arity, so a
    # coincidental same-name replacement is not silently declared "changed".
    propose(lambda record: _weak_key(record, canonical_owner), allow_subject_change)

    # Everything else that shares a subject is ambiguous, never merged.
    reported_left: set = set()
    reported_right: set = set()
    reported_keys: set = set()
    for left in remaining_left:
        left_key = _weak_key(left, canonical_owner)
        if left_key in reported_keys:
            continue
        group_left = [r for r in remaining_left if _weak_key(r, canonical_owner) == left_key]
        group_right = [r for r in remaining_right if _weak_key(r, canonical_owner) == left_key]
        if len(group_left) > 1 or len(group_right) > 1:
            reported_keys.add(left_key)
            ambiguities.append(
                Ambiguity(
                    kind=kind,
                    left=tuple(group_left),
                    right=tuple(group_right),
                    reason=(
                        "same subject but {0} left candidate(s) and {1} right candidate(s); "
                        "a signature or identity change cannot be assigned uniquely, so "
                        "these are not merged"
                    ).format(len(group_left), len(group_right)),
                )
            )
            reported_left.update(id(r) for r in group_left)
            reported_right.update(id(r) for r in group_right)

    remaining_left = [r for r in remaining_left if id(r) not in reported_left]
    remaining_right = [r for r in remaining_right if id(r) not in reported_right]
    return changes, remaining_left, remaining_right, ambiguities


def _compatible_type_subject(left: RowRecord, right: RowRecord) -> bool:
    a = left.identity
    b = right.identity
    assert isinstance(a, TypeIdentity) and isinstance(b, TypeIdentity)
    return bool(
        a.namespace == b.namespace
        or a.nesting == b.nesting
        or len(a.generic_params) == len(b.generic_params)
    )


def _change_fields(left: RowRecord, right: RowRecord) -> Tuple[str, ...]:
    # Order: owner/reference context first, then the method's own signature.

    if isinstance(left.identity, MethodIdentity):
        fields = []
        # Owner differences are expected when the owner itself was reported as
        # a changed identity.  The method still follows that owner.
        if left.identity.owner is not None and right.identity.owner is not None:
            if left.identity.owner.name != right.identity.owner.name:
                fields.append("owner-name")
            elif left.identity.owner.namespace != right.identity.owner.namespace:
                fields.append("owner-namespace")
            elif left.identity.owner.nesting != right.identity.owner.nesting:
                fields.append("owner-nesting")
            elif left.identity.owner.generic_params != right.identity.owner.generic_params:
                fields.append("owner-generic_params")
        if left.identity.signature != right.identity.signature:
            if left.extra.get("signature_skeleton") == right.extra.get("signature_skeleton"):
                # The only textual difference comes from a referenced type
                # whose own identity changed.  That type change is reported
                # separately; call this out rather than implying the method's
                # own parameter/return structure was edited.
                fields.append("signature-via-referenced-type")
            else:
                fields.append("signature")
        if left.identity.generic_params != right.identity.generic_params:
            fields.append("generic_params")
        return tuple(fields) if fields else ("identity",)
    if isinstance(left.identity, TypeIdentity):
        fields = []
        if left.identity.namespace != right.identity.namespace:
            fields.append("namespace")
        if left.identity.nesting != right.identity.nesting:
            fields.append("nesting")
        if left.identity.generic_params != right.identity.generic_params:
            fields.append("generic_params")
        if left.identity.constraints != right.identity.constraints:
            fields.append("constraints")
        return tuple(fields) if fields else ("identity",)
    return ("identity",)


def _change_kind(left: RowRecord, right: RowRecord) -> str:
    return ", ".join(_change_fields(left, right))


def _naive_token_compare(left: Side, right: Side) -> Dict[str, int]:
    """Quantify a naive comparison of MethodDef rows at the same RID."""
    common = set(left.methods) & set(right.methods)
    same = 0
    different = 0
    for rid in common:
        if left.methods[rid].identity.key() == right.methods[rid].identity.key():
            same += 1
        else:
            different += 1
    return {
        "method_rows_present_on_both_sides": len(common),
        "same_token_same_identity": same,
        "same_token_different_identity": different,
        "left_only_rows": len(set(left.methods) - common),
        "right_only_rows": len(set(right.methods) - common),
    }


def compare(left_path: str, right_path: str) -> Comparison:
    """Compare two .NET modules by read-only metadata identity.

    Both arguments are filesystem paths.  Each file is read once to compute a
    SHA-256 digest, then parsed by dnfile for its metadata.  Nothing is loaded,
    imported, JIT-compiled, or executed.
    """
    left = SideBuilder(left_path).side()
    right = SideBuilder(right_path).side()
    result = Comparison(left=left, right=right)
    result.notes.extend("left: " + n for n in left.warnings)
    result.notes.extend("right: " + n for n in right.warnings)

    type_mappings, left_types, right_types, type_dup = _unique_pairs(
        _index_by_identity(left.types.values()),
        _index_by_identity(right.types.values()),
        "duplicate-type-identity",
    )
    type_changes, left_types, right_types, type_amb = _pair_changes(
        left_types, right_types, "type-changed-candidate", allow_subject_change=True
    )

    # Methods are matched after types.  A type that was confirmed or paired as a
    # changed identity lets its methods follow their owner even if the type's
    # namespace or nesting moved.  If the owner is itself ambiguous, methods
    # are compared by the raw owner identity and may remain ambiguous.
    canonical_owner: Dict[int, Any] = {}
    for mapping in type_mappings + type_changes:
        key = mapping.left.identity.key()
        canonical_owner[mapping.left.rid] = key
        canonical_owner[mapping.right.rid] = key

    method_mappings, left_methods, right_methods, method_dup = _unique_pairs(
        _index_methods(left.methods.values(), canonical_owner),
        _index_methods(right.methods.values(), canonical_owner),
        "duplicate-method-identity",
    )
    method_changes, left_methods, right_methods, method_amb = _pair_changes(
        left_methods, right_methods, "method-changed-candidate", canonical_owner
    )

    result.type_mappings = sorted(type_mappings, key=lambda m: m.left.rid)
    result.method_mappings = sorted(method_mappings, key=lambda m: m.left.rid)
    result.type_changes = sorted(type_changes, key=lambda m: m.left.rid)
    result.method_changes = sorted(method_changes, key=lambda m: m.left.rid)
    result.removed_types = sorted(left_types, key=lambda r: r.rid)
    result.added_types = sorted(right_types, key=lambda r: r.rid)
    result.removed_methods = sorted(left_methods, key=lambda r: r.rid)
    result.added_methods = sorted(right_methods, key=lambda r: r.rid)
    result.ambiguities = type_dup + method_dup + type_amb + method_amb
    result.naive_token_summary = _naive_token_compare(left, right)
    return result


def _render_text(result: Comparison) -> str:
    lines: List[str] = []
    lines.append("metadata identity comparison (read-only; no assembly loaded or executed)")
    lines.append("  left : " + result.left.path)
    lines.append("         sha256:" + result.left.digest + " ({0} bytes)".format(result.left.size))
    lines.append("  right: " + result.right.path)
    lines.append("         sha256:" + result.right.digest + " ({0} bytes)".format(result.right.size))
    lines.append("")
    lines.append("summary")
    type_ambiguous = sum(
        1 for a in result.ambiguities
        if a.left and isinstance(a.left[0].identity, TypeIdentity)
    )
    method_ambiguous = sum(
        1 for a in result.ambiguities
        if a.left and isinstance(a.left[0].identity, MethodIdentity)
    )
    lines.append(
        "  types   confirmed={0} changed={1} ambiguous={2} removed={3} added={4}".format(
            len(result.type_mappings),
            len(result.type_changes),
            type_ambiguous,
            len(result.removed_types),
            len(result.added_types),
        )
    )
    lines.append(
        "  methods confirmed={0} changed={1} ambiguous={2} removed={3} added={4}".format(
            len(result.method_mappings),
            len(result.method_changes),
            method_ambiguous,
            len(result.removed_methods),
            len(result.added_methods),
        )
    )
    lines.append(
        "  naive same-token MethodDef comparison: {0} same identity, {1} different identity "
        "(the latter are row-renumbering false positives unless a change is listed below)".format(
            result.naive_token_summary.get("same_token_same_identity", 0),
            result.naive_token_summary.get("same_token_different_identity", 0),
        )
    )
    lines.append("")

    lines.extend(_render_mappings("confirmed type mappings", result.type_mappings, result.left, result.right))
    lines.extend(_render_mappings("confirmed method mappings", result.method_mappings, result.left, result.right))
    lines.extend(_render_mappings("type identity changes", result.type_changes, result.left, result.right))
    lines.extend(_render_mappings("method identity changes", result.method_changes, result.left, result.right))
    lines.extend(_render_ambiguities(result.ambiguities, result.left, result.right))
    lines.extend(_render_records("removed types", result.removed_types, result.left))
    lines.extend(_render_records("added types", result.added_types, result.right))
    lines.extend(_render_records("removed methods", result.removed_methods, result.left))
    lines.extend(_render_records("added methods", result.added_methods, result.right))
    if result.notes:
        lines.append("notes")
        lines.extend("  - " + note for note in result.notes)
    return "\n".join(lines).rstrip() + "\n"


def _render_mappings(title: str, mappings: Sequence[Mapping], left: Side, right: Side) -> List[str]:
    if not mappings:
        return []
    lines = [title]
    for mapping in mappings:
        suffix = " [" + ", ".join(mapping.changes) + "]" if mapping.changes else ""
        lines.append("  - " + mapping.left.label() + suffix)
        if mapping.changes and mapping.left.label() != mapping.right.label():
            lines.append("      after: " + mapping.right.label())
        lines.append("      left : " + _evidence_text(mapping.left, left))
        lines.append("      right: " + _evidence_text(mapping.right, right))
    lines.append("")
    return lines


def _render_ambiguities(ambiguities: Sequence[Ambiguity], left: Side, right: Side) -> List[str]:
    if not ambiguities:
        return []
    lines = ["ambiguous / unresolved candidates"]
    for ambiguity in ambiguities:
        lines.append("  - " + ambiguity.reason)
        for record in ambiguity.left:
            lines.append("      left : " + _evidence_text(record, left) + "  " + record.label())
        for record in ambiguity.right:
            lines.append("      right: " + _evidence_text(record, right) + "  " + record.label())
    lines.append("")
    return lines


def _evidence_text(record: RowRecord, side: Side) -> str:
    return "{0}:{1} token=0x{2:08x} offset={3} sha256:{4}".format(
        record.table,
        record.rid,
        record.token,
        "?" if record.file_offset is None else "0x{0:x}".format(record.file_offset),
        side.digest[:16],
    )


def _render_records(title: str, records: Sequence[RowRecord], side: Side) -> List[str]:
    if not records:
        return []
    lines = [title]
    for record in records:
        lines.append("  - " + record.label())
        lines.append("      " + _evidence_text(record, side))
    lines.append("")
    return lines


def format_comparison(comparison: Comparison) -> str:
    """Render an investigator-facing text report."""
    return comparison.render()


__all__ = [
    "Ambiguity",
    "Comparison",
    "IdentityError",
    "Mapping",
    "MethodIdentity",
    "RowRecord",
    "Side",
    "SideBuilder",
    "SignatureError",
    "TypeIdentity",
    "compare",
    "file_digest",
    "format_comparison",
]
