# -*- coding: utf-8 -*-
"""
Read-only analysis of .NET ``DeclSecurity`` (security declaration) rows.

This module deliberately keeps three kinds of evidence separate:

* storage facts: the raw ``Action`` value, the raw ``PermissionSet`` blob,
  the raw ``HasDeclSecurity`` coded index, and the concrete Assembly/TypeDef/
  MethodDef row that the index resolves to;
* interpreted content: a small, explicitly supported subset of permission
  attributes whose named arguments are decoded;
* runtime effect: never inferred here.  A ``DeclSecurity`` row records a
  request or annotation in metadata.  It does not prove that a runtime
  granted, enforced, or even honored that request.

Unknown actions, malformed or dangling indexes, and unrecognized legacy
permission-set encodings are reported as unknown/unsupported.  They are never
collapsed into "no security requirements".

ECMA-335 references:
    II.22.11 DeclSecurity
    II.23.1.3 DeclSecurity blob
    II.23.3 Custom attributes (named arguments)
"""

import enum
import struct as _struct
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import field, dataclass

__all__ = (
    "DeclSecurityAction",
    "NamedArgument",
    "PermissionAttribute",
    "PermissionSet",
    "SecurityDeclaration",
    "OwnerGroup",
    "DuplicateGroup",
    "SecurityAnalysis",
    "analyze",
    "decode_permission_set",
    "SUPPORTED_PERMISSION_ATTRIBUTES",
)


class DeclSecurityAction(enum.IntEnum):
    """
    Values defined by ``CorDeclSecurity`` in corhdr.h and ECMA-335.

    ``Nil`` is defined by the header but is not a meaningful action.  Values
    outside this enum are preserved as raw integers and reported as unknown.
    """

    Nil = 0x0000
    Request = 0x0001
    Demand = 0x0002
    Assert = 0x0003
    Deny = 0x0004
    PermitOnly = 0x0005
    LinkDemand = 0x0006
    InheritanceDemand = 0x0007
    RequestMinimum = 0x0008
    RequestOptional = 0x0009
    RequestRefuse = 0x000A
    PreJitGrant = 0x000B
    PreJitDeny = 0x000C
    NonCasDemand = 0x000D
    NonCasLinkDemand = 0x000E
    NonCasInheritance = 0x000F


# Payloads are decoded only for this explicit allow-list.  Other permission
# types keep their assembly-qualified type name and raw payload, and are
# marked unsupported rather than guessed at.
SUPPORTED_PERMISSION_ATTRIBUTES = frozenset(
    (
        "System.Security.Permissions.SecurityPermissionAttribute",
        "System.Security.Permissions.FileIOPermissionAttribute",
        "System.Security.Permissions.ReflectionPermissionAttribute",
        "System.Security.Permissions.EnvironmentPermissionAttribute",
        "System.Security.Permissions.RegistryPermissionAttribute",
        "System.Security.Permissions.FileDialogPermissionAttribute",
    )
)


PARENT_TABLES = {
    0: ("TypeDef", "type", 0x02000000),
    1: ("MethodDef", "method", 0x06000000),
    2: ("Assembly", "assembly", 0x20000000),
}

_ELEMENT_TYPES = {
    0x02: "bool",
    0x03: "char",
    0x04: "i1",
    0x05: "u1",
    0x06: "i2",
    0x07: "u2",
    0x08: "i4",
    0x09: "u4",
    0x0A: "i8",
    0x0B: "u8",
    0x0C: "r4",
    0x0D: "r8",
    0x0E: "string",
    0x1D: "array",
    0x50: "type",
    0x51: "boxed",
    0x55: "enum",
}

_SCALAR_FORMATS = {
    0x04: ("<b", 1),
    0x05: ("<B", 1),
    0x06: ("<h", 2),
    0x07: ("<H", 2),
    0x08: ("<i", 4),
    0x09: ("<I", 4),
    0x0A: ("<q", 8),
    0x0B: ("<Q", 8),
    0x0C: ("<f", 4),
    0x0D: ("<d", 8),
}


class _BlobError(Exception):
    """An error while decoding one bounded blob."""


class _UnsupportedType(_BlobError):
    """A named-argument encoding outside this limited decoder."""


def _read_compressed_uint(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise _BlobError("truncated compressed integer")
    b0 = data[offset]
    if b0 & 0x80 == 0:
        return b0, offset + 1
    if b0 & 0x40 == 0:
        if offset + 1 >= len(data):
            raise _BlobError("truncated two-byte compressed integer")
        return ((b0 & 0x3F) << 8) | data[offset + 1], offset + 2
    if b0 & 0x20 == 0:
        if offset + 3 >= len(data):
            raise _BlobError("truncated four-byte compressed integer")
        value = (b0 & 0x1F) << 24
        value |= data[offset + 1] << 16
        value |= data[offset + 2] << 8
        value |= data[offset + 3]
        return value, offset + 4
    raise _BlobError("invalid compressed integer leading byte 0x{:02x}".format(b0))


def _read_serstring(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Read a SerString; 0xFF means null."""
    if offset < len(data) and data[offset] == 0xFF:
        return None, offset + 1

    length, offset = _read_compressed_uint(data, offset)
    if offset + length > len(data):
        raise _BlobError("truncated SerString (wanted {} bytes)".format(length))
    raw = data[offset:offset + length]
    # Keep going on malformed UTF-8; the caller always retains the raw blob,
    # and an escaped name is better evidence than dropping the row.
    return raw.decode("utf-8", errors="backslashreplace"), offset + length


@dataclass(frozen=True)
class _TypeDescriptor:
    """A parsed FieldOrPropType from ECMA-335 II.23.3."""

    code: int
    element: Optional["_TypeDescriptor"] = None
    enum_name: Optional[str] = None
    enum_assembly: Optional[str] = None

    @property
    def display(self) -> str:
        if self.code == 0x1D:
            return "array<{}>".format(self.element.display if self.element else "?")
        if self.code == 0x55:
            return self.enum_name or "enum"
        return _ELEMENT_TYPES.get(self.code, "unknown")


def _read_type_descriptor(data: bytes, offset: int) -> Tuple[_TypeDescriptor, int]:
    """
    Read a complete FieldOrPropType.

    A single byte is not always enough: SZARRAY carries an element type and
    ENUM carries a serialized enum type name.
    """
    if offset >= len(data):
        raise _BlobError("truncated named-argument type descriptor")
    code = data[offset]
    offset += 1

    if code == 0x1D:  # SZARRAY
        element, offset = _read_type_descriptor(data, offset)
        return _TypeDescriptor(code, element=element), offset

    if code == 0x55:  # ENUM
        name, offset = _read_serstring(data, offset)
        enum_name = name
        enum_assembly = None
        if name and "," in name:
            enum_name, enum_assembly = (part.strip() for part in name.split(",", 1))
        return _TypeDescriptor(code, enum_name=enum_name, enum_assembly=enum_assembly), offset

    return _TypeDescriptor(code), offset


def _decode_named_arg_value(
    data: bytes,
    offset: int,
    descriptor: _TypeDescriptor,
) -> Tuple[Any, int, Optional[str]]:
    """
    Decode one named-argument value according to its type descriptor.

    Returns ``(value, new_offset, uncertainty_note)``.  Raises
    ``_UnsupportedType`` when the encoding needs external type information.
    """

    code = descriptor.code

    if code in _SCALAR_FORMATS:
        fmt, size = _SCALAR_FORMATS[code]
        if offset + size > len(data):
            raise _BlobError("truncated numeric named argument")
        return _struct.unpack_from(fmt, data, offset)[0], offset + size, None

    if code == 0x02:  # BOOLEAN
        if offset >= len(data):
            raise _BlobError("truncated bool named argument")
        return data[offset] != 0, offset + 1, None

    if code == 0x03:  # CHAR
        if offset + 2 > len(data):
            raise _BlobError("truncated char named argument")
        return chr(_struct.unpack_from("<H", data, offset)[0]), offset + 2, None

    if code == 0x0E:  # STRING
        value, offset = _read_serstring(data, offset)
        return value, offset, None

    if code == 0x50:  # TYPE
        # A System.Type value is serialized as its assembly-qualified name.
        value, offset = _read_serstring(data, offset)
        return value, offset, None

    if code == 0x51:  # BOXED
        if offset >= len(data):
            raise _BlobError("truncated boxed named argument")
        inner, offset = _read_type_descriptor(data, offset)
        return _decode_named_arg_value(data, offset, inner)

    if code == 0x55:  # ENUM
        # The underlying integer width lives in the enum's defining assembly,
        # which may not be available here.  All security-permission enums in
        # mscorlib use int32, but the value is explicitly marked uncertain.
        if offset + 4 > len(data):
            raise _BlobError("truncated enum named argument")
        value = _struct.unpack_from("<i", data, offset)[0]
        return (
            value,
            offset + 4,
            "enum underlying type assumed to be int32 (type {!r})".format(descriptor.enum_name),
        )

    if code == 0x1D:  # SZARRAY
        if descriptor.element is None:
            raise _BlobError("array named argument has no element type")
        # ECMA-335 II.23.3: the element count is a uint32.
        if offset + 4 > len(data):
            raise _BlobError("truncated array element count")
        count = _struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if count > len(data):
            raise _BlobError("implausible array element count {}".format(count))
        values = []
        note: Optional[str] = None
        for _ in range(count):
            value, offset, item_note = _decode_named_arg_value(data, offset, descriptor.element)
            values.append(value)
            if item_note and note is None:
                note = item_note
        return values, offset, note

    raise _UnsupportedType(
        "unsupported named-argument element type 0x{:02x}".format(code)
    )


@dataclass(frozen=True)
class NamedArgument:
    """One decoded field/property argument of a permission attribute."""

    kind: str
    type_code: int
    type_name: str
    name: Optional[str]
    value: Any
    raw_value: bytes
    status: str
    note: Optional[str] = None

    def __str__(self) -> str:
        name = self.name if self.name is not None else "<unnamed>"
        if self.status != "decoded":
            return "{}={!r} [{}: {}]".format(name, self.value, self.status, self.note or "")
        return "{}={!r}".format(name, self.value)


@dataclass(frozen=True)
class PermissionAttribute:
    """
    One security attribute encoded in a permission set.

    ``payload`` is the attribute-specific blob (not the enclosing
    permission-set blob).  It is always preserved, even when decoding fails.
    """

    type_name: Optional[str]
    attribute_type: Optional[str]
    supported: bool
    payload: bytes
    named_arguments: Tuple[NamedArgument, ...]
    status: str
    issues: Tuple[str, ...] = ()

    def display(self) -> str:
        name = self.attribute_type or self.type_name or "<unknown permission type>"
        if self.status in ("decoded", "partial") and self.named_arguments:
            args = ", ".join(str(a) for a in self.named_arguments)
            return "{}({})".format(name, args)
        if self.status == "unsupported":
            return "{} [unsupported permission type]".format(name)
        if self.status == "empty":
            return "{} [empty attribute payload]".format(name)
        return "{} [{}]".format(name, self.status)


@dataclass(frozen=True)
class PermissionSet:
    """Decoded form of one ``PermissionSet`` blob."""

    raw: bytes
    format: str
    attributes: Tuple[PermissionAttribute, ...]
    status: str
    issues: Tuple[str, ...] = ()

    def display(self) -> str:
        if self.format == "empty":
            return "empty permission set"
        if self.format == "legacy-xml":
            return "legacy XML permission set [not decoded; raw bytes preserved]"
        if not self.attributes:
            return "{} permission set [{}]".format(self.format, self.status)
        return "; ".join(a.display() for a in self.attributes)


def decode_permission_set(blob: Optional[bytes]) -> PermissionSet:
    """
    Decode a ``PermissionSet`` blob without ever discarding the raw bytes.

    The binary form follows ECMA-335 II.23.1.3: ``0x2E``, an attribute count,
    then one SerString type name, a payload length, and the attribute's named
    arguments, repeated for each attribute.  Legacy XML permission sets (used
    by early .NET versions) are recognized but deliberately not parsed.  Any
    other unrecognized form is reported as unsupported.
    """

    if blob is None:
        return PermissionSet(
            raw=b"",
            format="unavailable",
            attributes=(),
            status="unavailable",
            issues=("permission-set blob is not available",),
        )

    raw = bytes(blob)
    if len(raw) == 0:
        return PermissionSet(raw=raw, format="empty", attributes=(), status="empty")

    # Legacy permission sets were XML documents.  XML may carry a BOM or
    # leading whitespace; recognize those forms but do not try to parse them.
    for encoding, bom in (
        ("utf-8", b"\xef\xbb\xbf"),
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
    ):
        if raw.startswith(bom):
            body = raw[len(bom):]
            try:
                text = body.decode(encoding, errors="replace").lstrip()
            except (LookupError, UnicodeError):
                text = ""
            if text.startswith("<"):
                return PermissionSet(
                    raw=raw,
                    format="legacy-xml",
                    attributes=(),
                    status="unsupported",
                    issues=("legacy XML permission set is not decoded",),
                )
    if raw.lstrip(b" \t\r\n").startswith(b"<"):
        return PermissionSet(
            raw=raw,
            format="legacy-xml",
            attributes=(),
            status="unsupported",
            issues=("legacy XML permission set is not decoded",),
        )

    if raw[0] != 0x2E:
        return PermissionSet(
            raw=raw,
            format="unknown",
            attributes=(),
            status="unsupported",
            issues=("unrecognized permission-set format (first byte 0x{:02x})".format(raw[0]),),
        )

    issues: List[str] = []
    attributes: List[PermissionAttribute] = []
    offset = 1
    try:
        if offset >= len(raw):
            raise _BlobError("permission-set blob has no attribute count")
        count, offset = _read_compressed_uint(raw, offset)
        if count > len(raw):
            raise _BlobError("implausible permission attribute count {}".format(count))

        for index in range(count):
            if offset >= len(raw):
                raise _BlobError("truncated permission attribute {}".format(index))
            type_name, offset = _read_serstring(raw, offset)
            length, offset = _read_compressed_uint(raw, offset)
            if offset + length > len(raw):
                raise _BlobError("truncated permission attribute payload {}".format(index))
            payload = raw[offset:offset + length]
            offset += length
            attributes.append(_decode_permission_attribute(type_name, payload))
    except _BlobError as e:
        issues.append("permission-set parse error: {}".format(e))
        status = "partial" if attributes else "malformed"
        return PermissionSet(
            raw=raw,
            format="binary",
            attributes=tuple(attributes),
            status=status,
            issues=tuple(issues),
        )

    if offset != len(raw):
        issues.append(
            "{} trailing byte(s) after {} permission attribute(s)".format(
                len(raw) - offset, len(attributes)
            )
        )

    if not attributes:
        status = "empty"
    elif any(a.status == "malformed" for a in attributes):
        # A malformed attribute is not the same as an unsupported one: the
        # bytes claim to be decodable but are broken.
        status = "partial" if len(attributes) > 1 or any(a.named_arguments for a in attributes) else "malformed"
    elif any(a.status == "partial" for a in attributes):
        status = "partial"
    elif any(a.status == "unsupported" for a in attributes):
        status = "partial" if any(a.status in ("decoded", "empty") for a in attributes) else "unsupported"
    elif issues:
        status = "partial"
    else:
        status = "decoded"

    return PermissionSet(
        raw=raw,
        format="binary",
        attributes=tuple(attributes),
        status=status,
        issues=tuple(issues),
    )


def _decode_permission_attribute(type_name: Optional[str], payload: bytes) -> PermissionAttribute:
    attribute_type = None
    if type_name:
        attribute_type = type_name.split(",", 1)[0].strip()

    supported = attribute_type in SUPPORTED_PERMISSION_ATTRIBUTES
    if not supported:
        return PermissionAttribute(
            type_name=type_name,
            attribute_type=attribute_type,
            supported=False,
            payload=payload,
            named_arguments=(),
            status="unsupported",
            issues=("permission attribute is outside the supported subset",),
        )

    if len(payload) == 0:
        return PermissionAttribute(
            type_name=type_name,
            attribute_type=attribute_type,
            supported=True,
            payload=payload,
            named_arguments=(),
            status="empty",
        )

    issues: List[str] = []
    named_arguments: List[NamedArgument] = []
    offset = 0
    try:
        count, offset = _read_compressed_uint(payload, offset)
        if count > len(payload):
            raise _BlobError("implausible named-argument count {}".format(count))

        for index in range(count):
            start = offset
            if offset >= len(payload):
                raise _BlobError("truncated named argument {}".format(index))
            kind_byte = payload[offset]
            offset += 1
            if kind_byte == 0x53:
                kind = "field"
            elif kind_byte == 0x54:
                kind = "property"
            else:
                raise _BlobError(
                    "invalid named-argument kind 0x{:02x} at index {}".format(kind_byte, index)
                )

            descriptor, offset = _read_type_descriptor(payload, offset)
            type_code = descriptor.code
            name, offset = _read_serstring(payload, offset)
            value_start = offset
            try:
                value, offset, note = _decode_named_arg_value(payload, offset, descriptor)
                status = "decoded"
            except _UnsupportedType as e:
                # The value length is unknown, so stop decoding here but keep
                # the raw attribute payload intact for later inspection.
                named_arguments.append(
                    NamedArgument(
                        kind=kind,
                        type_code=type_code,
                        type_name=descriptor.display,
                        name=name,
                        value=None,
                        raw_value=payload[start:],
                        status="unsupported",
                        note=str(e),
                    )
                )
                issues.append(str(e))
                offset = len(payload)
                break

            named_arguments.append(
                NamedArgument(
                    kind=kind,
                    type_code=type_code,
                    type_name=descriptor.display,
                    name=name,
                    value=value,
                    raw_value=payload[start:offset],
                    status=status,
                    note=note,
                )
            )
            if note:
                issues.append(note)
    except _BlobError as e:
        issues.append("permission attribute parse error: {}".format(e))
        return PermissionAttribute(
            type_name=type_name,
            attribute_type=attribute_type,
            supported=True,
            payload=payload,
            named_arguments=tuple(named_arguments),
            status="partial" if named_arguments else "malformed",
            issues=tuple(issues),
        )

    if offset != len(payload):
        issues.append("{} trailing byte(s) in permission attribute payload".format(len(payload) - offset))

    status = "partial" if issues or any(a.status != "decoded" for a in named_arguments) else "decoded"
    if not named_arguments and not issues:
        status = "empty"
    return PermissionAttribute(
        type_name=type_name,
        attribute_type=attribute_type,
        supported=True,
        payload=payload,
        named_arguments=tuple(named_arguments),
        status=status,
        issues=tuple(issues),
    )


@dataclass(frozen=True)
class SecurityDeclaration:
    """
    One ``DeclSecurity`` row.

    Storage attributes (``row``, ``action_raw``, ``permission_set``,
    ``permission_set_blob``, ``parent``, ``parent_row``) are populated even
    when interpretation fails, so the original evidence is never lost.
    """

    index: int
    row: Any
    action_raw: Optional[int]
    action: Optional[DeclSecurityAction]
    permission_set: Any
    permission_set_blob: Optional[bytes]
    permission_set_blob_index: Optional[int]
    parent: Any
    parent_raw: Optional[int]
    parent_table: Optional[str]
    parent_row_index: Optional[int]
    parent_row: Any
    parent_kind: str
    parent_token: Optional[int]
    owner_key: str
    owner_display: str
    owner_name: Optional[str]
    owner_type_name: Optional[str]
    resolved: bool
    permission_set_decoded: PermissionSet
    issues: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def action_name(self) -> str:
        if self.action is not None:
            return self.action.name
        if self.action_raw is None:
            return "unreadable"
        return "unknown(0x{:04x})".format(self.action_raw)

    @property
    def action_known(self) -> bool:
        return self.action is not None

    @property
    def storage_facts(self) -> Dict[str, Any]:
        return {
            "decl_security_row": self.index,
            "action_raw": self.action_raw,
            "parent_raw": self.parent_raw,
            "parent_table": self.parent_table,
            "parent_row_index": self.parent_row_index,
            "parent_token": None if self.parent_token is None else "0x{:08x}".format(self.parent_token),
            "permission_set_blob_index": self.permission_set_blob_index,
            "permission_set_blob_size": None if self.permission_set_blob is None else len(self.permission_set_blob),
            "permission_set_blob_hex": None if self.permission_set_blob is None else self.permission_set_blob.hex(),
        }

    @property
    def payload_interpretable(self) -> bool:
        return self.permission_set_decoded.format in ("binary", "empty") and (
            self.permission_set_decoded.status in ("decoded", "partial", "empty")
        )

    @property
    def needs_manual_review(self) -> bool:
        # An unknown action, unresolved owner or unrecognized payload is not
        # evidence of "no security".  It is evidence that this tool must not
        # make that claim.
        if self.action is None or self.action == DeclSecurityAction.Nil:
            return True
        if not self.resolved:
            return True
        return not self.payload_interpretable

    def __str__(self) -> str:
        return "row {}: action {}; {}; {}".format(
            self.index,
            self.action_name,
            self.owner_display,
            self.permission_set_decoded.display(),
        )


@dataclass(frozen=True)
class OwnerGroup:
    """All declarations that resolve to one exact metadata owner."""

    key: str
    kind: str
    token: Optional[int]
    display: str
    declarations: Tuple[SecurityDeclaration, ...]
    resolved: bool

    @property
    def actions(self) -> Tuple[int, ...]:
        return tuple(d.action_raw for d in self.declarations if d.action_raw is not None)


@dataclass(frozen=True)
class DuplicateGroup:
    """Rows that repeat the same owner, action and permission-set bytes."""

    owner_key: str
    owner_display: str
    action_raw: int
    permission_set_blob: bytes
    row_indexes: Tuple[int, ...]

    def __str__(self) -> str:
        return "{} action 0x{:04x}: rows {}".format(
            self.owner_display, self.action_raw, ", ".join(str(i) for i in self.row_indexes)
        )


@dataclass(frozen=True)
class _ParentResolution:
    table: Optional[str]
    kind: str
    row_index: Optional[int]
    token: Optional[int]
    row: Any
    key: str
    display: str
    name: Optional[str]
    type_name: Optional[str]
    resolved: bool
    issues: Tuple[str, ...]


@dataclass(frozen=True)
class SecurityAnalysis:
    """
    Read-only result of inspecting the ``DeclSecurity`` table.

    ``table_present`` and ``declared_num_rows`` describe the metadata table;
    they do not say anything about runtime enforcement.
    """

    table_present: bool
    declared_num_rows: int
    parsed_num_rows: int
    declarations: Tuple[SecurityDeclaration, ...]
    groups: Tuple[OwnerGroup, ...]
    duplicates: Tuple[DuplicateGroup, ...]
    issues: Tuple[str, ...] = ()

    @property
    def has_declarations(self) -> bool:
        """True when the table declares one or more rows, regardless of decoding."""
        return self.table_present and self.declared_num_rows > 0

    @property
    def unresolved_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if not d.resolved)

    @property
    def unknown_action_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if d.action is None)

    @property
    def unsupported_payload_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if not d.payload_interpretable)

    @property
    def needs_manual_review(self) -> bool:
        return any(d.needs_manual_review for d in self.declarations)

    @property
    def assembly_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if d.parent_kind == "assembly" and d.resolved)

    @property
    def type_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if d.parent_kind == "type" and d.resolved)

    @property
    def method_declarations(self) -> Tuple[SecurityDeclaration, ...]:
        return tuple(d for d in self.declarations if d.parent_kind == "method" and d.resolved)

    @property
    def by_owner(self) -> Dict[str, Tuple[SecurityDeclaration, ...]]:
        return {g.key: g.declarations for g in self.groups}

    @property
    def security_presence(self) -> str:
        """
        A deliberately non-verdict summary.

        This describes metadata only.  Even zero rows does not prove that a
        runtime imposes no restrictions, since policy may come from other
        sources (host configuration, CAS policy, or attributes elsewhere).
        """
        if not self.table_present:
            return "no DeclSecurity metadata table was available"
        if self.declared_num_rows == 0:
            return "DeclSecurity metadata table present with zero declared rows"
        return "{} DeclSecurity row(s) declared in metadata".format(self.declared_num_rows)

    def declarations_for_assembly(self, name: Optional[str] = None) -> Tuple[SecurityDeclaration, ...]:
        declarations = self.assembly_declarations
        if name is None:
            return declarations
        return tuple(d for d in declarations if d.owner_name == name)

    def declarations_for_type(self, name: str) -> Tuple[SecurityDeclaration, ...]:
        return tuple(
            d for d in self.type_declarations
            if d.owner_name == name or (d.owner_name or "").endswith("." + name)
        )

    def declarations_for_method(
        self, name: str, owner_type: Optional[str] = None
    ) -> Tuple[SecurityDeclaration, ...]:
        declarations = tuple(d for d in self.method_declarations if d.owner_name == name)
        if owner_type is not None:
            declarations = tuple(
                d for d in declarations
                if d.owner_type_name == owner_type
                or (d.owner_type_name or "").endswith("." + owner_type)
            )
        return declarations

    def format_report(self) -> str:
        lines: List[str] = []
        lines.append("DeclSecurity read-only analysis")
        lines.append("")
        lines.append("Storage facts")
        lines.append("  {}".format(self.security_presence))
        if self.table_present:
            lines.append(
                "  table rows: declared={} parsed={}".format(
                    self.declared_num_rows, self.parsed_num_rows
                )
            )
        for d in self.declarations:
            parent = "{}[{}]".format(d.parent_table, d.parent_row_index)
            if d.parent_token is not None:
                parent += " token=0x{:08x}".format(d.parent_token)
            lines.append(
                "  row {}: action=0x{:04x} ({}) parent=0x{:04x} ({}) blob_index={} blob_size={}".format(
                    d.index,
                    d.action_raw if d.action_raw is not None else 0,
                    d.action_name,
                    d.parent_raw if d.parent_raw is not None else 0,
                    parent,
                    d.permission_set_blob_index,
                    "unavailable" if d.permission_set_blob is None else len(d.permission_set_blob),
                )
            )
            for issue in d.issues:
                lines.append("    ! {}".format(issue))

        lines.append("")
        lines.append("Ownership (each row belongs only to the object listed for it)")
        if not self.groups:
            lines.append("  no declarations to attribute")
        for group in self.groups:
            lines.append("  {} [{}]: {} declaration(s)".format(
                group.display, group.key, len(group.declarations)
            ))
            for d in group.declarations:
                lines.append(
                    "    row {}: action=0x{:04x} ({}) payload={}/{}".format(
                        d.index,
                        d.action_raw if d.action_raw is not None else 0,
                        d.action_name,
                        d.permission_set_decoded.format,
                        d.permission_set_decoded.status,
                    )
                )

        lines.append("")
        lines.append("Duplicate declarations")
        if self.duplicates:
            for duplicate in self.duplicates:
                lines.append("  {}".format(duplicate))
        else:
            lines.append("  none detected (same owner + same action + same blob bytes)")

        lines.append("")
        lines.append("Interpreted content (explicit supported attribute subset only)")
        interpreted_rows = set()
        for d in self.declarations:
            if d.permission_set_decoded.format == "binary" and d.permission_set_decoded.attributes:
                interpreted_rows.add(d.index)
                lines.append("  row {} ({}): {}".format(d.index, d.owner_display, d.permission_set_decoded.display()))
                for attr in d.permission_set_decoded.attributes:
                    if attr.status not in ("decoded", "empty"):
                        lines.append(
                            "    {} payload preserved ({} bytes, status={})".format(
                                attr.attribute_type or "<unknown>", len(attr.payload), attr.status
                            )
                        )
        if not interpreted_rows:
            lines.append("  no supported binary payload was decoded")

        lines.append("")
        lines.append("Not interpreted")
        uninterpreted = [
            d for d in self.declarations
            if d.index not in interpreted_rows or not d.payload_interpretable
        ]
        if not uninterpreted:
            lines.append("  none")
        for d in uninterpreted:
            if d.permission_set_blob is None:
                kept = "no blob bytes were readable"
            elif d.permission_set_decoded.format == "empty":
                kept = "blob is empty"
            else:
                kept = "raw bytes kept on the declaration"
            lines.append(
                "  row {} ({}): payload={}/{}; {}".format(
                    d.index, d.owner_display,
                    d.permission_set_decoded.format, d.permission_set_decoded.status,
                    kept,
                )
            )

        lines.append("")
        lines.append("Limits on inference")
        lines.append(
            "  A DeclSecurity row is a request/annotation stored in metadata. This report "
            "does not establish whether a runtime granted, enforced, ignored, or rejected it."
        )
        lines.append(
            "  Unknown actions, unresolved parents and unrecognized payloads are listed as "
            "unknown/unsupported, not as evidence that no security requirement exists."
        )
        if self.needs_manual_review:
            lines.append("  At least one row needs manual review; do not summarize it as 'no security'.")
        if self.issues:
            for issue in self.issues:
                lines.append("  ! {}".format(issue))
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.format_report()


def _as_tables(target: Any) -> Optional[Any]:
    """Accept a dnPE/ClrData/MetaDataTables and return MetaDataTables or None."""
    if target is None:
        return None
    if hasattr(target, "tables_list") and hasattr(target, "tables"):
        return target
    if hasattr(target, "net"):
        net = target.net
        return getattr(net, "mdtables", None) if net is not None else None
    if hasattr(target, "mdtables"):
        return target.mdtables
    return None


def _safe_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return str(value)


def _build_type_names(tables: Any) -> Tuple[Dict[int, str], Dict[int, int]]:
    """Map TypeDef rid -> full name and MethodDef rid -> owning TypeDef rid."""
    typedef_table = getattr(tables, "TypeDef", None)
    method_owner: Dict[int, int] = {}
    nested: Dict[int, int] = {}

    nested_table = getattr(tables, "NestedClass", None)
    if nested_table is not None:
        try:
            for row in nested_table.rows:
                if row is None:
                    continue
                try:
                    nested[row.NestedClass.row_index] = row.EnclosingClass.row_index
                except (AttributeError, IndexError, TypeError):
                    continue
        except Exception:
            pass

    type_names: Dict[int, str] = {}
    if typedef_table is None:
        return type_names, method_owner

    try:
        rows = list(typedef_table.rows)
    except Exception:
        return type_names, method_owner

    for index, row in enumerate(rows, start=1):
        if row is None:
            continue
        name = _safe_text(getattr(row, "TypeName", None)) or "<unknown>"
        namespace = _safe_text(getattr(row, "TypeNamespace", None)) or ""
        parts = ["{}.{}".format(namespace, name) if namespace else name]
        seen = {index}
        current = index
        while current in nested:
            current = nested[current]
            if current in seen or current < 1 or current > len(rows):
                break
            seen.add(current)
            parent = rows[current - 1]
            if parent is None:
                break
            parent_name = _safe_text(getattr(parent, "TypeName", None)) or "<unknown>"
            parent_ns = _safe_text(getattr(parent, "TypeNamespace", None)) or ""
            parts.append("{}.{}".format(parent_ns, parent_name) if parent_ns else parent_name)
        type_names[index] = "+".join(reversed(parts))
        try:
            for method_index in getattr(row, "MethodList", ()) or ():
                method_owner.setdefault(method_index.row_index, index)
        except Exception:
            continue
    return type_names, method_owner


def _resolve_parent(
    raw: Optional[int],
    tables: Any,
    type_names: Dict[int, str],
    method_owner: Dict[int, int],
) -> _ParentResolution:
    """Resolve a HasDeclSecurity coded index without trusting its validity."""
    issues: List[str] = []

    if raw is None:
        return _ParentResolution(
            None, "unknown", None, None, None,
            "unresolved:unreadable", "unreadable parent coded index",
            None, None, False, ("parent coded index is unreadable",),
        )

    tag = raw & 0x03
    rid = raw >> 2
    if tag not in PARENT_TABLES:
        issues.append("invalid HasDeclSecurity parent tag {}".format(tag))
        return _ParentResolution(
            None, "invalid", None, None, None,
            "unresolved:parent=0x{:04x}".format(raw),
            "unresolved parent (invalid tag 0x{:x})".format(tag),
            None, None, False, tuple(issues),
        )

    table_name, kind, token_prefix = PARENT_TABLES[tag]
    token = (token_prefix | rid) if rid > 0 else None
    table = getattr(tables, table_name, None)

    if rid == 0:
        issues.append("HasDeclSecurity parent row index is zero")
    if table is None:
        issues.append("parent table {} is not present".format(table_name))
    elif rid > table.num_rows:
        issues.append(
            "parent {} row index {} exceeds declared row count {}".format(
                table_name, rid, table.num_rows
            )
        )

    row = None
    if table is not None and rid > 0 and rid <= table.num_rows:
        try:
            row = table.get_with_row_index(rid)
        except (IndexError, TypeError, ValueError) as e:
            issues.append("failed to read parent {}[{}]: {}".format(table_name, rid, e))
        if row is None:
            issues.append(
                "parent {}[{}] is not available (truncated or unparsed)".format(table_name, rid)
            )

    if row is None:
        # Keep the exact token so a bad index stays visibly attached to the
        # object it claims, instead of becoming a file-wide verdict.
        return _ParentResolution(
            table_name, kind, rid, token, None,
            "unresolved:parent=0x{:04x}".format(raw) if token is None else "{}:0x{:08x}".format(kind, token),
            "{}[{}] (unresolved{})".format(
                table_name, rid, "; " + "; ".join(issues) if issues else ""
            ),
            None, None, False, tuple(issues),
        )

    if kind == "assembly":
        name = _safe_text(getattr(row, "Name", None)) or "<unnamed assembly>"
        display = 'Assembly "{}"'.format(name)
        owner_name, owner_type = name, None
    elif kind == "type":
        name = type_names.get(rid, "<unknown type>")
        display = 'Type "{}"'.format(name)
        owner_name, owner_type = name, None
    else:  # method
        method_name = _safe_text(getattr(row, "Name", None)) or "<unnamed method>"
        owner_rid = method_owner.get(rid)
        owner_type = type_names.get(owner_rid) if owner_rid else None
        display = (
            'Method "{}.{}"'.format(owner_type, method_name)
            if owner_type else 'Method "[unknown type].{}"'.format(method_name)
        )
        owner_name = method_name

    # A resolved row implies rid > 0, so token is set; keep the assertion local
    # so the type checker agrees without weakening the storage facts.
    assert token is not None
    return _ParentResolution(
        table_name, kind, rid, token, row,
        "{}:0x{:08x}".format(kind, token),
        display, owner_name, owner_type, True, tuple(issues),
    )


def analyze(target: Any) -> SecurityAnalysis:
    """
    Analyze the DeclSecurity table of a dnPE, ClrData, or MetaDataTables object.

    The operation is read-only.  Every declared row is represented, including
    unreadable rows and rows whose parent or payload cannot be resolved.
    """

    tables = _as_tables(target)
    if tables is None:
        return SecurityAnalysis(
            table_present=False,
            declared_num_rows=0,
            parsed_num_rows=0,
            declarations=(),
            groups=(),
            duplicates=(),
            issues=("no .NET metadata tables were available",),
        )

    table = getattr(tables, "DeclSecurity", None)
    if table is None:
        return SecurityAnalysis(
            table_present=False,
            declared_num_rows=0,
            parsed_num_rows=0,
            declarations=(),
            groups=(),
            duplicates=(),
            issues=("metadata has no DeclSecurity table",),
        )

    type_names, method_owner = _build_type_names(tables)
    declarations: List[SecurityDeclaration] = []
    analysis_issues: List[str] = []

    declared_num_rows = int(getattr(table, "num_rows", 0) or 0)
    try:
        parsed_rows = len(table.rows)
    except Exception:
        parsed_rows = 0

    readable_rows = 0
    for zero_index in range(declared_num_rows):
        row_index = zero_index + 1
        row = None
        if zero_index < parsed_rows:
            try:
                row = table.rows[zero_index]
            except Exception as e:
                analysis_issues.append(
                    "failed to read DeclSecurity row {}: {}".format(row_index, e)
                )

        if row is None:
            declarations.append(
                SecurityDeclaration(
                    index=row_index,
                    row=None,
                    action_raw=None,
                    action=None,
                    permission_set=None,
                    permission_set_blob=None,
                    permission_set_blob_index=None,
                    parent=None,
                    parent_raw=None,
                    parent_table=None,
                    parent_row_index=None,
                    parent_row=None,
                    parent_kind="unknown",
                    parent_token=None,
                    owner_key="unresolved:row={}".format(row_index),
                    owner_display="unreadable DeclSecurity row {}".format(row_index),
                    owner_name=None,
                    owner_type_name=None,
                    resolved=False,
                    permission_set_decoded=decode_permission_set(None),
                    issues=("DeclSecurity row is not readable (truncated or unparsed)",),
                )
            )
            continue

        # A row object can exist with empty data when the table is truncated;
        # its struct never had bytes unpacked.  Treat that as unreadable rather
        # than as a row with zeroed fields.
        struct = getattr(row, "struct", None)
        action_raw = getattr(struct, "Action", None) if struct is not None else None
        if action_raw is None:
            action_raw = getattr(row, "Action", None)
        blob_index = getattr(struct, "PermissionSet_BlobIndex", None) if struct is not None else None
        raw_parent = getattr(struct, "Parent_CodedIndex", None) if struct is not None else None

        if struct is None or (action_raw is None and raw_parent is None and blob_index is None):
            declarations.append(
                SecurityDeclaration(
                    index=row_index,
                    row=row,
                    action_raw=None,
                    action=None,
                    permission_set=None,
                    permission_set_blob=None,
                    permission_set_blob_index=None,
                    parent=None,
                    parent_raw=None,
                    parent_table=None,
                    parent_row_index=None,
                    parent_row=None,
                    parent_kind="unknown",
                    parent_token=None,
                    owner_key="unresolved:row={}".format(row_index),
                    owner_display="unreadable DeclSecurity row {}".format(row_index),
                    owner_name=None,
                    owner_type_name=None,
                    resolved=False,
                    permission_set_decoded=decode_permission_set(None),
                    issues=("DeclSecurity row has no readable data (truncated table)",),
                )
            )
            continue

        readable_rows += 1

        permission_set = getattr(row, "PermissionSet", None)
        blob: Optional[bytes] = None
        if permission_set is not None:
            try:
                blob = bytes(permission_set.value_bytes())
            except Exception as e:
                analysis_issues.append(
                    "failed to read PermissionSet bytes for DeclSecurity row {}: {}".format(
                        row_index, e
                    )
                )

        payload = decode_permission_set(blob)
        declaration_issues: List[str] = list(payload.issues)

        action: Optional[DeclSecurityAction] = None
        if action_raw is None:
            declaration_issues.append("Action value is not readable")
        else:
            try:
                action = DeclSecurityAction(action_raw)
            except ValueError:
                declaration_issues.append(
                    "unknown DeclSecurity action 0x{:04x}; raw value preserved".format(action_raw)
                )
            else:
                if action == DeclSecurityAction.Nil:
                    declaration_issues.append(
                        "DeclSecurity action is Nil (0x0000), not a meaningful security action"
                    )

        if blob is None:
            if blob_index is None:
                declaration_issues.append("PermissionSet blob index is not readable")
            else:
                declaration_issues.append(
                    "PermissionSet blob index 0x{:x} does not resolve in the #Blob heap".format(
                        blob_index
                    )
                )

        parent = _resolve_parent(raw_parent, tables, type_names, method_owner)
        declaration_issues.extend(parent.issues)

        declarations.append(
            SecurityDeclaration(
                index=row_index,
                row=row,
                action_raw=action_raw,
                action=action,
                permission_set=permission_set,
                permission_set_blob=blob,
                permission_set_blob_index=blob_index,
                parent=getattr(row, "Parent", None),
                parent_raw=raw_parent,
                parent_table=parent.table,
                parent_row_index=parent.row_index,
                parent_row=parent.row,
                parent_kind=parent.kind,
                parent_token=parent.token,
                owner_key=parent.key,
                owner_display=parent.display,
                owner_name=parent.name,
                owner_type_name=parent.type_name,
                resolved=parent.resolved,
                permission_set_decoded=payload,
                issues=tuple(declaration_issues),
            )
        )

    # Group by exact owner; each owner keeps every row.  This is what prevents
    # one declaration (or one action) from overwriting another.
    group_order: List[str] = []
    group_declarations: Dict[str, List[SecurityDeclaration]] = {}
    for declaration in declarations:
        if declaration.owner_key not in group_declarations:
            group_declarations[declaration.owner_key] = []
            group_order.append(declaration.owner_key)
        group_declarations[declaration.owner_key].append(declaration)

    groups = tuple(
        OwnerGroup(
            key=key,
            kind=group_declarations[key][0].parent_kind,
            token=group_declarations[key][0].parent_token,
            display=group_declarations[key][0].owner_display,
            declarations=tuple(group_declarations[key]),
            resolved=group_declarations[key][0].resolved,
        )
        for key in group_order
    )

    # Duplicate = same owner, same action, same blob bytes.  Different actions
    # on the same owner are distinct declarations, not duplicates.
    duplicate_order: List[Tuple[str, int, bytes]] = []
    duplicate_rows: Dict[Tuple[str, int, bytes], List[int]] = {}
    for declaration in declarations:
        if declaration.action_raw is None or declaration.permission_set_blob is None:
            continue
        key = (declaration.owner_key, declaration.action_raw, declaration.permission_set_blob)
        if key not in duplicate_rows:
            duplicate_order.append(key)
            duplicate_rows[key] = []
        duplicate_rows[key].append(declaration.index)

    duplicates = tuple(
        DuplicateGroup(
            owner_key=key[0],
            owner_display=group_declarations[key[0]][0].owner_display,
            action_raw=key[1],
            permission_set_blob=key[2],
            row_indexes=tuple(duplicate_rows[key]),
        )
        for key in duplicate_order
        if len(duplicate_rows[key]) > 1
    )

    return SecurityAnalysis(
        table_present=True,
        declared_num_rows=declared_num_rows,
        parsed_num_rows=readable_rows,
        declarations=tuple(declarations),
        groups=groups,
        duplicates=duplicates,
        issues=tuple(analysis_issues),
    )
