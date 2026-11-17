#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build the small, deterministic .NET assembly used by the DeclSecurity tests.

The fixture is intentionally hand-assembled so the test suite does not need a
.NET SDK.  It packs assembly-level, type-level and method-level declarations,
including two methods with the same name in different types, distinct actions
on one method, a repeated declaration, and several malformed rows.

Usage:
    python build_sample.py [output-path]
"""

import sys
import struct
from pathlib import Path


def compressed_uint(value):
    if value <= 0x7F:
        return bytes((value,))
    if value <= 0x3FFF:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


def serstring(value):
    if value is None:
        return b"\xFF"
    raw = value.encode("utf-8")
    return compressed_uint(len(raw)) + raw


def named_argument(kind, element_type, name, value):
    return bytes((kind, element_type)) + serstring(name) + value


def permission_set(attributes):
    body = bytearray(compressed_uint(len(attributes)))
    for type_name, arguments in attributes:
        payload = compressed_uint(len(arguments)) + b"".join(arguments)
        body += serstring(type_name) + compressed_uint(len(payload)) + payload
    return b"\x2E" + bytes(body)


SECURITY = (
    "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, "
    "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
)
FILE_IO = (
    "System.Security.Permissions.FileIOPermissionAttribute, mscorlib, "
    "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
)
ENVIRONMENT = (
    "System.Security.Permissions.EnvironmentPermissionAttribute, mscorlib, "
    "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
)
REFLECTION = (
    "System.Security.Permissions.ReflectionPermissionAttribute, mscorlib, "
    "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
)
CUSTOM = "Example.CustomPermissionAttribute, Example"


def main(output):
    strings = bytearray(b"\x00")

    def string_index(value):
        index = len(strings)
        strings.extend(value.encode("utf-8") + b"\x00")
        return index

    module_name = string_index("SecurityDeclSample.exe")
    module_type = string_index("<Module>")
    type_a = string_index("TypeA")
    type_b = string_index("TypeB")
    run_name = string_index("Run")
    assembly_name = string_index("SecurityDeclSample")

    blobs = bytearray(b"\x00")

    def blob_index(value):
        index = len(blobs)
        blobs.extend(compressed_uint(len(value)) + value)
        return index

    asm_payload = permission_set(
        [(SECURITY, [named_argument(0x54, 0x02, "SkipVerification", b"\x01")])]
    )
    type_a_payload = permission_set(
        [(FILE_IO, [named_argument(0x54, 0x0E, "Read", serstring(r"C:\temp"))])]
    )
    method_payload = permission_set(
        [(SECURITY, [named_argument(0x54, 0x02, "UnmanagedCode", b"\x01")])]
    )
    same_name_payload = permission_set(
        [(REFLECTION, [named_argument(0x54, 0x02, "MemberAccess", b"\x01")])]
    )
    unknown_action_payload = permission_set(
        [(SECURITY, [named_argument(0x54, 0x02, "Assertion", b"\x01")])]
    )
    type_b_payload = permission_set(
        [
            (ENVIRONMENT, [named_argument(0x54, 0x02, "Unrestricted", b"\x01")]),
            (CUSTOM, [named_argument(0x54, 0x02, "Flag", b"\x01")]),
        ]
    )
    legacy_xml = b'<PermissionSet class="System.Security.PermissionSet" version="1"/>'
    malformed = b"\x2E\x01\x20broken"

    blob_asm = blob_index(asm_payload)
    blob_type_a = blob_index(type_a_payload)
    blob_method = blob_index(method_payload)
    blob_same_name = blob_index(same_name_payload)
    blob_unknown_action = blob_index(unknown_action_payload)
    blob_type_b = blob_index(type_b_payload)
    blob_xml = blob_index(legacy_xml)
    blob_bad = blob_index(malformed)

    # (Action, raw HasDeclSecurity coded index, blob index)
    # coded index: (rid << 2) | tag, tags: TypeDef=0, MethodDef=1, Assembly=2.
    declarations = [
        (0x0008, (1 << 2) | 2, blob_asm),                    # assembly-level request
        (0x0002, (2 << 2) | 0, blob_type_a),                 # TypeA
        (0x0002, (3 << 2) | 0, blob_type_b),                 # TypeB
        (0x0002, (1 << 2) | 1, blob_method),                 # TypeA.Run, Demand
        (0x0006, (1 << 2) | 1, blob_method),                 # TypeA.Run, LinkDemand
        (0x0003, (2 << 2) | 1, blob_same_name),              # TypeB.Run, Assert
        (0x0022, (2 << 2) | 1, blob_unknown_action),         # TypeB.Run, unknown action
        (0x0002, (99 << 2) | 0, blob_xml),                   # dangling TypeDef + legacy XML
        (0x0002, (3 << 2) | 3, blob_bad),                    # invalid parent tag
        (0x0002, (1 << 2) | 1, 0xFFFF),                      # TypeA.Run, bad blob index
        (0x0002, (1 << 2) | 1, blob_method),                 # exact duplicate of TypeA.Run Demand
    ]

    table_names = [(0, 1), (2, 3), (6, 2), (14, len(declarations)), (32, 1)]
    mask = 0
    for number, _count in table_names:
        mask |= 1 << number

    rows = bytearray()
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    rows += struct.pack("<HHHHH", 0, module_name, 0, 0, 0)
    # TypeDef: Flags, TypeName, TypeNamespace, Extends, FieldList, MethodList
    rows += struct.pack("<IHHHHH", 0x00040000, module_type, 0, 0, 0, 1)
    rows += struct.pack("<IHHHHH", 0x00040000, type_a, 0, 0, 0, 1)
    rows += struct.pack("<IHHHHH", 0, type_b, 0, 0, 0, 2)
    # MethodDef: Rva, ImplFlags, Flags, Name, Signature, ParamList
    rows += struct.pack("<IHHHHH", 0, 0, 0x0016, run_name, 0, 0)  # TypeA.Run
    rows += struct.pack("<IHHHHH", 0, 0, 0x0016, run_name, 0, 0)  # TypeB.Run
    # DeclSecurity rows
    for action, parent, permission_blob in declarations:
        rows += struct.pack("<HHH", action, parent, permission_blob)
    # Assembly: HashAlgId, versions, Flags, PublicKey, Name, Culture
    rows += struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0, assembly_name, 0)

    table_stream = (
        struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, mask, 0)
        + b"".join(struct.pack("<I", count) for _number, count in table_names)
        + bytes(rows)
    )

    version = b"v4.0.30319\x00\x00"
    root = (
        struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
        + version
        + struct.pack("<HH", 0, 3)
    )

    def stream_header(offset, size, name):
        raw = name + b"\x00"
        raw += b"\x00" * ((-len(raw)) % 4)
        return struct.pack("<II", offset, size) + raw

    header_size = (
        len(root)
        + len(stream_header(0, 0, b"#~"))
        + len(stream_header(0, 0, b"#Strings"))
        + len(stream_header(0, 0, b"#Blob"))
    )
    tables_offset = header_size
    strings_offset = tables_offset + len(table_stream)
    blobs_offset = strings_offset + len(strings)
    metadata = (
        root
        + stream_header(tables_offset, len(table_stream), b"#~")
        + stream_header(strings_offset, len(strings), b"#Strings")
        + stream_header(blobs_offset, len(blobs), b"#Blob")
        + table_stream
        + bytes(strings)
        + bytes(blobs)
    )

    # CLR header starts the .text section: cb, runtime versions, metadata
    # RVA/size, flags, entry point, then resource and strong-name fields.
    content = (
        struct.pack("<IHHIIII", 0x48, 2, 5, 0x2048, len(metadata), 1, 0)
        + b"\x00" * (0x48 - 24)
        + metadata
    )
    raw_size = (len(content) + 0x1FF) // 0x200 * 0x200
    content += b"\x00" * (raw_size - len(content))

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into("<HBBIIIIII", optional, 0, 0x10B, 1, 0, raw_size, raw_size, 0, 0, 0x2000, 0x2000)
    struct.pack_into("<I", optional, 28, 0x400000)   # ImageBase
    struct.pack_into("<I", optional, 32, 0x2000)     # SectionAlignment
    struct.pack_into("<I", optional, 36, 0x200)      # FileAlignment
    struct.pack_into("<HHHHHH", optional, 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", optional, 56, 0x4000)     # SizeOfImage
    struct.pack_into("<I", optional, 60, 0x200)      # SizeOfHeaders
    struct.pack_into("<H", optional, 68, 3)          # Subsystem
    struct.pack_into("<HH", optional, 70, 0, 0)      # DllCharacteristics
    struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", optional, 88, 0, 16)     # LoaderFlags, NumberOfRvaAndSizes
    struct.pack_into("<II", optional, 96 + 14 * 8, 0x2000, 0x48)  # COM descriptor
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(content),
        0x2000,
        raw_size,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    if len(headers) > 0x200:
        raise SystemExit("headers exceed one file-alignment unit")
    headers += b"\x00" * (0x200 - len(headers))

    Path(output).write_bytes(headers + content)


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("security-declarations.exe")
    main(destination)
    print(destination)
