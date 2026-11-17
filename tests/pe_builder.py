# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""build tiny but valid .NET PEs for end-to-end reviewer tests.

the image is a PE32 with one ``.text`` section holding the CLR header, CIL
method bodies, and a ``#~`` metadata stream. metadata is emitted with 4-byte
heap indexes, so row layouts stay simple. nothing here is ever executed.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Union, Optional
from dataclasses import field, dataclass

SECTION_ALIGNMENT = 0x2000
FILE_ALIGNMENT = 0x200
TEXT_RVA = 0x2000
TEXT_RAW = 0x400
IMAGE_BASE = 0x400000
CLR_HEADER_SIZE = 0x48
CLR_FLAGS_ILONLY = 0x00000001

MODULE = 0x00
TYPEREF = 0x01
TYPEDEF = 0x02
METHODDEF = 0x06
MEMBERREF = 0x0A
STANDALONESIG = 0x11
MODULEREF = 0x1A
TYPESPEC = 0x1B
IMPLMAP = 0x1C
GENERICPARAM = 0x2A
METHODSPEC = 0x2B

TABLE_ORDER = [
    MODULE,
    TYPEREF,
    TYPEDEF,
    METHODDEF,
    MEMBERREF,
    STANDALONESIG,
    MODULEREF,
    TYPESPEC,
    IMPLMAP,
    GENERICPARAM,
    METHODSPEC,
]

HEAP_OFFSET_SIZES = 0x07  # 4-byte #Strings, #GUID, #Blob offsets


class _BlobHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.index: Dict[bytes, int] = {b"": 0}

    def add(self, value: bytes) -> int:
        if value in self.index:
            return self.index[value]
        offset = len(self.data)
        self.data.extend(_compressed_uint(len(value)))
        self.data.extend(value)
        self.index[value] = offset
        return offset


class _StringHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.index: Dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        if value in self.index:
            return self.index[value]
        offset = len(self.data)
        self.data.extend(value.encode("utf-8"))
        self.data.append(0)
        self.index[value] = offset
        return offset


@dataclass
class TypeRef:
    namespace: str
    name: str
    rid: int = 0


@dataclass
class ModuleRef:
    name: str
    rid: int = 0


@dataclass
class Method:
    name: str
    declaring_type: str
    body: Optional[bytes]
    pinvoke_module: Optional[str] = None
    pinvoke_name: Optional[str] = None
    virtual: bool = False
    abstract: bool = False
    generic: bool = False
    rid: int = 0
    body_rva: int = 0


@dataclass
class MemberRef:
    name: str
    parent: Union[TypeRef, ModuleRef]
    generic: bool = False
    rid: int = 0


@dataclass
class MethodSpecRef:
    name: str
    parent: MemberRef
    rid: int = 0


@dataclass
class AssemblySpec:
    module_name: str = "Fixture.dll"
    assembly_name: str = "Fixture"
    type_name: str = "Fixture"
    methods: List[Method] = field(default_factory=list)
    type_refs: List[TypeRef] = field(default_factory=list)
    module_refs: List[ModuleRef] = field(default_factory=list)
    member_refs: List[MemberRef] = field(default_factory=list)
    method_specs: List[MethodSpecRef] = field(default_factory=list)
    generic_param_rids: List[int] = field(default_factory=list)
    entry_point_rid: Optional[int] = None
    calli_signatures: int = 0

    def add_method(self, name: str, body: Optional[bytes], **kwargs) -> Method:
        method = Method(name=name, declaring_type=self.type_name, body=body, **kwargs)
        method.rid = len(self.methods) + 1
        self.methods.append(method)
        return method

    def add_type_ref(self, namespace: str, name: str) -> TypeRef:
        ref = TypeRef(namespace=namespace, name=name)
        ref.rid = len(self.type_refs) + 1
        self.type_refs.append(ref)
        return ref

    def add_module_ref(self, name: str) -> ModuleRef:
        ref = ModuleRef(name=name)
        ref.rid = len(self.module_refs) + 1
        self.module_refs.append(ref)
        return ref

    def add_member_ref(self, name: str, parent: Union[TypeRef, ModuleRef], generic: bool = False) -> MemberRef:
        ref = MemberRef(name=name, parent=parent, generic=generic)
        ref.rid = len(self.member_refs) + 1
        self.member_refs.append(ref)
        return ref

    def add_method_spec(self, name: str, parent: MemberRef) -> MethodSpecRef:
        ref = MethodSpecRef(name=name, parent=parent)
        ref.rid = len(self.method_specs) + 1
        self.method_specs.append(ref)
        return ref


def method_token(rid: int) -> int:
    return (METHODDEF << 24) | rid


def member_ref_token(rid: int) -> int:
    return (MEMBERREF << 24) | rid


def method_spec_token(rid: int) -> int:
    return (METHODSPEC << 24) | rid


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _compressed_uint(value: int) -> bytes:
    if value < 0x80:
        return struct.pack("<B", value)
    if value < 0x4000:
        return struct.pack("<H", 0x8000 | value)
    return struct.pack("<I", value | 0xC0000000)[:4]


def tiny(code: bytes) -> bytes:
    """wrap CIL bytes in a tiny method header (max 63 bytes of code)."""
    if len(code) > 63:
        raise ValueError("tiny method bodies hold at most 63 bytes")
    return bytes([(len(code) << 2) | 0x02]) + code


def _method_signature(param_count: int = 0, generic_params: int = 0, has_this: bool = False) -> bytes:
    flags = 0x20 if has_this else 0x00
    body = bytes([flags])
    if generic_params:
        body += _compressed_uint(generic_params)
    body += _compressed_uint(param_count) + b"\x01"
    return _compressed_uint(len(body)) + body


def _member_ref_signature(has_this: bool = False) -> bytes:
    body = bytes([0x20 if has_this else 0x00]) + b"\x00\x01"
    return _compressed_uint(len(body)) + body


def _calli_signature() -> bytes:
    body = b"\x00\x00\x01"
    return _compressed_uint(len(body)) + body


def _build_tables(assembly: AssemblySpec, strings: _StringHeap, blobs: _BlobHeap) -> bytes:
    module_rows = [
        struct.pack("<HIIII", 0, strings.add(assembly.module_name), 0, 0, 0),
    ]

    type_ref_rows = [
        struct.pack(
            "<HII",
            (1 << 2) | 0,  # ResolutionScope -> Module row 1
            strings.add(ref.name),
            strings.add(ref.namespace),
        )
        for ref in assembly.type_refs
    ]

    type_def_rows = [
        struct.pack("<IIIHHH", 0, strings.add("<Module>"), strings.add(""), 0, 1, 1),
        struct.pack(
            "<IIIHHH",
            0x00100001,
            strings.add(assembly.type_name),
            strings.add(""),
            0,
            1,
            1,
        ),
    ]

    method_rows = []
    for method in assembly.methods:
        flags = 0x0016
        if method.pinvoke_module:
            flags |= 0x2000
        if method.virtual:
            flags |= 0x0040
        if method.abstract:
            flags |= 0x0400
        impl_flags = 0x0000 if method.body is not None else 0x0003
        method_rows.append(
            struct.pack(
                "<IHHIIH",
                method.body_rva,
                impl_flags,
                flags,
                strings.add(method.name),
                blobs.add(_method_signature(generic_params=1 if method.generic else 0)),
                1,
            )
        )

    member_ref_rows = []
    for ref in assembly.member_refs:
        if isinstance(ref.parent, ModuleRef):
            coded = (ref.parent.rid << 3) | 2
        else:
            coded = (ref.parent.rid << 3) | 1
        member_ref_rows.append(struct.pack("<HII", coded, strings.add(ref.name), blobs.add(_member_ref_signature())))

    stand_alone_sig_rows = [
        struct.pack("<I", blobs.add(_calli_signature())) for _ in range(max(1, assembly.calli_signatures))
    ]

    module_ref_rows = [struct.pack("<I", strings.add(ref.name)) for ref in assembly.module_refs]

    impl_map_rows = []
    for method in assembly.methods:
        if not method.pinvoke_module:
            continue
        module_ref = next(ref for ref in assembly.module_refs if ref.name == method.pinvoke_module)
        impl_map_rows.append(
            struct.pack(
                "<HHIH",
                0,
                (method.rid << 1) | 1,
                strings.add(method.pinvoke_name or method.name),
                module_ref.rid,
            )
        )

    generic_param_rows = [
        struct.pack("<HHIH", 0, 0, (rid << 1) | 1, strings.add("T")) for rid in assembly.generic_param_rids
    ]

    method_spec_rows = [
        struct.pack("<HI", (ref.parent.rid << 1) | 1, blobs.add(b"\x01\x01")) for ref in assembly.method_specs
    ]

    rows: Dict[int, List[bytes]] = {
        MODULE: module_rows,
        TYPEREF: type_ref_rows,
        TYPEDEF: type_def_rows,
        METHODDEF: method_rows,
        MEMBERREF: member_ref_rows,
        STANDALONESIG: stand_alone_sig_rows if (assembly.calli_signatures or True) else [],
        MODULEREF: module_ref_rows,
        IMPLMAP: impl_map_rows,
        GENERICPARAM: generic_param_rows,
        METHODSPEC: method_spec_rows,
    }

    valid_mask = 0
    for table in TABLE_ORDER:
        if rows.get(table):
            valid_mask |= 1 << table

    counts = b"".join(struct.pack("<I", len(rows[table])) for table in TABLE_ORDER if rows.get(table))
    data = b"".join(b"".join(rows[table]) for table in TABLE_ORDER if rows.get(table))

    header = struct.pack("<IBBBBQQ", 0, 2, 0, HEAP_OFFSET_SIZES, 1, valid_mask, 0)
    return header + counts + data


def _build_metadata(assembly: AssemblySpec) -> bytes:
    strings = _StringHeap()
    blobs = _BlobHeap()
    tables = _build_tables(assembly, strings, blobs)

    tables_name = b"#~\x00\x00"
    strings_name = b"#Strings\x00\x00\x00\x00"
    blob_name = b"#Blob\x00\x00\x00"

    version = b"v4.0.30319\x00\x00"
    header = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    header += struct.pack("<HH", 0, 4)

    guid_name = b"#GUID\x00\x00\x00"
    guid_data = b"\x00" * 16
    streams_len = 12 + 20 + 16 + 16
    tables_offset = len(header) + streams_len
    strings_offset = tables_offset + len(tables)
    blob_offset = strings_offset + len(strings.data)
    guid_offset = blob_offset + len(blobs.data)

    streams = (
        struct.pack("<II", tables_offset, len(tables))
        + tables_name
        + struct.pack("<II", strings_offset, len(strings.data))
        + strings_name
        + struct.pack("<II", blob_offset, len(blobs.data))
        + blob_name
        + struct.pack("<II", guid_offset, len(guid_data))
        + guid_name
    )
    assert len(streams) == streams_len
    return header + streams + tables + bytes(strings.data) + bytes(blobs.data) + guid_data


def _layout_code(assembly: AssemblySpec) -> bytes:
    code = bytearray()
    for method in assembly.methods:
        if method.body is None:
            method.body_rva = 0
            continue
        code.extend(b"\x00" * (_align(len(code), 4) - len(code)))
        method.body_rva = TEXT_RVA + CLR_HEADER_SIZE + len(code)
        code.extend(method.body)
    return bytes(code)


def _pe_headers(text_size: int, metadata_rva: int, metadata_size: int) -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    signature = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into("<HBBIIIII", optional, 0, 0x10B, 6, 0, 0, 0, 0, TEXT_RVA, TEXT_RVA)
    struct.pack_into("<I", optional, 28, IMAGE_BASE)
    struct.pack_into("<II", optional, 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
    struct.pack_into("<HH", optional, 40, 4, 0)
    struct.pack_into("<HH", optional, 48, 4, 0)
    struct.pack_into("<I", optional, 56, _align(TEXT_RVA + text_size, SECTION_ALIGNMENT))
    struct.pack_into("<I", optional, 60, 0x400)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    # CLR data directory is entry 14
    struct.pack_into("<II", optional, 96 + 14 * 8, TEXT_RVA, CLR_HEADER_SIZE)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        text_size,
        TEXT_RVA,
        _align(text_size, FILE_ALIGNMENT),
        TEXT_RAW,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + signature + coff + bytes(optional) + section
    return headers + b"\x00" * (TEXT_RAW - len(headers))


def _clr_header(metadata_rva: int, metadata_size: int, entry_token: int) -> bytes:
    return struct.pack(
        "<IHHIIIIIIIIIIIIIIII",
        CLR_HEADER_SIZE,
        2,
        5,
        metadata_rva,
        metadata_size,
        CLR_FLAGS_ILONLY,
        entry_token,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )


def build_pe(assembly: AssemblySpec) -> bytes:
    """return a complete PE32 image for ``assembly``.

    two passes: the first fixes string/blob heap layout and method RVAs, the
    second emits identical metadata plus the final CLR entry point token.
    """
    code = _layout_code(assembly)
    metadata = _build_metadata(assembly)

    text = bytearray(CLR_HEADER_SIZE + len(code))
    text[CLR_HEADER_SIZE : CLR_HEADER_SIZE + len(code)] = code
    metadata_rva = TEXT_RVA + CLR_HEADER_SIZE + _align(len(code), 4)
    text.extend(b"\x00" * (metadata_rva - (TEXT_RVA + len(text))))
    text.extend(metadata)

    entry_token = method_token(assembly.entry_point_rid) if assembly.entry_point_rid else 0
    text[0:CLR_HEADER_SIZE] = _clr_header(metadata_rva, len(metadata), entry_token)

    resolved = bytes(text)
    resolved += b"\x00" * (_align(len(resolved), FILE_ALIGNMENT) - len(resolved))
    headers = _pe_headers(len(resolved), metadata_rva, len(metadata))
    return headers + resolved
