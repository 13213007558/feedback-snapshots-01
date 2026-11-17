# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""build a minimal managed PE that exercises interleaved token kinds

The fixture is generated rather than checked in so its metadata can be reviewed
as code. It contains one method whose body uses the same integer as an InlineTok
type, an InlineType, a generic MethodSpec, a field, a method, a string, a
standalone signature, and a local variable signature.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

SECTION_RVA = 0x2000
SECTION_RAW = 0x400
SECTION_SIZE = 0x1000
HEADERS_SIZE = 0x400
CLR_HEADER_SIZE = 72


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class _MetadataBuilder:
    def __init__(self) -> None:
        self.strings = bytearray(b"\x00")
        self.blobs = bytearray(b"\x00")
        self.user_strings = bytearray(b"\x00")
        self.guids = bytes(range(16))

    def string(self, value: str) -> int:
        offset = len(self.strings)
        self.strings.extend(value.encode("utf-8") + b"\x00")
        return offset

    def blob(self, value: bytes) -> int:
        offset = len(self.blobs)
        self.blobs.append(len(value))
        self.blobs.extend(value)
        return offset

    def user_string(self, value: str) -> int:
        offset = len(self.user_strings)
        data = value.encode("utf-16-le")
        self.user_strings.append(len(data) + 1)
        self.user_strings.extend(data)
        self.user_strings.append(0)
        return offset

    def metadata_root(self, tilde: bytes) -> bytes:
        version = b"v4.0.30319\x00\x00"
        streams: List[Tuple[bytes, bytes]] = [
            (b"#~", tilde),
            (b"#Strings", bytes(self.strings)),
            (b"#US", bytes(self.user_strings)),
            (b"#GUID", self.guids),
            (b"#Blob", bytes(self.blobs)),
        ]

        header_size = 16 + len(version) + 2 + 2
        for name, _ in streams:
            header_size += 8 + _align(len(name) + 1, 4)

        offset = header_size
        stream_headers = bytearray()
        stream_data = bytearray()
        for name, data in streams:
            stream_headers.extend(struct.pack("<II", offset, len(data)))
            stream_headers.extend(name + b"\x00" + b"\x00" * (_align(len(name) + 1, 4) - len(name) - 1))
            stream_data.extend(data)
            stream_data.extend(b"\x00" * (_align(len(stream_data), 4) - len(stream_data)))
            offset = _align(offset + len(data), 4)

        root = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
        root.extend(version)
        root.extend(struct.pack("<HH", 0, len(streams)))
        root.extend(stream_headers)
        root.extend(stream_data)
        assert len(root) == offset
        return bytes(root)


def build_managed_pe() -> bytes:
    """get the bytes of the generated managed PE fixture"""
    builder = _MetadataBuilder()
    name_program = builder.string("Program")
    name_main = builder.string("Main")
    name_field = builder.string("Field1")
    name_object = builder.string("Object")
    name_system = builder.string("System")
    name_ctor = builder.string(".ctor")
    name_generic = builder.string("GenericMethod")
    name_type_param = builder.string("T")

    # method and field signatures only need plausible blob shapes for this fixture
    sig_main = builder.blob(b"\x00\x01\x01\x08")
    sig_ctor = builder.blob(b"\x20\x00\x01")
    sig_generic = builder.blob(b"\x20\x00\x01\x1e\x00")
    sig_field = builder.blob(b"\x06\x08")
    sig_locals = builder.blob(b"\x07\x01\x08")
    sig_calli = builder.blob(b"\x00\x01\x01\x08")
    sig_typespec = builder.blob(b"\x15\x12\x08\x01")
    sig_inst = builder.blob(b"\x01\x08")
    user_hello = builder.user_string("hi")

    def type_ref(scope: int, name: int, namespace: int) -> bytes:
        return struct.pack("<HHH", scope, name, namespace)

    def type_def(name: int, namespace: int, extends: int, field_list: int, method_list: int) -> bytes:
        return struct.pack("<IHHHHH", 1, name, namespace, extends, field_list, method_list)

    def method_def(rva: int, name: int, signature: int) -> bytes:
        return struct.pack("<IHHHHH", rva, 0, 0x16, name, signature, 1)

    def member_ref(parent: int, name: int, signature: int) -> bytes:
        return struct.pack("<HHH", parent, name, signature)

    # table order must match ascending table numbers so row counts and data align
    tables: List[bytes] = []
    table_numbers: List[int] = []
    row_counts: List[int] = []

    table_numbers.append(0)
    tables.append(struct.pack("<HHHHH", 0, 1, 1, 0, 0))  # Module
    row_counts.append(1)

    table_numbers.append(1)
    tables.append(type_ref(4, name_object, name_system))  # TypeRef -> Module row 1
    row_counts.append(1)

    table_numbers.append(2)
    tables.append(type_def(name_program, 0, 5, 1, 1))  # TypeDef extends TypeRef row 1
    row_counts.append(1)

    table_numbers.append(4)
    tables.append(struct.pack("<HHH", 6, name_field, sig_field))  # Field
    row_counts.append(1)

    table_numbers.append(6)
    method_row_index = len(tables)
    tables.append(method_def(0, name_main, sig_main))
    row_counts.append(1)

    table_numbers.append(10)
    tables.append(member_ref(9, name_ctor, sig_ctor))  # MemberRef parent TypeRef row 1
    tables.append(member_ref(9, name_generic, sig_generic))
    row_counts.append(2)

    table_numbers.append(17)
    tables.append(struct.pack("<H", sig_locals))  # StandAloneSig local signature
    tables.append(struct.pack("<H", sig_calli))  # StandAloneSig calli signature
    row_counts.append(2)

    table_numbers.append(27)
    tables.append(struct.pack("<H", sig_typespec))  # TypeSpec
    row_counts.append(1)

    table_numbers.append(42)
    tables.append(struct.pack("<HHHH", 0, 0, 3, name_type_param))  # GenericParam owner MethodDef row 1
    row_counts.append(1)

    table_numbers.append(43)
    tables.append(struct.pack("<HH", 5, sig_inst))  # MethodSpec -> MemberRef row 2
    row_counts.append(1)

    assert table_numbers == sorted(table_numbers)
    valid_mask = sum(1 << number for number in table_numbers)

    def encode_tables(rows: List[bytes]) -> bytes:
        tilde = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0))
        tilde.extend(b"".join(struct.pack("<I", count) for count in row_counts))
        tilde.extend(b"".join(rows))
        return bytes(tilde)

    # IL body uses each token context; offsets are relative to the method body start
    code = bytearray()

    def emit(opcode: int, operand: int = None) -> None:
        code.append(opcode)
        if operand is not None:
            code.extend(struct.pack("<I", operand))

    emit(0x72, 0x70000000 | user_hello)  # ldstr
    emit(0x28, 0x0A000001)  # call MemberRef 1
    emit(0x6F, 0x0A000002)  # callvirt MemberRef 2
    emit(0x73, 0x2B000001)  # newobj MethodSpec 1 (generic member)
    emit(0x7B, 0x04000001)  # ldfld Field 1
    emit(0xD0, 0x1B000001)  # ldtoken TypeSpec 1 (InlineTok)
    emit(0x8C, 0x1B000001)  # box TypeSpec 1 (InlineType)
    emit(0x29, 0x11000002)  # calli StandAloneSig 2
    emit(0xD0, 0x06000001)  # ldtoken MethodDef 1
    emit(0x2A)  # ret

    body = bytearray(struct.pack("<HHII", 0x3013, 8, len(code), 0x11000001))
    body.extend(code)
    body.extend(b"\x00" * (_align(len(body), 4) - len(body)))

    metadata_size = len(builder.metadata_root(encode_tables(tables)))
    meta_offset = CLR_HEADER_SIZE
    body_offset = _align(meta_offset + metadata_size, 0x10)
    method_rva = SECTION_RVA + body_offset
    assert body_offset + len(body) <= SECTION_SIZE

    # patch the MethodDef RVA now that the body location is known
    tables[method_row_index] = method_def(method_rva, name_main, sig_main)
    meta = builder.metadata_root(encode_tables(tables))
    assert len(meta) == metadata_size

    clr = struct.pack(
        "<IHHIIIIIIIIII",
        CLR_HEADER_SIZE,
        2,
        5,
        SECTION_RVA + meta_offset,
        len(meta),
        1,
        0x06000001,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    pe = bytearray(HEADERS_SIZE)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = 0x98
    struct.pack_into("<HBB", pe, optional, 0x10B, 0, 0)
    struct.pack_into("<IIII", pe, optional + 4, 0x200, 0x200, 0, 0)
    struct.pack_into("<II", pe, optional + 16, 0, SECTION_RVA)
    struct.pack_into("<I", pe, optional + 28, 0x400000)
    struct.pack_into("<II", pe, optional + 32, SECTION_RVA, 0x200)
    struct.pack_into("<HHHHHH", pe, optional + 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<IIII", pe, optional + 56, 0x4000, 0x200, 0, 3)
    struct.pack_into("<II", pe, optional + 72, 0x100000, 0x1000)
    struct.pack_into("<II", pe, optional + 80, 0x100000, 0x1000)
    struct.pack_into("<II", pe, optional + 88, 0, 16)
    struct.pack_into("<II", pe, optional + 96 + 14 * 8, SECTION_RVA, CLR_HEADER_SIZE)

    section = 0x178
    pe[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        pe,
        section + 8,
        SECTION_SIZE,
        SECTION_RVA,
        SECTION_SIZE,
        SECTION_RAW,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    raw = bytearray(SECTION_SIZE)
    raw[0:CLR_HEADER_SIZE] = clr
    raw[meta_offset : meta_offset + len(meta)] = meta
    raw[body_offset : body_offset + len(body)] = body

    return bytes(pe) + bytes(raw)
