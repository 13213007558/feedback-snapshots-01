#!/usr/bin/env python3
"""
Build pointer-tables.exe, a hand-annotated, minimal .NET module that uses
uncompressed metadata ("#-") and the FieldPtr, MethodPtr, and ParamPtr tables.

The sample exists so that member ownership can be asserted against a layout
that is written out by hand (see README.md), rather than inferred from
whatever dnfile happens to produce.

Run from the repository root:

    python tests/data-pointer-tables/make_sample.py

The emitted file is deterministic, so re-running the script should not change
the checked-in binary.
"""
import os
import struct
import sys


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class StringsHeap:
    def __init__(self):
        self.data = bytearray(b"\x00")
        self.offsets = {b"": 0}

    def add(self, value):
        value = value.encode("utf-8") if isinstance(value, str) else value
        if value not in self.offsets:
            self.offsets[value] = len(self.data)
            self.data += value + b"\x00"
        return self.offsets[value]


class BlobHeap:
    def __init__(self):
        self.data = bytearray(b"\x00")
        self.offsets = {b"": 0}

    def add(self, value: bytes):
        if value not in self.offsets:
            assert len(value) < 0x80
            self.offsets[value] = len(self.data)
            self.data += bytes([len(value)]) + value
        return self.offsets[value]


# Metadata table numbers from ECMA-335 II.22.
MODULE = 0
TYPEDEF = 2
FIELDPTR = 3
FIELD = 4
METHODPTR = 5
METHODDEF = 6
PARAMPTR = 7
PARAM = 8

# TypeDef rows.  FieldList and MethodList index the pointer tables, as
# required by uncompressed metadata ("#-"); see README.md for the full
# ownership map that these values encode.
#
#   owner            FieldList  MethodList
#   <Module>          1          1
#   OwnerA            2          2
#   OwnerEmpty        4          4  (both runs are empty)
#   OwnerShared       4          4
#   OwnerInvalidPtr   6          5
#   OwnerDecreasing   7          7  (next owner starts lower: empty)
#   OwnerTail         5          6
#   OwnerFinal        6          7  (field run to table end; method start past end)
TYPEDEF_LAYOUT = (
    ("<Module>", 1, 1),
    ("OwnerA", 2, 2),
    ("OwnerEmpty", 4, 4),
    ("OwnerShared", 4, 4),
    ("OwnerInvalidPtr", 6, 5),
    ("OwnerDecreasing", 7, 7),
    ("OwnerTail", 5, 6),
    ("OwnerFinal", 6, 7),
)

FIELDPTR_VALUES = (1, 2, 2, 3, 0, 99, 2)
FIELD_NAMES = ("f_alpha", "f_beta", "f_gamma")

METHODPTR_VALUES = (3, 1, 4, 2, 1, 4)
METHOD_LAYOUT = (
    ("m_one", 1),
    ("m_two", 2),
    ("m_three", 4),
    ("m_four", 4),
)
METHOD_NAMES = tuple(m[0] for m in METHOD_LAYOUT)

PARAMPTR_VALUES = (2, 1, 3, 2, 1, 99)
PARAM_NAMES = ("p_first", "p_second", "p_third")


def build() -> bytes:
    strings = StringsHeap()
    blobs = BlobHeap()
    field_sig = blobs.add(b"\x06\x08")        # FIELD, int32
    method_sig = blobs.add(b"\x00\x00\x01")   # DEFAULT, 0 params, void

    name = {}
    for value in (
        [t[0] for t in TYPEDEF_LAYOUT]
        + list(FIELD_NAMES)
        + list(METHOD_NAMES)
        + list(PARAM_NAMES)
    ):
        name[value] = strings.add(value)

    # Module: Generation, Name, Mvid, EncId, EncBaseId
    module_rows = [struct.pack("<HHHHH", 0, name["<Module>"], 0, 0, 0)]

    # TypeDef: Flags, TypeName, TypeNamespace, Extends, FieldList, MethodList
    typedef_rows = [
        struct.pack("<IHHHHH", 0, name[owner], 0, 0, field_list, method_list)
        for owner, field_list, method_list in TYPEDEF_LAYOUT
    ]

    # FieldPtr: Field_Index (indexes Field)
    fieldptr_rows = [struct.pack("<H", v) for v in FIELDPTR_VALUES]
    field_rows = [
        struct.pack("<HHH", 0, name[n], field_sig)
        for n in FIELD_NAMES
    ]

    # MethodPtr: Method_Index (indexes MethodDef).  The values are deliberately
    # out of order, so direct indexing would name the wrong methods.
    methodptr_rows = [struct.pack("<H", v) for v in METHODPTR_VALUES]
    # MethodDef: Rva, ImplFlags, Flags, Name, Signature, ParamList (indexes ParamPtr)
    methoddef_rows = [
        struct.pack("<IHHHHH", 0, 0, 0, name[n], method_sig, param_list)
        for n, param_list in METHOD_LAYOUT
    ]

    # ParamPtr: Param_Index (indexes Param)
    paramptr_rows = [struct.pack("<H", v) for v in PARAMPTR_VALUES]
    # Param: Flags, Sequence, Name
    param_rows = [
        struct.pack("<HHH", 0, seq, name[n])
        for seq, n in enumerate(PARAM_NAMES, start=1)
    ]

    tables = {
        MODULE: module_rows,
        TYPEDEF: typedef_rows,
        FIELDPTR: fieldptr_rows,
        FIELD: field_rows,
        METHODPTR: methodptr_rows,
        METHODDEF: methoddef_rows,
        PARAMPTR: paramptr_rows,
        PARAM: param_rows,
    }

    mask_valid = sum(1 << number for number in tables)
    # Reserved, MajorVersion, MinorVersion, HeapOffsetSizes, Reserved,
    # MaskValid, MaskSorted.  HeapOffsetSizes = 0 -> 2-byte heap offsets.
    table_stream = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, mask_valid, 0)
    table_stream += b"".join(
        struct.pack("<I", len(tables[number])) for number in sorted(tables)
    )
    table_stream += b"".join(b"".join(tables[number]) for number in sorted(tables))

    streams = [
        (b"#-", table_stream),
        (b"#Strings", bytes(strings.data)),
        (b"#Blob", bytes(blobs.data)),
    ]

    version = b"v4.0.30319\x00\x00"
    metadata = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    metadata += struct.pack("<HH", 0, len(streams))

    # stream headers are 8 bytes + NUL-terminated name padded to 4 bytes
    header_size = len(metadata) + sum(8 + align(len(n) + 1, 4) for n, _ in streams)
    offset = header_size
    entries = b""
    payload = b""
    for stream_name, stream_data in streams:
        entries += struct.pack("<II", offset, len(stream_data))
        entries += stream_name + b"\x00" * (align(len(stream_name) + 1, 4) - len(stream_name))
        payload += stream_data
        offset += len(stream_data)
    metadata += entries + payload

    # .NET header, 72 bytes, immediately followed by the metadata root
    section_rva = 0x2000
    metadata_rva = section_rva + 72
    net_header = struct.pack(
        "<IHHIIII" + "I" * 12,
        72,              # cb
        2, 5,            # runtime version
        metadata_rva,    # MetaDataRva
        len(metadata),   # MetaDataSize
        1,               # Flags: COMIMAGE_FLAGS_ILONLY
        0,               # EntryPointTokenOrRva
        *([0] * 12),
    )
    section_data = net_header + metadata
    raw_size = align(len(section_data), 0x200)

    # PE headers: DOS stub, PE signature, COFF header, optional header, 1 section
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)          # PE32
    struct.pack_into("<BB", optional, 2, 8, 0)          # linker version
    struct.pack_into("<III", optional, 16, 0, section_rva, section_rva)
    struct.pack_into("<I", optional, 28, 0x400000)      # ImageBase
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", optional, 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", optional, 56, align(section_rva + len(section_data), 0x1000))
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)             # console subsystem
    struct.pack_into("<I", optional, 92, 16)            # NumberOfRvaAndSizes
    struct.pack_into("<II", optional, 96 + 14 * 8, section_rva, 72)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text", len(section_data), section_rva, raw_size, 0x200, 0, 0, 0, 0, 0x60000020,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    headers += b"\x00" * (0x200 - len(headers))
    return headers + section_data + b"\x00" * (raw_size - len(section_data))


def main() -> int:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pointer-tables.exe")
    data = build()
    with open(path, "wb") as f:
        f.write(data)
    print("wrote {} ({} bytes)".format(path, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
