#!/usr/bin/env python3
"""Generate a minimal .NET assembly that exercises P/Invoke (ImplMap) metadata.

No .NET compiler is required: the PE/CLR structures and the #~ metadata
stream are emitted directly.  The resulting module contains a single type
``Sample.NativeMethods`` whose methods carry ImplMap rows covering:

* the same import name under different mapping flags (ExactSpelling vs.
  CharSet.Unicode) leading to different candidate sets,
* a same-name managed overload pair sharing one import name,
* an ordinal import (``#123``),
* an unsupported calling convention (fastcall),
* a CharSet.Auto import whose transformation depends on the target platform,
* an import into a module that is missing from the export manifest.

The file is a static analysis fixture only; it is not meant to run.
"""

import struct
import sys

# CorPinvokeMap flag values (ECMA-335 II.10.1.7 / dnfile.enums).
NO_MANGLE = 0x0001
CHARSET_NOTSPEC = 0x0000
CHARSET_ANSI = 0x0002
CHARSET_UNICODE = 0x0004
CHARSET_AUTO = 0x0006
CALLCONV_WINAPI = 0x0100
CALLCONV_CDECL = 0x0200
CALLCONV_FASTCALL = 0x0500

# MethodDef flags.
MD_PUBLIC = 0x0006
MD_STATIC = 0x0010
MD_HIDEBYSIG = 0x0080
MD_PINVOKEIMPL = 0x2000
PINVOKE_METHOD_FLAGS = MD_PUBLIC | MD_STATIC | MD_HIDEBYSIG | MD_PINVOKEIMPL

# Method signatures (blob heap payloads).
SIG_NOARGS_I4 = bytes([0x00, 0x00, 0x08])        # int32 M()
SIG_I4_I4 = bytes([0x00, 0x01, 0x08, 0x08])      # int32 M(int32)

# (method name, signature, mapping flags, import name, module)
PIMPORTS = [
    ("GetVersionExact", SIG_NOARGS_I4, NO_MANGLE | CHARSET_NOTSPEC | CALLCONV_WINAPI, "GetVersion", "KERNEL32.dll"),
    ("GetVersion", SIG_NOARGS_I4, CHARSET_UNICODE | CALLCONV_WINAPI, "GetVersion", "KERNEL32.dll"),
    ("ReadFile", SIG_NOARGS_I4, CHARSET_ANSI | CALLCONV_WINAPI, "ReadFile", "KERNEL32.dll"),
    ("ReadFile", SIG_I4_I4, CHARSET_ANSI | CALLCONV_WINAPI, "ReadFile", "KERNEL32.dll"),
    ("MessageBoxAuto", SIG_NOARGS_I4, CHARSET_AUTO | CALLCONV_WINAPI, "MessageBox", "KERNEL32.dll"),
    ("OrdinalOnly", SIG_NOARGS_I4, NO_MANGLE | CHARSET_NOTSPEC | CALLCONV_WINAPI, "#123", "KERNEL32.dll"),
    ("FastCallBad", SIG_NOARGS_I4, NO_MANGLE | CHARSET_NOTSPEC | CALLCONV_FASTCALL, "FastThing", "KERNEL32.dll"),
    ("CdeclExact", SIG_NOARGS_I4, NO_MANGLE | CHARSET_NOTSPEC | CALLCONV_CDECL, "SomeCdeclFunc", "KERNEL32.dll"),
    ("DeleteFile", SIG_NOARGS_I4, CHARSET_UNICODE | CALLCONV_WINAPI, "DeleteFile", "nonexistent.dll"),
]


class Heap:
    def __init__(self, initial=b"\x00"):
        self.data = bytearray(initial)
        self.offsets = {}

    def add_string(self, value):
        if value in self.offsets:
            return self.offsets[value]
        offset = len(self.data)
        self.data += value.encode("utf-8") + b"\x00"
        self.offsets[value] = offset
        return offset

    def add_blob(self, payload):
        if payload in self.offsets:
            return self.offsets[payload]
        offset = len(self.data)
        assert len(payload) < 0x80, "only single-byte compressed lengths needed"
        self.data += bytes([len(payload)]) + payload
        self.offsets[payload] = offset
        return offset


def align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


def build_metadata():
    strings = Heap()
    blobs = Heap()
    guids = Heap(initial=b"")
    us = Heap()

    guid_offset = len(guids.data)
    guids.data += bytes(range(16))  # one dummy MVID

    # table ids used below
    (T_MODULE, T_TYPEDEF, T_METHODDEF, T_MODULEREF, T_IMPLMAP, T_ASSEMBLY) = (0, 2, 6, 26, 28, 32)

    rows = {}

    # Module table
    rows[T_MODULE] = [
        struct.pack("<HHHHH", 0, strings.add_string("pinvoke-sample.exe"), guid_offset // 16 + 1, 0, 0),
    ]

    # TypeDef table: Sample.NativeMethods, methods 1..N
    rows[T_TYPEDEF] = [
        struct.pack(
            "<IHHHHH",
            0x00100181,  # Public | Sealed | Abstract | BeforeFieldInit
            strings.add_string("NativeMethods"),
            strings.add_string("Sample"),
            0,  # Extends: none
            1,  # FieldList (Field table is empty)
            1,  # MethodList
        ),
    ]

    # MethodDef table
    method_rows = []
    for name, sig, _flags, _import, _module in PIMPORTS:
        method_rows.append(
            struct.pack(
                "<IHHHHH",
                0,  # RVA: no body for pinvokeimpl
                0,  # ImplFlags
                PINVOKE_METHOD_FLAGS,
                strings.add_string(name),
                blobs.add_blob(sig),
                1,  # ParamList (Param table is empty)
            )
        )
    rows[T_METHODDEF] = method_rows

    # ModuleRef table
    modules = []
    module_rid = {}
    for _name, _sig, _flags, _import, module in PIMPORTS:
        if module not in module_rid:
            modules.append(module)
            module_rid[module] = len(modules)
    rows[T_MODULEREF] = [struct.pack("<H", strings.add_string(m)) for m in modules]

    # ImplMap table (MemberForwarded coded index: tag 1 = MethodDef)
    implmap_rows = []
    for rid, (name, _sig, flags, import_name, module) in enumerate(PIMPORTS, start=1):
        implmap_rows.append(
            struct.pack(
                "<HHHH",
                flags,
                (rid << 1) | 1,
                strings.add_string(import_name),
                module_rid[module],
            )
        )
    rows[T_IMPLMAP] = implmap_rows

    # Assembly table
    rows[T_ASSEMBLY] = [
        struct.pack(
            "<IHHHHIHHH",
            0x8004,  # SHA1
            1, 0, 0, 0,
            0,
            0,  # PublicKey: null blob
            strings.add_string("pinvoke-sample"),
            0,  # Culture: null
        ),
    ]

    # #~ stream
    valid_mask = 0
    for table_id in rows:
        valid_mask |= 1 << table_id
    tables_stream = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, valid_mask)
    for table_id in sorted(rows):
        tables_stream += struct.pack("<I", len(rows[table_id]))
    for table_id in sorted(rows):
        for row in rows[table_id]:
            tables_stream += row

    streams = [
        ("#~", tables_stream),
        ("#Strings", bytes(strings.data)),
        ("#US", bytes(us.data)),
        ("#GUID", bytes(guids.data)),
        ("#Blob", bytes(blobs.data)),
    ]

    version = b"v4.0.30319\x00"
    header = struct.pack("<IHHI", 0x424A5342, 1, 1, 0)
    header += struct.pack("<I", align(len(version), 4))
    header += version + b"\x00" * (align(len(version), 4) - len(version))
    header += struct.pack("<HH", 0, len(streams))

    offset = len(header) + sum(8 + align(len(name) + 1, 4) for name, _ in streams)
    stream_headers = b""
    stream_data = b""
    for name, data in streams:
        stream_headers += struct.pack("<II", offset, len(data))
        encoded = name.encode("ascii") + b"\x00"
        stream_headers += encoded + b"\x00" * (align(len(encoded), 4) - len(encoded))
        stream_data += data
        pad = align(len(data), 4) - len(data)
        stream_data += b"\x00" * pad
        offset += len(data) + pad

    return header + stream_headers + stream_data


def build_pe():
    metadata = build_metadata()

    text_rva = 0x2000
    headers_size = 0x200
    file_alignment = 0x200
    section_alignment = 0x2000

    clr_header_size = 72
    metadata_rva = text_rva + clr_header_size

    text_body = struct.pack(
        "<IHHIIIIIIIIIIIIIIII",
        clr_header_size,  # cb
        2, 5,             # runtime version
        metadata_rva, len(metadata),
        0x1,              # ILONLY
        0,                # EntryPointToken
        0, 0,             # Resources
        0, 0,             # StrongNameSignature
        0, 0,             # CodeManagerTable
        0, 0,             # VTableFixups
        0, 0,             # ExportAddressTableJumps
        0, 0,             # ManagedNativeHeader
    ) + metadata

    raw_size = align(len(text_body), file_alignment)
    virtual_size = len(text_body)
    size_of_image = text_rva + align(virtual_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,  # I386
        1,      # one section
        0, 0, 0,
        224,    # SizeOfOptionalHeader
        0x0102, # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,          # PE32
        0, 0,           # linker version
        raw_size,       # SizeOfCode
        0, 0,           # initialized/uninitialized data
        0,              # AddressOfEntryPoint
        text_rva,       # BaseOfCode
        0,              # BaseOfData
        0x400000,       # ImageBase
        section_alignment,
        file_alignment,
        4, 0,           # OS version
        0, 0,           # image version
        4, 0,           # subsystem version
        0,              # Win32VersionValue
        size_of_image,
        headers_size,
        0,              # CheckSum
        3,              # Subsystem: console
        0,              # DllCharacteristics
        0x100000, 0x1000,
        0x100000, 0x1000,
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 14 * 8, text_rva, clr_header_size)
    optional += bytes(directories)
    assert len(optional) == 224

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        virtual_size,
        text_rva,
        raw_size,
        headers_size,
        0, 0, 0, 0,
        0x60000020,  # CODE | EXECUTE | READ
    )

    image = bytes(dos) + b"PE\x00\x00" + coff + optional + section
    image += b"\x00" * (headers_size - len(image))
    image += text_body + b"\x00" * (raw_size - len(text_body))
    return image


def main(argv):
    out_path = argv[1] if len(argv) > 1 else "pinvoke-sample.exe"
    with open(out_path, "wb") as handle:
        handle.write(build_pe())
    print("wrote", out_path)


if __name__ == "__main__":
    main(sys.argv)
