"""
Minimal .NET PE/metadata builder for tests.

Builds just enough of a PE32 + CLR header + metadata (#~, #Strings, #US,
#GUID, #Blob) for dnfile to parse Module, TypeDef, Assembly, AssemblyRef,
File, and ExportedType tables.  No code, no resources.
"""

import struct

# Implementation coded-index tags (ECMA-335 II.24.2.6)
IMPL_TAG = {"File": 0, "AssemblyRef": 1, "ExportedType": 2}


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _compressed_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x8000 | value)
    return struct.pack(">I", 0xC0000000 | value)


class _Strings(object):
    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.offsets = {"": 0}

    def add(self, s):
        if s in self.offsets:
            return self.offsets[s]
        offset = len(self.buf)
        self.buf += s.encode("utf-8") + b"\x00"
        self.offsets[s] = offset
        return offset


class _Blobs(object):
    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.offsets = {b"": 0}

    def add(self, data):
        if data in self.offsets:
            return self.offsets[data]
        offset = len(self.buf)
        self.buf += _compressed_uint(len(data)) + data
        self.offsets[data] = offset
        return offset


def _tables_stream(tables):
    valid = 0
    for number in tables:
        valid |= 1 << number
    out = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    for number in sorted(tables):
        out += struct.pack("<I", len(tables[number]))
    for number in sorted(tables):
        out += b"".join(tables[number])
    return out


def _metadata(streams):
    version = b"v4.0.30319\x00"
    version = version.ljust(_align(len(version), 4), b"\x00")
    header = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
    header += version
    header += struct.pack("<HH", 0, len(streams))

    entries_len = 0
    for name, _ in streams:
        entries_len += 8 + _align(len(name) + 1, 4)

    offset = len(header) + entries_len
    entries = b""
    data = b""
    for name, blob in streams:
        entries += struct.pack("<II", offset, len(blob))
        entries += name + b"\x00" * (_align(len(name) + 1, 4) - len(name))
        padded = blob + b"\x00" * (_align(len(blob), 4) - len(blob))
        data += padded
        offset += len(padded)
    return header + entries + data


def _pe_wrap(payload, characteristics=0x2002):
    file_align = 0x200
    section_align = 0x2000
    e_lfanew = 0x80
    raw_ptr = 0x200
    section_rva = 0x2000
    raw_size = _align(len(payload), file_align)
    size_of_image = section_rva + _align(len(payload), section_align)

    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, characteristics)

    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 0, 0,
        raw_size, 0, 0,
        0, section_rva, 0,
        0x400000, section_align, file_align,
        4, 0, 0, 0, 4, 0,
        0, size_of_image, raw_ptr, 0,
        3, 0,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 14 * 8, section_rva, 72)
    opt += bytes(directories)
    assert len(opt) == 0xE0

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(payload), section_rva, raw_size, raw_ptr,
        0, 0, 0, 0, 0x60000020,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + section
    headers = headers.ljust(raw_ptr, b"\x00")
    return headers + payload.ljust(raw_size, b"\x00")


def build_module(
    *,
    module_name,
    assembly=None,
    assembly_refs=(),
    files=(),
    type_defs=(),
    exported_types=(),
):
    """
    Build a minimal .NET module.

    assembly:       None or dict(name, version=(1,0,0,0), culture="",
                    public_key=b"", flags=0)
    assembly_refs:  list of dict(name, version=(1,0,0,0), culture="",
                    public_key_or_token=b"", flags=0, hash_value=b"")
    files:          list of module file names (File table)
    type_defs:      list of (namespace, name) tuples
    exported_types: list of dict(namespace="", name, typedef_id=0,
                    impl=None | (table_name, rid), flags=1)
    """
    strings = _Strings()
    blobs = _Blobs()

    tables = {}
    # Module (0)
    tables[0] = [struct.pack("<HHHHH", 0, strings.add(module_name), 1, 0, 0)]

    if type_defs:
        # TypeDef (2)
        tables[2] = [
            struct.pack(
                "<IHHHHH",
                0x100001,  # tdPublic | tdBeforeFieldInit
                strings.add(name),
                strings.add(namespace),
                0,  # Extends
                1,  # FieldList
                1,  # MethodList
            )
            for namespace, name in type_defs
        ]

    if assembly is not None:
        # Assembly (32)
        version = assembly.get("version", (1, 0, 0, 0))
        tables[32] = [
            struct.pack(
                "<IHHHHIHHH",
                0x8004,  # SHA1
                *version,
                assembly.get("flags", 0),
                blobs.add(assembly.get("public_key", b"")),
                strings.add(assembly["name"]),
                strings.add(assembly.get("culture", "")),
            )
        ]

    if assembly_refs:
        # AssemblyRef (35)
        tables[35] = [
            struct.pack(
                "<HHHHIHHHH",
                *ref.get("version", (1, 0, 0, 0)),
                ref.get("flags", 0),
                blobs.add(ref.get("public_key_or_token", b"")),
                strings.add(ref["name"]),
                strings.add(ref.get("culture", "")),
                blobs.add(ref.get("hash_value", b"")),
            )
            for ref in assembly_refs
        ]

    if files:
        # File (38)
        tables[38] = [
            struct.pack("<IHH", 0, strings.add(name), blobs.add(b""))
            for name in files
        ]

    if exported_types:
        # ExportedType (39)
        rows = []
        for et in exported_types:
            impl = et.get("impl")
            coded = 0
            if impl is not None:
                table_name, rid = impl
                coded = (rid << 2) | IMPL_TAG[table_name]
            rows.append(
                struct.pack(
                    "<IIHHH",
                    et.get("flags", 1),
                    et.get("typedef_id", 0),
                    strings.add(et["name"]),
                    strings.add(et.get("namespace", "")),
                    coded,
                )
            )
        tables[39] = rows

    tables_stream = _tables_stream(tables)
    metadata = _metadata(
        [
            (b"#~", tables_stream),
            (b"#Strings", bytes(strings.buf)),
            (b"#US", b"\x00"),
            (b"#GUID", bytes(range(16))),
            (b"#Blob", bytes(blobs.buf)),
        ]
    )

    section_rva = 0x2000
    clr_header = struct.pack(
        "<IHHIIII",
        72,  # cb
        2, 5,  # runtime version
        section_rva + 72,  # MetaData RVA
        len(metadata),  # MetaData size
        1,  # ILONLY
        0,  # EntryPointToken
    ) + b"\x00" * 48

    return _pe_wrap(clr_header + metadata)
