"""Deterministically hand-assembled .NET PE fixtures.

The upstream test corpus has no two same-named AssemblyRefs and no nested
TypeRef chain, so these fixtures are assembled directly from the ECMA-335
metadata layout.  They are structurally valid PE/CLR images (parseable by
dnfile and pefile), but they are *not* compiler output: there is no runtime,
no imports, and every method body is `ret`.

All bytes derive from fixed seeds, so rebuilding yields identical files.
The strong-name blobs are synthetic: they have the CAPI PUBLICKEYBLOB shape,
but they are not valid RSA keys and nothing here verifies a signature.
"""

from __future__ import annotations

import hashlib
import struct

# ---------------------------------------------------------------- primitives

def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def compress_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("<H", value | 0x8000)
    return struct.pack("<I", value | 0xC0000000)


def public_key_token(public_key: bytes) -> bytes:
    """ECMA-335 strong-name token: last 8 bytes of SHA-1, reversed."""
    return hashlib.sha1(public_key).digest()[-8:][::-1]


def synthetic_public_key(seed: bytes) -> bytes:
    """A CAPI PUBLICKEYBLOB-shaped, deterministic, non-cryptographic key."""
    modulus = b""
    counter = 0
    while len(modulus) < 128:
        modulus += hashlib.sha512(seed + counter.to_bytes(4, "little")).digest()
        counter += 1
    blob_header = struct.pack("<BBHI", 0x06, 0x02, 0x0000, 0x00002400)
    rsa_header = b"RSA1" + struct.pack("<II", 1024, 65537)
    return blob_header + rsa_header + modulus[:128]


TABLE_NUMBERS = {
    "Module": 0,
    "TypeRef": 1,
    "TypeDef": 2,
    "Field": 4,
    "MethodDef": 6,
    "Param": 8,
    "MemberRef": 10,
    "ModuleRef": 26,
    "TypeSpec": 27,
    "Assembly": 32,
    "AssemblyRef": 35,
    "NestedClass": 41,
}

CODED_INDEXES = {
    "TypeDefOrRef": (2, ("TypeDef", "TypeRef", "TypeSpec")),
    "ResolutionScope": (2, ("Module", "ModuleRef", "AssemblyRef", "TypeRef")),
    "MemberRefParent": (3, ("TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec")),
}

COLUMNS = {
    0: [
        ("Generation", "u2"),
        ("Name", "str"),
        ("Mvid", "guid"),
        ("EncId", "guid"),
        ("EncBaseId", "guid"),
    ],
    1: [
        ("ResolutionScope", "coded:ResolutionScope"),
        ("TypeName", "str"),
        ("TypeNamespace", "str"),
    ],
    2: [
        ("Flags", "u4"),
        ("TypeName", "str"),
        ("TypeNamespace", "str"),
        ("Extends", "coded:TypeDefOrRef"),
        ("FieldList", "idx:Field"),
        ("MethodList", "idx:MethodDef"),
    ],
    4: [("Flags", "u2"), ("Name", "str"), ("Signature", "blob")],
    6: [
        ("Rva", "u4"),
        ("ImplFlags", "u2"),
        ("Flags", "u2"),
        ("Name", "str"),
        ("Signature", "blob"),
        ("ParamList", "idx:Param"),
    ],
    10: [("Class", "coded:MemberRefParent"), ("Name", "str"), ("Signature", "blob")],
    32: [
        ("HashAlgId", "u4"),
        ("MajorVersion", "u2"),
        ("MinorVersion", "u2"),
        ("BuildNumber", "u2"),
        ("RevisionNumber", "u2"),
        ("Flags", "u4"),
        ("PublicKey", "blob"),
        ("Name", "str"),
        ("Culture", "str"),
    ],
    35: [
        ("MajorVersion", "u2"),
        ("MinorVersion", "u2"),
        ("BuildNumber", "u2"),
        ("RevisionNumber", "u2"),
        ("Flags", "u4"),
        ("PublicKey", "blob"),
        ("Name", "str"),
        ("Culture", "str"),
        ("HashValue", "blob"),
    ],
    41: [("NestedClass", "idx:TypeDef"), ("EnclosingClass", "idx:TypeDef")],
}

AF_PUBLIC_KEY = 0x0001
AF_RETARGETABLE = 0x0100


def coded_value(kind: str, table: str, rid: int) -> int:
    bits, names = CODED_INDEXES[kind]
    return (rid << bits) | names.index(table)


class _Heaps:
    def __init__(self) -> None:
        self.strings = bytearray(b"\x00")
        self.blob = bytearray(b"\x00")
        self.guid = bytearray()
        self._string_cache = {"": 0}
        self._blob_cache = {b"": 0}

    def add_string(self, value: str) -> int:
        if value not in self._string_cache:
            self._string_cache[value] = len(self.strings)
            self.strings += value.encode("utf-8") + b"\x00"
        return self._string_cache[value]

    def add_blob(self, value: bytes) -> int:
        if value not in self._blob_cache:
            self._blob_cache[value] = len(self.blob)
            self.blob += compress_uint(len(value)) + value
        return self._blob_cache[value]

    def add_guid(self, value: bytes) -> int:
        assert len(value) == 16
        self.guid += value
        return len(self.guid) // 16


# ------------------------------------------------------------------- builder

class AssemblyBuilder:
    """Minimal ECMA-335 writer for the tables used by the demo."""

    def __init__(
        self,
        name: str,
        version: tuple[int, int, int, int] = (0, 0, 0, 0),
        culture: str = "",
        public_key: bytes | None = None,
        flags: int = 0,
        kind: str = "dll",
        mvid_seed: bytes = b"fixture",
    ) -> None:
        self.name = name
        self.version = version
        self.culture = culture
        self.public_key = public_key
        self.flags = flags
        self.kind = kind
        self.heaps = _Heaps()
        self.mvid = hashlib.md5(mvid_seed + name.encode()).digest()
        self._mvid_index: int | None = None

        self.assembly_refs: list[dict] = []
        self.type_refs: list[dict] = []
        self.fields: list[dict] = []
        self.methods: list[dict] = []
        self.member_refs: list[dict] = []
        self.typedefs: list[dict] = []
        self.nested: list[tuple[int, int]] = []
        self._bodies: list[bytes] = []

    # -- row helpers -------------------------------------------------------
    def add_assembly_ref(
        self,
        name: str,
        version: tuple[int, int, int, int],
        culture: str,
        key_or_token: bytes | None,
        flags: int = 0,
    ) -> int:
        self.assembly_refs.append(
            {
                "MajorVersion": version[0],
                "MinorVersion": version[1],
                "BuildNumber": version[2],
                "RevisionNumber": version[3],
                "Flags": flags,
                "PublicKey": key_or_token or b"",
                "Name": name,
                "Culture": culture,
                "HashValue": b"",
            }
        )
        return len(self.assembly_refs)

    def add_type_ref(self, scope: tuple[str, int] | None, namespace: str, name: str) -> int:
        value = 0 if scope is None else coded_value("ResolutionScope", scope[0], scope[1])
        self.type_refs.append(
            {"ResolutionScope": value, "TypeName": name, "TypeNamespace": namespace}
        )
        return len(self.type_refs)

    def add_type_def(
        self,
        namespace: str,
        name: str,
        extends: tuple[str, int] | None,
        flags: int = 0x00000001,
        field_start: int = 1,
        method_start: int = 1,
    ) -> int:
        self.typedefs.append(
            {
                "Flags": flags,
                "TypeName": name,
                "TypeNamespace": namespace,
                "Extends": 0 if extends is None else coded_value("TypeDefOrRef", extends[0], extends[1]),
                "FieldList": field_start,
                "MethodList": method_start,
            }
        )
        return len(self.typedefs)

    def add_field(self, name: str, signature: bytes, flags: int = 0x0016) -> int:
        self.fields.append({"Flags": flags, "Name": name, "Signature": signature})
        return len(self.fields)

    def add_method(self, name: str, signature: bytes, flags: int = 0x0006, body: bytes = b"\x2a") -> int:
        while len(body) % 4:
            body += b"\x00"
        assert len(body) < 64
        self._bodies.append(bytes([((len(body) // 4) << 2) | 0x02]) + body)
        self.methods.append(
            {
                "Rva": 0,
                "ImplFlags": 0,
                "Flags": flags,
                "Name": name,
                "Signature": signature,
                "ParamList": 1,
            }
        )
        return len(self.methods)

    def add_member_ref(self, parent: tuple[str, int], name: str, signature: bytes) -> int:
        self.member_refs.append(
            {
                "Class": coded_value("MemberRefParent", parent[0], parent[1]),
                "Name": name,
                "Signature": signature,
            }
        )
        return len(self.member_refs)

    def add_nested(self, nested_rid: int, enclosing_rid: int) -> None:
        self.nested.append((nested_rid, enclosing_rid))

    # -- serialisation -----------------------------------------------------
    def _row_counts(self) -> dict[int, int]:
        return {
            0: 1,
            1: len(self.type_refs),
            2: len(self.typedefs),
            4: len(self.fields),
            6: len(self.methods),
            10: len(self.member_refs),
            32: 1,
            35: len(self.assembly_refs),
            41: len(self.nested),
        }

    @staticmethod
    def _width(kind: str, counts: dict[int, int]) -> int:
        if kind == "u2":
            return 2
        if kind == "u4":
            return 4
        if kind in ("str", "guid", "blob"):
            return 2  # HeapOffsetSizes == 0 in every fixture
        if kind.startswith("idx:"):
            return 2 if counts.get(TABLE_NUMBERS[kind[4:]], 0) <= 0xFFFF else 4
        if kind.startswith("coded:"):
            bits, names = CODED_INDEXES[kind[6:]]
            maximum = max(counts.get(TABLE_NUMBERS[n], 0) for n in names)
            return 2 if maximum <= (1 << (16 - bits)) else 4
        raise AssertionError(kind)

    def _rows_for(self, number: int) -> list[dict]:
        if number == 0:
            if self._mvid_index is None:
                self._mvid_index = self.heaps.add_guid(self.mvid)
            return [
                {
                    "Generation": 0,
                    "Name": self.name,
                    "Mvid": self._mvid_index,
                    "EncId": 0,
                    "EncBaseId": 0,
                }
            ]
        if number == 1:
            return self.type_refs
        if number == 2:
            return self.typedefs
        if number == 4:
            return self.fields
        if number == 6:
            return self.methods
        if number == 10:
            return self.member_refs
        if number == 32:
            return [
                {
                    "HashAlgId": 0x8004,
                    "MajorVersion": self.version[0],
                    "MinorVersion": self.version[1],
                    "BuildNumber": self.version[2],
                    "RevisionNumber": self.version[3],
                    "Flags": self.flags,
                    "PublicKey": self.public_key or b"",
                    "Name": self.name,
                    "Culture": self.culture,
                }
            ]
        if number == 35:
            return self.assembly_refs
        if number == 41:
            return [{"NestedClass": n, "EnclosingClass": e} for n, e in self.nested]
        raise AssertionError(number)

    def _pack_row(self, number: int, row: dict, counts: dict[int, int]) -> bytes:
        out = bytearray()
        for name, kind in COLUMNS[number]:
            value = row[name]
            width = self._width(kind, counts)
            if kind == "u2":
                out += struct.pack("<H", value)
            elif kind == "u4":
                out += struct.pack("<I", value)
            elif kind == "str":
                out += struct.pack("<H", self.heaps.add_string(str(value)))
            elif kind == "blob":
                out += struct.pack("<H", self.heaps.add_blob(bytes(value)))
            elif kind == "guid":
                out += struct.pack("<H", int(value))
            elif kind.startswith("idx:") or kind.startswith("coded:"):
                out += struct.pack("<H" if width == 2 else "<I", int(value))
            else:
                raise AssertionError(kind)
        return bytes(out)

    def _tables_stream(self) -> bytes:
        counts = self._row_counts()
        present = sorted(n for n, c in counts.items() if c > 0)
        valid = 0
        for number in present:
            valid |= 1 << number

        header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
        body = bytearray()
        for number in present:
            body += struct.pack("<I", counts[number])
        for number in present:
            for row in self._rows_for(number):
                body += self._pack_row(number, row, counts)
        return header + bytes(body)

    def _metadata(self) -> bytes:
        streams = [
            (b"#~", self._tables_stream()),
            (b"#Strings", bytes(self.heaps.strings)),
            (b"#GUID", bytes(self.heaps.guid)),
            (b"#Blob", bytes(self.heaps.blob)),
        ]
        version = b"v4.0.30319\x00\x00"
        root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
        root += struct.pack("<HH", 0, len(streams))

        header_size = len(root) + sum(8 + align(len(n) + 1, 4) for n, _ in streams)
        headers = bytearray()
        data = bytearray()
        for name, blob in streams:
            headers += struct.pack("<II", header_size + len(data), len(blob))
            headers += name + b"\x00" * (align(len(name) + 1, 4) - len(name))
            data += blob
            data += b"\x00" * (align(len(data), 4) - len(data))
        return root + bytes(headers) + bytes(data)

    def _set_method_rvas(self, base_rva: int) -> list[int]:
        offsets = []
        cursor = 0
        for index, body in enumerate(self._bodies):
            self.methods[index]["Rva"] = base_rva + cursor
            offsets.append(cursor)
            cursor = align(cursor + len(body), 4)
        return offsets

    def build(self) -> bytes:
        # Pass 1: size the metadata with placeholder RVAs.  The Rva column is
        # always 4 bytes, so the size does not change once RVAs are known.
        for method in self.methods:
            method["Rva"] = 0
        metadata = self._metadata()
        clr_header_size = 72
        metadata_rva_offset = clr_header_size
        bodies_offset = align(metadata_rva_offset + len(metadata), 4)
        section_rva = 0x2000

        # Pass 2: lay out bodies, then re-serialise the metadata.
        offsets = self._set_method_rvas(section_rva + bodies_offset)
        metadata = self._metadata()
        assert len(metadata) <= bodies_offset - metadata_rva_offset

        body_blob = bytearray()
        for body, offset in zip(self._bodies, offsets):
            if len(body_blob) < offset:
                body_blob += b"\x00" * (offset - len(body_blob))
            body_blob += body
            while len(body_blob) % 4:
                body_blob += b"\x00"

        entry_rva = self.methods[0]["Rva"] if self.methods else 0
        clr = struct.pack(
            "<IHH" + "I" * 16,
            72,
            2,
            5,
            section_rva + metadata_rva_offset,
            len(metadata),
            0x00000001,  # COMIMAGE_FLAGS_ILONLY
            0x06000001 if self.kind == "exe" else 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        )
        assert len(clr) == 72, len(clr)

        section = bytearray(b"\x00" * bodies_offset)
        section[: len(clr)] = clr
        section[metadata_rva_offset : metadata_rva_offset + len(metadata)] = metadata
        section[bodies_offset:] = bytes(body_blob)

        return _wrap_pe(
            section_rva, bytes(section), is_dll=self.kind == "dll", entry_rva=entry_rva
        )


def _wrap_pe(section_rva: int, section: bytes, is_dll: bool, entry_rva: int) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x2000
    size_of_headers = 0x200
    raw_size = align(len(section), file_alignment)
    characteristics = 0x0102 | (0x2000 if is_dll else 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = (
        b"\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!"
        b"This program cannot be run in DOS mode.\r\r\n$"
    )
    assert len(stub) <= 0x40, len(stub)
    dos[0x40 : 0x40 + len(stub)] = stub

    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, characteristics)

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)          # Magic
    struct.pack_into("<B", optional, 2, 8)              # MajorLinkerVersion
    struct.pack_into("<I", optional, 16, entry_rva)     # AddressOfEntryPoint
    struct.pack_into("<I", optional, 20, section_rva)   # BaseOfCode
    struct.pack_into("<I", optional, 28, 0x400000)      # ImageBase
    struct.pack_into("<I", optional, 32, section_alignment)
    struct.pack_into("<I", optional, 36, file_alignment)
    struct.pack_into("<H", optional, 40, 4)             # MajorOSVersion
    struct.pack_into("<H", optional, 48, 4)             # MajorSubsystemVersion
    struct.pack_into("<I", optional, 56, align(section_rva + len(section), section_alignment))
    struct.pack_into("<I", optional, 60, size_of_headers)
    struct.pack_into("<H", optional, 68, 3)             # Subsystem: console
    struct.pack_into("<I", optional, 92, 16)            # NumberOfRvaAndSizes
    struct.pack_into("<II", optional, 96 + 14 * 8, section_rva, len(section))

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(section),
        section_rva,
        raw_size,
        size_of_headers,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section_header
    headers += b"\x00" * (size_of_headers - len(headers))
    return headers + section + b"\x00" * (raw_size - len(section))
