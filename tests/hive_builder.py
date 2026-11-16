"""Build small, structurally valid regf hives for view-resolution tests.

The test hive contains two deliberately different keys at the same logical
location::

    Software\\Classes\\CLSID\\{...}                  -> "native-64"
    Software\\Wow6432Node\\Classes\\CLSID\\{...}     -> "wow-32"

Both exist on disk.  Neither is the "real" one for any particular process; the
view decides which physical path a caller reaches.
"""

from __future__ import annotations

import struct

HDR = 4096
HBIN_HDR = 32
NK = 76
VK = 20
GUID = "{11111111-2222-3333-4444-555555555555}"


class Node:
    def __init__(self, name: str, root: bool = False):
        self.name = name
        self.root = root
        self.parent: Node | None = None
        self.children: list[Node] = []
        self.values: list[tuple[str, int, bytes]] = []
        self.nk = 0
        self.lf: int | None = None
        self.vl: int | None = None
        self.vk: list[tuple[int, int, str, int, bytes]] = []

    def add(self, name: str) -> Node:
        child = Node(name)
        child.parent = self
        self.children.append(child)
        return child

    def val(self, name: str, value_type: int, data: str | bytes) -> Node:
        if isinstance(data, str):
            data = data.encode("utf-16-le") + b"\x00\x00"
        self.values.append((name, value_type, data))
        return self


def build(root: Node) -> bytes:
    cursor = [HBIN_HDR]

    def alloc(size: int) -> int:
        offset = cursor[0]
        cursor[0] += (size + 7) & ~7
        return offset

    def layout(node: Node) -> None:
        node.nk = alloc(4 + NK + len(node.name.encode("ascii")))
        node.lf = alloc(4 + 4 + 8 * len(node.children)) if node.children else None
        node.vl = alloc(4 + 4 * len(node.values)) if node.values else None
        for name, value_type, data in node.values:
            node.vk.append((alloc(4 + VK + len(name)), alloc(4 + len(data)), name, value_type, data))
        for child in node.children:
            layout(child)

    layout(root)
    hbin_size = (cursor[0] + 4095) & ~4095
    buf = bytearray(HDR + hbin_size)

    def put(offset: int, data: bytes) -> None:
        buf[HDR + offset : HDR + offset + len(data)] = data

    def cell(offset: int, data: bytes) -> None:
        put(offset, struct.pack("<i", -((len(data) + 4 + 7) & ~7)))
        put(offset + 4, data)

    def emit(node: Node) -> None:
        name = node.name.encode("ascii")
        cell(
            node.nk,
            struct.pack(
                "<2sH8sIIIIIIIIIIIIIIIHH",
                b"nk",
                0x20 | (0x04 if node.root else 0),
                b"\x00" * 8,
                0,
                0xFFFFFFFF if node.root else node.parent.nk,
                len(node.children),
                0,
                node.lf if node.lf is not None else 0xFFFFFFFF,
                0xFFFFFFFF,
                len(node.values),
                node.vl if node.vl is not None else 0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0,
                0,
                0,
                0,
                0,
                len(name),
                0,
            )
            + name,
        )
        if node.children:
            entries = b"".join(
                struct.pack("<I4s", child.nk, child.name.lower().encode("ascii")[:4].ljust(4, b"\x00"))
                for child in node.children
            )
            cell(node.lf, struct.pack("<2sH", b"lf", len(node.children)) + entries)
        if node.values:
            cell(node.vl, b"".join(struct.pack("<I", vk) for vk, *_ in node.vk))
        for vk, raw, value_name, value_type, data in node.vk:
            encoded = value_name.encode("ascii")
            cell(vk, struct.pack("<2sHIIIHH", b"vk", len(encoded), len(data), raw, value_type, 0x1, 0) + encoded)
            cell(raw, data)
        for child in node.children:
            emit(child)

    emit(root)
    put(0, struct.pack("<IIIIIQI", 0x6E696268, 0, hbin_size, 0, 0, 0, 0))

    header = bytearray(HDR)
    struct.pack_into(
        "<IIIQIIIIIII",
        header,
        0,
        0x66676572,
        1,
        1,
        0,
        1,
        5,
        0,
        1,
        root.nk,
        len(buf),
        1,
    )
    filename = b"TESTHIVE"
    header[48 : 48 + len(filename) * 2] = filename.decode().encode("utf-16-le")
    checksum = 0
    for (word,) in struct.iter_unpack("<I", header[:508]):
        checksum ^= word
    struct.pack_into("<I", header, 508, checksum)
    buf[:HDR] = header
    return bytes(buf)


def make_hive() -> bytes:
    root = Node("ROOT", root=True)

    software = root.add("Software")
    native = software.add("Classes").add("CLSID").add(GUID)
    native.val("", 1, "native-64")
    software.add("NativeOnly").val("Owner", 1, "native-64")

    wow = software.add("Wow6432Node")
    wow.add("Classes").add("CLSID").add(GUID).val("", 1, "wow-32")
    wow.add("WowOnly").val("Owner", 1, "wow-32")

    root.add("ControlSet001").add("Services").add("Foo").val("Start", 4, struct.pack("<I", 3))
    root.add("Select").val("Current", 4, struct.pack("<I", 1))
    return build(root)


def make_hive_without_select() -> bytes:
    root = Node("ROOT", root=True)
    root.add("Software").add("Classes").add("CLSID").add(GUID).val("", 1, "native-64")
    return build(root)
