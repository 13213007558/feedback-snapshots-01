"""Small synthetic hive builder used by tests that need several controlled hives."""

from __future__ import annotations

import struct
from typing import Any

HEADER_SIZE = 4096
HBIN_HEADER_SIZE = 32
KEY_NODE_SIZE = 76
KEY_VALUE_SIZE = 20


class HiveNode:
    def __init__(self, name: str, root: bool = False):
        self.name = name
        self.root = root
        self.parent: HiveNode | None = None
        self.children: list[HiveNode] = []
        self.values: list[tuple[str, int, bytes]] = []
        self.node_offset = 0
        self.index_offset: int | None = None
        self.value_list_offset: int | None = None
        self.value_entries: list[tuple[int, int, str, int, bytes]] = []

    def add(self, name: str) -> HiveNode:
        child = HiveNode(name)
        child.parent = self
        self.children.append(child)
        return child

    def value(self, name: str, value_type: int, data: Any) -> HiveNode:
        if isinstance(data, str):
            data = data.encode("utf-16-le") + b"\x00\x00"
        elif isinstance(data, int):
            data = struct.pack("<I", data)
        self.values.append((name, value_type, data))
        return self


def _align8(value: int) -> int:
    return (value + 7) & ~7


def build_hive(root: HiveNode, filename: str = "TESTHIVE") -> bytes:
    cursor = [HBIN_HEADER_SIZE]

    def allocate(payload_size: int) -> int:
        offset = cursor[0]
        cursor[0] += _align8(payload_size + 4)
        return offset

    def layout(node: HiveNode) -> None:
        name = node.name.encode("ascii")
        node.node_offset = allocate(KEY_NODE_SIZE + len(name))
        if node.children:
            node.index_offset = allocate(4 + 8 * len(node.children))
        if node.values:
            node.value_list_offset = allocate(4 + 4 * len(node.values))
        for name, value_type, data in node.values:
            entry_offset = allocate(KEY_VALUE_SIZE + len(name.encode("ascii")))
            data_offset = allocate(len(data))
            node.value_entries.append((entry_offset, data_offset, name, value_type, data))
        for child in node.children:
            layout(child)

    layout(root)
    hbin_size = _align8(cursor[0] + 4095)
    buffer = bytearray(HEADER_SIZE + hbin_size)

    def put(offset: int, data: bytes) -> None:
        base = HEADER_SIZE + offset
        buffer[base : base + len(data)] = data

    def put_cell(offset: int, data: bytes) -> None:
        size = _align8(len(data) + 4)
        put(offset, struct.pack("<i", -size) + data)

    def emit(node: HiveNode) -> None:
        name = node.name.encode("ascii")
        flags = 0x20 | (0x04 if node.root else 0)
        put_cell(
            node.node_offset,
            struct.pack(
                "<2sH8sIIIIIIIIIIIIIIIHH",
                b"nk",
                flags,
                b"\x00" * 8,
                0,
                0xFFFFFFFF if node.root else node.parent.node_offset,
                len(node.children),
                0,
                node.index_offset if node.index_offset is not None else 0xFFFFFFFF,
                0xFFFFFFFF,
                len(node.values),
                node.value_list_offset if node.value_list_offset is not None else 0xFFFFFFFF,
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
                struct.pack(
                    "<I4s",
                    child.node_offset,
                    child.name.lower().encode("ascii")[:4].ljust(4, b"\x00"),
                )
                for child in node.children
            )
            put_cell(node.index_offset, struct.pack("<2sH", b"lf", len(node.children)) + entries)

        if node.values:
            put_cell(
                node.value_list_offset,
                b"".join(struct.pack("<I", entry[0]) for entry in node.value_entries),
            )

        for entry_offset, data_offset, value_name, value_type, data in node.value_entries:
            value_name_bytes = value_name.encode("ascii")
            put_cell(
                entry_offset,
                struct.pack(
                    "<2sHII IHH",
                    b"vk",
                    len(value_name_bytes),
                    len(data),
                    data_offset,
                    value_type,
                    0x1,
                    0,
                )
                + value_name_bytes,
            )
            put_cell(data_offset, data)

        for child in node.children:
            emit(child)

    emit(root)

    put(0, struct.pack("<IIIIIQI", 0x6E696268, 0, hbin_size, 0, 0, 0, 0))

    header = bytearray(HEADER_SIZE)
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
        root.node_offset,
        len(buffer),
        1,
    )
    encoded_name = filename.encode("utf-16-le")
    header[48 : 48 + len(encoded_name)] = encoded_name

    crc = 0
    for (word,) in struct.iter_unpack("<I", header[:508]):
        crc ^= word
    struct.pack_into("<I", header, 508, crc)
    buffer[:HEADER_SIZE] = header

    return bytes(buffer)
