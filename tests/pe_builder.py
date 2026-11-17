import struct


def build_clr_pe(metadata):
    """Wrap metadata bytes in the smallest PE image that dnfile can parse."""
    section_rva = 0x2000
    section_raw = 0x200
    section_size = 0x400
    clr_header = struct.pack("<IHH", 0x48, 2, 5) + struct.pack(
        "<16I", section_rva + 0x48, len(metadata), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    assert len(clr_header) == 0x48

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<BB", optional, 2, 8, 0)
    struct.pack_into("<I", optional, 20, section_rva)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, section_rva)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<HH", optional, 40, 4, 0)
    struct.pack_into("<HH", optional, 48, 4, 0)
    struct.pack_into("<I", optional, 56, section_rva + section_size)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 72, 0x100000)
    struct.pack_into("<I", optional, 76, 0x1000)
    struct.pack_into("<I", optional, 80, 0x100000)
    struct.pack_into("<I", optional, 84, 0x1000)
    struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 96 + 14 * 8, section_rva, 0x48)

    section = struct.pack(
        "<8sIIIIIIHHI", b".text", section_size, section_rva, section_size, section_raw,
        0, 0, 0, 0, 0x60000020,
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    headers += b"\x00" * (section_raw - len(headers))
    payload = clr_header + metadata
    assert len(payload) <= section_size
    return headers + payload + b"\x00" * (section_size - len(payload))
