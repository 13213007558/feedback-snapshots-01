from __future__ import annotations

import struct
from io import BytesIO

CLSID = bytes.fromhex("0114020000000000c000000000000046")

# LINK_INFO fixed header is 12 bytes (size, header size, flags); the fixed body
# adds four 32-bit offsets (16 bytes). An extended 0x24 header appends two more
# 32-bit Unicode offsets (8 bytes) before the VolumeID structure.
LINK_INFO_FIXED_HEADER = 0x0C
LINK_INFO_FIXED_BODY = 0x10

# LinkFlags
HAS_LINK_TARGET_IDLIST = 0x1
HAS_LINK_INFO = 0x2
HAS_NAME = 0x4
HAS_RELATIVE_PATH = 0x8
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80


def _pad4(data: bytes) -> bytes:
    remainder = len(data) % 4
    return data + (b"\x00" * ((4 - remainder) % 4))


def shell_header(flags: int) -> bytes:
    out = BytesIO()
    out.write(struct.pack("<I", 0x4C))  # header size
    out.write(CLSID)
    out.write(struct.pack("<II", flags, 0x20))  # link flags, file attributes (ARCHIVE)
    out.write(struct.pack("<QQQ", 0, 0, 0))  # creation/access/write FILETIME
    out.write(struct.pack("<III", 0, 0, 1))  # file size, icon index, show command
    out.write(struct.pack("<BB", 0, 0))  # hotkey (keycode + modifier)
    out.write(struct.pack("<H", 0))  # reserved1
    out.write(struct.pack("<II", 0, 0))  # reserved2/3
    return out.getvalue()


def string_data_field(raw: bytes, character_count: int) -> bytes:
    return struct.pack("<H", character_count) + raw


def console_fe_block(code_page: int) -> bytes:
    return struct.pack("<II", 12, 0xA0000004) + struct.pack("<I", code_page)


def environment_block(target_ansi: bytes, target_unicode: bytes) -> bytes:
    ansi = target_ansi[:259].ljust(260, b"\x00")
    uni = target_unicode[:519].ljust(520, b"\x00")
    body = ansi + uni
    return struct.pack("<II", len(body) + 8, 0xA0000001) + body


def tracker_block(machine_id: bytes) -> bytes:
    # TRACKER_PROPS cstruct body: length(0x58), version, machine_id(16), four droids(64).
    body = struct.pack("<II", 0x58, 0)  # spec length field, version
    body += machine_id[:15].ljust(16, b"\x00")
    body += b"\x11" * 64  # volume/file droid and their birth variants (4x16)
    assert len(body) == 88
    # Outer block size includes the 8-byte block header (size + signature).
    return struct.pack("<II", len(body) + 8, 0xA0000003) + body


def unicode_link_info(local_ansi: bytes, local_unicode: bytes, suffix_ansi: bytes, suffix_unicode: bytes) -> bytes:
    """Build a LinkInfo (header size 0x24) carrying ANSI and UTF-16LE paths."""
    header_size = 0x24
    # A Unicode VolumeID has a 20-byte fixed header; its data holds a single
    # NUL. The ANSI label offset 0x14 plus a zero Unicode label offset means no
    # volume label is present, but the extended header is still used.
    volume_size = 0x15
    # Absolute offset of VolumeID: fixed header(12) + fixed body(16) + the two
    # 32-bit Unicode extension offsets(8) that make the header 0x24 bytes long.
    volume_offset = LINK_INFO_FIXED_HEADER + LINK_INFO_FIXED_BODY + 8

    local_ansi_field = local_ansi + b"\x00"
    suffix_ansi_field = suffix_ansi + b"\x00"
    local_uni_field = local_unicode + b"\x00\x00"
    suffix_uni_field = suffix_unicode + b"\x00\x00"

    # Lay every variable field out sequentially and derive absolute offsets from
    # the running position, so declared offsets always match the bytes on disk.
    cursor = volume_offset + volume_size
    local_ansi_offset = cursor
    cursor += len(local_ansi_field)
    suffix_ansi_offset = cursor
    cursor += len(suffix_ansi_field)
    local_uni_offset = cursor
    cursor += len(local_uni_field)
    suffix_uni_offset = cursor
    cursor += len(suffix_uni_field)
    total_size = cursor

    out = BytesIO()
    out.write(struct.pack("<II", total_size, header_size))
    out.write(struct.pack("<I", 0x1))  # LinkInfoFlags: VolumeIDAndLocalBasePath
    out.write(struct.pack("<IIII", volume_offset, local_ansi_offset, 0, suffix_ansi_offset))
    out.write(struct.pack("<II", local_uni_offset, suffix_uni_offset))
    assert out.tell() == volume_offset
    # VolumeID: size, drive type, serial, ANSI label offset 0x14, Unicode label
    # offset 0 (no label), then a single NUL data byte.
    out.write(struct.pack("<IIIII", volume_size, 3, 0x12345678, 0x14, 0))
    out.write(b"\x00")
    out.write(local_ansi_field)
    out.write(suffix_ansi_field)
    out.write(local_uni_field)
    out.write(suffix_uni_field)
    payload = out.getvalue()
    assert len(payload) == total_size
    return payload


def unicode_volume_label_link_info(label_unicode: bytes) -> bytes:
    """Build a LinkInfo whose VolumeID carries a UTF-16LE label.

    The ANSI label offset is set to 0x14 and a Unicode label offset points at a
    NUL-terminated UTF-16LE label inside the VolumeID data area.
    """
    header_size = 0x24
    volume_offset = LINK_INFO_FIXED_HEADER + LINK_INFO_FIXED_BODY + 8
    label_field = label_unicode + b"\x00\x00"
    # A Unicode VolumeID has a 20-byte fixed header (the extra
    # volume_label_offset_unicode field) followed by the label in data.
    volume_header = 20
    volume_size = volume_header + len(label_field)
    unicode_label_offset = 0x14  # structure-relative offset of the label in data
    total_size = volume_offset + volume_size

    out = BytesIO()
    out.write(struct.pack("<II", total_size, header_size))
    out.write(struct.pack("<I", 0x1))  # VolumeIDAndLocalBasePath
    out.write(struct.pack("<IIII", volume_offset, 0, 0, 0))
    out.write(struct.pack("<II", 0, 0))  # unused Unicode path offsets
    assert out.tell() == volume_offset
    # ANSI offset 0x14 signals "use the Unicode label offset instead".
    out.write(struct.pack("<IIIII", volume_size, 3, 0x12345678, 0x14, unicode_label_offset))
    out.write(label_field)
    payload = out.getvalue()
    assert len(payload) == total_size
    return payload


def ansi_link_info(net_name_ansi: bytes) -> bytes:
    """Build a network LinkInfo with an ANSI NetName and an empty path suffix."""
    header_size = 0x1C
    # header_size already covers the fixed 12-byte header plus the 16-byte body.
    cnrl_offset = header_size
    cnrl_header = 20
    net_name_relative_offset = cnrl_header  # relative to the CNRL start
    net_name_field = net_name_ansi + b"\x00"
    cnrl_size = cnrl_header + len(net_name_field)
    suffix_offset = cnrl_offset + cnrl_size
    total_size = suffix_offset + 1  # single NUL common path suffix

    out = BytesIO()
    out.write(struct.pack("<II", total_size, header_size))
    out.write(struct.pack("<I", 0x2))  # CommonNetworkRelativeLinkAndPathSuffix
    out.write(struct.pack("<IIII", 0, 0, cnrl_offset, suffix_offset))
    assert out.tell() == cnrl_offset
    # CNRL header: size, flags(valid_net_type=2), net/device offsets, provider type.
    out.write(struct.pack("<IIIII", cnrl_size, 0x2, net_name_relative_offset, 0, 0x20000))
    out.write(net_name_field)
    out.write(b"\x00")  # empty common path suffix
    payload = out.getvalue()
    assert len(payload) == total_size
    return payload


def build_lnk(
    *,
    is_unicode: bool,
    name_bytes: bytes,
    name_char_count: int,
    link_info: bytes | None = None,
    extra_blocks: list[bytes] | None = None,
) -> bytes:
    flags = HAS_NAME | (HAS_LINK_INFO if link_info is not None else 0)
    if is_unicode:
        flags |= IS_UNICODE
    out = BytesIO()
    out.write(shell_header(flags))
    if link_info is not None:
        out.write(link_info)
    out.write(string_data_field(name_bytes, name_char_count))
    for block in extra_blocks or []:
        out.write(block)
    out.write(struct.pack("<I", 0))  # terminal block
    return out.getvalue()
