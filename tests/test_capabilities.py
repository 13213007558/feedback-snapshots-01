from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.capability import (
    CAP_LAST_CAP,
    VFS_CAP_REVISION_1,
    VFS_CAP_REVISION_2,
    VFS_CAP_REVISION_3,
    CapabilityApplicability,
    CapabilityRevision,
    CapabilitySetKind,
    CapabilityStatus,
    analyze_file_capabilities,
    assess_capability,
    capability_name,
    parse_security_capability,
)
from dissect.squashfs.squashfs import SquashFS
from dissect.squashfs.xattr import Xattr, XattrSource

METADATA_SIZE = 8192
SQUASHFS_MAGIC = 0x73717368
SQUASHFS_INVALID_BLK = 0xFFFFFFFFFFFFFFFF
SQUASHFS_INVALID_FRAG = 0xFFFFFFFF
SQUASHFS_INVALID_XATTR = 0xFFFFFFFF


def capability_v1(permitted: int, inheritable: int = 0) -> bytes:
    return struct.pack("<III", VFS_CAP_REVISION_1, permitted, inheritable)


def capability_v2(permitted: int, inheritable: int = 0, *, effective: bool = True) -> bytes:
    magic = VFS_CAP_REVISION_2 | (0x1 if effective else 0)
    return struct.pack(
        "<IIIII",
        magic,
        permitted & 0xFFFFFFFF,
        inheritable & 0xFFFFFFFF,
        (permitted >> 32) & 0xFFFFFFFF,
        (inheritable >> 32) & 0xFFFFFFFF,
    )


def capability_v3(permitted: int, rootid: int, inheritable: int = 0, *, effective: bool = True) -> bytes:
    magic = VFS_CAP_REVISION_3 | (0x1 if effective else 0)
    return struct.pack(
        "<IIIIII",
        magic,
        permitted & 0xFFFFFFFF,
        inheritable & 0xFFFFFFFF,
        (permitted >> 32) & 0xFFFFFFFF,
        (inheritable >> 32) & 0xFFFFFFFF,
        rootid,
    )


def _metadata_block(data: bytes) -> bytes:
    assert len(data) <= METADATA_SIZE
    return struct.pack("<H", len(data) | 0x8000) + data


def _metadata_blocks(data: bytes) -> bytes:
    return b"".join(
        _metadata_block(data[offset : offset + METADATA_SIZE]) for offset in range(0, len(data), METADATA_SIZE)
    )


def _build_xattr_stream(
    xattr_sets: dict[int, list[tuple[str, bytes]]],
    out_of_line: set[str],
) -> tuple[bytes, dict[int, int], dict[tuple[int, str], int]]:
    stream = bytearray()
    entry_offsets: dict[int, int] = {}
    ool_offsets: dict[tuple[int, str], int] = {}
    shared_values: dict[tuple[str, bytes], int] = {}

    for xattr_id, entries in xattr_sets.items():
        entry_offsets[xattr_id] = len(stream)
        for name, value in entries:
            entry_type = c_squashfs.SQUASHFS_XATTR_SECURITY
            if name in out_of_line:
                entry_type |= c_squashfs.SQUASHFS_XATTR_VALUE_OOL
            stream += struct.pack("<HH", entry_type, len(name))
            stream += name.encode()
            if name in out_of_line:
                stream += struct.pack("<I", 8) + b"\x00" * 8
            else:
                stream += struct.pack("<I", len(value)) + value

    # Identical out-of-line values are stored once and shared between xattr IDs.
    for xattr_id, entries in xattr_sets.items():
        for name, value in entries:
            if name in out_of_line:
                key = (name, value)
                if key not in shared_values:
                    shared_values[key] = len(stream)
                    stream += struct.pack("<I", len(value)) + value
                ool_offsets[(xattr_id, name)] = shared_values[key]

    # Patch the out-of-line references now that the shared values have a final offset.
    position = 0
    for xattr_id, entries in xattr_sets.items():
        for name, _ in entries:
            _, name_size = struct.unpack_from("<HH", stream, position)
            position += 4 + name_size
            value_size = struct.unpack_from("<I", stream, position)[0]
            if name in out_of_line:
                struct.pack_into("<Q", stream, position + 4, ool_offsets[(xattr_id, name)])
                position += 4 + 8
            else:
                position += 4 + value_size

    return bytes(stream), entry_offsets, ool_offsets


def build_squashfs(
    files: list[tuple[str, int]],
    xattr_sets: dict[int, list[tuple[str, bytes]]],
    *,
    out_of_line: set[str] | None = None,
) -> bytes:
    """Build a small SquashFS 4.0 image containing regular files with xattrs."""
    out_of_line = out_of_line or set()
    xattr_stream, entry_offsets, _ = _build_xattr_stream(xattr_sets, out_of_line)

    out = bytearray(96)
    inode_start = len(out)

    inodes = bytearray(40)
    file_offsets: dict[str, int] = {}
    for inode_number, (name, xattr_id) in enumerate(files, start=2):
        file_offsets[name] = len(inodes)
        inodes += struct.pack(
            "<HHHHIIqqqIIII",
            c_squashfs.SQUASHFS_LREG_TYPE,
            0o644,
            0,
            0,
            0,
            inode_number,
            0,
            0,
            0,
            1,
            SQUASHFS_INVALID_FRAG,
            0,
            xattr_id,
        )

    inode_block = len(out)
    out += _metadata_block(bytes(inodes))

    directory_data = bytearray(struct.pack("<III", len(files) - 1, 0, 2))
    for inode_number, (name, _) in enumerate(files, start=2):
        directory_data += struct.pack("<HhHH", file_offsets[name], inode_number - 2, 2, len(name) - 1)
        directory_data += name.encode()

    directory_start = len(out)
    out += _metadata_block(bytes(directory_data))

    root_inode = struct.pack(
        "<HHHHIIIIIIHHI",
        c_squashfs.SQUASHFS_LDIR_TYPE,
        0o755,
        0,
        0,
        0,
        1,
        2,
        3 + len(directory_data),
        0,
        1,
        0,
        0,
        SQUASHFS_INVALID_XATTR,
    )
    inodes[0:40] = root_inode
    out[inode_block : inode_block + len(_metadata_block(bytes(inodes)))] = _metadata_block(bytes(inodes))

    xattr_table_start = len(out)
    out += _metadata_blocks(xattr_stream)

    xattr_ids = bytearray()
    ordered_ids = sorted(xattr_sets)
    for xattr_id in ordered_ids:
        # Shared values may be interleaved between IDs; only the inline entry region
        # belongs to the ID's declared size.
        entries = xattr_sets[xattr_id]
        inline_size = 0
        for name, value in entries:
            inline_size += 4 + len(name) + 4
            inline_size += 8 if name in out_of_line else len(value)
        xattr_ids += struct.pack("<QII", entry_offsets[xattr_id], len(entries), inline_size)

    xattr_id_block = len(out)
    out += _metadata_blocks(bytes(xattr_ids))

    inode_lookup = bytearray(struct.pack("<Q", 0))
    for name, _ in files:
        inode_lookup += struct.pack("<Q", file_offsets[name])
    inode_lookup_block = len(out)
    out += _metadata_block(bytes(inode_lookup))

    inode_lookup_start = len(out)
    out += struct.pack("<Q", inode_lookup_block)

    uid_block = len(out)
    out += _metadata_block(struct.pack("<I", 0))
    uid_start = len(out)
    out += struct.pack("<Q", uid_block)

    xattr_id_table_start = len(out)
    out += struct.pack("<QII", xattr_table_start, len(xattr_sets), 0)
    out += struct.pack("<Q", xattr_id_block)

    superblock = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        SQUASHFS_MAGIC,
        1 + len(files),
        0,
        4096,
        0,
        c_squashfs.ZLIB_COMPRESSION,
        12,
        0,
        1,
        4,
        0,
        0,
        len(out),
        uid_start,
        xattr_id_table_start,
        inode_start,
        directory_start,
        SQUASHFS_INVALID_BLK,
        inode_lookup_start,
    )
    assert len(superblock) == 96
    out[0:96] = superblock

    return bytes(out)


@pytest.fixture
def capability_sqfs() -> SquashFS:
    image = build_squashfs(
        [
            ("v3-root-0", 0),
            ("v3-root-1000", 1),
            ("v2", 2),
            ("truncated", 3),
            ("unknown-bits", 4),
            ("out-of-line", 5),
            ("conflict", 6),
            ("unknown-revision", 7),
            ("no-capability", 8),
            ("large-out-of-line", 9),
        ],
        {
            0: [("capability", capability_v3(1 << 13, rootid=0))],
            1: [("capability", capability_v3(1 << 13, rootid=1000))],
            2: [("capability", capability_v2((1 << 10) | (1 << 13)))],
            3: [("capability", capability_v3(1 << 13, rootid=0)[:16])],
            4: [("capability", capability_v2((1 << 9) | (1 << 41)))],
            5: [("capability", capability_v3(1 << 13, rootid=0))],
            6: [
                ("capability", capability_v3(1 << 13, rootid=0)),
                ("capability", capability_v3(1 << 13, rootid=1000)),
            ],
            7: [("capability", struct.pack("<I", 0x09000001) + b"A" * 20)],
            8: [("selinux", b"unconfined")],
            9: [("capability", b"\x00" * METADATA_SIZE)],
        },
        out_of_line={"capability"},
    )
    return SquashFS(BytesIO(image))


def test_v3_same_bits_different_rootid(capability_sqfs: SquashFS) -> None:
    root0 = capability_sqfs.get("v3-root-0").file_capabilities(namespace_rootid=0)
    assert root0 is not None
    assert root0.declaration.revision is CapabilityRevision.V3
    assert root0.declaration.status is CapabilityStatus.VALID
    assert root0.rootid == 0
    assert root0.declaration.permitted.names == ("CAP_NET_RAW",)
    assert root0.namespace.effective is True
    assert root0.namespace.effective_capabilities == ("CAP_NET_RAW",)

    same_bits = capability_sqfs.get("v3-root-1000").file_capabilities(namespace_rootid=0)
    assert same_bits is not None
    assert same_bits.declaration.permitted.raw == root0.declaration.permitted.raw
    assert same_bits.rootid == 1000
    assert same_bits.namespace.applicability is CapabilityApplicability.NOT_APPLICABLE
    assert same_bits.namespace.effective is False
    assert same_bits.namespace.effective_capabilities == ()

    matched = capability_sqfs.get("v3-root-1000").file_capabilities(namespace_rootid=1000)
    assert matched is not None
    assert matched.namespace.effective is True
    assert matched.namespace.effective_capabilities == ("CAP_NET_RAW",)


def test_v2_is_initial_namespace_only(capability_sqfs: SquashFS) -> None:
    inode = capability_sqfs.get("v2")
    report = inode.file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.declaration.revision is CapabilityRevision.V2
    assert report.declaration.status is CapabilityStatus.VALID
    assert report.declaration.rootid is None
    assert report.declaration.permitted.names == ("CAP_NET_BIND_SERVICE", "CAP_NET_RAW")
    assert report.namespace.effective is True

    other_namespace = inode.file_capabilities(namespace_rootid=1000)
    assert other_namespace is not None
    assert other_namespace.namespace.applicability is CapabilityApplicability.NOT_APPLICABLE
    assert other_namespace.namespace.effective is False


def test_truncated_value_is_not_effective(capability_sqfs: SquashFS) -> None:
    report = capability_sqfs.get("truncated").file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.declaration.revision is CapabilityRevision.V3
    assert report.declaration.status is CapabilityStatus.TRUNCATED
    assert report.declaration.raw == capability_v3(1 << 13, rootid=0)[:16]
    assert report.namespace.applicability is CapabilityApplicability.UNKNOWN
    assert report.namespace.effective is None
    assert report.namespace.effective_capabilities == ()


def test_out_of_line_value_is_fully_resolved(capability_sqfs: SquashFS) -> None:
    inode = capability_sqfs.get("out-of-line")
    attribute = inode.getxattr("security.capability")
    assert attribute is not None
    assert attribute.source.out_of_line is True
    assert attribute.source.ool_ref is not None
    assert attribute.source.value_ref == attribute.source.ool_ref + len(c_squashfs.squashfs_xattr_val)
    assert attribute.value == capability_v3(1 << 13, rootid=0)

    report = inode.file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.raw == capability_v3(1 << 13, rootid=0)
    assert report.source is attribute.source
    assert report.namespace.effective is True

    # The same xattr ID is shared by another inode, so the cached lookup must not leak
    # or lose the resolved value.
    assert capability_sqfs.get("v3-root-0").getxattr("security.capability").value == attribute.value


def test_unknown_capability_bits_are_reported(capability_sqfs: SquashFS) -> None:
    report = capability_sqfs.get("unknown-bits").file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.declaration.permitted.names == ("CAP_LINUX_IMMUTABLE",)
    assert report.declaration.permitted.unknown_bits == (41,)
    assert report.unknown_capability_bits == (41,)


def test_conflicting_attributes_are_not_effective(capability_sqfs: SquashFS) -> None:
    report = capability_sqfs.get("conflict").file_capabilities(namespace_rootid=0)
    assert report is not None
    assert len(report.conflicts) == 2
    assert report.reason == "conflicting security.capability attributes"
    assert report.namespace.applicability is CapabilityApplicability.UNKNOWN
    assert report.namespace.effective is None


def test_unknown_revision_is_not_effective(capability_sqfs: SquashFS) -> None:
    report = capability_sqfs.get("unknown-revision").file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.declaration.revision is None
    assert report.declaration.status is CapabilityStatus.UNKNOWN_REVISION
    assert report.namespace.effective is None


def test_value_spanning_metadata_blocks(capability_sqfs: SquashFS) -> None:
    inode = capability_sqfs.get("large-out-of-line")
    attribute = inode.getxattr("security.capability")
    assert attribute is not None
    assert len(attribute.value) == METADATA_SIZE
    assert attribute.value == b"\x00" * METADATA_SIZE
    report = inode.file_capabilities(namespace_rootid=0)
    assert report is not None
    assert report.declaration.status is CapabilityStatus.UNKNOWN_REVISION
    assert report.namespace.effective is None


def test_no_capability_returns_none(capability_sqfs: SquashFS) -> None:
    inode = capability_sqfs.get("no-capability")
    assert inode.xattr_id == 8
    assert inode.getxattr("security.capability") is None
    assert inode.file_capabilities(namespace_rootid=0) is None


def test_requires_caller_namespace(capability_sqfs: SquashFS) -> None:
    report = capability_sqfs.get("v3-root-0").file_capabilities()
    assert report is not None
    assert report.namespace.namespace_rootid is None
    assert report.namespace.effective is None
    assert report.namespace.reason == "target user namespace root not provided"


def test_inheritable_set_is_decoded() -> None:
    declaration = parse_security_capability(capability_v3(1 << 13, rootid=0, inheritable=1 << 8))
    assert declaration.status is CapabilityStatus.VALID
    assert declaration.permitted.names == ("CAP_NET_RAW",)
    assert declaration.inheritable.names == ("CAP_SETPCAP",)
    assert declaration.inheritable.kind is CapabilitySetKind.INHERITABLE
    assert declaration.permitted.word_offsets == (4, 12)
    assert declaration.inheritable.word_offsets == (8, 16)

    conclusion = assess_capability(declaration, namespace_rootid=0)
    assert conclusion.effective is True
    assert conclusion.effective_capabilities == ("CAP_NET_RAW",)


def test_effective_flag_not_set() -> None:
    declaration = parse_security_capability(capability_v3(1 << 13, rootid=0, effective=False))
    assert declaration.status is CapabilityStatus.VALID
    assert declaration.effective is None
    conclusion = assess_capability(declaration, namespace_rootid=0)
    assert conclusion.applicability is CapabilityApplicability.APPLICABLE
    assert conclusion.effective is False
    assert conclusion.effective_capabilities == ()


def test_capability_names_cover_known_range() -> None:
    assert capability_name(0) == "CAP_CHOWN"
    assert capability_name(13) == "CAP_NET_RAW"
    assert capability_name(CAP_LAST_CAP) == "CAP_CHECKPOINT_RESTORE"
    assert capability_name(CAP_LAST_CAP + 1) is None


def test_v1_is_unsupported() -> None:
    declaration = parse_security_capability(capability_v1(1 << 13))
    assert declaration.revision is CapabilityRevision.V1
    assert declaration.status is CapabilityStatus.UNSUPPORTED_REVISION
    conclusion = assess_capability(declaration, namespace_rootid=0)
    assert conclusion.effective is None
    assert conclusion.applicability is CapabilityApplicability.UNKNOWN


def test_unknown_flags_are_malformed() -> None:
    raw = bytearray(capability_v3(1 << 13, rootid=0))
    raw[0] |= 0x02  # Unknown flag bit, not VFS_CAP_FLAGS_EFFECTIVE.
    declaration = parse_security_capability(bytes(raw))
    assert declaration.status is CapabilityStatus.MALFORMED
    assert declaration.unknown_flags == 0x2
    assert assess_capability(declaration, namespace_rootid=0).effective is None


def test_iter_file_capabilities(capability_sqfs: SquashFS) -> None:
    reports = {inode.name: report for inode, report in capability_sqfs.iter_file_capabilities(0)}
    assert set(reports) == {
        "v3-root-0",
        "v3-root-1000",
        "v2",
        "truncated",
        "unknown-bits",
        "out-of-line",
        "conflict",
        "unknown-revision",
        "large-out-of-line",
    }
    assert reports["v3-root-0"].namespace.effective is True
    assert reports["v3-root-1000"].namespace.effective is False


def test_report_distinguishes_declaration_and_namespace() -> None:
    attribute = Xattr(
        name="security.capability",
        value=capability_v3(1 << 13, rootid=0),
        type=c_squashfs.SQUASHFS_XATTR_SECURITY,
        prefix=c_squashfs.SQUASHFS_XATTR_SECURITY,
        suffix="capability",
        source=XattrSource(xattr_id=0, value_size=24),
    )
    report = analyze_file_capabilities([attribute], namespace_rootid=1000)
    assert report is not None
    assert report.declaration is not None
    assert report.declaration.permitted.names == ("CAP_NET_RAW",)
    assert report.namespace.effective is False
    assert report.namespace.reason.startswith("capability rootid 0 does not match")
    assert report.permitted.kind is CapabilitySetKind.PERMITTED

    alias = analyze_file_capabilities([attribute], rootid=1000)
    assert alias is not None
    assert alias.namespace.effective is False
    assert alias.namespace.namespace_rootid == 1000
