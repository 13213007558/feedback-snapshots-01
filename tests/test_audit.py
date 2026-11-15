"""Tests for the read-only SquashFS permission evidence inventory."""

from __future__ import annotations

import json
import struct
from io import BytesIO

import pytest

from dissect.squashfs.audit import (
    OUT_OF_RANGE,
    RESOLVED,
    TABLE_TRUNCATED,
    UNKNOWN,
    PermissionEvidence,
    permission_inventory,
    render_json,
    render_text,
    resolve_identity,
)
from dissect.squashfs.squashfs import SquashFS
from tests._imagegen import (
    SQUASHFS_DIR_TYPE,
    SQUASHFS_FIFO_TYPE,
    SQUASHFS_FILE_TYPE,
    SQUASHFS_LDIR_TYPE,
    SQUASHFS_LREG_TYPE,
    SQUASHFS_SYMLINK_TYPE,
    Node,
    build_squashfs,
)


def _id_table() -> list[int]:
    # Index is deliberately not equal to the stored numeric ID. A second
    # metadata page is forced by exceeding 8192 bytes / 4 bytes per entry.
    ids = [0] * 2052
    ids[0] = 0
    ids[1] = 1000
    ids[2] = 2000
    ids[5] = 4321
    ids[2048] = 7000
    ids[2049] = 7070
    return ids


def _build_tree() -> Node:
    hard_target = Node("hardtarget", 0o4755, 1, 2049, SQUASHFS_FILE_TYPE, b"hard\n")
    shared = Node("shared", 0o755, 1, 1, SQUASHFS_DIR_TYPE, children=[hard_target])
    # Hard link: a second directory entry (different name) for the same inode.
    shared.children.append(
        Node("hardlink-a", 0o4755, 1, 2049, SQUASHFS_FILE_TYPE, b"hard\n", alias_of=hard_target)
    )

    return Node(
        "",
        0o755,
        0,
        0,
        SQUASHFS_LDIR_TYPE,
        children=[
            Node(
                "bin",
                0o755,
                0,
                0,
                SQUASHFS_DIR_TYPE,
                children=[
                    # Index 0 stores numeric uid 0: a definite root setuid file.
                    Node("su-root", 0o4755, 0, 0, SQUASHFS_FILE_TYPE, b"a\n"),
                    # Basic index 1 resolves to uid 1000 (index != id); extended inode.
                    Node("su-user", 0o4755, 1, 2, SQUASHFS_LREG_TYPE, b"b\n"),
                    Node("sg-tool", 0o2755, 1, 2, SQUASHFS_FILE_TYPE, b"c\n"),
                    Node("ww.sh", 0o666, 2, 1, SQUASHFS_FILE_TYPE, b"d\n"),
                ],
            ),
            shared,
            Node(
                "var",
                0o755,
                0,
                0,
                SQUASHFS_DIR_TYPE,
                children=[
                    Node(
                        "run",
                        0o1777,
                        0,
                        0,
                        SQUASHFS_LDIR_TYPE,
                        children=[
                            # GID index 2048 lives in the second ID metadata page.
                            Node("fifo", 0o2777, 5, 2048, SQUASHFS_FIFO_TYPE),
                        ],
                    ),
                ],
            ),
            Node("link", 0o777, 0, 0, SQUASHFS_SYMLINK_TYPE, "bin/su-root"),
        ],
    )


@pytest.fixture
def audit_fs() -> SquashFS:
    return SquashFS(BytesIO(build_squashfs(_build_tree(), _id_table())))


@pytest.fixture
def inventory(audit_fs: SquashFS) -> dict[str, PermissionEvidence]:
    return {path: item for item in permission_inventory(audit_fs) for path in item.paths}


def test_index_value_differs_from_resolved_id(inventory: dict[str, PermissionEvidence]) -> None:
    """Sample 1: header index and the numeric ID it resolves to are distinct."""
    item = inventory["/bin/su-user"]

    assert item.uid.index == 1
    assert item.uid.id == 1000
    assert item.uid.status == RESOLVED
    assert item.gid.index == 2
    assert item.gid.id == 2000
    # The raw index is retained, so the distinction is auditable.
    assert item.to_dict()["uid"]["raw_index"] == 1
    # This is an extended (LREG) inode resolved through the same identity path.
    assert item.extended_inode is True


def test_cross_page_gid(inventory: dict[str, PermissionEvidence]) -> None:
    """Sample 2: a GID index stored on the second ID metadata page."""
    fifo = inventory["/var/run/fifo"]
    hard = inventory["/shared/hardtarget"]

    assert fifo.gid.index == 2048
    assert fifo.gid.id == 7000
    assert fifo.gid.status == RESOLVED

    assert hard.gid.index == 2049
    assert hard.gid.id == 7070
    # A shared index resolves identically regardless of which inode references it.
    assert inventory["/shared/hardlink-a"].gid == hard.gid


def test_bad_index_is_unknown_not_zero() -> None:
    """Sample 3: an out-of-range index is unknown, never silently coerced to 0."""
    root = Node(
        "",
        0o755,
        0,
        0,
        SQUASHFS_LDIR_TYPE,
        children=[
            Node("bad-uid", 0o4755, 3000, 0, SQUASHFS_FILE_TYPE, b"x\n"),
            Node("bad-gid", 0o2755, 0, 9999, SQUASHFS_FILE_TYPE, b"y\n"),
        ],
    )
    fs = SquashFS(BytesIO(build_squashfs(root, [0, 1000, 2000])))

    bad_uid = next(item for item in permission_inventory(fs) if "/bad-uid" in item.paths)
    assert bad_uid.uid.status == UNKNOWN
    assert bad_uid.uid.id is None
    assert bad_uid.uid.index == 3000
    assert OUT_OF_RANGE in bad_uid.uid.reason
    # Unknown owner must not be reported as root.
    assert bad_uid.root_owned is None
    assert bad_uid.classification == "unknown-owner-setuid"

    bad_gid = next(item for item in permission_inventory(fs) if "/bad-gid" in item.paths)
    assert bad_gid.gid.status == UNKNOWN
    assert bad_gid.gid.id is None
    assert OUT_OF_RANGE in bad_gid.gid.reason


def test_truncated_id_entry_is_unknown() -> None:
    """A corrupt/truncated table entry is unknown while valid entries still resolve."""
    blob = bytearray(build_squashfs(_build_tree(), _id_table()))
    fs = SquashFS(BytesIO(blob))
    pointer_table = fs.sb.id_table_start
    # Repoint the second ID metadata block past EOF so cross-page reads fail.
    struct.pack_into("<Q", blob, pointer_table + 8, len(blob) - 1)

    damaged = SquashFS(BytesIO(bytes(blob)))
    cross = resolve_identity(damaged, 2048, "gid")
    assert cross.status == UNKNOWN
    assert cross.id is None
    assert TABLE_TRUNCATED in cross.reason

    first_page = resolve_identity(damaged, 1, "uid")
    assert first_page.status == RESOLVED
    assert first_page.id == 1000


def test_definite_root_setuid_vs_unknown_owner(audit_fs: SquashFS) -> None:
    root_item = next(
        item for item in permission_inventory(audit_fs) if "/bin/su-root" in item.paths
    )
    assert root_item.classification == "definitely-root-setuid"
    assert root_item.root_owned is True
    assert root_item.uid.id == 0
    assert root_item.uid.index == 0
    assert "setuid" in root_item.special_bits

    # Every judgement cites the raw on-disk fields it was derived from.
    payload = root_item.to_dict()
    assert payload["mode_raw"] == 0o4755
    assert payload["field_basis"]["uid_index"].startswith("inode header field 'uid'")


def test_hardlinks_counted_once_with_all_paths(
    audit_fs: SquashFS, inventory: dict[str, PermissionEvidence]
) -> None:
    target = inventory["/shared/hardtarget"]
    alias = inventory["/shared/hardlink-a"]

    # Both directory entries resolve to the same single evidence record/inode.
    assert target is alias
    assert set(target.paths) == {"/shared/hardtarget", "/shared/hardlink-a"}

    inode_numbers = [item.inode_number for item in permission_inventory(audit_fs)]
    assert len(inode_numbers) == len(set(inode_numbers))
    # Eight distinct underlying inodes carry special bits in the fixture.
    assert len(inode_numbers) == 8


def test_special_bits_and_type_coverage(inventory: dict[str, PermissionEvidence]) -> None:
    assert inventory["/bin/sg-tool"].special_bits == ("setgid",)
    assert inventory["/bin/ww.sh"].special_bits == ("world-writable",)
    assert inventory["/var/run"].special_bits == ("sticky", "world-writable")
    assert inventory["/var/run/fifo"].type_name == "fifo"
    assert inventory["/var/run"].type_name == "directory"


def test_renderers_include_raw_fields(audit_fs: SquashFS) -> None:
    items = permission_inventory(audit_fs)
    text = render_text(items)
    assert "definitely-root-setuid" in text
    assert "raw header.mode=" in text

    json_text = render_json(items)
    assert '"raw_index"' in json_text
    assert '"resolved_id"' in json_text
    # Resolved identities are always numeric; no local account names appear.
    payload = json.loads(json_text)
    for entry in payload:
        for identity in (entry["uid"], entry["gid"]):
            if identity["status"] == RESOLVED:
                assert isinstance(identity["resolved_id"], int)
        assert set(entry).isdisjoint({"user_name", "group_name", "owner_name"})
