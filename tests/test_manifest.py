from __future__ import annotations

import json
import stat
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.squashfs.manifest import build_permission_manifest

from ._squashfs_builder import build_identity_image

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.squashfs.manifest import PermissionManifest


@pytest.fixture
def manifest() -> PermissionManifest:
    return build_permission_manifest(build_identity_image().open())


def test_manifest_lists_permission_sensitive_objects(manifest: PermissionManifest) -> None:
    paths = [entry.path for entry in manifest]

    assert paths == [
        "/bad-index-setuid",
        "/boundary-gid",
        "/cross-page-setgid",
        "/hard-a",
        "/index-vs-uid",
        "/nested",
        "/nested/nested-child",
        "/root-setuid",
        "/same-index-a",
        "/same-index-b",
        "/sticky-dir",
        "/world-write",
    ]
    assert manifest.object_count == 12
    assert manifest.path_count == 13
    assert manifest.objects_examined == 14
    assert manifest.paths_examined == 15


def test_index_value_differs_from_uid(manifest: PermissionManifest) -> None:
    entry = next(entry for entry in manifest if entry.path == "/index-vs-uid")

    assert entry.owner.index == 0
    assert entry.owner_id == 1000
    assert entry.raw_fields["owner_index"]["value"] == 0
    assert entry.raw_fields["owner_index"]["resolved_id"] == 1000
    assert entry.raw_fields["mode"]["octal"] == "4755"


def test_cross_page_gid(manifest: PermissionManifest) -> None:
    entry = next(entry for entry in manifest if entry.path == "/cross-page-setgid")

    assert entry.setgid is True
    assert entry.group.index == 2500
    assert entry.group_id == 7500
    assert entry.group.pointer_index == 1
    assert entry.raw_fields["group_index"]["field"] == "squashfs_base_inode_header.guid"


def test_bad_index_owner_unknown(manifest: PermissionManifest) -> None:
    entry = next(entry for entry in manifest if entry.path == "/bad-index-setuid")

    assert entry.setuid is True
    assert entry.owner.index == 0xFFFF
    assert entry.owner_id is None
    assert entry.owner_known is False
    assert entry.owner_is_root is None
    assert entry.classification == "setuid_owner_unknown"
    assert entry.permission_known_owner_unknown is True
    assert entry.definitely_root_owned_setuid is False
    assert entry.raw_fields["owner_index"]["reason"] == "id_index_out_of_range"


def test_root_setuid_is_definite(manifest: PermissionManifest) -> None:
    entry = next(entry for entry in manifest if entry.path == "/root-setuid")

    assert entry.setuid is True
    assert entry.owner.index == 2
    assert entry.owner_id == 0
    assert entry.owner_is_root is True
    assert entry.definitely_root_owned_setuid is True
    assert entry.classification == "setuid_root"
    assert entry.raw_fields["owner_index"]["resolved_id"] == 0


def test_unknown_and_root_are_not_conflated() -> None:
    """A bad index and a valid index resolving to uid 0 must not share a judgement."""
    manifest = build_permission_manifest(build_identity_image().open())

    bad = next(entry for entry in manifest if entry.path == "/bad-index-setuid")
    root = next(entry for entry in manifest if entry.path == "/root-setuid")

    assert bad.owner_known is False
    assert root.owner_known is True
    assert bad.owner_id is None
    assert root.owner_id == 0
    assert bad.definitely_root_owned_setuid is False
    assert root.definitely_root_owned_setuid is True
    assert bad.classification == "setuid_owner_unknown"
    assert root.classification == "setuid_root"


def test_hardlinks_keep_paths_and_count_once(manifest: PermissionManifest) -> None:
    entry = next(entry for entry in manifest if entry.path == "/hard-a")

    assert entry.paths == ("/hard-a", "/hard-b")
    assert len(entry.paths) == 2
    assert manifest.object_count == sum(1 for _ in manifest)
    assert manifest.path_count == manifest.object_count + 1

    (group,) = manifest.hardlinks
    assert group.paths == ("/hard-a", "/hard-b")
    assert group.inode_number == entry.inode_number
    assert group.header_nlink == 2
    assert group.inode_block == entry.inode_block


def test_selection_options() -> None:
    sqfs = build_identity_image().open()

    no_sticky = build_permission_manifest(sqfs, include_sticky=False, include_world_writable=False)
    paths = {entry.path for entry in no_sticky}
    assert "/sticky-dir" not in paths
    assert "/world-write" not in paths
    assert "/root-setuid" in paths

    with_symlink = build_permission_manifest(sqfs, include_symlinks=True)
    assert "/setuid-symlink" in {entry.path for entry in with_symlink}

    default = build_permission_manifest(sqfs)
    assert "/setuid-symlink" not in {entry.path for entry in default}

    everything = build_permission_manifest(sqfs, include_all=True)
    assert everything.object_count == everything.objects_examined


def test_symlink_mode_does_not_create_false_finding() -> None:
    manifest = build_permission_manifest(build_identity_image().open())
    symlink = next(node for node in build_identity_image().open().root.iterdir() if node.name == "setuid-symlink")

    assert symlink.header.mode & stat.S_ISUID
    assert "/setuid-symlink" not in {entry.path for entry in manifest}


def test_json_output_has_raw_and_resolved_fields(manifest: PermissionManifest) -> None:
    payload = json.loads(manifest.to_json())

    assert payload["summary"]["matching_objects"] == 12
    for entry in payload["entries"]:
        assert entry["raw_fields"]["mode"]["field"] == "squashfs_base_inode_header.mode"
        assert entry["raw_fields"]["owner_index"]["field"] == "squashfs_base_inode_header.uid"
        assert entry["raw_fields"]["group_index"]["field"] == "squashfs_base_inode_header.guid"
        assert "owner" in entry["identity"]
        assert "group" in entry["identity"]


def test_degraded_id_table_preserves_permissions() -> None:
    manifest = build_permission_manifest(build_identity_image(truncate_id_pointers=True).open())

    assert manifest.object_count == 12
    assert manifest.unknown_identity_count == 12
    assert manifest.id_table_truncated is True
    assert manifest.id_table_error is None
    assert manifest.diagnostics == [
        {
            "scope": "id_table",
            "error": "id_table_truncated",
            "detail": ("one or more id-table block pointers are missing; identities that need them are unknown"),
        }
    ]
    for entry in manifest:
        assert entry.permission_known_owner_unknown is True
        assert entry.owner_id is None
        assert entry.raw_fields["mode"]["octal"] in {"4755", "2755", "1777", "0666", "2775"}


def test_path_source_is_fully_read(tmp_path: Path) -> None:
    """Opening by path must keep the image readable for the whole walk."""
    image = tmp_path / "identity.sqfs"
    image.write_bytes(build_identity_image().image)

    manifest = build_permission_manifest(image)

    assert manifest.source == str(image)
    assert manifest.object_count == 12
    assert manifest.diagnostics == []
    assert next(entry for entry in manifest if entry.path == "/cross-page-setgid").group_id == 7500


def test_bytes_and_file_sources() -> None:
    layout = build_identity_image()

    from_bytes = build_permission_manifest(layout.image)
    assert from_bytes.object_count == 12
    assert from_bytes.diagnostics == []

    from_file = build_permission_manifest(BytesIO(layout.image))
    assert from_file.object_count == 12
