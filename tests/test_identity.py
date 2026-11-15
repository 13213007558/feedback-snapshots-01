from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import InvalidIDError
from dissect.squashfs.identity import IdLookup
from dissect.squashfs.squashfs import SquashFS

from ._squashfs_builder import build_cross_block_id_image, build_identity_image

if TYPE_CHECKING:
    from ._squashfs_builder import ImageLayout


@pytest.fixture
def layout() -> ImageLayout:
    return build_identity_image()


@pytest.fixture
def sqfs(layout: ImageLayout) -> SquashFS:
    return layout.open()


def test_index_is_not_identity(sqfs: SquashFS) -> None:
    """The on-disk index field must not be reported as the numeric uid."""
    node = sqfs.get("index-vs-uid")

    assert node.header.uid == 0
    assert node.uid_index == 0
    assert node.uid == 1000
    assert node.uid_lookup.resolved_id == 1000
    assert node.uid_lookup.index == 0
    assert node.uid_lookup.raw_field == "squashfs_base_inode_header.uid"
    assert node.uid_lookup.pointer_index == 0
    assert node.uid_lookup.metadata_offset == 0


def test_extended_inode_cross_page_gid(sqfs: SquashFS, layout: ImageLayout) -> None:
    """An extended inode gid index in the second id metadata block resolves."""
    node = sqfs.get("cross-page-setgid")

    assert node.header.inode_type == c_squashfs.SQUASHFS_LREG_TYPE
    assert node.gid_index == 2500
    assert node.gid == 7500
    assert node.gid_lookup.pointer_index == 1
    assert node.gid_lookup.metadata_block == layout.id_metadata_starts[1]
    assert node.gid_lookup.metadata_offset == 1808


def test_last_entry_of_id_block(sqfs: SquashFS) -> None:
    """The final entry that fits in the first id metadata block resolves."""
    node = sqfs.get("boundary-gid")

    assert node.gid_index == 2047
    assert node.gid == 7047
    assert node.gid_lookup.pointer_index == 0
    assert node.gid_lookup.metadata_offset == 8188


def test_basic_and_extended_share_lookup_path(sqfs: SquashFS) -> None:
    """Basic and extended headers must produce the same evidence structure."""
    basic = sqfs.get("index-vs-uid")
    extended = sqfs.get("root-setuid")

    assert basic.header.inode_type == c_squashfs.SQUASHFS_FILE_TYPE
    assert extended.header.inode_type == c_squashfs.SQUASHFS_LREG_TYPE
    for node in (basic, extended):
        assert isinstance(node.uid_lookup, IdLookup)
        assert isinstance(node.gid_lookup, IdLookup)
        assert node.uid_lookup.raw_field == "squashfs_base_inode_header.uid"
        assert node.gid_lookup.raw_field == "squashfs_base_inode_header.guid"
        assert node.uid_lookup.index == node.header.uid
        assert node.gid_lookup.index == node.header.guid


def test_shared_index_resolves_consistently(sqfs: SquashFS) -> None:
    """Different inodes sharing an index get the same numeric identity."""
    first = sqfs.get("same-index-a")
    second = sqfs.get("same-index-b")

    assert first.uid_index == second.uid_index == 1
    assert first.uid == second.uid == 4242
    assert first.uid_lookup == second.uid_lookup


def test_bad_index_is_unknown_not_zero(sqfs: SquashFS) -> None:
    """An out-of-range index is unknown, never coerced to uid/gid 0."""
    node = sqfs.get("bad-index-setuid")

    assert node.uid_index == 0xFFFF
    assert node.uid is None
    assert node.uid_lookup.known is False
    assert node.uid_lookup.reason == "id_index_out_of_range"
    assert node.uid_lookup.resolved_id is None
    assert node.gid == 0
    assert node.gid_lookup.is_root is True

    with pytest.raises(InvalidIDError):
        sqfs._lookup_id(0xFFFF)


def test_truncated_id_pointer_array_is_unknown() -> None:
    """A missing id-pointer array yields unknown identities, not zero."""
    layout = build_identity_image(truncate_id_pointers=True)
    sqfs = layout.open()

    assert sqfs.id_table_truncated is True
    assert sqfs.id_table == []

    node = sqfs.get("root-setuid")
    assert node.uid is None
    assert node.uid_lookup.reason == "id_table_truncated"
    assert node.uid_lookup.index == 2


def test_id_lookup_does_not_query_local_accounts() -> None:
    """Numeric-only lookup: a uid with no local account still resolves."""
    layout = build_identity_image()
    sqfs = layout.open()
    node = sqfs.get("index-vs-uid")

    # If pwd.getpwuid were used, this would be an account-name lookup; the
    # module must return the image's numeric ID even when it is not local.
    assert node.uid == 1000
    assert isinstance(node.uid, int)
    assert node.uid_lookup.label == "uid:1000"


def test_id_lookup_entries_across_blocks() -> None:
    """Entries in the first and second id metadata blocks resolve consistently."""
    sqfs = build_identity_image().open()

    first = sqfs._resolve_id(2047, "uid", "squashfs_base_inode_header.uid")
    second = sqfs._resolve_id(2048, "uid", "squashfs_base_inode_header.uid")

    assert first.pointer_index == 0
    assert first.metadata_offset == 8188
    assert first.resolved_id == 7047
    assert second.pointer_index == 1
    assert second.metadata_offset == 0
    assert second.resolved_id == 7048


def test_id_entry_crosses_metadata_block() -> None:
    """An id entry may continue from one metadata block into the next."""
    layout = build_cross_block_id_image()
    sqfs = SquashFS(BytesIO(layout))

    before = sqfs._resolve_id(2046, "uid", "squashfs_base_inode_header.uid")
    crossing = sqfs._resolve_id(2047, "uid", "squashfs_base_inode_header.uid")

    assert before.resolved_id == 3046
    assert before.pointer_index == 0
    assert before.metadata_offset == 8184
    assert crossing.resolved_id == 5555
    assert crossing.pointer_index == 0
    assert crossing.metadata_offset == 8188
