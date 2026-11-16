"""Build an encrypted APFS volume with a historical snapshot from the test fixture.

The repository fixture only contains an encrypted volume without snapshots, so this
helper derives one from it. The derived image keeps the original container, volume,
keybag and password, and adds:

* a snapshot superblock with its own physical block and transaction ID,
* an encrypted snapshot root tree and file data,
* OMAP entries that map the shared root tree object ID to the snapshot's block at the
  snapshot transaction ID.
"""

from __future__ import annotations

import gzip
import stat
from io import BytesIO
from typing import TYPE_CHECKING, Any

from dissect.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.objects.fs import _hash_filename
from dissect.apfs.util import fletcher64, make_fs_object_key

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS

BLOCK_SIZE = c_apfs.NX_DEFAULT_BLOCK_SIZE
SNAPSHOT_XID = 6
SNAPSHOT_SBLOCK = 1001
SNAPSHOT_ROOT_TREE = 1002
SNAPSHOT_DATA = 1003
FOREIGN_SBLOCK = 1004
FUTURE_KEY_SBLOCK = 1005
MULTIKEY_SBLOCK = 1006
OMAP_TREE = 1000

CURRENT_FILE = "dir/file"
CURRENT_CONTENT = " File System\n".encode()
SNAPSHOT_CONTENT = b"content from the snapshot\n"

# Snapshot names used by the tests
SNAPSHOT_NAME = "Historical"
FOREIGN_NAME = "Foreign volume"
FUTURE_KEY_NAME = "Future key"
MULTIKEY_NAME = "Multi-key"


def build_image(path: str) -> bytes:
    """Build an encrypted APFS image with snapshots from the given fixture."""
    raw = bytearray(gzip.open(path, "rb").read())
    blocks = [raw[i : i + BLOCK_SIZE] for i in range(0, len(raw), BLOCK_SIZE)]

    container = APFS(BytesIO(raw))
    volume = container.volumes[0]
    volume.unlock("password")
    cipher = volume._cipher

    blocks[SNAPSHOT_ROOT_TREE] = cipher.encrypt(
        _leaf_block(
            _root_tree_records(SNAPSHOT_DATA, len(SNAPSHOT_CONTENT)),
            oid=volume.object.apfs_root_tree_oid,
            xid=SNAPSHOT_XID,
            subtype=c_apfs.OBJECT_TYPE_FSTREE,
            object_type=c_apfs.OBJ_ENCRYPTED | c_apfs.OBJECT_TYPE_BTREE,
        ),
        SNAPSHOT_ROOT_TREE * container.sectors_per_block,
    )
    blocks[SNAPSHOT_DATA] = cipher.encrypt(
        SNAPSHOT_CONTENT.ljust(BLOCK_SIZE, b"\0"),
        SNAPSHOT_DATA * container.sectors_per_block,
    )

    blocks[SNAPSHOT_SBLOCK] = _snapshot_superblock(volume, SNAPSHOT_SBLOCK, SNAPSHOT_XID)
    blocks[FOREIGN_SBLOCK] = _snapshot_superblock(
        volume,
        FOREIGN_SBLOCK,
        SNAPSHOT_XID,
        volume_uuid=_flip_uuid(volume.object.apfs_vol_uuid),
    )
    blocks[FUTURE_KEY_SBLOCK] = _snapshot_superblock(
        volume,
        FUTURE_KEY_SBLOCK,
        SNAPSHOT_XID,
        key_revision=volume.object.apfs_meta_crypto.key_revision + 1,
    )
    blocks[MULTIKEY_SBLOCK] = _snapshot_superblock(
        volume,
        MULTIKEY_SBLOCK,
        SNAPSHOT_XID,
        flags=volume.object.apfs_fs_flags & ~c_apfs.APFS_FS.ONEKEY,
    )

    blocks[volume.object.apfs_snap_meta_tree_oid] = _snapshot_meta_tree(volume)
    blocks[OMAP_TREE] = _omap_tree(volume)
    blocks[volume.omap.address] = _replace_omap_tree(volume, OMAP_TREE)

    return b"".join(blocks)


def _finish(block: bytearray) -> bytes:
    block[0:8] = fletcher64(block[8:]).to_bytes(8, "little")
    return bytes(block)


def _padded(struct: Any) -> bytes:
    return _finish(bytearray(struct.dumps().ljust(BLOCK_SIZE, b"\0")))


def _key(oid: int, type: c_apfs.APFS_TYPE) -> bytes:
    return make_fs_object_key(oid, type).dumps()


def _inode(oid: int, parent: int, mode: int, dstream: tuple[int, int] | None = None) -> bytes:
    value = c_apfs.j_inode_val(parent_id=parent, private_id=oid, mode=mode)
    if dstream is None:
        return value.dumps()

    size, crypto_id = dstream
    blob = c_apfs.xf_blob(xf_num_exts=1, xf_used_data=len(c_apfs.j_dstream))
    data = (
        blob.dumps()[:4]
        + c_apfs.x_field(x_type=c_apfs.INO_EXT_TYPE.DSTREAM, x_flags=0, x_size=len(c_apfs.j_dstream)).dumps()
        + c_apfs.j_dstream(size=size, alloced_size=BLOCK_SIZE, default_crypto_id=crypto_id).dumps()
    )
    return value.dumps() + data


def _drec(oid: int, name: str, file_id: int, flags: int) -> tuple[bytes, bytes]:
    name_bytes = name.encode() + b"\x00"
    hash_value = ((_hash_filename(name, True) << c_apfs.J_DREC_HASH_SHIFT) & c_apfs.J_DREC_HASH_MASK) | (
        len(name_bytes) & c_apfs.J_DREC_LEN_MASK
    )
    key = c_apfs.j_drec_hashed_key(
        hdr=make_fs_object_key(oid, c_apfs.APFS_TYPE.DIR_REC),
        name_len_and_hash=hash_value,
        name=name_bytes,
    )
    value = c_apfs.j_drec_val(file_id=file_id, date_added=0, flags=flags)
    return key.dumps(), value.dumps()


def _root_tree_records(data_block: int, size: int) -> list[tuple[bytes, bytes]]:
    records = [
        (_key(1, c_apfs.APFS_TYPE.INODE), _inode(1, 1, stat.S_IFDIR | 0o755)),
        (_key(2, c_apfs.APFS_TYPE.INODE), _inode(2, 1, stat.S_IFDIR | 0o755)),
        _drec(2, "dir", 19, c_apfs.DT.DIR),
        (_key(19, c_apfs.APFS_TYPE.INODE), _inode(19, 2, stat.S_IFDIR | 0o755)),
        _drec(19, "file", 18, c_apfs.DT.REG),
        (_key(18, c_apfs.APFS_TYPE.INODE), _inode(18, 19, stat.S_IFREG | 0o644, (size, data_block))),
        (
            c_apfs.j_file_extent_key(
                hdr=make_fs_object_key(18, c_apfs.APFS_TYPE.FILE_EXTENT),
                logical_addr=0,
            ).dumps(),
            c_apfs.j_file_extent_val(
                len_and_flags=BLOCK_SIZE,
                phys_block_num=data_block,
                crypto_id=data_block,
            ).dumps(),
        ),
    ]
    return sorted(records, key=lambda record: record[0])


def _leaf_block(
    records: list[tuple[bytes, bytes]],
    *,
    oid: int,
    xid: int,
    subtype: int,
    object_type: int = c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_BTREE_NODE,
) -> bytes:
    block = bytearray(BLOCK_SIZE)
    count = len(records)

    key_offset = len(c_apfs.btree_node_phys) + count * len(c_apfs.kvloc)
    value_end = BLOCK_SIZE - len(c_apfs.btree_info)
    key_cursor = key_offset
    value_cursor = value_end

    toc = bytearray()
    for key, value in records:
        block[key_cursor : key_cursor + len(key)] = key
        value_cursor -= len(value)
        block[value_cursor : value_cursor + len(value)] = value
        toc += c_apfs.kvloc(
            k=c_apfs.nloc(off=key_cursor - key_offset, len=len(key)),
            v=c_apfs.nloc(off=value_end - value_cursor, len=len(value)),
        ).dumps()
        key_cursor += len(key)

    block[len(c_apfs.btree_node_phys) : len(c_apfs.btree_node_phys) + len(toc)] = toc
    block[0 : len(c_apfs.btree_node_phys)] = c_apfs.btree_node_phys(
        btn_o=c_apfs.obj_phys(o_cksum=b"\0" * 8, o_oid=oid, o_xid=xid, o_type=object_type, o_subtype=subtype),
        btn_flags=c_apfs.BTNODE.ROOT | c_apfs.BTNODE.LEAF,
        btn_level=0,
        btn_nkeys=count,
        btn_table_space=c_apfs.nloc(off=0, len=len(toc)),
        btn_free_space=c_apfs.nloc(off=len(toc), len=key_offset - len(toc) - len(c_apfs.btree_node_phys)),
        btn_key_free_list=c_apfs.nloc(off=0, len=0),
        btn_val_free_list=c_apfs.nloc(off=0, len=0),
    ).dumps()

    info = c_apfs.btree_info(
        bt_fixed=c_apfs.btree_info_fixed(
            bt_flags=c_apfs.BTREE.SEQUENTIAL_INSERT | c_apfs.BTREE.KV_NONALIGNED,
            bt_node_size=BLOCK_SIZE,
            bt_key_size=0,
            bt_val_size=0,
        ),
        bt_longest_key=max(len(key) for key, _ in records),
        bt_longest_val=max(len(value) for _, value in records),
        bt_key_count=count,
        bt_node_count=1,
    )
    block[-len(info) :] = info.dumps()

    return _finish(block)


def _snapshot_superblock(
    volume: FS,
    block_address: int,
    xid: int,
    *,
    volume_uuid: bytes | None = None,
    key_revision: int | None = None,
    flags: int | None = None,
) -> bytes:
    source = volume.object.apfs_meta_crypto
    crypto = c_apfs.wrapped_meta_crypto_state(
        major_version=source.major_version,
        minor_version=source.minor_version,
        cpflags=source.cpflags,
        persistent_class=source.persistent_class,
        key_os_version=source.key_os_version,
        key_revision=source.key_revision if key_revision is None else key_revision,
        unused=source.unused,
    )

    superblock = c_apfs.apfs_superblock(
        apfs_o=c_apfs.obj_phys(
            o_cksum=b"\0" * 8,
            o_oid=block_address,
            o_xid=xid,
            o_type=c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_FS,
            o_subtype=0,
        ),
        apfs_magic=int.from_bytes(c_apfs.APFS_MAGIC, "big"),
        apfs_fs_index=volume.object.apfs_fs_index,
        apfs_incompatible_features=volume.object.apfs_incompatible_features,
        apfs_meta_crypto=crypto,
        apfs_omap_oid=volume.object.apfs_omap_oid,
        apfs_root_tree_oid=volume.object.apfs_root_tree_oid,
        apfs_snap_meta_tree_oid=0,
        apfs_vol_uuid=volume_uuid if volume_uuid is not None else volume.object.apfs_vol_uuid,
        apfs_fs_flags=volume.object.apfs_fs_flags if flags is None else flags,
        apfs_volname=b"Encrypted Snapshot",
    )
    return _padded(superblock)


def _snapshot_meta_tree(volume: FS) -> bytes:
    entries = [
        (SNAPSHOT_XID, SNAPSHOT_NAME, SNAPSHOT_SBLOCK),
        (SNAPSHOT_XID, FOREIGN_NAME, FOREIGN_SBLOCK),
        (SNAPSHOT_XID, FUTURE_KEY_NAME, FUTURE_KEY_SBLOCK),
        (SNAPSHOT_XID, MULTIKEY_NAME, MULTIKEY_SBLOCK),
    ]

    records = []
    for xid, name, sblock in entries:
        name_bytes = name.encode()
        value = c_apfs.j_snap_metadata_val(
            extentref_tree_oid=0,
            sblock_oid=sblock,
            create_time=1,
            change_time=1,
            inum=0,
            extentref_tree_type=0,
            flags=0,
            name_len=len(name_bytes),
            name=name_bytes,
        )
        records.append((_key(xid, c_apfs.APFS_TYPE.SNAP_METADATA), value.dumps()))

    return _leaf_block(
        sorted(records, key=lambda record: record[0]),
        oid=volume.object.apfs_snap_meta_tree_oid,
        xid=volume.xid,
        subtype=c_apfs.OBJECT_TYPE.SNAPMETATREE,
    )


def _omap_tree(volume: FS) -> bytes:
    records = list(Cursor(volume.omap.btree).walk())
    records.append(
        (
            c_apfs.omap_key(ok_oid=volume.object.apfs_root_tree_oid, ok_xid=SNAPSHOT_XID).dumps(),
            c_apfs.omap_val(ov_flags=0, ov_size=BLOCK_SIZE, ov_paddr=SNAPSHOT_ROOT_TREE).dumps(),
        )
    )
    records.sort(
        key=lambda record: (int.from_bytes(record[0][:8], "little"), int.from_bytes(record[0][8:16], "little"))
    )

    return _leaf_block(
        records,
        oid=OMAP_TREE,
        xid=volume.omap.xid,
        subtype=c_apfs.OBJECT_TYPE.OMAP,
        object_type=c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_BTREE,
    )


def _replace_omap_tree(volume: FS, tree: int) -> bytes:
    omap = c_apfs.omap_phys(volume.omap.block)
    omap.om_tree_oid = tree
    return _padded(omap)


def _flip_uuid(value: bytes) -> bytes:
    result = bytearray(value)
    result[0] ^= 0xFF
    return bytes(result)
