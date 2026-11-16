from __future__ import annotations

import gzip
import io
from typing import Any

import pytest

from dissect.apfs import APFS, CheckpointError
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.util import fletcher64
from tests.conftest import absolute_path


BLOCK_SIZE = 4096


def _load_image(name: str) -> bytearray:
    with gzip.open(absolute_path(name), "rb") as fh:
        return bytearray(fh.read())


def _read_block(image: bytearray, address: int) -> bytes:
    return bytes(image[address * BLOCK_SIZE : (address + 1) * BLOCK_SIZE])


def _write_block(image: bytearray, address: int, block: bytes) -> None:
    image[address * BLOCK_SIZE : (address + 1) * BLOCK_SIZE] = block


def _repack(block: bytes, struct: Any, **fields: Any) -> bytes:
    obj = struct(block)
    for name, value in fields.items():
        setattr(obj, name, value)

    result = bytearray(block)
    result[: len(obj.dumps())] = obj.dumps()
    result[:8] = fletcher64(result[8:]).to_bytes(8, "little")
    return bytes(result)


def _patch_nx(image: bytearray, address: int, **fields: object) -> None:
    _write_block(image, address, _repack(_read_block(image, address), c_apfs.nx_superblock, **fields))


def _patch_cpm(image: bytearray, address: int, oid: int) -> None:
    block = _read_block(image, address)
    obj = c_apfs.checkpoint_map_phys(block)
    obj.cpm_o.o_oid = oid
    _write_block(image, address, _repack(block, c_apfs.checkpoint_map_phys, cpm_o=obj.cpm_o))


def _relocate_checkpoint_group(
    image: bytearray, source_map: int, source_nx: int, map_address: int, nx_address: int, index: int
) -> None:
    """Move a checkpoint map/NX pair, keeping the map oid and NX window self-consistent."""
    map_block = _read_block(image, source_map)
    nx_block = _read_block(image, source_nx)

    _write_block(image, map_address, map_block)
    _patch_cpm(image, map_address, map_address)
    _write_block(
        image,
        nx_address,
        _repack(nx_block, c_apfs.nx_superblock, nx_xp_desc_index=index, nx_xp_desc_len=2, nx_xp_desc_next=(index + 2) % 8),
    )


def _rename_volume(image: bytearray, address: int, name: str) -> None:
    _write_block(
        image,
        address,
        _repack(_read_block(image, address), c_apfs.apfs_superblock, apfs_volname=name.encode()),
    )


def _open(image: bytearray) -> APFS:
    return APFS(io.BytesIO(bytes(image)))


def test_checkpoint_wrap_around() -> None:
    """The active checkpoint window may wrap around the end of the descriptor area."""
    image = _load_image("_data/case_insensitive.bin.gz")

    # Re-lay the descriptor ring so the checkpoint groups become:
    #   xid 1 -> slots (1, 2)   xid 2 -> slots (3, 4)
    #   xid 3 -> slots (5, 6)   xid 4 -> slots (7, 0)  (wraps)
    originals = {address: _read_block(image, address) for address in range(1, 9)}

    _write_block(image, 1, originals[8])
    _patch_nx(image, 1, nx_xp_desc_index=7, nx_xp_desc_len=2, nx_xp_desc_next=1)

    _write_block(image, 2, originals[1])
    _patch_cpm(image, 2, 2)
    _write_block(image, 3, _repack(originals[2], c_apfs.nx_superblock, nx_xp_desc_index=1, nx_xp_desc_len=2, nx_xp_desc_next=3))

    _write_block(image, 4, originals[3])
    _patch_cpm(image, 4, 4)
    _write_block(image, 5, _repack(originals[4], c_apfs.nx_superblock, nx_xp_desc_index=3, nx_xp_desc_len=2, nx_xp_desc_next=5))

    _write_block(image, 6, originals[5])
    _patch_cpm(image, 6, 6)
    _write_block(image, 7, _repack(originals[6], c_apfs.nx_superblock, nx_xp_desc_index=5, nx_xp_desc_len=2, nx_xp_desc_next=7))

    _write_block(image, 8, originals[7])
    _patch_cpm(image, 8, 8)

    _patch_nx(image, 0, nx_xp_desc_index=7, nx_xp_desc_len=2, nx_xp_desc_next=1)
    _rename_volume(image, 202, "Wrap active")

    container = _open(image)

    assert container.sb.xid == 4
    assert container.checkpoint.window.wraps
    assert container.checkpoint.window.slots == (7, 0)
    assert container.checkpoint.window.addresses == (8, 1)
    assert [volume.name for volume in container.volumes] == ["Wrap active"]
    assert "slots=(7, 0)" in container.checkpoint_report
    assert "Selected: xid=4" in container.checkpoint_report
    assert "Fallback: no" in container.checkpoint_report


def test_checkpoint_newest_omap_corrupt() -> None:
    """A corrupt OMAP on the newest checkpoint must cause a verified fallback."""
    image = _load_image("_data/case_insensitive.bin.gz")

    # Corrupt the OMAP of the newest checkpoint (xid 4), leaving its NX valid.
    omap = bytearray(_read_block(image, 203))
    omap[8] ^= 0xFF
    _write_block(image, 203, bytes(omap))

    _rename_volume(image, 202, "Newest")
    _rename_volume(image, 199, "Fallback")

    container = _open(image)

    assert container.sb.xid == 3
    assert container.checkpoint.fallback
    assert container.checkpoint.window.index == 6
    assert [volume.name for volume in container.volumes] == ["Fallback"]
    assert container.checkpoint.rejected_active
    assert "invalid OMAP object at block 203" in container.checkpoint.report()
    assert "selected linked prior checkpoint xid=3" in container.checkpoint.reason


def test_checkpoint_outside_window_candidate() -> None:
    """A checksum-valid NX with a higher xid outside the window is not the current state."""
    image = _load_image("_data/case_insensitive.bin.gz")

    # Point the anchor's active window at the xid 3 checkpoint in slots (4, 5).
    _patch_nx(image, 0, nx_xp_desc_index=4, nx_xp_desc_len=2, nx_xp_desc_next=6)

    # Block 8 holds the old xid 4 NX. Turn it into a self-consistent, checksum
    # valid pseudo candidate with a much higher xid, outside the active window.
    nx = c_apfs.nx_superblock(_read_block(image, 8))
    nx.nx_o.o_xid = 99
    _patch_nx(image, 8, nx_o=nx.nx_o, nx_next_xid=100)

    _rename_volume(image, 202, "Pseudo newest")
    _rename_volume(image, 199, "Window checkpoint")

    container = _open(image)

    assert container.sb.xid == 3
    assert [volume.name for volume in container.volumes] == ["Window checkpoint"]
    assert "outside active checkpoint descriptor window" in container.checkpoint_report
    assert "is newer than the active window checkpoint" in container.checkpoint_report
    assert "xid=99" in container.checkpoint_report
    assert "Selected: xid=3" in container.checkpoint_report


def test_checkpoint_all_candidates_invalid() -> None:
    """If every candidate fails, construction must fail instead of keeping half-initialized state."""
    image = _load_image("_data/case_insensitive.bin.gz")

    for address in (2, 4, 6, 8):
        block = bytearray(_read_block(image, address))
        block[8] ^= 0xFF
        _write_block(image, address, bytes(block))

    with pytest.raises(CheckpointError) as exc_info:
        _open(image)

    message = str(exc_info.value)
    assert "No consistent APFS checkpoint found" in message
    for xid in (1, 2, 3, 4):
        assert f"xid={xid}" in message
    assert "Selected: none" in message
