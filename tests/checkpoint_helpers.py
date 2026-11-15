from __future__ import annotations

import gzip
import struct
from pathlib import Path

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.util import fletcher64

BLOCK_SIZE = c_apfs.NX_DEFAULT_BLOCK_SIZE
_DATA = Path(__file__).parent / "_data"


def load_image(name: str) -> bytearray:
    """Load a (gzipped) test image into a mutable byte buffer."""
    with gzip.open(_DATA / name, "rb") as fh:
        return bytearray(fh.read())


def write_block(image: bytearray, address: int, block: bytes) -> None:
    """Overwrite a single block in the image buffer."""
    image[address * BLOCK_SIZE : (address + 1) * BLOCK_SIZE] = block


def read_block(image: bytearray, address: int) -> bytearray:
    """Read a single block from the image buffer."""
    return bytearray(image[address * BLOCK_SIZE : (address + 1) * BLOCK_SIZE])


def recheck(block: bytearray) -> bytearray:
    """Recompute and write the Fletcher-64 checksum of a full block."""
    block[: c_apfs.MAX_CKSUM_SIZE] = b"\x00" * c_apfs.MAX_CKSUM_SIZE
    checksum = fletcher64(bytes(block[c_apfs.MAX_CKSUM_SIZE :]))
    block[: c_apfs.MAX_CKSUM_SIZE] = struct.pack("<Q", checksum)
    return block


def parse_header(image: bytearray, address: int) -> c_apfs.obj_phys:
    """Parse the object header of a block."""
    return c_apfs.obj_phys(bytes(read_block(image, address)))


def find_descriptor_superblocks(image: bytearray) -> list[tuple[int, int]]:
    """Return ``(address, xid)`` pairs for every NX superblock in the descriptor ring."""
    anchor = c_apfs.nx_superblock(bytes(read_block(image, 0)))
    base = anchor.nx_xp_desc_base
    capacity = anchor.nx_xp_desc_blocks & 0x7FFFFFFF

    result: list[tuple[int, int]] = []
    for offset in range(capacity):
        address = base + offset
        header = parse_header(image, address)
        object_type = c_apfs.OBJECT_TYPE(header.o_type & c_apfs.OBJECT_TYPE_MASK)
        if object_type == c_apfs.OBJECT_TYPE.NX_SUPERBLOCK:
            result.append((address, header.o_xid))
    return result


def descriptor_window(image: bytearray) -> tuple[int, int, int, int]:
    """Return the descriptor ring ``(base, capacity, index, length)`` from the anchor."""
    anchor = c_apfs.nx_superblock(bytes(read_block(image, 0)))
    return (
        anchor.nx_xp_desc_base,
        anchor.nx_xp_desc_blocks & 0x7FFFFFFF,
        anchor.nx_xp_desc_index,
        anchor.nx_xp_desc_len,
    )


def set_descriptor_window(image: bytearray, *, index: int | None = None, length: int | None = None) -> None:
    """Rewrite the descriptor window fields of every superblock and re-checksum them.

    Keeps the anchor and all ring superblocks consistent about which window is valid, so the only thing the
    test changes is the window geometry itself. Fields are patched in place rather than re-serialized, so the
    trailing (struct-uncovered) bytes of a full block survive and the Fletcher checksum stays meaningful.
    """
    targets = [0]
    targets.extend(address for address, _ in find_descriptor_superblocks(image))

    for address in targets:
        block = read_block(image, address)

        offset_index = c_apfs.nx_superblock.lookup["nx_xp_desc_index"].offset
        offset_length = c_apfs.nx_superblock.lookup["nx_xp_desc_len"].offset
        if index is not None:
            block[offset_index : offset_index + 4] = struct.pack("<I", index)
        if length is not None:
            block[offset_length : offset_length + 4] = struct.pack("<I", length)
        write_block(image, address, recheck(block))


def corrupt_checksum(image: bytearray, address: int) -> None:
    """Flip a payload byte so the block keeps its old checksum but no longer matches it."""
    block = read_block(image, address)
    block[BLOCK_SIZE - 1] ^= 0xFF
    write_block(image, address, block)


def clone_superblock(image: bytearray, source_address: int, target_address: int, *, xid: int) -> None:
    """Copy a valid superblock onto another ring slot, give it a higher xid and make its checksum valid."""
    block = read_block(image, source_address)

    xid_offset = c_apfs.obj_phys.lookup["o_xid"].offset
    block[xid_offset : xid_offset + 8] = struct.pack("<Q", xid)
    write_block(image, target_address, recheck(block))
