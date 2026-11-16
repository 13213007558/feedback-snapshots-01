from __future__ import annotations

import io
import logging
import os
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import Error
from dissect.apfs.objects import NxSuperblock

if TYPE_CHECKING:
    from uuid import UUID

    from dissect.apfs.objects.fs import FS
    from dissect.apfs.objects.keybag import ContainerKeybag

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_APFS", "CRITICAL"))


def fusion_tier2_device_mask(block_size: int) -> int:
    """Return the tier-2 device selection bit as a block address mask.

    APFS defines the Fusion device selection bit as a byte address
    (``FUSION_TIER2_DEVICE_BYTE_ADDR``), while physical block addresses are
    expressed in blocks. The mask therefore depends on the container block size.

    Args:
        block_size: The block size of the container, in bytes.
    """
    if block_size <= 0 or block_size & (block_size - 1):
        raise ValueError(f"Invalid block size for Fusion address conversion: {block_size!r}")

    return c_apfs.FUSION_TIER2_DEVICE_BYTE_ADDR >> (block_size.bit_length() - 1)


class APFS:
    """Container class for APFS operations.

    Args:
        fh: File-like object to read the APFS container from.
        tier2_fh: Optional read-only file-like object for the second (tier-2) device of a
            Fusion Drive. Must be provided explicitly; the module never searches for or
            infers local devices.

    Note:
        Fusion routing is limited to physical block addresses that already contain the
        device selection bit (``FUSION_TIER2_DEVICE_BYTE_ADDR`` converted to blocks). The
        following on-disk Fusion structures are parsed as objects but are not applied to
        address resolution, so reads that depend on them are not supported:

        - The Fusion middle tree (``nx_fusion_mt_oid`` / ``FUSION_MIDDLE_TREE``), which maps
          a tier-1 address to a tier-2 address when the stored address has no tier-2 bit.
        - The Fusion write-back cache (``nx_fusion_wbc`` / ``NX_FUSION_WBC`` and
          ``NX_FUSION_WBC_LIST``), which redirects reads to pending data in the tier-1 cache.
        - Other Fusion metadata such as the write-back cache range and tenant records.

        Consequently, a block whose current contents are still in the write-back cache, or
        whose tier-2 location is only recorded in the middle tree, cannot be reconstructed
        from the two images with this entry point.
    """

    def __init__(self, fh: BinaryIO, tier2_fh: BinaryIO | None = None):
        self.fh = fh
        self.fh.seek(0)

        self.tier2_fh = tier2_fh
        if tier2_fh is not None and tier2_fh is fh:
            raise Error("The Fusion tier-2 device must be a separate file-like object")

        self.sb = NxSuperblock.from_block(self, 0, self.fh.read(c_apfs.NX_DEFAULT_BLOCK_SIZE))
        self.sb.check()

        self.sbs = sorted(
            [obj for obj in self.sb.checkpoint_objects if isinstance(obj, NxSuperblock)],
            key=lambda obj: obj.xid,
            reverse=True,
        )

        # TODO: Do more accurate checkpoint traversal
        for sb in self.sbs:
            try:
                sb.check()
                sb.compare(self.sb)
            except Exception as e:
                log.debug("Skipping superblock xid=%d: %s", sb.xid, e)
                continue

            if not sb.omap.is_valid():
                log.debug("Skipping superblock xid=%d: invalid OMAP", sb.xid)
                continue

            self.sb = sb
            break

    @property
    def block_size(self) -> int:
        """The block size of the container."""
        return self.sb.block_size

    @property
    def sectors_per_block(self) -> int:
        """The number of 512-byte sectors per block."""
        return self.block_size // 512

    @property
    def block_count(self) -> int:
        """The total number of blocks in the container."""
        return self.sb.block_count

    @property
    def uuid(self) -> UUID:
        """The UUID of the container."""
        return self.sb.uuid

    @cached_property
    def is_fusion(self) -> bool:
        """Whether the container is part of a Fusion Drive."""
        return c_apfs.NX_INCOMPAT.FUSION in c_apfs.NX_INCOMPAT(self.sb.object.nx_incompatible_features)

    @cached_property
    def tier2_block_mask(self) -> int:
        """The tier-2 device selection bit expressed as a physical block address mask."""
        return fusion_tier2_device_mask(self.block_size)

    def device_block_address(self, address: int) -> int:
        """Return the device-relative block address, without the Fusion tier-2 selection bit.

        Args:
            address: The physical block address as stored in an APFS structure.
        """
        return address & ~self.tier2_block_mask

    def read_block(self, address: int, count: int = 1) -> bytes:
        """Read one or more blocks, routing Fusion addresses to the correct device.

        This is a read-only entry point that applies the same device selection and bounds
        rules as all internal metadata and file data reads.

        Args:
            address: The physical block address to read. May include the Fusion tier-2 bit.
            count: The number of consecutive blocks to read.
        """
        return self._read_block(address, count)

    def read_block_with_device(self, address: int, count: int = 1) -> tuple[bytes, str]:
        """Read blocks and report the device they were read from.

        Args:
            address: The physical block address to read. May include the Fusion tier-2 bit.
            count: The number of consecutive blocks to read.

        Returns:
            A tuple of the block data and either ``"tier1"`` or ``"tier2"``.
        """
        tier = "tier2" if address & self.tier2_block_mask else "tier1"
        return self._read_block(address, count), tier

    @property
    def keybag(self) -> ContainerKeybag | None:
        """The container keybag, if present."""
        return self.sb.keylocker

    @property
    def volumes(self) -> list[FS]:
        """All the filesystems in the container."""
        return self.sb.filesystems

    @staticmethod
    def _stream_size(fh: BinaryIO) -> int | None:
        """Determine the size of a file-like object, if it can be determined cheaply.

        Seeking to the end of a compressed stream can be expensive, so this only inspects
        in-memory and plain on-disk streams. Other streams are bounded by their reads.
        """
        if isinstance(fh, io.BytesIO):
            return fh.getbuffer().nbytes

        if isinstance(fh, (io.BufferedReader, io.FileIO)):
            try:
                return os.fstat(fh.fileno()).st_size
            except OSError:
                return None

        return None

    def _read_block(self, address: int, count: int = 1) -> bytes:
        """Read one or more blocks from the container, routing Fusion addresses to their device.

        APFS defines the Fusion device selection bit as a byte address
        (``FUSION_TIER2_DEVICE_BYTE_ADDR``), while physical block addresses are expressed in
        blocks. The bit is therefore converted using the container block size before it is
        used on an address. Metadata objects and file extents share this same rule, so the
        tier is selected here for every read.

        A single read never spans both devices: a block range whose first block is on one
        device and whose last block is on the other is rejected. Addresses that carry the
        tier-2 bit are routed to ``tier2_fh`` only, and only when that device was provided.

        Args:
            address: The physical block address to read. May include the Fusion tier-2 bit.
            count: The number of consecutive blocks to read.

        Raises:
            Error: If the address selects the tier-2 device without one being provided, if
                a read crosses the Fusion device selection boundary, if the requested range
                is beyond the addressed device's capacity, or if the read returns short.
        """
        if count < 0:
            raise ValueError(f"Invalid block count: {count!r}")

        if address < 0:
            raise Error(f"Invalid negative block address: {address:#x}")

        block_size = self.block_size
        tier2_mask = self.tier2_block_mask
        use_tier2 = bool(address & tier2_mask)

        if use_tier2:
            if self.tier2_fh is None:
                raise Error(
                    f"Block address {address:#x} selects the Fusion tier-2 device, but no tier-2 device was provided"
                )

            fh = self.tier2_fh
            device_name = "tier-2"
        else:
            fh = self.fh
            device_name = "tier-1"

        if count and use_tier2 != bool((address + count - 1) & tier2_mask):
            raise Error(
                f"Read of {count} blocks from {address:#x} crosses the Fusion device selection boundary "
                f"({tier2_mask:#x})"
            )

        device_address = address & ~tier2_mask
        offset = device_address * block_size
        length = count * block_size

        if offset.bit_length() > 63:
            raise Error(f"Read of {count} blocks from {address:#x} is outside the {device_name} device address space")

        # The container superblock bounds the tier-1 device; its reported block count is
        # authoritative even when the first image itself cannot be sized.
        if not use_tier2 and self.block_count and device_address + count > self.block_count:
            raise Error(
                f"Read of {count} blocks from {address:#x} is beyond the capacity of the {device_name} device "
                f"({self.block_count} blocks)"
            )

        if (size := self._stream_size(fh)) is not None and offset + length > size:
            raise Error(
                f"Read of {count} blocks from {address:#x} is beyond the capacity of the {device_name} device "
                f"({size} bytes)"
            )

        fh.seek(offset)
        buf = fh.read(length)

        if len(buf) != length:
            raise Error(
                f"Short read from the {device_name} device at block {device_address:#x}: "
                f"expected {length} bytes, got {len(buf)}"
            )

        return buf
