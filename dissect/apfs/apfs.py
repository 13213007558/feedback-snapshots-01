from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, BinaryIO

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.checkpoint import select_checkpoint
from dissect.apfs.objects import NxSuperblock

if TYPE_CHECKING:
    from uuid import UUID

    from dissect.apfs.objects.fs import FS
    from dissect.apfs.objects.keybag import ContainerKeybag

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_APFS", "CRITICAL"))


class APFS:
    """Container class for APFS operations.

    Args:
        fh: File-like object to read the APFS container from.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        self.anchor = NxSuperblock.from_block(self, 0, self.fh.read(c_apfs.NX_DEFAULT_BLOCK_SIZE))
        self.anchor.check()

        # Bootstrap block size and block count from the anchor so the checkpoint
        # descriptor area can be read before a checkpoint has been selected.
        self.sb = self.anchor
        self.checkpoint = select_checkpoint(self, self.anchor)
        self.sb = self.checkpoint.superblock

        for message in self.checkpoint.log_messages():
            log.debug(message)

        if self.checkpoint.fallback:
            log.warning("Falling back to older APFS checkpoint:\n%s", self.checkpoint.report())

    @property
    def sbs(self) -> list[NxSuperblock]:
        """All superblocks found while selecting a checkpoint, newest first."""
        return sorted(
            [candidate.superblock for candidate in self.checkpoint.candidates if candidate.superblock is not None],
            key=lambda obj: obj.xid,
            reverse=True,
        )

    @property
    def checkpoint_report(self) -> str:
        """A human-readable report of the checkpoint selection."""
        return self.checkpoint.report()

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

    @property
    def keybag(self) -> ContainerKeybag | None:
        """The container keybag, if present."""
        return self.sb.keylocker

    @property
    def volumes(self) -> list[FS]:
        """All the filesystems in the container."""
        return self.sb.filesystems

    def _read_block(self, address: int, count: int = 1) -> bytes:
        """Read a block from the container.

        Args:
            address: The block address to read.
        """
        # TODO: Fusion tier2
        self.fh.seek(address * self.block_size)
        return self.fh.read(count * self.block_size)
