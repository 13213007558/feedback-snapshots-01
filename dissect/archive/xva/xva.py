from __future__ import annotations

import hashlib
import tarfile
from bisect import bisect_right
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO
from xml.etree import ElementTree

from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from collections.abc import Iterator

BLOCK_SIZE = 1024 * 1024


class UnsupportedChecksumError(NotImplementedError):
    """Raised when a checksum uses an algorithm this reader does not support."""


class XVA:
    """XVA reader.

    XenCenter export format. Basically a tar file with "blocks" of 1MB.
    """

    def __init__(self, fh: BinaryIO):
        # We don't have to cache tar members, tarfile already does that for us
        self.tar = tarfile.open(fileobj=fh)  # noqa: SIM115

    @cached_property
    def ova(self) -> ElementTree.Element:
        ova_member = self.tar.getmember("ova.xml")
        ova_fh = self.tar.extractfile(ova_member)
        return ElementTree.fromstring(ova_fh.read())

    def disks(self) -> list[str]:
        return [
            el.text
            for el in self.ova.findall(
                "*//member/name[.='VDI']/../..//name[.='type']/..value[.='Disk']/../..//name[.='VDI']/../value"
            )
        ]

    def open(self, ref: str, verify: bool = False) -> XVAStream:
        size = int(
            self.ova.find(f"*//member/name[.='id']/../value[.='{ref}']/../..//name[.='virtual_size']/../value").text
        )
        return XVAStream(self, ref, size, verify)


class XVAStream(AlignedStream):
    """XVA stream.

    XenServer usually just streams an XVA file right into an output file, so our use-case requires a bit
    more trickery. We generally don't stream directly into an output file, but try to create a file-like
    object for other code to use.

    The numbers for the block files (weirdly) don't represent offsets. It's possible for a block file
    to be 0 sized, in which case you should "add" that block to the stream, and continue on to the next.
    The next block might have a number + 1 of what your current offset is, but it will still contain the
    data for that current offset. For this reason we build a lookup list with offsets.
    """

    def __init__(self, xva: XVA, ref: str, size: int, verify: bool = False):
        self.xva = xva
        self.ref = ref
        self.verify = verify

        # Block and checksum members are keyed by their actual block number. Members are not necessarily stored
        # next to each other and may arrive in any order, so their pairing can't rely on tar ordering or adjacency.
        # A block number can occur more than once; the last occurrence wins, mirroring tarfile's own extraction.
        blocks: dict[int, tarfile.TarInfo] = {}
        checksums: dict[int, tarfile.TarInfo] = {}
        for block_index, member, is_checksum in _iter_block_files(xva, ref):
            if is_checksum:
                checksums[block_index] = member
            else:
                blocks[block_index] = member

        index = -1
        offset = 0
        self._lookup = []
        self._members = []
        for block_index in sorted(blocks):
            block_member = blocks[block_index]

            if block_index > index + 1:
                # Missing numbers are zero-filled holes in the stream.
                offset += (block_index - (index + 1)) * BLOCK_SIZE

            if block_member.size != 0:
                # A zero-sized block advances the block index (it is "added" to the stream) but carries no data,
                # so it gets no lookup entry and does not move the data offset; the next data lands here.
                self._lookup.append(offset)
                self._members.append((block_member, checksums.get(block_index)))

                offset += block_member.size

            index = block_index

        super().__init__(size, align=BLOCK_SIZE)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        while length > 0:
            if not self._lookup:
                # The disk contains no data blocks at all.
                result.append(b"\x00" * BLOCK_SIZE)
                offset += BLOCK_SIZE
                length -= BLOCK_SIZE
                continue

            # This method is probably sub-optimal, but it's fairly low effort and we rarely encounter XVA anyway
            block_idx = bisect_right(self._lookup, offset)
            nearest_offset = self._lookup[block_idx - 1]

            if offset >= nearest_offset + BLOCK_SIZE:
                result.append(b"\x00" * BLOCK_SIZE)
            else:
                block_member, checksum_member = self._members[block_idx - 1]
                buf = self.xva.tar.extractfile(block_member).read()

                if self.verify:
                    self._verify(block_member, checksum_member, buf)

                result.append(buf)

            offset += BLOCK_SIZE
            length -= BLOCK_SIZE

        return b"".join(result)

    def _verify(self, block_member: tarfile.TarInfo, checksum_member: tarfile.TarInfo | None, buf: bytes) -> None:
        if checksum_member is None:
            raise ValueError(f"No checksum for {block_member.name}")

        suffix = checksum_member.name.rsplit(".", 1)[-1]
        if suffix in ("checksum", "sha1"):
            expected = self.xva.tar.extractfile(checksum_member).read().decode().strip()
            if hashlib.sha1(buf).hexdigest() != expected:
                raise ValueError(f"Invalid checksum for {checksum_member.name}")
            return

        raise UnsupportedChecksumError(f"Unsupported checksum: {checksum_member.name}")


def _is_checksum_member(name: str) -> bool:
    suffix = name.rsplit(".", 1)[-1]
    return suffix in ("checksum", "sha1", "xxhash")


def _iter_block_files(xva: XVA, ref: str) -> Iterator[tuple[int, tarfile.TarInfo, bool]]:
    """Yield ``(block_index, member, is_checksum)`` for every member belonging to ``ref``.

    The members are yielded in their on-disk tar order, which is not assumed to be sorted or to keep a block next
    to its checksum. Membership is matched on the full ``ref/`` path prefix so a reference that is a prefix of
    another (e.g. ``Ref:1`` and ``Ref:10``) never picks up the other disk's members.
    """
    prefix = f"{ref}/"

    for member in xva.tar.getmembers():
        if not member.isfile() or not member.name.startswith(prefix):
            continue

        block_index = int(member.name[len(prefix) :].split("/", 1)[0].split(".", 1)[0])
        yield (block_index, member, _is_checksum_member(member.name))
