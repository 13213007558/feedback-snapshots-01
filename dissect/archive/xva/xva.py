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

        # Block file names follow the block number, but the tar member order is not guaranteed to match it.
        # Collect the members by their actual block number first, then build the offset lookup in order.
        index = -1
        offset = 0
        self._lookup = []
        self._members = []
        for block_index, block_member, checksum_member in _iter_block_files(xva, ref):
            if block_index > index + 1:
                skipped = block_index - (index + 1)
                offset += skipped * BLOCK_SIZE

            if block_member.size != 0:
                self._lookup.append(offset)
                self._members.append((block_member, checksum_member))

                offset += block_member.size

            index = block_index

        super().__init__(size, align=BLOCK_SIZE)

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        end = min(offset + length, self.size)
        position = offset

        while position < end:
            # Find the block that contains (or precedes) the current position. Blocks are sorted by their
            # logical offset, so a negative index means we're still in a leading hole.
            block_idx = bisect_right(self._lookup, position) - 1

            if block_idx < 0:
                next_offset = self._lookup[0] if self._lookup else end
                hole_end = min(next_offset, end)
                result.append(b"\x00" * (hole_end - position))
                position = hole_end
                continue

            block_member, checksum_member = self._members[block_idx]
            block_offset = self._lookup[block_idx]
            block_end = block_offset + block_member.size

            if position >= block_end:
                # We're in a hole after this block. Skip to the next block, or to the end of the read.
                next_offset = self._lookup[block_idx + 1] if block_idx + 1 < len(self._lookup) else end
                hole_end = min(next_offset, end)
                result.append(b"\x00" * (hole_end - position))
                position = hole_end
                continue

            read_end = min(block_end, end)
            buf = self.xva.tar.extractfile(block_member).read()

            if self.verify:
                self._verify(block_member, checksum_member, buf)

            result.append(buf[position - block_offset : read_end - block_offset])
            position = read_end

        return b"".join(result)

    def _verify(self, block_member: tarfile.TarInfo, checksum_member: tarfile.TarInfo | None, buf: bytes) -> None:
        if checksum_member is None:
            raise ValueError(f"No checksum for {block_member.name}")

        suffix = checksum_member.name.rsplit(".", 1)[-1]
        if suffix in ("checksum", "sha1"):
            try:
                expected = self.xva.tar.extractfile(checksum_member).read().decode().strip().lower()
            except UnicodeDecodeError:
                raise ValueError(f"Invalid checksum for {checksum_member.name}") from None

            if hashlib.sha1(buf).hexdigest() != expected:
                raise ValueError(f"Invalid checksum for {checksum_member.name}")
            return

        raise UnsupportedChecksumError(f"Unsupported checksum: {checksum_member.name}")


def _iter_block_files(xva: XVA, ref: str) -> Iterator[tuple[int, tarfile.TarInfo, tarfile.TarInfo | None]]:
    """Yield block members and their checksum member, sorted by the actual block number.

    A checksum member does not have to be adjacent to its block member (or even come after it) in the tar
    file, and the tar member order is not necessarily the logical block order. Group the members by block
    number and member identity instead, so each disk only reads members below its own ``ref/`` prefix.

    Duplicate members are resolved by tar order: the last occurrence wins. If a block has more than one
    checksum member, a supported algorithm is preferred over an unsupported one.
    """
    prefix = ref if ref.endswith("/") else f"{ref}/"
    blocks: dict[int, tarfile.TarInfo] = {}
    checksums: dict[int, dict[str, tarfile.TarInfo]] = {}

    for member in xva.tar.getmembers():
        # Check the trailing slash so a ref that is a prefix of another ref (``Ref:1`` vs ``Ref:10``)
        # can never read the other disk's members.
        if not member.isfile() or not member.name.startswith(prefix):
            continue

        name = member.name[len(prefix) :]
        if "/" in name:
            continue

        block, _, suffix = name.partition(".")
        try:
            index = int(block)
        except ValueError:
            continue

        if suffix in ("checksum", "sha1", "xxhash"):
            checksums.setdefault(index, {})[suffix] = member
        elif not suffix:
            blocks[index] = member

    for index in sorted(blocks):
        block_checksums = checksums.get(index, {})
        supported = next(
            (block_checksums[suffix] for suffix in ("checksum", "sha1") if suffix in block_checksums),
            None,
        )
        yield index, blocks[index], supported or next(iter(block_checksums.values()), None)
