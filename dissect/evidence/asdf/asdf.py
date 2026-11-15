# Acquire Snapshot Data Format

from __future__ import annotations

import gzip
import io
import tarfile
import uuid
from bisect import bisect_right
from collections import defaultdict
from typing import TYPE_CHECKING, BinaryIO

from dissect.util import ts
from dissect.util.stream import AlignedStream, RangeStream

from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.stream import (
    CompressedStream,
    Crc32Stream,
    HashedStream,
    WriteAllStream,
    write_all,
)
from dissect.evidence.exception import (
    InvalidBlock,
    InvalidSnapshot,
    UnsupportedVersion,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SnapshotTableEntry = tuple[int, int, int, int]

VERSION = 1
DEFAULT_BLOCK_SIZE = 4096
MAX_BLOCK_TABLE_SIZE = 2**32

MAX_IDX = 253
IDX_MEMORY = 254
IDX_METADATA = 255
RESERVED_IDX = [IDX_METADATA, IDX_MEMORY]

FILE_MAGIC = b"ASDF"
BLOCK_MAGIC = b"BL\xa5\xdf"
FOOTER_MAGIC = b"FT\xa5\xdf"
SPARSE_BYTES = b"\xa5\xdf"


class AsdfWriter(io.RawIOBase):
    """ASDF file writer.

    Current limitations:
        - Maximum source disk size is ~16EiB
        - Maximum number of disks is 254

    Some things are currently hardcoded (like SHA256), although they may
    become variable in the future.

    Args:
        fh: File-like object to write to.
        guid: Unique identifier. Used to link images to writers.
        compress: Write gzip compressed file.
        block_crc: Flag to store a CRC32 after each block.
    """

    def __init__(
        self,
        fh: BinaryIO,
        guid: uuid.UUID | None = None,
        compress: bool = False,
        block_crc: bool = True,
    ):
        self._fh = fh
        self.fh = self._fh

        if compress:
            self.fh = gzip.GzipFile(fileobj=WriteAllStream(self.fh), mode="wb")

        self.fh = HashedStream(self.fh)
        self.guid = guid or uuid.uuid4()

        # Options
        self.block_crc = block_crc
        self.block_compress = False  # Disabled for now

        self._table = defaultdict(list)
        self._table_lookup = defaultdict(list)
        self._table_offset = 0

        # Once any part of the file failed to be written, the writer is unusable and
        # can never produce a completed snapshot anymore
        self._failure: BaseException | None = None
        self._closed = False

        self._meta_buf = io.BytesIO()
        self._meta_tar = tarfile.open(fileobj=self._meta_buf, mode="w")  # noqa: SIM115

        self._write_header()

    @property
    def failed(self) -> BaseException | None:
        """Return the exception that put this writer in a failed state, if any."""
        return self._failure

    def _set_failure(self, exc: BaseException) -> None:
        """Record the first failure, keeping the original exception for diagnostics."""
        if self._failure is None:
            self._failure = exc

    def _raise_if_unusable(self) -> None:
        """Raise if this writer is closed or in a failed state."""
        if self._failure is not None:
            raise self._failure

        if self._closed:
            raise ValueError("I/O operation on closed ASDF writer")

    def add_metadata_file(self, path: str, fh: BinaryIO, size: int | None = None) -> None:
        """Add a file to the metadata stream.

        Args:
            path: The path in the metadata tar to write to.
            fh: The file-like object to write.
            size: Optional size to write.
        """
        self._raise_if_unusable()

        try:
            info = self._meta_tar.tarinfo()
            info.name = path
            info.uname = "root"
            info.gname = "root"

            if size is None and fh.seekable():
                fh.seek(0, io.SEEK_END)
                size = fh.tell()

            info.size = size or 0

            fh.seek(0)
            self._meta_tar.addfile(info, fh)
        except BaseException as e:
            self._set_failure(e)
            raise

    def add_bytes(self, data: bytes, idx: int = 0, base: int = 0) -> None:
        """Add some bytes into this snapshot.

        Convenience method for adding some bytes at a specific offset.

        Args:
            data: The bytes to copy.
            idx: The stream index.
            base: The base offset.
        """
        self.copy_bytes(io.BytesIO(data), 0, len(data), idx=idx, base=base)

    def copy_bytes(self, source: BinaryIO, offset: int, num_bytes: int, idx: int = 0, base: int = 0) -> None:
        """Copy some bytes from the source file-like object into this snapshot.

        Often the source will be a volume on a disk, which is usually represented
        as a relative stream. If this is the case, use the ``base`` argument to
        indicate what the byte offset of the source is, relative to the start
        of the disk. The ``offset`` argument is always the offset in the
        source, so that is not affected.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset into the source to start copying bytes from.
            num_bytes: The amount of bytes to copy.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        self._raise_if_unusable()

        try:
            self._write_block(source, offset, num_bytes, idx=idx, base=base)
        except BaseException as e:
            self._set_failure(e)
            raise

    def copy_block(
        self,
        source: BinaryIO,
        offset: int,
        num_blocks: int,
        block_size: int | None = None,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy some blocks in the given block size into this snapshot.

        If no block size is given, the ASDF native block size is used.
        This is really just a convenience method that does the block multiplication
        before calling ``copy_bytes``.

        Args:
            source: The source file-like object to copy the blocks from.
            offset: The byte offset into the source to start copying blocks from.
            num_blocks: The amount of blocks to copy.
            block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        block_size = block_size or DEFAULT_BLOCK_SIZE
        return self.copy_bytes(source, offset, num_blocks * block_size, idx, base)

    def copy_runlist(
        self,
        source: BinaryIO,
        runlist: list[tuple[int | None, int]],
        runlist_block_size: int,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy a runlist of blocks in the given block size into this snapshot.

        A runlist must be a list of tuples, where:
            (block_offset, num_blocks)

        This is really just a convenience method that does the runlist iteration
        and block multiplication before calling `copy_bytes`.

        Args:
            source: The source file-like object to copy the blocks from.
            runlist: The runlist that describes the blocks.
            runlist_block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        for run_offset, run_length in runlist:
            # If run_offset is None, it's a sparse run
            if run_offset is None:
                continue

            # Save a function call by directly calling copy_bytes instead of copy_block.
            self.copy_bytes(source, run_offset * runlist_block_size, run_length * runlist_block_size, idx, base)

    def close(self) -> None:
        """Close the ASDF file.

        Writes the metadata, block table and footer, then closes the destination
        file-like object. The footer is only written after all of the preceding
        data was accepted, so a failed write never leaves a file that looks
        complete.

        Closing is idempotent. If any write failed, the writer stays failed and
        a repeated close re-raises the original exception instead of turning
        the snapshot into a successful one.
        """
        if self._closed:
            if self._failure is not None:
                raise self._failure
            return

        self._closed = True
        try:
            if self._failure is not None:
                raise self._failure

            self._write_meta()
            if self._table:
                self._write_table()

            # Make sure all data before the footer is accepted by the destination before
            # declaring the snapshot complete by writing the footer
            self._flush()
            self._write_footer()
            self._flush()

            self.fh.close()
        except BaseException as e:
            self._set_failure(e)
            raise
        finally:
            try:
                # This may flush again, which must never mask the original failure
                super().close()
            except BaseException as e:
                already_failed = self._failure is not None and self._failure is not e
                self._set_failure(e)
                if not already_failed:
                    raise

    def _flush(self) -> None:
        """Flush the destination file-like object, if it supports flushing."""
        if hasattr(self.fh, "flush"):
            self.fh.flush()

    def _write_header(self) -> None:
        """Write the ASDF header to the destination file-like object."""
        header = c_asdf.header(
            magic=FILE_MAGIC,
            flags=c_asdf.FILE_FLAG.SHA256,  # Currently the only option
            version=VERSION,
            timestamp=ts.unix_now(),
            guid=self.guid.bytes_le,
        )
        header.write(self.fh)

    def _write_block(self, source: BinaryIO, offset: int, size: int, idx: int = 0, base: int = 0) -> None:
        """Write an ASDF block to the destination file-like object.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset of the copied block.
            size: The size of the copied block in bytes.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
        absolute_offset = base + offset

        lookup_table = self._table_lookup[idx]
        entry_table = self._table[idx]

        table_idx, absolute_offset, size = _table_fit(
            absolute_offset, size, entry_table, lookup_table, lambda e: (e[2], e[3])
        )

        if table_idx is None:
            return

        offset = absolute_offset - base

        # Setup the block flags and block writer
        flags = 0
        outfh = self.fh
        if self.block_crc:
            outfh = Crc32Stream(outfh)
            flags |= c_asdf.BLOCK_FLAG.CRC32
        if self.block_compress:
            outfh = CompressedStream(outfh)
            flags |= c_asdf.BLOCK_FLAG.COMPRESS

        block_offset = self.fh.tell()  # Block header location
        block = c_asdf.block(
            magic=BLOCK_MAGIC,
            flags=flags,
            idx=idx,
            offset=absolute_offset,
            size=size,
        )
        block.write(self.fh)
        data_offset = self.fh.tell()  # Block data location

        source_stream = RangeStream(source, offset, size)
        copied = 0
        while copied < size:
            buf = source_stream.read(min(io.DEFAULT_BUFFER_SIZE, size - copied))
            if not buf:
                break

            copied += len(buf)
            write_all(outfh, buf)

        # This writes any remaining data or footer for each block writer
        outfh.finalize()

        if copied != size:
            raise InvalidBlock(f"short block data: expected {size} bytes, got {copied}")

        data_size = self.fh.tell() - data_offset

        lookup_table.insert(table_idx, absolute_offset)
        entry_table.insert(table_idx, (flags, idx, absolute_offset, size, block_offset, data_size))

    def _write_meta(self) -> None:
        """Write the metadata tar to the destination file-like object."""
        self._meta_tar.close()

        size = self._meta_buf.tell()
        self._meta_buf.seek(0)
        self._write_block(self._meta_buf, 0, size, idx=IDX_METADATA)

    def _write_table(self) -> None:
        """Write the ASDF block table to the destination file-like object."""
        self._table_offset = self.fh.tell()
        for stream_table in self._table.values():
            for flags, idx, offset, size, file_offset, file_size in stream_table:
                table_entry = c_asdf.table_entry(
                    flags=flags,
                    idx=idx,
                    offset=offset,
                    size=size,
                    file_offset=file_offset,
                    file_size=file_size,
                )
                table_entry.write(self.fh)

    def _write_footer(self) -> None:
        """Write the ASDF footer to the destination file-like object."""
        footer = c_asdf.footer(
            magic=FOOTER_MAGIC,
            table_offset=self._table_offset,
            sha256=self.fh.digest(),
        )
        footer.write(self.fh)


class AsdfSnapshot:
    """ASDF file reader.

    Args:
        fh: File-like object to read the ASDF file from.
    """

    def __init__(self, fh: BinaryIO, recover: bool = False):
        self.fh = fh

        file_size = self.fh.seek(0, io.SEEK_END)
        self.fh.seek(0)

        # A normal read requires the smallest possible complete file (header + footer).
        # Recovery only needs the header, so interrupted files can still be inspected.
        min_size = len(c_asdf.header) if recover else len(c_asdf.header) + len(c_asdf.footer)
        if file_size < min_size:
            raise InvalidSnapshot("file too small")

        try:
            self.header = c_asdf.header(fh)
        except EOFError as e:
            raise InvalidSnapshot("truncated header") from e

        if self.header.magic != FILE_MAGIC:
            raise InvalidSnapshot("invalid header magic")

        if self.header.version > VERSION:
            raise UnsupportedVersion("higher version")

        self.timestamp = ts.from_unix(self.header.timestamp)
        self.guid = uuid.UUID(bytes_le=self.header.guid)

        self.table: dict[list[SnapshotTableEntry]] = defaultdict(list)
        self._table_lookup: dict[list[int]] = defaultdict(list)

        # The footer must be the last thing in the file, so anchor it to the end
        footer_offset = file_size - len(c_asdf.footer)
        if footer_offset < len(c_asdf.header):
            self.footer = None
        else:
            self.fh.seek(footer_offset)
            self.footer = c_asdf.footer(self.fh)

        table_offset = self.footer.table_offset if self.footer is not None else 0
        footer_valid = (
            self.footer is not None
            and self.footer.magic == FOOTER_MAGIC
            and len(c_asdf.header) <= table_offset <= footer_offset
        )
        if not footer_valid:
            # A file without a complete, consistent footer is not a finished snapshot
            if recover:
                self._recover_block_table(file_size)
            else:
                raise InvalidSnapshot("invalid footer")
        else:
            self._parse_block_table(table_offset, (footer_offset - table_offset) // len(c_asdf.table_entry))

        self.metadata = Metadata(self)

    def _parse_block_table(self, offset: int, count: int) -> None:
        """Parse the block table, getting rid of overlapping blocks."""
        self.fh.seek(offset)
        table_data = io.BytesIO(self.fh.read(count * len(c_asdf.table_entry)))
        if len(table_data.getbuffer()) != count * len(c_asdf.table_entry):
            raise InvalidSnapshot("truncated block table")

        for _ in range(count):
            entry = c_asdf.table_entry(table_data)

            # All block data must be present and live before the block table. Anything
            # else means the file was not completely written.
            data_offset = entry.file_offset + len(c_asdf.block)
            if (
                entry.file_offset < len(c_asdf.header)
                or data_offset > offset
                or data_offset + entry.file_size > offset
            ):
                raise InvalidSnapshot("block table entry out of bounds")

            self._table_insert(entry.idx, entry.offset, entry.size, entry.file_offset)

    def _recover_block_table(self, file_size: int | None = None) -> None:
        if file_size is None:
            file_size = self.fh.seek(0, io.SEEK_END)

        self.fh.seek(len(c_asdf.header))
        for block, file_offset in scrape_blocks(self.fh, file_size=file_size):
            self._table_insert(block.idx, block.offset, block.size, file_offset)

    def _table_insert(self, idx: int, offset: int, size: int, file_offset: int) -> None:
        stream_idx = idx
        entry_data_offset = file_offset + len(c_asdf.block)

        lookup_table = self._table_lookup[stream_idx]
        entry_table = self.table[stream_idx]

        table_idx, entry_offset, entry_size = _table_fit(
            offset, size, entry_table, lookup_table, lambda e: (e[0], e[1])
        )

        if table_idx is None:
            return

        entry_data_offset += entry_offset - offset

        lookup_table.insert(table_idx, entry_offset)
        entry_table.insert(
            table_idx,
            (
                entry_offset,
                entry_size,
                file_offset,
                entry_data_offset,
            ),
        )

    def contains(self, idx: int) -> bool:
        """Check whether this file contains the given stream index.

        Args:
            idx: The stream to check.
        """
        return idx in self.table

    def open(self, idx: int) -> AsdfStream:
        """Open a specific stream in the file.

        Args:
            idx: The stream to open.
        """
        if idx not in self.table:
            raise IndexError(f"invalid stream idx: {idx}")
        return AsdfStream(self, idx)

    def streams(self) -> Iterator[AsdfStream]:
        """Iterate over all streams in the file."""
        for i in sorted(self.table.keys()):
            yield self.open(i)

    def disks(self) -> Iterator[AsdfStream]:
        """Iterate over all non-reserved streams in the file."""
        for i in sorted(self.table.keys()):
            if i in RESERVED_IDX:
                continue
            yield self.open(i)


class Metadata:
    """ASDF metadata reader.

    Thin wrapper around ``tarfile``.

    Args:
        asdf: The :class:`AsdfSnapshot` to open the metadata of.
    """

    def __init__(self, asdf: AsdfSnapshot):
        self.tar = None
        if IDX_METADATA in asdf.table:
            self.tar = tarfile.open(fileobj=asdf.open(IDX_METADATA), mode="r")  # noqa: SIM115

    def names(self) -> list[str]:
        """Return all metadata file entries."""
        return self.tar.getnames() if self.tar else []

    def members(self) -> list[tarfile.TarInfo]:
        """Return all metadata :class:`tarfile.TarInfo` entries."""
        return self.tar.getmembers() if self.tar else []

    def open(self, path: str) -> BinaryIO:
        """Open a metadata entry and return a binary file-like object."""
        if self.tar:
            return self.tar.extractfile(path)
        raise KeyError(f"filename '{path}' not found")


class AsdfStream(AlignedStream):
    """ASDF stream from a snapshot.

    Args:
        asdf: :class:`AsdfSnapshot` parent object.
        idx: Stream index in the :class:`AsdfSnapshot`.
    """

    def __init__(self, asdf: AsdfSnapshot, idx: int):
        self.fh = asdf.fh
        self.asdf = asdf
        self.idx = idx
        self.table = asdf.table[idx]
        self._table_lookup = asdf._table_lookup[idx]

        # We don't actually know the size of the source disk
        # Doesn't really matter though, just take the last run offset + size
        size = self.table[-1][0] + self.table[-1][1]
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        size = self.size
        run_idx = bisect_right(self._table_lookup, offset) - 1
        runlist_len = len(self.table)

        while length > 0 and run_idx < runlist_len:
            run_start, run_size, run_file_offset, run_data_offset = self.table[run_idx]
            run_end = run_start + run_size

            if run_idx + 1 < runlist_len:
                next_run_start, _, _, _ = self.table[run_idx + 1]
            else:
                next_run_start = None

            if run_idx < 0:
                # Missing first block
                if next_run_start is None:
                    break

                sparse_remaining = next_run_start - offset

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif run_end <= offset:
                # Start outside of run bounds
                if next_run_start is None:
                    # No next run to sparse read to
                    break

                sparse_size = next_run_start - run_end
                sparse_pos = offset - run_end
                sparse_remaining = sparse_size - sparse_pos

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif offset < run_start:
                # Previous run consumed, and next run is far away
                sparse_remaining = run_start - offset
                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Don't proceed to next run, next loop iteration we'll be within the current run
            else:
                # We're in a run with data
                run_pos = offset - run_start
                run_remaining = run_size - run_pos
                read_count = min(size - offset, min(run_remaining, length))

                self.fh.seek(run_file_offset)
                if self.fh.read(4) != BLOCK_MAGIC:
                    raise InvalidBlock("invalid block magic")

                # Skip over block header
                self.fh.seek(run_data_offset + run_pos)
                result.append(self.fh.read(read_count))

                # Proceed to next run
                run_idx += 1

            offset += read_count
            length -= read_count

        return b"".join(result)


def scrape_blocks(
    fh: BinaryIO, buffer_size: int = io.DEFAULT_BUFFER_SIZE, file_size: int | None = None
) -> Iterator[c_asdf.block, int]:
    """Scrape for block headers in ``fh`` and yield parsed block headers and their offset.

    Only complete blocks are yielded: the block header and all of its data must fit
    within ``file_size``. This prevents a truncated tail from being recovered as if
    it were a complete block.

    Args:
        fh: The file-like object to scrape for block headers.
        buffer_size: The buffer size to use when scraping.
        file_size: The size of the file. Determined from ``fh`` if not given.
    """
    if file_size is None:
        pos = fh.tell()
        fh.seek(0, io.SEEK_END)
        file_size = fh.tell()
        fh.seek(pos)

    # If BLOCK_MAGIC is not found in the buffer (4 bytes), it's possible that part of it (up to 3 bytes) is in there
    # Keep an overlap buffer of 3 bytes that we prepend to the current buffer so we can also find these partial needles
    overlap_len = len(BLOCK_MAGIC) - 1
    overlap = b"\x00" * overlap_len
    while True:
        pos = fh.tell()
        # Never read beyond the known file size, so a buffer can't include data that isn't there
        buf = fh.read(min(buffer_size, max(0, file_size - pos)))
        if not buf:
            break

        data = overlap + buf
        needle_pos = -1
        while True:
            needle_pos = data.find(BLOCK_MAGIC, needle_pos + 1)
            if needle_pos == -1:
                break

            offset = pos + needle_pos - overlap_len
            if offset < 0 or offset + len(c_asdf.block) > file_size:
                continue

            fh.seek(offset)
            block_buf = fh.read(len(c_asdf.block))

            # Some sanity checks that this is actually a block header
            if len(block_buf) != len(c_asdf.block):
                continue

            if block_buf[4] not in c_asdf.BLOCK_FLAG:
                continue

            if block_buf[6:8] != b"\x00\x00":
                continue

            block_entry = c_asdf.block(block_buf)

            # Only yield blocks whose data is fully present in the file
            if offset + len(c_asdf.block) + block_entry.size > file_size:
                continue

            yield block_entry, offset

        # Keep the last 3 bytes as overlap
        overlap = data[-overlap_len:]
        # Consumer may seek the fh, so seek it back to where we were
        fh.seek(pos + len(buf))


def _table_fit(
    entry_offset: int, entry_size: int, entry_table: list, lookup_table: list, getentry: Callable
) -> tuple[int, int, int]:
    """Calculate where to insert an entry with the given offset and size into the entry table.

    Moves or shrinks the entry to prevent block overlap, and remove any overlapping blocks.

    Args:
        entry_offset: The entry offset to calculate the insert for.
        entry_size: The entry size to calculate the insert for.
        entry_table: The entry table to insert into or remove entries from.
        lookup_table: The lookup table for the entry_table.
        getentry: A callable to return the ``(offset, size)`` tuple from an entry.

    Returns:
        A tuple of the table index to insert into, an adjusted entry offset and an adjusted entry size.
    """
    entry_end = entry_offset + entry_size

    prev_end = None
    next_start = None
    next_end = None

    table_idx = bisect_right(lookup_table, entry_offset)
    if table_idx > 0:
        prev_start, prev_size = getentry(entry_table[table_idx - 1])
        prev_end = prev_start + prev_size
    if table_idx < len(lookup_table):
        next_start, next_size = getentry(entry_table[table_idx])
        next_end = next_start + next_size

    if prev_end and prev_end >= entry_end:
        # This block is fully contained in the previous block
        return None, None, None

    if prev_end and prev_end > entry_offset:
        # The start of this block overlaps with the previous, so shrink this block
        entry_offset = prev_end

    # We may completely overlap one or more next entries
    while next_end and next_end <= entry_end:
        lookup_table.pop(table_idx)
        entry_table.pop(table_idx)

        if table_idx < len(lookup_table):
            next_start, next_size = getentry(entry_table[table_idx])
            next_end = next_start + next_size
        else:
            next_start, next_end = None, None

    if next_start and next_start < entry_end < next_end:
        # The next block overlaps with this block, so shrink this block
        entry_end = next_start

    if entry_offset >= entry_end:
        # Shouldn't be possible to go beyond the end, but we may end up with a 0 sized block
        return None, None, None

    return table_idx, entry_offset, entry_end - entry_offset
