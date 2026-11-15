from __future__ import annotations

import logging
import os
import struct
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import InvalidDatabase

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_SQLITE3", "CRITICAL"))

# See https://sqlite.org/fileformat2.html#wal_file_format
WAL_HEADER_MAGIC_LE = 0x377F0682
WAL_HEADER_MAGIC_BE = 0x377F0683
WAL_HEADER_MAGIC = {WAL_HEADER_MAGIC_LE, WAL_HEADER_MAGIC_BE}


class WAL:
    def __init__(self, fh: Path | BinaryIO):
        # Use the provided WAL file handle or try to open a sidecar WAL file.
        if isinstance(fh, Path):
            path = fh
            fh = path.open("rb")
        else:
            path = None

        self.fh = fh
        self.path = path
        self.header = c_sqlite3.wal_header(fh)

        if self.header.magic not in WAL_HEADER_MAGIC:
            raise InvalidDatabase("Invalid WAL header magic")

        self.checksum_endian = "<" if self.header.magic == WAL_HEADER_MAGIC_LE else ">"

        # The highest page number committed by the newest, absolutely verified
        # generation. This is what sizes the normal database view.
        self.highest_page_num = 0
        if self.header_checksum_valid:
            self.highest_page_num = max(
                (
                    fr.page_number
                    for commit in self.commits
                    for fr in commit.frames
                    if (fr.header.salt1, fr.header.salt2) == (self.header.salt1, self.header.salt2)
                ),
                default=0,
            )

        self.frame = lru_cache(1024)(self.frame)

    def close(self) -> None:
        """Close the WAL."""
        # Only close WAL handle if we opened it using a path
        if self.path is not None:
            self.fh.close()

    def frame(self, frame_idx: int) -> Frame:
        frame_size = len(c_sqlite3.wal_frame) + self.header.page_size
        offset = len(c_sqlite3.wal_header) + frame_idx * frame_size
        return Frame(self, offset, frame_idx)

    def frames(self) -> Iterator[Frame]:
        frame_idx = 0
        while True:
            try:
                yield self.frame(frame_idx)
                frame_idx += 1
            except EOFError:  # noqa: PERF203
                break

    @cached_property
    def header_checksum_valid(self) -> bool:
        """Return whether the checksum of the WAL header is valid.

        The checksum is calculated over the first 24 bytes of the WAL header,
        using the endianness indicated by the header magic.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        self.fh.seek(0)
        buf = self.fh.read(len(c_sqlite3.wal_header))
        if len(buf) < len(c_sqlite3.wal_header):
            return False

        s0, s1 = checksum(buf[:24], self.checksum_endian)
        return (s0, s1) == (self.header.checksum1, self.header.checksum2)

    @cached_property
    def frame_validity(self) -> list[bool]:
        """Return the validity of every frame, indexed by frame index.

        Frames are validated generation by generation. A generation is a run of
        consecutive frames with equal salts; a checkpoint resets the WAL and starts
        a new generation with its own checksum chain.

        For the newest generation (salts matching the WAL header) the cumulative
        checksum chain is seeded with the WAL header checksum, provided the header
        checksum itself is valid. For older generations the historical WAL header
        is lost, so the first surviving frame of the generation can only be checked
        by salt and serves as the trust anchor for the relative checksum chain of
        the remaining frames of that generation.

        Once the chain of a generation breaks, that frame and all following frames
        of that generation are invalid, even if they look like valid commit records.
        Such frames can still be enumerated as raw evidence using :meth:`frames`.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        frames = list(self.frames())
        validity = [False] * len(frames)

        header_salts = (self.header.salt1, self.header.salt2)
        if not self.header_checksum_valid:
            log.warning("WAL header checksum mismatch, cannot absolutely verify the newest generation")

        salts = None
        absolute = False
        chain_valid = True
        first = True
        s0 = s1 = 0

        for frame in frames:
            frame_salts = (frame.header.salt1, frame.header.salt2)
            if frame_salts != salts:
                # A checkpoint reset the WAL, starting a new generation with its own chain
                salts = frame_salts
                chain_valid = True
                first = True
                absolute = salts == header_salts and self.header_checksum_valid
                if absolute:
                    s0, s1 = self.header.checksum1, self.header.checksum2

            if not chain_valid:
                continue

            if first and not absolute:
                # The historical WAL header of this generation is lost, so the first
                # surviving frame can only be checked by salt. Use its stored checksum
                # as the trust anchor for the relative chain of this generation.
                s0, s1 = frame.header.checksum1, frame.header.checksum2
                validity[frame.index] = True
                first = False
                continue

            first = False

            # The cumulative checksum is calculated over the first 8 bytes of the
            # frame header followed by the page data.
            self.fh.seek(frame.offset)
            header_buf = self.fh.read(8)
            self.fh.seek(frame.offset + len(c_sqlite3.wal_frame))
            page_buf = self.fh.read(self.header.page_size)
            s0, s1 = checksum(header_buf + page_buf, self.checksum_endian, s0, s1)

            if (s0, s1) != (frame.header.checksum1, frame.header.checksum2):
                log.warning(
                    "Frame %d checksum (%#x, %#x) does not match calculated checksum (%#x, %#x)",
                    frame.index,
                    frame.header.checksum1,
                    frame.header.checksum2,
                    s0,
                    s1,
                )
                chain_valid = False
                continue

            validity[frame.index] = True

        return validity

    @cached_property
    def valid_frame_count(self) -> int:
        """Return the number of leading frames of the newest WAL generation that
        form an unbroken valid chain (see :attr:`frame_validity`).
        """
        count = 0
        for valid in self.frame_validity:
            if not valid:
                break
            count += 1
        return count

    @cached_property
    def commits(self) -> list[Commit]:
        """Return all valid commits in the WAL file.

        Commits are frames where ``header.page_count`` specifies the size of the
        database file in pages after the commit. For all other frames it is 0.

        Only frames that are part of an unbroken valid checksum chain of their
        generation are considered (see :attr:`frame_validity`). Frames after the
        chain breaks -- including frames that look like commit records -- are not
        committed data and are excluded from the normal database view. They can
        still be enumerated as raw evidence using :meth:`frames`.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        commits = []
        frames = []
        salts = None

        for frame in self.frames():
            frame_salts = (frame.header.salt1, frame.header.salt2)
            if frame_salts != salts:
                # A checkpoint reset the WAL, discard any uncommitted frames of
                # the previous generation
                if frames:
                    log.warning("Discarding %d uncommitted frames at WAL generation boundary", len(frames))
                    frames = []
                salts = frame_salts

            if not frame.valid:
                if frames:
                    log.warning("Discarding %d uncommitted frames before invalid frame %d", len(frames), frame.index)
                    frames = []
                continue

            frames.append(frame)

            # A commit record has a page_count header greater than zero
            if frame.page_count > 0:
                commits.append(Commit(self, frames))
                frames = []

        if frames:
            log.warning("Found %d leftover frames after the last WAL commit", len(frames))

        return commits

    @cached_property
    def checkpoints(self) -> list[Checkpoint]:
        """Return deduplicated checkpoints, oldest first.

        Deduplicate commits by the ``salt1`` value of their first frame. Later
        commits overwrite earlier ones so the returned list contains the most
        recent commit for each ``salt1``, sorted ascending.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
            - https://sqlite.org/wal.html#checkpointing
        """
        checkpoints_map: dict[int, Checkpoint] = {}
        for commit in self.commits:
            if not commit.frames:
                continue
            salt1 = commit.frames[0].header.salt1
            # Keep the most recent commit for each salt1 (later commits overwrite).
            checkpoints_map[salt1] = commit

        return [checkpoints_map[salt] for salt in sorted(checkpoints_map.keys())]


class Frame:
    def __init__(self, wal: WAL, offset: int, index: int):
        self.wal = wal
        self.offset = offset
        self.index = index

        self.fh = wal.fh

        self.fh.seek(offset)
        self.header = c_sqlite3.wal_frame(self.fh)

    def __repr__(self) -> str:
        return f"<Frame page_number={self.page_number} page_count={self.page_count}>"

    @property
    def valid(self) -> bool:
        """Return whether this frame is part of the unbroken valid checksum chain
        of its generation.

        Matching salts alone are not sufficient: the cumulative checksum chain of
        the generation must be unbroken up to and including this frame (see
        :attr:`WAL.frame_validity`).
        """
        validity = self.wal.frame_validity
        return self.index < len(validity) and validity[self.index]

    @property
    def data(self) -> bytes:
        self.fh.seek(self.offset + len(c_sqlite3.wal_frame))
        return self.fh.read(self.wal.header.page_size)

    @property
    def page_number(self) -> int:
        return self.header.page_number

    @property
    def page_count(self) -> int:
        return self.header.page_count


class _FrameCollection:
    """Convenience class to keep track of a collection of frames that were committed together."""

    def __init__(self, wal: WAL, frames: list[Frame]):
        self.wal = wal
        self.frames = frames

    def __contains__(self, page: int) -> bool:
        return page in self.page_map

    def __getitem__(self, page: int) -> Frame:
        return self.page_map[page]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} frames={len(self.frames)}>"

    @cached_property
    def page_map(self) -> dict[int, Frame]:
        return {frame.page_number: frame for frame in self.frames}

    def get(self, page: int, default: Any = None) -> Frame:
        return self.page_map.get(page, default)


class Checkpoint(_FrameCollection):
    """A checkpoint is an operation that transfers all committed transactions from
    the WAL file back into the main database file.

    References:
        - https://sqlite.org/fileformat2.html#wal_file_format
    """


class Commit(_FrameCollection):
    """A commit is a collection of frames that were committed together.

    References:
        - https://sqlite.org/fileformat2.html#wal_file_format
    """


def checksum(buf: bytes, endian: str = ">", s0: int = 0, s1: int = 0) -> tuple[int, int]:
    num_ints = len(buf) // 4
    arr = struct.unpack(f"{endian}{num_ints}I", buf)

    for int_num in range(0, num_ints, 2):
        s0 = (s0 + (arr[int_num] + s1)) & 0xFFFFFFFF
        s1 = (s1 + (arr[int_num + 1] + s0)) & 0xFFFFFFFF

    return s0, s1
