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

        self.frame = lru_cache(1024)(self.frame)

        self.header_checksum_valid = self._verify_header_checksum()
        self.valid_frame_count = self._validate_frame_chain()

        self.highest_page_num = max(
            (fr.page_number for commit in self.commits for fr in commit.frames if fr.valid),
            default=0,
        )

    def close(self) -> None:
        """Close the WAL."""
        # Only close WAL handle if we opened it using a path
        if self.path is not None:
            self.fh.close()

    def frame(self, frame_idx: int) -> Frame:
        frame_size = len(c_sqlite3.wal_frame) + self.header.page_size
        offset = len(c_sqlite3.wal_header) + frame_idx * frame_size
        return Frame(self, offset)

    def frames(self) -> Iterator[Frame]:
        frame_idx = 0
        while True:
            try:
                yield self.frame(frame_idx)
                frame_idx += 1
            except EOFError:  # noqa: PERF203
                break

    def _verify_header_checksum(self) -> bool:
        """Verify the checksum of the WAL header.

        The header checksum is calculated over the first 24 bytes of the header.
        If the header checksum is invalid, no frame in the WAL can be trusted.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        self.fh.seek(0)
        buf = self.fh.read(24)
        if len(buf) < 24:
            return False
        return checksum(buf, self.checksum_endian) == (self.header.checksum1, self.header.checksum2)

    def _validate_frame_chain(self) -> int:
        """Validate the cumulative checksum chain of all frames.

        Each frame checksum is calculated over the first 8 bytes of the frame header and the page
        data, seeded with the checksum of the previous frame. A WAL file can contain multiple
        "generations" of frames: every checkpoint restart rewrites the WAL header with new salts
        and starts writing frames from the beginning of the file, but stale frames from older
        generations may still be present later in the file. Each generation has its own
        independent checksum chain, delimited by a change in the frame salt values.

        The chain of the first (current) generation is anchored at the checksum in the WAL
        header, but only if the frame salts match the header salts. The headers of older
        generations have been overwritten, so their chains are anchored at the stored checksum of
        the first frame of the generation; all subsequent frames in the generation are verified
        against the running chain.

        A frame that breaks the chain of its generation invalidates all subsequent frames in that
        generation, regardless of how legitimate they may look. Older generations are independent
        segments and are still validated.

        Returns the number of frames that are part of a valid checksum chain.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        if not self.header_checksum_valid:
            return 0

        valid_count = 0
        s0 = s1 = 0
        salts = None
        verify = False
        broken = False

        for frame in self.frames():
            frame_salts = (frame.header.salt1, frame.header.salt2)
            if frame_salts != salts:
                # A new generation starts here, the checksum chain restarts
                salts = frame_salts
                broken = False
                if frame.offset == len(c_sqlite3.wal_header) and frame_salts == (
                    self.header.salt1,
                    self.header.salt2,
                ):
                    # Current generation, anchor the chain at the WAL header checksum
                    s0, s1 = self.header.checksum1, self.header.checksum2
                    verify = True
                else:
                    # Historical generation, the original WAL header is lost so anchor the
                    # chain at the stored checksum of this frame and verify from the next
                    s0, s1 = frame.header.checksum1, frame.header.checksum2
                    verify = False

            if broken:
                continue

            data = frame.data
            if len(data) != self.header.page_size:
                broken = True
                continue

            if verify:
                buf = struct.pack(">II", frame.header.page_number, frame.header.page_count) + data
                s0, s1 = checksum(buf, self.checksum_endian, s0, s1)
                if (s0, s1) != (frame.header.checksum1, frame.header.checksum2):
                    log.warning(
                        "Encountered invalid WAL frame at offset %d, invalidating the rest of the chain",
                        frame.offset,
                    )
                    broken = True
                    continue
            else:
                # First frame of a historical generation, continue the chain from its checksum
                verify = True

            frame.checksum_valid = True
            valid_count += 1

        return valid_count

    @cached_property
    def commits(self) -> list[Commit]:
        """Return all valid commits in the WAL file.

        Commits are frames where ``header.page_count`` specifies the size of the
        database file in pages after the commit. For all other frames it is 0.

        A commit is only valid if all of its frames are part of a valid checksum
        chain (see :meth:`_validate_frame_chain`). Frames that are not part of a
        valid chain are never considered committed, even if they look like
        legitimate commit frames. Invalid frames can still be enumerated as raw
        evidence through :meth:`frames`.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        commits = []
        frames = []

        for frame in self.frames():
            if not frame.valid:
                # The checksum chain is broken, discard any partially collected transaction
                if frames:
                    log.warning("Discarding %d uncommitted frames before invalid frame", len(frames))
                    frames = []
                continue

            frames.append(frame)

            # A commit record has a page_count header greater than zero
            if frame.page_count > 0:
                commits.append(Commit(self, frames))
                frames = []

        if frames:
            # TODO: Do we want to track these somewhere?
            log.warning("Found leftover %d frames after the last WAL commit", len(frames))

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
    # Whether this frame is part of the valid checksum chain, set by the WAL during validation.
    checksum_valid = False

    def __init__(self, wal: WAL, offset: int):
        self.wal = wal
        self.offset = offset

        self.fh = wal.fh

        self.fh.seek(offset)
        self.header = c_sqlite3.wal_frame(self.fh)

    def __repr__(self) -> str:
        return f"<Frame page_number={self.page_number} page_count={self.page_count}>"

    @property
    def salt_valid(self) -> bool:
        """Whether the frame salts match the current WAL header salts.

        Frames of historical generations (from before a checkpoint restart) have
        different salts, but can still be part of a valid checksum chain.
        """
        return self.header.salt1 == self.wal.header.salt1 and self.header.salt2 == self.wal.header.salt2

    @property
    def valid(self) -> bool:
        """A frame is only valid if it is part of a valid checksum chain.

        Matching salts alone are not sufficient: the frame also has to verify
        against the cumulative checksum chain of its generation.
        """
        return self.checksum_valid

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
