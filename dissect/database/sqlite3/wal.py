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


class PageSource:
    """Describes where the data for a page came from.

    A page can either be read from the main database file or from a specific
    frame in the WAL file. For WAL frames the commit that contains the frame is
    also recorded, making it possible to explain which historical version of a
    page was used for a particular view.

    Args:
        page_number: The page number this source describes.
        frame: The WAL frame the page was read from, or ``None`` for the main database file.
        collection: The commit or checkpoint that contains ``frame``.
    """

    __slots__ = ("page_number", "frame", "collection")

    def __init__(
        self,
        page_number: int,
        frame: Frame | None = None,
        collection: _FrameCollection | None = None,
    ):
        self.page_number = page_number
        self.frame = frame
        self.collection = collection

    def __repr__(self) -> str:
        if self.frame is None:
            return f"<PageSource page={self.page_number} source=database>"
        return f"<PageSource page={self.page_number} source=wal frame={self.frame.index}>"

    @property
    def source(self) -> str:
        """The source of the page, either ``database`` or ``wal``."""
        return "database" if self.frame is None else "wal"

    @property
    def from_database(self) -> bool:
        """Whether the page was read from the main database file."""
        return self.frame is None

    @property
    def from_wal(self) -> bool:
        """Whether the page was read from a WAL frame."""
        return self.frame is not None

    @property
    def commit(self) -> Commit | None:
        """The commit that contains the frame, if the page came from a commit."""
        return self.collection if isinstance(self.collection, Commit) else None

    @property
    def frame_index(self) -> int | None:
        """The index of the frame in the WAL file, if the page came from the WAL."""
        return self.frame.index if self.frame is not None else None


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
        self.highest_page_num = max(fr.page_number for commit in self.commits for fr in commit.frames if fr.valid)

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
    def commits(self) -> list[Commit]:
        """Return all commits in the WAL file.

        Commits are frames where ``header.page_count`` specifies the size of the
        database file in pages after the commit. For all other frames it is 0.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        commits = []
        frames = []

        for frame in self.frames():
            frames.append(frame)

            # A commit record has a page_count header greater than zero
            if frame.page_count > 0:
                commits.append(Commit(self, frames, len(commits)))
                frames = []

        if frames:
            # TODO: Do we want to track these somewhere?
            log.warning("Found leftover %d frames after the last WAL commit", len(frames))

        return commits

    @cached_property
    def valid_commits(self) -> list[Commit]:
        """Return the commits that can be used to build a database view.

        The WAL is append-only, and frames from previous WAL generations can
        still be present after the current generation. Those frames have a
        different salt than the WAL header and are not part of the current
        history, so their commits are skipped.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
            - https://sqlite.org/wal.html#reader_algorithm
        """
        return [commit for commit in self.commits if commit.valid]

    def commit_history(self, commit: Commit | int) -> dict[int, Frame]:
        """Return the visible page map for the given commit.

        The returned mapping contains the most recent frame for every page that
        is part of the database at the time of ``commit``. Only commits from the
        same WAL generation (identified by the ``salt1`` value of the frames)
        are accumulated, so older generations that are still present in the WAL
        file can not leak into this view. Frames from commits after ``commit``
        are never included. Pages that were written before a commit that shrunk
        the database are removed from the history, even if the database grows
        again later.

        Args:
            commit: A :class:`Commit` object or an index into :attr:`commits`.

        Raises:
            IndexError: If ``commit`` is an integer that is out of range.
            ValueError: If ``commit`` does not belong to this WAL or is not part of a valid generation.
        """
        if isinstance(commit, int):
            if commit < 0 or commit >= len(self.commits):
                raise IndexError("WAL commit index out of range")
            commit = self.commits[commit]

        if commit.wal is not self:
            raise ValueError("Commit does not belong to this WAL")
        if not commit.valid:
            raise ValueError("Commit is not part of the current WAL generation")

        generation = commit.frames[0].header.salt1
        history: dict[int, Frame] = {}

        for current in self.commits:
            if current.frames[0].header.salt1 != generation:
                # Only accumulate commits from the same WAL generation.
                if history:
                    break
                continue

            for frame in current.frames:
                history[frame.page_number] = frame

            # A commit can shrink the database. Pages above the new page count
            # no longer exist in this version of the database.
            for page_number in [page_number for page_number in history if page_number > current.page_count]:
                del history[page_number]

            if current is commit:
                return history

        raise ValueError("Commit is not part of the WAL history")

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
    def __init__(self, wal: WAL, offset: int, index: int | None = None):
        self.wal = wal
        self.offset = offset
        self.index = index
        self.commit: Commit | None = None

        self.fh = wal.fh

        self.fh.seek(offset)
        self.header = c_sqlite3.wal_frame(self.fh)

    def __repr__(self) -> str:
        return f"<Frame page_number={self.page_number} page_count={self.page_count}>"

    @property
    def valid(self) -> bool:
        salt1_match = self.header.salt1 == self.wal.header.salt1
        salt2_match = self.header.salt2 == self.wal.header.salt2

        return salt1_match and salt2_match

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

    def __init__(self, wal: WAL, frames: list[Frame], index: int | None = None):
        self.wal = wal
        self.frames = frames
        self.index = index

        for frame in frames:
            if isinstance(self, Commit):
                frame.commit = self

    def __contains__(self, page: int) -> bool:
        return page in self.page_map

    def __getitem__(self, page: int) -> Frame:
        return self.page_map[page]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} frames={len(self.frames)}>"

    @cached_property
    def page_map(self) -> dict[int, Frame]:
        return {frame.page_number: frame for frame in self.frames}

    @cached_property
    def valid(self) -> bool:
        """Whether all frames in this collection belong to the current WAL."""
        return bool(self.frames) and all(frame.valid for frame in self.frames)

    @property
    def page_count(self) -> int:
        """The size of the database in pages after this collection."""
        return self.frames[-1].page_count if self.frames else 0

    @property
    def db_size(self) -> int:
        """Alias of :attr:`page_count`, matching the SQLite WAL frame header naming."""
        return self.page_count

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


def checksum(buf: bytes, endian: str = ">") -> tuple[int, int]:
    s0 = s1 = 0
    num_ints = len(buf) // 4
    arr = struct.unpack(f"{endian}{num_ints}I", buf)

    for int_num in range(0, num_ints, 2):
        s0 = (s0 + (arr[int_num] + s1)) & 0xFFFFFFFF
        s1 = (s1 + (arr[int_num + 1] + s0)) & 0xFFFFFFFF

    return s0, s1
