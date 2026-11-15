from __future__ import annotations

import itertools
import re
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import (
    InvalidCommit,
    InvalidDatabase,
    InvalidPageNumber,
    InvalidPageType,
    NoCellData,
    NoWriteAheadLog,
)
from dissect.database.sqlite3.util import parse_table_columns_constraints
from dissect.database.sqlite3.wal import WAL

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from typing_extensions import Self

    from dissect.database.sqlite3.wal import Checkpoint, Commit, Frame

ENCODING = {
    1: "utf-8",
    2: "utf-16-le",
    3: "utf-16-be",
}

PAGE_TYPES = {
    c_sqlite3.PAGE_TYPE_INTERIOR_INDEX: "PAGE_TYPE_INTERIOR_INDEX",
    c_sqlite3.PAGE_TYPE_INTERIOR_TABLE: "PAGE_TYPE_INTERIOR_TABLE",
    c_sqlite3.PAGE_TYPE_LEAF_INDEX: "PAGE_TYPE_LEAF_INDEX",
    c_sqlite3.PAGE_TYPE_LEAF_TABLE: "PAGE_TYPE_LEAF_TABLE",
}

# See https://www.sqlite.org/fileformat.html -- Record format
SERIAL_TYPES = {
    0: lambda fh: None,
    1: c_sqlite3.int8,
    2: c_sqlite3.int16,
    3: c_sqlite3.int24,
    4: c_sqlite3.int32,
    5: c_sqlite3.int48,
    6: c_sqlite3.int64,
    7: c_sqlite3.double,
    8: lambda fh: 0,
    9: lambda fh: 1,
}

# See https://sqlite.org/fileformat2.html#magic_header_string
SQLITE3_HEADER_MAGIC = b"SQLite format 3\x00"


class SQLite3:
    """SQLite3 database class.

    Loads a SQLite3 database from the given file-like object or path. If a path is provided (or can be deduced
    from the file-like object), a WAL file will be automatically looked for with a few common suffixes.
    Optionally a WAL file-like object or path can be directly provided to read changes from the WAL (this takes
    priority over the aforementioned WAL lookup). Additionally, a specific checkpoint from the WAL can be applied.

    A read-only view of the database as it was after a specific WAL commit can be created with ``commit``.
    Such a view resolves every page to the newest version that was visible at that commit: frames from the
    target commit and all commits before it are applied in order, pages that were not changed by any of those
    commits are read from the database file, and pages beyond the page count of the target commit are not
    part of the view. Use :meth:`commit_views` to iterate over all available commit views.

    A commit view starts from the assumption that the database file represents the state at the start of the
    WAL generation that the target commit belongs to. This is the case for a WAL that accumulated all commits
    since the last checkpoint. If a checkpoint has written later commits back into the database file while the
    WAL kept appending, pages that no visible commit changed cannot be proven to be the historical version.

    Args:
        fh: The path or file-like object to open a SQLite3 database on.
        wal: The path or file-like object to open a SQLite3 WAL file on.
        checkpoint: The checkpoint to apply from the WAL file. Can be a :class:`Checkpoint` object or an integer index.
        commit: The commit to create a view for. Can be a :class:`Commit` object or an integer index.

    Raises:
        ~dissect.database.sqlite3.exception.InvalidDatabase: If the file-like object does not look like a SQLite3
            database based on the header magic.
        ~dissect.database.sqlite3.exception.NoWriteAheadLog: If a commit view is requested without a WAL.
        ~dissect.database.sqlite3.exception.InvalidCommit: If the requested commit is not usable.

    References:
        - https://sqlite.org/fileformat2.html
    """

    def __init__(
        self,
        fh: Path | BinaryIO,
        wal: WAL | Path | BinaryIO | None = None,
        checkpoint: Checkpoint | int | None = None,
        commit: Commit | int | None = None,
    ):
        if isinstance(fh, Path):
            path = fh
            fh = path.open("rb")
        else:
            path = None

        self.fh = fh
        self.path = path
        self.wal = None
        self.checkpoint = None
        self.commit = None
        self._commit_pages: dict[int, tuple[Frame, int]] = {}
        self._shared = False

        # Always start at the beginning of the file, also when a shared file handle is passed in.
        self.fh.seek(0)
        self.header = c_sqlite3.header(self.fh)
        if self.header.magic != SQLITE3_HEADER_MAGIC:
            raise InvalidDatabase("Invalid header magic")

        self.encoding = ENCODING.get(self.header.text_encoding, "utf-8")
        self.page_size = self.header.page_size
        if self.page_size == 1:
            self.page_size = 65536

        self.usable_page_size = self.page_size - self.header.reserved_size
        if self.usable_page_size < 480:
            raise InvalidDatabase("Usable page size is too small")

        if wal:
            self.wal = wal if isinstance(wal, WAL) else WAL(wal)
        else:
            # Check for WAL sidecar next to the DB.
            # If we have a path, we can deduce the WAL path.
            # If we don't have a path, we can try to get it from the file handle.
            if path is None:
                # By deducing the path at this point and not earlier, we can keep the original passed
                # path to indicate if we should close the file handle later on.
                name = getattr(fh, "name", None)
                path = Path(name) if name else None

            if path is not None:
                wal_path = path.with_name(f"{path.name}-wal")
                if wal_path.exists() and wal_path.stat().st_size > 0:
                    self.wal = WAL(wal_path)

        # If a checkpoint index was provided, resolve it to a Checkpoint object.
        if self.wal and isinstance(checkpoint, int):
            if checkpoint < 0 or checkpoint >= len(self.wal.checkpoints):
                raise IndexError("WAL checkpoint index out of range")
            self.checkpoint = self.wal.checkpoints[checkpoint]
        else:
            self.checkpoint = checkpoint

        if checkpoint is not None and commit is not None:
            raise ValueError("Cannot combine a checkpoint and a commit in one view")

        # If a commit was provided, resolve it and collect the page versions that were visible at that commit.
        if commit is not None:
            if not self.wal:
                raise NoWriteAheadLog("A WAL file is required to create a commit view")

            if isinstance(commit, int):
                if commit < 0 or commit >= len(self.wal.valid_commits):
                    raise IndexError("WAL commit index out of range")
                commit = self.wal.valid_commits[commit]

            if commit.wal is not self.wal:
                raise ValueError("Commit does not belong to the provided WAL")

            if commit.index < 0:
                raise InvalidCommit("Commit has no valid index")

            if not commit.valid:
                raise InvalidCommit("Commit contains frames from a different WAL generation")

            # Commits are only additive within one WAL generation. A newer generation replaces the database
            # file contents rather than extending an older generation, so a view can only be built from the
            # frames of the target commit's own generation. Older generations in the WAL were superseded by a
            # checkpoint and are not reconstructable from the current database file.
            self.commit = commit
            for current in self.wal.valid_commits[: commit.index + 1]:
                for frame in current.frames:
                    self._commit_pages[frame.page_number] = (frame, current.index)

            # A commit that shrinks the database removes all pages beyond its page count from this view.
            self.page_count = commit.page_count
        else:
            # Determine the highest page count we have encountered while parsing the SQLite3 header and optionally WAL.
            self.page_count = (
                max(self.header.page_count, self.wal.highest_page_num) if self.wal else self.header.page_count
            )

        self.page = lru_cache(256)(self.page)

    def __repr__(self) -> str:
        return f"<SQLite3 path={self.path} fh={self.fh} wal={self.wal} checkpoint={bool(self.checkpoint)} pages={self.page_count}>"  # noqa: E501

    def __enter__(self) -> Self:
        """Return ``self`` upon entering the runtime context."""
        return self

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self.close()
        return False

    def _share(self, view: SQLite3) -> SQLite3:
        """Mark a view as sharing this database's file handles, so it does not close them."""
        view._shared = True
        return view

    def close(self) -> None:
        """Close the database and WAL."""
        # Only close DB handle if we opened it using a path, and not when this is a view sharing a parent's handles.
        if self.path is not None and not self._shared:
            self.fh.close()

        if self.wal is not None and not self._shared:
            self.wal.close()

    def checkpoints(self) -> Iterator[SQLite3]:
        """Yield instances of the database at all available checkpoints in the WAL file, if applicable."""
        if not self.wal:
            return

        for checkpoint in self.wal.checkpoints:
            yield self._share(SQLite3(self.fh, self.wal, checkpoint))

    def commit_view(self, commit: Commit | int) -> SQLite3:
        """Return a read-only view of the database as it was after the given WAL commit.

        Args:
            commit: The commit to create a view for. Can be a :class:`Commit` object or an integer index.

        Raises:
            ~dissect.database.sqlite3.exception.NoWriteAheadLog: If this database has no WAL.
            ~dissect.database.sqlite3.exception.InvalidCommit: If the commit is not part of a valid history.
            IndexError: If an integer index is out of range.
        """
        if not self.wal:
            raise NoWriteAheadLog("A WAL file is required to create a commit view")

        return self._share(SQLite3(self.fh, self.wal, commit=commit))

    def commit_views(self) -> Iterator[SQLite3]:
        """Yield a read-only view of the database for every usable commit in the WAL file, oldest first.

        Commits from a superseded WAL generation (for example before a WAL reset) cannot be reconstructed
        against the current database file and are skipped.
        """
        if not self.wal:
            return

        for index in range(len(self.wal.valid_commits)):
            yield self.commit_view(index)

    def commits(self) -> Iterator[SQLite3]:
        """Yield instances of the database at all available commits in the WAL file, if applicable.

        This is the commit counterpart of :meth:`checkpoints`.
        """
        yield from self.commit_views()

    def page_source(self, num: int) -> PageSource:
        """Return where the data for the given page comes from in this view.

        For a regular database this is the latest committed WAL frame, if any, or the database file.
        For a commit view it is the newest visible frame at or before the target commit, or the database file.

        Args:
            num: The page number to describe.

        Raises:
            ~dissect.database.sqlite3.exception.InvalidPageNumber: If the page number is out of bounds for this view.
        """
        if (num < 1 or num > self.page_count) and self.page_count > 0:
            raise InvalidPageNumber("Page number exceeds boundaries")

        frame = None
        commit_index = None
        if self.commit is not None:
            if (source := self._commit_pages.get(num)) is not None:
                frame, commit_index = source
        elif self.checkpoint is not None:
            if (candidate := self.checkpoint.get(num)) is not None:
                frame = candidate
                if self.checkpoint.index >= 0:
                    commit_index = self.checkpoint.index
        elif self.wal:
            for commit in reversed(self.wal.valid_commits):
                if (candidate := commit.get(num)) is not None:
                    frame, commit_index = candidate, commit.index
                    break

        if frame is None:
            return PageSource(page_number=num, kind=PageSource.DATABASE, page_count=self.page_count)

        return PageSource(
            page_number=num,
            kind=PageSource.WAL,
            page_count=self.page_count,
            frame_index=self.wal.frame_index(frame) if self.wal else None,
            commit_index=commit_index,
            frame=frame,
        )

    def page_sources(self) -> Iterator[PageSource]:
        """Yield the source of every page that is part of this view, in page order."""
        for num in range(1, self.page_count + 1):
            yield self.page_source(num)

    def table(self, name: str) -> Table | None:
        name = name.lower()
        for table in self.tables():
            if table.name.lower() == name:
                return table
        return None

    def tables(self) -> Iterator[Table]:
        # Page 1 contains sqlite_master table
        for cell in walk_tree(self, self.page(1)):
            if cell.values[0] != "table":
                continue

            yield Table(self, *cell.values)

    def index(self, name: str) -> Index | None:
        name = name.lower()
        for index in self.indices():
            if index.name.lower() == name:
                return index
        return None

    def indices(self) -> Iterator[Index]:
        # Page 1 contains sqlite_master table
        for cell in walk_tree(self, self.page(1)):
            if cell.values[0] != "index":
                continue

            yield Index(self, *cell.values)

    def raw_page(self, num: int) -> bytes:
        """Retrieve the raw frame data for the given page number.

        Reads the page from a checkpoint, if this class was initialized with a WAL checkpoint.
        Reads the page as it was visible at a specific commit, if this class was initialized with a WAL commit.

        If a WAL is available, will first check if the WAL contains a more recent version of the page,
        otherwise it will read the page from the database file.

        References:
            - https://sqlite.org/fileformat2.html#reader_algorithm
        """
        # Only throw an out of bounds exception if the header contains a page_count.
        # Some old versions of SQLite3 do not set/update the page_count correctly.
        if (num < 1 or num > self.page_count) and self.page_count > 0:
            raise InvalidPageNumber("Page number exceeds boundaries")

        data = None
        if self.commit is not None:
            # A commit view only sees page versions from the target commit and the commits before it.
            if (source := self._commit_pages.get(num)) is not None:
                data = source[0].data

        elif self.checkpoint is not None and (frame := self.checkpoint.get(num)):
            # If a specific WAL checkpoint was provided, use it instead of the on-disk page.
            data = frame.data

        elif self.wal:
            # Check if the latest valid instance of the page is committed (either the frame itself
            # is the commit frame or it is included in a commit's frames). If so, return that frame's data.
            for commit in reversed(self.wal.commits):
                if (frame := commit.get(num)) and frame.valid:
                    data = frame.data
                    break

        if data is not None:
            if num == 1:
                # Page 1 has a database header that needs to be stripped
                return data[len(c_sqlite3.header) :]
            return data

        # Else we read the page from the database file.
        self.fh.seek(len(c_sqlite3.header) if num == 1 else (num - 1) * self.page_size)
        return self.fh.read(self.page_size)

    def page(self, num: int) -> Page:
        return Page(self, num)

    def pages(self) -> Iterator[Page]:
        for i in range(self.page_count):
            yield self.page(i + 1)

    def cells(self) -> Iterator[Cell]:
        for page in self.pages():
            yield from page.cells()


class Column:
    """Describes a column of a sqlite table."""

    SPACE = r"\s"
    EXPRESSION = r"\(.+?\)"
    STRING = r"['\"].+?['\"]"
    TOKENIZER_EXPRESSION = re.compile(f"({SPACE}|{EXPRESSION}|{STRING})")

    def __init__(self, name: str, description: str):
        self.name = name
        self.default_value = self._parse_default_value_from_description(description)

    def _parse_default_value_from_description(self, description: str) -> bool | str | int | float | None:
        """Find the default from the description string."""
        if "DEFAULT" not in description.upper():
            return None

        tokens = self._tokenize(description)
        value = self._get_default_value(tokens)

        return self._parse_default_value(value)

    def _tokenize(self, description: str) -> list[str]:
        """Tokenize the description string."""
        tokens = self.TOKENIZER_EXPRESSION.split(description)
        # Remove spaces and empty tokens from the list
        return [x for x in tokens if x and x != " "]

    def _get_default_value(self, tokens: list[str]) -> str:
        """Retrieve the default from the tokens."""
        # The +1 is to account for the space after the default
        value_index = [x.upper() for x in tokens].index("DEFAULT") + 1
        return tokens[value_index]

    def _parse_default_value(self, value: str) -> bool | str | int | float | None:
        """Parses the default value.

        The value can hold an expression surrounded by ().
        This can be a literal, so these values get stripped.
        """
        try:
            return self._parse_literal(value.strip("()"))
        except ValueError:
            return None

    def _parse_literal(self, value: str) -> bool | str | int | float:
        """Tries to convert a literal from a string to any type.

        CURRENT_(TIME|DATE|TIMESTAMP) isn't being taken into account.
        """
        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            pass

        if value.upper() in ["TRUE", "FALSE"]:
            return value.upper() == "TRUE"

        # Convert the string literal
        if set(value) & {"'", '"'}:
            return value.strip("'\"")

        raise ValueError("Unknown literal")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Column):
            return other.name == self.name and other.default_value == self.default_value
        return False

    def __repr__(self) -> str:
        return f"<Column name={self.name} default_value={self.default_value}>"


class Table:
    def __init__(self, sqlite: SQLite3, type_: str, name: str, table_name: str, page: int, sql: str):
        self.sqlite = sqlite
        self.type = type_
        self.name = name
        self.table_name = table_name
        self.page = page
        self.sql = sql
        self.columns = []
        self.primary_key = None

        self.primary_key, columns, _ = parse_table_columns_constraints(sql)
        self.columns = [Column(name, description) for name, description in columns]

    def __repr__(self) -> str:
        return f"<Table name={self.name} page={self.page}>"

    def __iter__(self) -> Iterator[Row]:
        return self.rows()

    def row(self, idx: int) -> Row:
        return list(self.rows())[idx]

    def rows(self) -> Iterator[Row]:
        for cell in walk_tree(self.sqlite, self.sqlite.page(self.page)):
            yield Row(self, cell)


class Index:
    def __init__(self, sqlite: SQLite3, type_: str, name: str, table_name: str, page: int, sql: str):
        self.sqlite = sqlite
        self.type = type_
        self.name = name
        self.table_name = table_name
        self.page = page
        self.sql = sql

    def __repr__(self) -> str:
        return f"<Index name={self.name} page={self.page}>"


class Row:
    def __init__(self, table: Table, cell: Cell):
        self._table = table
        self._cell = cell
        self._values, self._unknowns = self._match_columns_to_values(table.columns, cell.values)

        # If there is no primary key or the primary key is a compound key,
        # primary_key will be None, but then all (primary key) columns will
        # already have a value assigned.
        primary_key = table.primary_key
        if primary_key and self._values.get(primary_key, None) is None and self._cell.key is not None:
            self._values[primary_key] = self._cell.key

    def _match_columns_to_values(self, columns: list[Column], values: list[Any]) -> tuple[dict[str, Any], list[Any]]:
        """Match all table columns to the cell values in this row.

        If there are any cell values with unknown column names
        they get added to the unknown list.
        """
        row_values = {}
        unknowns = []

        for column, value in itertools.zip_longest(columns, values, fillvalue=Empty):
            column_value = column.default_value if value is Empty else value
            if column is Empty:
                unknowns.append(column_value)
            else:
                row_values.update({column.name: column_value})

        return row_values, unknowns

    def __iter__(self) -> Iterator[tuple[str, Any]]:
        for col in self._table.columns:
            yield col.name, self[col.name]

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError:
            return object.__getattribute__(self, key)

    def __repr__(self) -> str:
        values = " ".join([f"{key}={value!r}" for key, value in self._values.items()])
        return f"<Row table={self._table.name} {values}>"

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)


class Empty:
    pass


class PageSource:
    """Describes where the data of a page in a database view comes from.

    Attributes:
        page_number: The page number this source describes.
        kind: Either ``PageSource.WAL`` when the page comes from a WAL frame, or ``PageSource.DATABASE``
            when it comes from the database file.
        page_count: The number of pages that are part of the view this source was requested from.
        frame_index: The zero-based index of the WAL frame that provided this page, if ``kind`` is
            ``PageSource.WAL``, otherwise ``None``.
        commit_index: The zero-based index of the WAL commit that made this frame visible, if ``kind`` is
            ``PageSource.WAL``, otherwise ``None``.
        frame: The WAL frame that provided this page, if ``kind`` is ``PageSource.WAL``, otherwise ``None``.
    """

    WAL = "wal"
    DATABASE = "database"

    def __init__(
        self,
        page_number: int,
        kind: str,
        page_count: int | None = None,
        frame_index: int | None = None,
        commit_index: int | None = None,
        frame: Frame | None = None,
    ):
        self.page_number = page_number
        self.kind = kind
        self.page_count = page_count
        self.frame_index = frame_index
        self.commit_index = commit_index
        self.frame = frame

    @property
    def from_wal(self) -> bool:
        """Return whether this page comes from a WAL frame."""
        return self.kind == self.WAL

    @property
    def from_database(self) -> bool:
        """Return whether this page comes from the database file."""
        return self.kind == self.DATABASE

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PageSource):
            return NotImplemented
        return (
            self.page_number == other.page_number
            and self.kind == other.kind
            and self.frame_index == other.frame_index
            and self.commit_index == other.commit_index
        )

    def __repr__(self) -> str:
        if self.kind == self.WAL:
            return (
                f"<PageSource page={self.page_number} kind={self.kind} "
                f"frame={self.frame_index} commit={self.commit_index}>"
            )
        return f"<PageSource page={self.page_number} kind={self.kind}>"


class Page:
    def __init__(self, sqlite: SQLite3, num: int):
        self.sqlite = sqlite
        self.num = num

        self.source = sqlite.page_source(num)
        self.data = sqlite.raw_page(num)
        self.offset = (num - 1) * sqlite.page_size
        buf = memoryview(self.data)

        header_len = len(c_sqlite3.page_header)
        self.header = c_sqlite3.page_header(buf[:header_len])
        self.right_page = None

        if self.header.flags not in PAGE_TYPES:
            raise InvalidPageType("Unknown page type")

        fp = header_len
        if self.header.flags in (
            c_sqlite3.PAGE_TYPE_INTERIOR_INDEX,
            c_sqlite3.PAGE_TYPE_INTERIOR_TABLE,
        ):
            self.right_page = c_sqlite3.uint32(buf[fp : fp + 4])
            fp += 4

        self.cell_pointers = c_sqlite3.uint16[self.header.cell_count](buf[fp : fp + (self.header.cell_count * 2)])

        self.cell = lru_cache(256)(self.cell)

    def __repr__(self) -> str:
        page_type = PAGE_TYPES[self.header.flags]
        return f"<Page num={self.num} type={page_type} offset=0x{self.offset:x}>"

    def open(self) -> BytesIO:
        return BytesIO(self.data)

    def cell(self, num: int) -> Cell:
        if num >= self.header.cell_count or num < 0:
            raise IndexError("Invalid cell number")

        offset = self.cell_pointers[num]
        return Cell(self, offset)

    def cells(self) -> Iterator[Cell]:
        for cell_num in range(self.header.cell_count):
            yield self.cell(cell_num)


class Cell:
    def __init__(self, page: Page, offset: int):
        self.page = page
        self.offset = offset
        self._offset = offset - len(c_sqlite3.header) if page.num == 1 else offset

        self.size = None
        self.key = None
        self.left_page = None

        self._data = None
        self._types = None
        self._values = None

        sqlite = page.sqlite
        cell_buf = BytesIO(page.data[self._offset :])

        self.max_payload_size = (sqlite.usable_page_size - 12) * 64 // 255 - 23
        self.min_payload_size = (sqlite.usable_page_size - 12) * 32 // 255 - 23

        if page.header.flags == c_sqlite3.PAGE_TYPE_LEAF_TABLE:
            self.size = varint(cell_buf)
            self.key = varint(cell_buf)
            self.max_payload_size = sqlite.usable_page_size - 35
        elif page.header.flags == c_sqlite3.PAGE_TYPE_INTERIOR_TABLE:
            self.left_page = c_sqlite3.uint32(cell_buf)
            self.key = varint(cell_buf)
        elif page.header.flags == c_sqlite3.PAGE_TYPE_LEAF_INDEX:
            self.size = varint(cell_buf)
        elif page.header.flags == c_sqlite3.PAGE_TYPE_INTERIOR_INDEX:
            self.left_page = c_sqlite3.uint32(cell_buf)
            self.size = varint(cell_buf)
        else:
            raise InvalidPageType("Unknown page type")

        self._record_offset = cell_buf.tell()

    def __repr__(self) -> str:
        return f"<Cell page={self.page.num} offset=0x{self.offset:x}>"

    @property
    def data(self) -> bytes:
        if self.size is None:
            raise NoCellData("Cell has no data")

        if not self._data:
            offset = self._offset + self._record_offset
            page_data = self.page.data

            if self.size <= self.max_payload_size:
                size = max(self.size, 4)

                buf = page_data[offset : offset + size]
            else:
                # If the data does not fit in a single page, there is an
                # overflow. The last 4 bytes of the first page will contain the
                # next (overflow) page number. Each subsequent overflow page
                # will have the next overflow page in the first 4 bytes (which
                # are 0 if there is no next overflow page), followed by the
                # page data.
                result = []

                min_local = self.min_payload_size
                max_local = self.max_payload_size
                surplus = min_local + (self.size - min_local) % (self.page.sqlite.usable_page_size - 4)

                local_size = surplus if surplus <= max_local else min_local

                local_buf = page_data[offset : offset + local_size + 4]
                result.append(local_buf[:-4])

                overflow_page = c_sqlite3.uint32(local_buf[-4:])
                overflow_size = self.size - local_size

                while overflow_page:
                    # page_size is the total page size, including the 4 bytes
                    # for the next overflow page in front of the page data.
                    # overflow_size is the size of the page data without the
                    # extra 4 bytes for the next overflow page, so it needs to
                    # be added.
                    data_size = min(overflow_size + 4, self.page.sqlite.usable_page_size)
                    page_buf = self.page.sqlite.raw_page(overflow_page)[:data_size]

                    overflow_page = c_sqlite3.uint32(page_buf[:4])
                    result.append(page_buf[4:])

                buf = b"".join(result)

            self._data = buf

        return self._data

    def _read_record(self) -> None:
        self._types, self._values = read_record(BytesIO(self.data), self.page.sqlite.encoding)

    @property
    def types(self) -> list[int]:
        if not self._types:
            self._read_record()

        return self._types

    @property
    def values(self) -> list[int | float | str | bytes | None]:
        if not self._values:
            self._read_record()

        return self._values


def walk_tree(sqlite: SQLite3, page: Page) -> Iterator[Cell]:
    if page.header.flags in (
        c_sqlite3.PAGE_TYPE_LEAF_TABLE,
        c_sqlite3.PAGE_TYPE_LEAF_INDEX,
    ):
        for cell in page.cells():
            yield cell
    else:
        for cell in page.cells():
            left_page = sqlite.page(cell.left_page)
            for cell in walk_tree(sqlite, left_page):
                yield cell

        right_page = sqlite.page(page.right_page)
        for cell in walk_tree(sqlite, right_page):
            yield cell


def read_record(fh: BinaryIO, encoding: str) -> tuple[list[int], list[int | float | str | bytes | None]]:
    start = fh.tell()
    size = varint(fh)
    end = start + size

    types = []
    while fh.tell() < end:
        types.append(varint(fh))

    values = []
    for type_ in types:
        if type_ in SERIAL_TYPES:
            val = SERIAL_TYPES[type_](fh)
        else:
            if type_ % 2 == 0:
                val = fh.read((type_ - 12) // 2)
            else:
                try:
                    val = fh.read((type_ - 13) // 2).decode(encoding)
                except UnicodeDecodeError as e:
                    val = e.object

        values.append(val)

    return types, values


def varint(fh: BinaryIO) -> int:
    byte_num = 0
    value = 0

    while True:
        val = ord(fh.read(1))

        if byte_num == 8:
            value |= val
            return value

        value |= val & 0x7F
        if val & 0x80:
            value = value << 7
            byte_num += 1
        else:
            return value
