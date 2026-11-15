from __future__ import annotations

import enum
import itertools
import re
import struct
from dataclasses import dataclass, replace
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import (
    InvalidDatabase,
    InvalidPageNumber,
    InvalidPageType,
    NoCellData,
)
from dissect.database.sqlite3.util import parse_table_columns_constraints
from dissect.database.sqlite3.wal import WAL

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from types import TracebackType

    from typing_extensions import Self

    from dissect.database.sqlite3.wal import Checkpoint, Frame

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


class StorageClass(enum.Enum):
    """The physical storage class of a value in a record.

    This is the type actually used by a record. It is independent of the type
    declared for the column in the table definition.
    """

    NULL = "null"
    INTEGER = "integer"
    REAL = "real"
    TEXT = "text"
    BLOB = "blob"
    RESERVED = "reserved"


# Serial type -> (storage class, size in bytes). Types >= 12 are text or blob.
SERIAL_TYPE_INFO = {
    0: (StorageClass.NULL, 0),
    1: (StorageClass.INTEGER, 1),
    2: (StorageClass.INTEGER, 2),
    3: (StorageClass.INTEGER, 3),
    4: (StorageClass.INTEGER, 4),
    5: (StorageClass.INTEGER, 6),
    6: (StorageClass.INTEGER, 8),
    7: (StorageClass.REAL, 8),
    8: (StorageClass.INTEGER, 0),
    9: (StorageClass.INTEGER, 0),
    10: (StorageClass.RESERVED, 0),
    11: (StorageClass.RESERVED, 0),
}

CONSTRAINT_KEYWORDS = {
    "CONSTRAINT",
    "PRIMARY",
    "NOT",
    "NULL",
    "UNIQUE",
    "CHECK",
    "DEFAULT",
    "COLLATE",
    "REFERENCES",
    "GENERATED",
    "AS",
}


def serial_type_info(serial_type: int) -> tuple[StorageClass, int]:
    """Return the storage class and payload size for a serial type.

    See https://www.sqlite.org/fileformat.html#record_format.
    """
    if serial_type >= 12:
        size = (serial_type - 12) // 2
        return (StorageClass.TEXT if serial_type % 2 else StorageClass.BLOB, size)

    return SERIAL_TYPE_INFO.get(serial_type, (StorageClass.RESERVED, 0))


_DECLARED_TYPE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s*(\([^)]*\))?")


def get_declared_type(description: str) -> str | None:
    """Return the declared type from a column definition.

    The declared type is the part of the column definition before the first
    constraint keyword. If a column has no declared type, ``None`` is returned.
    """
    match = _DECLARED_TYPE_RE.match(description)
    if not match:
        return None

    words = match.group(1).split()
    for idx, word in enumerate(words):
        if word.upper() in CONSTRAINT_KEYWORDS:
            words = words[:idx]
            break

    if not words:
        return None

    declared_type = " ".join(words)
    if match.group(2):
        # Only include an argument list when it directly follows the type name.
        trailing = description[match.start(1) :].lstrip()
        if trailing and re.match(r"^(?:" + re.escape(declared_type) + r")\s*\(", trailing, re.IGNORECASE):
            declared_type += match.group(2)

    return declared_type


@dataclass(frozen=True)
class DataRun:
    """A contiguous run of bytes belonging to a record.

    Values in a SQLite record can be split across the page that contains the
    record and one or more overflow pages. A run describes one such piece:

    Args:
        page: The page number containing this run.
        page_offset: The offset of the run in the page data as returned by
            :meth:`SQLite3.raw_page`.
        length: The number of bytes in this run.
        source: Where the page was read from: ``"database"``, ``"wal"`` or
            ``"checkpoint"``.
        file_offset: The offset of the run in the main database file. This is
            only set when the run was read from the main database file; a run
            from a WAL frame has no file range.
    """

    page: int
    page_offset: int
    length: int
    source: str = "database"
    file_offset: int | None = None

    @property
    def page_range(self) -> tuple[int, int]:
        """Return the ``(start, end)`` byte range within the page data."""
        return self.page_offset, self.page_offset + self.length

    @property
    def file_range(self) -> tuple[int, int] | None:
        """Return the ``(start, end)`` byte range in the main database file, if known."""
        if self.file_offset is None:
            return None
        return self.file_offset, self.file_offset + self.length


@dataclass
class Field:
    """A single value as it is stored in a SQLite record.

    A field keeps the information needed to trace a value back to the record:
    the serial type and storage class that were actually used, the raw bytes,
    the offset in the record payload, the physical page runs that contain those
    bytes, the decoded value and any decoding error. It also references the
    column the value was interpreted as, if any, so the declared column type
    can be compared to the storage class of this particular value.

    Fields are only created for values that are physically present in a record.
    Columns that are filled with a table default because they are absent from
    the record are not represented as a :class:`Field`.
    """

    index: int
    column: Column | None
    serial_type: int
    storage_class: StorageClass
    offset: int
    raw: bytes
    value: Any = None
    error: Exception | None = None
    ranges: tuple[DataRun, ...] = ()

    @property
    def name(self) -> str | None:
        """Return the name of the column this field was interpreted as, if any."""
        return self.column.name if self.column is not None else None

    @property
    def declared_type(self) -> str | None:
        """Return the type declared for the column, if this field has a column."""
        return self.column.declared_type if self.column is not None else None

    @property
    def length(self) -> int:
        """Return the number of raw bytes stored for this field."""
        return len(self.raw)

    @property
    def raw_range(self) -> tuple[int, int]:
        """Return the ``(start, end)`` byte range in the record payload."""
        return self.offset, self.offset + self.length

    @property
    def file_range(self) -> tuple[int, int] | None:
        """Return the ``(start, end)`` range in the main database file, if contiguous.

        A field that is split across overflow pages has no single contiguous
        file range. Use :attr:`ranges` to inspect each physical run.
        """
        if len(self.ranges) == 1:
            return self.ranges[0].file_range
        return None

    @property
    def file_ranges(self) -> tuple[tuple[int, int], ...]:
        """Return the ``(start, end)`` ranges in the main database file for all runs."""
        return tuple(run.file_range for run in self.ranges if run.file_range is not None)

    @property
    def decoded(self) -> bool:
        """Return whether the raw bytes were decoded without error."""
        return self.error is None

    def __repr__(self) -> str:
        name = f" name={self.name!r}" if self.name is not None else ""
        error = f" error={self.error!r}" if self.error is not None else ""
        return (
            f"<Field index={self.index}{name} serial_type={self.serial_type} "
            f"storage_class={self.storage_class.value} length={self.length}{error}>"
        )


# See https://sqlite.org/fileformat2.html#magic_header_string
SQLITE3_HEADER_MAGIC = b"SQLite format 3\x00"


class SQLite3:
    """SQLite3 database class.

    Loads a SQLite3 database from the given file-like object or path. If a path is provided (or can be deduced
    from the file-like object), a WAL file will be automatically looked for with a few common suffixes.
    Optionally a WAL file-like object or path can be directly provided to read changes from the WAL (this takes
    priority over the aforementioned WAL lookup). Additionally, a specific checkpoint from the WAL can be applied.

    Args:
        fh: The path or file-like object to open a SQLite3 database on.
        wal: The path or file-like object to open a SQLite3 WAL file on.
        checkpoint: The checkpoint to apply from the WAL file. Can be a :class:`Checkpoint` object or an integer index.

    Raises:
        ~dissect.database.sqlite3.exception.InvalidDatabase: If the file-like object does not look like a SQLite3
            database based on the header magic.

    References:
        - https://sqlite.org/fileformat2.html
    """

    def __init__(
        self,
        fh: Path | BinaryIO,
        wal: WAL | Path | BinaryIO | None = None,
        checkpoint: Checkpoint | int | None = None,
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

        # Determine the highest page count we have encountered while parsing the SQLite3 header and optionally WAL.
        self.page_count = max(self.header.page_count, self.wal.highest_page_num) if self.wal else self.header.page_count

        self.page = lru_cache(256)(self.page)
        self.page_source = lru_cache(256)(self.page_source)

    def __repr__(self) -> str:
        return f"<SQLite3 path={self.path} fh={self.fh} wal={self.wal} checkpoint={bool(self.checkpoint)} pages={self.page_count}>"  # noqa: E501

    def __enter__(self) -> Self:
        """Return ``self`` upon entering the runtime context."""
        return self

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """Close the database and WAL."""
        # Only close DB handle if we opened it using a path
        if self.path is not None:
            self.fh.close()

        if self.wal is not None:
            self.wal.close()

    def checkpoints(self) -> Iterator[SQLite3]:
        """Yield instances of the database at all available checkpoints in the WAL file, if applicable."""
        if not self.wal:
            return

        for checkpoint in self.wal.checkpoints:
            yield SQLite3(self.fh, self.wal, checkpoint)

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

    def page_source(self, num: int) -> str:
        """Return where the given page is read from.

        The return value is ``"checkpoint"`` for a specific WAL checkpoint,
        ``"wal"`` for a committed WAL frame or ``"database"`` for the main
        database file.
        """
        return self._page_frame(num)[0]

    def _page_frame(self, num: int) -> tuple[str, Frame | None]:
        """Return the source and WAL frame for the given page number."""
        if (num < 1 or num > self.page_count) and self.page_count > 0:
            raise InvalidPageNumber("Page number exceeds boundaries")

        if self.checkpoint is not None and (frame := self.checkpoint.get(num)):
            return "checkpoint", frame

        if self.wal:
            for commit in reversed(self.wal.commits):
                if (frame := commit.get(num)) and frame.valid:
                    return "wal", frame

        return "database", None

    def raw_page(self, num: int) -> bytes:
        """Retrieve the raw frame data for the given page number.

        Reads the page from a checkpoint, if this class was initialized with a WAL checkpoint.

        If a WAL is available, will first check if the WAL contains a more recent version of the page,
        otherwise it will read the page from the database file.

        References:
            - https://sqlite.org/fileformat2.html#reader_algorithm
        """
        # Only throw an out of bounds exception if the header contains a page_count.
        # Some old versions of SQLite3 do not set/update the page_count correctly.
        if (num < 1 or num > self.page_count) and self.page_count > 0:
            raise InvalidPageNumber("Page number exceeds boundaries")

        # If a specific WAL checkpoint was provided, use it instead of the on-disk page.
        # If a WAL is available, check if the latest valid instance of the page is committed
        # (either the frame itself is the commit frame or it is included in a commit's frames).
        source, frame = self._page_frame(num)
        if frame is not None:
            data = frame.data
            if num == 1:
                # Page 1 has a database header that needs to be stripped
                return data[len(c_sqlite3.header) :]
            return data

        # Else we read the page from the database file.
        assert source == "database"
        if num == 1:  # Page 1 is root, skip header
            self.fh.seek(len(c_sqlite3.header))
        else:
            self.fh.seek((num - 1) * self.page_size)
        return self.fh.read(self.header.page_size)

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
        self.description = description
        self.default_value = self._parse_default_value_from_description(description)

    @property
    def declared_type(self) -> str | None:
        """Return the type declared for this column, if any.

        SQLite allows a column to have no declared type. In that case this
        returns ``None``. The declared type does not restrict the storage class
        actually used by individual records.
        """
        return get_declared_type(self.description)

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

        self.primary_key_column = None
        if self.primary_key is not None:
            for column in self.columns:
                if column.name == self.primary_key:
                    self.primary_key_column = column
                    break

    def __repr__(self) -> str:
        return f"<Table name={self.name} page={self.page}>"

    def __iter__(self) -> Iterator[Row]:
        return self.rows()

    def row(self, idx: int) -> Row:
        return list(self.rows())[idx]

    def rows(self) -> Iterator[Row]:
        for cell in walk_tree(self.sqlite, self.sqlite.page(self.page)):
            yield Row(self, cell)

    def record(self, cell: Cell) -> Record:
        """Return the evidence :class:`Record` for the given cell."""
        return Record(self, cell)

    def records(self) -> Iterator[Record]:
        """Iterate over the evidence records of this table.

        Unlike :meth:`rows`, the returned records preserve the storage class,
        raw bytes, byte ranges and decoding errors of every stored field.
        """
        for cell in walk_tree(self.sqlite, self.sqlite.page(self.page)):
            yield Record(self, cell)


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
        self._record = None
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

    @property
    def record(self) -> Record:
        """Return the evidence :class:`Record` for this row."""
        if self._record is None:
            self._record = Record(self._table, self._cell)
        return self._record


class Record:
    """A record with lossless field evidence.

    This is the evidence-oriented counterpart of :class:`Row`. It keeps the
    serial type, storage class, raw bytes, byte ranges and decoding error for
    each field that is physically present in the record. Column interpretation
    is attached separately, so the type declared for a column can be compared
    with the storage class actually used by this record.

    Accessing a record never executes SQL from the database; it only parses
    the record structure and the bytes of the cell.

    Args:
        table: The table this record belongs to.
        cell: The cell containing the record.
    """

    def __init__(self, table: Table, cell: Cell):
        self.table = table
        self.cell = cell

        self.fields: list[Field] = []
        self._field_map: dict[str, Field] = {}
        self.unknowns: list[Field] = []

        for field in cell.fields:
            column = table.columns[field.index] if field.index < len(table.columns) else None
            bound = replace(field, column=column)
            self.fields.append(bound)
            if column is not None:
                self._field_map[column.name] = bound
            else:
                self.unknowns.append(bound)

        # SQLite stores the INTEGER PRIMARY KEY as an alias for the rowid, so
        # the record often contains a NULL in that column while the actual
        # key lives in the cell. Keep that relationship explicit instead of
        # changing the stored field.
        column = table.primary_key_column
        if (
            table.primary_key
            and column is not None
            and column.declared_type is not None
            and column.declared_type.upper() == "INTEGER"
            and cell.key is not None
        ):
            self._rowid_column = table.primary_key
        else:
            self._rowid_column = None

    def __repr__(self) -> str:
        return f"<Record table={self.table.name!r} fields={len(self.fields)}>"

    def __iter__(self) -> Iterator[tuple[str | None, Field]]:
        for field in self.fields:
            yield field.name, field

    def __len__(self) -> int:
        return len(self.fields)

    def __getitem__(self, key: str) -> Field:
        return self.get(key)

    def __getattr__(self, key: str) -> Any:
        if key.startswith("_"):
            return object.__getattribute__(self, key)

        try:
            return self._field_map[key]
        except KeyError:
            raise AttributeError(key) from None

    def get(self, key: str, default: Any = None) -> Any:
        """Return the evidence field for the given column name."""
        return self._field_map.get(key, default)

    def value(self, key: str, default: Any = None) -> Any:
        """Return the decoded value for the given column name.

        For an ``INTEGER PRIMARY KEY`` that is an alias for the rowid, this
        returns the rowid when the column itself is absent or stored as NULL.
        Use :meth:`get` to inspect the stored field.
        """
        field = self._field_map.get(key)
        if field is not None:
            if field.value is None and key == self._rowid_column and field.storage_class is StorageClass.NULL:
                return self.cell.key
            return field.value
        if key == self._rowid_column:
            return self.cell.key
        return default

    def field(self, key: str, default: Any = None) -> Field | Any:
        """Return the stored :class:`Field` for the given column name."""
        return self._field_map.get(key, default)

    @property
    def key(self) -> int | None:
        """Return the rowid of this record, if it has one."""
        return self.cell.key

    rowid = key

    @property
    def types(self) -> list[int]:
        """Return the serial types of this record."""
        return [field.serial_type for field in self.fields]

    def values(self) -> dict[str, Any]:
        """Return the decoded values for the columns that are present."""
        return {field.name: self.value(field.name) for field in self.fields if field.name is not None}

    def as_row(self) -> Row:
        """Return a convenience :class:`Row` for this record."""
        return Row(self.table, self.cell)

    def as_dict(self) -> dict[str, dict[str, Any]]:
        """Return a report-friendly description of every field.

        Each entry describes the actual storage encoding of the field and the
        declared type of its column as separate values.
        """
        return {
            field.name or f"column_{field.index}": {
                "index": field.index,
                "declared_type": field.declared_type,
                "serial_type": field.serial_type,
                "storage_class": field.storage_class.value,
                "length": field.length,
                "offset": field.offset,
                "raw_range": field.raw_range,
                "file_range": field.file_range,
                "file_ranges": field.file_ranges,
                "ranges": [
                    {
                        "page": run.page,
                        "source": run.source,
                        "page_range": run.page_range,
                        "file_range": run.file_range,
                    }
                    for run in field.ranges
                ],
                "value": field.value,
                "error": str(field.error) if field.error is not None else None,
            }
            for field in self.fields
        }


class Empty:
    pass


class Page:
    def __init__(self, sqlite: SQLite3, num: int):
        self.sqlite = sqlite
        self.num = num

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
        self._data_runs = None
        self._types = None
        self._values = None
        self._fields = None

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

    def _file_offset(self, page_num: int, page_offset: int) -> int | None:
        """Return the offset in the main database file for a page offset, if applicable."""
        if self.page.sqlite.page_source(page_num) != "database":
            # A page from the WAL has no meaningful offset in the main file.
            return None

        if page_num == 1:
            # Page 1 is returned without the database header.
            return len(c_sqlite3.header) + page_offset
        return (page_num - 1) * self.page.sqlite.page_size + page_offset

    @property
    def data_runs(self) -> tuple[DataRun, ...]:
        """Return the physical page runs that contain the record payload."""
        self._read_data()
        return self._data_runs

    @property
    def data(self) -> bytes:
        self._read_data()
        return self._data

    def _read_data(self) -> None:
        if self.size is None:
            raise NoCellData("Cell has no data")

        if self._data is None:
            offset = self._offset + self._record_offset
            page_data = self.page.data
            runs = []

            if self.size <= self.max_payload_size:
                # Keep the historical minimum read of 4 bytes so that a very
                # short record still contains a complete header varint.
                buf = page_data[offset : offset + max(self.size, 4)]
                if buf:
                    runs.append(
                        DataRun(
                            page=self.page.num,
                            page_offset=offset,
                            length=min(len(buf), self.size),
                            source=self.page.sqlite.page_source(self.page.num),
                            file_offset=self._file_offset(self.page.num, offset),
                        )
                    )
            else:
                # If the data does not fit in a single page, there is an
                # overflow. The last 4 bytes of the first page will contain the
                # next (overflow) page number. Each subsequent overflow page
                # will have the next overflow page in the first 4 bytes (which
                # are 0 if there is no next overflow page), followed by the
                # page data.
                min_local = self.min_payload_size
                max_local = self.max_payload_size
                surplus = min_local + (self.size - min_local) % (self.page.sqlite.usable_page_size - 4)

                local_size = surplus if surplus <= max_local else min_local
                local_size = min(local_size, self.size)

                local_buf = page_data[offset : offset + local_size]
                runs.append(
                    DataRun(
                        page=self.page.num,
                        page_offset=offset,
                        length=len(local_buf),
                        source=self.page.sqlite.page_source(self.page.num),
                        file_offset=self._file_offset(self.page.num, offset),
                    )
                )

                pointer_buf = page_data[offset + local_size : offset + local_size + 4]
                overflow_page = c_sqlite3.uint32(pointer_buf) if len(pointer_buf) == 4 else 0
                remaining = self.size - len(local_buf)
                result = [local_buf]

                while overflow_page and remaining > 0:
                    # page_size is the total page size, including the 4 bytes
                    # for the next overflow page in front of the page data.
                    # Read at most the number of bytes still needed, plus the
                    # pointer to the next overflow page.
                    data_size = min(remaining + 4, self.page.sqlite.usable_page_size)
                    page_buf = self.page.sqlite.raw_page(overflow_page)[:data_size]
                    if len(page_buf) < 4:
                        break

                    next_page = c_sqlite3.uint32(page_buf[:4])
                    chunk = page_buf[4 : 4 + remaining]

                    runs.append(
                        DataRun(
                            page=overflow_page,
                            page_offset=4,
                            length=len(chunk),
                            source=self.page.sqlite.page_source(overflow_page),
                            file_offset=self._file_offset(overflow_page, 4),
                        )
                    )
                    result.append(chunk)
                    remaining -= len(chunk)
                    overflow_page = next_page

                buf = b"".join(result)

            self._data = buf
            self._data_runs = tuple(runs)

    def _read_record(self) -> None:
        self._types, self._fields = read_record_fields(self.data, self.page.sqlite.encoding, self.data_runs)
        self._values = [field.value for field in self._fields]

    @property
    def types(self) -> list[int]:
        """Return the serial types of the fields in this record."""
        if self._types is None:
            self._read_record()

        return self._types

    @property
    def values(self) -> list[int | float | str | bytes | None]:
        """Return the decoded values of this record."""
        if self._values is None:
            self._read_record()

        return self._values

    @property
    def fields(self) -> list[Field]:
        """Return the evidence fields of this record."""
        if self._fields is None:
            self._read_record()

        return self._fields


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
    """Read a record and return its serial types and decoded values.

    This is the convenience interface used by :class:`Row`. For an interface
    that preserves storage information and raw bytes, use
    :func:`read_record_fields` or :meth:`Table.records`.
    """
    start = fh.tell()
    size = varint(fh)
    end = start + size

    types = []
    while fh.tell() < end:
        try:
            types.append(varint(fh))
        except EOFError:  # noqa: PERF203
            break

    values = []
    for serial_type in types:
        _, length = serial_type_info(serial_type)
        raw = fh.read(length)
        values.append(_decode_value(serial_type, raw, encoding)[0])

    return types, values


def read_record_fields(data: bytes, encoding: str, runs: Sequence[DataRun] = ()) -> tuple[list[int], list[Field]]:
    """Read a record and return its serial types and evidence fields.

    Args:
        data: The raw record payload, starting with the record header.
        encoding: The text encoding of the database.
        runs: The physical page runs that contain ``data``. Used to populate
            the byte ranges of each field.

    The returned fields are in record order. Fields are only created for
    values that are present in the record; absent trailing columns are not
    materialized. A field that cannot be decoded as text keeps its raw bytes
    and the decoding error, while all other fields in the record are still
    returned.

    References:
        - https://www.sqlite.org/fileformat2.html#record_format
    """
    if not data:
        return [], []

    fh = BytesIO(data)
    start = fh.tell()
    try:
        size = varint(fh)
    except EOFError:
        return [], []
    end = start + size

    types = []
    while fh.tell() < end:
        # A truncated header is treated as the end of the field list.
        if fh.tell() >= len(data):
            break
        try:
            types.append(varint(fh))
        except EOFError:
            break

    fields = []
    offset = end
    for index, serial_type in enumerate(types):
        storage_class, length = serial_type_info(serial_type)
        raw = data[offset : offset + length]

        value, error = _decode_value(serial_type, raw, encoding)

        fields.append(
            Field(
                index=index,
                column=None,
                serial_type=serial_type,
                storage_class=storage_class,
                offset=offset,
                raw=raw,
                value=value,
                error=error,
                ranges=_map_runs(runs, offset, len(raw)),
            )
        )
        offset += length

    return types, fields


def _decode_value(serial_type: int, raw: bytes, encoding: str) -> tuple[Any, Exception | None]:
    """Decode a single record value, returning the value and any decoding error."""
    storage_class, _ = serial_type_info(serial_type)

    if storage_class is StorageClass.NULL:
        return None, None

    if storage_class is StorageClass.INTEGER:
        if serial_type == 8:
            return 0, None
        if serial_type == 9:
            return 1, None
        return int.from_bytes(raw, "big", signed=True), None

    if storage_class is StorageClass.REAL:
        if len(raw) != 8:
            return None, ValueError(f"Invalid real payload length: {len(raw)}")
        return struct.unpack(">d", raw)[0], None

    if storage_class is StorageClass.TEXT:
        try:
            return raw.decode(encoding), None
        except UnicodeDecodeError as e:
            # Preserve both the bytes and the error. Do not let a bad text
            # field suppress the other fields in the record.
            return raw, e

    if storage_class is StorageClass.BLOB:
        return raw, None

    return raw, None


def _map_runs(runs: Sequence[DataRun], offset: int, length: int) -> tuple[DataRun, ...]:
    """Map a range in the record payload to physical page runs."""
    if not runs or length == 0:
        return ()

    result = []
    run_offset = 0

    for run in runs:
        run_end = run_offset + run.length
        start = max(offset, run_offset)
        stop = min(offset + length, run_end)

        if start < stop:
            delta = start - run_offset
            result.append(
                DataRun(
                    page=run.page,
                    page_offset=run.page_offset + delta,
                    length=stop - start,
                    source=run.source,
                    file_offset=run.file_offset + delta if run.file_offset is not None else None,
                )
            )

        run_offset = run_end
        if run_offset >= offset + length:
            break

    return tuple(result)


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
