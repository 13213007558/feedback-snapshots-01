"""Query equivalence regression tests for the NTDS query engine.

Opening up optimizations (``optimize=True``) or reordering conditions must never change the set of
objects a query hits. These tests build a small set of account records with unique DNTs and evaluate
every query through three execution paths that must agree with an independent, bounded reference
interpreter:

- the optimized query path (indexes where available),
- the unoptimized query path,
- a full table scan (a database variant without any indexes).

Historically divergent behaviour that these tests guard against:

- the tail-wildcard index range search included the first record *beyond* the upper bound
  (one record too many), and returned the last index record for out-of-range prefixes;
- wildcard patterns with both a middle and a trailing ``*`` were wrongly routed to the prefix
  range search, under-reporting matches;
- OR operations yielded duplicate records for objects matching multiple branches;
- unknown attributes in record filters were silently treated as an empty result;
- exact matches on non-indexed attributes were case-sensitive while the index path is not.
"""

from __future__ import annotations

import fnmatch
import re
import struct
from bisect import bisect_left
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from dissect.util.ldap import LogicalOperator, SearchFilter

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.query import Query

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.ntds import NTDS

SAM_USER_OBJECT = 0x30000000
SAM_MACHINE_ACCOUNT = 0x30000001

PERSON_DNT = 5001
COMPUTER_DNT = 5002

# Independent mapping of objectCategory names to DNTs, mirroring what the schema encoders do
CATEGORY_DNTS = {"person": PERSON_DNT, "computer": COMPUTER_DNT}

ATTRIBUTES = [
    # name, column, syntax, indexed
    ("sAMAccountName", "ATT_sam", 12, True),
    ("description", "ATT_desc", 12, False),
    ("sAMAccountType", "ATT_sat", 9, True),
    ("userAccountControl", "ATT_uac", 9, False),
    ("objectCategory", "ATT_oc", 1, True),
]

ATTR_TO_COLUMN = {name: column for name, column, _, _ in ATTRIBUTES}
INDEXED_COLUMNS = {column for _, column, _, indexed in ATTRIBUTES if indexed}

# A small set of account records, each with a unique DNT. The values are chosen to stress the
# execution paths under test: a record ("hoe") sits exactly on the upper bound of the "hod*" index
# range, one record has two multi-values matching the same prefix, and case differs from queries.
ACCOUNTS = [
    {"dnt": 1001, "attrs": {"sAMAccountName": ["Hodor"], "description": "Brainless giant",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1002, "attrs": {"sAMAccountName": ["hodrick"], "description": "Stable boy",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1003, "attrs": {"sAMAccountName": ["hoe"], "description": "Garden tool",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1004, "attrs": {"sAMAccountName": ["hoded", "hodder"], "description": "Two names",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x202,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1005, "attrs": {"sAMAccountName": ["ADMIN"], "description": "Administrator",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1006, "attrs": {"sAMAccountName": ["admin2"], "description": None,
                            "sAMAccountType": SAM_MACHINE_ACCOUNT, "userAccountControl": 0x200,
                            "objectCategory": COMPUTER_DNT}},
    {"dnt": 1007, "attrs": {"sAMAccountName": ["zztop"], "description": "Sharp dressed",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
    {"dnt": 1008, "attrs": {"sAMAccountName": None, "description": "No name",
                            "sAMAccountType": SAM_USER_OBJECT, "userAccountControl": 0x200,
                            "objectCategory": PERSON_DNT}},
]


def _fake_key(value: Any) -> bytes:
    """Encode a value into a normalized key, mimicking the ESE index key normalization."""
    if isinstance(value, str):
        return b"\x7f" + value.upper().encode() + b"\x00"
    if isinstance(value, int):
        return b"\x7f" + struct.pack(">I", (value ^ (1 << 31)) & 0xFFFFFFFF)
    raise TypeError(f"Cannot encode key for value: {value!r}")


class FakeRecord:
    """Minimal stand-in for an ESE record, keyed by a unique DNT."""

    def __init__(self, dnt: int, values: dict[str, Any]) -> None:
        self._node = SimpleNamespace(key=struct.pack(">I", dnt))
        self._values = values

    def get(self, column: str, raw: bool = False) -> Any:
        return self._values.get(column)


class FakeCursor:
    """In-memory cursor mimicking the ESE cursor semantics that queries rely on.

    Notably, a non-exact seek lands on the first entry greater than or equal to the key, or on the
    last entry if the key is beyond all entries (like ``find_node`` does for the real B+Tree).
    """

    def __init__(self, index: FakeIndex) -> None:
        self.index = index
        self._idx = 0

    def __iter__(self) -> Iterator[FakeRecord]:
        self._idx = 0
        while self._idx < len(self.index.entries):
            yield self.record()
            self._idx += 1

    def make_key(self, values: list[Any]) -> bytes:
        return b"".join(_fake_key(value) for value in values)

    def key(self) -> bytes:
        return self.index.entries[self._idx][0]

    def record(self) -> FakeRecord:
        self.index.db.records_accessed += 1
        return self.index.entries[self._idx][1]

    def reset(self) -> FakeCursor:
        self._idx = 0
        return self

    def next(self) -> FakeRecord | None:
        self._idx += 1
        if self._idx >= len(self.index.entries):
            return None
        return self.record()

    def seek_key(self, key: bytes) -> FakeCursor:
        if not self.index.entries:
            raise KeyNotFoundError(f"Key not found: {key!r}")
        self._idx = bisect_left(self.index.entries, key, key=lambda entry: entry[0])
        if self._idx >= len(self.index.entries):
            self._idx = len(self.index.entries) - 1
        return self

    def seek(self, values: list[Any]) -> FakeCursor:
        return self.seek_key(self.make_key(values))

    def find_all(self, **kwargs: Any) -> Iterator[FakeRecord]:
        ((column, value),) = kwargs.items()
        target = self.make_key([value])
        idx = bisect_left(self.index.entries, target, key=lambda entry: entry[0])
        while idx < len(self.index.entries) and self.index.entries[idx][0] == target:
            self.index.db.records_accessed += 1
            yield self.index.entries[idx][1]
            idx += 1


class FakeIndex:
    """In-memory index over a single column, with one entry per (multi-)value."""

    def __init__(self, db: FakeDB, table: FakeTable, column: str) -> None:
        self.db = db
        self.table = table
        self.columns = [column]
        entries = []
        for record in table._records:
            value = record.get(column)
            for single_value in value if isinstance(value, list) else [value]:
                if single_value is not None:
                    entries.append((_fake_key(single_value), record))
        self.entries = sorted(entries, key=lambda entry: entry[0])

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)


class FakeTable:
    def __init__(self, db: FakeDB, records: list[FakeRecord], indexed_columns: set[str]) -> None:
        self._db = db
        self._records = records
        self._indexes = {column: FakeIndex(db, self, column) for column in indexed_columns}

    def records(self) -> Iterator[FakeRecord]:
        for record in self._records:
            self._db.records_accessed += 1
            yield record

    def find_index(self, column_names: list[str]) -> FakeIndex | None:
        return self._indexes.get(column_names[0])


class FakeSchema:
    def __init__(self) -> None:
        self._entries = [
            SimpleNamespace(name=name, column=column, syntax=syntax, dnt=0) for name, column, syntax, _ in ATTRIBUTES
        ] + [SimpleNamespace(name=name, column=None, syntax=0, dnt=dnt) for name, dnt in CATEGORY_DNTS.items()]

    def lookup_attribute(self, name: str) -> SimpleNamespace | None:
        return next((entry for entry in self._entries if entry.name == name and entry.column is not None), None)

    def lookup(self, name: str) -> SimpleNamespace | None:
        return next((entry for entry in self._entries if entry.name == name), None)


class FakeDB:
    """Minimal stand-in for the NTDS database, with an optional set of indexes."""

    def __init__(self, indexed_columns: set[str]) -> None:
        self.records_accessed = 0
        records = [
            FakeRecord(
                account["dnt"],
                {"DNT_col": account["dnt"]}
                | {ATTR_TO_COLUMN[name]: value for name, value in account["attrs"].items()},
            )
            for account in ACCOUNTS
        ]
        self.data = SimpleNamespace(
            schema=FakeSchema(),
            table=FakeTable(self, records, indexed_columns),
        )


@pytest.fixture
def indexed_db() -> FakeDB:
    return FakeDB(INDEXED_COLUMNS)


@pytest.fixture
def scan_db() -> FakeDB:
    """A database variant without any indexes, forcing full table scans."""
    return FakeDB(set())


# Independent encoders for the reference interpreter, mapping filter strings to stored values
REFERENCE_ENCODERS = {
    "sAMAccountName": lambda value: value,
    "description": lambda value: value,
    "cn": lambda value: value,
    "sAMAccountType": int,
    "userAccountControl": int,
    "objectCategory": lambda value: CATEGORY_DNTS[value],
}


def reference_query(accounts: list[dict], query: str) -> list[int]:
    """Independent bounded filter interpreter: full scan over the accounts, returning DNTs.

    Defines the expected semantics: case-insensitive string comparison, wildcard matching on any
    of the multi-values, AND/OR as set operations with each object returned at most once.
    """
    return _evaluate_filter(accounts, SearchFilter.parse(query, optimize=False))


def _evaluate_filter(accounts: list[dict], filter: SearchFilter) -> list[int]:
    if filter.is_nested():
        results = [_evaluate_filter(accounts, child) for child in filter.children]
        if filter.operator == LogicalOperator.AND:
            return [dnt for dnt in results[0] if all(dnt in result for result in results[1:])]
        if filter.operator == LogicalOperator.OR:
            return list(dict.fromkeys(dnt for result in results for dnt in result))
        raise ValueError(f"Unsupported operator: {filter.operator}")

    if filter.attribute not in REFERENCE_ENCODERS:
        raise ValueError(f"Attribute {filter.attribute!r} not found in the NTDS database")

    if "*" in filter.value:
        pattern = re.compile(fnmatch.translate(filter.value), re.IGNORECASE)

        def matches(value: Any) -> bool:
            return isinstance(value, str) and pattern.match(value) is not None
    else:
        expected = REFERENCE_ENCODERS[filter.attribute](filter.value)

        def matches(value: Any) -> bool:
            if isinstance(value, str) and isinstance(expected, str):
                return value.casefold() == expected.casefold()
            return value == expected

    result = []
    for account in accounts:
        values = account["attrs"].get(filter.attribute)
        if values is None:
            continue
        if not isinstance(values, list):
            values = [values]
        if any(matches(value) for value in values):
            result.append(account["dnt"])
    return result


QUERIES = [
    # Exact match on an indexed attribute, case must not matter
    "(sAMAccountName=HODOR)",
    "(sAMAccountName=hodor)",
    # Exact match on a multi-valued attribute
    "(sAMAccountName=hodder)",
    # Presence filter
    "(sAMAccountName=*)",
    # Tail wildcard; "hoe" sits exactly on the upper bound of the range and must not match
    "(sAMAccountName=hod*)",
    "(sAMAccountName=adm*)",
    # Out-of-range prefix must be empty, not the last index record
    "(sAMAccountName=zzz*)",
    # Middle wildcards, with and without a trailing wildcard
    "(sAMAccountName=h*d*r)",
    "(sAMAccountName=h*r)",
    "(sAMAccountName=*or*)",
    # Exact match on a non-indexed attribute, case must not matter
    "(description=brainless giant)",
    "(description=Brainless Giant)",
    # Wildcard on a non-indexed attribute
    "(description=*Giant*)",
    # Exact match on indexed and non-indexed integer attributes (encoded values)
    "(sAMAccountType=805306369)",
    "(userAccountControl=512)",
    # Exact match on an attribute encoded through the schema (name -> DNT)
    "(objectCategory=person)",
    # AND conditions in both orders
    "(&(sAMAccountType=805306368)(sAMAccountName=hod*))",
    "(&(sAMAccountName=hod*)(sAMAccountType=805306368))",
    "(&(userAccountControl=512)(sAMAccountName=hod*))",
    "(&(sAMAccountName=hod*)(userAccountControl=512))",
    # OR with branches hitting the same object must not yield duplicates
    "(|(sAMAccountName=Hodor)(description=Brainless*))",
    "(|(sAMAccountName=hod*)(sAMAccountName=hodor))",
    "(|(objectCategory=person)(sAMAccountType=805306369))",
    # Nested logic
    "(&(objectCategory=person)(|(description=*giant*)(sAMAccountName=adm*)))",
]


@pytest.mark.parametrize("query", QUERIES)
def test_query_equivalence(indexed_db: FakeDB, scan_db: FakeDB, query: str) -> None:
    """All execution paths must return exactly the expected set of DNTs, without duplicates."""
    expected = reference_query(ACCOUNTS, query)

    for db in (indexed_db, scan_db):
        for optimize in (True, False):
            result = [record.get("DNT_col") for record in Query(db, query, optimize=optimize).process()]
            assert len(result) == len(set(result)), f"duplicate hits for {query!r} (optimize={optimize})"
            assert sorted(result) == sorted(expected), f"mismatch for {query!r} (optimize={optimize})"


def test_unknown_attribute_raises(indexed_db: FakeDB, scan_db: FakeDB) -> None:
    """Unsupported filter attributes must raise, also when used as a non-base AND condition."""
    for db in (indexed_db, scan_db):
        for optimize in (True, False):
            with pytest.raises(ValueError, match="nonexistent_attr"):
                list(Query(db, "(nonexistent_attr=foo)", optimize=optimize).process())
            with pytest.raises(ValueError, match="nonexistent_attr"):
                list(Query(db, "(&(sAMAccountName=Hodor)(nonexistent_attr=foo))", optimize=optimize).process())


def test_index_reduces_record_access(indexed_db: FakeDB, scan_db: FakeDB) -> None:
    """A working index must reduce the number of records actually accessed."""
    query = "(sAMAccountName=Hodor)"

    indexed_db.records_accessed = 0
    assert len(list(Query(indexed_db, query).process())) == 1
    indexed_access = indexed_db.records_accessed

    scan_db.records_accessed = 0
    assert len(list(Query(scan_db, query).process())) == 1
    scan_access = scan_db.records_accessed

    assert scan_access == len(ACCOUNTS)
    assert 0 < indexed_access < scan_access


GOAD_ATTRIBUTES = ["sAMAccountName", "description", "cn", "sAMAccountType", "userAccountControl"]

GOAD_QUERIES = [
    "(sAMAccountName=hod*)",
    "(sAMAccountName=*odor)",
    "(sAMAccountName=h*d*r)",
    "(sAMAccountName=*a*)",
    "(sAMAccountName=zzz*)",
    "(sAMAccountName=HODOR)",
    "(description=Brainless*)",
    "(cn=HODOR)",
    "(&(sAMAccountType=805306369)(sAMAccountName=h*))",
    "(&(sAMAccountName=h*)(sAMAccountType=805306369))",
    "(|(sAMAccountName=hodor)(cn=hodor))",
    "(|(sAMAccountName=hodor)(sAMAccountName=HODOR))",
]


def test_goad_query_equivalence(goad: NTDS) -> None:
    """The optimized query path on a real NTDS database must match the reference interpreter."""
    db = goad.db
    columns = {name: db.data.schema.lookup_attribute(name=name).column for name in GOAD_ATTRIBUTES}
    accounts = [
        {
            "dnt": record.get("DNT_col"),
            "attrs": {name: record.get(column) for name, column in columns.items()},
        }
        for record in db.data.table.records()
    ]

    for query in GOAD_QUERIES:
        expected = reference_query(accounts, query)
        for optimize in (True, False):
            result = [record.get("DNT_col") for record in Query(db, query, optimize=optimize).process()]
            assert len(result) == len(set(result)), f"duplicate hits for {query!r} (optimize={optimize})"
            assert sorted(result) == sorted(expected), f"mismatch for {query!r} (optimize={optimize})"
