"""Query equivalence regression tests for the NTDS LDAP query engine.

Turning query optimization on or reordering AND conditions must never change the set of matched
objects. These tests use a small, fully controlled set of account records (each with a unique DNT)
and compare the optimized query engine against:

* an independent, straightforward reference filter interpreter over the same records, and
* a forced full-table-scan execution path (the attributes are temporarily stripped of indexes).

The in-memory harness mimics the ESE index semantics that matter for equivalence: normalized index
keys (case-insensitive text, binary integers), one index entry per value for multivalued attributes
and a cursor that performs non-exact seeks. It also records how many records/index entries each
execution path actually visits, so the tests can prove that a normal index still reduces the number
of records touched compared with a full table scan.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from dissect.database.ese.ntds.query import Query, _increment_last_char
from dissect.database.ese.ntds.schema import AttributeEntry
from dissect.util.ldap import SearchFilter

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.record import Record


# ---------------------------------------------------------------------------
# Minimal in-memory ESE-like harness
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeColumn:
    name: str
    is_text: bool = False
    is_multivalue: bool = False


@dataclass(frozen=True)
class FakeNode:
    key: bytes
    record_key: bytes | None = None  # secondary indexes point at the primary (DNT) key


class FakeRawCursor:
    """In-order cursor over a sorted list of nodes, mirroring ``RawCursor`` semantics."""

    def __init__(self, nodes: list[FakeNode]):
        self._nodes = nodes
        self._idx = 0

    def reset(self) -> FakeRawCursor:
        self._idx = 0
        return self

    def first(self) -> bool:
        self._idx = 0
        return bool(self._nodes)

    def next(self) -> bool:
        if self._idx + 1 < len(self._nodes):
            self._idx += 1
            return True
        return False

    def node(self) -> FakeNode:
        return self._nodes[self._idx]

    @property
    def state(self) -> tuple[int]:
        return (self._idx,)

    @state.setter
    def state(self, value: tuple[int]) -> None:
        (self._idx,) = value

    def search(self, key: bytes, exact: bool = True) -> FakeRawCursor:
        # First node with a key greater than or equal to the requested key
        lo, hi = 0, len(self._nodes)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._nodes[mid].key < key:
                lo = mid + 1
            else:
                hi = mid
        if exact and (lo >= len(self._nodes) or self._nodes[lo].key != key):
            raise KeyError(key)
        if lo >= len(self._nodes):
            raise KeyError(key)
        self._idx = lo
        return self


class FakeCursor:
    def __init__(self, index: FakeIndex):
        self.index = index
        self._primary = FakeRawCursor(index.nodes)
        self._secondary = None if index.is_primary else FakeRawCursor(index.table.primary_nodes)

    def reset(self) -> FakeCursor:
        self._primary.reset()
        if self._secondary is not None:
            self._secondary.reset()
        return self

    def make_key(self, *args: Any, **kwargs: Any) -> bytes:
        values = args[0] if args else [kwargs[c.name] for c in self.index.columns if c.name in kwargs]
        return self.index.make_key(values)

    def seek_key(self, key: bytes) -> FakeCursor:
        self._primary.search(key, exact=False)
        return self

    def seek(self, *args: Any, **kwargs: Any) -> FakeCursor:
        return self.seek_key(self.make_key(*args, **kwargs))

    def record(self) -> FakeRecord:
        node = self._primary.node()
        if self._secondary is not None:
            record_key = node.record_key
            self._secondary.search(record_key, exact=True)
            primary_node = self._secondary.node()
            return self.index.table.record_by_key[primary_node.key]
        return self.index.table.record_by_key[node.key]

    def __iter__(self) -> Iterator[FakeRecord]:
        self._primary.first()
        while True:
            yield self.record()
            if not self._primary.next():
                break

    def find_all(self, **kwargs: Any) -> Iterator[FakeRecord]:
        column = self.index.columns[0].name
        value = kwargs.pop(column)
        assert not kwargs
        key = self.make_key([value])
        try:
            self._primary.search(key, exact=True)
        except KeyError:
            return
        seen: set[bytes] = set()
        while self._primary.node().key == key:
            record = self.record()
            if record._node.key not in seen:
                seen.add(record._node.key)
                yield record
            if not self._primary.next():
                break


class FakeIndex:
    def __init__(self, table: FakeTable, column: FakeColumn, is_primary: bool = False):
        self.table = table
        self.columns = [column]
        self.is_primary = is_primary
        self.nodes = self._build_nodes() if is_primary or column is not None else []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def make_key(self, values: list[Any]) -> bytes:
        if self.is_primary:
            return _int_key(values[0])
        column = self.columns[0]
        return _attribute_key(column, values[0])

    def _build_nodes(self) -> list[FakeNode]:
        if self.is_primary:
            nodes = [FakeNode(_int_key(record.dnt)) for record in self.table.rows]
            return sorted(nodes, key=lambda node: node.key)

        column = self.columns[0]
        nodes: list[FakeNode] = []
        for record in self.table.rows:
            value = record.values.get(column.name)
            if value is None:
                continue
            entries = value if column.is_multivalue else [value]
            for entry in entries:
                # One index entry per attribute value; the node resolves back to the DNT record
                nodes.append(FakeNode(_attribute_key(column, entry), _int_key(record.dnt)))
        nodes.sort(key=lambda node: node.key)
        return nodes


def _int_key(value: int) -> bytes:
    # Long values are stored with the high bit flipped, see dissect.database.ese.index.encode_key
    return b"\x7f" + ((value ^ (1 << 31)) & 0xFFFFFFFF).to_bytes(4, "big")


def _attribute_key(column: FakeColumn, value: Any) -> bytes:
    if column.is_text:
        # Case-insensitive, NUL-terminated normalized text key (ASCII/Unicode indexes uppercase)
        return b"\x7f" + str(value).upper().encode() + b"\x00"
    if isinstance(value, int):
        return _int_key(value)
    return b"\x7f" + bytes(value)


class FakeRecord:
    def __init__(self, table: FakeTable, dnt: int, values: dict[str, Any]):
        self._table = table
        self.dnt = dnt
        self.values = values
        self._node = FakeNode(_int_key(dnt))

    def get(self, column: str) -> Any:
        return self.values.get(column)


class FakeTable:
    def __init__(self, rows: list[FakeRecord], columns: list[FakeColumn], indexed: set[str]):
        self.rows = rows
        self._columns = {column.name: column for column in columns}
        self.record_by_key = {_int_key(record.dnt): record for record in rows}
        self.primary_nodes = [FakeNode(_int_key(record.dnt)) for record in rows]
        self.primary_nodes.sort(key=lambda node: node.key)
        self._indexed = set(indexed)
        self.access_count = 0

    def column(self, name: str) -> FakeColumn:
        return self._columns[name]

    def find_index(self, column_names: list[str]) -> FakeIndex | None:
        name = column_names[0]
        if name not in self._indexed:
            return None
        return FakeIndex(self, self._columns[name])

    def records_iter(self) -> Iterator[FakeRecord]:
        for record in self.rows:
            self.access_count += 1
            yield record

    # The query engine calls ``table.records()``
    def records(self) -> Iterator[FakeRecord]:
        yield from self.records_iter()


class FakeSchema:
    def __init__(self, entries: dict[str, AttributeEntry]):
        self._entries = entries

    def lookup_attribute(self, name: str) -> AttributeEntry | None:
        return self._entries.get(name)


class FakeData:
    def __init__(self, table: FakeTable, schema: FakeSchema):
        self.table = table
        self.schema = schema


class FakeDB:
    def __init__(self, table: FakeTable, schema: FakeSchema):
        self.data = FakeData(table, schema)


# ---------------------------------------------------------------------------
# Controlled account dataset (every account has a unique DNT)
# ---------------------------------------------------------------------------

COLUMNS = [
    FakeColumn("col_sam", is_text=True),  # indexed, single value
    FakeColumn("col_cn", is_text=True),  # indexed, single value
    FakeColumn("col_desc", is_text=True, is_multivalue=True),  # not indexed, multivalue
    FakeColumn("col_spn", is_text=True, is_multivalue=True),  # indexed, multivalue
    FakeColumn("col_type", is_text=False),  # indexed, integer
]

ACCOUNTS = [
    # DNT, sAMAccountName, cn, description (multi, non-indexed), servicePrincipalName (multi, indexed), type
    (101, "hodor", "Hodor", ["loyal gatekeeper"], ["HOST/winterfell", "HTTP/winterfell"], 805306368),
    (102, "hodora", "Hodora", ["north of the wall"], ["HOST/wall"], 805306368),
    # Directly past the "hod" prefix to expose an off-by-one in the index range upper bound
    (103, "hoe", "Hoe", ["gardener"], [], 805306368),
    (104, "hodge", "Hodge", ["hedge witch"], ["HOST/hodge", "HTTP/hodge"], 805306369),
    # All-z prefix to exercise the last-character carry logic
    (105, "zz", "ZZ", ["zulu account"], [], 805306369),
    (106, "zza", "ZZA", ["zulu alpha"], ["HOST/zza"], 805306369),
    (107, "arya", "Arya", ["no one"], [], 805306370),
    # Shares an SPN value with 101 to create duplicate secondary-index keys across records
    (108, "bran", "Bran", ["three eyed raven"], ["HOST/winterfell"], 805306370),
]

ATTRIBUTES = {
    "sAMAccountName": "col_sam",
    "cn": "col_cn",
    "description": "col_desc",
    "servicePrincipalName": "col_spn",
    "accountType": "col_type",
}

INDEXED_ATTRIBUTES = {"sAMAccountName", "cn", "servicePrincipalName", "accountType"}
TEXT_SYNTAX = 12
INT_SYNTAX = 9


def _build_db(*, indexed: bool = True) -> FakeDB:
    records = [
        FakeRecord(None, dnt, dict(zip([c.name for c in COLUMNS], values, strict=False))) for dnt, *values in ACCOUNTS
    ]
    entries = {}
    for ldap_name, column_name in ATTRIBUTES.items():
        column = next(c for c in COLUMNS if c.name == column_name)
        entries[ldap_name] = AttributeEntry(
            dnt=-1,
            id=-1,
            name=ldap_name,
            column=column_name,
            syntax=TEXT_SYNTAX if column.is_text else INT_SYNTAX,
            om_syntax=None,
            om_object_class=None,
            is_single_valued=not column.is_multivalue,
            link_id=None,
            search_flags=None,
        )
    indexed_columns = {ATTRIBUTES[name] for name in INDEXED_ATTRIBUTES} if indexed else set()
    table = FakeTable(records, COLUMNS, indexed_columns)
    for record in records:
        record._table = table
    return FakeDB(table, FakeSchema(entries))


@pytest.fixture()
def db() -> FakeDB:
    return _build_db(indexed=True)


@pytest.fixture()
def scan_db() -> FakeDB:
    # Same dataset, but no attribute has an index: every query must fall back to a full table scan
    return _build_db(indexed=False)


# ---------------------------------------------------------------------------
# Independent reference filter interpreter (does not import any Query logic)
# ---------------------------------------------------------------------------


def _match_simple(attribute: str, value: str, record: FakeRecord) -> bool:
    column = ATTRIBUTES[attribute]
    record_value = record.get(column)
    if record_value is None:
        return False

    is_wildcard = "*" in value
    if is_wildcard:
        pattern = re.compile(fnmatch.translate(value), re.IGNORECASE)
        candidates = record_value if isinstance(record_value, list) else [record_value]
        return any(isinstance(candidate, str) and pattern.match(candidate) for candidate in candidates)

    candidates = record_value if isinstance(record_value, list) else [record_value]
    return value in [str(candidate) for candidate in candidates]


def _evaluate(node: SearchFilter, record: FakeRecord) -> bool:
    if node.is_nested():
        if node.operator.value == "&":
            return all(_evaluate(child, record) for child in node.children)
        if node.operator.value == "|":
            return any(_evaluate(child, record) for child in node.children)
        raise NotImplementedError(node.operator)
    return _match_simple(node.attribute, node.value, record)


def reference_matches(db: FakeDB, query: str) -> set[int]:
    """Expected set of DNTs computed by the independent reference interpreter."""
    parsed = SearchFilter.parse(query, optimize=False)
    return {record.dnt for record in db.data.table.rows if _evaluate(parsed, record)}


def engine_matches(db: FakeDB, query: str, *, optimize: bool) -> set[int]:
    return {record.dnt for record in Query(db, query, optimize=optimize).process()}


# ---------------------------------------------------------------------------
# Equivalence matrix
# ---------------------------------------------------------------------------

QUERIES = [
    # indexed attribute, exact match
    "(sAMAccountName=hodor)",
    # indexed attribute, tail wildcard
    "(sAMAccountName=hod*)",
    "(sAMAccountName=zz*)",
    # presence filter on an indexed attribute
    "(sAMAccountName=*)",
    # middle wildcard (full index scan + pattern filter)
    "(sAMAccountName=*dor)",
    "(sAMAccountName=h*d*)",
    # non-indexed attribute (full table scan), multivalue
    "(description=loyal*)",
    "(description=*one*)",
    "(description=*)",
    # indexed multivalue attribute: exact, tail and middle wildcard plus presence
    "(servicePrincipalName=HOST/winterfell)",
    "(servicePrincipalName=HOST*)",
    "(servicePrincipalName=*winterfell*)",
    "(servicePrincipalName=*)",
    # indexed integer attribute, exact match
    "(accountType=805306368)",
    # AND conditions in both orders, mixing indexed and non-indexed attributes
    "(&(sAMAccountName=hod*)(description=loyal*))",
    "(&(description=loyal*)(sAMAccountName=hod*))",
    # OR with overlapping branches (duplicate hits must be removed)
    "(|(sAMAccountName=hodor)(cn=Hodor))",
    "(|(sAMAccountName=h*)(servicePrincipalName=HOST*))",
    # Nested AND inside OR
    "(|(&(sAMAccountName=hodor)(accountType=805306368))(sAMAccountName=arya))",
]


@pytest.mark.parametrize("query", QUERIES)
def test_optimized_matches_reference(db: FakeDB, query: str) -> None:
    expected = reference_matches(db, query)
    assert engine_matches(db, query, optimize=True) == expected


@pytest.mark.parametrize("query", QUERIES)
def test_full_scan_matches_reference(scan_db: FakeDB, query: str) -> None:
    expected = reference_matches(scan_db, query)
    assert engine_matches(scan_db, query, optimize=True) == expected


@pytest.mark.parametrize("query", QUERIES)
def test_optimization_and_condition_order_do_not_change_hits(db: FakeDB, query: str) -> None:
    optimized = engine_matches(db, query, optimize=True)
    unoptimized = engine_matches(db, query, optimize=False)
    expected = reference_matches(db, query)
    assert optimized == unoptimized == expected


def test_index_range_upper_bound_does_not_take_one_extra_record(db: FakeDB) -> None:
    # "hod*" must match hodor/hodora/hodge but never "hoe", the record immediately past the range
    assert engine_matches(db, "(sAMAccountName=hod*)", optimize=True) == {101, 102, 104}
    # The all-z carry case must still include both zulu accounts
    assert engine_matches(db, "(sAMAccountName=zz*)", optimize=True) == {105, 106}


def test_or_deduplicates_overlapping_hits(db: FakeDB) -> None:
    records = list(Query(db, "(|(sAMAccountName=hodor)(cn=Hodor))").process())
    assert [record.dnt for record in records] == [101]


def test_multivalued_index_deduplicates_within_one_branch(db: FakeDB) -> None:
    # DNT 101 and 108 both carry HOST/winterfell; each must be reported exactly once even though the
    # secondary index has one entry per SPN value
    records = list(Query(db, "(servicePrincipalName=HOST/winterfell)").process())
    assert sorted(record.dnt for record in records) == [101, 108]


def test_encoded_values_use_the_same_comparison_rules_as_stored_keys(db: FakeDB) -> None:
    # Stored keys are uppercased; a lowercase exact query and an uppercase query must hit identically
    assert engine_matches(db, "(cn=hodor)", optimize=True) == {101}
    assert engine_matches(db, "(cn=HODOR)", optimize=True) == {101}


def test_unsupported_filters_are_errors_not_empty_results(db: FakeDB) -> None:
    for query in (
        "(sAMAccountName>=hodor)",
        "(sAMAccountName~=hodor)",
        "(!(sAMAccountName=hodor))",
        "(accountType=805*)",
        "(unknownAttribute=value)",
        "(&(sAMAccountName=hodor)(unknownAttribute=value))",
        "(|(unknownAttribute=value)(sAMAccountName=hodor))",
    ):
        with pytest.raises((NotImplementedError, ValueError)):
            list(Query(db, query).process())


def test_index_reduces_records_accessed(db: FakeDB, scan_db: FakeDB) -> None:
    query = "(sAMAccountName=hod*)"

    # Full scan touches every record in the table
    list(Query(scan_db, query).process())
    full_scan_accesses = scan_db.data.table.access_count
    assert full_scan_accesses == len(ACCOUNTS)

    # The indexed range scan must not visit every record
    indexed_path = list(Query(db, query).process())
    range_entries_visited = _count_index_entries_visited(db, query)
    assert {record.dnt for record in indexed_path} == reference_matches(db, query)
    assert range_entries_visited < full_scan_accesses


def _count_index_entries_visited(db: FakeDB, query: str) -> int:
    """Count the index entries inspected by a tail-wildcard range scan."""
    from dissect.database.ese.ntds import query as query_module

    original = query_module._process_wildcard_tail
    visited = 0

    def counting(index: FakeIndex, column: str, value: str) -> Iterator[Record]:
        nonlocal visited
        for record in original(index, column, value):
            visited += 1
            yield record

    query_module._process_wildcard_tail = counting
    try:
        list(Query(db, query).process())
    finally:
        query_module._process_wildcard_tail = original
    return visited


def test_increment_last_char_carry() -> None:
    assert _increment_last_char("hod") == "hoe"
    assert _increment_last_char("zz") is None
    assert _increment_last_char("") is None
