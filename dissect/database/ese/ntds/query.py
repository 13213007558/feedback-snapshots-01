from __future__ import annotations

import fnmatch
import logging
import re
from typing import TYPE_CHECKING

from dissect.database.ese.ntds.util import encode_value
from dissect.util.ldap import ComparisonOperator, LogicalOperator, SearchFilter

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.index import Index
    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.ntds.schema import AttributeEntry
    from dissect.database.ese.record import Record


log = logging.getLogger(__name__)

# Only equality filters can be translated into NTDS database queries. All other comparison
# operators are explicitly unsupported and must not be silently interpreted as equality.
_SUPPORTED_COMPARISON_OPERATORS = (ComparisonOperator.EQ,)


class Query:
    def __init__(self, db: Database, query: str, *, optimize: bool = True) -> None:
        self.db = db
        self.query = query
        self._filter = SearchFilter.parse(query, optimize=optimize)

    def process(self) -> Iterator[Object]:
        """Process the LDAP query against the NTDS database.

        Yields:
            Matching records from the NTDS database.
        """
        yield from self._process_query(self._filter)

    def _process_query(self, filter: SearchFilter, records: Iterator[Record] | None = None) -> Iterator[Record]:
        """Process LDAP query recursively, handling nested logical operations.

        Args:
            filter: The LDAP search filter to process.
            records: Optional iterable of records to filter instead of querying the database.

        Yields:
            Records matching the search filter.
        """
        if filter.is_nested():
            if filter.operator == LogicalOperator.AND:
                yield from self._process_and_operation(filter, records)
            elif filter.operator == LogicalOperator.OR:
                yield from self._process_or_operation(filter, records)
            else:
                # LogicalOperator.NOT has no index translation; do not pretend it matches nothing
                raise NotImplementedError(f"Unsupported logical operator in query: {filter.operator.value!r}")
        elif records is not None:
            yield from self._filter_records(filter, records)
        else:
            yield from self._query_database(filter)

    def _query_database(self, filter: SearchFilter) -> Iterator[Record]:
        """Execute a simple LDAP filter against the database.

        Args:
            filter: The LDAP search filter to execute.

        Yields:
            Records matching the filter.
        """
        # Validate attribute exists and get column mapping
        if (schema := self.db.data.schema.lookup_attribute(name=filter.attribute)) is None:
            raise ValueError(f"Attribute {filter.attribute!r} not found in the NTDS database")

        if filter.operator not in _SUPPORTED_COMPARISON_OPERATORS:
            raise NotImplementedError(
                f"Unsupported comparison operator {filter.operator.value!r} for attribute {filter.attribute!r}"
            )

        if "*" in filter.value and not _is_text_attribute(self.db, schema):
            # Wildcard matching is only defined for textual attributes, and index keys for other
            # types (integers, bytes, ...) cannot be range-scanned with a string prefix
            raise NotImplementedError(f"Wildcard filters are not supported for attribute {filter.attribute!r}")

        encoded_value = encode_value(self.db, schema, filter.value)
        has_wildcard = "*" in filter.value

        # Get the database index for this attribute
        if (index := self.db.data.table.find_index([schema.column])) is None:
            # If no index is available, we have to scan the entire table
            log.debug("No index found for attribute %s (%s), scanning entire table", filter.attribute, schema.column)
            yield from self._filter_records(filter, self.db.data.table.records())
        elif has_wildcard:
            if filter.value.endswith("*") and "*" not in filter.value[:-1]:
                yield from _process_wildcard_tail(index, schema.column, encoded_value)
            else:
                # For more complex wildcard patterns, we need to scan the index and apply the filter
                log.debug(
                    "Complex wildcard search for attribute %s (%s), scanning entire index",
                    filter.attribute,
                    schema.column,
                )
                yield from _unique_records(self._filter_records(filter, index.cursor()))
        else:
            # Exact match query
            yield from _unique_records(index.cursor().find_all(**{schema.column: encoded_value}))

    def _process_and_operation(self, filter: SearchFilter, records: Iterator[Record] | None) -> Iterator[Record]:
        """Process AND logical operation.

        Args:
            filter: The LDAP search filter with AND operator.
            records: Optional iterable of records to filter.

        Yields:
            Records matching all conditions in the AND operation.
        """
        if records is not None:
            records_to_process = records
            children_to_check = filter.children
        else:
            # Use the first child as base query, then filter with remaining children
            base_query, *remaining_children = filter.children
            records_to_process = self._process_query(base_query)
            children_to_check = remaining_children

        for record in records_to_process:
            if all(any(self._process_query(child, records=[record])) for child in children_to_check):
                yield record

    def _process_or_operation(self, filter: SearchFilter, records: Iterator[Record] | None) -> Iterator[Record]:
        """Process OR logical operation.

        Args:
            filter: The LDAP search filter with OR operator.
            records: Optional iterable of records to filter.

        Yields:
            Records matching any condition in the OR operation. A record is yielded at most once,
            even when multiple branches of the OR (or a multivalued index) match it.
        """
        records = list(records) if records is not None else None
        seen: set[bytes] = set()
        for child in filter.children:
            for record in self._process_query(child, records=records):
                key = record._node.key
                if key in seen:
                    continue
                seen.add(key)
                yield record

    def _filter_records(self, filter: SearchFilter, records: Iterator[Record]) -> Iterator[Record]:
        """Filter an iterable of records against a simple LDAP filter.

        Args:
            filter: The LDAP filter to apply.
            records: The iterable of records to filter.

        Yields:
            Records that match the filter criteria.
        """
        if (schema := self.db.data.schema.lookup_attribute(name=filter.attribute)) is None:
            # Keep the same error semantics as a direct database query instead of silently matching nothing
            raise ValueError(f"Attribute {filter.attribute!r} not found in the NTDS database")

        if filter.operator not in _SUPPORTED_COMPARISON_OPERATORS:
            raise NotImplementedError(
                f"Unsupported comparison operator {filter.operator.value!r} for attribute {filter.attribute!r}"
            )

        encoded_value = encode_value(self.db, schema, filter.value)
        re_encoded_value = None

        has_wildcard = "*" in filter.value and isinstance(encoded_value, str)
        if has_wildcard:
            re_encoded_value = re.compile(fnmatch.translate(encoded_value), re.IGNORECASE)

        for record in records:
            record_value = record.get(schema.column)

            if isinstance(record_value, list):
                # Currently assume that we can only search for single values, not lists
                if has_wildcard and record_value and isinstance(record_value[0], str):
                    if any(re_encoded_value.match(rv) for rv in record_value):
                        yield record
                elif encoded_value in record_value:
                    yield record

            elif (
                has_wildcard and isinstance(record_value, str) and re_encoded_value.match(record_value)
            ) or record_value == encoded_value:
                yield record


def _is_text_attribute(db: Database, schema: AttributeEntry) -> bool:
    """Return whether the attribute stores textual values that support wildcard matching.

    Prefers the actual ESE column type when the column exists in the data table, and falls back to
    the attribute syntax (``12`` is String(Unicode)) for attributes without a backing table column.

    Args:
        db: The associated NTDS database instance.
        schema: The LDAP attribute schema.

    Returns:
        Whether wildcard filters are meaningful for this attribute.
    """
    try:
        return db.data.table.column(schema.column).is_text
    except KeyError:
        return schema.syntax == 12


def _unique_records(records: Iterator[Record]) -> Iterator[Record]:
    """Yield each record only once, identified by its index node key.

    Secondary indexes of multivalued attributes contain one entry per attribute value, so a single
    record can be visited multiple times while scanning such an index.

    Args:
        records: The records to deduplicate.

    Yields:
        The input records without duplicates.
    """
    seen: set[bytes] = set()
    for record in records:
        key = record._node.key
        if key in seen:
            continue
        seen.add(key)
        yield record


def _process_wildcard_tail(index: Index, column: str, filter_value: str) -> Iterator[Record]:
    """Handle tail wildcard queries (for example ``hod*``) using an index range scan.

    The range boundaries are derived from the normalized index key bytes rather than the raw filter
    string, so text normalization (such as LCMapString sort keys for Unicode indexes) is applied with
    the exact same rules as when the indexed values were stored. Every candidate inside the range is
    still validated against the actual wildcard pattern, and multivalued indexes are deduplicated.

    Args:
        index: The database index to search.
        column: The indexed database column name.
        filter_value: The textual filter value containing a single trailing ``*``.

    Yields:
        Records matching the wildcard pattern.
    """
    pattern = re.compile(fnmatch.translate(filter_value), re.IGNORECASE)

    prefix = filter_value[:-1]
    start_key = index.make_key([prefix]) if prefix else None
    # Increment the raw prefix and let the index normalize the upper bound with the exact same key
    # encoding rules. Normalized sort keys (for example Unicode LCMapString keys) are not byte-prefix
    # composable, so manipulating the encoded bytes directly would produce an incorrect bound.
    # An empty prefix (the presence filter ``*``) covers the entire index and has no upper bound.
    end_value = _increment_last_char(prefix) if prefix else None
    # When no in-alphabet successor exists (for example an all-"z" prefix), there is no finite upper
    # bound: the scan runs to the end of the index and the wildcard pattern still filters precisely
    end_key = index.make_key([end_value]) if end_value is not None else None

    cursor = index.cursor()
    if prefix:
        cursor.seek_key(start_key)
    else:
        # A presence filter starts at the first entry of the index instead of seeking to an empty key
        cursor.reset()
        cursor._primary.first()
    raw_cursor = cursor._primary

    seen: set[bytes] = set()
    while True:
        # Both bounds are non-exact seeks expressed in normalized index keys, so comparing the
        # current node against the exclusive upper bound stays correct even when the bound key is
        # not itself present in the index
        if end_key is not None and raw_cursor.node().key >= end_key:
            break

        record = cursor.record()
        record_key = record._node.key
        if record_key not in seen:
            seen.add(record_key)
            record_value = record.get(column)
            values = record_value if isinstance(record_value, list) else [record_value]
            if any(isinstance(value, str) and pattern.match(value) for value in values):
                yield record

        if not raw_cursor.next():
            break


def _increment_last_char(value: str) -> str | None:
    """Increment the last character in a string to find the next lexicographically sortable key.

    The result is used as the raw input of an index range upper bound and is normalized together
    with the lower bound, so text normalization rules stay identical on both sides. The carry is
    case-aware to keep the successor within the same (upper- or lower-case) alphabet.

    Args:
        value: The string to increment.

    Returns:
        A new string with the last character incremented, or ``None`` when every character is already
        at the end of its alphabet (for example ``"zz"`` or ``"ZZ"``), in which case no in-alphabet
        successor exists.
    """
    characters = list(value)
    i = len(characters) - 1

    while i >= 0:
        char = characters[i]
        if "a" <= char < "z":
            characters[i] = chr(ord(char) + 1)
            return "".join(characters[: i + 1])
        if "A" <= char < "Z":
            characters[i] = chr(ord(char) + 1)
            return "".join(characters[: i + 1])
        i -= 1

    return None
