"""Tests for the opt-in origin-graded dict cursors.

These tests build result packets locally (no server needed) and feed them
through OriginDictCursor / OriginSSDictCursor to verify that the public
grading follows the actual field origin (org_table/org_name) rather than
the display key, and that it is re-evaluated when a call advances to a
second result set.
"""

import struct
import unittest

from pymysql.cursors import (
    GRADE_APPROVED,
    GRADE_PENDING,
    OriginDictCursor,
    OriginSSDictCursor,
    PublicRow,
)
from pymysql.constants import FIELD_TYPE
from pymysql.protocol import FieldDescriptorPacket

PUBLIC_ORIGINS = frozenset(
    {
        ("orders", "id"),
        ("orders", "total"),
        ("users", "id"),
    }
)


def _lcs(value):
    data = value.encode("utf8")
    return bytes([len(data)]) + data


def make_field(name, org_name, table_name, org_table):
    """Build a FieldDescriptorPacket like the server would send."""
    data = (
        _lcs("def")  # catalog
        + _lcs("report")  # db
        + _lcs(table_name)
        + _lcs(org_table)
        + _lcs(name)
        + _lcs(org_name)
        + struct.pack("<xHIBHBxx", 33, 11, FIELD_TYPE.VAR_STRING, 0, 0)
    )
    return FieldDescriptorPacket(data, "utf8")


class FakeResult:
    """Minimal stand-in for connections.MySQLResult."""

    def __init__(self, fields, rows, has_next=False):
        self.fields = fields
        self.rows = rows
        self.has_next = has_next
        self.affected_rows = len(rows)
        self.insert_id = None
        self.warning_count = 0
        self.description = tuple(f.description() for f in fields)
        self.unbuffered_active = False
        self._unread_rows = list(rows)

    def _read_rowdata_packet_unbuffered(self):
        if not self._unread_rows:
            self.unbuffered_active = False
            return None
        return self._unread_rows.pop(0)

    def _finish_unbuffered_query(self):
        self.unbuffered_active = False
        self._unread_rows = []


class FakeConnection:
    """Serves a queue of locally built result sets."""

    def __init__(self, results):
        self._pending_results = list(results)
        self._result = None

    def query(self, q, unbuffered=False):
        self._result = self._pending_results.pop(0)

    def next_result(self, unbuffered=False):
        self._result = self._pending_results.pop(0)


def make_cursor(cursor_type, results):
    class ReportCursor(cursor_type):
        public_origins = PUBLIC_ORIGINS

    conn = FakeConnection(results)
    cursor = ReportCursor(conn)
    cursor.execute("SELECT ... ; SELECT ...")
    return cursor


def build_result_sets():
    """Two result sets over same-named columns from two tables.

    Set 1 orders the duplicate `id` columns as orders then users; set 2
    swaps them and re-sources the `order_total` display key to a
    non-public origin.
    """
    fields1 = [
        # A plainly attributable normal column.
        make_field("id", "id", "orders", "orders"),
        # Duplicate name, reached through a table alias -> display key "u.id".
        make_field("id", "id", "u", "users"),
        # SQL alias as display key, real origin is orders.total.
        make_field("order_total", "total", "o", "orders"),
        # Confirmed non-public origin -> excluded from the public result.
        make_field("secret", "password", "u", "users"),
        # Expression: metadata cannot confirm an origin -> pending.
        make_field("expr", "", "", ""),
    ]
    rows1 = [(1, 7, 100, "pw-hash", "x")]

    fields2 = [
        # Same display key "id", now sourced from users.
        make_field("id", "id", "users", "users"),
        # Swapped duplicate: orders.id now gets the qualified display key.
        make_field("id", "id", "orders", "orders"),
        # Same display key as in set 1, but a new non-public origin.
        make_field("order_total", "total", "u", "users"),
        make_field("expr", "", "", ""),
    ]
    rows2 = [(7, 1, 999, "y")]

    return (
        FakeResult(fields1, rows1, has_next=True),
        FakeResult(fields2, rows2),
    )


EXPECTED_CLASSIFICATION_1 = {
    "id": GRADE_APPROVED,
    "u.id": GRADE_APPROVED,
    "order_total": GRADE_APPROVED,
    "expr": GRADE_PENDING,
}
EXPECTED_CLASSIFICATION_2 = {
    "id": GRADE_APPROVED,
    "orders.id": GRADE_APPROVED,
    "expr": GRADE_PENDING,
}


class OriginCursorTestMixin:
    cursor_type = None

    def setUp(self):
        self.result_sets = build_result_sets()
        self.cursor = make_cursor(self.cursor_type, self.result_sets)

    def fetch_all_current_set(self):
        raise NotImplementedError

    def check_row(self, row, expected, approved, pending):
        self.assertIsInstance(row, PublicRow)
        self.assertEqual(expected, dict(row))
        self.assertEqual(approved, row.approved_keys)
        self.assertEqual(pending, row.pending_keys)

    def test_first_result_set_grading(self):
        self.assertEqual(EXPECTED_CLASSIFICATION_1, self.cursor.field_classification)
        rows = self.fetch_all_current_set()
        self.assertEqual(1, len(rows))
        self.check_row(
            rows[0],
            {"id": 1, "u.id": 7, "order_total": 100, "expr": "x"},
            ("id", "u.id", "order_total"),
            ("expr",),
        )

    def test_second_result_set_regrades_same_named_columns(self):
        self.fetch_all_current_set()
        self.assertTrue(self.cursor.nextset())
        self.assertEqual(EXPECTED_CLASSIFICATION_2, self.cursor.field_classification)
        rows = self.fetch_all_current_set()
        self.assertEqual(1, len(rows))
        # "id" now holds the users.id value, orders.id moved to the
        # qualified display key, and "order_total" was re-sourced to a
        # non-public origin and dropped.
        self.check_row(
            rows[0],
            {"id": 7, "orders.id": 1, "expr": "y"},
            ("id", "orders.id"),
            ("expr",),
        )
        self.assertIsNone(self.cursor.nextset())


class TestOriginDictCursor(OriginCursorTestMixin, unittest.TestCase):
    cursor_type = OriginDictCursor

    def fetch_all_current_set(self):
        return self.cursor.fetchall()


class TestOriginSSDictCursor(OriginCursorTestMixin, unittest.TestCase):
    cursor_type = OriginSSDictCursor

    def fetch_all_current_set(self):
        return list(self.cursor.fetchall_unbuffered())


if __name__ == "__main__":
    unittest.main()
