from __future__ import annotations

from typing import Any
from unittest.mock import Mock

from dissect.database.sqlite3.sqlite3 import Column, Provenance, Row


def _cell(physical_values: list[Any]) -> Mock:
    cell = Mock()
    cell.values = physical_values
    cell.key = 1
    return cell


def _table(columns: list[Column], primary_key: str | None = None) -> Mock:
    table = Mock()
    table.columns = columns
    table.primary_key = primary_key
    table.name = "evidence"
    return table


def test_stored_explicit_null_distinct_from_synthesized_default() -> None:
    # A column with a DEFAULT: a physically present serial-type-0 NULL must be
    # reported as STORED, while a missing field must be reported as DEFAULT.
    columns = [
        Column("id", "INTEGER PRIMARY KEY"),
        Column("label", "TEXT"),
        Column("note", "TEXT DEFAULT 'legacy-note'"),
    ]
    table = _table(columns, primary_key="id")

    explicit_null = Row(table, _cell([None, "delta", None]))
    assert explicit_null.provenance("note") == Provenance.STORED
    assert explicit_null.get("note") is None

    missing_field = Row(table, _cell([None, "beta"]))
    assert missing_field.provenance("note") == Provenance.DEFAULT
    assert missing_field.get("note") == "legacy-note"


def test_missing_field_without_default_is_indeterminate_null() -> None:
    columns = [Column("id", "INTEGER PRIMARY KEY"), Column("label", "TEXT"), Column("added", "TEXT")]
    table = _table(columns, primary_key="id")
    row = Row(table, _cell([None, "before"]))
    # The added column has no field and no default; the NULL is a reader
    # convention and cannot be distinguished from an explicit NULL on disk.
    assert row.provenance("added") == Provenance.NULL
    assert row.get("added") is None


def test_rowid_alias_provenance() -> None:
    columns = [Column("id", "INTEGER PRIMARY KEY"), Column("label", "TEXT")]
    table = _table(columns, primary_key="id")
    row = Row(table, _cell([None, "alpha"]))
    assert row.provenance("id") == Provenance.ROWID
    assert row.get("id") == 1


def test_extra_physical_fields_are_unknown_not_misinterpreted() -> None:
    # A historical/newer record read through a smaller schema: extra physical
    # fields must not be relabeled as known columns.
    columns = [Column("id", "INTEGER PRIMARY KEY"), Column("label", "TEXT")]
    table = _table(columns, primary_key="id")
    row = Row(table, _cell([None, "alpha", "alpha-rewritten", 7]))
    assert row._unknowns == ["alpha-rewritten", 7]
    assert set(row._provenance.values()) <= {Provenance.ROWID, Provenance.STORED}


def test_explain_reports_value_and_provenance() -> None:
    columns = [Column("id", "INTEGER PRIMARY KEY"), Column("note", "TEXT DEFAULT 'd'")]
    table = _table(columns, primary_key="id")
    row = Row(table, _cell([None]))
    explained = row.explain()
    assert explained["note"] == {"value": "d", "provenance": Provenance.DEFAULT}
    assert explained["id"]["provenance"] == Provenance.ROWID


def test_blob_literal_default() -> None:
    column = Column("payload", "BLOB DEFAULT x'2a2b'")
    assert column.default_value == b"*+"
    assert column.default_is_expression is False


def test_parenthesized_constant_is_not_expression() -> None:
    for description, expected in [
        ("TEXT DEFAULT ('XX')", "XX"),
        ("INTEGER DEFAULT (0)", 0),
        ("DEFAULT (TRUE)", True),
    ]:
        column = Column("c", description)
        assert column.default_value == expected
        assert column.default_is_expression is False


def test_non_constant_expression_is_flagged() -> None:
    column = Column("tag", "TEXT DEFAULT (upper('z'))")
    # The expression cannot be evaluated from schema text; it is flagged so the
    # reader never presents a parsed fragment as the real default.
    assert column.default_is_expression is True
    assert column.default_value is None


def test_blob_and_expression_inside_tokenizer_edge_cases() -> None:
    # These previously broke the regex tokenizer (split on quote/space).
    blob = Column("c", "INTEGER DEFAULT x'1f2f' NOT NULL")
    assert blob.default_value == bytes.fromhex("1f2f")
    nested = Column("c", "DEFAULT (something == (DATA == (BETA not NULL)))")
    assert nested.default_is_expression is True
    assert nested.default_value is None
