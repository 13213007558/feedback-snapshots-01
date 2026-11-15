from __future__ import annotations

import pytest

from dissect.database.sqlite3.util import parse_table_columns_constraints, parse_table_definition, split_sql_list

testdata = [
    pytest.param(
        "CREATE TABLE foo (column1, column2 INTEGER NOT NULL PRIMARY KEY)",
        (
            "column2",
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL PRIMARY KEY"),
            ],
            [],
        ),
        id="create-table-simple",
    ),
    pytest.param(
        "CREATE TABLE something (\n  column1 INTEGER NOT NULL,\n  column2 INTEGER NOT NULL,\n"
        "value,\n  PRIMARY KEY ( column1, column2)\n);",
        (
            None,
            [
                ("column1", "INTEGER NOT NULL"),
                ("column2", "INTEGER NOT NULL"),
                ("value", ""),
            ],
            [
                "PRIMARY KEY ( column1, column2)",
            ],
        ),
        id="create-table-constraint-pk",
    ),
    pytest.param(
        "GaRbAgE FoOoOoO ( \n\tcolumn1\n\tsome expression (with (nested (braces))), "
        "column2 (()), CONSTRAINT (with( some\n(braces\n)\n))\n)",
        (
            None,
            [
                ("column1", "some expression (with (nested (braces)))"),
                ("column2", "(())"),
            ],
            [
                "CONSTRAINT (with( some\n(braces\n)\n))",
            ],
        ),
        id="create-table-nested-braces",
    ),
    pytest.param(
        "CREATE TABLE bar (column1, column2 INTEGER NOT NULL, PRIMARY KEY ( column2 ))",
        (
            "column2",
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL"),
            ],
            [
                "PRIMARY KEY ( column2 )",
            ],
        ),
        id="create-table-empty-column-constraint-pk",
    ),
    pytest.param(
        "CREATE TABLE bla (column1, column2 INTEGER NOT NULL, PRIMARY KEY ( column1, column2 ))",
        (
            None,
            [
                ("column1", ""),
                ("column2", "INTEGER NOT NULL"),
            ],
            [
                "PRIMARY KEY ( column1, column2 )",
            ],
        ),
        id="create-table-empty-column-constraint-multiple-pk",
    ),
    pytest.param(
        "CREATE TABLE bla (userId, test, UNIQUE(userId, test))",
        (
            None,
            [
                ("userId", ""),
                ("test", ""),
            ],
            [
                "UNIQUE(userId, test)",
            ],
        ),
        id="create-table-unique-constraint",
    ),
    pytest.param(
        "CREATE TABLE something (\n  column1, -- comment\n  column2\n)",
        (
            None,
            [
                ("column1", ""),
                ("column2", ""),
            ],
            [],
        ),
        id="create-table-newline-comments",
    ),
    pytest.param(
        'CREATE TABLE foo (\n  "column-1",\n  "column--2", -- comment\n  "column-`-\'-3" -- comment, "column-\\"4"\n)',
        (
            None,
            [
                ("column-1", ""),
                ("column--2", ""),
                ("column-`-'-3", ""),
            ],
            [],
        ),
        id="create-table-newline-comments-quotes-backticks",
    ),
    # Windows Index database
    pytest.param(
        "CREATE TABLE TableName (Id INTEGER PRIMARY KEY, UniqueKey TEXT NOT NULL UNIQUE, Name TEXT NOT NULL)",
        (
            "Id",
            [
                ("Id", "INTEGER PRIMARY KEY"),
                ("UniqueKey", "TEXT NOT NULL UNIQUE"),  # <- this should not end up in the constraints list
                ("Name", "TEXT NOT NULL"),
            ],
            [],
        ),
        id="create-table-unique-in-column-name",
    ),
    # Mozilla Firefox moz_places
    pytest.param(
        "CREATE TABLE moz_places (   id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL , description TEXT, preview_image_url TEXT, origin_id INTEGER REFERENCES moz_origins(id))",  # noqa: E501
        (
            "id",
            [
                ("id", "INTEGER PRIMARY KEY"),
                ("url", "LONGVARCHAR"),
                ("title", "LONGVARCHAR"),
                ("rev_host", "LONGVARCHAR"),
                ("visit_count", "INTEGER DEFAULT 0"),
                ("hidden", "INTEGER DEFAULT 0 NOT NULL"),
                ("typed", "INTEGER DEFAULT 0 NOT NULL"),
                ("frecency", "INTEGER DEFAULT -1 NOT NULL"),
                ("last_visit_date", "INTEGER"),
                ("guid", "TEXT"),
                ("foreign_count", "INTEGER DEFAULT 0 NOT NULL"),  # <- this should not end up in the constraints list
                ("url_hash", "INTEGER DEFAULT 0 NOT NULL"),
                ("description", "TEXT"),
                ("preview_image_url", "TEXT"),
                ("origin_id", "INTEGER REFERENCES moz_origins(id)"),
            ],
            [],
        ),
        id="create-table-firefox-foreign-in-column-name",
    ),
    # Primary key constraint with multiple parts, but not a compound/composite constraint.
    pytest.param(
        'CREATE TABLE "example"("foo" INTEGER, "bar" TEXT NOT NULL, PRIMARY KEY("foo" AUTOINCREMENT))',
        (
            "foo",
            [
                ("foo", "INTEGER"),
                ("bar", "TEXT NOT NULL"),
            ],
            [
                'PRIMARY KEY("foo" AUTOINCREMENT)',
            ],
        ),
        id="primary-key-constraint-multiple-parts",
    ),
]


@pytest.mark.parametrize(("sql", "result"), testdata)
def test_parse_table_columns_constraints(sql: str, result: tuple) -> None:
    assert parse_table_columns_constraints(sql) == result


@pytest.mark.parametrize(
    ("sql", "columns", "primary_key", "without_rowid"),
    [
        pytest.param(
            "CREATE TABLE foo (payload TEXT, k INTEGER, extra TEXT, PRIMARY KEY (k)) WITHOUT ROWID",
            ["payload", "k", "extra"],
            ["k"],
            True,
            id="without-rowid-single-key",
        ),
        pytest.param(
            "CREATE TABLE foo (payload TEXT, k INTEGER PRIMARY KEY, extra TEXT) WITHOUT ROWID",
            ["payload", "k", "extra"],
            ["k"],
            True,
            id="without-rowid-column-key",
        ),
        pytest.param(
            'CREATE TABLE foo (note TEXT, "quoted key" INTEGER, body TEXT, PRIMARY KEY ("quoted key", note))'
            " WITHOUT ROWID",
            ["note", "quoted key", "body"],
            ["quoted key", "note"],
            True,
            id="without-rowid-quoted-column-name",
        ),
        pytest.param(
            'CREATE TABLE foo ("weird ""name" TEXT, z TEXT, PRIMARY KEY (z, "weird ""name")) WITHOUT ROWID',
            ['weird "name', "z"],
            ["z", 'weird "name'],
            True,
            id="without-rowid-escaped-quote",
        ),
        pytest.param(
            "CREATE TABLE foo (a TEXT, b INTEGER, c TEXT, PRIMARY KEY (b DESC, a ASC)) WITHOUT ROWID",
            ["a", "b", "c"],
            ["b", "a"],
            True,
            id="without-rowid-key-order-and-sort-order",
        ),
        pytest.param(
            "CREATE TABLE foo (a TEXT, b INTEGER DEFAULT 7, PRIMARY KEY (a)) WITHOUT ROWID, STRICT",
            ["a", "b"],
            ["a"],
            True,
            id="without-rowid-table-options",
        ),
        pytest.param(
            "CREATE TABLE foo (x INTEGER PRIMARY KEY, y TEXT)",
            ["x", "y"],
            ["x"],
            False,
            id="rowid-integer-primary-key",
        ),
        pytest.param(
            "CREATE TABLE foo (x INTEGER, y TEXT, PRIMARY KEY (x DESC))",
            ["x", "y"],
            ["x"],
            False,
            id="rowid-table-constraint-desc",
        ),
        pytest.param(
            "CREATE TABLE foo (x INTEGER PRIMARY KEY DESC, y TEXT)",
            ["x", "y"],
            ["x"],
            False,
            id="rowid-column-constraint-desc",
        ),
    ],
)
def test_parse_table_definition(sql: str, columns: list[str], primary_key: list[str], without_rowid: bool) -> None:
    definition = parse_table_definition(sql)

    assert [column[0] for column in definition.columns] == columns
    assert definition.primary_key == primary_key
    assert definition.without_rowid is without_rowid


@pytest.mark.parametrize(
    ("sql", "rowid_alias"),
    [
        pytest.param("CREATE TABLE foo (id INTEGER PRIMARY KEY, value TEXT)", "id", id="integer-primary-key"),
        pytest.param("CREATE TABLE foo (value TEXT, id INTEGER, PRIMARY KEY (id))", "id", id="table-constraint"),
        pytest.param("CREATE TABLE foo (id INTEGER, value TEXT, PRIMARY KEY (id DESC))", "id", id="descending"),
        pytest.param("CREATE TABLE foo (id INTEGER, value TEXT, PRIMARY KEY (id COLLATE NOCASE))", "id", id="collate"),
        pytest.param("CREATE TABLE foo (id INT PRIMARY KEY, value TEXT)", None, id="not-integer-type"),
        pytest.param("CREATE TABLE foo (id INTEGER(8) PRIMARY KEY, value TEXT)", None, id="integer-with-size"),
        pytest.param("CREATE TABLE foo (id INTEGER PRIMARY KEY DESC, value TEXT)", None, id="column-desc"),
        pytest.param(
            "CREATE TABLE foo (id INTEGER PRIMARY KEY, value TEXT) WITHOUT ROWID",
            None,
            id="without-rowid",
        ),
        pytest.param("CREATE TABLE foo (a INTEGER, b INTEGER, PRIMARY KEY (a, b))", None, id="composite"),
    ],
)
def test_parse_table_definition_rowid_alias(sql: str, rowid_alias: str | None) -> None:
    assert parse_table_definition(sql).rowid_alias == rowid_alias


def test_split_sql_list_keeps_quoted_commas() -> None:
    assert list(split_sql_list('a, "b,c", (d, e), [f,g]')) == ["a", '"b,c"', "(d, e)", "[f,g]"]
