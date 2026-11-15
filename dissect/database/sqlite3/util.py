from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.database.sqlite3.exception import InvalidSQL

if TYPE_CHECKING:
    from collections.abc import Iterator


def split_sql_list(sql: str) -> Iterator[str]:
    """Split a string on comma's (``,``) while ignoring any comma's contained
    within an arbitrary level of nested braces (``( )``).
    """
    level = 0
    comment = 0
    quote = None
    line_buf = ""

    for char in sql:
        if not quote and char == "-" and comment != 2:
            comment += 1
        elif comment == 2 and char == "\n":
            comment = 0
        elif comment != 2:
            if comment == 1:
                line_buf += "-"
                comment = 0

            if char == "(":
                level += 1
                line_buf += char
            elif char == ")":
                level -= 1
                line_buf += char
            elif char == "," and level == 0:
                yield line_buf.strip()
                line_buf = ""
            else:
                if char in ('"', "'", "`"):
                    if not quote:
                        quote = char
                    elif char == quote:
                        quote = None
                line_buf += char

    if level != 0:
        bracket_type = "(" if level < 0 else ")"
        raise InvalidSQL(f"Not a valid SQL list definition: {sql!r} missing {level} {bracket_type}'s")

    if line_buf:
        yield line_buf.strip()


def parse_table_columns_constraints(sql: str) -> tuple[str | None, list[str], list[str]]:
    """Parse ``SQL CREATE TABLE`` statements and return the primary key, column definitions and table constraints.

    The retrun value is a tuple of:

    (primary_key, [column, ...], [table_constraint, ...])
    where column is a tuple of:
    (column_name, column_type_constraint)
    """
    primary_key = None
    columns = []
    table_constraints = []

    # The column definitions and table constraints are a comma separated list
    # of definitions between the outer most `(...)' in the CREATE TABLE
    # statement, e.g.:
    # CREATE TABLE foo (col1, col2, CONSTRAINT)
    #
    # See https://sqlite.org/lang_createtable.html and
    # https://sqlite.org/syntax/create-table-stmt.html
    #
    # re.DOTALL is needed since the SQL statement may be formatted using
    # `\n' and we want the newline to be regarded as any other character.
    column_sql = re.search(r"\((.+)\)", sql, flags=re.DOTALL)
    if not column_sql:
        raise InvalidSQL(
            f"Not a valid CREATE TABLE definition: no column definitions or table constraints found in {sql!r}"
        )

    for column_def in split_sql_list(column_sql.groups()[0]):
        column_name, column_type_constraint = split_column_def(sql, column_def)

        if column_name.upper() == "PRIMARY":
            primary_key = get_primary_key_from_constraint(column_type_constraint, column_def, sql)
        elif "PRIMARY KEY" in column_type_constraint.upper():
            primary_key = column_name

        if "(" in column_def and column_name.upper().startswith(
            (
                "CONSTRAINT",
                "UNIQUE",
                "CHECK",
                "FOREIGN",
                "PRIMARY",
            )
        ):
            table_constraints.append(column_def)

        else:
            columns.append((column_name, column_type_constraint))

    return primary_key, columns, table_constraints


def split_column_def(sql: str, column_def: str) -> tuple[str, str]:
    """Splits the column definition to name and constraint."""
    if not column_def.strip():
        raise InvalidSQL(f"Not a valid CREATE TABLE definition: empty column definition in {sql!r}")

    return split_column_name(column_def)


def split_column_name(definition: str) -> tuple[str, str]:
    """Split a column (or primary key column) definition into the column name and the remainder.

    Handles quoted column names (``"..."``, ``'...'``, ``` ``...`` ``` and ``[...]``), including
    quoted names containing whitespace. Doubled quote characters inside a quoted name are
    unescaped.
    """
    definition = definition.strip()
    if not definition:
        return "", ""

    if definition[0] in ('"', "'", "`", "["):
        closer = "]" if definition[0] == "[" else definition[0]
        idx = 1
        while True:
            idx = definition.find(closer, idx)
            if idx == -1:
                # Unterminated quote, treat the remainder as the column name.
                return definition[1:], ""
            if closer != "]" and definition[idx + 1 : idx + 2] == closer:
                # Doubled quote character, this is an escaped quote inside the name.
                idx += 2
                continue
            break

        name = definition[1:idx]
        if closer != "]":
            name = name.replace(closer * 2, closer)
        return name, definition[idx + 1 :].strip()

    parts = definition.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def get_primary_key_columns_from_constraint(constraint: str) -> list[str]:
    """Return the ordered column names from a ``PRIMARY KEY (...)`` constraint definition.

    Handles compound primary keys and quoted column names, e.g. ``PRIMARY KEY ("key one", "key two")``
    returns ``["key one", "key two"]``.
    """
    primary_key_sql = re.search(r"\((.+)\)", constraint, flags=re.DOTALL)
    if not primary_key_sql:
        raise InvalidSQL(f"Not a valid PRIMARY KEY constraint definition: {constraint!r}")

    matched_group = primary_key_sql.groups()[0]
    return [name for name in (split_column_name(def_)[0] for def_ in split_sql_list(matched_group)) if name]


def get_primary_key_from_constraint(column_type_constraint: str, column_def: str, sql: str) -> str | None:
    """Finds a primary key from sql string."""
    primary_key = None

    try:
        primary_key_columns = get_primary_key_columns_from_constraint(column_type_constraint)
    except InvalidSQL:
        raise InvalidSQL(
            f"Not a valid CREATE TABLE definition: invalid PRIMARY KEY table constraint {column_def!r} in {sql!r}"
        ) from None

    # We only handle single primary keys, no compound keys or expressions, so a single entry in the list consisting of
    # a single part. For example we parse ``id`` as a primary_key in the constraint ``PRIMARY KEY("id" AUTOINCREMENT)``.
    if len(primary_key_columns) == 1:
        primary_key = primary_key_columns[0]
    return primary_key
