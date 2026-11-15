from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.database.sqlite3.exception import InvalidSQL

if TYPE_CHECKING:
    from collections.abc import Iterator

# Keywords that start a column constraint in a column definition.
COLUMN_CONSTRAINT_KEYWORDS = frozenset(
    {
        "AS",
        "CHECK",
        "COLLATE",
        "CONSTRAINT",
        "DEFAULT",
        "GENERATED",
        "NOT",
        "PRIMARY",
        "REFERENCES",
        "UNIQUE",
    }
)

TABLE_CONSTRAINT_KEYWORDS = frozenset({"CHECK", "FOREIGN", "PRIMARY", "UNIQUE"})

# Opening and closing quote characters for SQLite identifiers and strings.
QUOTE_CHARS = {
    '"': '"',
    "'": "'",
    "`": "`",
    "[": "]",
}


@dataclass
class ColumnDefinition:
    """The declaration of a single table column."""

    name: str
    type: str = ""
    primary_key: bool = False
    primary_key_desc: bool = False
    generated: bool = False
    virtual_generated: bool = False


@dataclass
class TableDefinition:
    """The parts of a ``CREATE TABLE`` statement that are relevant for reading records."""

    columns: list[tuple[str, str]] = field(default_factory=list)
    column_definitions: list[ColumnDefinition] = field(default_factory=list)
    primary_key: list[str] = field(default_factory=list)
    table_constraints: list[str] = field(default_factory=list)
    without_rowid: bool = False
    rowid_alias: str | None = None


@dataclass
class Token:
    """A single token from a SQL definition."""

    kind: str
    value: str
    start: int
    end: int
    depth: int = 0
    quoted: bool = False


def split_sql_list(sql: str) -> Iterator[str]:
    """Split a string on comma's (``,``) while ignoring any comma's contained
    within an arbitrary level of nested braces (``( )``) or quotes.
    """
    level = 0
    quote = None
    quote_close = None
    line_buf = ""
    i = 0
    length = len(sql)

    while i < length:
        char = sql[i]

        if quote:
            line_buf += char

            if char == quote_close:
                # A doubled quote is an escaped quote inside an identifier or string.
                if quote_close != "]" and i + 1 < length and sql[i + 1] == quote_close:
                    line_buf += sql[i + 1]
                    i += 2
                    continue
                quote = None
                quote_close = None

            i += 1
            continue

        if char == "-" and i + 1 < length and sql[i + 1] == "-":
            newline = sql.find("\n", i + 2)
            if newline == -1:
                break
            i = newline + 1
            continue

        if char == "/" and i + 1 < length and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue

        if char in QUOTE_CHARS:
            quote = char
            quote_close = QUOTE_CHARS[char]
            line_buf += char
        elif char == "(":
            level += 1
            line_buf += char
        elif char == ")":
            level -= 1
            line_buf += char
        elif char == "," and level == 0:
            yield line_buf.strip()
            line_buf = ""
        else:
            line_buf += char

        i += 1

    if level != 0:
        bracket_type = "(" if level < 0 else ")"
        raise InvalidSQL(f"Not a valid SQL list definition: {sql!r} missing {level} {bracket_type}'s")

    if line_buf:
        yield line_buf.strip()


def _scan_sql(sql: str) -> Iterator[tuple[int, str]]:
    """Yield ``(index, char)`` pairs for characters that are not part of a comment or quoted string."""
    quote = None
    i = 0
    length = len(sql)

    while i < length:
        char = sql[i]

        if quote:
            if char == quote:
                # A doubled quote is an escaped quote inside an identifier or string.
                if quote != "]" and i + 1 < length and sql[i + 1] == quote:
                    i += 2
                    continue
                quote = None
            i += 1
            continue

        if char in QUOTE_CHARS:
            quote = QUOTE_CHARS[char]
            i += 1
            continue

        if char == "-" and i + 1 < length and sql[i + 1] == "-":
            newline = sql.find("\n", i + 2)
            i = length if newline == -1 else newline + 1
            continue

        if char == "/" and i + 1 < length and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            i = length if end == -1 else end + 2
            continue

        yield i, char
        i += 1


def _find_table_body(sql: str) -> tuple[int, int]:
    """Return the start and end offsets of the outermost column definition list."""
    start = None
    level = 0
    end = None

    for idx, char in _scan_sql(sql):
        if char == "(":
            if start is None:
                start = idx
            level += 1
        elif char == ")":
            level -= 1
            if start is not None and level == 0:
                end = idx
                break

    if start is None or end is None:
        raise InvalidSQL(
            f"Not a valid CREATE TABLE definition: no column definitions or table constraints found in {sql!r}"
        )

    return start, end


def _tokenize(sql: str) -> list[Token]:
    """Tokenize a SQL definition into words, quoted identifiers and punctuation."""
    tokens = []
    depth = 0
    i = 0
    length = len(sql)

    while i < length:
        char = sql[i]

        if char.isspace():
            i += 1
            continue

        if char == "-" and i + 1 < length and sql[i + 1] == "-":
            newline = sql.find("\n", i + 2)
            i = length if newline == -1 else newline + 1
            continue

        if char == "/" and i + 1 < length and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            i = length if end == -1 else end + 2
            continue

        if char in QUOTE_CHARS:
            closer = QUOTE_CHARS[char]
            start = i
            i += 1
            value = []

            while i < length:
                if sql[i] == closer:
                    if closer != "]" and i + 1 < length and sql[i + 1] == closer:
                        value.append(closer)
                        i += 2
                        continue
                    i += 1
                    break

                value.append(sql[i])
                i += 1
            else:
                raise InvalidSQL(f"Not a valid SQL definition: unterminated quote in {sql!r}")

            tokens.append(Token("identifier", "".join(value), start, i, depth, quoted=True))
            continue

        if char == "(":
            tokens.append(Token("punct", char, i, i + 1, depth))
            depth += 1
            i += 1
            continue

        if char == ")":
            depth -= 1
            tokens.append(Token("punct", char, i, i + 1, depth))
            i += 1
            continue

        if char == ",":
            tokens.append(Token("punct", char, i, i + 1, depth))
            i += 1
            continue

        start = i
        while (
            i < length
            and not sql[i].isspace()
            and sql[i] not in "(),"
            and sql[i] not in QUOTE_CHARS
            and not (sql[i] == "-" and i + 1 < length and sql[i + 1] == "-")
            and not (sql[i] == "/" and i + 1 < length and sql[i + 1] == "*")
        ):
            i += 1

        tokens.append(Token("word", sql[start:i], start, i, depth))

    return tokens


def _parse_identifier(sql: str) -> tuple[str | None, int]:
    """Parse an identifier at the start of ``sql`` and return its value and end offset."""
    tokens = _tokenize(sql)
    if not tokens:
        return None, 0

    token = tokens[0]
    if sql[: token.start].strip():
        return None, 0

    if token.kind == "identifier":
        return token.value, token.end

    if token.kind != "word":
        return None, 0

    return token.value, token.end


def _find_matching_paren(tokens: list[Token], index: int) -> int:
    """Return the index of the closing parenthesis matching the opening parenthesis at ``index``."""
    depth = tokens[index].depth
    for j in range(index + 1, len(tokens)):
        if tokens[j].kind == "punct" and tokens[j].value == ")" and tokens[j].depth == depth:
            return j

    raise InvalidSQL("Not a valid SQL definition: unmatched parenthesis")


def _split_token_group(tokens: list[Token]) -> Iterator[list[Token]]:
    """Split tokens on commas at the depth of the first token."""
    group = []
    base_depth = tokens[0].depth if tokens else 0

    for token in tokens:
        if token.kind == "punct" and token.value == "," and token.depth == base_depth:
            if group:
                yield group
            group = []
        else:
            group.append(token)

    if group:
        yield group


def _parse_indexed_column(tokens: list[Token]) -> str | None:
    """Parse an indexed-column definition and return the column name, if it is not an expression."""
    if not tokens:
        return None

    token = tokens[0]
    if token.kind == "identifier":
        return token.value

    if token.kind != "word":
        return None

    if len(tokens) > 1 and tokens[1].kind == "punct" and tokens[1].value == "(":
        return None

    return token.value


def _find_table_primary_key(tokens: list[Token]) -> list[str]:
    """Find a table-level ``PRIMARY KEY`` constraint and return its columns in key order."""
    for i in range(len(tokens) - 1):
        token = tokens[i]
        if token.depth != 0 or token.kind != "word" or token.quoted or token.value.upper() != "PRIMARY":
            continue

        key_token = tokens[i + 1]
        if key_token.depth != 0 or key_token.kind != "word" or key_token.quoted:
            continue
        if key_token.value.upper() != "KEY":
            continue

        if i + 2 >= len(tokens) or tokens[i + 2].kind != "punct" or tokens[i + 2].value != "(":
            raise InvalidSQL("Not a valid SQL definition: PRIMARY KEY without column list")

        close = _find_matching_paren(tokens, i + 2)
        columns = []
        for indexed_column in _split_token_group(tokens[i + 3 : close]):
            name = _parse_indexed_column(indexed_column)
            if name is not None:
                columns.append(name)

        return columns

    return []


def _parse_generated_column(tokens: list[Token]) -> tuple[bool, bool]:
    """Return whether a column is generated and whether it is VIRTUAL.

    Virtual generated columns are not stored in the record, whereas STORED generated columns are.
    """
    for i, token in enumerate(tokens):
        if token.depth != 0 or token.kind != "word" or token.quoted or token.value.upper() != "GENERATED":
            continue

        if i + 1 >= len(tokens) or tokens[i + 1].value.upper() != "ALWAYS":
            continue

        virtual = False
        for later in tokens[i + 1 :]:
            if later.depth != 0 or later.kind != "word" or later.quoted:
                continue
            if later.value.upper() == "VIRTUAL":
                virtual = True
            elif later.value.upper() == "STORED":
                virtual = False

        return True, virtual

    return False, False


def _parse_column_definition(column_def: str, tokens: list[Token], name_end: int) -> ColumnDefinition:
    """Parse the parts of a column definition that affect record layout."""
    type_tokens = []
    for token in tokens:
        if token.start < name_end:
            continue

        if (
            token.depth == 0
            and token.kind == "word"
            and not token.quoted
            and token.value.upper() in COLUMN_CONSTRAINT_KEYWORDS
        ):
            break

        type_tokens.append(token)

    column_type = ""
    if type_tokens:
        if len(type_tokens) == 1 and type_tokens[0].kind == "identifier":
            column_type = type_tokens[0].value
        else:
            column_type = column_def[type_tokens[0].start : type_tokens[-1].end].strip()

    column_pk = False
    column_pk_desc = False
    for i in range(len(tokens) - 1):
        token = tokens[i]
        if token.depth != 0 or token.kind != "word" or token.quoted or token.value.upper() != "PRIMARY":
            continue

        key_token = tokens[i + 1]
        if key_token.depth != 0 or key_token.kind != "word" or key_token.quoted:
            continue
        if key_token.value.upper() != "KEY":
            continue

        column_pk = True
        if i + 2 < len(tokens):
            next_token = tokens[i + 2]
            column_pk_desc = (
                next_token.depth == 0
                and next_token.kind == "word"
                and not next_token.quoted
                and next_token.value.upper() == "DESC"
            )
        break

    generated, virtual_generated = _parse_generated_column(tokens)

    return ColumnDefinition(
        name="",
        type=column_type,
        primary_key=column_pk,
        primary_key_desc=column_pk_desc,
        generated=generated,
        virtual_generated=virtual_generated,
    )


def _is_table_constraint(keyword: str, tokens: list[Token]) -> bool:
    """Return whether a definition is a table constraint rather than a column definition."""
    if keyword == "CONSTRAINT":
        # CONSTRAINT <name> <constraint>, or the historical CONSTRAINT (...) form.
        if len(tokens) >= 2 and tokens[1].kind == "punct" and tokens[1].value == "(":
            return True

        return (
            len(tokens) >= 3
            and tokens[1].kind == "word"
            and not tokens[1].quoted
            and tokens[2].value.upper() in TABLE_CONSTRAINT_KEYWORDS
        )

    if keyword == "PRIMARY":
        return (
            len(tokens) >= 3
            and tokens[1].kind == "word"
            and tokens[1].value.upper() == "KEY"
            and tokens[2].kind == "punct"
            and tokens[2].value == "("
        )

    if keyword == "FOREIGN":
        return (
            len(tokens) >= 3
            and tokens[1].kind == "word"
            and tokens[1].value.upper() == "KEY"
            and tokens[2].kind == "punct"
            and tokens[2].value == "("
        )

    if keyword in ("CHECK", "UNIQUE"):
        return len(tokens) >= 2 and tokens[1].kind == "punct" and tokens[1].value == "("

    return False


def _has_without_rowid(sql: str) -> bool:
    tokens = _tokenize(sql)
    for i in range(len(tokens) - 1):
        first, second = tokens[i], tokens[i + 1]
        if (
            first.kind == "word"
            and not first.quoted
            and first.value.upper() == "WITHOUT"
            and second.kind == "word"
            and not second.quoted
            and second.value.upper() == "ROWID"
        ):
            return True

    return False


def parse_table_definition(sql: str) -> TableDefinition:
    """Parse a ``CREATE TABLE`` statement.

    Args:
        sql: The ``CREATE TABLE`` statement as stored in ``sqlite_master``.

    Returns:
        A :class:`TableDefinition` with the declared columns, primary key columns (in key order),
        table constraints and whether the table is a ``WITHOUT ROWID`` table.
    """
    definition = TableDefinition()
    start, end = _find_table_body(sql)

    column_info = {}

    for column_def in split_sql_list(sql[start + 1 : end]):
        tokens = _tokenize(column_def)
        if not tokens:
            continue

        first = tokens[0]
        keyword = first.value.upper() if first.kind == "word" and not first.quoted else ""

        if keyword and _is_table_constraint(keyword, tokens):
            definition.table_constraints.append(column_def)

            if keyword in ("CONSTRAINT", "PRIMARY"):
                columns = _find_table_primary_key(tokens)
                if columns:
                    definition.primary_key = columns

            continue

        name, name_end = _parse_identifier(column_def)
        if name is None:
            raise InvalidSQL(
                f"Not a valid CREATE TABLE definition: invalid column definition {column_def!r} in {sql!r}"
            )

        column_definition = _parse_column_definition(column_def, tokens, name_end)
        column_definition.name = name
        definition.columns.append((name, column_def[name_end:].strip()))
        definition.column_definitions.append(column_definition)
        column_info[name.lower()] = column_definition

        if column_definition.primary_key:
            definition.primary_key = [name]

    definition.without_rowid = _has_without_rowid(sql[end + 1 :])

    if not definition.without_rowid and len(definition.primary_key) == 1:
        primary_key = definition.primary_key[0]
        column_definition = column_info.get(primary_key.lower())
        if (
            column_definition is not None
            and column_definition.type.upper() == "INTEGER"
            and not (column_definition.primary_key and column_definition.primary_key_desc)
        ):
            definition.rowid_alias = primary_key

    return definition


def parse_table_columns_constraints(sql: str) -> tuple[str | None, list[tuple[str, str]], list[str]]:
    """Parse ``SQL CREATE TABLE`` statements and return the primary key, column definitions and table constraints.

    The retrun value is a tuple of:

    (primary_key, [column, ...], [table_constraint, ...])
    where column is a tuple of:
    (column_name, column_type_constraint)

    For a compound primary key, ``primary_key`` is ``None``. Use :func:`parse_table_definition` to
    retrieve the individual primary key columns in key order.
    """
    definition = parse_table_definition(sql)
    primary_key = definition.primary_key[0] if len(definition.primary_key) == 1 else None

    return primary_key, definition.columns, definition.table_constraints


def split_column_def(sql: str, column_def: str) -> tuple[str, str]:
    """Splits the column definition to name and constraint."""
    column_name, name_end = _parse_identifier(column_def)
    if column_name is None:
        raise InvalidSQL(f"Not a valid CREATE TABLE definition: empty column definition in {sql!r}")

    return column_name, column_def[name_end:].strip()


def get_primary_key_from_constraint(column_type_constraint: str, column_def: str, sql: str) -> str | None:
    """Finds a primary key from sql string."""
    primary_key = _find_table_primary_key(_tokenize(column_def))
    return primary_key[0] if len(primary_key) == 1 else None
