# Copyright 2025 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""External variable contract checking for parsed YARA rules.

YARA rules can read *external variables* supplied by the calling program.  The
caller is responsible for declaring each variable name together with its
runtime type, and a rule that treats, for example, a string variable as an
integer fails when YARA binds the externals rather than when the rule is
authored.  This module performs a limited, *static* contract check so that such
integration mistakes can be caught before a rule set is published.

The checker is intentionally conservative:

* It never evaluates a condition.  Only the static types of the supported
  expressions are derived.
* A correctly typed expression is not the same thing as an effective
  detection, and nothing here claims otherwise.
* Any expression shape that is not explicitly understood is reported as
  unsupported instead of being silently accepted.

The check distinguishes four namespaces:

1. external variables provided through an :class:`ExternalVariableContract`;
2. references to other rules;
3. fields reached through imported modules (for example ``pe.sections``);
4. loop local variables introduced by ``for ... in`` expressions.
"""
import enum
import logging

from plyara.core import Parser

logger = logging.getLogger(__name__)


class VariableType(enum.Enum):
    """The external variable types supported by YARA."""

    INTEGER = 'integer'
    STRING = 'string'
    BOOLEAN = 'boolean'
    FLOAT = 'float'


class ContractIssueCode(enum.Enum):
    """The categories of contract violations reported by the checker."""

    UNDECLARED_IDENTIFIER = 'undeclared_identifier'
    TYPE_CONFLICT = 'type_conflict'
    UNSUPPORTED_EXPRESSION = 'unsupported_expression'


class ContractSeverity(enum.Enum):
    """Severity of a reported issue.

    Every issue is an error because the checker fails closed: a rule carrying
    any issue is excluded from the verified list.
    """

    ERROR = 'error'


# Internal type lattice used while deriving expression types.
class _Type(enum.Enum):
    INTEGER = 'integer'
    STRING = 'string'
    BOOLEAN = 'boolean'
    FLOAT = 'float'
    REGEX = 'regex'
    STRING_REF = 'string_ref'
    RANGE = 'range'
    SET = 'set'
    UNKNOWN = 'unknown'


class _Typed:
    """An inferred type paired with the provenance needed for precise issues.

    Attributes:
        type: The derived :class:`_Type`.
        source: Where the type came from: ``'external'`` for a contract
            variable, ``'loop'`` for a loop local, ``'rule'`` for a rule
            reference, ``'module'`` for an imported-module expression, or
            ``'intrinsic'`` for literals and built-ins.
        name: The originating identifier when ``source`` is external or a loop
            local, otherwise ``None``.
        term_index: The term that introduced the typed value.
    """

    __slots__ = ('type', 'source', 'name', 'term_index')

    def __init__(self, type_, source='intrinsic', name=None, term_index=None):
        """Initialize a typed value."""
        self.type = type_
        self.source = source
        self.name = name
        self.term_index = term_index


def _intrinsic(type_, term_index=None):
    """Build a typed value with no external provenance."""
    return _Typed(type_, 'intrinsic', term_index=term_index)


_STRING_BUILTINS = {
    'string.concat', 'string.contains', 'string.endswith', 'string.equals',
    'string.icontains', 'string.iequals', 'string.iendswith', 'string.istartswith',
    'string.length', 'string.startswith', 'string.to_int', 'string.to_int_be',
    'string.count',
}
_INTEGER_BUILTINS = {
    'int8', 'int16', 'int32', 'int8be', 'int16be', 'int32be',
    'uint8', 'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be',
}
_INTEGER_MODULE_CALLS = {
    'math.count', 'math.deviation', 'math.in_range', 'math.max', 'math.means',
    'math.min', 'math.mode', 'math.percentage', 'math.serial_correlation',
    'math.sum', 'math.variance',
    'hash.md5', 'hash.sha1', 'hash.sha256', 'hash.checksum32', 'hash.crc32',
    'elf.type', 'elf.machine',
}
_STRING_MODULE_CALLS = {
    'magic.type', 'magic.mime_type', 'math.to_number',
}
_BOOLEAN_MODULE_CALLS = {
    'pe.exports', 'pe.imports', 'pe.is_dll', 'pe.is_64bit', 'pe.is_32bit',
    'pe.rva_to_offset', 'cuckoo.network.http',
}
_STRING_OPS = {
    'contains', 'icontains', 'startswith', 'istartswith', 'endswith',
    'iendswith', 'iequals', 'matches',
}
_ARITHMETIC_OPS = {'+', '-', '*', '\\', '%', '>>', '<<', '&', '|', '^'}
_COMPARISON_OPS = {'==', '!=', '>', '<', '>=', '<='}
_LOGICAL_OPS = {'and', 'or'}


class ContractIssue:
    """A single contract violation located inside a rule condition.

    Attributes:
        code: One of :class:`ContractIssueCode` describing the violation.
        rule_name: Name of the rule the issue belongs to.
        message: Human readable explanation of the violation.
        line: One-based line number within the parsed source, or ``None`` when
            the term could not be located in the raw condition text.
        column: One-based column number on ``line``, or ``None``.
        term: The condition term that triggered the issue.
        term_index: Zero-based index of the term in the rule's
            ``condition_terms`` list, or ``None`` for whole-expression issues.
        rationale: Explanation of how the derived type was reached.
    """

    def __init__(self, code, rule_name, message, line, column, term, term_index, rationale):
        """Initialize a contract issue."""
        self.code = code
        self.rule_name = rule_name
        self.message = message
        self.line = line
        self.column = column
        self.term = term
        self.term_index = term_index
        self.rationale = rationale

    def as_dict(self):
        """Return the issue as a JSON-serializable dictionary."""
        return {
            'code': self.code.value,
            'severity': ContractSeverity.ERROR.value,
            'rule_name': self.rule_name,
            'message': self.message,
            'line': self.line,
            'column': self.column,
            'term': self.term,
            'term_index': self.term_index,
            'rationale': self.rationale,
        }

    def __repr__(self):
        """Return an unambiguous representation of the issue."""
        location = f'{self.line}:{self.column}' if self.line else '?:?'
        return f'<ContractIssue {self.code.value} {self.rule_name}@{location}: {self.message}>'


class ExternalVariableContract:
    """The names and runtime types a calling program binds as externals.

    The contract is explicit: the caller supplies every variable name together
    with its type.  Nothing is guessed from the rule text.
    """

    def __init__(self, variables=None):
        """Initialize the contract.

        Args:
            variables: Optional mapping of external variable name to a
                :class:`VariableType` (or its value string).  Names are matched
                exactly as they appear in a YARA condition.
        """
        self._variables = dict()
        if variables:
            for name, variable_type in variables.items():
                self.declare(name, variable_type)

    def declare(self, name, variable_type):
        """Declare an external variable and its type.

        Args:
            name: The external variable identifier, for example ``my_ext``.
            variable_type: A :class:`VariableType` member or one of the strings
                ``'integer'``, ``'string'``, ``'boolean'`` or ``'float'``.

        Returns:
            ExternalVariableContract: The contract itself, allowing chaining.

        Raises:
            ValueError: If the name is empty or the type is unknown.
        """
        if not isinstance(name, str) or not name:
            raise ValueError('External variable name must be a non-empty string')

        if isinstance(variable_type, str):
            variable_type = VariableType(variable_type)
        if not isinstance(variable_type, VariableType):
            raise ValueError(f'Unknown external variable type: {variable_type!r}')

        internal = _Type(variable_type.value)
        if name in self._variables and self._variables[name] != internal:
            raise ValueError(f'Conflicting redeclaration of external variable {name!r}')
        self._variables[name] = internal
        return self

    @property
    def names(self):
        """Return the declared external variable names."""
        return set(self._variables)

    def type_of(self, name):
        """Return the internal type of an external variable, or ``None``."""
        return self._variables.get(name)

    def __contains__(self, name):
        """Return whether ``name`` is a declared external variable."""
        return name in self._variables

    def __len__(self):
        """Return the number of declared external variables."""
        return len(self._variables)


class TermLocator:
    """Map flat condition terms back to line and column positions.

    Plyara emits conditions as a flat list of terms without positions.  The raw
    condition text is still available on each parsed rule, so terms are located
    by re-scanning that text.  Comments inside a condition are skipped the same
    way Plyara skips them while tokenizing.
    """

    def __init__(self, raw_condition, rule_start_line, rule_stop_line=None):
        """Initialize the locator.

        Args:
            raw_condition: The rule's ``raw_condition`` text including the
                leading ``condition:`` marker.
            rule_start_line: The rule's ``start_line`` (the line of its
                ``rule`` keyword).
            rule_stop_line: The rule's ``stop_line`` (the closing-brace line).
                When omitted the start line is used, which is exact for
                single-line rules.
        """
        self._text = raw_condition or ''
        self._body = self._strip_marker(self._text)
        # Offset of the body within the retained raw condition text, used to
        # translate a body offset back into an offset of the full raw text.
        self._body_offset = len(self._text) - len(self._body)
        if rule_stop_line is None:
            rule_stop_line = rule_start_line
        self._stop_line = rule_stop_line
        # When the raw text ends with a newline the closing brace sits on its
        # own line below the last condition line; otherwise it shares the last
        # condition line.
        self._brace_on_own_line = self._text.endswith('\n')
        self._positions = self._scan(self._body)

    @staticmethod
    def _strip_marker(text):
        """Remove the leading ``condition:`` marker retained by Plyara."""
        marker = 'condition'
        if text.startswith(marker):
            rest = text[len(marker):]
            colon = rest.find(':')
            if colon != -1:
                return rest[colon + 1:]
        return text

    # Multi-character operators, longest first so the longest match wins.
    _MULTI_OPS = ('==', '!=', '>=', '<=', '>>', '<<', '..')
    _SINGLE_OPS = set('()[]{}.,:+-*\\%~^&|<>')
    _ID_START = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_')
    _ID_PART = _ID_START | set('0123456789.')

    @classmethod
    def _scan(cls, text):
        """Return the absolute offset of every non-comment, non-space token.

        The token boundaries mirror Plyara's condition lexer: dotted module
        paths stay in one identifier token, strings and regular expressions are
        single tokens, and multi-character operators are not split.
        """
        offsets = list()
        index = 0
        length = len(text)
        while index < length:
            char = text[index]
            if char.isspace():
                index += 1
                continue
            if char == '/' and index + 1 < length and text[index + 1] == '/':
                newline = text.find('\n', index)
                index = length if newline == -1 else newline
                continue
            if char == '/' and index + 1 < length and text[index + 1] == '*':
                end = text.find('*/', index + 2)
                index = length if end == -1 else end + 2
                continue

            offsets.append(index)

            if char == '"':
                index = cls._skip_quoted(text, index, length, '"')
                continue
            if char == '/':
                # A slash begins a regex unless it forms a shift operator.
                if text.startswith('//', index) or text.startswith('/*', index):
                    index += 1
                elif index + 1 < length and text[index + 1] in cls._ID_START | {'"'}:
                    index = cls._skip_regex(text, index, length)
                else:
                    index += 1
                continue
            if char in cls._ID_START:
                index += 1
                while index < length and text[index] in cls._ID_PART:
                    index += 1
                continue
            if char.isdigit():
                index = cls._skip_number(text, index, length)
                continue
            if char in ('$', '#', '@', '!'):
                multi = next((op for op in cls._MULTI_OPS if text.startswith(op, index)), None)
                if multi:
                    index += len(multi)
                    continue
                index += 1
                while index < length and (text[index].isalnum() or text[index] in '_*'):
                    index += 1
                continue
            matched = False
            for op in cls._MULTI_OPS:
                if text.startswith(op, index):
                    index += len(op)
                    matched = True
                    break
            if not matched:
                index += 1 if char in cls._SINGLE_OPS else 1
        return offsets

    @staticmethod
    def _skip_quoted(text, index, length, quote):
        """Advance past a quoted string token, honoring backslash escapes."""
        index += 1
        while index < length:
            if text[index] == '\\':
                index += 2
                continue
            if text[index] == quote:
                return index + 1
            index += 1
        return index

    @staticmethod
    def _skip_regex(text, index, length):
        """Advance past a regular expression token including its modifiers."""
        index += 1
        while index < length:
            if text[index] == '\\':
                index += 2
                continue
            if text[index] == '/':
                index += 1
                while index < length and text[index] in 'ins':
                    index += 1
                return index
            index += 1
        return index

    @staticmethod
    def _skip_number(text, index, length):
        """Advance past a numeric literal, including hex and ``KB`` sizes.

        A single decimal point is part of a floating point literal, but the two
        dots of a range operator (``..``) are left for the operator branch.
        """
        if text.startswith('0x', index):
            index += 2
            while index < length and text[index] in '0123456789abcdefABCDEF':
                index += 1
            return index
        while index < length and text[index].isdigit():
            index += 1
        if index < length and text[index] == '.' and not text.startswith('..', index):
            index += 1
            while index < length and text[index].isdigit():
                index += 1
        if index < length and text[index] in 'KM' and index + 1 < length and text[index + 1] == 'B':
            index += 2
        return index

    def locate(self, term_index):
        """Locate a term by its index in ``condition_terms``.

        Args:
            term_index: Zero-based index of the term.

        Returns:
            tuple: ``(line, column, offset)`` with a one-based absolute source
            line and a one-based column, or ``(None, None, None)`` when the term
            cannot be located.  The column is source-absolute for terms on a
            condition body line, and relative to the retained condition text
            when the body shares the ``condition:`` marker line.
        """
        if term_index < 0 or term_index >= len(self._positions):
            return None, None, None

        body_offset = self._positions[term_index]
        # Count newlines from the token to the end of the retained text.  The
        # token's line is the stop line minus that count.  When the condition
        # spans multiple lines but the closing brace shares the final condition
        # line, the stop line sits one line lower than the last retained line.
        newlines_after = self._body.count('\n', body_offset)
        line = self._stop_line - newlines_after
        if newlines_after and not self._brace_on_own_line:
            line -= 1

        # Columns are measured within the source line containing the token.
        # A newline before the token delimits the line inside the retained raw
        # text.  With no preceding newline the body shares the condition line,
        # and the marker prefix (everything up to the body offset) is included.
        absolute_offset = self._body_offset + body_offset
        last_newline = self._text.rfind('\n', 0, absolute_offset)
        if last_newline != -1:
            column = absolute_offset - last_newline
        else:
            column = absolute_offset + 1
        return line, column, body_offset


class _Node:
    """A minimal syntax tree node retaining the originating term index.

    Attributes:
        kind: The grammar construct, for example ``'identifier'`` or ``'binary'``.
        value: Literal value for leaf nodes.
        term_index: Index into the rule's ``condition_terms`` for the leading
            term of this node, used for precise issue locations.
        children: Child nodes in source order.
        meta: Optional mapping of auxiliary grammar data (operator, field).
    """

    __slots__ = ('kind', 'value', 'term_index', 'children', 'meta')

    def __init__(self, kind, term_index, value=None, children=None, meta=None):
        """Initialize a syntax tree node."""
        self.kind = kind
        self.value = value
        self.term_index = term_index
        self.children = children or list()
        self.meta = meta or dict()


class _TermParser:
    """Build a syntax tree from Plyara's flat ``condition_terms`` list.

    This is a structural parser only: it groups tokens into expressions without
    assigning any meaning or type to them.  Grammar that cannot be expressed in
    the supported subset raises :class:`ContractSyntaxError`, which the checker
    converts into an unsupported-expression issue rather than a crash.
    """

    QUANTIFIERS = {'all', 'any', 'none'}

    def __init__(self, terms):
        """Initialize the parser.

        Args:
            terms: The ``condition_terms`` list produced by Plyara.
        """
        self._terms = terms
        self._index = 0

    def parse(self):
        """Parse the complete term list and return the root syntax node."""
        node = self._parse_expression()
        if not self._at_end():
            raise ContractSyntaxError(self._peek(), self._index)
        return node

    def _peek(self):
        """Return the current term without consuming it."""
        if self._at_end():
            return None
        return self._terms[self._index]

    def _advance(self):
        """Consume and return the current term."""
        term = self._terms[self._index]
        self._index += 1
        return term

    def _at_end(self):
        """Return whether all terms have been consumed."""
        return self._index >= len(self._terms)

    def _accept(self, term):
        """Consume the current term when it matches ``term``."""
        if self._peek() == term:
            self._advance()
            return True
        return False

    def _expect(self, term):
        """Consume ``term`` or raise a syntax error."""
        if not self._accept(term):
            raise ContractSyntaxError(self._peek(), self._index, expected=term)

    # Expression precedence (lowest to highest): or, and, not, comparison,
    # range 'in', string relations, bitwise or/xor/and, shifts, additive,
    # multiplicative, unary, postfix/primary.
    def _parse_expression(self):
        """Parse a full boolean expression starting at the current term."""
        return self._parse_or()

    def _parse_or(self):
        """Parse left-associative ``or`` expressions."""
        node = self._parse_and()
        while self._peek() == 'or':
            operator_index = self._index
            self._advance()
            right = self._parse_and()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': 'or'})
        return node

    def _parse_and(self):
        """Parse left-associative ``and`` expressions."""
        node = self._parse_not()
        while self._peek() == 'and':
            operator_index = self._index
            self._advance()
            right = self._parse_not()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': 'and'})
        return node

    def _parse_not(self):
        """Parse prefix ``not`` and ``defined`` expressions."""
        if self._peek() == 'not':
            operator_index = self._index
            self._advance()
            operand = self._parse_not()
            return _Node('unary', operator_index, children=[operand], meta={'operator': 'not'})
        if self._peek() == 'defined':
            operator_index = self._index
            self._advance()
            operand = self._parse_not()
            return _Node('unary', operator_index, children=[operand], meta={'operator': 'defined'})
        return self._parse_comparison()

    def _parse_comparison(self):
        """Parse comparisons, range membership and string relations."""
        node = self._parse_bitwise_or()
        while True:
            operator = self._peek()
            if operator in _COMPARISON_OPS:
                operator_index = self._index
                self._advance()
                right = self._parse_bitwise_or()
                node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
            elif operator in ('in', 'at'):
                operator_index = self._index
                self._advance()
                right = self._parse_bitwise_or()
                node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
            elif operator in _STRING_OPS:
                operator_index = self._index
                self._advance()
                right = self._parse_bitwise_or()
                node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
            else:
                break
        return node

    def _parse_bitwise_or(self):
        """Parse bitwise ``|`` expressions."""
        node = self._parse_bitwise_xor()
        while self._peek() == '|':
            operator_index = self._index
            self._advance()
            right = self._parse_bitwise_xor()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': '|'})
        return node

    def _parse_bitwise_xor(self):
        """Parse bitwise ``^`` expressions."""
        node = self._parse_bitwise_and()
        while self._peek() == '^':
            operator_index = self._index
            self._advance()
            right = self._parse_bitwise_and()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': '^'})
        return node

    def _parse_bitwise_and(self):
        """Parse bitwise ``&`` expressions."""
        node = self._parse_shift()
        while self._peek() == '&':
            operator_index = self._index
            self._advance()
            right = self._parse_shift()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': '&'})
        return node

    def _parse_shift(self):
        """Parse ``>>`` and ``<<`` expressions."""
        node = self._parse_additive()
        while self._peek() in ('>>', '<<'):
            operator = self._advance()
            operator_index = self._index - 1
            right = self._parse_additive()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
        return node

    def _parse_additive(self):
        """Parse ``+`` and ``-`` expressions."""
        node = self._parse_multiplicative()
        while self._peek() in ('+', '-'):
            operator = self._advance()
            operator_index = self._index - 1
            right = self._parse_multiplicative()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
        return node

    def _parse_multiplicative(self):
        """Parse ``*``, ``\\`` and ``%`` expressions."""
        node = self._parse_unary_arithmetic()
        while self._peek() in ('*', '\\', '%'):
            operator = self._advance()
            operator_index = self._index - 1
            right = self._parse_unary_arithmetic()
            node = _Node('binary', operator_index, children=[node, right], meta={'operator': operator})
        return node

    def _parse_unary_arithmetic(self):
        """Parse unary ``-`` and bitwise ``~`` expressions."""
        if self._peek() in ('-', '~'):
            operator = self._advance()
            operator_index = self._index - 1
            operand = self._parse_unary_arithmetic()
            return _Node('unary', operator_index, children=[operand], meta={'operator': operator})
        return self._parse_postfix()

    def _parse_postfix(self):
        """Parse a primary expression followed by calls, indexes and fields."""
        node = self._parse_primary()
        while True:
            if self._peek() == '(':
                open_index = self._index
                self._advance()
                arguments = list()
                if self._peek() != ')':
                    arguments.append(self._parse_expression())
                    while self._accept(','):
                        arguments.append(self._parse_expression())
                self._expect(')')
                node = _Node('call', open_index, children=[node] + arguments,
                             meta={'arg_count': len(arguments)})
            elif self._peek() == '[':
                open_index = self._index
                self._advance()
                index_node = self._parse_expression()
                self._expect(']')
                node = _Node('index', open_index, children=[node, index_node])
            elif self._peek() == '.':
                dot_index = self._index
                self._advance()
                field = self._advance()
                node = _Node('field', dot_index, children=[node], meta={'field': field})
            else:
                break
        return node

    def _parse_primary(self):
        """Parse leaves, parenthesized expressions, ranges and for-loops."""
        term = self._peek()
        term_index = self._index

        if term is None:
            raise ContractSyntaxError(None, self._index)

        if term == '(':
            self._advance()
            node = self._parse_parenthesized()
            return node

        if term == 'for':
            return self._parse_for()

        if term in self.QUANTIFIERS or self._is_number(term):
            # A number only begins a quantifier when followed by 'of'.
            if self._is_number(term) and self._terms[self._index + 1:self._index + 2] != ['of']:
                pass
            else:
                return self._parse_quantifier()
        if term in ('true', 'false'):
            self._advance()
            return _Node('boolean', term_index, value=(term == 'true'))

        if term == 'filesize':
            self._advance()
            return _Node('builtin', term_index, value='filesize')

        if term == 'entrypoint':
            self._advance()
            return _Node('builtin', term_index, value='entrypoint')

        if term == 'them':
            self._advance()
            return _Node('string_set', term_index, value='them')

        if term in _INTEGER_BUILTINS:
            self._advance()
            return _Node('builtin', term_index, value=term)

        if self._is_number(term):
            self._advance()
            kind = 'float' if '.' in term else 'integer'
            return _Node(kind, term_index, value=term)

        if term.startswith('"'):
            self._advance()
            return _Node('string_literal', term_index, value=term)

        if term.startswith('/'):
            self._advance()
            return _Node('regex_literal', term_index, value=term)

        if term[0] in ('$', '#', '@', '!'):
            self._advance()
            return _Node('string_reference', term_index, value=term)

        if term in ('*', ):
            self._advance()
            return _Node('wildcard', term_index, value=term)

        if self._is_identifier(term):
            self._advance()
            return _Node('identifier', term_index, value=term)

        raise ContractSyntaxError(term, term_index)

    @staticmethod
    def _is_identifier(term):
        """Return whether ``term`` is a plain (possibly dotted) identifier."""
        if not term or term[0] in ('$', '#', '@', '!', '"', '/', '('):
            return False
        if term in ('all', 'any', 'none', 'and', 'or', 'not', 'of', 'in', 'for', 'defined'):
            return False
        return term[0].isalpha() or term[0] == '_'

    @staticmethod
    def _is_number(term):
        """Return whether ``term`` is an integer, hex or floating literal."""
        if term.startswith('0x'):
            return True
        return term[0].isdigit()

    def _parse_parenthesized(self):
        """Parse a parenthesized expression, tuple or integer range."""
        elements = list()
        indexes = list()
        elements.append(self._parse_expression())
        indexes.append(self._index)
        while self._accept(','):
            elements.append(self._parse_expression())
            indexes.append(self._index)

        range_node = None
        if self._peek() == '..':
            dot_index = self._index
            self._advance()
            upper = self._parse_expression()
            range_node = _Node('range', dot_index, children=[elements[0], upper])
            elements = [range_node]

        self._expect(')')

        if range_node is not None:
            return range_node
        if len(elements) == 1:
            return elements[0]
        return _Node('tuple', indexes[0] if indexes else self._index, children=elements)

    def _parse_for(self):
        """Parse the ``for`` iteration and quantifier constructs.

        YARA provides two shapes::

            for QUANTIFIER VAR in ITERABLE : ( BODY )
            for QUANTIFIER of STRINGSET : ( BODY )
        """
        for_index = self._index
        self._expect('for')

        quantifier = self._advance()
        if quantifier not in self.QUANTIFIERS and not self._is_number(quantifier):
            raise ContractSyntaxError(quantifier, self._index - 1)
        quantifier_node = _Node('quantifier_value', self._index - 1, value=quantifier)

        if self._peek() != 'of':
            variable = self._advance()
            if not self._is_identifier(variable):
                raise ContractSyntaxError(variable, self._index - 1)
            self._expect('in')
            iterable = self._parse_postfix()
            self._expect(':')
            self._expect('(')
            body = self._parse_expression()
            self._expect(')')
            return _Node('for', for_index,
                         children=[quantifier_node, iterable, body],
                         meta={'loop_variable': variable})

        self._advance()  # consume 'of'
        target = self._parse_postfix()
        self._expect(':')
        self._expect('(')
        body = self._parse_expression()
        self._expect(')')
        return _Node('for_of', for_index, children=[quantifier_node, target, body])

    def _parse_quantifier(self):
        """Parse ``all of``, ``any of`` and ``N of`` string-set constructs."""
        quantifier_index = self._index
        quantifier = self._advance()
        self._expect('of')

        if self._peek() == '(':
            open_index = self._index
            self._advance()
            members = list()
            if self._peek() != ')':
                members.append(self._parse_expression())
                while self._accept(','):
                    members.append(self._parse_expression())
            self._expect(')')
            target = _Node('string_set', open_index, children=members, value='tuple')
        else:
            target = self._parse_postfix()

        return _Node('quantifier', quantifier_index, children=[target],
                     meta={'quantifier': quantifier})


class ContractSyntaxError(Exception):
    """Raised when condition terms cannot be grouped into the supported AST."""

    def __init__(self, term, term_index, expected=None):
        """Initialize the syntax error."""
        self.term = term
        self.term_index = term_index
        self.expected = expected
        message = f'Unexpected term {term!r} at index {term_index}'
        if expected:
            message += f' (expected {expected!r})'
        super().__init__(message)


class RuleContractChecker:
    """Check parsed YARA rules against an external variable contract.

    The checker derives static types for the supported expression subset and
    records an issue for every problem it can explain.  It never evaluates a
    condition, and any construct outside the supported subset is reported as
    unsupported rather than assumed correct.
    """

    def __init__(self, contract, ruleset=None):
        """Initialize the checker.

        Args:
            contract: An :class:`ExternalVariableContract` describing every
                external variable the calling program will bind.
            ruleset: Optional list of parsed rules, as returned by
                :meth:`plyara.Plyara.parse_string`, used to resolve references
                to other rules and string identifiers.
        """
        self._contract = contract
        self._ruleset = ruleset or list()
        self._rule_names = {rule['rule_name'] for rule in self._ruleset}
        self._issues = list()
        self._locator = None
        self._rule_name = None
        self._terms = list()
        self._loop_scopes = list()

    def check(self, ruleset=None):
        """Check every rule and return a :class:`ContractReport`.

        Args:
            ruleset: Optional parsed ruleset overriding the one given at
                construction time.

        Returns:
            ContractReport: The aggregated findings and verified rule names.
        """
        if ruleset is not None:
            self._ruleset = ruleset
            self._rule_names = {rule['rule_name'] for rule in self._ruleset}

        self._issues = list()
        verified = list()

        for rule in self._ruleset:
            self._rule_name = rule['rule_name']
            self._terms = rule.get('condition_terms', list())
            self._loop_scopes = list()
            self._locator = TermLocator(
                rule.get('raw_condition', ''),
                rule.get('start_line', 1),
                rule.get('stop_line'),
            )

            issue_count_before = len(self._issues)
            self._check_rule(rule)

            if len(self._issues) == issue_count_before:
                verified.append(self._rule_name)

        return ContractReport(list(self._issues), verified)

    def _check_rule(self, rule):
        """Parse and type-check a single rule, capturing unsupported shapes."""
        if not self._terms:
            self._report_unsupported(
                0,
                'rule has no condition terms to check',
                'a rule without a parsed condition cannot be verified against the contract'
            )
            return

        try:
            root = _TermParser(self._terms).parse()
        except ContractSyntaxError as error:
            self._report_unsupported(
                error.term_index if error.term_index is not None else 0,
                f'condition uses an expression structure outside the supported subset: {error}',
                'the flat condition terms could not be grouped into the supported grammar'
            )
            return

        derived = self._infer(root)
        if derived.type not in (_Type.UNKNOWN, _Type.BOOLEAN):
            self._report_unsupported(
                root.term_index,
                'condition does not resolve to a boolean expression',
                f'the top-level expression was derived as {derived.type.value}'
            )

    # -- issue reporting -------------------------------------------------
    def _location(self, term_index):
        """Return ``(line, column)`` for a term index."""
        line, column, _ = self._locator.locate(term_index)
        return line, column

    def _report(self, code, term_index, message, rationale):
        """Record a contract issue at the given term."""
        line, column = self._location(term_index)
        term = self._terms[term_index] if 0 <= term_index < len(self._terms) else None
        self._issues.append(ContractIssue(
            code, self._rule_name, message, line, column, term, term_index, rationale
        ))

    def _report_undeclared(self, term_index, name, rationale):
        """Record an undeclared-identifier issue."""
        self._report(
            ContractIssueCode.UNDECLARED_IDENTIFIER,
            term_index,
            f'identifier {name!r} is not declared as an external variable, rule, module field or loop variable',
            rationale
        )

    def _report_conflict(self, term_index, name, declared, used, rationale):
        """Record a type-conflict issue for a contract variable."""
        self._report(
            ContractIssueCode.TYPE_CONFLICT,
            term_index,
            f'{name!r} is declared {declared.value} in the contract but is used as {used.value}',
            rationale
        )

    def _report_unsupported(self, term_index, message, rationale):
        """Record an unsupported-expression issue."""
        self._report(ContractIssueCode.UNSUPPORTED_EXPRESSION, term_index, message, rationale)

    # -- type inference --------------------------------------------------
    def _infer(self, node):
        """Derive the static type of a syntax node, recording issues."""
        handler = getattr(self, f'_infer_{node.kind}', None)
        if handler is None:
            self._report_unsupported(
                node.term_index,
                f'unsupported expression construct {node.kind!r}',
                'no inference rule is registered for this construct'
            )
            return _intrinsic(_Type.UNKNOWN)
        return handler(node)

    def _infer_integer(self, node):
        """Integer literal."""
        return _intrinsic(_Type.INTEGER, node.term_index)

    def _infer_float(self, node):
        """Floating point literal."""
        return _intrinsic(_Type.FLOAT, node.term_index)

    def _infer_boolean(self, node):
        """Boolean literal ``true`` or ``false``."""
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _infer_string_literal(self, node):
        """Quoted string literal."""
        return _intrinsic(_Type.STRING, node.term_index)

    def _infer_regex_literal(self, node):
        """Regular expression literal."""
        return _intrinsic(_Type.REGEX, node.term_index)

    def _infer_builtin(self, node):
        """Infer types for the file and integer-read built-ins."""
        if node.value in ('filesize', 'entrypoint') or node.value in _INTEGER_BUILTINS:
            return _intrinsic(_Type.INTEGER, node.term_index)
        self._report_unsupported(
            node.term_index, f'unsupported built-in {node.value!r}',
            'the built-in is not part of the supported subset'
        )
        return _intrinsic(_Type.UNKNOWN)

    def _infer_string_reference(self, node):
        """Infer the type of ``$s``, ``#s``, ``@s`` and ``!s`` references."""
        symbol = node.value[0]
        if symbol == '$':
            return _intrinsic(_Type.STRING_REF, node.term_index)
        if symbol in ('#', '@', '!'):
            return _intrinsic(_Type.INTEGER, node.term_index)
        self._report_unsupported(
            node.term_index, f'unsupported string reference {node.value!r}',
            'the leading symbol is not one of $, #, @ or !'
        )
        return _intrinsic(_Type.UNKNOWN)

    def _infer_wildcard(self, node):
        """A wildcard such as ``$*`` only appears inside string sets."""
        return _intrinsic(_Type.STRING_REF, node.term_index)

    def _infer_identifier(self, node):
        """Resolve a bare identifier against loop, contract and rule scopes."""
        name = node.value

        for scope in reversed(self._loop_scopes):
            if name in scope:
                return _Typed(scope[name], 'loop', name=name, term_index=node.term_index)

        if '.' in name:
            return self._infer_module_path(node, name)

        if name in self._contract:
            return _Typed(self._contract.type_of(name), 'external', name=name,
                          term_index=node.term_index)

        if name in self._rule_names:
            return _Typed(_Type.BOOLEAN, 'rule', name=name, term_index=node.term_index)

        self._report_undeclared(
            node.term_index, name,
            'no loop variable, external variable or rule with this name is in scope'
        )
        return _intrinsic(_Type.UNKNOWN, node.term_index)

    def _infer_module_path(self, node, path):
        """Infer the type of a dotted module field or zero-argument use."""
        module = path.split('.', 1)[0]
        if module not in Parser.IMPORT_OPTIONS:
            self._report_undeclared(
                node.term_index, path,
                f'{module!r} is not an imported YARA module or a declared external variable'
            )
            return _intrinsic(_Type.UNKNOWN, node.term_index)
        known = _MODULE_FIELD_TYPES.get(path)
        if known is not None:
            return _Typed(known, 'module', name=path, term_index=node.term_index)
        # An imported module path whose schema we do not model is a legal mixed
        # module expression: keep it unknown instead of failing it.
        return _Typed(_Type.UNKNOWN, 'module', name=path, term_index=node.term_index)

    def _infer_unary(self, node):
        """Infer types for ``not``, ``defined``, unary ``-`` and ``~``."""
        operand = self._infer(node.children[0])
        operator = node.meta['operator']

        if operator == 'not':
            if operand.type not in (_Type.BOOLEAN, _Type.UNKNOWN):
                self._flag_misuse(node.children[0].term_index, operand, _Type.BOOLEAN,
                                  f'logical not requires a boolean operand, got {operand.type.value}')
            return _intrinsic(_Type.BOOLEAN, node.term_index)

        if operator == 'defined':
            return _intrinsic(_Type.BOOLEAN, node.term_index)

        if operator in ('-', '~'):
            if operand.type not in (_Type.INTEGER, _Type.FLOAT, _Type.UNKNOWN):
                self._flag_misuse(node.children[0].term_index, operand, _Type.INTEGER,
                                  f'operator {operator!r} requires a numeric operand, got {operand.type.value}')
            return _intrinsic(operand.type if operand.type != _Type.UNKNOWN else _Type.INTEGER,
                              node.term_index)

        self._report_unsupported(
            node.term_index, f'unsupported unary operator {operator!r}',
            'no inference rule is registered for this operator'
        )
        return _intrinsic(_Type.UNKNOWN)

    def _infer_binary(self, node):
        """Infer the type of a binary expression, checking operand contracts."""
        operator = node.meta['operator']
        left = self._infer(node.children[0])
        right = self._infer(node.children[1])

        if operator in _LOGICAL_OPS:
            return self._check_logical(node, operator, left, right)
        if operator in _COMPARISON_OPS:
            return self._check_comparison(node, operator, left, right)
        if operator in _STRING_OPS:
            return self._check_string_operation(node, operator, left, right)
        if operator in ('in', 'at'):
            return self._check_membership(node, operator, left, right)
        if operator in _ARITHMETIC_OPS:
            return self._check_arithmetic(node, operator, left, right)

        self._report_unsupported(
            node.term_index, f'unsupported binary operator {operator!r}',
            'no inference rule is registered for this operator'
        )
        return _intrinsic(_Type.UNKNOWN)

    def _flag_misuse(self, term_index, typed_value, required_type, detail):
        """Report a type conflict for an external variable or a generic misuse.

        Only a value explicitly declared in the contract is reported as a type
        conflict.  Loop locals, module expressions and other derived values
        produce an unsupported-expression finding instead.
        """
        if typed_value.source == 'external':
            self._report_conflict(
                term_index, typed_value.name, typed_value.type, required_type, detail
            )
        else:
            self._report_unsupported(term_index, detail, self._provenance(typed_value))

    @staticmethod
    def _provenance(typed_value):
        """Build a rationale string describing where a typed value came from."""
        if typed_value.source == 'external':
            return f"external variable {typed_value.name!r} is declared {typed_value.type.value} in the contract"
        if typed_value.source == 'loop':
            return f"loop local {typed_value.name!r} is bound to {typed_value.type.value} by the iterable"
        if typed_value.source == 'rule':
            return f"rule reference {typed_value.name!r} always has boolean type"
        if typed_value.source == 'module':
            return f"module expression {typed_value.name!r} derived as {typed_value.type.value}"
        return f"intrinsic expression derived as {typed_value.type.value}"

    def _check_logical(self, node, operator, left, right):
        """Type-check ``and`` and ``or``."""
        for typed_value, operand_node in ((left, node.children[0]), (right, node.children[1])):
            if typed_value.type not in (_Type.BOOLEAN, _Type.UNKNOWN):
                self._flag_misuse(
                    operand_node.term_index, typed_value, _Type.BOOLEAN,
                    f'operator {operator!r} requires boolean operands, got {typed_value.type.value}'
                )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _check_comparison(self, node, operator, left, right):
        """Type-check equality, inequality and ordering comparisons."""
        numeric = {_Type.INTEGER, _Type.FLOAT}
        comparable = numeric | {_Type.STRING, _Type.BOOLEAN}

        if left.type in comparable and right.type in comparable:
            if left.type != right.type and not (left.type in numeric and right.type in numeric):
                self._flag_pair_mismatch(node, operator, left, right)
        elif _Type.UNKNOWN not in (left.type, right.type):
            self._report_unsupported(
                node.term_index,
                f'cannot compare {left.type.value} with {right.type.value} using {operator!r}',
                'one operand is not a scalar comparable value'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _flag_pair_mismatch(self, node, operator, left, right):
        """Report a comparison mismatch, preferring the contract operand."""
        for typed_value, other in ((left, right), (right, left)):
            if typed_value.source == 'external':
                self._report_conflict(
                    typed_value.term_index, typed_value.name, typed_value.type, other.type,
                    f'operator {operator!r} compares {typed_value.type.value} external variable '
                    f'with a {other.type.value} operand'
                )
                return
        self._report_unsupported(
            node.term_index,
            f'cannot compare {left.type.value} with {right.type.value} using {operator!r}',
            'comparison operands must share a comparable type'
        )

    def _check_string_operation(self, node, operator, left, right):
        """Type-check ``contains``, ``matches``, ``startswith`` and friends."""
        if left.type not in (_Type.STRING, _Type.UNKNOWN):
            self._flag_misuse(
                node.children[0].term_index, left, _Type.STRING,
                f'operator {operator!r} requires a string on the left, got {left.type.value}'
            )

        if operator == 'matches':
            if right.type not in (_Type.REGEX, _Type.UNKNOWN):
                self._flag_misuse(
                    node.children[1].term_index, right, _Type.REGEX,
                    f'operator matches requires a regex on the right, got {right.type.value}'
                )
        elif right.type not in (_Type.STRING, _Type.UNKNOWN):
            self._flag_misuse(
                node.children[1].term_index, right, _Type.STRING,
                f'operator {operator!r} requires a string on the right, got {right.type.value}'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _check_membership(self, node, operator, left, right):
        """Type-check ``in`` ranges/sets and the ``at`` offset operator."""
        if operator == 'at':
            if left.type not in (_Type.STRING_REF, _Type.UNKNOWN):
                self._flag_misuse(
                    node.children[0].term_index, left, _Type.STRING_REF,
                    f'operator at requires a string reference on the left, got {left.type.value}'
                )
            if right.type not in (_Type.INTEGER, _Type.UNKNOWN):
                self._flag_misuse(
                    node.children[1].term_index, right, _Type.INTEGER,
                    f'operator at requires an integer offset, got {right.type.value}'
                )
            return _intrinsic(_Type.BOOLEAN, node.term_index)

        if right.type == _Type.RANGE:
            if left.type not in (_Type.INTEGER, _Type.STRING_REF, _Type.UNKNOWN):
                self._flag_misuse(
                    node.children[0].term_index, left, _Type.INTEGER,
                    f'range membership requires an integer or string, got {left.type.value}'
                )
        elif right.type not in (_Type.SET, _Type.UNKNOWN):
            self._report_unsupported(
                node.children[1].term_index,
                f'operator in requires a range or set on the right, got {right.type.value}',
                'the right-hand side of in must be a parenthesized range or set'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _check_arithmetic(self, node, operator, left, right):
        """Type-check arithmetic and bitwise operators."""
        numeric = {_Type.INTEGER, _Type.FLOAT, _Type.UNKNOWN}
        if left.type not in numeric or right.type not in numeric:
            for typed_value, operand_node in ((left, node.children[0]), (right, node.children[1])):
                if typed_value.type not in (_Type.INTEGER, _Type.FLOAT, _Type.UNKNOWN):
                    self._flag_misuse(
                        operand_node.term_index, typed_value, _Type.INTEGER,
                        f'operator {operator!r} requires numeric operands, got {typed_value.type.value}'
                    )
            return _intrinsic(_Type.UNKNOWN)

        bitwise = _ARITHMETIC_OPS - {'+', '-', '*', '\\', '%'}
        if _Type.FLOAT in (left.type, right.type) and operator in bitwise:
            self._report_unsupported(
                node.term_index,
                f'operator {operator!r} is not defined for floating point operands',
                'bitwise and shift operators require integer operands'
            )
            return _intrinsic(_Type.UNKNOWN)
        if _Type.FLOAT in (left.type, right.type):
            return _intrinsic(_Type.FLOAT, node.term_index)
        if _Type.UNKNOWN in (left.type, right.type):
            return _intrinsic(_Type.UNKNOWN, node.term_index)
        return _intrinsic(_Type.INTEGER, node.term_index)

    def _infer_range(self, node):
        """Infer the type of an integer range ``(a .. b)``."""
        for bound_node in node.children:
            bound = self._infer(bound_node)
            if bound.type not in (_Type.INTEGER, _Type.UNKNOWN):
                self._flag_misuse(
                    bound_node.term_index, bound, _Type.INTEGER,
                    f'range bounds must be integers, got {bound.type.value}'
                )
        return _intrinsic(_Type.RANGE, node.term_index)

    def _infer_tuple(self, node):
        """Infer the type of a parenthesized set of expressions."""
        members = [self._infer(child) for child in node.children]
        member_types = {member.type for member in members}
        if member_types <= {_Type.INTEGER, _Type.UNKNOWN}:
            return _intrinsic(_Type.SET, node.term_index)
        if member_types <= {_Type.STRING_REF, _Type.UNKNOWN}:
            return _intrinsic(_Type.SET, node.term_index)
        self._report_unsupported(
            node.term_index,
            f'mixed-type set with members {sorted(member_type.value for member_type in member_types)}',
            'a parenthesized set must contain only integers or only string references'
        )
        return _intrinsic(_Type.UNKNOWN, node.term_index)

    def _infer_string_set(self, node):
        """Infer the type of ``them`` or a parenthesized string set."""
        if node.value == 'them':
            return _intrinsic(_Type.SET, node.term_index)
        members = [self._infer(child) for child in node.children]
        if any(member.type not in (_Type.STRING_REF, _Type.UNKNOWN) for member in members):
            self._report_unsupported(
                node.term_index, 'string set contains a non-string member',
                'quantifier targets must be string references'
            )
            return _intrinsic(_Type.UNKNOWN, node.term_index)
        return _intrinsic(_Type.SET, node.term_index)

    def _infer_index(self, node):
        """Infer the type of an indexed expression such as ``@a[i]``."""
        target = self._infer(node.children[0])
        index = self._infer(node.children[1])
        if index.type not in (_Type.INTEGER, _Type.UNKNOWN):
            self._flag_misuse(
                node.children[1].term_index, index, _Type.INTEGER,
                f'index expression must be an integer, got {index.type.value}'
            )
        if target.type == _Type.STRING_REF:
            return _intrinsic(_Type.INTEGER, node.term_index)
        if target.source == 'module':
            return _Typed(_Type.UNKNOWN, 'module', name=target.name, term_index=node.term_index)
        return _intrinsic(_Type.UNKNOWN, node.term_index)

    def _infer_field(self, node):
        """Infer the type of ``object.field``, including module field chains."""
        parent_node = node.children[0]
        parent = self._infer(parent_node)
        field = node.meta['field']

        if parent_node.kind == 'identifier' and '.' not in parent_node.value:
            module = parent_node.value
            if module in Parser.IMPORT_OPTIONS:
                path = f'{module}.{field}'
                known = _MODULE_FIELD_TYPES.get(path)
                if known is not None:
                    return _Typed(known, 'module', name=path, term_index=node.term_index)
                return _Typed(_Type.UNKNOWN, 'module', name=path, term_index=node.term_index)

        if parent.source == 'module':
            path = f'{parent.name}.{field}'
            known = _MODULE_FIELD_TYPES.get(path)
            if known is not None:
                return _Typed(known, 'module', name=path, term_index=node.term_index)
            return _Typed(_Type.UNKNOWN, 'module', name=path, term_index=node.term_index)

        if parent.type == _Type.UNKNOWN:
            return _intrinsic(_Type.UNKNOWN, node.term_index)

        self._report_unsupported(
            node.term_index,
            f'field access {field!r} on a {parent.type.value} expression is not supported',
            'field access outside imported module objects is outside the supported subset'
        )
        return _intrinsic(_Type.UNKNOWN, node.term_index)

    def _infer_call(self, node):
        """Infer the return type of a function or module method call."""
        callee = node.children[0]
        arguments = [self._infer(argument) for argument in node.children[1:]]

        if callee.kind == 'builtin':
            return _intrinsic(_Type.INTEGER, node.term_index)

        if callee.kind == 'identifier' and '.' in callee.value:
            return self._module_call_type(callee.value, arguments, callee.term_index)

        if callee.kind == 'field':
            full_path = self._flatten_field(callee)
            if full_path:
                return self._module_call_type(full_path, arguments, callee.term_index)

        self._report_unsupported(
            callee.term_index, 'unsupported call target',
            'only imported module functions and integer built-ins are supported as call targets'
        )
        return _intrinsic(_Type.UNKNOWN, node.term_index)

    def _flatten_field(self, node):
        """Reconstruct a dotted module path from a field/identifier chain."""
        if node.kind == 'identifier':
            return node.value
        if node.kind == 'field' and node.children[0].kind in ('identifier', 'field'):
            base = self._flatten_field(node.children[0])
            return f'{base}.{node.meta["field"]}' if base else None
        return None

    def _module_call_type(self, path, arguments, term_index):
        """Return a known module function return type, or ``UNKNOWN``."""
        if path in _STRING_MODULE_CALLS:
            return _Typed(_Type.STRING, 'module', name=path, term_index=term_index)
        if path in _BOOLEAN_MODULE_CALLS:
            return _Typed(_Type.BOOLEAN, 'module', name=path, term_index=term_index)
        if path in _INTEGER_MODULE_CALLS:
            return _Typed(_Type.INTEGER, 'module', name=path, term_index=term_index)
        if path in _STRING_BUILTINS:
            if path in ('string.length', 'string.count', 'string.to_int', 'string.to_int_be'):
                return _Typed(_Type.INTEGER, 'module', name=path, term_index=term_index)
            return _Typed(_Type.STRING, 'module', name=path, term_index=term_index)
        return _Typed(_Type.UNKNOWN, 'module', name=path, term_index=term_index)

    def _infer_quantifier(self, node):
        """Infer the boolean type of an ``all/any/none/N of`` expression."""
        target = self._infer(node.children[0])
        if target.type not in (_Type.SET, _Type.STRING_REF, _Type.UNKNOWN):
            self._report_unsupported(
                node.children[0].term_index,
                f'quantifier target must be a string set, got {target.type.value}',
                'of-expressions quantify over string identifier sets'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _infer_quantifier_value(self, node):
        """Infer the integer quantifier value used inside for-loops."""
        if self._is_integer_token(node.value):
            return _intrinsic(_Type.INTEGER, node.term_index)
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    @staticmethod
    def _is_integer_token(value):
        """Return whether a quantifier token is a numeric count."""
        return value[:1].isdigit()

    def _infer_for(self, node):
        """Infer the type of a ``for ... in`` loop with a local variable."""
        quantifier_node, iterable_node, body_node = node.children
        self._infer(quantifier_node)
        iterable = self._infer(iterable_node)

        variable = node.meta['loop_variable']
        element_type = self._loop_element_type(iterable.type)
        self._loop_scopes.append({variable: element_type})
        try:
            body = self._infer(body_node)
        finally:
            self._loop_scopes.pop()

        if body.type not in (_Type.BOOLEAN, _Type.UNKNOWN):
            self._report_unsupported(
                body_node.term_index,
                f'for-loop body must be boolean, got {body.type.value}',
                'the predicate of a for expression must be a boolean condition'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    def _infer_for_of(self, node):
        """Infer the type of a ``for ... of`` string-set loop."""
        quantifier_node, target_node, body_node = node.children
        self._infer(quantifier_node)
        target = self._infer(target_node)
        if target.type not in (_Type.SET, _Type.STRING_REF, _Type.UNKNOWN):
            self._report_unsupported(
                target_node.term_index,
                f'for-of target must be a string set, got {target.type.value}',
                'for-of loops iterate over string identifier sets'
            )
        body = self._infer(body_node)
        if body.type not in (_Type.BOOLEAN, _Type.UNKNOWN):
            self._report_unsupported(
                body_node.term_index,
                f'for-of body must be boolean, got {body.type.value}',
                'the predicate of a for expression must be a boolean condition'
            )
        return _intrinsic(_Type.BOOLEAN, node.term_index)

    @staticmethod
    def _loop_element_type(iterable_type):
        """Determine the type bound to a loop variable."""
        if iterable_type in (_Type.RANGE, _Type.SET):
            return _Type.INTEGER
        return _Type.UNKNOWN


# A limited schema for frequently used, stable module fields.  Anything not
# listed here remains UNKNOWN: legal module expressions are preserved, while
# external variables are still checked against the explicit contract.
_MODULE_FIELD_TYPES = {
    'pe.is_64bit': _Type.BOOLEAN,
    'pe.is_32bit': _Type.BOOLEAN,
    'pe.is_dll': _Type.BOOLEAN,
    'pe.is_exe': _Type.BOOLEAN,
    'pe.number_of_sections': _Type.INTEGER,
    'pe.entry_point': _Type.INTEGER,
    'pe.timestamp': _Type.INTEGER,
    'elf.entry_point': _Type.INTEGER,
    'elf.type': _Type.INTEGER,
    'magic.type': _Type.STRING,
    'magic.mime_type': _Type.STRING,
}


class ContractReport:
    """The outcome of checking a ruleset against a contract.

    Attributes:
        issues: All :class:`ContractIssue` findings across the ruleset.
        verified_rules: Names of rules that produced no issues.
    """

    def __init__(self, issues, verified_rules):
        """Initialize a contract report."""
        self.issues = issues
        self.verified_rules = verified_rules

    @property
    def is_valid(self):
        """Return whether every rule passed the contract check."""
        return not self.issues

    def issues_for(self, rule_name):
        """Return the issues attached to a specific rule."""
        return [issue for issue in self.issues if issue.rule_name == rule_name]

    def as_dict(self):
        """Return the report as a JSON-serializable dictionary."""
        return {
            'is_valid': self.is_valid,
            'verified_rules': list(self.verified_rules),
            'issues': [issue.as_dict() for issue in self.issues],
        }

    def __repr__(self):
        """Return an unambiguous representation of the report."""
        return f'<ContractReport valid={self.is_valid} verified={len(self.verified_rules)} issues={len(self.issues)}>'


def check_external_variables(ruleset, contract):
    """Check a parsed ruleset against an external variable contract.

    This is a convenience wrapper around :class:`RuleContractChecker`.

    Args:
        ruleset: List of rule dictionaries as returned by
            :meth:`plyara.Plyara.parse_string`.
        contract: An :class:`ExternalVariableContract`.

    Returns:
        ContractReport: The aggregated findings and verified rule names.
    """
    return RuleContractChecker(contract, ruleset).check()
