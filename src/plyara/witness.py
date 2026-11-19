"""Generate bounded witness candidates for a small subset of parsed YARA rules.

The generator consumes the dictionary representation produced by :class:`plyara.core.Plyara`.
It never executes a rule or any external program: candidates are assembled in memory and verified
with a separate, finite byte matcher in this module.

Supported conditions use ``and``, ``or`` and ``not`` over string references, ``$s at N``,
``$s in (N..M)`` and comparisons against ``filesize``. Supported strings are text strings and
hex strings with finite jumps, wildcards and alternations. Everything else is reported as
undecided instead of being approximated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    'MAX_CANDIDATES',
    'MAX_LENGTH',
    'UnsupportedRuleError',
    'WitnessResult',
    'check_rule',
    'explain_rule',
    'generate_witness',
    'generate_witnesses',
]

MAX_LENGTH = 256
MAX_CANDIDATES = 4096
_MAX_CLAUSES = 128
_MAX_START_COMBINATIONS = 2048
_FILLERS = (0x00, 0x41, 0xFF, 0x01, 0x20, 0x7F)

_STATUS_WITNESS = 'witness'
_STATUS_NO_WITNESS = 'no_witness_within_bound'
_STATUS_UNDECIDED = 'undecided'


class UnsupportedRuleError(ValueError):
    """Raised when a rule or condition is outside the supported witness subset."""


@dataclass(frozen=True)
class WitnessResult:
    """Result of a bounded witness search.

    Attributes:
        status: One of ``witness``, ``no_witness_within_bound`` or ``undecided``.
        rule_name: Name of the parsed rule.
        candidate: Shortest candidate found, or ``None``.
        evidence: Condition evidence for a candidate, or an explanation for failure.
        bound: Search limits and work performed.
        reason: Human-readable reason for a non-witness result.
    """

    status: str
    rule_name: str
    candidate: bytes | None
    evidence: Mapping[str, Any]
    bound: Mapping[str, Any]
    reason: str | None = None

    @property
    def candidate_hex(self) -> str | None:
        """Return the candidate as uppercase hexadecimal, if one was found."""
        if self.candidate is None:
            return None
        return self.candidate.hex().upper()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the result."""
        return {
            'status': self.status,
            'rule_name': self.rule_name,
            'candidate_hex': self.candidate_hex,
            'candidate_length': None if self.candidate is None else len(self.candidate),
            'evidence': dict(self.evidence),
            'bound': dict(self.bound),
            'reason': self.reason,
        }


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_int(token: Any) -> int:
    """Parse a decimal, hexadecimal or filesize token into an integer."""
    if not isinstance(token, str):
        raise UnsupportedRuleError(f'unsupported numeric token: {token!r}')
    text = token.strip()
    match = re.fullmatch(r'(\d+)([KM]B)', text, flags=re.IGNORECASE)
    if match:
        scale = 1024 if match.group(2).upper() == 'KB' else 1024 * 1024
        return int(match.group(1)) * scale
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', text):
        return int(text, 16)
    if re.fullmatch(r'\d+', text):
        return int(text, 10)
    raise UnsupportedRuleError(f'unsupported numeric token: {token!r}')


def _decode_text(value: str) -> bytes:
    """Decode the escape syntax stored by Plyara for a text string."""
    if not isinstance(value, str) or not value:
        raise UnsupportedRuleError('text strings must be non-empty strings')
    result = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char != '\\':
            codepoint = ord(char)
            if codepoint > 0x7F:
                raise UnsupportedRuleError(f'text string character is not ASCII: {char!r}')
            result.append(codepoint)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise UnsupportedRuleError('text string ends with a backslash')
        escape = value[index]
        index += 1
        if escape == 'x':
            if index + 2 > len(value):
                raise UnsupportedRuleError('short hexadecimal escape in text string')
            digits = value[index:index + 2]
            if not re.fullmatch(r'[0-9A-Fa-f]{2}', digits):
                raise UnsupportedRuleError(f'invalid hexadecimal escape: \\x{digits}')
            result.append(int(digits, 16))
            index += 2
        elif escape in {'\\', '"'}:
            result.append(ord(escape))
        elif escape == 'n':
            result.append(0x0A)
        elif escape == 'r':
            result.append(0x0D)
        elif escape == 't':
            result.append(0x09)
        else:
            raise UnsupportedRuleError(f'unsupported text escape: \\{escape}')
    if not result:
        raise UnsupportedRuleError('text strings must be non-empty')
    return bytes(result)


# ---------------------------------------------------------------------------
# Hex pattern parsing used by the generator
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _HByte:
    """A single hex byte with optional wildcard nibbles or negation."""

    mask: int
    value: int
    negated: bool

    def choose(self) -> int:
        """Choose a stable byte that satisfies the specification."""
        for candidate in range(256):
            matched = (candidate & self.mask) == self.value
            if matched != self.negated:
                return candidate
        raise UnsupportedRuleError('hex byte specification has no satisfying byte')

    def matches(self, byte: int) -> bool:
        """Return whether a byte satisfies the specification."""
        return ((byte & self.mask) == self.value) != self.negated


@dataclass(frozen=True)
class _HJump:
    """A finite hex jump."""

    low: int
    high: int


@dataclass(frozen=True)
class _HSeq:
    """A concatenation of hex items."""

    items: tuple[Any, ...]


@dataclass(frozen=True)
class _HAlt:
    """An alternation of hex sequences."""

    branches: tuple[Any, ...]


def _hex_items(value: str) -> list[str]:
    """Split a Plyara hex value into lexical items."""
    if not isinstance(value, str):
        raise UnsupportedRuleError('hex string value must be text')
    text = value.strip()
    if not (text.startswith('{') and text.endswith('}')):
        raise UnsupportedRuleError('hex strings must be enclosed in braces')
    text = text[1:-1]
    text = re.sub(r'//[^\r\n]*', ' ', text)
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
    tokens = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char in '()|':
            tokens.append(char)
            index += 1
            continue
        if char == '[':
            end = text.find(']', index)
            if end < 0:
                raise UnsupportedRuleError('unterminated hex jump')
            token = text[index:end + 1]
            if not re.fullmatch(r'\[\s*\d+\s*(?:-\s*\d+\s*)?\]', token):
                raise UnsupportedRuleError(f'unsupported or unbounded hex jump: {token}')
            tokens.append(re.sub(r'\s+', '', token))
            index = end + 1
            continue
        token = text[index:index + 2]
        if len(token) == 2 and re.fullmatch(r'~?[0-9A-Fa-f?]{2}', token):
            tokens.append(token)
            index += 2
            continue
        raise UnsupportedRuleError(f'unsupported hex token near: {text[index:index + 8]!r}')
    return tokens


def _hex_byte(token: str) -> _HByte:
    """Build a byte specification from one hex token."""
    negated = token.startswith('~')
    if negated:
        token = token[1:]
    mask = 0
    value = 0
    for position, char in enumerate(token):
        shift = 4 if position == 0 else 0
        if char != '?':
            mask |= 0x0F << shift
            value |= int(char, 16) << shift
    return _HByte(mask=mask, value=value, negated=negated)


class _HexParser:
    """Recursive-descent parser for the supported hex grammar."""

    def __init__(self, tokens: Sequence[str]):
        self.tokens = list(tokens)
        self.index = 0

    def peek(self) -> str | None:
        """Return the next token without consuming it."""
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def take(self) -> str:
        """Consume and return the next token."""
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError('unexpected end of hex string')
        self.index += 1
        return token

    def parse(self) -> Any:
        """Parse the full token stream."""
        node = self.parse_alt()
        if self.peek() is not None:
            raise UnsupportedRuleError(f'unexpected hex token: {self.peek()}')
        return node

    def parse_alt(self) -> Any:
        """Parse an alternation, which may have a single branch."""
        branches = [self.parse_seq()]
        while self.peek() == '|':
            self.take()
            branches.append(self.parse_seq())
        if len(branches) == 1:
            return branches[0]
        return _HAlt(tuple(branches))

    def parse_seq(self) -> Any:
        """Parse a non-empty sequence of bytes, jumps and groups."""
        items = []
        while self.peek() not in (None, ')', '|'):
            token = self.peek()
            if token == '(':
                self.take()
                node = self.parse_alt()
                if self.peek() != ')':
                    raise UnsupportedRuleError('unbalanced parentheses in hex string')
                self.take()
                items.append(node)
            elif token.startswith('['):
                self.take()
                body = token[1:-1]
                if '-' in body:
                    low_text, high_text = body.split('-', 1)
                    low, high = int(low_text), int(high_text)
                else:
                    low = high = int(body)
                if low > high:
                    raise UnsupportedRuleError(f'invalid hex jump bounds: {token}')
                items.append(_HJump(low=low, high=high))
            else:
                items.append(_hex_byte(self.take()))
        if not items:
            raise UnsupportedRuleError('empty sequence in hex string')
        if len(items) == 1:
            return items[0]
        return _HSeq(tuple(items))


def _hex_length(node: Any) -> int:
    """Return the minimum number of bytes emitted by a hex node."""
    if isinstance(node, _HByte):
        return 1
    if isinstance(node, _HJump):
        return node.low
    if isinstance(node, _HSeq):
        return sum(_hex_length(item) for item in node.items)
    if isinstance(node, _HAlt):
        return min(_hex_length(branch) for branch in node.branches)
    raise UnsupportedRuleError(f'unknown hex node: {node!r}')


def _hex_variants(node: Any) -> tuple[bytes, ...]:
    """Return a bounded set of concrete expansions covering hex alternatives."""
    if isinstance(node, _HByte):
        return (bytes([node.choose()]),)
    if isinstance(node, _HJump):
        return (bytes([0]) * node.low,)
    if isinstance(node, _HSeq):
        products = [b'']
        for item in node.items:
            branches = _hex_variants(item)
            if len(products) * len(branches) > 16:
                branches = branches[:1]
            products = [prefix + branch for prefix in products for branch in branches]
            if len(products) > 16:
                products = products[:16]
        return tuple(products)
    if isinstance(node, _HAlt):
        variants: list[bytes] = []
        for branch in node.branches:
            variants.extend(_hex_variants(branch))
        return tuple(dict.fromkeys(variants))[:16]
    raise UnsupportedRuleError(f'unknown hex node: {node!r}')


def _hex_bytes(node: Any) -> bytes:
    """Emit a shortest stable concrete byte string for a hex node."""
    if isinstance(node, _HByte):
        return bytes([node.choose()])
    if isinstance(node, _HJump):
        return bytes([0]) * node.low
    if isinstance(node, _HSeq):
        return b''.join(_hex_bytes(item) for item in node.items)
    if isinstance(node, _HAlt):
        choices = [(_hex_bytes(branch), index) for index, branch in enumerate(node.branches)]
        data, _ = min(choices, key=lambda item: (len(item[0]), item[1]))
        return data
    raise UnsupportedRuleError(f'unknown hex node: {node!r}')


# ---------------------------------------------------------------------------
# Generator-side condition parsing
# ---------------------------------------------------------------------------
# Literals are tuples: (kind, name, first, second, positive).
#   ('present', name, None, None, positive)
#   ('at', name, offset, None, positive)
#   ('in', name, low, high, positive)
#   ('filesize', None, op, value, positive)
#   ('const', None, value, None, True)

_OPERATORS = {'==', '!=', '>', '>=', '<', '<='}


class _ConditionParser:
    """Parse Plyara condition terms into a small boolean tree."""

    def __init__(self, terms: Sequence[Any]):
        if not isinstance(terms, (list, tuple)) or not terms:
            raise UnsupportedRuleError('rule has no condition terms')
        self.terms = [term for term in terms if not (isinstance(term, str) and term.startswith(('//', '/*')))]
        self.index = 0

    def peek(self) -> Any:
        """Return the next term without consuming it."""
        if self.index >= len(self.terms):
            return None
        return self.terms[self.index]

    def take(self) -> Any:
        """Consume and return the next term."""
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError('unexpected end of condition')
        self.index += 1
        return token

    def parse(self) -> Any:
        """Parse the full condition."""
        node = self.parse_or()
        if self.peek() is not None:
            raise UnsupportedRuleError(f'unsupported condition term: {self.peek()!r}')
        return node

    def parse_or(self) -> Any:
        """Parse an or-expression."""
        node = self.parse_and()
        while self.peek() == 'or':
            self.take()
            node = ('or', node, self.parse_and())
        return node

    def parse_and(self) -> Any:
        """Parse an and-expression."""
        node = self.parse_not()
        while self.peek() == 'and':
            self.take()
            node = ('and', node, self.parse_not())
        return node

    def parse_not(self) -> Any:
        """Parse a negation or an atom."""
        if self.peek() == 'not':
            self.take()
            return ('not', self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        """Parse a parenthesized expression or an atom."""
        token = self.peek()
        if token == '(':
            self.take()
            node = self.parse_or()
            if self.peek() != ')':
                raise UnsupportedRuleError('unbalanced parentheses in condition')
            self.take()
            return node
        return self.parse_atom()

    def parse_atom(self) -> Any:
        """Parse a string reference, filesize comparison or boolean constant."""
        token = self.take()
        if token in ('true', 'false'):
            return ('lit', ('const', None, token == 'true', None, True))
        if isinstance(token, str) and token.startswith('$'):
            return self.parse_string_atom(token)
        if token == 'filesize':
            return self.parse_filesize_left()
        if isinstance(token, str) and (re.fullmatch(r'\d+', token) or token.lower().startswith('0x')
                                       or re.fullmatch(r'\d+[KM]B', token, flags=re.IGNORECASE)):
            operator = self.take()
            if operator not in _OPERATORS:
                raise UnsupportedRuleError(f'unsupported comparison operator: {operator!r}')
            if self.take() != 'filesize':
                raise UnsupportedRuleError('only numeric comparisons against filesize are supported')
            return ('lit', ('filesize', None, operator, _parse_int(token), True))
        raise UnsupportedRuleError(f'unsupported condition term: {token!r}')

    def parse_filesize_left(self) -> Any:
        """Parse a filesize comparison with filesize on the left."""
        operator = self.take()
        if operator not in _OPERATORS:
            raise UnsupportedRuleError(f'unsupported comparison operator: {operator!r}')
        value = _parse_int(self.take())
        return ('lit', ('filesize', None, operator, value, True))

    def parse_string_atom(self, name: Any) -> Any:
        """Parse a string reference with optional at or in placement."""
        if not isinstance(name, str) or name.endswith('*'):
            raise UnsupportedRuleError(f'unsupported string reference: {name!r}')
        token = self.peek()
        if token == 'at':
            self.take()
            offset = _parse_int(self.take())
            if offset < 0:
                raise UnsupportedRuleError('negative at offset')
            return ('lit', ('at', name, offset, None, True))
        if token == 'in':
            self.take()
            if self.take() != '(':
                raise UnsupportedRuleError('expected ( after in')
            low = _parse_int(self.take())
            if self.take() != '..':
                raise UnsupportedRuleError('expected .. in in-range')
            high = _parse_int(self.take())
            if self.take() != ')':
                raise UnsupportedRuleError('expected ) after in-range')
            if low < 0 or high < low:
                raise UnsupportedRuleError(f'invalid in-range: {low}..{high}')
            return ('lit', ('in', name, low, high, True))
        return ('lit', ('present', name, None, None, True))


def _nnf(node: Any, negate: bool = False) -> Any:
    """Convert a parsed condition to negation normal form."""
    kind = node[0]
    if kind == 'lit':
        _kind, name, first, second, positive = node[1]
        if _kind == 'const':
            return ('lit', ('const', None, first != negate, None, True))
        return ('lit', (_kind, name, first, second, positive != negate))
    if kind == 'not':
        return _nnf(node[1], not negate)
    if kind == 'and':
        left, right = node[1], node[2]
        if negate:
            return ('or', _nnf(left, True), _nnf(right, True))
        return ('and', _nnf(left), _nnf(right))
    if kind == 'or':
        left, right = node[1], node[2]
        if negate:
            return ('and', _nnf(left, True), _nnf(right, True))
        return ('or', _nnf(left), _nnf(right))
    raise UnsupportedRuleError(f'unknown condition node: {node!r}')


def _dnf(node: Any) -> list[list[tuple[Any, ...]]]:
    """Expand a negation-normal-form tree into capped disjunctive normal form."""
    kind = node[0]
    if kind == 'lit':
        literal = node[1]
        if literal[0] == 'const':
            return [[]] if literal[2] else []
        return [[literal]]
    if kind == 'or':
        clauses = _dnf(node[1]) + _dnf(node[2])
        if len(clauses) > _MAX_CLAUSES:
            raise UnsupportedRuleError('condition expands beyond the clause bound')
        return clauses
    if kind == 'and':
        left = _dnf(node[1])
        right = _dnf(node[2])
        if len(left) * len(right) > _MAX_CLAUSES:
            raise UnsupportedRuleError('condition expands beyond the clause bound')
        return [a + b for a in left for b in right]
    raise UnsupportedRuleError(f'unknown condition node: {node!r}')


# ---------------------------------------------------------------------------
# String patterns shared by the generator
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Pattern:
    """A concrete shortest expansion and its occurrence length."""

    name: str
    data: bytes
    variants: tuple[bytes, ...] = ()


def _build_patterns(rule: Mapping[str, Any], max_length: int) -> dict[str, _Pattern]:
    """Compile every string in a rule into a concrete shortest expansion."""
    patterns = {}
    for entry in rule.get('strings', []):
        if not isinstance(entry, Mapping):
            raise UnsupportedRuleError('unsupported strings section entry')
        name = entry.get('name')
        string_type = entry.get('type')
        value = entry.get('value')
        modifiers = entry.get('modifiers', [])
        if not isinstance(name, str) or not name.startswith('$'):
            raise UnsupportedRuleError(f'invalid string name: {name!r}')
        if modifiers:
            raise UnsupportedRuleError(f'unsupported string modifiers: {modifiers!r}')
        if string_type == 'text':
            data = _decode_text(value)
            variants = ()
        elif string_type == 'byte':
            node = _HexParser(_hex_items(value)).parse()
            minimum = _hex_length(node)
            if minimum == 0:
                raise UnsupportedRuleError('hex strings must emit at least one byte')
            if minimum > max_length:
                raise UnsupportedRuleError(
                    f'string {name} needs at least {minimum} bytes, beyond max_length={max_length}'
                )
            data = _hex_bytes(node)
            variants = _hex_variants(node)
        else:
            raise UnsupportedRuleError(f'unsupported string type: {string_type!r}')
        if name in patterns:
            raise UnsupportedRuleError(f'duplicate string name: {name}')
        patterns[name] = _Pattern(name=name, data=data, variants=variants)
    return patterns


def _validate_references(clause: Iterable[tuple[Any, ...]], patterns: Mapping[str, _Pattern]) -> None:
    """Ensure every string literal in a clause refers to a known string."""
    for literal in clause:
        if literal[0] in {'present', 'at', 'in'}:
            if literal[1] not in patterns:
                raise UnsupportedRuleError(f'condition refers to unknown string: {literal[1]}')


# ---------------------------------------------------------------------------
# Generator placement search
# ---------------------------------------------------------------------------

def _literal_filesize_ok(literal: tuple[Any, ...], length: int) -> bool:
    """Return whether a filesize literal holds for a candidate length."""
    _kind, _name, operator, value, positive = literal
    operations = {
        '==': length == value,
        '!=': length != value,
        '>': length > value,
        '>=': length >= value,
        '<': length < value,
        '<=': length <= value,
    }
    return operations[operator] == positive


def _choose_starts(positive: list[tuple[Any, ...]], data: bytes, length: int) -> list[list[int]]:
    """Build extra start-position groups needed for one concrete pattern."""
    size = len(data)
    last = length - size
    fixed = sorted({literal[2] for literal in positive if literal[0] == 'at'})
    if any(start + size > length for start in fixed):
        return [[]]

    groups: list[list[int]] = []
    for literal in positive:
        if literal[0] != 'in':
            continue
        low, high = literal[2], min(literal[3], last)
        if any(low <= start <= high for start in fixed):
            continue
        if low > high:
            groups.append([])
        else:
            groups.append([start for start in range(low, high + 1) if start not in fixed])
    if not fixed and not groups and any(literal[0] == 'present' for literal in positive):
        groups.append(list(range(0, last + 1)) if last >= 0 else [])
    return groups


def _clause_occurrences(clause: Sequence[tuple[Any, ...]], patterns: Mapping[str, _Pattern],
                        length: int) -> list[list[tuple[bytes, int]]]:
    """Enumerate concrete placements for one DNF clause at a candidate length."""
    by_name: dict[str, list[tuple[Any, ...]]] = {}
    for literal in clause:
        if not literal[4] or literal[0] not in {'present', 'at', 'in'}:
            continue
        by_name.setdefault(literal[1], []).append(literal)

    per_string: list[list[list[tuple[bytes, int]]]] = []
    for name in sorted(by_name):
        positive = by_name[name]
        pattern = patterns[name]
        variants = pattern.variants or (pattern.data,)
        alternatives: list[list[tuple[bytes, int]]] = []
        seen: set[tuple[tuple[bytes, int], ...]] = set()
        for variant in variants:
            groups = _choose_starts(positive, variant, length)
            if any(not group for group in groups):
                continue
            fixed = sorted({literal[2] for literal in positive if literal[0] == 'at'})
            choices = [()] if not groups else _product(groups)
            for combination in choices:
                placements = tuple(sorted({(variant, start) for start in list(fixed) + list(combination)}))
                if placements not in seen:
                    seen.add(placements)
                    alternatives.append(list(placements))
        if not alternatives:
            return []
        per_string.append(alternatives)

    combinations: list[list[tuple[bytes, int]]] = [[]]
    for alternatives in per_string:
        if len(combinations) * len(alternatives) > _MAX_START_COMBINATIONS:
            raise UnsupportedRuleError('placement search exceeds the start-combination bound')
        combinations = [base + extra for base in combinations for extra in alternatives]
    return combinations


def _product(groups: Sequence[Sequence[int]]) -> list[tuple[int, ...]]:
    """Return a capped Cartesian product of start-position groups."""
    results: list[tuple[int, ...]] = [()]
    for group in groups:
        if len(results) * len(group) > _MAX_START_COMBINATIONS:
            raise UnsupportedRuleError('placement search exceeds the start-combination bound')
        results = [prefix + (item,) for prefix in results for item in group]
    return results


def _assemble(length: int, placements: Iterable[tuple[bytes, int]], filler: int) -> bytes | None:
    """Assemble one candidate, returning None on an out-of-range or byte conflict."""
    cells: list[int | None] = [None] * length
    for pattern, start in sorted(set(placements)):
        if start < 0 or start + len(pattern) > length:
            return None
        for offset, byte in enumerate(pattern):
            position = start + offset
            if cells[position] is not None and cells[position] != byte:
                return None
            cells[position] = byte
    for position in range(length):
        if cells[position] is None:
            cells[position] = _filler_byte(position, length, filler)
    return bytes(cells)


def _filler_byte(position: int, length: int, seed: int) -> int:
    """Return a deterministic filler byte that varies with position."""
    return (seed + 37 * position + length) & 0xFF


def _search_bound(max_length: int, max_candidates: int, lengths_tried: int,
                  candidates_checked: int, clauses: int) -> dict[str, Any]:
    """Describe the finite search that was performed."""
    return {
        'max_length': max_length,
        'max_candidates': max_candidates,
        'lengths_tried': lengths_tried,
        'candidates_checked': candidates_checked,
        'dnf_clauses': clauses,
        'complete_for_supported_subset': False,
    }


def generate_witness(rule: Mapping[str, Any], max_length: int = MAX_LENGTH,
                     max_candidates: int = MAX_CANDIDATES) -> WitnessResult:
    """Search for a shortest candidate satisfying one parsed rule.

    Args:
        rule: One rule dictionary returned by ``Plyara.parse_string``.
        max_length: Largest candidate size considered, in bytes.
        max_candidates: Largest number of assembled candidates verified.

    Returns:
        A :class:`WitnessResult`. A failed finite search is reported as
        ``no_witness_within_bound``, never as a proof of unsatisfiability.
    """
    if not isinstance(rule, Mapping):
        raise TypeError('rule must be a Plyara rule dictionary')
    if max_length < 0 or max_candidates < 1:
        raise ValueError('max_length must be non-negative and max_candidates must be positive')
    rule_name = str(rule.get('rule_name', '<unnamed>'))
    bound = _search_bound(max_length, max_candidates, 0, 0, 0)

    try:
        if 'global' in rule.get('scopes', []):
            raise UnsupportedRuleError('global-scope rules are outside the supported subset')
        patterns = _build_patterns(rule, max_length)
        parser = _ConditionParser(rule.get('condition_terms', []))
        tree = _nnf(parser.parse())
        clauses = _dnf(tree)
    except UnsupportedRuleError as error:
        return WitnessResult(
            status=_STATUS_UNDECIDED,
            rule_name=rule_name,
            candidate=None,
            evidence={'unsupported': str(error)},
            bound=bound,
            reason=f'undecided: {error}',
        )

    bound = _search_bound(max_length, max_candidates, 0, 0, len(clauses))
    if not clauses:
        return WitnessResult(
            status=_STATUS_NO_WITNESS,
            rule_name=rule_name,
            candidate=None,
            evidence={'explanation': 'the supported condition is constant false'},
            bound=bound,
            reason='no candidate exists within the supported fragment; this is not a proof of '
                   'unsatisfiability over all YARA inputs',
        )

    candidates_checked = 0
    try:
        for clause in clauses:
            _validate_references(clause, patterns)
    except UnsupportedRuleError as error:
        return WitnessResult(
            status=_STATUS_UNDECIDED,
            rule_name=rule_name,
            candidate=None,
            evidence={'unsupported': str(error)},
            bound=bound,
            reason=f'undecided: {error}',
        )

    lengths_tried = 0
    for length in range(0, max_length + 1):
        lengths_tried = length + 1
        for clause in clauses:
            filesize_literals = [literal for literal in clause if literal[0] == 'filesize']
            if any(not _literal_filesize_ok(literal, length) for literal in filesize_literals):
                continue
            try:
                occurrence_sets = _clause_occurrences(clause, patterns, length)
            except UnsupportedRuleError as error:
                return WitnessResult(
                    status=_STATUS_UNDECIDED,
                    rule_name=rule_name,
                    candidate=None,
                    evidence={'unsupported': str(error)},
                    bound=_search_bound(max_length, max_candidates, length, candidates_checked, len(clauses)),
                    reason=f'undecided: {error}',
                )
            for occurrences in occurrence_sets:
                for filler in _FILLERS:
                    candidates_checked += 1
                    if candidates_checked > max_candidates:
                        return WitnessResult(
                            status=_STATUS_NO_WITNESS,
                            rule_name=rule_name,
                            candidate=None,
                            evidence={
                                'explanation': 'candidate budget exhausted before a witness was found',
                                'condition_terms': list(rule.get('condition_terms', [])),
                            },
                            bound=_search_bound(max_length, max_candidates, length, candidates_checked, len(clauses)),
                            reason='no candidate found within the search bound; this is not a proof of '
                                   'unsatisfiability over all YARA inputs',
                        )
                    candidate = _assemble(length, occurrences, filler)
                    if candidate is None:
                        continue
                    if check_rule(rule, candidate):
                        return WitnessResult(
                            status=_STATUS_WITNESS,
                            rule_name=rule_name,
                            candidate=candidate,
                            evidence=explain_rule(rule, candidate),
                            bound=_search_bound(max_length, max_candidates, length, candidates_checked, len(clauses)),
                            reason=None,
                        )

    return WitnessResult(
        status=_STATUS_NO_WITNESS,
        rule_name=rule_name,
        candidate=None,
        evidence={
            'explanation': 'no candidate was found in the finite length and candidate space',
            'condition_terms': list(rule.get('condition_terms', [])),
        },
        bound=_search_bound(max_length, max_candidates, lengths_tried, candidates_checked, len(clauses)),
        reason='no candidate found within the search bound; this is not a proof of unsatisfiability '
               'over all YARA inputs',
    )


def generate_witnesses(rules: Iterable[Mapping[str, Any]], max_length: int = MAX_LENGTH,
                       max_candidates: int = MAX_CANDIDATES) -> list[WitnessResult]:
    """Search each rule in a parsed ruleset for a witness."""
    return [generate_witness(rule, max_length=max_length, max_candidates=max_candidates) for rule in rules]


# ---------------------------------------------------------------------------
# Independent finite matcher
# ---------------------------------------------------------------------------
# The matcher deliberately parses strings and conditions again. It only looks at
# the bytes in memory and never invokes YARA, a solver or an external program.

@dataclass(frozen=True)
class _MByte:
    """Matcher-side hex byte specification."""

    mask: int
    value: int
    negated: bool

    def matches(self, byte: int) -> bool:
        """Return whether a byte satisfies the specification."""
        return ((byte & self.mask) == self.value) != self.negated


@dataclass(frozen=True)
class _MJump:
    """Matcher-side finite jump."""

    low: int
    high: int


@dataclass(frozen=True)
class _MSeq:
    """Matcher-side hex sequence."""

    items: tuple[Any, ...]


@dataclass(frozen=True)
class _MAlt:
    """Matcher-side hex alternation."""

    branches: tuple[Any, ...]


class _MatchHexParser:
    """Matcher-side parser for the supported bounded hex grammar."""

    def __init__(self, tokens: Sequence[str]):
        self.tokens = list(tokens)
        self.index = 0

    def peek(self) -> str | None:
        """Return the next token without consuming it."""
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        """Consume and return the next token."""
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError('unexpected end of hex string')
        self.index += 1
        return token

    def parse(self) -> Any:
        """Parse the complete token stream."""
        node = self.parse_alt()
        if self.peek() is not None:
            raise UnsupportedRuleError(f'unexpected hex token: {self.peek()}')
        return node

    def parse_alt(self) -> Any:
        """Parse alternation."""
        branches = [self.parse_seq()]
        while self.peek() == '|':
            self.take()
            branches.append(self.parse_seq())
        return branches[0] if len(branches) == 1 else _MAlt(tuple(branches))

    def parse_seq(self) -> Any:
        """Parse a sequence of hex items."""
        items = []
        while self.peek() not in (None, ')', '|'):
            token = self.peek()
            if token == '(':
                self.take()
                items.append(self.parse_alt())
                if self.take() != ')':
                    raise UnsupportedRuleError('unbalanced parentheses in hex string')
            elif token.startswith('['):
                self.take()
                body = token[1:-1]
                if '-' in body:
                    low, high = (int(part) for part in body.split('-', 1))
                else:
                    low = high = int(body)
                if low < 0 or high < low:
                    raise UnsupportedRuleError(f'invalid hex jump: {token}')
                items.append(_MJump(low, high))
            else:
                token = self.take()
                negated = token.startswith('~')
                token = token.lstrip('~')
                mask = 0
                value = 0
                for position, char in enumerate(token):
                    if char != '?':
                        shift = 4 if position == 0 else 0
                        mask |= 0x0F << shift
                        value |= int(char, 16) << shift
                items.append(_MByte(mask, value, negated))
        if not items:
            raise UnsupportedRuleError('empty sequence in hex string')
        return items[0] if len(items) == 1 else _MSeq(tuple(items))


def _match_hex_node(node: Any, data: bytes, position: int,
                    cache: dict[tuple[Any, int], frozenset[int]]) -> frozenset[int]:
    """Return all end positions reachable from one start position."""
    key = (node, position)
    if key in cache:
        return cache[key]
    ends: set[int] = set()
    if isinstance(node, _MByte):
        if position < len(data) and node.matches(data[position]):
            ends.add(position + 1)
    elif isinstance(node, _MJump):
        upper = min(node.high, len(data) - position)
        ends.update(position + count for count in range(node.low, upper + 1))
    elif isinstance(node, _MAlt):
        for branch in node.branches:
            ends.update(_match_hex_node(branch, data, position, cache))
    elif isinstance(node, _MSeq):
        positions = {position}
        for item in node.items:
            next_positions: set[int] = set()
            for current in positions:
                next_positions.update(_match_hex_node(item, data, current, cache))
            positions = next_positions
            if not positions:
                break
        ends.update(positions)
    else:
        raise UnsupportedRuleError('unknown hex node during matching')
    result = frozenset(ends)
    cache[key] = result
    return result


def _match_text_occurrences(pattern: bytes, data: bytes) -> list[int]:
    """Find overlapping text occurrences."""
    starts = []
    position = data.find(pattern)
    while position >= 0:
        starts.append(position)
        position = data.find(pattern, position + 1)
    return starts


def _match_hex_occurrences(node: Any, data: bytes) -> list[int]:
    """Find overlapping bounded-hex occurrences."""
    cache: dict[tuple[Any, int], frozenset[int]] = {}
    starts = []
    for position in range(0, len(data) + 1):
        if _match_hex_node(node, data, position, cache):
            starts.append(position)
    return starts


def _match_patterns(rule: Mapping[str, Any]) -> dict[str, Any]:
    """Build matcher-side patterns from a parsed rule."""
    compiled = {}
    for entry in rule.get('strings', []):
        if not isinstance(entry, Mapping):
            raise UnsupportedRuleError('unsupported strings section entry')
        name = entry.get('name')
        string_type = entry.get('type')
        value = entry.get('value')
        modifiers = entry.get('modifiers', [])
        if modifiers:
            raise UnsupportedRuleError(f'unsupported string modifiers: {modifiers!r}')
        if not isinstance(name, str) or not name.startswith('$'):
            raise UnsupportedRuleError(f'invalid string name: {name!r}')
        if string_type == 'text':
            compiled[name] = ('text', _match_decode_text(value))
        elif string_type == 'byte':
            tokens = _match_hex_tokens(value)
            node = _MatchHexParser(tokens).parse()
            if _match_hex_min_length(node) == 0:
                raise UnsupportedRuleError('hex strings must emit at least one byte')
            compiled[name] = ('hex', node)
        else:
            raise UnsupportedRuleError(f'unsupported string type: {string_type!r}')
    return compiled


def _match_decode_text(value: str) -> bytes:
    """Decode text escapes independently from the generator."""
    if not isinstance(value, str) or not value:
        raise UnsupportedRuleError('text strings must be non-empty')
    output = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char != '\\':
            if ord(char) > 0x7F:
                raise UnsupportedRuleError('text string character is not ASCII')
            output.append(ord(char))
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise UnsupportedRuleError('text string ends with a backslash')
        escape = value[index]
        index += 1
        if escape == 'x':
            digits = value[index:index + 2]
            if not re.fullmatch(r'[0-9A-Fa-f]{2}', digits):
                raise UnsupportedRuleError('invalid hexadecimal escape')
            output.append(int(digits, 16))
            index += 2
        elif escape in {'\\', '"'}:
            output.append(ord(escape))
        elif escape in {'n', 'r', 't'}:
            output.append({'n': 10, 'r': 13, 't': 9}[escape])
        else:
            raise UnsupportedRuleError(f'unsupported text escape: \\{escape}')
    return bytes(output)


def _match_hex_tokens(value: str) -> list[str]:
    """Tokenize a hex string independently from the generator."""
    text = value.strip() if isinstance(value, str) else ''
    if not (text.startswith('{') and text.endswith('}')):
        raise UnsupportedRuleError('hex strings must be enclosed in braces')
    text = re.sub(r'//[^\r\n]*', ' ', text[1:-1])
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
    tokens = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text[index] in '()|':
            tokens.append(text[index])
            index += 1
            continue
        if text[index] == '[':
            end = text.find(']', index)
            if end < 0:
                raise UnsupportedRuleError('unterminated hex jump')
            token = text[index:end + 1]
            if not re.fullmatch(r'\[\s*\d+\s*(?:-\s*\d+\s*)?\]', token):
                raise UnsupportedRuleError(f'unsupported or unbounded hex jump: {token}')
            tokens.append(re.sub(r'\s+', '', token))
            index = end + 1
            continue
        token = text[index:index + 2]
        if len(token) == 2 and re.fullmatch(r'~?[0-9A-Fa-f?]{2}', token):
            tokens.append(token)
            index += 2
            continue
        raise UnsupportedRuleError(f'unsupported hex token: {text[index:index + 8]!r}')
    return tokens


def _matcher_atom_value(atom: tuple[Any, ...], occurrences: Mapping[str, list[int]], length: int) -> bool:
    """Evaluate one matcher atom."""
    kind = atom[0]
    if kind == 'present':
        return bool(occurrences.get(atom[1]))
    if kind == 'at':
        return atom[2] in occurrences.get(atom[1], [])
    if kind == 'in':
        return any(atom[2] <= start <= atom[3] for start in occurrences.get(atom[1], []))
    if kind == 'filesize':
        return {
            '==': length == atom[3],
            '!=': length != atom[3],
            '>': length > atom[3],
            '>=': length >= atom[3],
            '<': length < atom[3],
            '<=': length <= atom[3],
        }[atom[2]]
    if kind == 'const':
        return bool(atom[2])
    raise UnsupportedRuleError(f'unknown atom: {atom!r}')


class _MatchConditionParser:
    """Matcher-side condition parser, independent of the generator parser."""

    def __init__(self, terms: Sequence[Any]):
        if not isinstance(terms, (list, tuple)) or not terms:
            raise UnsupportedRuleError('rule has no condition terms')
        self.terms = [term for term in terms if not (isinstance(term, str) and term.startswith(('//', '/*')))]
        self.index = 0

    def peek(self) -> Any:
        """Return the next term without consuming it."""
        return self.terms[self.index] if self.index < len(self.terms) else None

    def take(self) -> Any:
        """Consume and return the next term."""
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError('unexpected end of condition')
        self.index += 1
        return token

    def parse(self) -> Any:
        """Parse the full condition."""
        node = self.parse_or()
        if self.peek() is not None:
            raise UnsupportedRuleError(f'unsupported condition term: {self.peek()!r}')
        return node

    def parse_or(self) -> Any:
        """Parse an or-expression."""
        node = self.parse_and()
        while self.peek() == 'or':
            self.take()
            node = ('or', node, self.parse_and())
        return node

    def parse_and(self) -> Any:
        """Parse an and-expression."""
        node = self.parse_unary()
        while self.peek() == 'and':
            self.take()
            node = ('and', node, self.parse_unary())
        return node

    def parse_unary(self) -> Any:
        """Parse negation or a primary expression."""
        if self.peek() == 'not':
            self.take()
            return ('not', self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        """Parse parentheses or an atom."""
        if self.peek() == '(':
            self.take()
            node = self.parse_or()
            if self.take() != ')':
                raise UnsupportedRuleError('unbalanced parentheses in condition')
            return node
        return self.parse_atom()

    def parse_atom(self) -> Any:
        """Parse one string reference, filesize comparison or constant."""
        token = self.take()
        if token in ('true', 'false'):
            return ('atom', ('const', None, token == 'true', None, True))
        if isinstance(token, str) and token.startswith('$'):
            if token.endswith('*'):
                raise UnsupportedRuleError(f'unsupported string reference: {token}')
            followed = self.peek()
            if followed == 'at':
                self.take()
                return ('atom', ('at', token, _parse_int(self.take()), None, True))
            if followed == 'in':
                self.take()
                if self.take() != '(':
                    raise UnsupportedRuleError('expected ( after in')
                low = _parse_int(self.take())
                if self.take() != '..':
                    raise UnsupportedRuleError('expected .. in in-range')
                high = _parse_int(self.take())
                if self.take() != ')':
                    raise UnsupportedRuleError('expected ) after in-range')
                return ('atom', ('in', token, low, high, True))
            return ('atom', ('present', token, None, None, True))
        if token == 'filesize':
            operator = self.take()
            if operator not in _OPERATORS:
                raise UnsupportedRuleError(f'unsupported comparison operator: {operator!r}')
            return ('atom', ('filesize', None, operator, _parse_int(self.take()), True))
        if isinstance(token, str) and (re.fullmatch(r'\d+', token) or token.lower().startswith('0x')
                                       or re.fullmatch(r'\d+[KM]B', token, flags=re.IGNORECASE)):
            operator = self.take()
            if operator not in _OPERATORS:
                raise UnsupportedRuleError(f'unsupported comparison operator: {operator!r}')
            if self.take() != 'filesize':
                raise UnsupportedRuleError('only numeric comparisons against filesize are supported')
            return ('atom', ('filesize', None, operator, _parse_int(token), True))
        raise UnsupportedRuleError(f'unsupported condition term: {token!r}')


def _match_evaluate(node: Any, occurrences: Mapping[str, list[int]], length: int,
                    evidence: list[dict[str, Any]] | None = None) -> bool:
    """Evaluate a matcher condition tree, optionally recording atom evidence."""
    kind = node[0]
    if kind == 'atom':
        value = _matcher_atom_value(node[1], occurrences, length)
        if evidence is not None:
            evidence.append({'atom': _format_atom(node[1]), 'value': value})
        return value
    if kind == 'not':
        return not _match_evaluate(node[1], occurrences, length, evidence)
    if kind == 'and':
        left = _match_evaluate(node[1], occurrences, length, evidence)
        right = _match_evaluate(node[2], occurrences, length, evidence)
        return left and right
    if kind == 'or':
        left = _match_evaluate(node[1], occurrences, length, evidence)
        right = _match_evaluate(node[2], occurrences, length, evidence)
        return left or right
    raise UnsupportedRuleError(f'unknown condition node: {kind!r}')


def _format_atom(atom: tuple[Any, ...]) -> str:
    """Format one atom for evidence output."""
    kind = atom[0]
    if kind == 'present':
        return atom[1]
    if kind == 'at':
        return f'{atom[1]} at {atom[2]}'
    if kind == 'in':
        return f'{atom[1]} in ({atom[2]}..{atom[3]})'
    if kind == 'filesize':
        return f'filesize {atom[2]} {atom[3]}'
    if kind == 'const':
        return 'true' if atom[2] else 'false'
    return repr(atom)


def _collect_occurrences(rule: Mapping[str, Any], data: bytes) -> dict[str, list[int]]:
    """Collect matcher-side occurrences for every rule string."""
    compiled = _match_patterns(rule)
    occurrences = {}
    for name, (kind, payload) in compiled.items():
        if kind == 'text':
            occurrences[name] = _match_text_occurrences(payload, data)
        else:
            occurrences[name] = _match_hex_occurrences(payload, data)
    return occurrences


def check_rule(rule: Mapping[str, Any], data: bytes) -> bool:
    """Match one parsed rule against candidate bytes with the finite matcher.

    Args:
        rule: One rule dictionary returned by Plyara.
        data: Candidate bytes to inspect.

    Returns:
        True when the supported condition matches.

    Raises:
        UnsupportedRuleError: If the rule is outside the supported subset or malformed.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('data must be bytes')
    occurrences = _collect_occurrences(rule, bytes(data))
    tree = _MatchConditionParser(rule.get('condition_terms', [])).parse()
    return _match_evaluate(tree, occurrences, len(data))


def explain_rule(rule: Mapping[str, Any], data: bytes) -> dict[str, Any]:
    """Return condition evidence for a candidate, using the finite matcher.

    Args:
        rule: One rule dictionary returned by Plyara.
        data: Candidate bytes to inspect.

    Returns:
        Evidence mapping with filesize, string occurrences and per-atom values.
    """
    occurrences = _collect_occurrences(rule, bytes(data))
    tree = _MatchConditionParser(rule.get('condition_terms', [])).parse()
    atoms: list[dict[str, Any]] = []
    matched = _match_evaluate(tree, occurrences, len(data), atoms)
    return {
        'condition_terms': list(rule.get('condition_terms', [])),
        'filesize': len(data),
        'strings': {name: {'min_length': _pattern_length(rule, name), 'occurrences': starts}
                    for name, starts in occurrences.items()},
        'atoms': atoms,
        'matched': matched,
    }


def _pattern_length(rule: Mapping[str, Any], name: str) -> int:
    """Return the lexical length of a string's generated or literal form."""
    for entry in rule.get('strings', []):
        if entry.get('name') == name:
            if entry.get('type') == 'text':
                return len(_match_decode_text(entry.get('value')))
            if entry.get('type') == 'byte':
                compiled = _MatchHexParser(_match_hex_tokens(entry.get('value'))).parse()
                return _match_hex_min_length(compiled)
    raise UnsupportedRuleError(f'unknown string: {name}')


def _match_hex_min_length(node: Any) -> int:
    """Return the minimum emitted size of a matcher hex node."""
    if isinstance(node, _MByte):
        return 1
    if isinstance(node, _MJump):
        return node.low
    if isinstance(node, _MSeq):
        return sum(_match_hex_min_length(item) for item in node.items)
    if isinstance(node, _MAlt):
        return min(_match_hex_min_length(branch) for branch in node.branches)
    raise UnsupportedRuleError('unknown hex node')
