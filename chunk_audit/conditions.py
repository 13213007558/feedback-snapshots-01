"""Recursive-descent parser for the *supported subset* of YARA conditions.

Plyara already lowers a condition into a flat token list (``condition_terms``).
We rebuild an AST for the finite, position-independent subset used by the
chunking pre-check:

* string references ``$a`` / ``$*`` and the boolean helpers ``any``/``all``
  (``of them`` / ``of ($a, $b)``);
* positive/zero counts ``#a == n`` and ``#a > n`` (existence-only reasoning);
* the connectives ``and`` / ``or`` / ``not`` and parentheses.

Everything that depends on offsets, file size, modules or arithmetic is parsed
into an :class:`Unsupported` node carrying a reason, so the caller keeps the
rule *undecided* rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class ConditionError(ValueError):
    """Raised on malformed condition token streams."""


@dataclass
class Unsupported:
    reason: str
    tokens: List[str] = field(default_factory=list)


@dataclass
class Ref:
    identifier: str                 # '$a', or '*' for the wildcard
    negated: bool = False


@dataclass
class Count:
    identifier: str                 # 'a' from '#a'
    exists_only: bool               # True for '#a > 0' / '#a >= 1'
    negated: bool = False


@dataclass
class Quantifier:
    mode: str                       # 'any' | 'all'
    identifiers: List[str]          # ['*'] means "them"/wildcard
    negated: bool = False


@dataclass
class Not:
    operand: object


@dataclass
class And:
    operands: List[object]


@dataclass
class Or:
    operands: List[object]


_IDENT_RE = __import__("re").compile(r"^\$[A-Za-z0-9_]*$|^\*$")


def _is_string_ref(token: str) -> bool:
    return token.startswith("$") and token not in {"$"}


def _reason_for(token: str) -> str:
    if token == "at":
        return "positional 'at' binds a match to a global offset (offset rebasing across windows)"
    if token == "in":
        return "positional 'in' range uses global offsets that do not survive windowing"
    if token == "filesize":
        return "'filesize' is a whole-file relation; each window reports its own size"
    if token.startswith("@"):
        return "match offset '@' operator requires global positions"
    if token == "for":
        return "'for ... :' quantifier expression not in the supported boolean subset"
    if token in {"uint8", "uint16", "int8", "int16", "int32", "uint32", "int8be", "uint32be"}:
        return "integer data read at a global offset"
    if "." in token or token.endswith(")"):
        return "module/function call needs whole-file or module state"
    return f"unsupported condition construct {token!r}"


class _ConditionParser:
    def __init__(self, tokens: List[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _expect(self, expected: str) -> None:
        token = self._peek()
        if token != expected:
            raise ConditionError(f"Expected {expected!r}, got {token!r}")
        self._next()

    def parse(self) -> object:
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ConditionError(f"Trailing tokens: {self.tokens[self.pos:]!r}")
        return node

    def _parse_or(self) -> object:
        operands = [self._parse_and()]
        while self._peek() == "or":
            self._next()
            operands.append(self._parse_and())
        return operands[0] if len(operands) == 1 else Or(operands)

    def _parse_and(self) -> object:
        operands = [self._parse_not()]
        while self._peek() == "and":
            self._next()
            operands.append(self._parse_not())
        return operands[0] if len(operands) == 1 else And(operands)

    def _parse_not(self) -> object:
        if self._peek() == "not":
            self._next()
            return Not(self._parse_not())
        return self._parse_atom()

    def _parse_atom(self) -> object:
        token = self._peek()
        if token == "(":
            self._next()
            node = self._parse_or()
            self._expect(")")
            return self._parse_postfix(node)
        if token in {"any", "all"}:
            node = self._parse_quantifier()
            return self._parse_postfix(node)
        if token is not None and token.startswith("#"):
            node = self._parse_count()
            return self._parse_postfix(node)
        if token is not None and _is_string_ref(token):
            self._next()
            return self._parse_postfix(Ref(token))
        if token is None:
            raise ConditionError("Unexpected end of condition")
        return self._consume_unsupported()

    def _parse_postfix(self, node: object) -> object:
        """Attach positional constraints (``at`` / ``in``) as unsupported."""
        while self._peek() in {"at", "in"}:
            keyword = self._next()
            consumed = [keyword]
            depth = 0
            while self.pos < len(self.tokens):
                current = self._peek()
                if current == "(":
                    depth += 1
                elif current == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and current in {"and", "or"}:
                    break
                consumed.append(self._next())
            reason = _reason_for(keyword)
            node = Unsupported(reason, consumed)
        return node

    def _parse_quantifier(self) -> object:
        mode = self._next()               # 'any' or 'all'
        self._expect("of")
        identifiers: List[str] = []
        if self._peek() == "them":
            self._next()
            identifiers = ["*"]
        else:
            self._expect("(")
            while True:
                token = self._next()
                if not _is_string_ref(token) and token != "*":
                    raise ConditionError(f"Bad identifier in 'of' list: {token!r}")
                identifiers.append(token.lstrip("$") or "*")
                if self._peek() == ",":
                    self._next()
                    continue
                break
            self._expect(")")
        return Quantifier(mode, identifiers)

    def _parse_count(self) -> object:
        token = self._next()               # '#a'
        identifier = token[1:]
        comparator = self._peek()
        exists_only = False
        if comparator in {">", ">=", "==", "!=", "<", "<="}:
            self._next()
            number = self._next()
            exists_only = comparator in {">", ">="} and number.isdigit() and (
                int(number) == 0 if comparator == ">" else int(number) == 1
            )
            if not exists_only:
                return Unsupported(
                    f"count comparison {token} {comparator} {number} needs cross-window totals",
                    [token, comparator, number],
                )
        return Count(identifier, exists_only=exists_only)

    def _consume_unsupported(self) -> Unsupported:
        start = self.pos
        token = self._next()
        reason = _reason_for(token)
        # Consume the remainder of the atom (parenthesised calls, ranges, etc.)
        depth = 0
        while self.pos < len(self.tokens):
            current = self._peek()
            if current == "(":
                depth += 1
            elif current == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and current in {"and", "or"}:
                break
            self._next()
        return Unsupported(reason, self.tokens[start:self.pos])


def parse_condition(tokens: List[str]) -> object:
    """Parse Plyara condition tokens into a condition AST."""
    return _ConditionParser(list(tokens)).parse()


def collect_unsupported(node: object) -> List[Unsupported]:
    """Return every unsupported construct reachable in the AST."""
    if isinstance(node, Unsupported):
        return [node]
    if isinstance(node, (And, Or)):
        found: List[Unsupported] = []
        for operand in node.operands:
            found.extend(collect_unsupported(operand))
        return found
    if isinstance(node, Not):
        return collect_unsupported(node.operand)
    return []
