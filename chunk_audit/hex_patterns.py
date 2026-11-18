"""Static length analysis for YARA hex strings.

This module turns a YARA hex pattern (the ``{ ... }`` byte string) into a small
AST and derives *provable* match length bounds:

* ``min_length`` -- every possible match spans at least this many bytes;
* ``max_length`` -- every possible match spans at most this many bytes, or
  ``None`` when an *open* jump (``[-]`` / ``[N-]``) makes the span unbounded.

Only the hex pattern itself is reasoned about; no bytes are ever scanned here.
The grammar handled is the documented YARA hex string form: fixed/wildcard
nibbles, alternation groups ``( a | b )`` and jumps ``[n]``, ``[m-n]``,
``[n-]`` and ``[-]``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


class HexParseError(ValueError):
    """Raised when a hex pattern uses syntax the finite analyzer cannot parse."""


_TOKEN_RE = re.compile(
    r"""
      \[\s*(?P<jlo>\d+)?\s*-\s*(?P<jhi>\d+)?\s*\]   # open/closed jump [a-b], [a-], [-b], [-]
    | \[\s*(?P<jexact>\d+)\s*\]                      # fixed jump [n]
    | \(\s*|\s*\)                                    # alternation parens
    | \|                                             # alternation separator
    | (?P<byte>[0-9A-Fa-f?]{2})                     # nibble pair: AA, A?, ?A, ??
    """,
    re.VERBOSE,
)


@dataclass
class HexNode:
    kind: str                      # 'byte' | 'jump' | 'alt' | 'seq'
    min_length: int
    max_length: Optional[int]      # None => unbounded
    detail: str = ""
    children: List["HexNode"] = field(default_factory=list)
    raw_byte: Optional[str] = None

    @property
    def bounded(self) -> bool:
        return self.max_length is not None


def _tokenize(pattern: str) -> List[str]:
    body = pattern.strip()
    if body.startswith("{"):
        body = body[1:]
    if body.endswith("}"):
        body = body[:-1]
    tokens: List[str] = []
    pos = 0
    stripped = body
    while pos < len(stripped):
        match = _TOKEN_RE.match(stripped, pos)
        if not match:
            if stripped[pos].isspace():
                pos += 1
                continue
            raise HexParseError(
                f"Unparseable hex token at offset {pos}: {stripped[pos:]!r}"
            )
        token = match.group(0).strip()
        if token:
            tokens.append(token)
        pos = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: List[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> HexNode:
        node = self._parse_sequence(stop_at_paren=False)
        if self.pos != len(self.tokens):
            raise HexParseError(f"Unexpected token near: {self.tokens[self.pos:]!r}")
        return node

    def _parse_sequence(self, stop_at_paren: bool) -> HexNode:
        children: List[HexNode] = []
        while True:
            token = self._peek()
            if token is None or (token == ")" and stop_at_paren):
                break
            if token == "(":
                children.append(self._parse_alt())
            elif token.startswith("["):
                children.append(self._parse_jump())
            elif token == "|":
                if stop_at_paren:
                    break
                raise HexParseError("Alternation separator '|' outside group")
            elif token == ")":
                raise HexParseError("Unmatched ')' in hex pattern")
            else:
                children.append(self._parse_byte(token))
        if not children:
            raise HexParseError("Empty hex sequence/alternative")
        return self._seq(children)

    @staticmethod
    def _seq(children: List[HexNode]) -> HexNode:
        if len(children) == 1:
            return children[0]
        min_length = sum(child.min_length for child in children)
        maxes = [child.max_length for child in children]
        max_length = None if any(value is None for value in maxes) else sum(maxes)
        return HexNode("seq", min_length, max_length, children=children)

    def _parse_byte(self, token: str) -> HexNode:
        self._next()
        if not re.fullmatch(r"[0-9A-Fa-f?]{2}", token):
            raise HexParseError(f"Invalid byte nibble pair: {token!r}")
        wildcard = "?" in token
        detail = "wildcard" if wildcard else "fixed"
        return HexNode("byte", 1, 1, detail=detail, raw_byte=token.upper())

    def _parse_jump(self) -> HexNode:
        token = self._next()
        match = _TOKEN_RE.match(token)
        if match.group("jexact") is not None:
            lo = hi = int(match.group("jexact"))
        else:
            lo = int(match.group("jlo")) if match.group("jlo") else 0
            hi_raw = match.group("jhi")
            hi = int(hi_raw) if hi_raw is not None else None
        if hi is not None and lo > hi:
            raise HexParseError(f"Jump range inverted: {token}")
        if hi is None:
            detail = "open-jump"
        elif lo == hi:
            detail = "fixed-jump"
        else:
            detail = "range-jump"
        return HexNode("jump", lo, hi, detail=detail)

    def _parse_alt(self) -> HexNode:
        self._next()  # consume '('
        alternatives: List[HexNode] = []
        while True:
            alternatives.append(self._parse_sequence(stop_at_paren=True))
            token = self._peek()
            if token == "|":
                self._next()
                continue
            if token == ")":
                self._next()
                break
            raise HexParseError("Unterminated alternation group, expected '|' or ')'")
        if len(alternatives) < 2:
            raise HexParseError("Alternation group needs at least two branches")
        min_length = min(branch.min_length for branch in alternatives)
        maxes = [branch.max_length for branch in alternatives]
        max_length = None if any(value is None for value in maxes) else max(maxes)
        return HexNode("alt", min_length, max_length, detail="alternation",
                       children=alternatives)


def analyze_hex(pattern: str) -> HexNode:
    """Parse ``pattern`` and return its length-bounded AST."""
    return _Parser(_tokenize(pattern)).parse()


def explain(node: HexNode, indent: int = 0) -> str:
    """Render a human-readable proof of the per-node length contribution."""
    pad = "  " * indent
    span = (
        f"{node.min_length}..unbounded"
        if node.max_length is None
        else f"{node.min_length}..{node.max_length}"
    )
    lines = [f"{pad}{node.kind} [{node.detail}] length={span}"]
    for child in node.children:
        lines.append(explain(child, indent + 1))
    return "\n".join(lines)
