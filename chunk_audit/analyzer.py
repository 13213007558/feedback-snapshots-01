"""Rule-level static pre-check for sliding-window YARA scanning.

The analyzer decides, *without scanning any sample*, whether a given windowing
policy (window size ``W``, step ``S`` -> guaranteed overlap ``W-S+1``) can
split a match and therefore cause false negatives:

* ``safe``      -- every pattern that can fire the rule has a provable maximum
                    match length ``<= W-S+1`` and the condition uses only the
                    supported position-independent boolean subset;
* ``at_risk``   -- a supported pattern provably has a match longer than the
                    guaranteed overlap, so a straddling witness exists;
* ``undecided`` -- unsupported syntax, an unbounded pattern, or a condition
                    needing global offsets / whole-file state.

The verdict is never based solely on pattern text length: hex alternations,
fixed/range/open jumps and wildcard nibbles are all expanded to provable
minimum/maximum byte spans first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from plyara.core import Plyara
from plyara.exceptions import ParseTypeError, ParseValueError

from .conditions import And, Count, Not, Or, Quantifier, Ref, collect_unsupported, parse_condition
from .hex_patterns import HexParseError, analyze_hex, explain

SAFE = "safe"
AT_RISK = "at_risk"
UNDECIDED = "undecided"

_UNBOUNDED_MODIFIERS = {"base64", "base64wide"}


@dataclass
class StringLength:
    name: str
    kind: str
    min_length: Optional[int]
    max_length: Optional[int]          # None => unbounded / unknown
    bounded: bool
    reasons: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    hex_tree: Optional[object] = None


@dataclass
class RuleVerdict:
    rule_name: str
    verdict: str
    guarantee: int
    strings: Dict[str, StringLength]
    unsupported: List[str] = field(default_factory=list)
    blocking_strings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    condition_kind: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "verdict": self.verdict,
            "guaranteed_overlap": self.guarantee,
            "condition_kind": self.condition_kind,
            "unsupported": self.unsupported,
            "blocking_strings": self.blocking_strings,
            "notes": self.notes,
            "strings": {
                name: {
                    "kind": sl.kind,
                    "min_length": sl.min_length,
                    "max_length": sl.max_length,
                    "bounded": sl.bounded,
                    "modifiers": sl.modifiers,
                    "reasons": sl.reasons,
                }
                for name, sl in self.strings.items()
            },
        }


def analyze_ruleset(rules_text: str, window_size: int, step: int) -> List[RuleVerdict]:
    """Parse a YARA ruleset and return one verdict per rule for the policy."""
    if step <= 0 or window_size <= 0 or step > window_size:
        raise ValueError("Require 0 < step <= window_size")
    try:
        rules = Plyara().parse_string(rules_text)
    except (ParseTypeError, ParseValueError) as exc:
        raise HexParseError(f"Plyara rejected input: {exc}") from exc
    return [_analyze_rule(rule, window_size, step) for rule in rules]


def _analyze_rule(rule: dict, window_size: int, step: int) -> RuleVerdict:
    guarantee = window_size - step + 1
    lengths = {
        entry["name"]: _string_length(entry)
        for entry in rule.get("strings", [])
    }
    verdict = RuleVerdict(
        rule_name=rule.get("rule_name", "<unnamed>"),
        verdict=SAFE,
        guarantee=guarantee,
        strings=lengths,
    )
    _evaluate_condition(rule, verdict)
    _evaluate_lengths(lengths, guarantee, verdict)
    return verdict


# --------------------------------------------------------------------------- #
# String length analysis
# --------------------------------------------------------------------------- #
def _string_length(entry: dict) -> StringLength:
    name = entry["name"]
    kind = entry["type"]
    modifiers = entry.get("modifiers", [])
    if kind == "byte":
        return _hex_length(name, entry["value"], modifiers)
    if kind == "text":
        return _text_length(name, entry["value"], modifiers)
    return _regex_length(name, entry["value"], modifiers)


def _hex_length(name: str, value: str, modifiers: List[str]) -> StringLength:
    try:
        tree = analyze_hex(value)
    except HexParseError as exc:
        return StringLength(name, "byte", None, None, False,
                            [f"unparseable hex syntax: {exc}"], modifiers)
    reasons = [explain(tree).replace("\n", " | ")]
    return StringLength(name, "byte", tree.min_length, tree.max_length,
                        tree.bounded, reasons, modifiers, hex_tree=tree)


def _text_length(name: str, value: str, modifiers: List[str]) -> StringLength:
    base = len(value.encode("latin-1", "backslashreplace"))
    if any(mod in _UNBOUNDED_MODIFIERS or mod.startswith("base64") for mod in modifiers):
        return StringLength(name, "text", None, None, False,
                            ["base64/base64wide encoding depends on surrounding bytes"],
                            modifiers)
    wide = "wide" in modifiers
    ascii_variant = "wide" not in modifiers
    spans = []
    if ascii_variant:
        spans.append(base)
    if wide:
        spans.append(base * 2)
    reasons = [f"literal {base} chars; " + ("wide doubles width" if wide else "ascii width")]
    if any(mod.startswith("xor") for mod in modifiers):
        reasons.append("xor preserves match length")
    return StringLength(name, "text", min(spans), max(spans), True, reasons, modifiers)


def _regex_length(name: str, value: str, modifiers: List[str]) -> StringLength:
    body = value[1:-1] if value.startswith("/") else value
    try:
        min_length, max_length = _regex_bounds(body)
    except _RegexUnbounded:
        return StringLength(name, "regex", None, None, False,
                            ["regex contains unbounded/unsupported construct"], modifiers)
    wide = "wide" in modifiers
    if wide:
        min_length, max_length = min_length * 2, max_length * 2
    return StringLength(name, "regex", min_length, max_length, True,
                        [f"provable regex span {min_length}..{max_length}"], modifiers)


class _RegexUnbounded(Exception):
    """Signals an open quantifier (``*``/``+``/``{n,}``)."""


class _RegexScanner:
    def __init__(self, body: str) -> None:
        self.body = body
        self.pos = 0

    def bounds(self):
        min_length, max_length = self._parse_alternation()
        if self.pos != len(self.body):
            raise _RegexUnbounded()
        return min_length, max_length

    def _parse_alternation(self):
        branches = [self._parse_sequence()]
        while self._peek() == "|":
            self.pos += 1
            branches.append(self._parse_sequence())
        min_length = min(lo for lo, _ in branches)
        max_length = max(hi for _, hi in branches)
        return min_length, max_length

    def _parse_sequence(self):
        total_min = total_max = 0
        while self.pos < len(self.body) and self._peek() not in {"|", ")"}:
            unit_min, unit_max = self._parse_unit()
            q_min, q_max = self._parse_quantifier()
            if q_max is None:
                raise _RegexUnbounded()
            total_min += unit_min * q_min
            total_max += unit_max * q_max
        return total_min, total_max

    def _parse_unit(self):
        char = self._peek()
        if char == "(":
            self.pos += 1
            bounds = self._parse_alternation()
            if self._peek() != ")":
                raise _RegexUnbounded()
            self.pos += 1
            return bounds
        if char == "[":
            self.pos += 1
            if self._peek() == "^":
                self.pos += 1
            if self._peek() == "]":
                self.pos += 1
            while self.pos < len(self.body) and self._peek() != "]":
                self.pos += 1
            if self.pos >= len(self.body):
                raise _RegexUnbounded()
            self.pos += 1
            return 1, 1
        if char == "\\":
            self.pos += 2
            return 1, 1
        if char in {".", "^", "$"}:
            self.pos += 1
            return (1, 1) if char == "." else (0, 0)
        self.pos += 1
        return 1, 1

    def _parse_quantifier(self):
        char = self._peek()
        if char == "?" :
            self.pos += 1
            return 0, 1
        if char in {"*", "+"}:
            self.pos += 1
            if self._peek() == "?":
                self.pos += 1
            return (1, None) if char == "+" else (0, None)
        if char == "{":
            close = self.body.find("}", self.pos)
            if close == -1:
                return 1, 1
            inside = self.body[self.pos + 1:close]
            self.pos = close + 1
            if "," in inside:
                lo_s, hi_s = inside.split(",", 1)
                lo = int(lo_s) if lo_s.strip() else 0
                if not hi_s.strip():
                    return lo, None
                return lo, int(hi_s)
            exact = int(inside)
            return exact, exact
        return 1, 1

    def _peek(self):
        return self.body[self.pos] if self.pos < len(self.body) else None


def _regex_bounds(body: str):
    return _RegexScanner(body).bounds()


# --------------------------------------------------------------------------- #
# Condition analysis
# --------------------------------------------------------------------------- #
def _evaluate_condition(rule: dict, verdict: RuleVerdict) -> None:
    tokens = rule.get("condition_terms", [])
    try:
        tree = parse_condition(tokens)
    except Exception as exc:  # noqa: BLE001 - any parse failure => undecided
        verdict.verdict = UNDECIDED
        verdict.unsupported.append(f"condition not in supported subset: {exc}")
        verdict.condition_kind = "unsupported"
        return
    unsupported = collect_unsupported(tree)
    for node in unsupported:
        verdict.unsupported.append(node.reason)
    if unsupported:
        verdict.verdict = UNDECIDED
        verdict.condition_kind = "global-or-unsupported"
        return
    verdict.condition_kind = _classify_boolean(tree)
    if verdict.condition_kind == "mixed-and":
        verdict.notes.append(
            "AND of distinct strings: each pattern fits a window only individually; "
            "joint placement is demonstrated by the finite matcher, not claimed safe here"
        )


def _classify_boolean(node: object) -> str:
    if isinstance(node, (Ref, Count, Quantifier)):
        return "single-or-existence"
    if isinstance(node, Not):
        return "negated"
    if isinstance(node, Or):
        kinds = {_classify_boolean(child) for child in node.operands}
        return "single-or-existence" if kinds <= {"single-or-existence"} else "mixed-and"
    if isinstance(node, And):
        kinds = [_classify_boolean(child) for child in node.operands]
        if all(kind == "single-or-existence" for kind in kinds) and len(node.operands) == 1:
            return "single-or-existence"
        return "mixed-and"
    return "unsupported"


# --------------------------------------------------------------------------- #
# Length vs. window geometry
# --------------------------------------------------------------------------- #
def _evaluate_lengths(lengths: Dict[str, StringLength], guarantee: int,
                      verdict: RuleVerdict) -> None:
    requires_co_occurrence = verdict.condition_kind == "mixed-and"
    for name, sl in lengths.items():
        if not sl.bounded or sl.max_length is None:
            verdict.blocking_strings.append(name)
            verdict.notes.append(f"{name}: unbounded/unknown match length -> undecided")
            if verdict.verdict == SAFE:
                verdict.verdict = UNDECIDED
            continue
        if sl.max_length > guarantee:
            verdict.blocking_strings.append(name)
            verdict.notes.append(
                f"{name}: max match {sl.max_length} B > guaranteed overlap {guarantee} B "
                f"(window must be at least step + {sl.max_length} - 1 to contain it)"
            )
            if verdict.verdict == SAFE:
                verdict.verdict = AT_RISK
    if requires_co_occurrence and verdict.verdict == SAFE:
        # Each string fits a window individually, but AND needs them in the
        # *same* window, which windowing cannot guarantee by string length alone.
        verdict.verdict = AT_RISK
        verdict.notes.append(
            "short strings joined by AND: co-location in one window is not implied by "
            "per-string length; the finite matcher supplies a separation witness"
        )
    if verdict.verdict == SAFE:
        verdict.notes.append(
            f"every firing pattern has max length <= {guarantee} B of guaranteed overlap; "
            "any match is contained in at least one window"
        )
