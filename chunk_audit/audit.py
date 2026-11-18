"""Glue layer: static verdicts plus concrete, matcher-generated witnesses.

For rules whose strings are in the supported bounded subset, synthetic buffers
are built that place a match so it straddles a window boundary (or place two
strings in separate windows). The independent finite matcher then scans both
the whole buffer and every window, proving whether the windowing loses the
match. Unsupported/unbounded rules are reported as undecided and never sent to
the matcher.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from plyara.core import Plyara

from . import analyzer
from .hex_patterns import analyze_hex
from .matcher import compare_windows, match_hex, match_text, windows_for


@dataclass
class StringReport:
    name: str
    kind: str
    max_length: Optional[int]
    witness: Optional[dict] = None


@dataclass
class AuditReport:
    rule_name: str
    verdict: str
    guarantee: int
    condition_kind: str
    unsupported: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    strings: List[StringReport] = field(default_factory=list)
    windows: List[tuple] = field(default_factory=list)
    separation_witness: Optional[dict] = None

    def as_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "verdict": self.verdict,
            "guaranteed_overlap": self.guarantee,
            "condition_kind": self.condition_kind,
            "unsupported": self.unsupported,
            "notes": self.notes,
            "windows": self.windows,
            "separation_witness": self.separation_witness,
            "strings": [
                {
                    "string": sr.name,
                    "kind": sr.kind,
                    "max_length": sr.max_length,
                    "witness": sr.witness,
                }
                for sr in self.strings
            ],
        }


def audit_ruleset(rules_text: str, window_size: int, step: int,
                  buffer_padding: int = 4) -> List[AuditReport]:
    """Return static verdicts augmented with finite-matcher witnesses."""
    verdicts = analyzer.analyze_ruleset(rules_text, window_size, step)
    parsed = {rule["rule_name"]: rule for rule in Plyara().parse_string(rules_text)}
    reports: List[AuditReport] = []
    for verdict in verdicts:
        rule = parsed[verdict.rule_name]
        report = AuditReport(
            rule_name=verdict.rule_name,
            verdict=verdict.verdict,
            guarantee=verdict.guarantee,
            condition_kind=verdict.condition_kind,
            unsupported=list(verdict.unsupported),
            notes=list(verdict.notes),
        )
        for entry in rule.get("strings", []):
            report.strings.append(
                _audit_string(entry, verdict, window_size, step, buffer_padding, report)
            )
        if verdict.condition_kind == "mixed-and":
            report.separation_witness = _separation_witness(
                rule, window_size, step, buffer_padding
            )
        reports.append(report)
    return reports


def _separation_witness(rule: dict, window_size: int, step: int, padding: int):
    """Place two AND-ed strings far apart and prove no window contains both."""
    usable = [entry for entry in rule.get("strings", [])
              if entry["type"] in {"byte", "text"}][:2]
    if len(usable) < 2:
        return None
    first, second = usable
    first_frag = _literal_fragment(first)
    second_frag = _literal_fragment(second)
    first_pos = 0
    second_pos = window_size * 3
    buffer = bytearray(b"\x00" * (second_pos + len(second_frag) + padding))
    buffer[first_pos:first_pos + len(first_frag)] = first_frag
    buffer[second_pos:second_pos + len(second_frag)] = second_frag
    windows = windows_for(len(buffer), window_size, step)
    intervals = [
        (first["name"], first_pos, first_pos + len(first_frag)),
        (second["name"], second_pos, second_pos + len(second_frag)),
    ]
    shared = [
        window for window in windows
        if all(start >= window[0] and end <= window[1] for _, start, end in intervals)
    ]
    return {
        "placements": [{"string": name, "start": lo, "end": hi}
                       for name, lo, hi in intervals],
        "windows": windows,
        "window_containing_all": shared or None,
        "rule_lost": not shared,
    }


def _literal_fragment(entry: dict) -> bytes:
    if entry["type"] == "text":
        return entry["value"].encode("latin-1", "backslashreplace")
    tree = analyze_hex(entry["value"])
    assignment = _max_bytes(tree)
    fragment = bytearray(max(assignment) + 1)
    for offset, value in assignment.items():
        fragment[offset] = value
    return bytes(fragment)


def _audit_string(entry: dict, verdict: analyzer.RuleVerdict, window_size: int,
                  step: int, padding: int, report: AuditReport) -> StringReport:
    name = entry["name"]
    length_info = verdict.strings[name]
    sr = StringReport(name, entry["type"], length_info.max_length)
    if not length_info.bounded or length_info.max_length is None:
        return sr
    if entry["type"] not in {"byte", "text"}:
        report.notes.append(f"{name}: regex length proven statically; not exercised by the byte matcher")
        return sr
    data, match_fn = _build_straddle(entry, window_size, padding)
    report.windows = windows_for(len(data), window_size, step)
    _, _, witnesses = compare_windows(match_fn, name, data, window_size, step)
    if witnesses:
        sr.witness = witnesses[0].as_dict()
    return sr


def _build_straddle(entry: dict, window_size: int, padding: int):
    """Place a *maximum-length* match so it crosses a non-overlapping boundary."""
    boundary = window_size
    start = boundary - 1
    if entry["type"] == "byte":
        tree = analyze_hex(entry["value"])
        assignment = _max_bytes(tree)
        span = max(offset + 1 for offset in assignment)
        data = bytearray(b"\x00" * (start + span + padding))
        for offset, value in assignment.items():
            data[start + offset] = value
        return bytes(data), lambda buf: match_hex(tree, buf)
    modifiers = entry.get("modifiers", [])
    needle = entry["value"].encode("latin-1", "backslashreplace")
    data = bytearray(b"\x00" * (start + len(needle) + padding))
    data[start:start + len(needle)] = needle
    return bytes(data), lambda buf: match_text(entry["value"], modifiers, buf)


def _max_bytes(tree) -> Dict[int, int]:
    """Pick one concrete byte assignment of a hex pattern's maximum match."""
    chosen: Dict[int, int] = {}

    def walk(node, offset):
        if node.kind == "byte":
            if node.raw_byte is not None and "?" not in node.raw_byte:
                chosen[offset] = int(node.raw_byte, 16)
            return offset + 1
        if node.kind == "jump":
            return offset + (node.max_length if node.max_length is not None else node.min_length)
        if node.kind == "alt":
            branch = max(node.children, key=lambda child: child.max_length or child.min_length)
            return walk(branch, offset)
        for child in node.children:
            offset = walk(child, offset)
        return offset

    walk(tree, 0)
    return chosen
