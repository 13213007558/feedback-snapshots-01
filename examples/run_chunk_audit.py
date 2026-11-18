"""Demonstrate the windowing false-negative pre-check.

Run with::

    .venv/bin/python examples/run_chunk_audit.py

It uses a synthetic in-memory buffer (never a real sample) and an independent
finite matcher to contrast whole-buffer matches against per-window matches.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from chunk_audit.audit import audit_ruleset
from chunk_audit.matcher import Match, match_text, windows_for

WINDOW_SIZE = 16
STEP = 8                       # guaranteed overlap = 16 - 8 + 1 = 9 bytes
RULES_PATH = pathlib.Path(__file__).with_name("chunking_rules.yar")


def demo_far_apart() -> None:
    """Two 4-byte strings placed 64 bytes apart under a 16-byte window."""
    data = bytearray(b"\x00" * 96)
    data[4:8] = b"AAAA"
    data[68:72] = b"BBBB"
    windows = windows_for(len(data), WINDOW_SIZE, STEP)
    whole_a = {m for m in match_text("AAAA", [], bytes(data))}
    whole_b = {m for m in match_text("BBBB", [], bytes(data))}

    def windowed(match_fn):
        found = set()
        for start, end in windows:
            for local in match_fn(bytes(data[start:end])):
                found.add(Match(start + local.start, start + local.end))
        return found

    win_a, win_b = windowed(lambda buf: match_text("AAAA", [], buf)), \
        windowed(lambda buf: match_text("BBBB", [], buf))
    intervals_a = [(m.start, m.end) for m in win_a]
    intervals_b = [(m.start, m.end) for m in win_b]
    co_occur = any(
        any(not (ea <= sb or eb <= sa) for sb, eb in intervals_b)
        for sa, ea in intervals_a
    )
    print("far_apart_pair:")
    print(f"  whole-buffer matches: A={sorted(map(_label, whole_a))}, B={sorted(map(_label, whole_b))}")
    print(f"  windows={windows}")
    print(f"  any single window containing both: {co_occur} (rule is lost under AND)")


def _label(match: Match) -> str:
    return f"[{match.start},{match.end})"


def main() -> None:
    print(f"Window policy: W={WINDOW_SIZE}, S={STEP}, guaranteed overlap={WINDOW_SIZE - STEP + 1} bytes\n")
    reports = audit_ruleset(RULES_PATH.read_text(), WINDOW_SIZE, STEP)
    for report in reports:
        doc = report.as_dict()
        print(f"{doc['rule']}: {doc['verdict'].upper()} (condition={doc['condition_kind']})")
        for note in doc["notes"]:
            print(f"  - {note}")
        for item in doc["strings"]:
            if item["witness"]:
                witness = item["witness"]
                print(f"  ! witness {item['string']} match [{witness['start']},{witness['end']}) "
                      f"crosses boundary {witness['crossing_boundary']} -> not contained in any window")
        if doc["separation_witness"]:
            sw = doc["separation_witness"]
            placed = ", ".join(f"{p['string']}@[{p['start']},{p['end']})" for p in sw["placements"])
            print(f"  ! separation witness ({placed}); a window containing both exists: "
                  f"{sw['window_containing_all'] is not None} -> rule_lost={sw['rule_lost']}")
        for reason in doc["unsupported"]:
            print(f"  ? undecided: {reason}")
        print()
    demo_far_apart()


if __name__ == "__main__":
    main()
