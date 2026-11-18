"""Independent finite matcher used to *demonstrate* windowing misses.

The matcher is deliberately self-contained (plain Python, no YARA engine) and
only implements the provably bounded subset accepted by the analyzer:

* hex strings with fixed/range/open-free jumps, wildcard nibbles and bounded
  alternation groups;
* text strings with ``ascii``/``wide``/``nocase``/``xor``/``fullword``.

It reports every match interval ``(start, end)``. Comparing matches on the
whole buffer with matches contained in individual sliding windows yields
concrete false-negative witnesses. The buffers here are synthetic fixtures --
the analyzer never scans real samples.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from .hex_patterns import HexNode


@dataclass(frozen=True)
class Match:
    start: int
    end: int                     # exclusive

    @property
    def length(self) -> int:
        return self.end - self.start


# --------------------------------------------------------------------------- #
# Hex matching
# --------------------------------------------------------------------------- #
def _byte_matches(pattern_byte: str, value: int) -> bool:
    high, low = pattern_byte[0], pattern_byte[1]
    if high != "?" and int(high, 16) != (value >> 4):
        return False
    if low != "?" and int(low, 16) != (value & 0x0F):
        return False
    return True


def _hex_endpoints(node: HexNode, data: bytes, pos: int) -> List[int]:
    """Return all end offsets reachable by matching ``node`` at ``pos``."""
    kind = node.kind
    if kind == "byte":
        if pos < len(data) and _byte_matches(node.raw_byte, data[pos]):
            return [pos + 1]
        return []
    if kind == "jump":
        lo, hi = node.min_length, node.max_length
        upper = len(data) if hi is None else min(len(data), pos + hi)
        return [end for end in range(pos + lo, upper + 1)]
    if kind == "alt":
        ends: List[int] = []
        for branch in node.children:
            ends.extend(_hex_endpoints(branch, data, pos))
        return ends
    if kind == "seq":
        endpoints = [pos]
        for child in node.children:
            nxt: List[int] = []
            for endpoint in endpoints:
                nxt.extend(_hex_endpoints(child, data, endpoint))
            endpoints = list(dict.fromkeys(nxt))
            if not endpoints:
                return []
        return endpoints
    raise ValueError(f"Unknown hex node kind {kind!r}")


def _token_of(node: HexNode) -> str:
    # Retained for debugging; byte matching uses ``HexNode.raw_byte``.
    return getattr(node, "raw_byte", "??")


def match_hex(node: HexNode, data: bytes) -> List[Match]:
    """Find all matches of a bounded hex AST, including variable-length ones."""
    matches: List[Match] = []
    for start in range(len(data) + 1):
        for end in _hex_endpoints(node, data, start):
            matches.append(Match(start, end))
    return matches


# --------------------------------------------------------------------------- #
# Text string matching
# --------------------------------------------------------------------------- #
def _text_encodings(value: bytes, modifiers: Sequence[str]) -> List[bytes]:
    wide = any(mod == "wide" or mod.startswith("base64wide") for mod in modifiers)
    ascii_mode = not any(mod == "wide" for mod in modifiers)
    variants: List[bytes] = []
    if ascii_mode:
        variants.append(value)
    if wide:
        variants.append(b"".join(bytes([char, 0]) for char in value))
    return variants


def _xor_keys(modifiers: Sequence[str]) -> List[int]:
    keys = [0]
    for mod in modifiers:
        if mod == "xor":
            keys = list(range(256))
        elif mod.startswith("xor("):
            bounds = mod[4:-1]
            if "-" in bounds:
                lo_s, hi_s = bounds.split("-")
                keys = list(range(int(lo_s, 0), int(hi_s, 0) + 1))
            else:
                keys = [int(bounds, 0)]
    return keys


def match_text(value: str, modifiers: Sequence[str], data: bytes) -> List[Match]:
    raw = value.encode("latin-1", "backslashreplace")
    nocase = "nocase" in modifiers
    fullword = "fullword" in modifiers
    matches: List[Match] = []
    for key in _xor_keys(modifiers):
        encoded = bytes(byte ^ key for byte in raw)
        for needle in _text_encodings(encoded, modifiers):
            needle_cf = needle.lower() if nocase else needle
            for start in range(len(data) - len(needle) + 1):
                window = data[start:start + len(needle)]
                if (window.lower() if nocase else window) != needle_cf:
                    continue
                if fullword and not _is_fullword(data, start, start + len(needle)):
                    continue
                matches.append(Match(start, start + len(needle)))
    return _dedupe(matches)


def _is_fullword(data: bytes, start: int, end: int) -> bool:
    left_ok = start == 0 or not _is_word(data[start - 1])
    right_ok = end == len(data) or not _is_word(data[end])
    return left_ok and right_ok


def _is_word(value: int) -> bool:
    return chr(value).isalnum() or value == 0x5F


def _dedupe(matches: List[Match]) -> List[Match]:
    return list(dict.fromkeys(matches))


# --------------------------------------------------------------------------- #
# Windowing comparison
# --------------------------------------------------------------------------- #
def windows_for(length: int, window_size: int, step: int) -> List[tuple]:
    """Return ``(window_start, window_end)`` with a clamped final window."""
    if length == 0:
        return [(0, 0)]
    windows: List[tuple] = []
    start = 0
    while start < length:
        end = min(length, start + window_size)
        windows.append((start, end))
        if end == length:
            break
        start += step
    return windows


def contained_in_any_window(match: Match, windows: List[tuple]) -> bool:
    return any(start <= match.start and match.end <= end for start, end in windows)


@dataclass
class Witness:
    string_name: str
    match: Match
    crossing_gap: Optional[tuple]   # the (window_end, next_window_start) boundary straddled

    def as_dict(self) -> dict:
        return {
            "string": self.string_name,
            "start": self.match.start,
            "end": self.match.end,
            "length": self.match.length,
            "crossing_boundary": self.crossing_gap,
        }


def compare_windows(match_fn: Callable[[bytes], List[Match]],
                    name: str, data: bytes, window_size: int, step: int):
    """Run ``match_fn`` on the full buffer and per window, returning misses."""
    full_matches = match_fn(data)
    windows = windows_for(len(data), window_size, step)
    windowed: List[Match] = []
    for win_start, win_end in windows:
        for local in match_fn(data[win_start:win_end]):
            windowed.append(Match(win_start + local.start, win_start + local.end))
    windowed_set = set(windowed)
    missed = [match for match in full_matches if match not in windowed_set]
    witnesses: List[Witness] = []
    for match in missed:
        gap = _straddled_gap(match, windows)
        witnesses.append(Witness(name, match, gap))
    return full_matches, windowed, witnesses


def _straddled_gap(match: Match, windows: List[tuple]) -> Optional[tuple]:
    for index in range(len(windows) - 1):
        left_end = windows[index][1]
        right_start = windows[index + 1][0]
        boundary = max(right_start, min(left_end, match.end - 1))
        # A match is split when a window boundary falls strictly inside it and
        # neither neighbouring window spans the whole interval.
        if right_start < match.end and left_end > match.start and not (
            windows[index][0] <= match.start and match.end <= left_end
        ) and not (right_start <= match.start and match.end <= windows[index + 1][1]):
            return (min(left_end, right_start), max(left_end, right_start), boundary)
    return None
