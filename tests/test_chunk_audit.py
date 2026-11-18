"""Unit tests for the windowing false-negative pre-check."""
import unittest

from chunk_audit.analyzer import analyze_ruleset
from chunk_audit.audit import audit_ruleset
from chunk_audit.conditions import parse_condition
from chunk_audit.hex_patterns import HexParseError, analyze_hex
from chunk_audit.matcher import (
    compare_windows,
    match_hex,
    match_text,
    windows_for,
)


class HexLengthTests(unittest.TestCase):
    def test_fixed_and_wildcard_bytes(self):
        node = analyze_hex("{ AA ?? D? EF }")
        self.assertTrue(node.bounded)
        self.assertEqual((node.min_length, node.max_length), (4, 4))

    def test_fixed_range_and_open_jumps(self):
        node = analyze_hex("{ AA [3] BB [2-5] CC }")
        self.assertEqual((node.min_length, node.max_length), (8, 11))
        open_node = analyze_hex("{ 11 [4-] 22 }")
        self.assertFalse(open_node.bounded)
        self.assertIsNone(open_node.max_length)
        self.assertEqual(open_node.min_length, 6)
        fully_open = analyze_hex("{ AA [-] BB }")
        self.assertFalse(fully_open.bounded)

    def test_alternation_bounds(self):
        node = analyze_hex("{ ( AA | BB CC DD ) ( 11 | 22 ) }")
        self.assertEqual(node.min_length, 2)       # 1-byte branch + 1-byte branch
        self.assertEqual(node.max_length, 4)       # 3-byte branch + 1-byte branch

    def test_rejects_bad_nibble(self):
        with self.assertRaises(HexParseError):
            analyze_hex("{ GG }")


class WindowGeometryTests(unittest.TestCase):
    def test_clamped_final_window(self):
        self.assertEqual(windows_for(20, 8, 8), [(0, 8), (8, 16), (16, 20)])

    def test_overlapping_windows(self):
        self.assertEqual(windows_for(24, 16, 8),
                         [(0, 16), (8, 24)])


class FiniteMatcherTests(unittest.TestCase):
    def test_hex_matches_fixed_and_wildcard(self):
        tree = analyze_hex("{ DE ?? BE }")
        matches = match_hex(tree, b"\x00\xde\xad\xbe\x00")
        intervals = {(m.start, m.end) for m in matches}
        self.assertIn((1, 4), intervals)

    def test_range_jump_variable_length(self):
        tree = analyze_hex("{ AA [1-2] BB }")
        matches = match_hex(tree, b"\xaa\x00\xbb\xaa\x00\x00\xbb")
        lengths = {m.length for m in matches}
        self.assertEqual(lengths, {3, 4})

    def test_whole_vs_windows_detects_straddle(self):
        tree = analyze_hex("{ DE AD BE EF }")
        data = b"\x00" * 15 + b"\xde\xad\xbe\xef" + b"\x00" * 4
        full, windowed, witnesses = compare_windows(
            lambda buf: match_hex(tree, buf), "$sig", data, 16, 16
        )
        self.assertTrue(full)
        self.assertFalse(windowed)
        self.assertEqual(len(witnesses), 1)
        self.assertEqual((witnesses[0].match.start, witnesses[0].match.end), (15, 19))

    def test_overlap_contains_short_match(self):
        tree = analyze_hex("{ 01 02 }")
        data = b"\x00" * 15 + b"\x01\x02" + b"\x00" * 8
        _, windowed, witnesses = compare_windows(
            lambda buf: match_hex(tree, buf), "$s", data, 16, 8
        )
        self.assertTrue(windowed)
        self.assertEqual(witnesses, [])

    def test_text_and_wide_matching(self):
        self.assertTrue(match_text("AB", [], b"\x41\x42"))
        wide = match_text("AB", ["wide"], b"\x41\x00\x42\x00")
        self.assertTrue(wide)
        nocase = match_text("ab", ["nocase"], b"\x41\x42")
        self.assertTrue(nocase)


class RuleVerdictTests(unittest.TestCase):
    RULES = """
rule straddle { strings: $a = { DE AD BE EF 01 02 03 04 05 06 07 08 } condition: $a }
rule safe { strings: $s = { 01 02 } condition: $s }
rule open { strings: $u = { 11 [-] 22 } condition: $u }
rule sized { strings: $e = "ELF" condition: $e and filesize < 1024 }
rule pair { strings: $a = "AAAA" $b = "BBBB" condition: $a and $b }
rule either { strings: $a = "AA" $b = "BB" condition: $a or $b }
rule atrule { strings: $a = "MZ" condition: $a at 0 }
"""

    def _verdict(self, name):
        return {v.rule_name: v for v in analyze_ruleset(self.RULES, 16, 8)}[name]

    def test_safe_and_risk_length_reasoning(self):
        self.assertEqual(self._verdict("straddle").verdict, "at_risk")
        self.assertEqual(self._verdict("safe").verdict, "safe")

    def test_unbounded_and_global_remain_undecided(self):
        self.assertEqual(self._verdict("open").verdict, "undecided")
        self.assertEqual(self._verdict("sized").verdict, "undecided")
        self.assertEqual(self._verdict("atrule").verdict, "undecided")

    def test_and_distinct_strings_not_claimed_safe(self):
        pair = self._verdict("pair")
        self.assertEqual(pair.verdict, "at_risk")
        self.assertEqual(pair.condition_kind, "mixed-and")
        # OR of short strings remains decidable from per-string length.
        self.assertEqual(self._verdict("either").condition_kind, "single-or-existence")

    def test_audit_produces_witnesses(self):
        reports = {r.rule_name: r for r in audit_ruleset(self.RULES, 16, 8)}
        straddle = reports["straddle"].strings[0]
        self.assertIsNotNone(straddle.witness)
        self.assertTrue(reports["pair"].separation_witness["rule_lost"])
        # Undecided rules never get a matcher witness.
        self.assertIsNone(reports["open"].strings[0].witness)


class ConditionSubsetTests(unittest.TestCase):
    def test_at_is_unsupported_node(self):
        from chunk_audit.conditions import Unsupported, collect_unsupported
        tree = parse_condition(["$a", "at", "0"])
        self.assertIsInstance(tree, Unsupported)
        self.assertTrue(collect_unsupported(tree))

    def test_boolean_connectives(self):
        tree = parse_condition(["$a", "and", "(", "$b", "or", "$c", ")"])
        from chunk_audit.conditions import And, Or
        self.assertIsInstance(tree, And)
        self.assertIsInstance(tree.operands[1], Or)


if __name__ == "__main__":
    unittest.main()
