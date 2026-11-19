"""Unit tests for bounded YARA witness generation."""
import unittest

from plyara.core import Plyara
from plyara.witness import (
    MAX_CANDIDATES,
    MAX_LENGTH,
    UnsupportedRuleError,
    check_rule,
    explain_rule,
    generate_witness,
    generate_witnesses,
)


def parse_one(source):
    """Parse a single rule with a fresh parser."""
    rules = Plyara().parse_string(source)
    assert len(rules) == 1
    return rules[0]


class TestSatisfiableWitness(unittest.TestCase):
    """A supported rule should yield a short verified candidate."""

    def setUp(self):
        self.rule = parse_one(
            'rule supported { strings: $a = "MAGIC" $b = { 4D 5A ?? 00 [1-2] 41 } '
            'condition: $b at 0 and $a in (7..12) and filesize >= 11 }'
        )

    def test_witness_is_found_and_verified(self):
        result = generate_witness(self.rule, max_length=32)

        self.assertEqual(result.status, 'witness')
        self.assertIsNotNone(result.candidate)
        self.assertGreaterEqual(len(result.candidate), 11)
        self.assertTrue(check_rule(self.rule, result.candidate))

    def test_evidence_names_the_satisfied_atoms(self):
        result = generate_witness(self.rule, max_length=32)
        atoms = {item['atom']: item['value'] for item in result.evidence['atoms']}

        self.assertTrue(atoms['$b at 0'])
        self.assertTrue(any(key.startswith('$a in ') and value for key, value in atoms.items()))
        self.assertTrue(atoms['filesize >= 11'])

    def test_bound_reports_the_search(self):
        result = generate_witness(self.rule, max_length=32, max_candidates=100)

        self.assertEqual(result.bound['max_length'], 32)
        self.assertEqual(result.bound['max_candidates'], 100)
        self.assertGreaterEqual(result.bound['candidates_checked'], 1)
        self.assertEqual(result.bound['dnf_clauses'], 1)


class TestOverlappingWitness(unittest.TestCase):
    """Different strings may overlap when their concrete bytes agree."""

    def test_overlapping_text_strings_are_satisfiable(self):
        rule = parse_one(
            'rule overlap { strings: $a = "ABCD" $b = "BCDE" '
            'condition: $a at 0 and $b at 1 }'
        )

        result = generate_witness(rule, max_length=12)

        self.assertEqual(result.status, 'witness')
        self.assertEqual(result.candidate, b'ABCDE')
        self.assertTrue(check_rule(rule, result.candidate))

    def test_hex_alternation_can_match_an_overlapping_text_string(self):
        rule = parse_one(
            'rule overlap_hex { strings: $a = { 41 ( 42 | 43 ) } $b = "BC" '
            'condition: $a at 0 and $b at 1 }'
        )

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'witness')
        self.assertEqual(result.candidate, b'ABC')
        self.assertTrue(check_rule(rule, result.candidate))


class TestConflictingWitness(unittest.TestCase):
    """Conflicting placements should be reported as bounded failure, not unsatisfiability."""

    def setUp(self):
        self.rule = parse_one(
            'rule conflicting { strings: $a = "ABCD" $b = "WXYZ" '
            'condition: $a at 0 and $b at 2 }'
        )

    def test_no_witness_within_bound(self):
        result = generate_witness(self.rule, max_length=16)

        self.assertEqual(result.status, 'no_witness_within_bound')
        self.assertIsNone(result.candidate)
        self.assertIn('not a proof of unsatisfiability', result.reason)
        self.assertFalse(result.bound['complete_for_supported_subset'])

    def test_range_skips_a_position_reserved_by_at(self):
        rule = parse_one(
            'rule reserved { strings: $a = "MAGIC" $b = "WXYZ" '
            'condition: $a at 0 and $b in (1..6) }'
        )

        result = generate_witness(rule, max_length=16)

        self.assertEqual(result.status, 'witness')
        self.assertTrue(check_rule(rule, result.candidate))
        self.assertNotEqual(result.candidate.find(b'WXYZ'), 1)

    def test_matcher_rejects_a_non_conflicting_layout(self):
        self.assertFalse(check_rule(self.rule, b'ABCDWXYZ'))

    def test_matcher_rejects_every_conflicting_layout(self):
        for data in (b'ABWXYZ', b'ABCDWXYZ', b'\x00ABCDWXYZ', b'ABCD' + b'WXYZ'):
            with self.subTest(data=data):
                self.assertFalse(check_rule(self.rule, data))


class TestUnsupportedWitness(unittest.TestCase):
    """Rules outside the subset must be undecided rather than approximated."""

    def test_regex_string_is_undecided(self):
        rule = parse_one('rule regex_rule { strings: $a = /ab+c/ condition: $a }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'undecided')
        self.assertIsNone(result.candidate)
        self.assertIn('regex', result.reason)

    def test_module_function_is_undecided(self):
        rule = parse_one(
            'rule module_rule { strings: $a = "AB" condition: $a and uint16(0) == 0x5A4D }'
        )

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'undecided')
        self.assertIn('uint16', result.reason)

    def test_unbounded_jump_is_undecided(self):
        rule = parse_one('rule jump_rule { strings: $a = { 41 [3-] 42 } condition: $a }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'undecided')
        self.assertIn('jump', result.reason)

    def test_matcher_also_rejects_out_of_subset_rule(self):
        rule = parse_one('rule jump_rule { strings: $a = { 41 [3-] 42 } condition: $a }')

        with self.assertRaises(UnsupportedRuleError):
            check_rule(rule, b'A\x00\x00\x00B')

    def test_oversized_pattern_is_undecided(self):
        rule = parse_one('rule big_jump { strings: $a = { 41 [50] 42 } condition: $a }')

        result = generate_witness(rule, max_length=16)

        self.assertEqual(result.status, 'undecided')
        self.assertIn('max_length', result.reason)

    def test_top_level_alternation_is_supported(self):
        rule = parse_one('rule bare_alt { strings: $a = { 41 | 42 } condition: $a at 0 }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'witness')
        self.assertEqual(result.candidate, b'A')

    def test_string_modifier_is_undecided(self):
        rule = parse_one('rule modifier_rule { strings: $a = "AB" nocase condition: $a }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'undecided')
        self.assertIn('modifier', result.reason)


class TestNegationAndAbsence(unittest.TestCase):
    """Negated references and ranges must constrain the generated bytes."""

    def test_absent_string_with_small_filesize(self):
        rule = parse_one('rule absent { strings: $a = "AB" condition: not $a and filesize <= 2 }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'witness')
        self.assertLessEqual(len(result.candidate), 2)
        self.assertNotIn(b'AB', result.candidate)

    def test_range_excluding_one_start(self):
        rule = parse_one(
            'rule ranged { strings: $a = "AB" condition: $a in (3..6) and not ($a at 3) }'
        )

        result = generate_witness(rule, max_length=12)

        self.assertEqual(result.status, 'witness')
        self.assertTrue(check_rule(rule, result.candidate))
        self.assertGreater(result.candidate.find(b'AB'), 3)


class TestPublicApi(unittest.TestCase):
    """Exercise the ruleset API, matcher errors and explanation output."""

    def test_generate_witnesses_returns_one_result_per_rule(self):
        rules = Plyara().parse_string(
            'rule one { strings: $a = "A" condition: $a } '
            'rule two { strings: $b = { 42 [1] 43 } condition: $b at 1 }'
        )

        results = generate_witnesses(rules, max_length=16)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.status == 'witness' for result in results))
        self.assertTrue(all(check_rule(rule, result.candidate) for rule, result in zip(rules, results)))

    def test_explain_rule_records_occurrences(self):
        rule = parse_one('rule evidence { strings: $a = "AB" condition: $a at 2 }')

        evidence = explain_rule(rule, b'00AB')

        self.assertEqual(evidence['filesize'], 4)
        self.assertEqual(evidence['strings']['$a']['occurrences'], [2])
        self.assertTrue(evidence['matched'])

    def test_matcher_raises_for_unsupported_rule(self):
        rule = parse_one('rule unsupported { strings: $a = "AB" condition: $a or true and uint8(0) }')

        with self.assertRaises(UnsupportedRuleError):
            check_rule(rule, b'AB')

    def test_filesize_only_rule_needs_no_strings(self):
        rule = parse_one('rule size_only { condition: filesize == 5 }')

        result = generate_witness(rule, max_length=8)

        self.assertEqual(result.status, 'witness')
        self.assertEqual(len(result.candidate), 5)
        self.assertTrue(check_rule(rule, result.candidate))

    def test_default_bounds_are_exposed(self):
        rule = parse_one('rule defaults { strings: $a = "AB" condition: $a }')

        result = generate_witness(rule)

        self.assertEqual(result.bound['max_length'], MAX_LENGTH)
        self.assertEqual(result.bound['max_candidates'], MAX_CANDIDATES)


if __name__ == '__main__':
    unittest.main(verbosity=2)
