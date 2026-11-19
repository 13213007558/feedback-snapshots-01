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
"""Unit tests for external variable contract checking."""
import importlib.resources
import unittest

import plyara
from plyara.contracts import (
    ContractIssueCode,
    ContractReport,
    ExternalVariableContract,
    RuleContractChecker,
    TermLocator,
    VariableType,
    check_external_variables,
)


def parse(condition):
    """Parse a single-rule condition and return the parsed rule dictionary."""
    return plyara.Plyara().parse_string(f'rule r {{\n  condition:\n    {condition}\n}}')[0]


class TestExternalVariableContract(unittest.TestCase):
    """Check contract construction and validation."""

    def test_declare_with_enum_and_string(self):
        """Enum members and their value strings produce the same contract."""
        enum_contract = ExternalVariableContract({'a': VariableType.INTEGER})
        string_contract = ExternalVariableContract({'a': 'integer'})
        self.assertEqual(enum_contract.type_of('a'), string_contract.type_of('a'))
        self.assertIn('a', enum_contract)
        self.assertEqual(len(enum_contract), 1)

    def test_unknown_type_rejected(self):
        """An unsupported type string raises a ValueError."""
        with self.assertRaises(ValueError):
            ExternalVariableContract({'a': 'object'})

    def test_empty_name_rejected(self):
        """An empty variable name raises a ValueError."""
        with self.assertRaises(ValueError):
            ExternalVariableContract({'': VariableType.INTEGER})

    def test_conflicting_redeclaration_rejected(self):
        """Redeclaring a name with a different type raises a ValueError."""
        contract = ExternalVariableContract({'a': VariableType.INTEGER})
        with self.assertRaises(ValueError):
            contract.declare('a', VariableType.STRING)

    def test_redeclaration_same_type_allowed(self):
        """Redeclaring a name with the same type is idempotent."""
        contract = ExternalVariableContract({'a': VariableType.INTEGER})
        contract.declare('a', VariableType.INTEGER)
        self.assertEqual(contract.names, {'a'})


class TestTermLocator(unittest.TestCase):
    """Check that flat condition terms map back to exact source positions."""

    def _locate(self, source):
        rule = plyara.Plyara().parse_string(source)[0]
        locator = TermLocator(rule['raw_condition'], rule['start_line'], rule['stop_line'])
        return rule, locator

    def _assert_terms_point_at_source(self, source):
        """Every located term must point exactly at itself in the source."""
        rule, locator = self._locate(source)
        source_lines = source.splitlines()
        for index, term in enumerate(rule['condition_terms']):
            line, column, _ = locator.locate(index)
            snippet = source_lines[line - 1][column - 1:column - 1 + len(term)]
            self.assertEqual(snippet, term)

    def test_token_count_aligns_with_plyara(self):
        """The locator finds one position for every emitted term."""
        source = (
            'rule r {\n'
            '  condition:\n'
            '    pe.sections[0].name == "x // not a comment" and #a >= 2 and\n'
            '    uint32(0) == 0xdead and 1..#a and 5KB and ext matches /a\\/b/is\n'
            '}'
        )
        rule, locator = self._locate(source)
        self.assertEqual(len(locator._positions), len(rule['condition_terms']))
        for index, term in enumerate(rule['condition_terms']):
            _, _, offset = locator.locate(index)
            self.assertEqual(locator._body[offset:offset + len(term)], term)

    def test_every_term_points_at_its_source_text(self):
        """Reported line and column land exactly on the originating term."""
        sources = [
            'rule r {\n  condition:\n    ext_int > 0\n    or ext_str > 9\n}',
            'rule r {\n  condition:\n    // leading comment\n    foo >= 2\n}',
            'rule q2 {\ncondition:\n b }',
            'rule q {\ncondition:\n b\n}',
        ]
        for source in sources:
            with self.subTest(source=source):
                self._assert_terms_point_at_source(source)

    def test_comments_do_not_shift_positions(self):
        """Line and block comments inside a condition are skipped."""
        source = (
            'rule r {\n'
            '  condition:\n'
            '    // leading comment\n'
            '    foo /* block */ >= 2 and "q" == "x"\n'
            '}'
        )
        rule, locator = self._locate(source)
        foo_index = rule['condition_terms'].index('foo')
        line, column, _ = locator.locate(foo_index)
        self.assertEqual((line, column), (4, 5))

    def test_multiline_position_is_absolute(self):
        """Line numbers are absolute across multi-line conditions."""
        source = (
            'rule r {\n'
            '  condition:\n'
            '    ext_int > 0\n'
            '    or ext_str > 9\n'
            '}'
        )
        rule, locator = self._locate(source)
        ext_str_index = rule['condition_terms'].index('ext_str')
        line, column, _ = locator.locate(ext_str_index)
        self.assertEqual((line, column), (4, 8))
        ext_int_index = rule['condition_terms'].index('ext_int')
        first_line, first_column, _ = locator.locate(ext_int_index)
        self.assertEqual((first_line, first_column), (3, 5))

    def test_shared_marker_line_uses_condition_relative_column(self):
        """A body on the condition marker line is located within that line."""
        source = 'rule same { condition: ext_str == 1 }'
        rule, locator = self._locate(source)
        ext_str_index = rule['condition_terms'].index('ext_str')
        line, column, _ = locator.locate(ext_str_index)
        self.assertEqual(line, 1)
        self.assertEqual(
            rule['raw_condition'][column - 1:column - 1 + len('ext_str')], 'ext_str'
        )


class TestSupportedExpressions(unittest.TestCase):
    """Check that correctly typed, supported expressions are verified."""

    def setUp(self):
        """Build a contract covering every external type."""
        self.contract = ExternalVariableContract({
            'ext_integer': VariableType.INTEGER,
            'ext_string': VariableType.STRING,
            'ext_boolean': VariableType.BOOLEAN,
            'ext_float': VariableType.FLOAT,
        })

    def check(self, condition):
        """Return the report for a single-rule condition."""
        return check_external_variables([parse(condition)], self.contract)

    def test_scalar_contract_usage_verifies(self):
        """Each external type used correctly produces no issues."""
        report = self.check(
            'ext_integer > 1 and ext_string contains "x" and '
            'ext_boolean == true and ext_float + 1.0 > 0.5'
        )
        self.assertTrue(report.is_valid)
        self.assertEqual(report.verified_rules, ['r'])

    def test_integer_float_comparison_verifies(self):
        """Integers and floats are mutually comparable."""
        report = self.check('ext_integer == ext_float')
        self.assertTrue(report.is_valid)

    def test_defined_and_not_verify(self):
        """Defined and logical negation of a boolean are supported."""
        report = self.check('defined ext_integer and not ext_boolean')
        self.assertTrue(report.is_valid)

    def test_true_false_branches_verify(self):
        """Both branches of a disjunction are independently derived."""
        condition = (
            '(ext_boolean and ext_integer > 0) or '
            '(not ext_boolean and ext_string startswith "a")'
        )
        report = self.check(condition)
        self.assertTrue(report.is_valid)

    def test_rule_reference_is_boolean(self):
        """A reference to another rule resolves to a boolean."""
        rules = plyara.Plyara().parse_string(
            'rule base { condition: true }\n'
            'rule dependent { condition: base and ext_integer == 1 }'
        )
        report = check_external_variables(rules, self.contract)
        self.assertEqual(report.verified_rules, ['base', 'dependent'])

    def test_legal_module_expression_preserved(self):
        """Unknown but well-formed module fields stay legal when mixed."""
        rules = plyara.Plyara().parse_string(
            'import "pe"\n'
            'rule r { condition: pe.unknown_deep.field == ext_integer }'
        )
        report = check_external_variables(rules, self.contract)
        self.assertTrue(report.is_valid)


class TestTypeConflicts(unittest.TestCase):
    """Check that contract type misuse is reported as a type conflict."""

    def setUp(self):
        """Build a contract covering every external type."""
        self.contract = ExternalVariableContract({
            'ext_integer': VariableType.INTEGER,
            'ext_string': VariableType.STRING,
            'ext_boolean': VariableType.BOOLEAN,
            'ext_float': VariableType.FLOAT,
        })

    def check(self, condition):
        """Return the single issue reported for a condition."""
        report = check_external_variables([parse(condition)], self.contract)
        self.assertEqual(len(report.issues), 1)
        return report.issues[0]

    def test_string_compared_as_integer(self):
        """A string external on the ordering side is a conflict."""
        issue = self.check('ext_string > 5')
        self.assertEqual(issue.code, ContractIssueCode.TYPE_CONFLICT)
        self.assertEqual(issue.term, 'ext_string')

    def test_integer_used_as_string(self):
        """An integer external fed to a string operator is a conflict."""
        issue = self.check('ext_integer contains "x"')
        self.assertEqual(issue.code, ContractIssueCode.TYPE_CONFLICT)
        self.assertEqual(issue.term, 'ext_integer')

    def test_boolean_used_in_arithmetic(self):
        """A boolean external in arithmetic is a conflict."""
        issue = self.check('ext_boolean + 1 > 0')
        self.assertEqual(issue.code, ContractIssueCode.TYPE_CONFLICT)
        self.assertEqual(issue.term, 'ext_boolean')

    def test_string_matches_integer_is_conflict(self):
        """The right side of matches must be a regex."""
        issue = self.check('ext_string matches ext_integer')
        self.assertEqual(issue.code, ContractIssueCode.TYPE_CONFLICT)

    def test_float_bitwise_is_unsupported_not_conflict(self):
        """A bitwise operator on a float is unsupported, not a contract clash."""
        report = check_external_variables([parse('ext_float & 1 == 0')], self.contract)
        self.assertEqual(report.issues[0].code, ContractIssueCode.UNSUPPORTED_EXPRESSION)

    def test_conflict_excludes_from_verified(self):
        """A rule with a conflict never appears in the verified list."""
        report = check_external_variables([parse('ext_string > 5')], self.contract)
        self.assertEqual(report.verified_rules, [])
        self.assertFalse(report.is_valid)


class TestUndeclaredAndUnsupported(unittest.TestCase):
    """Check fail-closed handling of missing definitions and unknown forms."""

    def setUp(self):
        """Build a minimal integer-only contract."""
        self.contract = ExternalVariableContract({'ext_integer': VariableType.INTEGER})

    def test_undeclared_identifier_reported(self):
        """An identifier absent from every scope is undeclared."""
        report = check_external_variables([parse('ext_missing == 1')], self.contract)
        issue = report.issues[0]
        self.assertEqual(issue.code, ContractIssueCode.UNDECLARED_IDENTIFIER)
        self.assertEqual(issue.term, 'ext_missing')

    def test_unknown_call_target_is_unsupported(self):
        """A call on a bare non-module identifier cannot be auto-passed."""
        report = check_external_variables([parse('ext_integer == mystery(1)')], self.contract)
        self.assertEqual(report.issues[0].code, ContractIssueCode.UNSUPPORTED_EXPRESSION)

    def test_non_imported_dotted_path_undeclared(self):
        """A dotted name that is not an imported module is undeclared."""
        report = check_external_variables([parse('ext_integer in ghost.field')], self.contract)
        self.assertEqual(report.issues[0].code, ContractIssueCode.UNDECLARED_IDENTIFIER)

    def test_unsupported_construct_does_not_auto_pass(self):
        """An unsupported expression keeps the rule out of the verified list."""
        report = check_external_variables([parse('ext_integer == mystery(1)')], self.contract)
        self.assertFalse(report.is_valid)
        self.assertEqual(report.verified_rules, [])


class TestLoopScopes(unittest.TestCase):
    """Check loop local variables, shadowing and nested iteration."""

    def setUp(self):
        """Build a contract with an integer and a string external."""
        self.contract = ExternalVariableContract({
            'ext_integer': VariableType.INTEGER,
            'ext_string': VariableType.STRING,
        })

    def check(self, condition):
        """Return the report for a single-rule condition."""
        return check_external_variables([parse(condition)], self.contract)

    def test_nested_loops_with_distinct_locals_verify(self):
        """Each nested loop binds its own integer local variable."""
        condition = (
            'for all i in (1 .. 3) : ( '
            'for any j in (1 .. 3) : ( i > 0 and j > 0 and ext_integer > i + j ) )'
        )
        report = self.check(condition)
        self.assertTrue(report.is_valid)

    def test_same_name_local_shadows_external(self):
        """A loop local named like an external integer shadows it in the body."""
        condition = 'for any ext_string in (1 .. 5) : ( ext_string > 0 ) and ext_string contains "x"'
        report = self.check(condition)
        self.assertTrue(report.is_valid)

    def test_nested_same_name_shadows_outer_local(self):
        """An inner loop local may shadow the outer loop local of the same name."""
        condition = (
            'for all i in (1 .. 3) : ( '
            'for any i in (4 .. 6) : ( i > 3 ) and i < 4 )'
        )
        report = self.check(condition)
        self.assertTrue(report.is_valid)

    def test_loop_local_type_misuse_is_unsupported(self):
        """Misusing an integer loop local as a string is unsupported."""
        report = self.check('for any i in (1 .. 3) : ( i contains "x" )')
        issue = report.issues[0]
        self.assertEqual(issue.code, ContractIssueCode.UNSUPPORTED_EXPRESSION)
        self.assertEqual(issue.term, 'i')
        self.assertIn('loop local', issue.rationale)

    def test_loop_local_does_not_escape_scope(self):
        """A loop local referenced after the loop is undeclared."""
        report = self.check('for any i in (1 .. 3) : ( i > 0 ) and i > 0')
        self.assertEqual(report.issues[0].code, ContractIssueCode.UNDECLARED_IDENTIFIER)
        self.assertEqual(report.issues[0].term, 'i')

    def test_iterating_integer_set_binds_integer_local(self):
        """Iterating a parenthesized integer set binds an integer local."""
        report = self.check('for any k in (ext_integer, 2, 3) : ( k >= ext_integer )')
        self.assertTrue(report.is_valid)

    def test_for_of_string_set_verifies(self):
        """A for-of loop over string identifiers is boolean."""
        rules = plyara.Plyara().parse_string(
            'rule r { strings: $a = "x" condition: for any of them : ( $ at filesize ) }'
        )
        report = check_external_variables(rules, self.contract)
        self.assertTrue(report.is_valid)


class TestContractRulesetFixture(unittest.TestCase):
    """Check the curated valid and invalid rules end to end."""

    EXPECTED_VERIFIED = [
        'valid_simple_contract',
        'valid_module_mix',
        'valid_true_false_branches',
        'valid_nested_loops',
        'valid_same_name_local_shadows_external',
        'valid_string_quantifiers',
    ]
    EXPECTED_REJECTED = {
        'invalid_string_compared_as_integer': ContractIssueCode.TYPE_CONFLICT,
        'invalid_integer_used_as_string': ContractIssueCode.TYPE_CONFLICT,
        'invalid_boolean_used_in_arithmetic': ContractIssueCode.TYPE_CONFLICT,
        'invalid_undeclared_variable': ContractIssueCode.UNDECLARED_IDENTIFIER,
        'invalid_loop_local_type_misuse': ContractIssueCode.UNSUPPORTED_EXPRESSION,
        'invalid_loop_local_leaves_scope': ContractIssueCode.UNDECLARED_IDENTIFIER,
    }

    def setUp(self):
        """Parse the fixture ruleset and build its contract."""
        data = importlib.resources.files('tests.data.contracts')
        ruleset = plyara.Plyara().parse_string(data.joinpath('contract_ruleset.yar').read_text())
        contract = ExternalVariableContract({
            'ext_integer': VariableType.INTEGER,
            'ext_string': VariableType.STRING,
            'ext_boolean': VariableType.BOOLEAN,
        })
        self.report = check_external_variables(ruleset, contract)

    def test_verified_and_rejected_partition(self):
        """The verified list and rejected rules form a clean partition."""
        rejected = {issue.rule_name for issue in self.report.issues}
        self.assertEqual(sorted(self.report.verified_rules), sorted(self.EXPECTED_VERIFIED))
        self.assertEqual(set(rejected), set(self.EXPECTED_REJECTED))
        self.assertFalse(set(self.report.verified_rules) & rejected)

    def test_expected_issue_codes(self):
        """Each invalid rule reports the precise issue code."""
        codes = {issue.rule_name: issue.code for issue in self.report.issues}
        self.assertEqual(codes, self.EXPECTED_REJECTED)

    def test_every_issue_has_location_and_rationale(self):
        """Issues carry a concrete condition location and derivation basis."""
        for issue in self.report.issues:
            self.assertIsNotNone(issue.line)
            self.assertIsNotNone(issue.column)
            self.assertIsNotNone(issue.term)
            self.assertTrue(issue.rationale)

    def test_report_serialization(self):
        """The report is JSON-serializable and self-describing."""
        payload = self.report.as_dict()
        self.assertFalse(payload['is_valid'])
        self.assertEqual(len(payload['issues']), len(self.EXPECTED_REJECTED))
        for issue in payload['issues']:
            self.assertEqual(issue['severity'], 'error')
            self.assertIn(issue['code'], {code.value for code in ContractIssueCode})


class TestNoEvaluation(unittest.TestCase):
    """Check that the checker derives types without evaluating conditions."""

    def setUp(self):
        """Build an integer contract."""
        self.contract = ExternalVariableContract({'ext_integer': VariableType.INTEGER})

    def test_division_by_zero_does_not_raise(self):
        """A condition that would raise when evaluated is only type-checked."""
        rule = parse('ext_integer > (1 \\ 0)')
        report = check_external_variables([rule], self.contract)
        self.assertTrue(report.is_valid)

    def test_checker_returns_report_type(self):
        """The convenience entry point returns a ContractReport."""
        report = check_external_variables([parse('ext_integer > 0')], self.contract)
        self.assertIsInstance(report, ContractReport)

    def test_syntax_error_becomes_issue_not_exception(self):
        """An ungroupable term stream is reported as unsupported, not raised."""
        rule = {
            'rule_name': 'broken',
            'start_line': 1,
            'raw_condition': 'condition: (',
            'condition_terms': ['('],
        }
        report = RuleContractChecker(self.contract, [rule]).check()
        self.assertEqual(report.issues[0].code, ContractIssueCode.UNSUPPORTED_EXPRESSION)
        self.assertIsInstance(report.issues[0].term_index, int)


if __name__ == '__main__':
    unittest.main()
