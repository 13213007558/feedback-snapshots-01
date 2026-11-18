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
"""Unit tests for the read-only module access auditor."""
import importlib.resources
import unittest

from plyara import AuditCategory, ModuleAccessAuditor, audit_module_access
from plyara.core import Plyara


class TestModuleAccessAuditor(unittest.TestCase):
    """Check import versus condition usage auditing."""

    def setUp(self):
        """Load the shared rulesets and a deliberately small policy."""
        self.data = importlib.resources.files('tests.data.audit')
        self.ruleset = self.data.joinpath('module_access_ruleset.yar').read_text()
        self.unknown_ruleset = self.data.joinpath('unknown_root_ruleset.yar').read_text()
        self.allowed_modules = {
            'pe': {
                'number_of_sections',
                'exports',
                'sections',
                'DLL',
                'machine',
                'characteristics',
            },
            'hash': {'sha256', 'md5'},
        }
        self.rule_exceptions = {
            'exempted_forbidden_member': {'pe.forbidden_member'},
        }

    def _audit(self, text=None, exceptions=None):
        return ModuleAccessAuditor(
            allowed_modules=self.allowed_modules,
            rule_exceptions=exceptions if exceptions is not None else self.rule_exceptions,
        ).audit(text if text is not None else self.ruleset)

    def _findings(self, report, category):
        return [
            finding for finding in report.findings
            if finding.category is category
        ]

    def test_allowed_members_produce_no_blocking_findings(self):
        report = self._audit()
        rule_audit = next(item for item in report.rule_audits if item.rule_name == 'allowed_pe_fields')
        self.assertEqual(rule_audit.used_modules, ['pe'])
        self.assertEqual(rule_audit.blocking_findings, [])

    def test_same_name_string_and_regex_are_pseudo_names(self):
        report = self._audit()
        pseudo = self._findings(report, AuditCategory.PSEUDO_NAME)
        references = {finding.reference for finding in pseudo}

        self.assertIn('$pe', references)
        self.assertIn('$rx', references)
        self.assertIn('pe.number_of_sections', references)
        self.assertIn('pe.forbidden_member', references)

        for finding in pseudo:
            self.assertFalse(finding.exempt)

        same_name_audit = next(
            item for item in report.rule_audits
            if item.rule_name == 'same_name_string_is_not_module_access'
        )
        self.assertEqual(same_name_audit.blocking_findings, [])

        blocking = report.blocking_findings
        self.assertNotIn('pe.number_of_sections', [finding.reference for finding in blocking])
        self.assertNotIn('pe.forbidden_member', [
            finding.reference for finding in blocking
            if finding.rule_name == 'same_name_string_is_not_module_access'
        ])

    def test_forbidden_member_is_unknown_member_with_location(self):
        report = self._audit()
        findings = [
            finding for finding in self._findings(report, AuditCategory.UNKNOWN_MEMBER)
            if finding.rule_name == 'forbidden_pe_member'
        ]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.reference, 'pe.forbidden_member')
        self.assertEqual(finding.line, 26)
        self.assertEqual(finding.column, 9)
        self.assertFalse(finding.exempt)

    def test_dynamic_index_is_reported_as_indeterminate(self):
        report = self._audit()
        findings = self._findings(report, AuditCategory.INDETERMINATE_ACCESS)
        dynamic = [finding for finding in findings if finding.reference == 'pe.sections[i]']
        self.assertEqual(len(dynamic), 1)
        self.assertEqual(dynamic[0].line, 33)

    def test_static_index_nested_member_is_indeterminate(self):
        report = self._audit()
        nested = [
            finding for finding in self._findings(report, AuditCategory.INDETERMINATE_ACCESS)
            if finding.reference == 'pe.sections[0].name'
        ]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0].line, 39)

    def test_indexed_access_still_counts_module_as_used(self):
        report = self._audit()
        dynamic_audit = next(
            item for item in report.rule_audits
            if item.rule_name == 'dynamic_index_is_indeterminate'
        )
        self.assertIn('pe', dynamic_audit.used_modules)

    def test_unused_import_is_reported_once_at_ruleset_scope(self):
        report = self._audit()
        unused = self._findings(report, AuditCategory.UNUSED_IMPORT)
        self.assertEqual(len(unused), 1)
        self.assertEqual(unused[0].reference, 'hash')
        self.assertIsNone(unused[0].rule_name)
        self.assertEqual(unused[0].line, 6)

    def test_rule_exception_exempts_but_still_reports(self):
        report = self._audit()
        findings = [
            finding for finding in self._findings(report, AuditCategory.UNKNOWN_MEMBER)
            if finding.rule_name == 'exempted_forbidden_member'
        ]
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].exempt)

        self.assertNotIn('exempted_forbidden_member', {
            finding.rule_name for finding in report.blocking_findings
        })
        self.assertTrue(any(
            finding.rule_name == 'exempted_forbidden_member'
            for finding in report.findings
        ))

    def test_without_exception_the_same_member_blocks(self):
        report = self._audit(exceptions={})
        exempt_rule_findings = [
            finding for finding in report.blocking_findings
            if finding.rule_name == 'exempted_forbidden_member'
        ]
        self.assertEqual(len(exempt_rule_findings), 1)
        self.assertEqual(exempt_rule_findings[0].category, AuditCategory.UNKNOWN_MEMBER)

    def test_report_fails_when_blocking_findings_exist(self):
        report = self._audit()
        self.assertFalse(report.passed)

    def test_report_passes_for_clean_policy_match(self):
        clean = """
import "pe"

rule clean {
    condition:
        pe.number_of_sections == 1
}
"""
        report = ModuleAccessAuditor(self.allowed_modules).audit(clean)
        self.assertTrue(report.passed)
        self.assertEqual(report.blocking_findings, [])

    def test_allowlisted_module_without_import_is_undeclared(self):
        report = ModuleAccessAuditor(self.allowed_modules).audit(self.unknown_ruleset)
        findings = self._findings(report, AuditCategory.UNDECLARED_MODULE_USE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reference, 'pe.machine')
        self.assertEqual(findings[0].line, 4)

    def test_unknown_module_root_is_ambiguous(self):
        report = ModuleAccessAuditor(self.allowed_modules).audit(self.unknown_ruleset)
        findings = self._findings(report, AuditCategory.AMBIGUOUS_IDENTIFIER)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reference, 'mystery.thing')
        self.assertEqual(findings[0].line, 10)

    def test_audit_does_not_mutate_input_text(self):
        original = self.ruleset
        snapshot = original
        self._audit()
        self.assertEqual(original, snapshot)

    def test_audit_does_not_mutate_parsed_rule_dictionaries(self):
        parser = Plyara(import_effects=True)
        rules = parser.parse_string(self.ruleset)
        import copy
        before = copy.deepcopy(rules)
        self._audit()
        self.assertEqual(rules, before)

    def test_as_dict_is_json_ready(self):
        import json
        report = self._audit()
        encoded = json.dumps(report.as_dict())
        decoded = json.loads(encoded)
        self.assertIn('passed', decoded)
        self.assertIn('findings', decoded)
        self.assertIn('rules', decoded)
        for finding in decoded['findings']:
            self.assertIn('category', finding)
            self.assertIsInstance(finding['exempt'], bool)

    def test_convenience_function_returns_same_report_type(self):
        report = audit_module_access(
            self.ruleset,
            allowed_modules=self.allowed_modules,
            rule_exceptions=self.rule_exceptions,
        )
        self.assertIsInstance(report, type(self._audit()))

    def test_module_presence_does_not_allow_other_members(self):
        policy = {'pe': {'number_of_sections'}}
        report = ModuleAccessAuditor(policy).audit(self.ruleset)
        blocked_members = {
            finding.reference for finding in report.blocking_findings
            if finding.category is AuditCategory.UNKNOWN_MEMBER
        }
        self.assertIn('pe.forbidden_member', blocked_members)
        self.assertIn('pe.exports', blocked_members)


if __name__ == '__main__':
    unittest.main(verbosity=2)
