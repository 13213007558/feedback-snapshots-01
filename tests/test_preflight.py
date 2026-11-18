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
"""Unit tests for the offline namespace link preflight."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from plyara.preflight import SourceText
from plyara.preflight import preflight

ALPHA = """
private rule shared_helper {
    strings:
        $alpha = "alpha 4c 6f 67 69 63"
    condition:
        $alpha
}

global rule alpha_gate {
    condition:
        true
}

rule entry_alpha {
    condition:
        shared_helper and alpha_gate and beta.shared_helper and ext_score > 10
}
"""

BETA = """
private rule shared_helper {
    strings:
        $beta = { 42 45 54 41 }
    condition:
        $beta
}

rule entry_beta {
    condition:
        shared_helper and ext_score > 20
}
"""


class TestPreflight(unittest.TestCase):
    """Verify namespace-scoped linking and deterministic reporting."""

    def sources(self):
        """Build the two-package fixture used by several tests."""
        return [
            SourceText('alpha', ALPHA, origin='alpha.yar', externals={'ext_score': 'integer'}),
            SourceText('beta', BETA, origin='beta.yar'),
        ]

    def test_same_name_helpers_never_cross_namespaces(self):
        report = preflight(self.sources())
        resolved = {
            (reference.namespace, reference.rule, reference.term): reference
            for reference in report.references
            if reference.target_kind == 'rule'
        }

        alpha_local = resolved[('alpha', 'entry_alpha', 'shared_helper')]
        beta_local = resolved[('beta', 'entry_beta', 'shared_helper')]
        beta_qualified = resolved[('alpha', 'entry_alpha', 'beta.shared_helper')]

        self.assertEqual(alpha_local.target_namespace, 'alpha')
        self.assertIn('$alpha', alpha_local.target_conditions[0])
        self.assertEqual(beta_local.target_namespace, 'beta')
        self.assertIn('$beta', beta_local.target_conditions[0])
        self.assertEqual(beta_qualified.target_namespace, 'beta')
        self.assertEqual(beta_qualified.target_sources[0].origin, 'beta.yar')

        self.assertFalse(report.duplicates)
        self.assertFalse(report.missing)
        self.assertFalse(report.ambiguous)
        self.assertTrue(report.ok)

    def test_same_namespace_can_span_multiple_texts(self):
        report = preflight([
            SourceText('pack', 'rule shared_helper { condition: true }', origin='defs.yar'),
            SourceText('pack', 'rule entry { condition: shared_helper }', origin='entries.yar'),
        ])

        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.target_namespace, 'pack')
        self.assertEqual(reference.target_sources[0].origin, 'defs.yar')
        self.assertEqual(reference.source.origin, 'entries.yar')
        self.assertFalse(report.duplicates)

    def test_input_order_does_not_change_report(self):
        sources = self.sources()
        forward = preflight(sources)
        reverse = preflight(list(reversed(sources)))

        self.assertEqual(forward, reverse)
        self.assertEqual(forward.to_json(), reverse.to_json())

    def test_every_resolved_reference_points_back_to_a_source(self):
        texts = {source.origin: source.text for source in self.sources()}
        report = preflight(self.sources())

        self.assertTrue(report.references)
        for reference in report.references:
            expected = hashlib.sha256(texts[reference.source.origin].encode('utf-8')).hexdigest()
            self.assertEqual(reference.source.source_sha256, expected)
            self.assertEqual(reference.source.namespace, reference.namespace)
            line = texts[reference.source.origin].splitlines()[reference.source.start_line - 1]
            self.assertIn('rule', line)

            if reference.target_kind == 'rule':
                for target in reference.target_sources:
                    expected_target = hashlib.sha256(texts[target.origin].encode('utf-8')).hexdigest()
                    self.assertEqual(target.source_sha256, expected_target)

    def test_duplicate_definition_is_reported_per_namespace(self):
        report = preflight([
            SourceText('pack', 'rule shared_helper { condition: true }', origin='one.yar'),
            SourceText('pack', 'rule shared_helper { condition: false }', origin='two.yar'),
            SourceText('other', 'rule shared_helper { condition: true }', origin='three.yar'),
        ])

        self.assertEqual(len(report.duplicates), 1)
        duplicate = report.duplicates[0]
        self.assertEqual((duplicate.namespace, duplicate.name), ('pack', 'shared_helper'))
        self.assertEqual(len(duplicate.definitions), 2)
        self.assertEqual(
            {definition.location.origin for definition in duplicate.definitions},
            {'one.yar', 'two.yar'},
        )
        self.assertFalse(report.ok)

    def test_missing_reference_keeps_concrete_source(self):
        report = preflight([
            SourceText('alpha', 'rule entry_alpha { condition: unknown_helper }', origin='alpha.yar'),
            SourceText('beta', 'rule unknown_helper { condition: true }', origin='beta.yar'),
        ])

        self.assertEqual(len(report.missing), 1)
        missing = report.missing[0]
        self.assertEqual(missing.expected_namespace, 'alpha')
        self.assertEqual(missing.source.origin, 'alpha.yar')
        self.assertEqual(missing.condition, 'condition: unknown_helper')
        self.assertEqual(missing.term_index, 0)
        self.assertEqual(
            [definition.location.origin for definition in missing.definitions_elsewhere],
            ['beta.yar'],
        )
        self.assertFalse(report.ok)

    def test_qualified_reference_to_unknown_namespace_is_missing(self):
        report = preflight([
            SourceText('alpha', 'rule entry { condition: ghost.helper }', origin='alpha.yar'),
            SourceText('other', 'rule helper { condition: true }', origin='other.yar'),
        ])

        self.assertEqual(len(report.missing), 1)
        self.assertEqual(report.missing[0].expected_namespace, 'ghost')
        self.assertEqual(report.missing[0].term, 'ghost.helper')
        self.assertFalse(report.references)

    def test_ambiguous_reference_is_distinct_from_missing(self):
        report = preflight([
            SourceText('alpha', 'rule helper { condition: true }', origin='one.yar'),
            SourceText('alpha', 'rule helper { condition: false }', origin='two.yar'),
            SourceText('alpha', 'rule entry { condition: helper }', origin='three.yar'),
        ])

        self.assertEqual(len(report.ambiguous), 1)
        self.assertEqual(report.ambiguous[0].expected_namespace, 'alpha')
        self.assertEqual(len(report.ambiguous[0].candidates), 2)
        self.assertFalse(report.missing)
        self.assertFalse(report.ok)

    def test_global_gating_is_implicit_and_namespace_local(self):
        report = preflight([
            SourceText('alpha', 'global rule gate { condition: true }\n'
                                'rule dependent { condition: true }', origin='alpha.yar'),
            SourceText('beta', 'rule dependent { condition: true }', origin='beta.yar'),
        ])

        self.assertEqual(len(report.global_gating), 1)
        gating = report.global_gating[0]
        self.assertEqual((gating.namespace, gating.global_rule), ('alpha', 'gate'))
        self.assertEqual([rule.name for rule in gating.gated_rules], ['dependent'])
        self.assertEqual(gating.gated_rules[0].location.origin, 'alpha.yar')
        self.assertEqual(gating.source.origin, 'alpha.yar')

    def test_external_conflicts_are_reported_separately(self):
        report = preflight([
            SourceText('alpha', 'rule uses_ext { condition: shared > 1 }',
                       origin='alpha.yar', externals={'shared': 'integer'}),
            SourceText('beta', 'rule uses_ext { condition: shared matches /x/ }',
                       origin='beta.yar', externals={'shared': 'string'}),
        ])

        kinds = {conflict.kind for conflict in report.external_conflicts}
        self.assertIn('type_mismatch', kinds)

        conflict = next(item for item in report.external_conflicts if item.kind == 'type_mismatch')
        self.assertEqual(conflict.name, 'shared')
        self.assertEqual(
            {(declaration.value_type, declaration.location.origin)
             for declaration in conflict.declarations},
            {('integer', 'alpha.yar'), ('string', 'beta.yar')},
        )
        self.assertFalse(report.missing)
        self.assertFalse(report.ok)

    def test_external_and_rule_name_collision_is_reported(self):
        report = preflight([
            SourceText('alpha', 'rule shared { condition: true }\n'
                                'rule entry { condition: shared }', externals={'shared': 'boolean'}),
        ])

        shadow = [item for item in report.external_conflicts if item.kind == 'rule_name_shadow']
        self.assertEqual(len(shadow), 1)
        self.assertEqual(shadow[0].namespace, 'alpha')
        self.assertEqual(len(shadow[0].rules), 1)
        self.assertEqual(report.references[0].target_kind, 'rule')

    def test_external_reference_resolves_without_rule_candidate(self):
        report = preflight([
            SourceText('alpha', 'rule entry { condition: ext_value == 1 }',
                       externals={'ext_value': 'integer'}),
        ])

        self.assertEqual(len(report.references), 1)
        reference = report.references[0]
        self.assertEqual(reference.target_kind, 'external')
        self.assertEqual(reference.target_name, 'ext_value')
        self.assertEqual(reference.target_sources[0].origin, reference.source.origin)
        self.assertTrue(report.ok)

    def test_include_is_recorded_but_never_opened(self):
        with tempfile.TemporaryDirectory() as directory:
            included = Path(directory, 'included.yar')
            included.write_text('rule hidden { condition: true }', encoding='utf-8')

            report = preflight([
                SourceText('alpha', 'include "included.yar"\n'
                                    'rule entry { condition: hidden }', origin='alpha.yar'),
            ])

            self.assertEqual([include.target for include in report.includes], ['included.yar'])
            self.assertEqual(report.sources[0].include_count, 1)
            self.assertEqual(len(report.rules), 1)
            self.assertEqual(len(report.missing), 1)
            self.assertEqual(report.missing[0].term, 'hidden')

    def test_module_and_iteration_variables_are_not_dependencies(self):
        report = preflight([
            SourceText(
                'alpha',
                'import "pe"\n'
                'rule entry {\n'
                '    strings:\n'
                '        $a = "omega"\n'
                '    condition:\n'
                '        pe.number_of_sections > 0 and\n'
                '        for any i in (1..#a) : ( @a[i] > 0 and i > 0 )\n'
                '}',
                origin='alpha.yar',
            ),
        ])

        self.assertFalse(report.references)
        self.assertFalse(report.missing)
        self.assertTrue(report.ok)

    def test_parse_failure_is_reported_without_aborting_other_sources(self):
        report = preflight([
            SourceText('broken', 'rule broken { condition: }', origin='broken.yar'),
            SourceText('alpha', 'rule entry { condition: true }', origin='alpha.yar'),
        ])

        self.assertEqual(len(report.parse_failures), 1)
        failure = report.parse_failures[0]
        self.assertEqual(failure.origin, 'broken.yar')
        self.assertEqual(failure.error_type, 'ParseTypeError')
        self.assertEqual(len(report.rules), 1)
        self.assertEqual(report.rules[0].location.origin, 'alpha.yar')
        self.assertFalse(report.ok)

    def test_report_serializes_to_deterministic_json(self):
        forward = preflight(self.sources()).to_dict()
        reverse = preflight(list(reversed(self.sources()))).to_dict()

        self.assertEqual(forward, reverse)
        self.assertEqual(forward['schema_version'], 1)
        self.assertEqual(forward['summary']['includes_not_opened'], 0)

    def test_cli_reads_manifest_from_stdin(self):
        manifest = json.dumps({
            'sources': [
                {'namespace': 'alpha', 'text': ALPHA, 'origin': 'alpha.yar',
                 'externals': {'ext_score': 'integer'}},
                {'namespace': 'beta', 'text': BETA, 'origin': 'beta.yar'},
            ],
        })
        result = subprocess.run(
            [sys.executable, '-m', 'plyara.preflight', '--check'],
            input=manifest,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['summary']['rules'], 5)

    def test_cli_check_fails_on_link_errors(self):
        manifest = json.dumps({
            'sources': [
                {'namespace': 'alpha', 'text': 'rule entry { condition: ghost }'},
            ],
        })
        result = subprocess.run(
            [sys.executable, '-m', 'plyara.preflight', '--check'],
            input=manifest,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['ok'])


if __name__ == '__main__':
    unittest.main()
