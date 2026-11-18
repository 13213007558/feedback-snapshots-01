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
"""Unit tests for effective YARA dependency analysis."""
import importlib.resources
import unittest

from plyara.dependencies import DependencyAnalyzer
from plyara.dependencies import EdgeKind
from plyara.dependencies import RuleRef
from plyara.dependencies import SymbolKind


class TestDependencyAnalysis(unittest.TestCase):
    """Validate graph construction, gating semantics and impact closure."""

    def setUp(self):
        self.data = importlib.resources.files('tests.data.dependencies')
        self.security_path = self.data.joinpath('security_ruleset.yar')
        self.other_path = self.data.joinpath('other_namespace.yar')
        self.analyzer = DependencyAnalyzer(external_variables=('ext_var', 'os_ext'))
        self.graph = self.analyzer.analyze_paths((self.security_path, self.other_path))

    def _ref(self, namespace, name):
        return RuleRef(namespace, name)

    def _edge_pairs(self, kind):
        return {
            (edge.source.name, edge.target.name)
            for edge in self.graph.edges if edge.kind == kind
        }

    def test_explicit_edges_only_come_from_conditions(self):
        explicit = self._edge_pairs(EdgeKind.EXPLICIT)
        self.assertIn(('Priv_PEAttributes', 'Priv_FileHeader'), explicit)
        self.assertIn(('Detection_Dropper', 'Priv_PEAttributes'), explicit)
        self.assertIn(('Cycle_A', 'Cycle_B'), explicit)
        self.assertIn(('Cycle_B', 'Cycle_A'), explicit)
        # A same-named identifier inside a comment or a string literal is not
        # an explicit reference.
        self.assertNotIn(('Detection_Generic', 'G_Platform'), explicit)
        self.assertNotIn(('Priv_FileHeader', 'G_Platform'), explicit)
        self.assertNotIn(('Priv_FileHeader', 'G_SupportedOS'), explicit)

    def test_wildcard_edges_expand_to_matching_rules(self):
        wildcard = self._edge_pairs(EdgeKind.WILDCARD)
        self.assertEqual(
            wildcard,
            {
                ('Detection_Wildcard', 'Detection_Dropper'),
                ('Detection_Wildcard', 'Detection_Generic'),
            },
        )
        wildcard_edges = [
            edge for edge in self.graph.edges if edge.kind == EdgeKind.WILDCARD
        ]
        self.assertTrue(all(edge.snippet == 'Detection_*' for edge in wildcard_edges))
        self.assertTrue(all(edge.line == 48 for edge in wildcard_edges))

    def test_module_members_are_not_rule_references(self):
        explicit = self._edge_pairs(EdgeKind.EXPLICIT)
        self.assertNotIn(('Priv_PEAttributes', 'pe'), explicit)
        unresolved_names = {item.symbol for item in self.graph.unresolved}
        self.assertNotIn('pe', unresolved_names)
        self.assertNotIn('imphash', unresolved_names)
        self.assertNotIn('number_of_sections', unresolved_names)

    def test_external_variables_are_classified_not_resolved_as_rules(self):
        externals = {
            (item.rule.name, item.symbol)
            for item in self.graph.unresolved
            if item.kind == SymbolKind.EXTERNAL
        }
        self.assertIn(('Detection_Dropper', 'ext_var'), externals)
        self.assertIn(('G_SupportedOS', 'os_ext'), externals)
        self.assertIn(('Uses_External_Only', 'os_ext'), externals)
        # No edge may point at an external variable.
        self.assertFalse(
            any(edge.target.name in ('ext_var', 'os_ext') for edge in self.graph.edges)
        )

    def test_undeclared_external_stays_unresolved(self):
        graph = DependencyAnalyzer().analyze_paths((self.security_path,))
        unresolved = {
            (item.rule.name, item.symbol)
            for item in graph.unresolved if item.kind == SymbolKind.UNRESOLVED
        }
        self.assertIn(('Detection_Dropper', 'ext_var'), unresolved)
        self.assertIn(('G_SupportedOS', 'os_ext'), unresolved)

    def test_global_gate_edges_cover_every_non_global_rule_in_namespace(self):
        gates = {
            (edge.source.name, edge.target.name)
            for edge in self.graph.edges
            if edge.kind == EdgeKind.GATE and edge.source.namespace == 'security_ruleset'
        }
        gated_names = {source for source, target in gates if target == 'G_Platform'}
        expected = {
            'Priv_FileHeader',
            'Priv_PEAttributes',
            'Detection_Dropper',
            'Detection_Generic',
            'Detection_Wildcard',
            'Cycle_A',
            'Cycle_B',
            'Uses_External_Only',
        }
        self.assertEqual(gated_names, expected)
        # Globals do not gate each other and rules never gate themselves.
        self.assertFalse(
            any(source == 'G_SupportedOS' for source, _ in gates if _ == 'G_Platform')
        )

    def test_gates_are_namespace_scoped(self):
        isolated_gates = {
            (edge.source.name, edge.target.namespace)
            for edge in self.graph.edges
            if edge.kind == EdgeKind.GATE and edge.source.namespace == 'other_namespace'
        }
        self.assertEqual(
            isolated_gates,
            {('Isolated_Detection', 'other_namespace'),
             ('Isolated_Follower', 'other_namespace')},
        )
        security_gate_sources = {
            edge.source.namespace for edge in self.graph.edges
            if edge.kind == EdgeKind.GATE and edge.target.namespace == 'security_ruleset'
        }
        self.assertEqual(security_gate_sources, {'security_ruleset'})

    def test_cross_namespace_same_name_is_not_a_local_reference(self):
        explicit = {
            (edge.source.namespace, edge.source.name, edge.target.namespace)
            for edge in self.graph.edges if edge.kind == EdgeKind.EXPLICIT
        }
        # Isolated_Detection names G_Platform; it must resolve inside its own
        # namespace rather than silently linking to the security ruleset.
        self.assertIn(('other_namespace', 'Isolated_Detection', 'other_namespace'), explicit)
        self.assertNotIn(
            ('other_namespace', 'Isolated_Detection', 'security_ruleset'), explicit,
        )

    def test_removing_global_gate_impacts_whole_namespace(self):
        gate = self._ref('security_ruleset', 'G_Platform')
        impacted = {ref.name for ref in self.graph.impact(gate)}
        self.assertEqual(impacted, {
            'Priv_FileHeader',
            'Priv_PEAttributes',
            'Detection_Dropper',
            'Detection_Generic',
            'Detection_Wildcard',
            'Cycle_A',
            'Cycle_B',
            'Uses_External_Only',
        })
        # The other namespace is outside the gate's reach.
        self.assertNotIn(self._ref('other_namespace', 'Isolated_Detection'),
                         self.graph.impact(gate))

    def test_non_global_change_uses_reverse_reachability(self):
        helper = self._ref('security_ruleset', 'Priv_FileHeader')
        impacted = {ref.name for ref in self.graph.impact(helper)}
        self.assertEqual(impacted, {
            'Priv_PEAttributes',
            'Detection_Dropper',
            'Detection_Generic',
            'Detection_Wildcard',
        })

    def test_impact_evidence_paths(self):
        gate = self._ref('security_ruleset', 'G_Platform')
        explanations = self.graph.explain_impact(gate)
        dropper = self._ref('security_ruleset', 'Detection_Dropper')
        self.assertTrue(all(edge.kind == EdgeKind.GATE for edge in explanations[dropper]))
        helper = self._ref('security_ruleset', 'Priv_FileHeader')
        helper_paths = self.graph.explain_impact(helper)
        dropper_path = helper_paths[self._ref('security_ruleset', 'Detection_Dropper')]
        self.assertEqual(
            [edge.target.name for edge in dropper_path],
            ['Priv_FileHeader', 'Priv_PEAttributes'],
        )

    def test_cycles_are_reported_once_as_a_path(self):
        cycles = self.graph.cycles()
        self.assertEqual(len(cycles), 1)
        names = [ref.name for ref in cycles[0]]
        self.assertEqual(names[0], names[-1])
        self.assertEqual(set(names[:-1]), {'Cycle_A', 'Cycle_B'})

    def test_every_edge_records_source_location(self):
        for edge in self.graph.edges:
            info = self.graph.rules[edge.source]
            self.assertGreaterEqual(edge.line, info.start_line)
            self.assertLessEqual(edge.line, info.stop_line)
            self.assertTrue(edge.snippet)

    def test_string_names_and_loop_variables_are_not_references(self):
        source = '''
rule Helper { condition: true }
rule LoopUser {
    strings:
        $a = "Helper"
    condition:
        for any section in (0..2) : ( section > 0 ) and #a > 0
}
'''
        graph = DependencyAnalyzer().analyze_strings({'loop.yar': source})
        explicit = {(edge.source.name, edge.target.name)
                    for edge in graph.edges if edge.kind == EdgeKind.EXPLICIT}
        self.assertNotIn(('LoopUser', 'Helper'), explicit)
        loop_vars = {item.symbol for item in graph.unresolved
                     if item.kind == SymbolKind.LOOP_VAR}
        self.assertIn('section', loop_vars)

    def test_duplicate_rule_name_in_namespace_is_rejected(self):
        source = 'rule Dup { condition: true }\nrule Dup { condition: false }\n'
        with self.assertRaises(ValueError):
            DependencyAnalyzer().analyze_strings({'dup.yar': source})


if __name__ == '__main__':
    unittest.main()
