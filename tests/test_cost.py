# Copyright 2026 plyara Maintainers
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
"""Unit tests for the condition cost analysis module."""
import copy
import json
import unittest

import plyara.core
from plyara.cost import CostClass
from plyara.cost import CostConfig
from plyara.cost import Poly
from plyara.cost import SampleEnv
from plyara.cost import analyze_condition
from plyara.cost import analyze_rule
from plyara.cost import analyze_source
from plyara.cost import verify_with_samples


def generous_config(**kwargs):
    """Build a config that only constrains what the test cares about."""
    kwargs.setdefault('max_degree', 10)
    kwargs.setdefault('max_work', 10 ** 18)
    return CostConfig(**kwargs)


class TestCostAnalysis(unittest.TestCase):
    """Check the static cost bound derivation."""

    def test_single_level_filesize_loop_is_linear(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..filesize) : ( $a at i ) }'

        report = analyze_source(source, generous_config(max_degree=1))[0]

        self.assertTrue(report.supported)
        self.assertEqual(report.cost_class, CostClass.LINEAR)
        self.assertEqual(report.bound, Poly.filesize())
        self.assertTrue(report.safe_to_publish)
        loop_items = [item for item in report.items if item.construct.startswith('for')]
        self.assertEqual(len(loop_items), 1)
        self.assertIn('filesize', loop_items[0].source)

    def test_two_level_correlated_loop_is_polynomial(self):
        source = (
            'rule r { strings: $a = "AA" condition: '
            'for any i in (1..filesize) : ( for any j in (i..filesize) : ( $a at j ) ) }'
        )

        report = analyze_source(source, generous_config())[0]

        self.assertTrue(report.supported)
        self.assertEqual(report.cost_class, CostClass.POLYNOMIAL)
        self.assertEqual(report.bound, Poly.filesize().mul(Poly.filesize()))
        loop_items = [item for item in report.items if item.construct.startswith('for')]
        self.assertEqual(len(loop_items), 2)
        self.assertIn('i', loop_items[0].construct)

    def test_polynomial_loop_rejected_by_degree_budget(self):
        source = (
            'rule r { strings: $a = "AA" condition: '
            'for any i in (1..filesize) : ( for any j in (i..filesize) : ( $a at j ) ) }'
        )

        report = analyze_source(source, generous_config(max_degree=1))[0]

        self.assertFalse(report.safe_to_publish)
        self.assertTrue(any('degree' in reason for reason in report.reasons))

    def test_finite_constant_loop_is_constant(self):
        source = 'rule r { strings: $a = "AA" condition: for all i in (1..16) : ( $a at i ) }'

        report = analyze_source(source, generous_config())[0]

        self.assertEqual(report.cost_class, CostClass.CONSTANT)
        self.assertEqual(report.bound, Poly.constant(16))
        self.assertTrue(report.safe_to_publish)

    def test_occurrence_count_comparison(self):
        source = 'rule r { strings: $a = "AA" condition: #a > 2 }'

        report = analyze_source(source, generous_config())[0]

        self.assertEqual(report.cost_class, CostClass.CONSTANT)
        self.assertTrue(report.safe_to_publish)

    def test_loop_over_occurrence_count_is_linear(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..#a) : ( $a at i ) }'

        report = analyze_source(source, generous_config(max_degree=1))[0]

        self.assertEqual(report.cost_class, CostClass.LINEAR)
        self.assertTrue(report.safe_to_publish)

    def test_external_variable_bounds_come_from_config(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (ext_lo..ext_hi) : ( $a at i ) }'
        config = generous_config(external_bounds={'ext_lo': (1, 4), 'ext_hi': (8, 16)})

        report = analyze_source(source, config)[0]

        self.assertEqual(report.cost_class, CostClass.CONSTANT)
        self.assertEqual(report.bound, Poly.constant(16))
        self.assertTrue(report.safe_to_publish)

    def test_unbounded_external_variable_is_not_publishable(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..ext_hi) : ( $a at i ) }'

        report = analyze_source(source, generous_config())[0]

        self.assertFalse(report.supported)
        self.assertEqual(report.cost_class, CostClass.UNKNOWN)
        self.assertFalse(report.safe_to_publish)
        self.assertTrue(any('ext_hi' in reason for reason in report.reasons))

    def test_shortcircuit_counts_both_branches(self):
        source = 'rule r { strings: $a = "AA" condition: false and $a }'

        report = analyze_source(source, generous_config())[0]

        self.assertEqual(report.bound, Poly.constant(1))
        and_items = [item for item in report.items if item.construct == 'boolean and']
        self.assertEqual(len(and_items), 1)
        self.assertIn('short-circuit', and_items[0].source)
        self.assertIn('not treated as free', and_items[0].source)

    def test_budget_overflow_is_not_publishable(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..filesize) : ( $a at i ) }'
        config = generous_config(max_degree=1, max_work=10, reference_filesize=1000)

        report = analyze_source(source, config)[0]

        self.assertFalse(report.safe_to_publish)
        self.assertTrue(any('budget' in reason for reason in report.reasons))

    def test_unsupported_constructs_are_not_publishable(self):
        unsupported = [
            'rule r { strings: $a = "AA" condition: any of them }',
            'rule r { condition: uint16(0) == 0x5A4D }',
            'rule r { condition: pe.number_of_sections > 3 }',
            'rule r { strings: $a = "AA" condition: !a > 1 }',
            'rule r { strings: $a = "AA" condition: for any of ($a) : ( true ) }',
        ]
        for source in unsupported:
            report = analyze_source(source, generous_config())[0]
            self.assertFalse(report.supported, source)
            self.assertEqual(report.cost_class, CostClass.UNKNOWN)
            self.assertFalse(report.safe_to_publish, source)

    def test_rule_dictionary_is_not_modified(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..filesize) : ( $a at i ) }'
        entry = plyara.core.Plyara().parse_string(source)[0]
        snapshot = copy.deepcopy(entry)

        analyze_rule(entry, generous_config())

        self.assertEqual(entry, snapshot)

    def test_report_is_json_serializable(self):
        source = 'rule r { strings: $a = "AA" condition: $a and filesize > 10 }'

        report = analyze_source(source, generous_config())[0]

        serialized = json.dumps(report.to_dict())
        self.assertIn('"cost_class": "constant"', serialized)


class TestInterpreterCrossCheck(unittest.TestCase):
    """Check derived bounds against the independent counting interpreter."""

    def test_single_level_loop_within_bound(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (1..filesize) : ( $a at i ) }'
        terms = plyara.core.Plyara().parse_string(source)[0]['condition_terms']
        samples = [
            SampleEnv(filesize=5, matches={'$a': [0, 2, 4]}),
            SampleEnv(filesize=8, matches={}),
            SampleEnv(filesize=3, matches={'$a': [2]}),
        ]

        checks = verify_with_samples(terms, samples, generous_config())

        self.assertEqual(len(checks), 3)
        for check in checks:
            self.assertTrue(check.within_bound, check)

    def test_two_level_correlated_loop_within_bound(self):
        source = (
            'rule r { strings: $a = "AA" condition: '
            'for all i in (1..filesize) : ( for any j in (i..filesize) : ( $a at j ) ) }'
        )
        terms = plyara.core.Plyara().parse_string(source)[0]['condition_terms']
        samples = [
            SampleEnv(filesize=4, matches={'$a': [0, 1, 2, 3]}),
            SampleEnv(filesize=6, matches={'$a': [5]}),
        ]

        checks = verify_with_samples(terms, samples, generous_config())

        for check in checks:
            self.assertTrue(check.within_bound, check)
        self.assertEqual(checks[0].bound, 16)

    def test_finite_constant_loop_within_bound(self):
        source = 'rule r { strings: $a = "AA" condition: for all i in (1..4) : ( $a at i ) }'
        terms = plyara.core.Plyara().parse_string(source)[0]['condition_terms']
        samples = [SampleEnv(filesize=100, matches={'$a': [0, 1, 2, 3]})]

        checks = verify_with_samples(terms, samples, generous_config())

        self.assertEqual(checks[0].bound, 4)
        self.assertTrue(checks[0].within_bound)

    def test_shortcircuit_measured_work_not_above_bound(self):
        source = 'rule r { strings: $a = "AA" condition: false and for any i in (1..filesize) : ( $a at i ) }'
        terms = plyara.core.Plyara().parse_string(source)[0]['condition_terms']
        samples = [SampleEnv(filesize=10, matches={'$a': [0]})]

        checks = verify_with_samples(terms, samples, generous_config())

        self.assertEqual(checks[0].measured, 0)
        self.assertTrue(checks[0].within_bound)

    def test_external_variable_loop_within_bound(self):
        source = 'rule r { strings: $a = "AA" condition: for any i in (ext_lo..ext_hi) : ( $a at i ) }'
        terms = plyara.core.Plyara().parse_string(source)[0]['condition_terms']
        config = generous_config(external_bounds={'ext_lo': (1, 4), 'ext_hi': (8, 16)})
        samples = [
            SampleEnv(filesize=20, matches={'$a': [1, 2]}, externals={'ext_lo': 2, 'ext_hi': 5}),
            SampleEnv(filesize=20, matches={}, externals={'ext_lo': 4, 'ext_hi': 16}),
        ]

        checks = verify_with_samples(terms, samples, config)

        for check in checks:
            self.assertTrue(check.within_bound, check)


if __name__ == '__main__':
    unittest.main()
