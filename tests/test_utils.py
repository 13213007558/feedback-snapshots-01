# Copyright 2014 Christian Buia
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
"""Unit tests for plyara utility functions."""
import importlib.resources
import unittest

import plyara.core
from plyara.utils import generate_hash
from plyara.utils import rebuild_yara_rule
from plyara.utils import resolve_condition_references


class TestUtilities(unittest.TestCase):
    """Check the various utility functions."""

    def setUp(self):
        """Prepare for utility unit testing."""
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.utils')
        self.imports = importlib.resources.files('tests.data.imports')
        self.common = importlib.resources.files('tests.data.common')
        # self.maxDiff = None

    def test_generate_hash(self):
        input_string = self.data.joinpath('logic_collision_ruleset.yar').read_text()

        result = plyara.core.Plyara().parse_string(input_string)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = generate_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():
            self.assertTrue(len(set(hashvalues)) == 1, 'Collision detection failure for {}'.format(setname))

    def test_generate_hash_output_legacy(self):
        rule_hashes = self.data.joinpath('rulehashes_legacy.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result, legacy=True)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_output(self):
        rule_hashes = self.data.joinpath('rulehashes.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_rebuild_yara_rule(self):
        input_string = self.data.joinpath('rebuild_ruleset.yar').read_text(encoding='utf-8')
        test_result = self.data.joinpath('rebuild_ruleset_good_enough.yar').read_text(encoding='utf-8')

        result = plyara.core.Plyara().parse_string(input_string)

        rebuilt_rules = str()
        for rule in result:
            rebuilt_rules += rebuild_yara_rule(rule)

        self.assertEqual(test_result, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        parsed = plyara.core.Plyara().parse_string(test_rule)
        for rule in parsed:
            unparsed = rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)


class TestResolveConditionReferences(unittest.TestCase):
    """Check the limited condition reference resolver."""

    SHARED_STRINGS = '''
        $a = "foo"
        $b1 = "bar"
        $b2 = "baz"
        $ = "anon"
    '''

    def _resolve(self, condition, strings=None):
        strings = self.SHARED_STRINGS if strings is None else strings
        section = '\nstrings:{}\n'.format(strings) if strings.strip() else ''
        test_rule = 'rule test_rule {{{}\ncondition:\n{}\n}}'.format(section, condition)
        parsed = plyara.core.Plyara().parse_string(test_rule)
        self.assertEqual(len(parsed), 1)
        return resolve_condition_references(parsed[0])

    def test_of_wildcard_set(self):
        result = self._resolve('any of ($b*)')

        self.assertEqual(len(result['sets']), 1)
        entry = result['sets'][0]
        self.assertEqual(entry['quantifier'], 'any')
        self.assertEqual(entry['expression'], ['$b*'])
        self.assertEqual(entry['members'], ['$b1', '$b2'])
        self.assertEqual(entry['status'], 'resolved')
        self.assertEqual(entry['scope'], 'condition')
        self.assertEqual(result['issues'], list())

    def test_of_them_set(self):
        result = self._resolve('2 of them')

        self.assertEqual(len(result['sets']), 1)
        entry = result['sets'][0]
        self.assertEqual(entry['quantifier'], '2')
        self.assertEqual(entry['expression'], ['them'])
        self.assertEqual(entry['members'], ['$a', '$b1', '$b2', '$'])
        self.assertEqual(entry['status'], 'resolved')

    def test_for_of_anonymous_references(self):
        result = self._resolve('for any of ($*) : ( # > 1 and $ )')

        self.assertEqual(len(result['sets']), 1)
        entry = result['sets'][0]
        self.assertEqual(entry['quantifier'], 'any')
        self.assertEqual(entry['expression'], ['$*'])
        self.assertEqual(entry['members'], ['$a', '$b1', '$b2', '$'])
        self.assertEqual(entry['scope'], 'for_of')

        self.assertEqual(len(result['references']), 2)
        count_ref, match_ref = result['references']
        self.assertEqual(count_ref['term'], '#')
        self.assertEqual(count_ref['kind'], 'anonymous_count')
        self.assertEqual(count_ref['scope'], 'for_of_body')
        self.assertEqual(count_ref['members'], ['$a', '$b1', '$b2', '$'])
        self.assertEqual(count_ref['source'], 'for_of_set')
        self.assertEqual(count_ref['status'], 'resolved')
        self.assertEqual(match_ref['term'], '$')
        self.assertEqual(match_ref['kind'], 'anonymous_match')
        self.assertEqual(match_ref['members'], ['$a', '$b1', '$b2', '$'])
        self.assertEqual(match_ref['source'], 'for_of_set')
        self.assertEqual(result['issues'], list())
        self.assertEqual(result['unparsed'], list())

    def test_direct_reference_kinds(self):
        result = self._resolve('$a and #b1 > 0 and @b2 == 1 and !b1 < 10')

        kinds = [ref['kind'] for ref in result['references']]
        self.assertEqual(kinds, ['match', 'count', 'offset', 'length'])
        for ref, name in zip(result['references'], ['$a', '$b1', '$b2', '$b1']):
            self.assertEqual(ref['members'], [name])
            self.assertEqual(ref['source'], 'strings')
            self.assertEqual(ref['status'], 'resolved')
            self.assertEqual(ref['scope'], 'condition')
        self.assertEqual(result['issues'], list())

    def test_duplicate_reference_positions_preserved(self):
        result = self._resolve('$a and $a or #b1 and #b1')

        self.assertEqual(len(result['references']), 4)
        indexes = [ref['index'] for ref in result['references']]
        self.assertEqual(len(set(indexes)), 4)
        first, second = [ref for ref in result['references'] if ref['term'] == '$a']
        self.assertNotEqual(first['index'], second['index'])

    def test_undefined_reference_not_filled_from_string_content(self):
        strings = '\n$a = "this text mentions $ghost and #ghost"\n'
        result = self._resolve('$ghost and #ghost', strings=strings)

        self.assertEqual(len(result['references']), 2)
        for ref in result['references']:
            self.assertEqual(ref['status'], 'undefined')
            self.assertEqual(ref['members'], list())
        self.assertEqual(len(result['issues']), 2)
        self.assertTrue(any('$ghost' in issue for issue in result['issues']))
        self.assertTrue(any('#ghost' in issue for issue in result['issues']))

    def test_empty_set_reported(self):
        result = self._resolve('any of ($zz*)')

        self.assertEqual(result['sets'][0]['status'], 'empty_set')
        self.assertEqual(result['sets'][0]['members'], list())
        self.assertTrue(any('matched no strings' in issue for issue in result['issues']))

    def test_undefined_set_member_reported(self):
        result = self._resolve('all of ($a, $ghost)')

        entry = result['sets'][0]
        self.assertEqual(entry['status'], 'resolved')
        self.assertEqual(entry['members'], ['$a'])
        self.assertTrue(any('Undefined string "$ghost"' in issue for issue in result['issues']))

    def test_them_with_no_strings_is_empty_set(self):
        result = self._resolve('any of them', strings='')

        self.assertEqual(result['sets'][0]['status'], 'empty_set')
        self.assertEqual(result['sets'][0]['members'], list())
        self.assertTrue(any('empty set' in issue for issue in result['issues']))

    def test_unparsed_syntax_reported_honestly(self):
        result = self._resolve('any of them in (0..100) and for all i in (1..#a) : ( @a[i] < 5 )')

        self.assertEqual(result['sets'][0]['status'], 'resolved')
        reasons = [entry['reason'] for entry in result['unparsed']]
        self.assertTrue(any('Range qualifier' in reason for reason in reasons))
        self.assertTrue(any('For-in loop' in reason for reason in reasons))

        offset_refs = [ref for ref in result['references'] if ref['term'] == '@a']
        self.assertEqual(len(offset_refs), 1)
        self.assertEqual(offset_refs[0]['members'], ['$a'])
        self.assertEqual(offset_refs[0]['scope'], 'for_in_body')


if __name__ == '__main__':
    unittest.main()
