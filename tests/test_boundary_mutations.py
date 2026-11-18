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
"""Bounded rule-boundary mutation tests for plyara.

Seeds carry hand-written structural expectations (never re-derived by the
parser under test). Mutations only touch whitespace, comment placement,
and escape spelling, so the structural record must stay invariant.
Negative controls change meaning on purpose and must be caught by the
same criterion. Any failure saves the seed, the mutant, and a minimized
failing text under tests/boundary_artifacts/.
"""
import dataclasses
import enum
import json
import os
import pathlib
import re
import unittest

import plyara.core
from plyara.exceptions import ParseError

ARTIFACT_DIR = pathlib.Path(
    os.environ.get('PLYARA_BOUNDARY_ARTIFACTS', pathlib.Path(__file__).parent / 'boundary_artifacts')
)


@dataclasses.dataclass(frozen=True)
class StringRecord:
    """Structural record of one string definition."""

    name: str
    type: str
    modifiers: tuple


@dataclasses.dataclass(frozen=True)
class RuleRecord:
    """Structural record of one rule: name, scope, tags, strings, condition."""

    rule_name: str
    scopes: tuple
    tags: tuple
    strings: tuple
    condition_terms: tuple


@dataclasses.dataclass(frozen=True)
class Seed:
    """A rule text plus its hand-written expected structural record."""

    name: str
    text: str
    expected: tuple


class Verdict(enum.Enum):
    """Outcome of comparing one mutant against its seed expectation."""

    PASS = 'pass'
    BOUNDARY_ESCAPE = 'boundary_escape'
    PARSE_ERROR = 'parse_error'


@dataclasses.dataclass
class Outcome:
    """Classification result for one parsed mutant."""

    verdict: Verdict
    diff: dict = dataclasses.field(default_factory=dict)
    error: str = ''


def extract_records(parsed_rules):
    """Map plyara parser output dicts to structural records."""
    records = []
    for rule in parsed_rules:
        strings = tuple(
            StringRecord(s['name'], s['type'], tuple(s.get('modifiers', ())))
            for s in rule.get('strings', ())
        )
        records.append(RuleRecord(
            rule_name=rule['rule_name'],
            scopes=tuple(rule.get('scopes', ())),
            tags=tuple(rule.get('tags', ())),
            strings=strings,
            condition_terms=tuple(rule.get('condition_terms', ())),
        ))
    return tuple(records)


def diff_records(expected, actual):
    """Compare structural records field by field; return a human-readable diff."""
    diff = {}
    if len(expected) != len(actual):
        diff['rule_count'] = {'expected': len(expected), 'actual': len(actual)}
    for index, (exp, act) in enumerate(zip(expected, actual)):
        for field in dataclasses.fields(RuleRecord):
            exp_value = getattr(exp, field.name)
            act_value = getattr(act, field.name)
            if exp_value != act_value:
                key = f'rule[{index}].{field.name}'
                diff[key] = {'expected': list(exp_value) if isinstance(exp_value, tuple) else exp_value,
                             'actual': list(act_value) if isinstance(act_value, tuple) else act_value}
    return diff


def classify(text, expected):
    """Parse text through the real entry point and classify the outcome.

    A boundary escape (comment or pattern content promoted to a condition,
    modifier, or rule) means the parse succeeded but the structure changed.
    A parse error means the text was rejected. The two are never conflated.
    """
    parser = plyara.core.Plyara()
    try:
        parsed = parser.parse_string(text)
    except ParseError as exc:
        return Outcome(Verdict.PARSE_ERROR, error=f'{type(exc).__name__}: {exc}')
    actual = extract_records(parsed)
    diff = diff_records(expected, actual)
    if diff:
        return Outcome(Verdict.BOUNDARY_ESCAPE, diff=diff)
    return Outcome(Verdict.PASS)


SEED_BASIC = Seed(
    name='basic',
    text=(
        'private rule alpha : t1 t2 {\n'
        '  strings:\n'
        '    $a = "alpha" nocase wide\n'
        '    $b = { 6A 40 [1-2] 68 }\n'
        '    $c = /al+ha/\n'
        '  condition:\n'
        '    any of them\n'
        '}\n'
    ),
    expected=(RuleRecord(
        rule_name='alpha',
        scopes=('private',),
        tags=('t1', 't2'),
        strings=(
            StringRecord('$a', 'text', ('nocase', 'wide')),
            StringRecord('$b', 'byte', ()),
            StringRecord('$c', 'regex', ()),
        ),
        condition_terms=('any', 'of', 'them'),
    ),),
)

SEED_TWO_RULES = Seed(
    name='two_rules',
    text=(
        'global rule beta {\n'
        '  condition:\n'
        '    true\n'
        '}\n'
        '\n'
        'rule gamma {\n'
        '  strings:\n'
        '    $x = "g"\n'
        '  condition:\n'
        '    $x\n'
        '}\n'
    ),
    expected=(
        RuleRecord(
            rule_name='beta',
            scopes=('global',),
            tags=(),
            strings=(),
            condition_terms=('true',),
        ),
        RuleRecord(
            rule_name='gamma',
            scopes=(),
            tags=(),
            strings=(StringRecord('$x', 'text', ()),),
            condition_terms=('$x',),
        ),
    ),
)

SEED_ESCAPES = Seed(
    name='escapes',
    text=(
        'rule delta {\n'
        '  strings:\n'
        '    $q = "qu\\x69ck"\n'
        '    $r = "ra\\"ar"\n'
        '    $s = /re.x/\n'
        '  condition:\n'
        '    all of them\n'
        '}\n'
    ),
    expected=(RuleRecord(
        rule_name='delta',
        scopes=(),
        tags=(),
        strings=(
            StringRecord('$q', 'text', ()),
            StringRecord('$r', 'text', ()),
            StringRecord('$s', 'regex', ()),
        ),
        condition_terms=('all', 'of', 'them'),
    ),),
)

SEEDS = (SEED_BASIC, SEED_TWO_RULES, SEED_ESCAPES)

LINE_COMMENT_PAYLOADS = (
    '// condition:',
    '// rule injected { condition: true }',
    '// strings: $evil = "x"',
)

BLOCK_COMMENT_PAYLOADS = (
    '/* condition: */',
    '/* rule injected { strings: $z = "z" condition: $z } */',
    '/*\ncondition:\n*/',
)


def whitespace_mutations(text):
    """Meaning-preserving whitespace rewrites."""
    mutants = {
        'crlf': text.replace('\n', '\r\n'),
        'blank_line_between_each': '\n\n'.join(text.split('\n')),
        'trailing_spaces': '\n'.join(line + '   ' for line in text.split('\n')),
    }
    tabbed_lines = []
    for line in text.split('\n'):
        stripped = line.lstrip(' ')
        tabbed_lines.append('\t' * ((len(line) - len(stripped)) // 2) + stripped)
    mutants['indent_with_tabs'] = '\n'.join(tabbed_lines)
    return mutants


def comment_mutations(text):
    """Insert comments carrying adversarial payloads at every line boundary."""
    lines = text.split('\n')
    mutants = {}
    payloads = LINE_COMMENT_PAYLOADS + BLOCK_COMMENT_PAYLOADS
    for payload_index, payload in enumerate(payloads):
        for boundary in range(len(lines) + 1):
            mutated = lines[:boundary] + [payload] + lines[boundary:]
            mutants[f'comment_{payload_index}_at_line_{boundary}'] = '\n'.join(mutated)
    for boundary in range(len(lines)):
        mutated = list(lines)
        mutated[boundary] = mutated[boundary] + ' // condition:'
        mutants[f'trailing_comment_at_line_{boundary}'] = '\n'.join(mutated)
    return mutants


TEXT_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
PLAIN_CHAR_RE = re.compile(r'[A-Za-z0-9]')


def escape_mutations(text):
    """Respell text-string literals with equivalent escape forms."""
    mutants = {}
    for match_index, match in enumerate(TEXT_STRING_RE.finditer(text)):
        plain = PLAIN_CHAR_RE.search(match.group(1))
        if plain:
            char = plain.group(0)
            respelled = match.group(0).replace(char, f'\\x{ord(char):02x}', 1)
            mutants[f'hex_escape_literal_{match_index}'] = text[:match.start()] + respelled + text[match.end():]
        if '\\x' in match.group(1):
            unescaped = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                match.group(0),
            )
            mutants[f'unescape_literal_{match_index}'] = text[:match.start()] + unescaped + text[match.end():]
    return mutants


def all_mutations(seed):
    """Enumerate the bounded, deterministic mutation set for a seed."""
    mutants = {}
    mutants.update(whitespace_mutations(seed.text))
    mutants.update(comment_mutations(seed.text))
    mutants.update(escape_mutations(seed.text))
    return mutants


def negative_controls():
    """Meaning-changing edits with the verdict the criterion must produce."""
    return (
        ('scope_keyword_removed', Verdict.BOUNDARY_ESCAPE,
         SEED_BASIC.text.replace('private rule', 'rule'), SEED_BASIC),
        ('condition_term_changed', Verdict.BOUNDARY_ESCAPE,
         SEED_BASIC.text.replace('any of them', 'all of them'), SEED_BASIC),
        ('extra_string_added', Verdict.BOUNDARY_ESCAPE,
         SEED_BASIC.text.replace('  condition:', '    $evil = "x"\n  condition:'), SEED_BASIC),
        ('condition_keyword_deleted', Verdict.PARSE_ERROR,
         SEED_BASIC.text.replace('  condition:\n', ''), SEED_BASIC),
        ('unterminated_block_comment', Verdict.PARSE_ERROR,
         SEED_BASIC.text.replace('  condition:', '  /* condition:'), SEED_BASIC),
        ('comment_promoted_to_rule', Verdict.BOUNDARY_ESCAPE,
         SEED_TWO_RULES.text + 'rule injected {\n  condition:\n    true\n}\n', SEED_TWO_RULES),
        # An unterminated comment at end of input silently swallows the rule:
        # the parse succeeds with one rule missing and raises no error.
        ('unterminated_comment_swallows_rule', Verdict.BOUNDARY_ESCAPE,
         SEED_TWO_RULES.text.replace(
             'rule gamma {\n  strings:\n    $x = "g"\n  condition:\n    $x\n}\n',
             'rule gamma { strings: $x = "g" /* condition: $x }'), SEED_TWO_RULES),
    )


def minimize_failing_text(text, expected, verdict):
    """Greedily delete lines while the same failing verdict reproduces."""
    lines = text.split('\n')
    shrunk = True
    while shrunk:
        shrunk = False
        for index in range(len(lines)):
            candidate = lines[:index] + lines[index + 1:]
            if not any(candidate):
                continue
            outcome = classify('\n'.join(candidate), expected)
            if outcome.verdict == verdict:
                lines = candidate
                shrunk = True
                break
    return '\n'.join(lines)


def save_failure_artifacts(seed_name, mutation_name, seed, mutant_text, outcome):
    """Persist seed, mutant, minimized text, and verdict for a failure."""
    target = ARTIFACT_DIR / f'{seed_name}__{mutation_name}'
    target.mkdir(parents=True, exist_ok=True)
    (target / 'seed.yar').write_text(seed.text)
    (target / 'mutant.yar').write_text(mutant_text)
    (target / 'minimized.yar').write_text(minimize_failing_text(mutant_text, seed.expected, outcome.verdict))
    (target / 'verdict.json').write_text(json.dumps({
        'seed': seed_name,
        'mutation': mutation_name,
        'verdict': outcome.verdict.value,
        'diff': outcome.diff,
        'error': outcome.error,
    }, indent=2))
    return target


class TestBoundaryMutations(unittest.TestCase):
    """Mutation sweep over seeds with hand-written structural expectations."""

    def test_seed_expectations_are_plausible(self):
        """Sanity check: each seed text must match its own hand-written record."""
        for seed in SEEDS:
            with self.subTest(seed=seed.name):
                outcome = classify(seed.text, seed.expected)
                self.assertEqual(outcome.verdict, Verdict.PASS, outcome.error or outcome.diff)

    def test_mutations_preserve_structure(self):
        """Every meaning-preserving mutant must keep the seed's structure."""
        failures = []
        for seed in SEEDS:
            for mutation_name, mutant_text in all_mutations(seed).items():
                with self.subTest(seed=seed.name, mutation=mutation_name):
                    outcome = classify(mutant_text, seed.expected)
                    if outcome.verdict != Verdict.PASS:
                        target = save_failure_artifacts(seed.name, mutation_name, seed, mutant_text, outcome)
                        failures.append(f'{seed.name}/{mutation_name}: {outcome.verdict.value} '
                                        f'(artifacts: {target})')
                        self.fail(failures[-1])
        self.assertEqual(failures, [])

    def test_negative_controls_are_caught(self):
        """Meaning-changing edits must produce their pinned non-PASS verdict."""
        for name, expected_verdict, text, seed in negative_controls():
            with self.subTest(control=name):
                outcome = classify(text, seed.expected)
                self.assertEqual(outcome.verdict, expected_verdict,
                                 f'negative control {name}: {outcome.error or outcome.diff}')

    def test_criterion_distinguishes_escape_from_error(self):
        """A promoted comment section is an escape, not a syntax error.

        Fabricate the parser output that would result if a comment payload
        like '/* condition: true */' were promoted to a real section, and
        verify the criterion reports BOUNDARY_ESCAPE, distinct from the
        PARSE_ERROR reported for ordinary malformed input.
        """
        promoted_condition = [{
            'rule_name': 'alpha',
            'scopes': ['private'],
            'tags': ['t1', 't2'],
            'strings': [
                {'name': '$a', 'value': 'alpha', 'type': 'text', 'modifiers': ['nocase', 'wide']},
                {'name': '$b', 'value': '{ 6A 40 [1-2] 68 }', 'type': 'byte'},
                {'name': '$c', 'value': '/al+ha/', 'type': 'regex'},
            ],
            'condition_terms': ['true'],
        }]
        escape_outcome = Outcome(Verdict.PASS)
        diff = diff_records(SEED_BASIC.expected, extract_records(promoted_condition))
        if diff:
            escape_outcome = Outcome(Verdict.BOUNDARY_ESCAPE, diff=diff)
        self.assertEqual(escape_outcome.verdict, Verdict.BOUNDARY_ESCAPE)
        self.assertTrue(any('condition_terms' in key for key in escape_outcome.diff))

        promoted_rule = list(plyara.core.Plyara().parse_string(SEED_TWO_RULES.text))
        promoted_rule.append({'rule_name': 'injected', 'condition_terms': ['true']})
        rule_diff = diff_records(SEED_TWO_RULES.expected, extract_records(promoted_rule))
        self.assertIn('rule_count', rule_diff)

        error_outcome = classify('rule broken { condition: }', SEED_BASIC.expected)
        self.assertEqual(error_outcome.verdict, Verdict.PARSE_ERROR)
        self.assertNotEqual(escape_outcome.verdict, error_outcome.verdict)


if __name__ == '__main__':
    unittest.main()
