#!/usr/bin/env python3
"""Syntax capability probe for the plyara-based ingestion chain.

The chain under test is: Plyara.parse_string -> rebuild_yara_rule ->
detect_dependencies / generate_hash.  Every case below is a short YARA rule
with an intended meaning.  The probe asserts the *observed* behavior of this
toolchain, not whether the rule is valid YARA: no YARA engine is bundled here,
so engine-level semantics stay marked ENGINE-CHECK.

Classification:
  GREEN  parse + round-trip rebuild + re-parse preserve the rule, and the
         downstream util used for this construct is reliable.
  AMBER  parsing succeeds (often stored verbatim), but rebuild or dependency
         / hash analysis is lossy, heuristic, or blind.  "No error" is not
         treated as support.
  RED    this toolchain refuses or silently corrupts the construct.  Such
         rules must be excluded from automated migration.

Exit code is non-zero if any RED case is observed, so this can gate a
pre-upgrade run directly.
"""
import logging
import sys
import warnings
from dataclasses import dataclass, field

import plyara
from plyara.exceptions import ParseError
from plyara.utils import detect_dependencies, generate_hash, rebuild_yara_rule

warnings.simplefilter('ignore')
logging.getLogger('plyara.utils').setLevel(logging.CRITICAL)

GREEN = 'GREEN'
AMBER = 'AMBER'
RED = 'RED'
ENGINE = 'ENGINE-CHECK required'


@dataclass
class CaseResult:
    case_id: str
    area: str
    verdict: str
    observed: str
    engine_note: str
    migration: str


@dataclass
class Case:
    case_id: str
    area: str
    rule: str
    expected_verdict: str
    engine_note: str
    migration: str
    check: str = 'roundtrip'
    expect_parse: bool = True
    extra: dict = field(default_factory=dict)


def _parse(rule):
    return plyara.Plyara().parse_string(rule)


def _roundtrip(rule):
    parsed = _parse(rule)
    rebuilt = rebuild_yara_rule(parsed[0])
    reparsed = _parse(rebuilt)
    return parsed[0], rebuilt, reparsed[0]


def run_case(case):
    observed_parts = []
    verdict = case.expected_verdict
    try:
        parsed, rebuilt, reparsed = _roundtrip(case.rule)
        observed_parts.append('parse=OK rebuild+reparse=OK')
    except ParseError as exc:
        if not case.expect_parse:
            observed_parts.append(f'parse=REFUSED({exc.__class__.__name__}: {exc})')
            return CaseResult(case.case_id, case.area, verdict, '; '.join(observed_parts),
                              case.engine_note, case.migration)
        observed_parts.append(f'parse=UNEXPECTED REFUSAL({exc})')
        return CaseResult(case.case_id, case.area, RED, '; '.join(observed_parts),
                          case.engine_note, case.migration)
    except Exception as exc:  # util-layer crash (e.g. meta float ValueError)
        observed_parts.append(f'util=CRASH({exc.__class__.__name__}: {exc})')
        return CaseResult(case.case_id, case.area, RED, '; '.join(observed_parts),
                          case.engine_note, case.migration)

    if case.check == 'hex-negation-collision':
        plain = generate_hash(_parse(case.extra['plain_rule'])[0])
        negated = generate_hash(parsed)
        collide = plain == negated
        observed_parts.append(f'generate_hash collision with plain={collide}')
        if collide:
            verdict = RED
    elif case.check == 'hex-alt-collision':
        alt = generate_hash(_parse(case.extra['alt_rule'])[0])
        plain = generate_hash(_parse(case.extra['plain_rule'])[0])
        collide = alt == plain
        observed_parts.append(f'generate_hash alternation/plain collision={collide}')
        if collide:
            verdict = AMBER
    elif case.check == 'dep-blind':
        deps = detect_dependencies(parsed)
        observed_parts.append(f'detect_dependencies={deps} expected={case.extra["want_deps"]}')
        if deps != case.extra['want_deps']:
            verdict = AMBER
    elif case.check == 'dep-fp':
        deps = detect_dependencies(parsed)
        observed_parts.append(f'detect_dependencies={deps} expected=[]')
        if deps:
            verdict = AMBER
    elif case.check == 'hexnum-split':
        terms = parsed['condition_terms']
        split = '0x1234567890ABCDE' in terms and 'F' in terms
        observed_parts.append(f'64-bit hex token split into two terms={split}')
        if split:
            verdict = RED
    elif case.check == 'rebuild-drops':
        rebuilt = rebuild_yara_rule(parsed)
        lost = [token for token in case.extra['lost_tokens'] if token not in rebuilt]
        observed_parts.append(f'rebuild missing tokens={lost}')
        if lost:
            verdict = AMBER
    elif case.check == 'comment-relocation':
        comments = parsed.get('comments', [])
        inside_value = any(c in parsed['strings'][0]['value'] for c in case.extra['comments'])
        relocated = all(c in comments for c in case.extra['comments'])
        rebuilt = rebuild_yara_rule(parsed)
        rule_level_after = any(c in rebuilt for c in comments)
        observed_parts.append(
            f'comment duplicated to rule-level comments={relocated}, also inside string value={inside_value}, '
            f'rule-level comment survives rebuild={rule_level_after}')
        if relocated and inside_value and not rule_level_after:
            verdict = AMBER
    elif case.check == 'hash-unhandled':
        stream_records = []

        class _Capture(logging.Handler):
            def emit(self, record):
                stream_records.append(record.getMessage())

        handler = _Capture()
        logger = logging.getLogger('plyara.utils')
        logger.addHandler(handler)
        logger.setLevel(logging.ERROR)
        generate_hash(parsed)
        logger.removeHandler(handler)
        observed_parts.append(f'generate_hash unhandled logs={stream_records}')
        if stream_records:
            verdict = AMBER

    return CaseResult(case.case_id, case.area, verdict, '; '.join(observed_parts),
                      case.engine_note, case.migration)


CASES = [
    # ---------------- text strings ----------------
    Case('T1', 'text',
         'rule t1 { strings: $a = "plain text" condition: $a }',
         GREEN, ENGINE, 'none; safe baseline', 'roundtrip'),
    Case('T2', 'text',
         r'rule t2 { strings: $a = "tab\there\nline" condition: $a }',
         GREEN, ENGINE, 'none; escape kept verbatim and round-trips', 'roundtrip'),
    Case('T3', 'text',
         r'rule t3 { strings: $a = "say \"hi\"" condition: $a }',
         GREEN, ENGINE, 'none; escaped quote survives rebuild (issue #163 fixed)', 'roundtrip'),
    Case('T4', 'text',
         r'rule t4 { strings: $a = "A\x41" condition: $a }',
         GREEN, ENGINE, 'engine only interprets \\x41; plyara stores text literally', 'roundtrip'),
    Case('T5', 'text',
         r'rule t5 { strings: $a = "bad \a escape" condition: $a }',
         RED, 'invalid YARA too; rule must be fixed before ingestion',
         'reject at preflight; do not rewrite the detection condition', 'roundtrip',
         expect_parse=False),
    Case('T6', 'text',
         r'rule t6 { strings: $a = "snowman \u{2603}" condition: $a }',
         RED, 'YARA 5.0 accepts \\u{...}; engine version decides validity',
         'block migration until plyara adds the escape; keep original rule, engine-test on YARA 5',
         'roundtrip', expect_parse=False),
    Case('T7', 'text',
         'rule t7 { strings: $a = "café" condition: $a }',
         AMBER, 'engine UTF-8 semantics (README known issue #155 for meta/comments)',
         'usable for strings; do not rely on plyara for non-ASCII meta/comments', 'roundtrip'),

    # ---------------- regex strings ----------------
    Case('R1', 'regex',
         r'rule r1 { strings: $a = /foo.*bar/i condition: $a }',
         AMBER, 'regex semantics are never interpreted; engine owns matching',
         'safe to store/rebuild; mark semantic analysis out of scope', 'roundtrip'),
    Case('R2', 'regex',
         r'rule r2 { strings: $a = /dot.does.not.cross/s condition: $a }',
         AMBER, ENGINE, 'same as R1; s flag stored verbatim', 'roundtrip'),
    Case('R3', 'regex',
         r'rule r3 { strings: $a = /both flags/is condition: $a }',
         AMBER, ENGINE, 'canonicalize suffix to /is in source rules', 'roundtrip'),
    Case('R4', 'regex',
         r'rule r4 { strings: $a = /both flags/si condition: $a }',
         RED, 'valid YARA (flag order is irrelevant to engine); only plyara rejects it',
         'preflight rewrite of flag order only (/si -> /is); detection pattern untouched',
         'roundtrip', expect_parse=False),
    Case('R5', 'regex',
         r'rule r5 { strings: $a = /inline (?i) flag/ condition: $a }',
         AMBER, 'engine version must confirm inline scoped flag support',
         'stored verbatim; no tooling may evaluate the (?i) scope itself', 'roundtrip'),
    Case('R6', 'regex',
         'rule r6 { strings: $a = /utf8 é/ condition: $a }',
         RED, 'engine regex byte semantics version-dependent',
         'block; engine-test non-ASCII regex manually', 'roundtrip', expect_parse=False),
    Case('R7', 'regex',
         r'rule r7 { condition: ext matches /a\.b/i }',
         AMBER, ENGINE, 'condition-level regex stored as one term; rebuild only', 'roundtrip'),

    # ---------------- hex strings ----------------
    Case('H1', 'hex',
         'rule h1 { strings: $a = { 6A 40 68 ?? 30 } condition: $a }',
         AMBER, ENGINE, 'structure not modeled; byte meaning left to engine', 'roundtrip'),
    Case('H2', 'hex',
         'rule h2 { strings: $a = { AA ( BB | CC ) DD } condition: $a }',
         AMBER, ENGINE, 'alternation preserved verbatim in storage/rebuild only',
         'roundtrip'),
    Case('H3', 'hex',
         'rule h3 { strings: $a = { AA [2-4] BB } condition: $a }',
         AMBER, ENGINE, 'jump bounds lexically checked only; engine confirms', 'roundtrip'),
    Case('H4', 'hex',
         'rule h4 { strings: $a = { AA [] BB } condition: $a }',
         AMBER, 'empty [] jump is rejected by YARA; plyara accepts it',
         'flag all empty-jump rules for engine confirmation; do not auto-delete', 'roundtrip'),
    Case('H5', 'hex',
         'rule h5 { strings: $a = { ~AA BB } condition: $a }',
         RED, 'YARA 5.0 negation semantics; older engines reject the rule',
         'exclude from hash-based dedup; engine-test; never strip ~ to force support',
         'hex-negation-collision',
         extra={'plain_rule': 'rule h5p { strings: $h = { AA BB } condition: $h }'}),
    Case('H6', 'hex',
         'rule h6 { strings: $a = { ~( AA | BB ) } condition: $a }',
         RED, 'rejection is toolchain-only here; engine behavior version-dependent',
         'block migration; keep source rule for engine validation', 'roundtrip',
         expect_parse=False),
    Case('H7', 'hex',
         'rule h7 { strings: $a = { AA ?? BB } condition: $a }',
         AMBER, '?? shorthand introduced in YARA 4.3; engine version gate needed',
         'store verbatim; confirm engine >= 4.3 in preflight inventory', 'roundtrip'),
    Case('H8', 'hex',
         'rule h8 { strings: $a = { AA /* keep */ BB } condition: $a }',
         AMBER, ENGINE, 'comment is duplicated into rule-level comments and dropped from there on rebuild',
         'comment-relocation', extra={'comments': ['/* keep */']}),
    Case('H9', 'hex',
         'rule h9 { strings: $a = { ( AA | BB ) } condition: $a }',
         AMBER, ENGINE, 'dedup must use raw_strings, not generate_hash, for alternations',
         'hex-alt-collision',
         extra={'alt_rule': 'rule h9a { strings: $h = { ( AA | BB ) } condition: $h }',
                'plain_rule': 'rule h9p { strings: $h = { AA BB } condition: $h }'}),

    # ---------------- modifiers ----------------
    Case('M1', 'modifier',
         'rule m1 { strings: $a = "x" nocase wide ascii fullword condition: $a }',
         GREEN, ENGINE, 'none; modifiers round-trip and enter hash via <MODIFIED>', 'roundtrip'),
    Case('M2', 'modifier',
         'rule m2 { strings: $a = "x" xor(0x01-0xff) condition: $a }',
         GREEN, ENGINE, 'xor range kept as text; engine owns key-space semantics', 'roundtrip'),
    Case('M3', 'modifier',
         'rule m3 { strings: $a = "x" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") condition: $a }',
         GREEN, 'custom alphabet validity beyond length 64 is engine-checked',
         'none for single alphabet', 'roundtrip'),
    Case('M4', 'modifier',
         'rule m4 { strings: $a = "x" '
         'base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") '
         'base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") '
         'condition: $a }',
         RED, 'multiple base64 alphabets are a YARA 4.3 feature the grammar cannot represent',
         'hold rule until plyara grammar update; do not drop the second alphabet',
         'roundtrip', expect_parse=False),
    Case('M5', 'modifier',
         'rule m5 { strings: $a = "x" private condition: $a }',
         GREEN, ENGINE, 'none', 'roundtrip'),
    Case('M6', 'modifier',
         'rule m6 { strings: $a = "x" nocase xor condition: $a }',
         RED, 'engine also rejects incompatible pairs; preflight mirrors that',
         'reject; source rule author must resolve, do not guess which modifier to drop',
         'roundtrip', expect_parse=False),

    # ---------------- conditions ----------------
    Case('C1', 'condition',
         'rule c1 { condition: filesize < 100KB and not ($a or $b) }',
         AMBER, ENGINE, 'token stream + spacing heuristics only; no condition AST exists',
         'roundtrip'),
    Case('C2', 'condition',
         'rule c2 { strings: $a1="x" $a2="y" condition: for any i in (1..#a1) : ( @a1[i] > 0 ) }',
         AMBER, ENGINE, 'iterator variables are invisible to dependency modeling; round-trip only',
         'roundtrip'),
    Case('C3', 'condition',
         'rule c3 { condition: defined(other_rule) }',
         AMBER, ENGINE, 'dependency graph misses defined-wrapped rule references',
         'dep-blind', extra={'want_deps': ['other_rule']}),
    Case('C4', 'condition',
         'rule c4 { condition: for any s in pe.sections : ( other_rule ) }',
         AMBER, ENGINE, 'rule refs inside for-bodies are invisible to detect_dependencies',
         'dep-blind', extra={'want_deps': ['other_rule']}),
    Case('C5', 'condition',
         'rule c5 { condition: left icontains "q" and right }',
         AMBER, ENGINE, 'new i* string keywords are absent from the dependency skip-list',
         'dep-fp'),
    Case('C6', 'condition',
         'rule c6 { condition: uint32(0) == 0x1234567890ABCDEF }',
         RED, 'rule itself may be valid 64-bit YARA; plyara corrupts it silently',
         'block; wait for lexer fix; never truncate the constant to make it parse',
         'hexnum-split'),
    Case('C7', 'condition',
         'rule c7 { condition: entrypoint > 0 }',
         AMBER, 'entrypoint removed in YARA 5.0 (pe.entry_point replaces it)',
         'inventory as engine-version-gated; migration decision belongs to rule owner',
         'roundtrip'),
    Case('C8', 'condition',
         'include "lib/proto.yar"\nrule c8 { condition: proto_const == 1 }',
         AMBER, 'cross-file resolution never happens in this chain',
         'rebuild-drops', extra={'lost_tokens': ['include']}),
    Case('C9', 'condition',
         'rule c9 { meta: v = 1.5 condition: false }',
         RED, 'floating meta is invalid YARA anyway',
         'reject at preflight; ask rule author for int/string meta', 'roundtrip',
         expect_parse=False),
    Case('C10', 'condition',
         'rule c10 { strings: $a="x" condition: #a == 2 and @a[2] > 100 }',
         AMBER, ENGINE, 'count/position terms hash only when the string is statically resolvable',
         'roundtrip'),
    Case('C11', 'condition',
         'rule c11 { condition: @ghost > 0 }',
         AMBER, ENGINE, 'generate_hash logs "Unhandled" yet still returns a digest; treat hash as void',
         'hash-unhandled'),
]


def main():
    results = [run_case(case) for case in CASES]
    widths = dict(case=6, area=10, verdict=7)
    print('plyara ingestion-chain syntax capability probe')
    print('=' * 100)
    for result in results:
        print(f"{result.case_id:<{widths['case']}} {result.area:<{widths['area']}} "
              f"{result.verdict:<{widths['verdict']}} {result.observed}")
    print('=' * 100)
    counts = {GREEN: 0, AMBER: 0, RED: 0}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1
    print(f"summary: GREEN={counts[GREEN]} AMBER={counts[AMBER]} RED={counts[RED]} "
          f"(total={len(results)})")
    print('AMBER/RED cases and migration handling:')
    for result in results:
        if result.verdict in (AMBER, RED):
            print(f"  [{result.verdict}] {result.case_id} ({result.area}): {result.migration}")
            print(f"         engine: {result.engine_note}")
    red = counts[RED]
    print('RESULT:', 'FAIL - RED constructs present, gate the upgrade' if red else
          'PASS - no hard failures (AMBER items still require the listed handling)')
    return 1 if red else 0


if __name__ == '__main__':
    sys.exit(main())
