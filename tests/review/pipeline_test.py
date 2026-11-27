import json
import os

import pytest

from detect_secrets.review import ParsePath
from detect_secrets.review import Representation
from detect_secrets.review import review_config
from detect_secrets.review import write_internal_record
from detect_secrets.review.fingerprint import compute_fingerprint
from detect_secrets.review.rules import PLACEHOLDER_SENTINEL

FIXTURE_DIR = os.path.join('test_data', 'review')
STRUCTURED_FIXTURE = os.path.join(FIXTURE_DIR, 'structured_config.yaml')
BROKEN_FIXTURE = os.path.join(FIXTURE_DIR, 'broken_config.yaml')


def _raw_marker_lines(text):
    return [
        line_number
        for line_number, line in enumerate(text.splitlines(), start=1)
        if PLACEHOLDER_SENTINEL in line
    ]


def _findings_by_line(findings):
    return {finding.original_location.line: finding for finding in findings}


@pytest.fixture
def structured_text():
    with open(STRUCTURED_FIXTURE, encoding='utf-8') as handle:
        return handle.read()


@pytest.fixture
def broken_text():
    with open(BROKEN_FIXTURE, encoding='utf-8') as handle:
        return handle.read()


def test_structured_path_normalizes_and_preserves_original_location(structured_text):
    result = review_config(STRUCTURED_FIXTURE, structured_text)

    assert result.parse_path == ParsePath.STRUCTURED
    assert result.diagnostic is None

    # Normalization re-orders rows: the first normalized row is not the first
    # placeholder line in the original input.
    assert result.normalized_lines[0].startswith('a_placeholder =')
    assert result.findings

    marker_lines = _raw_marker_lines(structured_text)
    findings = _findings_by_line(result.findings)

    for original_line in marker_lines:
        finding = findings[original_line]
        # The public, shareable coordinate always points at the original input.
        assert finding.original_location.representation == Representation.ORIGINAL
        assert finding.original_location.line == original_line
        # The normalized coordinate is explicitly labelled as a different space.
        assert finding.normalized_location is not None
        assert finding.normalized_location.representation == Representation.NORMALIZED
        assert finding.normalized_location.line != original_line


def test_structured_placeholder_sits_at_different_position_in_each_representation(
    structured_text,
):
    result = review_config(STRUCTURED_FIXTURE, structured_text)
    first = result.findings[0]

    # The placeholder is on line 3 of the raw input but row 1 after sorting.
    assert first.original_location.line == 3
    assert first.normalized_location.line == 1
    assert first.normalized_index == 1

    # The fingerprint is reproducible from the structured path and the original
    # (not normalized) coordinate, and is salted away from the text identity.
    recomputed = compute_fingerprint(
        rule_id=first.rule_id,
        parse_path=ParsePath.STRUCTURED,
        original_location=first.original_location,
        logical_path=('a_placeholder',),
    )
    assert recomputed == first.fingerprint

    text_identity = compute_fingerprint(
        rule_id=first.rule_id,
        parse_path=ParsePath.TEXT,
        original_location=first.original_location,
        logical_path=('a_placeholder',),
    )
    assert text_identity != first.fingerprint


def test_fallback_path_uses_raw_text_without_normalized_coordinates(broken_text):
    result = review_config(BROKEN_FIXTURE, broken_text)

    assert result.parse_path == ParsePath.TEXT
    assert result.normalized_entries == []
    assert result.normalized_lines == []
    assert result.diagnostic is not None

    marker_lines = _raw_marker_lines(broken_text)
    assert len(result.findings) == len(marker_lines) == 1

    finding = result.findings[0]
    assert finding.original_location.line == marker_lines[0] == 4
    assert finding.original_location.representation == Representation.ORIGINAL
    assert finding.normalized_location is None
    assert finding.normalized_index is None
    assert finding.evidence['source'] == ParsePath.TEXT.value


def test_fallback_diagnostic_keeps_raw_exception_internally(broken_text):
    result = review_config(BROKEN_FIXTURE, broken_text)

    diagnostic = result.diagnostic
    assert diagnostic.error_type == 'ParserError'
    assert diagnostic.problem_line == 4
    assert diagnostic.problem_column is not None
    # The raw exception text (which echoes input) is retained for local triage.
    assert '[' in diagnostic.message

    internal = result.internal_record()
    assert internal['diagnostic'] == diagnostic.to_dict()


def test_public_report_never_carries_restricted_data(structured_text, broken_text):
    for filename, text in (
        (STRUCTURED_FIXTURE, structured_text),
        (BROKEN_FIXTURE, broken_text),
    ):
        result = review_config(filename, text)
        public = json.dumps(result.public_report().to_dict())

        # No config values, no normalized-only coordinates, no exception text.
        assert 'restricted_value' not in public
        assert Representation.NORMALIZED.value not in public
        assert 'diagnostic' not in public
        assert 'unclosed' not in public
        # Every exposed location is explicitly an original coordinate.
        for finding in result.public_report().findings:
            assert finding.location['representation'] == Representation.ORIGINAL.value


def test_public_locations_match_each_parse_path_no_cross_source_attribution(
    structured_text,
    broken_text,
):
    structured = review_config(STRUCTURED_FIXTURE, structured_text)
    fallback = review_config(BROKEN_FIXTURE, broken_text)

    structured_public = {
        finding.location['line']: finding for finding in structured.public_report().findings
    }
    fallback_public = {
        finding.location['line']: finding for finding in fallback.public_report().findings
    }

    # Structured finding reports its raw line (3), never its normalized row (1).
    assert set(structured_public) == set(_raw_marker_lines(structured_text))
    structured_first = structured_public[3]
    assert structured_first.parse_path == ParsePath.STRUCTURED.value
    assert structured_first.location['line'] == 3
    assert structured_first.evidence['source'] == ParsePath.STRUCTURED.value

    # Fallback finding reports its raw line (4) and stays in the text identity.
    assert set(fallback_public) == {4}
    fallback_finding = fallback_public[4]
    assert fallback_finding.parse_path == ParsePath.TEXT.value
    assert fallback_finding.evidence['source'] == ParsePath.TEXT.value

    # Fingerprints are path-salted: the same rule on different paths can never
    # be treated as the same duplicate finding.
    structured_fingerprints = {f.fingerprint for f in structured.findings}
    fallback_fingerprints = {f.fingerprint for f in fallback.findings}
    assert structured_fingerprints.isdisjoint(fallback_fingerprints)


def test_internal_record_holds_full_provenance_locally(structured_text, tmp_path):
    result = review_config(STRUCTURED_FIXTURE, structured_text)
    target = os.path.join(str(tmp_path), 'internal.json')

    write_internal_record(result, target)
    record = json.load(open(target, encoding='utf-8'))

    assert record['parse_path'] == ParsePath.STRUCTURED.value
    assert record['normalized_lines'] == result.normalized_lines
    stored = record['findings'][0]
    assert stored['restricted_value'] is not None
    assert stored['original_location']['representation'] == Representation.ORIGINAL.value
    assert stored['normalized_location']['representation'] == Representation.NORMALIZED.value
    # The two coordinates of the same finding genuinely differ.
    assert (
        stored['original_location']['line']
        != stored['normalized_location']['line']
    )


def test_duplicate_same_name_fields_merge_and_keep_all_original_locations():
    text = (
        'name: first\n'
        'name: second\n'
        'name: REVIEW_PLACEHOLDER\n'
    )
    result = review_config('dupes.yaml', text)

    assert result.parse_path == ParsePath.STRUCTURED
    entry = result.normalized_entries[0]
    assert entry.logical_path == ('name',)
    assert entry.occurrence_count == 3
    assert [location.line for location in entry.original_locations] == [1, 2, 3]

    finding = result.findings[0]
    # Public location is the original occurrence line, not the merged row index.
    assert finding.original_location.line == 3
    assert finding.normalized_location.line == 1
    assert finding.evidence['merged_occurrences'] == '3'
