"""Orchestration for the structured-config review pipeline.

The pipeline first tries a structured (normalized) parse so the config is easy
to audit. If that fails it falls back to reviewing the original text verbatim,
recording the raw parse exception only in the internal diagnostic. Findings on
either path carry coordinates that match the representation they came from.
"""
from typing import List
from typing import Optional

import yaml

from .fingerprint import compute_fingerprint
from .models import Finding
from .models import NormalizedEntry
from .models import ParseDiagnostic
from .models import ParsePath
from .models import Representation
from .models import ReviewResult
from .models import SourceLocation
from .normalize import parse_structured
from .normalize import render_normalized
from .rules import PlaceholderRule


def review_config(filename: str, text: str) -> ReviewResult:
    """Run the full pipeline against one config document."""
    try:
        entries = parse_structured(text)
    except yaml.YAMLError as error:
        return _review_text_fallback(filename, text, error)

    return _review_structured(filename, text, entries)


def _review_structured(
    filename: str,
    text: str,
    entries: List[NormalizedEntry],
) -> ReviewResult:
    rule = PlaceholderRule()
    normalized_lines = render_normalized(entries)
    findings: List[Finding] = []
    seen_fingerprints = set()

    for entry in entries:
        candidate_text = '' if entry.value is None else entry.value
        if rule.evaluate_text(candidate_text) is None:
            continue

        # A merged entry can have several original occurrences. Evaluate each
        # occurrence against its own value so the finding points at the exact
        # original line rather than the merged row.
        for index, original_location in enumerate(entry.original_locations):
            occurrence_value = _value_at(entry, index)
            hit = rule.evaluate_text(occurrence_value)
            if hit is None:
                continue

            # The normalized row is recorded internally, but the public location
            # is always the original occurrence the entry was derived from.
            normalized_location = SourceLocation(
                line=entry.normalized_line,
                representation=Representation.NORMALIZED,
                path=entry.logical_path,
            )
            fingerprint = compute_fingerprint(
                rule_id=hit.rule_id,
                parse_path=ParsePath.STRUCTURED,
                original_location=original_location,
                logical_path=entry.logical_path,
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            findings.append(
                Finding(
                    rule_id=hit.rule_id,
                    parse_path=ParsePath.STRUCTURED,
                    original_location=original_location,
                    normalized_location=normalized_location,
                    evidence={
                        'source': ParsePath.STRUCTURED.value,
                        'detail': hit.evidence,
                        'logical_path': '.'.join(entry.logical_path),
                        'merged_occurrences': str(entry.occurrence_count),
                    },
                    restricted_value=hit.restricted_value,
                    fingerprint=fingerprint,
                    normalized_index=entry.normalized_line,
                ),
            )

    return ReviewResult(
        filename=filename,
        parse_path=ParsePath.STRUCTURED,
        findings=findings,
        normalized_entries=entries,
        normalized_lines=normalized_lines,
        original_text=text,
    )


def _value_at(entry: NormalizedEntry, index: int) -> str:
    """Return the value of one original occurrence within a merged entry."""
    value = entry.occurrence_values[index] if entry.occurrence_values else entry.value
    return '' if value is None else value


def _review_text_fallback(
    filename: str,
    text: str,
    error: yaml.YAMLError,
) -> ReviewResult:
    rule = PlaceholderRule()
    findings: List[Finding] = []
    seen_fingerprints = set()
    lines = text.splitlines()

    for line_number, line in enumerate(lines, start=1):
        hit = rule.evaluate_text(line)
        if hit is None:
            continue

        original_location = SourceLocation(
            line=line_number,
            representation=Representation.ORIGINAL,
        )
        fingerprint = compute_fingerprint(
            rule_id=hit.rule_id,
            parse_path=ParsePath.TEXT,
            original_location=original_location,
            logical_path=(),
        )
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        findings.append(
            Finding(
                rule_id=hit.rule_id,
                parse_path=ParsePath.TEXT,
                original_location=original_location,
                # There is no normalized representation on the fallback path.
                normalized_location=None,
                evidence={
                    'source': ParsePath.TEXT.value,
                    'detail': hit.evidence,
                },
                restricted_value=hit.restricted_value,
                fingerprint=fingerprint,
            ),
        )

    return ReviewResult(
        filename=filename,
        parse_path=ParsePath.TEXT,
        findings=findings,
        normalized_entries=[],
        normalized_lines=[],
        original_text=text,
        diagnostic=_build_diagnostic(error),
    )


def _build_diagnostic(error: yaml.YAMLError) -> ParseDiagnostic:
    problem_line: Optional[int] = None
    problem_column: Optional[int] = None
    mark = getattr(error, 'problem_mark', None)
    if mark is not None:
        problem_line = mark.line + 1
        problem_column = mark.column + 1

    return ParseDiagnostic(
        error_type=type(error).__name__,
        # The raw exception message stays internal: it can echo input fragments.
        message=str(error),
        problem_line=problem_line,
        problem_column=problem_column,
    )
