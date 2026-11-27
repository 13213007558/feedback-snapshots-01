"""
External hand-off support for triage work.

The regular ``audit report`` re-opens source files and embeds the matched
marker value (and the source line containing it) in its output. That material
must stay on the machine that performed the scan, so it cannot be sent to an
outside reviewer.

This module projects a baseline into a *shareable* document that only carries
locatable metadata and the one-way ``hashed_secret`` fingerprint. The same
projection is used in three places, so a finding keeps one stable identity
across the whole round trip:

1. :func:`project_baseline` -- build the document we send out.
2. :func:`load_handoff`     -- re-open that document without touching source.
3. :func:`merge_review`     -- fold the returned decisions back into a baseline.

A finding is identified by the composite key
``(filename, line_number, type)`` -- never by ``hashed_secret`` alone. Two
different plugin categories can flag the same line and the same value, which
means they share a fingerprint but are distinct findings and must be triaged
independently.
"""
import argparse
import json
from collections import OrderedDict
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from ..__version__ import VERSION
from ..core import baseline
from ..exceptions import InvalidBaselineError
from ..exceptions import UnableToReadBaselineError

SCHEMA_VERSION = '1.0'
DOCUMENT_KIND = 'detect-secrets-handoff'

# The only finding fields allowed to leave the machine. Everything else -- in
# particular any plaintext marker value or source line -- is projected away.
SHAREABLE_FINDING_FIELDS = (
    'filename',
    'line_number',
    'type',
    'hashed_secret',
    'is_verified',
)

# A returned review adds the triage decision. It is a plain boolean (or unset),
# never a marker value, so it is the only extra field allowed on the way back.
REVIEW_DECISION_FIELD = 'is_secret'
REVIEW_FINDING_FIELDS = SHAREABLE_FINDING_FIELDS + (REVIEW_DECISION_FIELD,)

# The vendor writes decisions back against this tri-part identity. It does not
# include the fingerprint, so a shared fingerprint can never cross-wire two
# categories found at the same location.
IDENTITY_FIELDS = ('filename', 'line_number', 'type')

# Both the outward projection and the returned review must be able to locate a
# finding and reference its fingerprint. Everything else is optional on input.
REQUIRED_FINDING_FIELDS = IDENTITY_FIELDS + ('hashed_secret',)

VALID_DECISIONS = (True, False, None)


class HandoffError(Exception):
    """Raised when a hand-off document or review cannot be processed."""


class LeakageError(HandoffError):
    """Raised when a shareable artifact would carry a local marker value."""


def finding_key(finding: Dict[str, Any]) -> Tuple[str, int, str]:
    """Stable composite identity for a single finding."""
    return (
        str(finding['filename']),
        int(finding['line_number']),
        str(finding['type']),
    )


def _iter_baseline_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for filename, entries in data.get('results', {}).items():
        for entry in entries:
            findings.append({'filename': filename, **entry})
    return findings


def _project_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    projected = {field: finding[field] for field in SHAREABLE_FINDING_FIELDS}
    # Normalize the optional line number to an int; the key relies on it.
    projected['line_number'] = int(projected['line_number'])
    return projected


def assert_shareable(document: Dict[str, Any]) -> None:
    """
    Fail closed if a document that is about to be shared still carries a field
    that could hold a local marker value. This is the single enforcement point
    used by export, re-open and merge, so every public stage obeys the same
    projection.

    Both the outward projection and the returned review form pass through here;
    the latter may additionally carry the boolean ``is_secret`` decision.

    :raises LeakageError: if a forbidden field is present anywhere in findings.
    """
    allowed = set(REVIEW_FINDING_FIELDS)
    for finding in document.get('findings', []):
        forbidden = set(finding) - allowed
        if forbidden:
            raise LeakageError(
                'refusing to share finding at {location}: forbidden field(s) '
                '{fields}'.format(
                    location=_format_location(finding),
                    fields=sorted(forbidden),
                ),
            )


def project_baseline(baseline_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Project a baseline dictionary into the shareable hand-off document.

    The output deliberately omits plugin/filter configuration and every local
    marker value. Findings are ordered by their composite key for deterministic
    output and stable diffs.
    """
    findings = sorted(
        (_project_finding(finding) for finding in _iter_baseline_findings(baseline_data)),
        key=finding_key,
    )
    document = OrderedDict()
    document['kind'] = DOCUMENT_KIND
    document['schema_version'] = SCHEMA_VERSION
    document['source_version'] = baseline_data.get('version', VERSION)
    document['findings'] = findings

    assert_shareable(document)
    return document


def load_handoff(text: str) -> Dict[str, Any]:
    """
    Parse and validate a hand-off document received from disk.

    Unlike :mod:`detect_secrets.audit.report`, this never opens the scanned
    source files: the document is self-contained and carries no marker values.

    :raises HandoffError: if the payload is not a valid hand-off document.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError as e:
        raise HandoffError('hand-off document is not valid JSON: {}'.format(e)) from e

    if not isinstance(document, dict) or document.get('kind') != DOCUMENT_KIND:
        raise HandoffError('not a {} document'.format(DOCUMENT_KIND))
    if not isinstance(document.get('findings'), list):
        raise HandoffError('hand-off document has no findings list')

    for index, finding in enumerate(document['findings']):
        missing = [field for field in REQUIRED_FINDING_FIELDS if field not in finding]
        if missing:
            raise HandoffError(
                'finding #{} is missing required field(s): {}'.format(index, sorted(missing)),
            )
        decision = finding.get(REVIEW_DECISION_FIELD)
        if REVIEW_DECISION_FIELD in finding and decision not in VALID_DECISIONS:
            raise HandoffError(
                'finding #{} has invalid {}={!r}'.format(
                    index, REVIEW_DECISION_FIELD, decision,
                ),
            )

    assert_shareable(document)
    return document


def load_baseline(path: str) -> Dict[str, Any]:
    """Read and upgrade a baseline, applying the same handling as the CLI."""
    return baseline.upgrade(baseline.load_from_file(path))


def _format_location(finding: Dict[str, Any]) -> str:
    return '{}:{} [{}]'.format(
        finding.get('filename', '?'),
        finding.get('line_number', '?'),
        finding.get('type', '?'),
    )


def _index_review_decisions(
    review_findings: List[Dict[str, Any]],
) -> Dict[Tuple[str, int, str], Optional[bool]]:
    decisions: Dict[Tuple[str, int, str], Optional[bool]] = {}
    for finding in review_findings:
        missing = [field for field in IDENTITY_FIELDS if field not in finding]
        if missing:
            raise HandoffError(
                'review entry is missing identity field(s): {}'.format(sorted(missing)),
            )
        decision = finding.get('is_secret')
        if decision not in VALID_DECISIONS:
            raise HandoffError(
                'review entry for {location} has invalid is_secret={value!r}'.format(
                    location=_format_location(finding),
                    value=decision,
                ),
            )
        key = (str(finding['filename']), int(finding['line_number']), str(finding['type']))
        if key in decisions:
            raise HandoffError('duplicate review entry for {}'.format(_format_location(finding)))
        decisions[key] = decision
    return decisions


def merge_review(
    baseline_data: Dict[str, Any],
    review: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Tuple[str, int, str]]]:
    """
    Apply vendor decisions back onto a baseline.

    Matching uses the composite key ``(filename, line_number, type)``. Two
    findings that share a fingerprint but differ in category are therefore
    matched independently, and the fingerprint is never used as a join key.

    The baseline's own secret material is never read or emitted here; only the
    ``is_secret`` audit field is written.

    :returns: ``(updated_baseline, applied, unmatched_keys)`` where ``applied``
        records every decision that landed on an exact finding, and
        ``unmatched_keys`` lists review entries that matched nothing.
    """
    if review.get('kind') != DOCUMENT_KIND:
        raise HandoffError('review payload is not a {} document'.format(DOCUMENT_KIND))

    decisions = _index_review_decisions(review.get('findings', []))
    updated = json.loads(json.dumps(baseline_data))

    applied: List[Dict[str, Any]] = []
    matched_keys = set()
    for filename, entries in updated.get('results', {}).items():
        for entry in entries:
            key = (str(filename), int(entry['line_number']), str(entry['type']))
            if key not in decisions:
                continue
            entry['is_secret'] = decisions[key]
            matched_keys.add(key)
            # Only surface findings the vendor actually decided on; an unset
            # slot is an explicit "no decision", not a verdict.
            if decisions[key] is not None:
                applied.append(
                    {
                        'filename': key[0],
                        'line_number': key[1],
                        'type': key[2],
                        'is_secret': decisions[key],
                    },
                )

    unmatched = sorted(set(decisions) - matched_keys)
    return updated, applied, unmatched


def build_review_template(document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce the blank review form the vendor fills in.

    It keeps the same composite identity fields plus the fingerprint for the
    reviewer's reference, and adds an unset ``is_secret`` slot. No marker value
    is added.
    """
    findings = []
    for finding in document['findings']:
        findings.append(
            OrderedDict(
                [
                    ('filename', finding['filename']),
                    ('line_number', finding['line_number']),
                    ('type', finding['type']),
                    ('hashed_secret', finding['hashed_secret']),
                    ('is_secret', None),
                ],
            ),
        )
    review = OrderedDict()
    review['kind'] = DOCUMENT_KIND
    review['schema_version'] = SCHEMA_VERSION
    review['findings'] = findings
    assert_shareable(review)
    return review


def _read(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.read()
    except OSError as e:
        raise HandoffError('cannot read {}: {}'.format(path, e)) from e


def _write(path: str, document: Dict[str, Any]) -> None:
    assert_shareable(document)
    with open(path, 'w') as handle:
        handle.write(json.dumps(document, indent=2) + '\n')


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='detect-secrets-handoff',
        description='Project, re-open and merge external secret-triage reviews '
        'without sharing local marker values.',
    )
    subparsers = parser.add_subparsers(dest='action', required=True)

    export_parser = subparsers.add_parser(
        'export', help='project a local baseline into a shareable document',
    )
    export_parser.add_argument('baseline')
    export_parser.add_argument('--output', '-o')

    template_parser = subparsers.add_parser(
        'template', help='emit the blank review form for a hand-off document',
    )
    template_parser.add_argument('handoff')
    template_parser.add_argument('--output', '-o')

    reopen_parser = subparsers.add_parser(
        'reopen', help='validate and re-print a hand-off document',
    )
    reopen_parser.add_argument('handoff')

    merge_parser = subparsers.add_parser(
        'merge', help='apply a returned review onto a local baseline',
    )
    merge_parser.add_argument('baseline')
    merge_parser.add_argument('review')
    merge_parser.add_argument('--output', '-o')

    args = parser.parse_args(argv)

    try:
        if args.action == 'export':
            document = project_baseline(load_baseline(args.baseline))
            if args.output:
                _write(args.output, document)
            else:
                print(json.dumps(document, indent=2))

        elif args.action == 'template':
            document = load_handoff(_read(args.handoff))
            review = build_review_template(document)
            if args.output:
                _write(args.output, review)
            else:
                print(json.dumps(review, indent=2))

        elif args.action == 'reopen':
            document = load_handoff(_read(args.handoff))
            print(json.dumps(document, indent=2))

        elif args.action == 'merge':
            review = load_handoff(_read(args.review))
            updated, applied, unmatched = merge_review(load_baseline(args.baseline), review)
            if args.output:
                with open(args.output, 'w') as handle:
                    handle.write(json.dumps(updated, indent=2) + '\n')
            report = {
                'applied': applied,
                'unmatched': [
                    {'filename': key[0], 'line_number': key[1], 'type': key[2]}
                    for key in unmatched
                ],
            }
            print(json.dumps(report, indent=2))
    except (HandoffError, UnableToReadBaselineError, InvalidBaselineError) as e:
        parser.exit(1, 'error: {}\n'.format(e))

    return 0


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(main())
