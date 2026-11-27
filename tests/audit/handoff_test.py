import json

import pytest

from detect_secrets.audit import handoff

SHARED_HASH = '25910f981e85ca04baf359199dd0bd4a3ae738b6'
OTHER_HASH = '5f75cd15fa9cbb71385a5267502ee6c6286d0464'
LOCAL_MARKER = 'AKIAIOSFODNN7EXAMPLE'


def make_baseline():
    # Two findings at app.py:1 share a fingerprint but differ in category.
    return {
        'version': '1.5.0',
        'plugins_used': [],
        'filters_used': [],
        'results': {
            'app.py': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'app.py',
                    'hashed_secret': SHARED_HASH,
                    'is_verified': False,
                    'line_number': 1,
                },
                {
                    'type': 'Secret Keyword',
                    'filename': 'app.py',
                    'hashed_secret': SHARED_HASH,
                    'is_verified': False,
                    'line_number': 1,
                },
            ],
            'app2.py': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'app2.py',
                    'hashed_secret': SHARED_HASH,
                    'is_verified': False,
                    'line_number': 1,
                },
                {
                    'type': 'Hex High Entropy String',
                    'filename': 'app2.py',
                    'hashed_secret': OTHER_HASH,
                    'is_verified': False,
                    'line_number': 2,
                },
            ],
        },
        'generated_at': '2026-11-27T00:00:00Z',
    }


def test_project_strips_to_shareable_fields_and_orders_by_key():
    document = handoff.project_baseline(make_baseline())

    assert document['kind'] == handoff.DOCUMENT_KIND
    assert len(document['findings']) == 4
    keys = [handoff.finding_key(f) for f in document['findings']]
    assert keys == sorted(keys)
    for finding in document['findings']:
        assert set(finding) == set(handoff.SHAREABLE_FINDING_FIELDS)
        assert LOCAL_MARKER not in json.dumps(finding)


def test_projection_never_carries_marker_or_source_line():
    baseline = make_baseline()
    baseline['results']['app.py'][0]['secret_value'] = LOCAL_MARKER
    baseline['results']['app.py'][0]['line'] = 'apikey = "{}"'.format(LOCAL_MARKER)

    document = handoff.project_baseline(baseline)
    assert LOCAL_MARKER not in json.dumps(document)
    assert all('line' not in f and 'secret_value' not in f for f in document['findings'])


def test_assert_shareable_rejects_forbidden_field():
    document = handoff.project_baseline(make_baseline())
    document['findings'][0]['secret_value'] = LOCAL_MARKER

    with pytest.raises(handoff.LeakageError):
        handoff.assert_shareable(document)


def test_reopen_round_trips_without_source_files():
    document = handoff.project_baseline(make_baseline())
    reopened = handoff.load_handoff(json.dumps(document))
    assert reopened['findings'] == document['findings']


def test_load_handoff_rejects_wrong_kind_and_bad_json():
    with pytest.raises(handoff.HandoffError):
        handoff.load_handoff('{"kind": "something-else", "findings": []}')
    with pytest.raises(handoff.HandoffError):
        handoff.load_handoff('not json')


def test_review_template_includes_decision_slot_only():
    document = handoff.project_baseline(make_baseline())
    review = handoff.build_review_template(document)

    expected_fields = set(handoff.IDENTITY_FIELDS) | {'hashed_secret', 'is_secret'}
    for finding in review['findings']:
        assert finding['is_secret'] is None
        assert set(finding) == expected_fields
        assert 'is_verified' not in finding
    handoff.assert_shareable(review)


def test_merge_matches_on_composite_key_not_fingerprint():
    baseline = make_baseline()
    review = handoff.build_review_template(handoff.project_baseline(baseline))
    for finding in review['findings']:
        key = handoff.finding_key(finding)
        if key == ('app.py', 1, 'AWS Access Key'):
            finding['is_secret'] = True
        elif key == ('app.py', 1, 'Secret Keyword'):
            finding['is_secret'] = False
        elif key == ('app2.py', 1, 'AWS Access Key'):
            finding['is_secret'] = False

    updated, applied, unmatched = handoff.merge_review(baseline, review)
    assert unmatched == []
    assert len(applied) == 3

    entries = {
        handoff.finding_key(entry): entry
        for entries in updated['results'].values()
        for entry in entries
    }
    aws = entries[('app.py', 1, 'AWS Access Key')]
    keyword = entries[('app.py', 1, 'Secret Keyword')]

    # Same fingerprint, opposite verdicts: decisions never cross-wired.
    assert aws['hashed_secret'] == keyword['hashed_secret'] == SHARED_HASH
    assert aws['is_secret'] is True
    assert keyword['is_secret'] is False
    # Untouched finding keeps no decision.
    assert entries[('app2.py', 2, 'Hex High Entropy String')].get('is_secret') is None


def test_merge_does_not_mutate_input_baseline():
    baseline = make_baseline()
    review = handoff.build_review_template(handoff.project_baseline(baseline))
    review['findings'][0]['is_secret'] = True

    handoff.merge_review(baseline, review)
    assert 'is_secret' not in baseline['results']['app.py'][0]


def test_merge_reports_unmatched_review_entries():
    baseline = make_baseline()
    review = {
        'kind': handoff.DOCUMENT_KIND,
        'schema_version': handoff.SCHEMA_VERSION,
        'findings': [
            {
                'filename': 'ghost.py',
                'line_number': 99,
                'type': 'AWS Access Key',
                'hashed_secret': SHARED_HASH,
                'is_secret': True,
            },
        ],
    }
    _, applied, unmatched = handoff.merge_review(baseline, review)
    assert applied == []
    assert unmatched == [('ghost.py', 99, 'AWS Access Key')]


def test_merge_rejects_invalid_and_duplicate_decisions():
    baseline = make_baseline()
    bad_review = handoff.build_review_template(handoff.project_baseline(baseline))
    bad_review['findings'][0]['is_secret'] = 'yes'
    with pytest.raises(handoff.HandoffError):
        handoff.merge_review(baseline, bad_review)

    dup_review = {
        'kind': handoff.DOCUMENT_KIND,
        'schema_version': handoff.SCHEMA_VERSION,
        'findings': [
            {
                'filename': 'app.py', 'line_number': 1, 'type': 'AWS Access Key',
                'hashed_secret': SHARED_HASH, 'is_secret': True,
            },
            {
                'filename': 'app.py', 'line_number': 1, 'type': 'AWS Access Key',
                'hashed_secret': SHARED_HASH, 'is_secret': False,
            },
        ],
    }
    with pytest.raises(handoff.HandoffError):
        handoff.merge_review(baseline, dup_review)


def test_main_export_merge_round_trip(tmp_path, capsys):
    baseline_path = tmp_path / 'baseline.json'
    handoff_path = tmp_path / 'handoff.json'
    review_path = tmp_path / 'review.json'
    merged_path = tmp_path / 'merged.json'
    baseline_path.write_text(json.dumps(make_baseline()))

    handoff.main(['export', str(baseline_path), '--output', str(handoff_path)])
    assert LOCAL_MARKER not in handoff_path.read_text()

    handoff.main(['template', str(handoff_path), '--output', str(review_path)])
    review = json.loads(review_path.read_text())
    for finding in review['findings']:
        if handoff.finding_key(finding) == ('app.py', 1, 'AWS Access Key'):
            finding['is_secret'] = True
    review_path.write_text(json.dumps(review))

    rc = handoff.main(['merge', str(baseline_path), str(review_path), '--output', str(merged_path)])
    assert rc == 0
    capsys.readouterr()
    merged = json.loads(merged_path.read_text())
    target = next(
        entry for entry in merged['results']['app.py']
        if entry['type'] == 'AWS Access Key' and entry['line_number'] == 1
    )
    assert target['is_secret'] is True

    handoff.main(['reopen', str(handoff_path)])
    printed = capsys.readouterr().out
    assert json.loads(printed)['kind'] == handoff.DOCUMENT_KIND
