"""
End-to-end demonstration of the external review hand-off workflow.

It builds TWO fully synthetic scan baselines (no real secrets, no production
source), exports a shareable projection of each, simulates an outside vendor
returning different decisions, re-opens the shared reports, and merges the
decisions back. At every stage that leaves the local machine it asserts that no
local marker value (plaintext secret or source line) is present.

Run from the repository root:

    python handoff_demo/run_demo.py
"""
import json
import os
import shutil
import tempfile

from detect_secrets.audit import handoff
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings

PLUGINS = [
    {'name': 'AWSKeyDetector'},
    {'name': 'HexHighEntropyString', 'limit': 3.0},
    {'name': 'KeywordDetector'},
]

# Every literal below is synthetic and obviously fake.
SNAPSHOT_A = {
    'app.py': [
        'apikey = "AKIAIOSFODNN7EXAMPLE"',
        'password = "e17d4c9b3a2f50816a9c7d4e2b1f8063deadbeef"',
    ],
    'app2.py': [
        'token = "AKIAIOSFODNN7EXAMPLE"',
    ],
}

SNAPSHOT_B = {
    # Same AWS literal again, plus a brand new hex literal, so the two
    # baselines share a fingerprint while remaining distinct snapshots.
    'app.py': [
        'apikey = "AKIAIOSFODNN7EXAMPLE"',
        'password = "0a1b2c3d4e5f60718293a4b5c6d7e8f9cafebabe"',
    ],
    'app2.py': [
        'token = "AKIAIOSFODNN7EXAMPLE"',
    ],
}

# Marker values that must never appear in any shared artifact.
LOCAL_MARKERS = [
    'AKIAIOSFODNN7EXAMPLE',
    'e17d4c9b3a2f50816a9c7d4e2b1f8063deadbeef',
    '0a1b2c3d4e5f60718293a4b5c6d7e8f9cafebabe',
]


def build_baseline(root, snapshot, label):
    for filename, lines in snapshot.items():
        with open(os.path.join(root, filename), 'w') as handle:
            handle.write('\n'.join(lines) + '\n')

    # Scan from inside the snapshot root so filenames are repo-relative, just
    # like a real `detect-secrets scan` run.
    previous_cwd = os.getcwd()
    os.chdir(root)
    try:
        with transient_settings({'plugins_used': PLUGINS}):
            collection = SecretsCollection()
            # One file at a time avoids any multiprocessing pool, keeping the
            # demo deterministic and fully offline.
            for filename in sorted(snapshot):
                collection.scan_file(filename)
            data = baseline.format_for_output(collection)
    finally:
        os.chdir(previous_cwd)

    with open(os.path.join(root, '{}.baseline.json'.format(label)), 'w') as handle:
        handle.write(json.dumps(data, indent=2) + '\n')
    return data


def assert_no_local_markers(payload, stage, markers):
    blob = json.dumps(payload)
    leaked = [marker for marker in markers if marker in blob]
    if leaked:
        raise AssertionError(
            'stage {!r} leaked local marker value(s): {}'.format(stage, leaked),
        )


def fill_vendor_decisions(review_template):
    """Pretend to be the outside vendor, who only sees the projected form."""
    review = json.loads(json.dumps(review_template))
    decisions = {
        # Two categories at app.py:1 share a fingerprint but are triaged
        # separately: the AWS key is real, the keyword hit is a false positive.
        ('app.py', 1, 'AWS Access Key'): True,
        ('app.py', 1, 'Secret Keyword'): False,
        # The shared AWS literal in the other file gets its own decision.
        ('app2.py', 1, 'AWS Access Key'): False,
    }
    for finding in review['findings']:
        key = (finding['filename'], finding['line_number'], finding['type'])
        if key in decisions:
            finding['is_secret'] = decisions[key]
    return review


def main():
    workdir = tempfile.mkdtemp(prefix='ds-handoff-demo-')
    try:
        dir_a = os.path.join(workdir, 'snapshot_a')
        dir_b = os.path.join(workdir, 'snapshot_b')
        os.makedirs(dir_a)
        os.makedirs(dir_b)

        baseline_a = build_baseline(dir_a, SNAPSHOT_A, 'a')
        baseline_b = build_baseline(dir_b, SNAPSHOT_B, 'b')

        print('== local baselines (stay on this machine) ==')
        for label, data in (('A', baseline_a), ('B', baseline_b)):
            count = sum(len(entries) for entries in data['results'].values())
            print('baseline {}: {} findings'.format(label, count))

        # 1. Export both baselines through the single shared projection.
        export_a = handoff.project_baseline(baseline_a)
        export_b = handoff.project_baseline(baseline_b)
        for stage, doc in (('export A', export_a), ('export B', export_b)):
            handoff.assert_shareable(doc)
            assert_no_local_markers(doc, stage, LOCAL_MARKERS)

        # Persist exactly what would be sent to the vendor.
        shared_path = os.path.join(workdir, 'shared-handoff-a.json')
        with open(shared_path, 'w') as handle:
            handle.write(json.dumps(export_a, indent=2) + '\n')
        assert_no_local_markers(
            json.loads(open(shared_path).read()), 'shared file', LOCAL_MARKERS,
        )

        # 2. Re-open the shared report from disk without touching source files.
        reopened = handoff.load_handoff(open(shared_path).read())
        assert reopened['findings'] == export_a['findings']
        print('\n== re-opened shareable report ==')
        for finding in reopened['findings']:
            print(handoff._format_location(finding))

        # 3. Vendor fills in a review against the projected identities.
        review = fill_vendor_decisions(handoff.build_review_template(export_a))
        handoff.assert_shareable(review)
        assert_no_local_markers(review, 'vendor review', LOCAL_MARKERS)

        review_path = os.path.join(workdir, 'review-a.json')
        with open(review_path, 'w') as handle:
            handle.write(json.dumps(review, indent=2) + '\n')
        review_reloaded = handoff.load_handoff(open(review_path).read())

        # 4. Merge decisions back using the composite identity, not the hash.
        updated, applied, unmatched = handoff.merge_review(baseline_a, review_reloaded)
        assert not unmatched, 'every review entry must land on a finding: {}'.format(unmatched)

        by_key = {
            (entry['filename'], entry['line_number'], entry['type']): entry
            for entry in (
                updated['results']['app.py'] + updated['results']['app2.py']
            )
        }
        collision_aws = by_key[('app.py', 1, 'AWS Access Key')]
        collision_keyword = by_key[('app.py', 1, 'Secret Keyword')]
        shared_literal_other_file = by_key[('app2.py', 1, 'AWS Access Key')]

        assert collision_aws['is_secret'] is True
        assert collision_keyword['is_secret'] is False
        assert collision_aws['hashed_secret'] == collision_keyword['hashed_secret']
        assert shared_literal_other_file['is_secret'] is False

        print('\n== merged decisions (exact findings) ==')
        for item in applied:
            print(
                '{location} -> is_secret={decision}'.format(
                    location=handoff._format_location(item),
                    decision=item['is_secret'],
                ),
            )

        print(
            '\ncollision check: shared fingerprint {hash!r} keeps '
            'AWS={aws} vs Keyword={keyword}'.format(
                hash=collision_aws['hashed_secret'],
                aws=collision_aws['is_secret'],
                keyword=collision_keyword['is_secret'],
            ),
        )

        # 5. A forbidden local field must be rejected before anything is shared.
        poisoned = json.loads(json.dumps(export_a))
        poisoned['findings'][0]['secret_value'] = 'AKIAIOSFODNN7EXAMPLE'
        try:
            handoff.assert_shareable(poisoned)
        except handoff.LeakageError as exc:
            print('\nleakage guard blocked forbidden field: {}'.format(exc))
        else:  # pragma: no cover
            raise AssertionError('leakage guard failed to reject poisoned document')

        print('\nOK: report locatable, decisions exact, no local marker shared.')
        print('(scratch directory was: {})'.format(workdir))
        return workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    main()
