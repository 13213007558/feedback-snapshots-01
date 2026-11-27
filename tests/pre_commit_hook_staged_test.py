"""
Regression tests for reviewing the exact snapshot recorded in the Git index.

The real hook is invoked as a subprocess, so these tests exercise the console entry point
and its receipt exactly as a commit would. Only fictional markers are used.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from detect_secrets.__version__ import VERSION


# These decode to strings like "fake-staged-secret-marker-alpha-001".
MARKER_ALPHA = 'ZmFrZS1zdGFnZWQtc2VjcmV0LW1hcmtlci1hbHBoYS0wMDE'
MARKER_BRAVO = 'ZmFrZS1zdGFnZWQtc2VjcmV0LW1hcmtlci1icmF2by0wMDI'
MARKER_CHARLIE = 'ZmFrZS1zdGFnZWQtc2VjcmV0LW1hcmtlci1jaGFybGllLTAwMw'

BASELINE = '.secrets.baseline'
RENAMED_BASELINE = 'config/secrets.baseline'


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, 'init', '-q')
    _git(tmp_path, 'config', 'user.email', 'fixture@example.invalid')
    _git(tmp_path, 'config', 'user.name', 'Fixture')
    _git(tmp_path, 'config', 'commit.gpgsign', 'false')
    return tmp_path


def test_marker_only_in_staged_content_is_blocked_despite_worktree_baseline(repo):
    """
    The approved baseline exists only in the working tree. The staged content must still be
    evaluated against the baseline version that is actually part of the commit.
    """
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _write_baseline(repo, BASELINE, {})
    _commit(repo, 'base')

    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'add', 'app.py')

    # Later working-tree edits are not part of the index and must not become the input.
    _write(repo, 'app.py', _marker_line(MARKER_BRAVO))
    _write_baseline(repo, BASELINE, {'app.py': [_finding('app.py', MARKER_ALPHA)]})

    staged_source_blob = _index_blob(repo, 'app.py')
    staged_baseline_blob = _index_blob(repo, BASELINE)
    source_bytes = _cat_blob(repo, staged_source_blob)
    baseline_bytes = _cat_blob(repo, staged_baseline_blob)

    assert MARKER_ALPHA in source_bytes.decode('utf-8')
    assert MARKER_BRAVO not in source_bytes.decode('utf-8')
    assert json.loads(baseline_bytes)['results'] == {}

    before = _snapshot(repo)
    result = _run_hook(repo, '--staged', '--json', 'app.py', '--baseline', BASELINE)
    after = _snapshot(repo)

    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt['mode'] == 'staged'
    assert receipt['decision'] == 'block'
    assert receipt['blocking_reason'] == 'new-secrets'

    # The receipt points at exactly the blobs read back above, not the working-tree copies.
    source_receipt = receipt['inputs'][0]
    assert source_receipt['path'] == 'app.py'
    assert source_receipt['blob'] == staged_source_blob
    assert source_receipt['blob_sha256'] == hashlib.sha256(source_bytes).hexdigest()
    assert source_receipt['worktree_matches_index'] is False
    assert source_receipt['worktree_blob'] == _worktree_blob(repo, 'app.py')
    assert source_receipt['worktree_blob'] != staged_source_blob

    assert receipt['baseline']['path'] == BASELINE
    assert receipt['baseline']['blob'] == staged_baseline_blob
    assert receipt['baseline']['blob_sha256'] == hashlib.sha256(baseline_bytes).hexdigest()
    assert receipt['baseline']['approved_secret_count'] == 0
    assert receipt['baseline']['version'] == VERSION
    assert receipt['baseline']['worktree_matches_index'] is False

    # The finding is the staged marker, identified only by its hash.
    findings = receipt['new_secrets']['app.py']
    assert [item['hashed_secret'] for item in findings] == [_hash_secret(MARKER_ALPHA)]
    assert MARKER_ALPHA not in result.stdout
    assert MARKER_BRAVO not in result.stdout
    assert MARKER_ALPHA not in result.stderr
    assert MARKER_BRAVO not in result.stderr

    # A read-only review leaves both the index and the working tree alone.
    assert _snapshot(repo) == before
    assert after == before

    # Negative control: a stand-in that binds the source to the index but reads the
    # baseline from the working tree cannot reproduce the real decision.
    stand_in = _StandInSourceOnlyReview(repo, 'app.py', BASELINE)
    assert stand_in.decision == 'pass'
    assert stand_in.decision != receipt['decision']
    assert stand_in.approval_basis == 'working-tree baseline'
    assert stand_in.staged_baseline_blob != stand_in.approval_blob


def test_staged_rename_uses_the_renamed_baseline_blob(repo):
    """
    The baseline was renamed and updated, and the update is staged together with the rename.
    The receipt must name the renamed path, the staged blob, and the previous path.
    """
    legacy_results = {
        f'legacy/file_{index}.py': [_finding(f'legacy/file_{index}.py', MARKER_CHARLIE)]
        for index in range(40)
    }
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _write_baseline(repo, BASELINE, legacy_results)
    _commit(repo, 'base with legacy baseline')

    (repo / 'config').mkdir()
    _git(repo, 'mv', BASELINE, RENAMED_BASELINE)
    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'add', 'app.py')

    staged_results = dict(legacy_results)
    staged_results['app.py'] = [_finding('app.py', MARKER_ALPHA)]
    _write_baseline(repo, RENAMED_BASELINE, staged_results)
    _git(repo, 'add', RENAMED_BASELINE)

    rename_status = _git(repo, 'diff', '--cached', '--name-status', '-M').decode('utf-8')
    assert f'R' in rename_status
    assert f'{BASELINE}\t{RENAMED_BASELINE}' in rename_status

    _write(repo, 'app.py', _marker_line(MARKER_BRAVO))
    _write_baseline(repo, RENAMED_BASELINE, legacy_results)

    staged_source_blob = _index_blob(repo, 'app.py')
    staged_baseline_blob = _index_blob(repo, RENAMED_BASELINE)
    source_bytes = _cat_blob(repo, staged_source_blob)
    baseline_bytes = _cat_blob(repo, staged_baseline_blob)
    baseline_document = json.loads(baseline_bytes)

    assert MARKER_ALPHA in source_bytes.decode('utf-8')
    assert baseline_document['results']['app.py'][0]['hashed_secret'] == _hash_secret(MARKER_ALPHA)
    assert baseline_document['results']['app.py'][0]['hashed_secret'] != _hash_secret(MARKER_BRAVO)

    before = _snapshot(repo)
    result = _run_hook(repo, '--staged', '--json', 'app.py', '--baseline', RENAMED_BASELINE)
    after = _snapshot(repo)

    assert result.returncode == 0
    receipt = json.loads(result.stdout)
    assert receipt['decision'] == 'pass'
    assert receipt['blocking_reason'] is None
    assert receipt['new_secret_count'] == 0

    assert receipt['baseline']['path'] == RENAMED_BASELINE
    assert receipt['baseline']['blob'] == staged_baseline_blob
    assert receipt['baseline']['blob_sha256'] == hashlib.sha256(baseline_bytes).hexdigest()
    assert receipt['baseline']['renamed_from'] == BASELINE
    assert receipt['baseline']['approved_secret_count'] == 41
    assert receipt['baseline']['worktree_matches_index'] is False

    source_receipt = receipt['inputs'][0]
    assert source_receipt['blob'] == staged_source_blob
    assert source_receipt['blob_sha256'] == hashlib.sha256(source_bytes).hexdigest()
    assert source_receipt['worktree_matches_index'] is False

    assert _snapshot(repo) == before
    assert after == before
    assert MARKER_ALPHA not in result.stdout
    assert MARKER_BRAVO not in result.stdout

    # The approved snapshot is the one named by the receipt; the old path is only provenance.
    assert _cat_blob(repo, receipt['baseline']['blob']) == baseline_bytes
    assert json.loads(_cat_blob(repo, _index_blob(repo, RENAMED_BASELINE)))['results']['app.py']


def test_baseline_version_mismatch_blocks_and_names_the_staged_version(repo):
    """
    The staged baseline records an older version than the running tool. The receipt must
    show both versions, take the staged blob, and never rewrite either copy.
    """
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _write_baseline(repo, BASELINE, {}, version='1.4.0')
    _commit(repo, 'base with older baseline')

    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'add', 'app.py')
    _write_baseline(repo, BASELINE, {'app.py': [_finding('app.py', MARKER_ALPHA)]}, version='1.4.0')
    _git(repo, 'add', BASELINE)

    # A newer, working-tree-only baseline would make the marker look approved.
    _write_baseline(repo, BASELINE, {'app.py': [_finding('app.py', MARKER_ALPHA)]}, version=VERSION)

    staged_baseline_blob = _index_blob(repo, BASELINE)
    staged_baseline = json.loads(_cat_blob(repo, staged_baseline_blob))
    working_baseline = json.loads((repo / BASELINE).read_text())

    assert staged_baseline['version'] == '1.4.0'
    assert working_baseline['version'] == VERSION

    before = _snapshot(repo)
    result = _run_hook(repo, '--staged', '--json', 'app.py', '--baseline', BASELINE)
    after = _snapshot(repo)

    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt['decision'] == 'block'
    assert receipt['blocking_reason'] == 'baseline-version-mismatch'
    assert receipt['version_consistent'] is False
    assert receipt['tool_version'] == VERSION
    assert receipt['baseline']['version'] == '1.4.0'
    assert receipt['baseline']['version_consistent'] is False
    assert receipt['baseline']['blob'] == staged_baseline_blob
    assert receipt['baseline']['blob_sha256'] == hashlib.sha256(
        _cat_blob(repo, staged_baseline_blob),
    ).hexdigest()
    assert receipt['baseline']['worktree_matches_index'] is False
    assert 'baseline file was updated' not in result.stdout.lower()

    # The approval in the working tree is not the approval used by this review.
    assert receipt['new_secrets'] == {}
    stand_in = _StandInSourceOnlyReview(repo, 'app.py', BASELINE)
    assert stand_in.decision == 'pass'
    assert stand_in.decision != receipt['decision']
    assert stand_in.staged_baseline_blob != stand_in.approval_blob

    assert _snapshot(repo) == before
    assert after == before
    assert json.loads((repo / BASELINE).read_text())['version'] == VERSION
    assert json.loads(_cat_blob(repo, _index_blob(repo, BASELINE)))['version'] == '1.4.0'


def _marker_line(marker):
    return f'TOKEN = "{marker}"\n'


def _hash_secret(marker):
    return hashlib.sha1(marker.encode('utf-8')).hexdigest()


def _finding(path, marker, line_number=1):
    return {
        'type': 'Base64 High Entropy String',
        'filename': path,
        'hashed_secret': _hash_secret(marker),
        'is_verified': False,
        'line_number': line_number,
    }


def _write(repo, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _write_baseline(repo, path, results, version=VERSION):
    document = {
        'version': version,
        'plugins_used': [
            {'name': 'Base64HighEntropyString', 'limit': 4.5},
        ],
        'filters_used': [],
        'results': results,
    }
    _write(repo, path, json.dumps(document, indent=2) + '\n')


def _git(repo, *args):
    return subprocess.check_output(['git', *args], cwd=str(repo), stderr=subprocess.DEVNULL)


def _commit(repo, message):
    _git(repo, 'add', '--all')
    _git(repo, 'commit', '-qm', message)


def _index_blob(repo, path):
    return _git(repo, 'rev-parse', f':{path}').decode('utf-8').strip()


def _worktree_blob(repo, path):
    return _git(repo, 'hash-object', '--', path).decode('utf-8').strip()


def _cat_blob(repo, object_id):
    return _git(repo, 'cat-file', 'blob', object_id)


def _hook_command():
    console_script = Path(sys.executable).with_name('detect-secrets-hook')
    if console_script.exists():
        return [str(console_script)]

    # Fallback for environments where the console script is not next to the interpreter.
    return [
        sys.executable,
        '-c',
        'import sys; from detect_secrets.pre_commit_hook import main; sys.exit(main())',
    ]


def _run_hook(repo, *args):
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None)
    return subprocess.run(
        [*_hook_command(), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=environment,
    )


def _snapshot(repo):
    """Captures the semantic state of both the index and the working tree."""
    worktree = {}
    for path in sorted(repo.rglob('*')):
        if '.git' in path.parts or not path.is_file():
            continue
        worktree[str(path.relative_to(repo))] = path.read_bytes()

    return {
        'index': _git(repo, 'ls-files', '-s', '-z'),
        'status': _git(repo, 'status', '--porcelain=v1', '-z'),
        'worktree': worktree,
    }


class _StandInSourceOnlyReview:
    """
    A deliberately naive stand-in: the source is read from the index, but the approval is
    read from the working tree. It must not be able to explain which baseline was approved.
    """

    approval_basis = 'working-tree baseline'

    def __init__(self, repo, source_path, baseline_path):
        self.repo = repo
        self.source_path = source_path
        self.baseline_path = baseline_path
        self.staged_baseline_blob = _index_blob(repo, baseline_path)
        self.approval_blob = _worktree_blob(repo, baseline_path)
        self.decision = self._decide()

    def _decide(self):
        source = _cat_blob(self.repo, _index_blob(self.repo, self.source_path)).decode('utf-8')
        baseline = json.loads((self.repo / self.baseline_path).read_text())
        approved = {
            item['hashed_secret']
            for findings in baseline['results'].values()
            for item in findings
        }

        for marker in (MARKER_ALPHA, MARKER_BRAVO, MARKER_CHARLIE):
            if marker in source and _hash_secret(marker) not in approved:
                return 'block'

        return 'pass'


def test_unmerged_input_is_blocked_without_choosing_a_side(repo):
    """
    A conflicted path has no single staged version. The review must block, name it as
    unmerged, and leave the conflict in place.
    """
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _commit(repo, 'base')

    _git(repo, 'checkout', '-qb', 'other')
    _write(repo, 'app.py', _marker_line(MARKER_BRAVO))
    _git(repo, 'commit', '-qam', 'other')

    _git(repo, 'checkout', '-q', '-')
    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'commit', '-qam', 'main')

    merge = subprocess.run(
        ['git', 'merge', 'other'],
        cwd=str(repo),
        capture_output=True,
    )
    assert merge.returncode != 0

    before = _snapshot(repo)
    result = _run_hook(repo, '--staged', '--json', 'app.py')
    after = _snapshot(repo)

    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt['decision'] == 'block'
    assert receipt['blocking_reason'] == 'unmerged-input'
    assert receipt['inputs'][0]['path'] == 'app.py'
    assert receipt['inputs'][0]['staged'] is False
    assert receipt['inputs'][0]['unmerged'] is True
    assert receipt['new_secrets'] == {}

    assert _snapshot(repo) == before
    assert after == before
    assert MARKER_ALPHA not in result.stdout
    assert MARKER_BRAVO not in result.stdout


def test_human_readable_review_names_the_staged_blobs(repo):
    """
    The non-JSON receipt also has to identify the reviewed snapshot, since that is what a
    reviewer would keep in a commit log.
    """
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _write_baseline(repo, BASELINE, {})
    _commit(repo, 'base')

    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'add', 'app.py')
    _write(repo, 'app.py', _marker_line(MARKER_BRAVO))

    staged_source_blob = _index_blob(repo, 'app.py')
    staged_baseline_blob = _index_blob(repo, BASELINE)
    before = _snapshot(repo)

    result = _run_hook(repo, '--staged', 'app.py', '--baseline', BASELINE)
    after = _snapshot(repo)

    assert result.returncode == 1
    assert f'app.py @ {staged_source_blob}' in result.stdout
    assert 'working tree differs from index' in result.stdout
    assert f'{BASELINE} @ {staged_baseline_blob}' in result.stdout
    assert 'Total secrets detected: 1' in result.stdout
    assert MARKER_ALPHA not in result.stdout
    assert MARKER_BRAVO not in result.stdout

    assert _snapshot(repo) == before
    assert after == before


def test_staged_marker_is_not_masked_by_a_clean_worktree_copy(repo):
    """
    The working tree no longer contains the marker, but the commit still would. Scanning
    the current path (the worktree) would incorrectly approve it.
    """
    _write(repo, 'app.py', 'TOKEN = "not a secret"\n')
    _write_baseline(repo, BASELINE, {})
    _commit(repo, 'base')

    _write(repo, 'app.py', _marker_line(MARKER_ALPHA))
    _git(repo, 'add', 'app.py')
    _write(repo, 'app.py', 'TOKEN = "cleaned up in the worktree"\n')

    staged_source_blob = _index_blob(repo, 'app.py')
    assert MARKER_ALPHA in _cat_blob(repo, staged_source_blob).decode('utf-8')
    assert MARKER_ALPHA not in (repo / 'app.py').read_text()

    before = _snapshot(repo)
    result = _run_hook(repo, '--staged', '--json', 'app.py', '--baseline', BASELINE)
    after = _snapshot(repo)

    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt['decision'] == 'block'
    assert receipt['blocking_reason'] == 'new-secrets'
    assert receipt['inputs'][0]['blob'] == staged_source_blob
    assert receipt['inputs'][0]['worktree_matches_index'] is False
    assert receipt['mixed_worktree_and_index'] == ['app.py']
    assert [item['hashed_secret'] for item in receipt['new_secrets']['app.py']] == [
        _hash_secret(MARKER_ALPHA),
    ]

    # Negative control: scanning the worktree copy alone would have approved this commit.
    assert _StandInWorktreeSourceReview(repo, 'app.py', BASELINE).decision == 'pass'
    assert _StandInWorktreeSourceReview(repo, 'app.py', BASELINE).decision != receipt['decision']

    assert _snapshot(repo) == before
    assert after == before


class _StandInWorktreeSourceReview:
    """Scans the current path files, as the original hook did, and reads the worktree baseline."""

    approval_basis = 'working-tree source'

    def __init__(self, repo, source_path, baseline_path):
        self.decision = self._decide(repo, source_path, baseline_path)

    def _decide(self, repo, source_path, baseline_path):
        source = (repo / source_path).read_text()
        baseline = json.loads((repo / baseline_path).read_text())
        approved = {
            item['hashed_secret']
            for findings in baseline['results'].values()
            for item in findings
        }

        for marker in (MARKER_ALPHA, MARKER_BRAVO, MARKER_CHARLIE):
            if marker in source and _hash_secret(marker) not in approved:
                return 'block'

        return 'pass'
