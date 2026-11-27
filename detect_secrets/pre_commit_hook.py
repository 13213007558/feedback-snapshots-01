import argparse
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from detect_secrets.__version__ import VERSION
from detect_secrets.core import baseline
from detect_secrets.core import scan
from detect_secrets.core.log import log
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.util import color
from detect_secrets.util import git


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = parse_args(argv)
    except ValueError:
        return 1

    if args.verbose:    # pragma: no cover
        log.set_debug_level(args.verbose)

    if args.staged:
        return run_staged_review(args)

    # Find all secrets in files to be committed
    secrets = SecretsCollection()
    for filename in args.filenames:
        secrets.scan_file(filename)

    new_secrets = secrets
    if args.baseline:
        new_secrets = secrets - args.baseline

    if new_secrets:
        if args.json:
            print(json.dumps(baseline.format_for_output(new_secrets), indent=2))
        else:
            pretty_print_diagnostics(new_secrets)
        return 1

    if not args.baseline:
        return 0

    # Only attempt baseline modifications if we don't find any new secrets.
    is_modified = should_update_baseline(
        args.baseline,
        scanned_results=secrets,
        filelist=args.filenames,
        baseline_version=args.baseline_version,
    )

    if is_modified:
        if args.baseline_version != VERSION:
            with open(args.baseline_filename) as f:
                old_baseline = json.loads(f.read())

            # Override the results, because this has been updated in `should_update_baseline`.
            old_baseline['results'] = args.baseline.json()

            args.baseline = baseline.upgrade(old_baseline)

        baseline.save_to_file(args.baseline, filename=args.baseline_filename)
        print(
            'The baseline file was updated.\n'
            'Probably to keep line numbers of secrets up-to-date.\n'
            'Please `git add {}`, thank you.\n\n'.format(args.baseline_filename),
        )
        return 3

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    :raises: ValueError
    """
    output = ParserBuilder().add_pre_commit_arguments().parse_args(argv)
    if output.baseline and not getattr(output, 'staged', False):
        raise_exception_if_baseline_file_is_unstaged(output.baseline_filename)

    return output


def run_staged_review(args: argparse.Namespace) -> int:
    """
    Reviews the exact versions recorded in the Git index, without touching either the
    index or the working tree.

    The baseline is already loaded from its index blob (see `usage.baseline.parse_args`).
    Here we scan each requested file from its index blob and emit a receipt that ties
    every decision to the blob that was read.
    """
    secrets = SecretsCollection()
    input_receipts: List[Dict[str, Any]] = []
    missing: List[str] = []
    unmerged: List[str] = []
    binary: List[str] = []
    try:
        conflicted = git.get_unmerged_paths(*args.filenames)
    except subprocess.CalledProcessError:
        print('Unable to read the Git index for a staged review.', file=sys.stderr)
        return 1

    for filename in args.filenames:
        staged = git.read_index_blob(filename)
        if staged is None:
            (unmerged if filename in conflicted else missing).append(filename)
            input_receipts.append(_input_receipt(filename, None, filename in conflicted))
            continue

        input_receipts.append(_input_receipt(filename, staged, False))
        if staged.content is None:
            binary.append(filename)
            continue

        for secret in scan.scan_file_contents(staged.path, staged.content):
            secrets[staged.path].add(secret)

    baseline_collection = args.baseline
    new_secrets = secrets
    if baseline_collection is not None:
        new_secrets = secrets - baseline_collection

    baseline_version = getattr(args, 'baseline_version', None)
    baseline_blob = getattr(args, 'baseline_blob', None)
    version_consistent = baseline_version is None or baseline_version == VERSION

    receipt: Dict[str, Any] = {
        'mode': 'staged',
        'tool_version': VERSION,
        'baseline': _baseline_receipt(args, baseline_version, baseline_blob),
        'inputs': input_receipts,
        'mixed_worktree_and_index': sorted(
            item['path'] for item in input_receipts
            if item['staged'] and not item['worktree_matches_index']
        ),
        'new_secrets': new_secrets.json(),
        'new_secret_count': len(new_secrets),
        'version_consistent': version_consistent,
        'decision': 'pass',
        'blocking_reason': None,
    }

    if unmerged:
        receipt['decision'] = 'block'
        receipt['blocking_reason'] = 'unmerged-input'
    elif missing:
        receipt['decision'] = 'block'
        receipt['blocking_reason'] = 'unstaged-input'
    elif binary:
        receipt['decision'] = 'block'
        receipt['blocking_reason'] = 'binary-input'
    elif not version_consistent:
        receipt['decision'] = 'block'
        receipt['blocking_reason'] = 'baseline-version-mismatch'
    elif new_secrets:
        receipt['decision'] = 'block'
        receipt['blocking_reason'] = 'new-secrets'

    if args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        _print_staged_review(receipt, new_secrets)

    return 0 if receipt['decision'] == 'pass' else 1


def _blob_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _input_receipt(
    filename: str,
    staged: Optional[git.StagedContent],
    unmerged: bool = False,
) -> Dict[str, Any]:
    worktree_blob = git.get_worktree_blob_id(filename)
    if staged is None:
        return {
            'path': filename,
            'staged': False,
            'unmerged': unmerged,
            'blob': None,
            'blob_sha256': None,
            'bytes': None,
            'head_blob': git.get_head_blob_id(filename),
            'worktree_blob': worktree_blob,
            'worktree_matches_index': False,
        }

    return {
        'path': staged.path,
        'staged': True,
        'unmerged': False,
        'blob': staged.object_id,
        'blob_sha256': _blob_sha256(staged.raw),
        'bytes': len(staged.raw),
        'head_blob': git.get_head_blob_id(staged.path),
        'worktree_blob': worktree_blob,
        'worktree_matches_index': worktree_blob == staged.object_id,
    }


def _baseline_receipt(
    args: argparse.Namespace,
    baseline_version: Optional[str],
    baseline_blob: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not getattr(args, 'baseline_filename', None):
        return None

    filename = args.baseline_filename
    staged = git.read_index_blob(filename)
    worktree_blob = git.get_worktree_blob_id(filename)

    baseline: Dict[str, Any] = {
        'path': filename,
        'blob': staged.object_id if staged else baseline_blob,
        'blob_sha256': _blob_sha256(staged.raw) if staged else None,
        'version': baseline_version,
        'version_consistent': baseline_version is None or baseline_version == VERSION,
        'renamed_from': getattr(args, 'baseline_rename_source', None),
        'approved_secret_count': len(args.baseline) if args.baseline is not None else 0,
        'worktree_blob': worktree_blob,
        'worktree_matches_index': bool(
            staged and worktree_blob == staged.object_id,
        ),
    }

    return baseline


def _print_staged_review(receipt: Dict[str, Any], new_secrets: SecretsCollection) -> None:
    baseline = receipt['baseline']
    if baseline:
        print(
            'Baseline (index): {path} @ {blob} (version {version}{rename})'.format(
                path=baseline['path'],
                blob=baseline['blob'],
                version=baseline['version'],
                rename=(
                    f", renamed from {baseline['renamed_from']}"
                    if baseline['renamed_from'] else ''
                ),
            ),
        )

    for item in receipt['inputs']:
        print(
            'Input (index): {path} @ {blob} (working tree {state})'.format(
                path=item['path'],
                blob=item['blob'],
                state=(
                    'matches index' if item['worktree_matches_index']
                    else 'differs from index'
                ),
            ),
        )

    if receipt['blocking_reason'] == 'new-secrets':
        pretty_print_diagnostics(new_secrets)
    elif receipt['blocking_reason']:
        print(f'Blocked: {receipt["blocking_reason"]}')
    else:
        print('No new secrets found in the staged content.')


def raise_exception_if_baseline_file_is_unstaged(filename: str) -> None:
    """
    We want to make sure that if there are changes to the baseline
    file, they will be included in the commit. This way, we can keep
    our baselines up-to-date.

    :raises: ValueError
    """
    if filename in git.get_changed_but_unstaged_files():
        print(
            f'Your baseline file ({filename}) is unstaged.\n'
            f'`git add {filename}` to fix this.',
        )
        raise ValueError


def should_update_baseline(
    secrets: SecretsCollection,
    scanned_results: SecretsCollection,
    filelist: List[str],
    baseline_version: str,
) -> bool:
    """
    :returns: True if changes occurred.
    """
    original = SecretsCollection.load_from_baseline({'results': secrets.json()})

    secrets.trim(scanned_results=scanned_results, filelist=filelist)

    if baseline_version != VERSION:
        return True

    if not secrets.exactly_equals(original):
        return True

    return False


def pretty_print_diagnostics(secrets: SecretsCollection, width: int = 80) -> None:
    # Header
    print(
        textwrap.fill(
            color.colorize(
                'ERROR: Potential secrets about to be committed to git repo!',
                color.AnsiColor.RED,
            ),
            width=width,
        ),
    )
    print()

    # Display found secrets
    for _, secret in secrets:
        print(secret)

    # Display the number of detected secrets
    print(f'\nTotal secrets detected: {len(secrets)}')

    # Display mitigation suggestions
    print('Possible mitigations:')
    wrapper = textwrap.TextWrapper(
        initial_indent='  - ',
        subsequent_indent='    ',
        width=width,
    )
    for suggestion in [
        'For information about putting your secrets in a safer place, '
        'please ask {0}'.format(os.environ.get('DETECT_SECRETS_SECURITY_TEAM', 'in #security')),

        'Mark false positives with an inline '
        '`{0}` comment'.format(color.colorize('pragma: allowlist secret', color.AnsiColor.BOLD)),
    ]:
        print(wrapper.fill(suggestion))

    print()
    print(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
            width=width,
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
