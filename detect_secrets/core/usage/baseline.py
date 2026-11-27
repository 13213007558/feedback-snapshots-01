import argparse
import json
import os
import subprocess

from .. import baseline
from ...exceptions import UnableToReadBaselineError
from ...util import git
from .common import initialize_plugin_settings


def _valid_baseline_path(path: str) -> str:
    if os.path.isfile(path):
        return path

    # A staged-only baseline has no working tree copy, but it can still be reviewed.
    try:
        if git.read_index_blob(path) is not None:
            return path
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass

    raise argparse.ArgumentTypeError(f'Invalid path: {path}')


def add_baseline_option(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument(
        '--baseline',
        nargs=1,
        metavar='FILENAME',
        type=_valid_baseline_path,
        help=help,
    )


def parse_args(args: argparse.Namespace) -> None:
    if not hasattr(args, 'baseline') or not args.baseline:
        return initialize_plugin_settings(args)

    staged = getattr(args, 'staged', False)
    try:
        if staged:
            staged_baseline = git.read_index_blob(args.baseline[0])
            if staged_baseline is None:
                raise ValueError(f'Baseline is not staged: {args.baseline[0]}')

            if staged_baseline.content is None:
                raise ValueError(f'Baseline is not valid UTF-8: {args.baseline[0]}')

            loaded_baseline = json.loads(staged_baseline.content)
            args.baseline_blob = staged_baseline.object_id
            args.baseline_rename_source = git.get_staged_rename_source(args.baseline[0])
        else:
            loaded_baseline = baseline.load_from_file(args.baseline[0])
    except UnableToReadBaselineError:
        raise argparse.ArgumentTypeError('Unable to read baseline.')
    except (ValueError, json.decoder.JSONDecodeError) as e:
        raise argparse.ArgumentTypeError(str(e) or 'Unable to read baseline.')

    try:
        args.baseline_filename = args.baseline[0]
        args.baseline_version = loaded_baseline['version']
        args.baseline = baseline.load(loaded_baseline, filename=args.baseline_filename)
    except KeyError:
        raise argparse.ArgumentTypeError('Invalid baseline.')
