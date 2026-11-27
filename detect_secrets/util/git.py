import os
import subprocess
from typing import Dict
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Tuple

from ..core.log import log
from .path import get_relative_path


class IndexEntry(NamedTuple):
    path: str
    mode: str
    object_id: str
    stage: int


class StagedContent(NamedTuple):
    path: str
    object_id: str
    raw: bytes
    content: Optional[str]


def get_root_directory(path: str = '') -> str:
    """
    :raises: CalledProcessError
    """
    command = ['git']
    if path:
        command.extend(['-C', path])

    command.extend(['rev-parse', '--show-toplevel'])
    return subprocess.check_output(command).decode('utf-8').strip()


def get_tracked_files(root: str) -> Set[str]:
    """Parsing .gitignore rules is hard.

    However, a way we can get around this problem by just listing all
    currently tracked git files, and start our search from there.
    After all, if it isn't in the git repo, we're not concerned about
    it, because secrets aren't being entered in a shared place.

    :raises: CalledProcessError
    """
    output = set()
    try:
        files = subprocess.check_output(
            ['git', '-C', root, 'ls-files'],
            stderr=subprocess.DEVNULL,
        )

        for filename in files.decode('utf-8').splitlines():
            path = get_relative_path(root, os.path.join(root, filename))
            if path:
                output.add(path)

    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:   # pragma: no cover
        log.warning('Unable to find `git` in PATH, and therefore, unable to get tracked files.')

    return output


def get_changed_but_unstaged_files() -> Set[str]:
    try:
        files = subprocess.check_output('git diff --name-only'.split()).decode().splitlines()
    except subprocess.CalledProcessError:   # pragma: no cover
        # Since we don't pipe stderr, we get free logging through git.
        raise ValueError

    return set(files)


def _normalize_path(path: str) -> str:
    return os.path.normpath(path).replace(os.sep, '/')


def _git(*args: str) -> bytes:
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL)


def get_index_entries(*paths: str) -> Dict[str, IndexEntry]:
    """
    Reads stage-0 entries from the index, without touching the working tree.

    Conflicted paths (stages 1-3) are deliberately omitted: there is no single staged
    version that could be approved, and callers should treat them as absent.

    :raises: CalledProcessError
    """
    output = _git('ls-files', '-s', '-z', '--', *paths)
    entries: Dict[str, IndexEntry] = {}
    for record in output.split(b'\0'):
        if not record:
            continue

        metadata, path = record.split(b'\t', 1)
        mode, object_id, stage = metadata.decode('utf-8').split()
        if stage != '0':
            continue

        normalized = _normalize_path(path.decode('utf-8'))
        entries[normalized] = IndexEntry(
            path=normalized,
            mode=mode,
            object_id=object_id,
            stage=int(stage),
        )

    return entries


def read_index_blob(path: str) -> Optional[StagedContent]:
    """
    Returns the exact bytes stored in the index for `path`, or None if it is not staged.

    :raises: CalledProcessError
    """
    normalized = _normalize_path(path)
    entry = get_index_entries(normalized).get(normalized)
    if not entry:
        return None

    raw = _git('cat-file', 'blob', entry.object_id)
    try:
        content: Optional[str] = raw.decode('utf-8')
    except UnicodeDecodeError:
        content = None

    return StagedContent(
        path=normalized,
        object_id=entry.object_id,
        raw=raw,
        content=content,
    )


def get_worktree_blob_id(path: str) -> Optional[str]:
    """Computes the blob id for the working tree copy, without writing it to the object db."""
    try:
        return _git('hash-object', '--', path).decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None


def get_head_blob_id(path: str) -> Optional[str]:
    try:
        return _git('rev-parse', '--verify', f'HEAD:{path}').decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None


def get_unmerged_paths(*paths: str) -> Set[str]:
    """
    Returns paths that have conflict stages (1-3) in the index.

    A conflicted path has no single approved version, so staged review must not guess.
    """
    output = _git('ls-files', '-u', '-z', '--', *paths)
    unmerged: Set[str] = set()
    for record in output.split(b'\0'):
        if not record:
            continue

        _, path = record.split(b'\t', 1)
        unmerged.add(_normalize_path(path.decode('utf-8')))

    return unmerged


def get_staged_rename_source(path: str) -> Optional[str]:
    """
    If this path was staged as a rename, returns the previous path.

    The rename search is done against the whole index (not just `path`), since a
    pathspec would hide the deleted side of the rename from git's similarity detection.
    """
    try:
        output = _git('diff', '--cached', '--name-status', '-z', '-M')
    except subprocess.CalledProcessError:   # pragma: no cover
        return None

    normalized_path = _normalize_path(path)
    parts = output.split(b'\0')
    index = 0
    while index < len(parts):
        field = parts[index]
        if not field:
            index += 1
            continue

        status = field.decode('utf-8')
        if status.startswith(('R', 'C')):
            old_path = parts[index + 1].decode('utf-8')
            new_path = parts[index + 2].decode('utf-8')
            if _normalize_path(new_path) == normalized_path:
                return old_path
            index += 3
        else:
            index += 2

    return None
