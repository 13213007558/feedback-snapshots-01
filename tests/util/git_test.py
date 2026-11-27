import subprocess

import pytest

from detect_secrets.util import git


def test_index_entries_ignore_conflict_stages_and_normalize_paths():
    output = (
        b'100644 aaaa 0\tplain.py\0'
        b'100644 bbbb 1\tconflicted.py\0'
        b'100644 cccc 2\tconflicted.py\0'
    )

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', lambda *args, **kwargs: output)
        entries = git.get_index_entries('plain.py', 'conflicted.py')

    assert list(entries) == ['plain.py']
    assert entries['plain.py'].object_id == 'aaaa'
    assert entries['plain.py'].stage == 0


def test_read_index_blob_uses_the_index_object_id():
    calls = []

    def fake_check_output(command, **kwargs):
        calls.append(command)
        if command[1] == 'ls-files':
            return b'100644 deadbeef 0\tdir/file.py\0'
        return b'TOKEN = "synthetic"\n'

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', fake_check_output)
        staged = git.read_index_blob('dir/file.py')

    assert staged is not None
    assert staged.path == 'dir/file.py'
    assert staged.object_id == 'deadbeef'
    assert staged.raw == b'TOKEN = "synthetic"\n'
    assert staged.content == 'TOKEN = "synthetic"\n'
    assert ['git', 'cat-file', 'blob', 'deadbeef'] in calls


def test_read_index_blob_returns_none_for_an_absent_path():
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', lambda *args, **kwargs: b'')
        assert git.read_index_blob('absent.py') is None


def test_read_index_blob_keeps_binary_content_undecoded():
    def fake_check_output(command, **kwargs):
        if command[1] == 'ls-files':
            return b'100644 cafe 0\timage.bin\0'
        return b'\xff\xfe\x00'

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', fake_check_output)
        staged = git.read_index_blob('image.bin')

    assert staged is not None
    assert staged.raw == b'\xff\xfe\x00'
    assert staged.content is None


def test_staged_rename_source_matches_the_new_path():
    output = b'R097\0old/.secrets.baseline\0config/secrets.baseline\0M\0app.py\0'

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', lambda *args, **kwargs: output)
        assert git.get_staged_rename_source('config/secrets.baseline') == 'old/.secrets.baseline'
        assert git.get_staged_rename_source('app.py') is None


def test_unmerged_paths_are_reported():
    output = b'100644 aaaa 1\tapp.py\0' + b'100644 bbbb 2\tapp.py\0'

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(subprocess, 'check_output', lambda *args, **kwargs: output)
        assert git.get_unmerged_paths('app.py') == {'app.py'}
