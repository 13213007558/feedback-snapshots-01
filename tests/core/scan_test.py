import os
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


class TestScanFile:
    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield


class TestScanFileContents:
    @staticmethod
    def test_uses_the_given_path_for_filters_and_results():
        content = 'http://username:whywouldyouusehttpforpasswords@example.com\n'
        with transient_settings({'plugins_used': [{'name': 'BasicAuthDetector'}]}):
            secrets = list(scan.scan_file_contents('test_data/not-on-disk.txt', content))

        assert len(secrets) == 1
        assert secrets[0].filename == 'test_data/not-on-disk.txt'
        assert secrets[0].line_number == 1

    @staticmethod
    def test_applies_filename_filters_to_the_staged_path():
        content = 'http://username:whywouldyouusehttpforpasswords@example.com\n'
        with transient_settings({
            'plugins_used': [{'name': 'BasicAuthDetector'}],
            'filters_used': [{
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': [r'\.lock$'],
            }],
        }):
            assert not list(scan.scan_file_contents('package.lock', content))
            assert list(scan.scan_file_contents('app.txt', content))

    @staticmethod
    def test_does_not_require_the_file_to_exist():
        content = 'http://username:whywouldyouusehttpforpasswords@example.com\n'
        with transient_settings({'plugins_used': [{'name': 'BasicAuthDetector'}]}):
            assert not os.path.exists('test_data/staged-only/app.txt')
            assert list(scan.scan_file_contents('test_data/staged-only/app.txt', content))

    @staticmethod
    def test_yaml_transformers_still_apply_to_staged_content():
        content = 'token: ZmFrZS1zdGFnZWQtc2VjcmV0LW1hcmtlci1hbHBoYS0wMDE\n'
        with transient_settings({
            'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}],
        }):
            secrets = list(scan.scan_file_contents('settings.yaml', content))

        assert len(secrets) == 1
        assert secrets[0].filename == 'settings.yaml'
