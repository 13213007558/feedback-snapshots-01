"""Tests for the --approved-source / --approved-build-tool source rules."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.lib import PipTestEnvironment, create_basic_wheel_for_package

# Build dependencies can be installed in a subprocess (default) or in process
# (--use-feature=inprocess-build-deps); source rules must apply to both.
INSTALLER_ARGS = [
    pytest.param([], id="subprocess"),
    pytest.param(["--use-feature=inprocess-build-deps"], id="inprocess"),
]

# A minimal PEP 517 build backend, shipped inside the "approved-backend"
# wheel as a top-level module. It records when the build entry point runs
# so tests can prove whether pip reached it.
BACKEND_SRC = '''\
import base64
import csv
import hashlib
import io
import os
from zipfile import ZipFile

PROJECT = "mixedproj"
VERSION = "1.0"

WHEEL = """\\
Wheel-Version: 1.0
Generator: mixed_backend 1.0
Root-Is-Purelib: true
Tag: py3-none-any
"""

METADATA = """\\
Metadata-Version: 2.1
Name: mixedproj
Version: 1.0
Requires-Dist: normaldep
"""


def _dist_info():
    return f"{PROJECT}-{VERSION}.dist-info"


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    dist_info = os.path.join(metadata_directory, _dist_info())
    os.mkdir(dist_info)
    with open(os.path.join(dist_info, "METADATA"), "w") as f:
        f.write(METADATA)
    return _dist_info()


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    # Prove that the build entry point ran: pip invokes the backend with
    # the source tree as the working directory.
    with open(os.path.join(os.getcwd(), "backend-ran.txt"), "w") as f:
        f.write("yes")

    record = []

    def add_file(z, name, data):
        data = data.encode("utf-8")
        z.writestr(name, data)
        digest = hashlib.sha256(data).digest()
        hash_ = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        record.append((name, f"sha256={hash_}", len(data)))

    wheel_name = f"{PROJECT}-{VERSION}-py3-none-any.whl"
    with ZipFile(os.path.join(wheel_directory, wheel_name), "w") as z:
        dist_info = _dist_info()
        add_file(z, f"{dist_info}/WHEEL", WHEEL)
        add_file(z, f"{dist_info}/METADATA", METADATA)
        add_file(z, f"{PROJECT}.py", "")
        record.append((f"{dist_info}/RECORD", "", ""))
        buf = io.BytesIO()
        wrapper = io.TextIOWrapper(buf, newline="", encoding="utf-8")
        csv.writer(wrapper).writerows(record)
        z.writestr(f"{dist_info}/RECORD", buf.getvalue())
        wrapper.close()
    return wheel_name
'''

PYPROJECT_TOML = """\
[build-system]
requires = ["approved-backend"]
build-backend = "mixed_backend"
"""


def _make_repos(script: PipTestEnvironment) -> tuple[Path, Path, Path]:
    """Create an approved repo with a runtime dependency, an unapproved
    repo with the build backend, and a project needing both."""
    repo_approved = script.scratch_path / "approved_repo"
    repo_other = script.scratch_path / "other_repo"
    repo_approved.mkdir()
    repo_other.mkdir()

    normaldep = create_basic_wheel_for_package(script, "normaldep", "1.0")
    shutil.move(normaldep, repo_approved / normaldep.name)

    backend = create_basic_wheel_for_package(
        script,
        "approved_backend",
        "1.0",
        extra_files={"mixed_backend.py": BACKEND_SRC},
    )
    shutil.move(backend, repo_other / backend.name)

    project_dir = script.scratch_path / "mixedproj"
    project_dir.mkdir()
    (project_dir / "pyproject.toml").write_text(PYPROJECT_TOML)

    return repo_approved, repo_other, project_dir


@pytest.mark.parametrize("installer_args", INSTALLER_ARGS)
def test_mixed_sources_with_build_tool_exception(
    script: PipTestEnvironment, installer_args: list[str]
) -> None:
    """A valid mixed configuration: the runtime dependency comes from the
    approved source while the vetted build tool is fetched, by exception,
    from an unapproved one."""
    repo_approved, repo_other, project_dir = _make_repos(script)

    result = script.pip_install_local(
        "--no-cache-dir",
        "--approved-source",
        str(repo_approved),
        "--approved-build-tool",
        "approved-backend",
        *installer_args,
        str(project_dir),
        find_links=[repo_approved, repo_other],
        build_isolation=True,
    )

    script.assert_installed(mixedproj="1.0", normaldep="1.0")
    assert "error" not in result.stderr.lower()
    # The build backend was installed from the unapproved repo and ran.
    assert (project_dir / "backend-ran.txt").exists()


@pytest.mark.parametrize("installer_args", INSTALLER_ARGS)
def test_build_dependency_without_approved_source_fails_before_build(
    script: PipTestEnvironment, installer_args: list[str]
) -> None:
    """A build request for a package that has no approved source must fail
    before the build entry point is run."""
    repo_approved, repo_other, project_dir = _make_repos(script)

    result = script.pip_install_local(
        "--no-cache-dir",
        "--approved-source",
        str(repo_approved),
        *installer_args,
        str(project_dir),
        find_links=[repo_approved, repo_other],
        build_isolation=True,
        expect_error=True,
    )

    assert "No matching distribution found for approved-backend" in result.stderr
    assert "not from an approved source" in result.stderr
    # The failure happened while installing build dependencies, i.e. before
    # the build entry point (build_wheel) was invoked.
    assert not (project_dir / "backend-ran.txt").exists()


def test_regular_dependency_without_approved_source_fails(
    script: PipTestEnvironment,
) -> None:
    """Regular dependencies are also confined to the approved sources."""
    repo_approved, repo_other, _ = _make_repos(script)

    result = script.pip_install_local(
        "--no-cache-dir",
        "--approved-source",
        str(repo_approved),
        # Only available from the unapproved repo.
        "approved-backend",
        find_links=[repo_approved, repo_other],
        expect_error=True,
    )

    assert "No matching distribution found for approved-backend" in result.stderr
    assert "not from an approved source" in result.stderr
    script.assert_not_installed("approved-backend")


def test_regular_dependency_from_approved_source_succeeds(
    script: PipTestEnvironment,
) -> None:
    """Packages below an approved source install normally."""
    repo_approved, repo_other, _ = _make_repos(script)

    script.pip_install_local(
        "--no-cache-dir",
        "--approved-source",
        str(repo_approved),
        "normaldep",
        find_links=[repo_approved, repo_other],
    )

    script.assert_installed(normaldep="1.0")
