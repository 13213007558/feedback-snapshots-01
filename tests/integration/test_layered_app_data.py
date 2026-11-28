"""End-to-end checks for a read-only shared cache layered over a private staging folder.

The shared cache is a real virtualenv app-data tree, frozen read-only like the one a build machine hands
to every project. One seed (pip) is pre-baked into it; the other seed (setuptools) is missing and has to be
generated inside the project's private staging folder. Every assertion proves the shared tree is read but
never written, while the private tree is the only place new files and locks appear.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

from virtualenv import cli_run
from virtualenv.app_data.layered_run import cli_run_layered
from virtualenv.seed.wheels.embed import get_embed_wheel

_PY: Final[str] = f"{sys.version_info.major}.{sys.version_info.minor}"


def _freeze_read_only(folder: Path) -> None:
    """Remove every write bit so any attempt to write raises, like a read-only mount."""
    for root, dirs, files in os.walk(folder):
        for name in files + dirs:
            os.chmod(os.path.join(root, name), 0o555 if os.path.isdir(os.path.join(root, name)) else 0o444)
    os.chmod(folder, 0o555)


def _snapshot(folder: Path) -> set[str]:
    return {str(path.relative_to(folder)) for path in folder.rglob("*")}


@pytest.fixture
def shared_cache(tmp_path: Path) -> Path:
    """A real app-data cache containing only the pip image, frozen read-only."""
    cache = tmp_path / "shared-cache"
    # seed the cache with a pip-only environment so the pip image is baked in
    cli_run(
        [
            str(tmp_path / "warmer"),
            "--app-data",
            str(cache),
            "--no-periodic-update",
            "--no-setuptools",
            "--activators",
            "",
        ]
    )
    _freeze_read_only(cache)
    return cache


@pytest.fixture
def private_index(tmp_path: Path) -> Path:
    """A private staging source (stand-in for the private index) holding the missing setuptools wheel."""
    index = tmp_path / "private" / "index"
    index.mkdir(parents=True)
    wheel = get_embed_wheel("setuptools", _PY)
    shutil.copy2(wheel.path, index / wheel.path.name)
    return index


def _layered_args(dest: Path, index: Path) -> list[str]:
    return [
        str(dest),
        "--setuptools",
        "bundle",
        "--extra-search-dir",
        str(index),
        "--no-periodic-update",
        "--no-download",
        "--activators",
        "",
    ]


def test_shared_hit_is_read_and_missing_seed_is_built_privately(
    tmp_path: Path, shared_cache: Path, private_index: Path
) -> None:
    private_stage = tmp_path / "private" / "stage"
    before = _snapshot(shared_cache)

    session, store = cli_run_layered(
        str(shared_cache), str(private_stage), _layered_args(tmp_path / "env", private_index)
    )

    # the shared cache is byte-for-byte unchanged and still read-only
    assert _snapshot(shared_cache) == before
    assert not os.access(shared_cache, os.W_OK)
    # no lock was created inside the shared tree during the run
    assert not {p for p in shared_cache.rglob("*.lock") if str(p.relative_to(shared_cache)) not in before}

    # the missing setuptools image exists only in the private staging folder
    setuptools_image = private_stage / "wheel" / _PY / "image" / "1" / "CopyPipInstall"
    private_images = {p.name for p in setuptools_image.iterdir() if p.is_dir()}
    assert any(name.startswith("setuptools-") for name in private_images)
    assert not (shared_cache / "wheel" / _PY / "image" / "1" / "CopyPipInstall" / "setuptools-0").exists()
    # every private lock stays inside the staging folder
    assert all(str(p.resolve()).startswith(str(private_stage.resolve())) for p in private_stage.rglob("*.lock"))

    # both seeds are importable: pip came from the shared image, setuptools from the private one
    env_python = tmp_path / "env" / "bin" / "python"
    import_check = (
        "import pip, setuptools; "
        f"assert pip.__version__ == {get_embed_wheel('pip', _PY).version!r}; "
        f"assert setuptools.__version__ == {get_embed_wheel('setuptools', _PY).version!r}"
    )
    result = subprocess.run(
        [str(env_python), "-c", import_check], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert session.seeder.app_data is store


def test_two_interleaved_sessions_share_read_only_cache_and_isolate_private_writes(
    tmp_path: Path, shared_cache: Path, private_index: Path
) -> None:
    # each project session gets its own private staging folder, as separate projects would, and runs as a
    # separate local process so the two sessions genuinely interleave
    stage_a = tmp_path / "project-a" / "stage"
    stage_b = tmp_path / "project-b" / "stage"
    env_a = tmp_path / "project-a" / "env"
    env_b = tmp_path / "project-b" / "env"
    before = _snapshot(shared_cache)

    common = [
        sys.executable,
        "-c",
        "import sys; from pathlib import Path; "
        "from virtualenv.app_data.layered_run import cli_run_layered; "
        "cli_run_layered(sys.argv[1], sys.argv[2], "
        "[sys.argv[3], '--setuptools', 'bundle', '--extra-search-dir', sys.argv[4], "
        "'--no-periodic-update', '--no-download', '--activators', ''])",
        str(shared_cache),
    ]
    process_a = subprocess.Popen([*common, str(stage_a), str(env_a), str(private_index)])  # noqa: S603 - fixed argv
    process_b = subprocess.Popen([*common, str(stage_b), str(env_b), str(private_index)])  # noqa: S603 - fixed argv
    code_a = process_a.wait()
    code_b = process_b.wait()
    assert (code_a, code_b) == (0, 0)

    # the shared cache served both sessions without a single write
    assert _snapshot(shared_cache) == before
    # each session materialised its own private setuptools image, never in the shared tree
    for stage in (stage_a, stage_b):
        images = stage / "wheel" / _PY / "image" / "1" / "CopyPipInstall"
        assert any(p.name.startswith("setuptools-") for p in images.iterdir() if p.is_dir())
    assert not any(shared_cache.rglob("setuptools-*"))


def test_failed_build_reclaims_its_staging_directory(
    tmp_path: Path, shared_cache: Path, private_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from virtualenv.app_data.layered_run import FAIL_IMAGE_ENV

    private_stage = tmp_path / "private" / "stage"
    # force the image build to fail after creating its staging directory
    monkeypatch.setenv(FAIL_IMAGE_ENV, "injected build failure")
    with pytest.raises(RuntimeError, match="layered seed failed|injected build failure"):
        cli_run_layered(str(shared_cache), str(private_stage), _layered_args(tmp_path / "env", private_index))

    # no half-built image and no staging directory survive a caught failure
    installer_dir = private_stage / "wheel" / _PY / "image" / "1" / "CopyPipInstall"
    leftovers = [p for p in installer_dir.glob("CopyPipInstall-*")] if installer_dir.exists() else []
    assert leftovers == []
    assert not list(private_stage.rglob("*.tmp"))
    # the shared cache remains untouched even though the build failed
    assert not any(shared_cache.rglob("setuptools-*"))


def test_orphaned_staging_directory_is_detected_by_audit(tmp_path: Path, shared_cache: Path) -> None:
    # simulate a process killed mid-build: its staging directory is left behind with no chance to clean up
    private_stage = tmp_path / "private" / "stage"
    installer_dir = private_stage / "wheel" / _PY / "image" / "1" / "CopyPipInstall"
    orphan = installer_dir / "CopyPipInstall-setuptools-84.2.1-py3-none-any"
    orphan.mkdir(parents=True)
    (orphan / "half-extracted.txt").write_text("partial", encoding="utf-8")

    assert find_orphaned_staging(private_stage) == [orphan]
    # cleaning the orphan up makes the audit come back clean
    shutil.rmtree(orphan)
    assert find_orphaned_staging(private_stage) == []


def find_orphaned_staging(private_stage: Path) -> list[Path]:
    """Return the staging directories a killed or failed build could leave inside the private folder."""
    return sorted(path for path in private_stage.rglob("CopyPipInstall-*") if path.is_dir())
