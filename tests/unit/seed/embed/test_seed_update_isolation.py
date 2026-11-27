"""Safety of updating a seed package in one environment while another keeps using the shared image.

The build service may only refresh the seed components of the one virtual environment it was asked to update. A second
environment links the same wheel image from the shared application data folder and may start at any time, so an update
has to (a) leave that shared image and the running environment untouched on failure, with the old launcher still usable,
and (b) make the updated environment provably run the new version once the new install record is written.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from virtualenv.app_data import AppDataDiskFolder
from virtualenv.info import fs_supports_symlink
from virtualenv.run import cli_run
from virtualenv.seed.embed.via_app_data.pip_install.copy import CopyPipInstall
from virtualenv.seed.embed.via_app_data.pip_install.symlink import SymlinkPipInstall

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

    from virtualenv.run.session import Session

_DIST: Final[str] = "seedemo"
_LAUNCHER: Final[str] = "seedemo"
_OLD: Final[str] = "1.0"
_NEW: Final[str] = "2.0"


def _make_wheel(folder: Path, version: str) -> Path:
    """Build a small pure-Python wheel with an importable package and a console script entry point."""
    folder.mkdir(parents=True, exist_ok=True)
    wheel: Final[Path] = folder / f"{_DIST}-{version}-py3-none-any.whl"
    files: Final[dict[str, str]] = {
        f"{_DIST}/__init__.py": f"__version__ = {version!r}\n\ndef main() -> None:\n    print(__version__)\n",
        f"{_DIST}-{version}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {_DIST}\nVersion: {version}\n",
        f"{_DIST}-{version}.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{_DIST}-{version}.dist-info/top_level.txt": f"{_DIST}\n",
        f"{_DIST}-{version}.dist-info/entry_points.txt": f"[console_scripts]\n{_LAUNCHER} = {_DIST}:main\n",
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        archive.writestr(f"{_DIST}-{version}.dist-info/RECORD", "".join(f"{name},,\n" for name in files))
    return wheel


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, object]:
    """Two seed-only environments sharing one application data cache, plus the old and new wheels."""
    cache: Final[Path] = tmp_path / "app-data"
    old_wheel: Final[Path] = _make_wheel(tmp_path / "wheels", _OLD)
    new_wheel: Final[Path] = _make_wheel(tmp_path / "wheels", _NEW)
    app_data: Final[AppDataDiskFolder] = AppDataDiskFolder(str(cache))

    def _env(name: str) -> Session:
        return cli_run(
            [str(tmp_path / name), "--no-seed", "--app-data", str(cache), "--activators=", "--no-periodic-update"],
            setup_logging=False,
        )

    target: Final[Session] = _env("target-env")  # the environment the build service updates
    other: Final[Session] = _env("other-env")  # keeps linking the shared image
    return {
        "app_data": app_data,
        "old_wheel": old_wheel,
        "new_wheel": new_wheel,
        "target": target,
        "other": other,
    }


def _image(session: Session, app_data: AppDataDiskFolder, installer: type, wheel: Path) -> Path:
    key: Final[Path] = Path(installer.__name__) / wheel.stem
    return app_data.wheel_image(session.interpreter.version_release_str, key)


def _install(session: Session, app_data: AppDataDiskFolder, installer: type, wheel: Path) -> None:
    image: Final[Path] = _image(session, app_data, installer, wheel)
    seeder: Final = installer(wheel, session.creator, image)
    seeder.build_image()
    seeder.install(session.interpreter.version_info)


def _imported_version(session: Session) -> str:
    return subprocess.check_output(
        [str(session.creator.exe), "-c", f"import {_DIST}; print({_DIST}.__version__)"], text=True
    ).strip()


def _metadata_version(session: Session) -> str:
    return subprocess.check_output(
        [
            str(session.creator.exe),
            "-c",
            f"import importlib.metadata as meta; print(meta.version({_DIST!r}))",
        ],
        text=True,
    ).strip()


def _dist_info(session: Session) -> Path:
    return next(session.creator.purelib.glob(f"{_DIST}-*.dist-info"))


def _package(session: Session) -> Path:
    return session.creator.purelib / _DIST


def _run_launcher(session: Session) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(session.creator.script(_LAUNCHER))], capture_output=True, text=True, check=False
    )


@pytest.mark.skipif(not fs_supports_symlink(), reason="the shared-image environment links its seed files")
def test_seed_update_failure_protects_the_other_environment_and_launcher(
    layout: dict[str, object], mocker: MockerFixture
) -> None:
    app_data: Final[AppDataDiskFolder] = layout["app_data"]
    old_wheel: Final[Path] = layout["old_wheel"]
    new_wheel: Final[Path] = layout["new_wheel"]
    target: Final[Session] = layout["target"]
    other: Final[Session] = layout["other"]

    # the target takes copied files; the other environment links the same version's shared image
    _install(target, app_data, CopyPipInstall, old_wheel)
    _install(other, app_data, SymlinkPipInstall, old_wheel)

    package_target, package_other = _package(target), _package(other)
    assert package_target.is_symlink() is False  # copy: the environment owns real files
    assert package_other.is_symlink() is True  # link: files belong to the shared image, not the environment
    shared_image: Final[Path] = (package_other / "__init__.py").resolve()
    assert str(app_data) in str(shared_image)
    assert (_imported_version(target), _imported_version(other)) == (_OLD, _OLD)
    old_launcher: Final[Path] = target.creator.script(_LAUNCHER)

    # fail the upgrade while its image is still staged, before the atomic publish and before any env install record
    new_image: Final[Path] = _image(target, app_data, CopyPipInstall, new_wheel)
    staging: Final[Path] = new_image.parent.with_name(f"{new_image.parent.name}-{new_image.name}")
    mocker.patch.object(
        CopyPipInstall,
        "_populate_image",
        autospec=True,
        side_effect=RuntimeError("injected failure before the new install record"),
    )
    with pytest.raises(RuntimeError, match="injected failure"):
        CopyPipInstall(new_wheel, target.creator, new_image).build_image()

    # no partial image or staging directory survives; the old images are intact
    assert (new_image.exists(), staging.exists()) == (False, False)
    # both environments still import the old version and the target's old launcher still runs it
    assert (_imported_version(target), _imported_version(other)) == (_OLD, _OLD)
    result: Final[subprocess.CompletedProcess[str]] = _run_launcher(target)
    assert (result.returncode, result.stdout.strip()) == (0, _OLD)
    assert old_launcher.exists()
    # the linked environment still resolves to the very same shared image and keeps its old metadata
    assert (package_other / "__init__.py").resolve() == shared_image
    assert _dist_info(target).name == f"{_DIST}-{_OLD}.dist-info"
    assert _dist_info(other).name == f"{_DIST}-{_OLD}.dist-info"


@pytest.mark.skipif(not fs_supports_symlink(), reason="the shared-image environment links its seed files")
def test_successful_seed_update_leaves_the_linked_environment_on_the_old_image(
    layout: dict[str, object]
) -> None:
    app_data: Final[AppDataDiskFolder] = layout["app_data"]
    old_wheel: Final[Path] = layout["old_wheel"]
    new_wheel: Final[Path] = layout["new_wheel"]
    target: Final[Session] = layout["target"]
    other: Final[Session] = layout["other"]

    _install(target, app_data, CopyPipInstall, old_wheel)
    _install(other, app_data, SymlinkPipInstall, old_wheel)
    shared_old_image: Final[Path] = (_package(other) / "__init__.py").resolve()

    # only the target environment is updated to the new wheel
    _install(target, app_data, CopyPipInstall, new_wheel)

    # the target provably runs the new version through import, metadata and its launcher; the other stays on the old one
    assert (_imported_version(target), _metadata_version(target)) == (_NEW, _NEW)
    assert (_imported_version(other), _metadata_version(other)) == (_OLD, _OLD)
    new_launcher: Final[subprocess.CompletedProcess[str]] = _run_launcher(target)
    old_launcher: Final[subprocess.CompletedProcess[str]] = _run_launcher(other)
    assert (new_launcher.returncode, new_launcher.stdout.strip()) == (0, _NEW)
    assert (old_launcher.returncode, old_launcher.stdout.strip()) == (0, _OLD)
    # ownership evidence survives the update: target owns copied files, other still links the untouched shared image
    assert _package(target).is_symlink() is False
    assert _package(other).is_symlink() is True
    assert (_package(other) / "__init__.py").resolve() == shared_old_image
    assert _dist_info(target).name == f"{_DIST}-{_NEW}.dist-info"
    assert _dist_info(other).name == f"{_DIST}-{_OLD}.dist-info"
