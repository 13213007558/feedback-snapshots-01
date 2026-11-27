"""Demonstrate a seed package update that is scoped to one virtual environment.

The build service may only refresh the seed components of the one environment it is asked to update. A second
environment links the same wheel image from the shared virtualenv application data folder and may start while the
update runs, so the update has to:

* build the new wheel image in a private staging directory and publish it atomically, so a failure leaves no partial
  image and never touches an environment install record;
* leave the linked environment and its shared image untouched, with the target's old launcher still runnable;
* make the updated environment provably run the new version once the update succeeds.

The script builds two tiny local wheels and two environments. The target environment copies its seed files (it owns
them), the other environment symlinks them from the shared image. One update is made to fail before its install record
is written, then the update is retried successfully. Real interpreter imports, launcher destinations and file listings
are compared at every step. Run it with the repository environment::

    python tasks/demo_seed_update_isolation.py
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Final
from unittest.mock import patch

from virtualenv.app_data import AppDataDiskFolder
from virtualenv.run import cli_run
from virtualenv.seed.embed.via_app_data.pip_install.copy import CopyPipInstall
from virtualenv.seed.embed.via_app_data.pip_install.symlink import SymlinkPipInstall

_DIST: Final[str] = "seedemo"
_LAUNCHER: Final[str] = "seedemo"
_OLD: Final[str] = "1.0"
_NEW: Final[str] = "2.0"


def _make_wheel(folder: Path, version: str) -> Path:
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


def _env(root: Path, cache: Path, name: str):
    return cli_run(
        [str(root / name), "--no-seed", "--app-data", str(cache), "--activators=", "--no-periodic-update"],
        setup_logging=False,
    )


def _image(session, app_data, installer, wheel: Path) -> Path:
    return app_data.wheel_image(session.interpreter.version_release_str, Path(installer.__name__) / wheel.stem)


def _install(session, app_data, installer, wheel: Path) -> None:
    image: Final[Path] = _image(session, app_data, installer, wheel)
    seeder = installer(wheel, session.creator, image)
    seeder.build_image()  # extract into staging, then atomically publish the image
    seeder.install(session.interpreter.version_info)  # only now is the environment install record written


def _version(session) -> str:
    return subprocess.check_output(
        [str(session.creator.exe), "-c", f"import {_DIST}; print({_DIST}.__version__)"], text=True
    ).strip()


def _launcher(session) -> tuple[int, str]:
    result = subprocess.run([str(session.creator.script(_LAUNCHER))], capture_output=True, text=True, check=False)
    return result.returncode, result.stdout.strip()


def _package(session) -> Path:
    return session.creator.purelib / _DIST


def _dist_info(session) -> str:
    return next(session.creator.purelib.glob(f"{_DIST}-*.dist-info")).name


def _listing(session) -> list[str]:
    return sorted(
        f"{entry.name}{' -> ' + str(entry.readlink()) if entry.is_symlink() else ''}"
        for entry in session.creator.purelib.iterdir()
        if entry.name.startswith(_DIST)
    )


def _report(title: str) -> None:
    print(f"\n=== {title} ===")


def main(keep: bool) -> int:
    work: Final[Path] = Path(tempfile.mkdtemp(prefix="seed-update-isolation-"))
    try:
        cache: Final[Path] = work / "app-data"
        app_data: Final[AppDataDiskFolder] = AppDataDiskFolder(str(cache))
        old_wheel: Final[Path] = _make_wheel(work / "wheels", _OLD)
        new_wheel: Final[Path] = _make_wheel(work / "wheels", _NEW)
        target = _env(work, cache, "target-env")  # updated by the build service, copies its files
        other = _env(work, cache, "other-env")  # untouched, links the shared image

        _install(target, app_data, CopyPipInstall, old_wheel)
        _install(other, app_data, SymlinkPipInstall, old_wheel)
        shared_old_image: Final[Path] = (_package(other) / "__init__.py").resolve()

        _report("initial state, both environments on the old wheel")
        print(f"target import={_version(target)} package_is_symlink={_package(target).is_symlink()}")
        print(f"other  import={_version(other)} package_is_symlink={_package(other).is_symlink()}")
        print(f"other  shared image={shared_old_image}")
        print("target site-packages:", _listing(target))
        print("other  site-packages:", _listing(other))

        _report("failed update: build the new image, then fail before the install record is written")
        new_image: Final[Path] = _image(target, app_data, CopyPipInstall, new_wheel)
        staging: Final[Path] = new_image.parent.with_name(f"{new_image.parent.name}-{new_image.name}")

        def _fail(self, zip_ref, folder) -> None:  # noqa: ANN001 - signature mirrors the patched method
            raise RuntimeError("injected failure before the new install record")

        with patch.object(CopyPipInstall, "_populate_image", autospec=True, side_effect=_fail):
            try:
                CopyPipInstall(new_wheel, target.creator, new_image).build_image()
            except RuntimeError as error:
                print(f"update failed as expected: {error}")
        print(f"partial image present={new_image.exists()} staging left behind={staging.exists()}")
        print(f"target import={_version(target)} dist_info={_dist_info(target)} launcher={_launcher(target)}")
        print(f"other  import={_version(other)} dist_info={_dist_info(other)}")
        print(f"other  shared image unchanged={(_package(other) / '__init__.py').resolve() == shared_old_image}")

        _report("successful retry: update only the target environment to the new wheel")
        _install(target, app_data, CopyPipInstall, new_wheel)
        print(f"target import={_version(target)} dist_info={_dist_info(target)} launcher={_launcher(target)}")
        print(f"other  import={_version(other)} dist_info={_dist_info(other)} launcher={_launcher(other)}")
        print(f"target package_is_symlink={_package(target).is_symlink()} (still owns copied files)")
        print(f"other  package_is_symlink={_package(other).is_symlink()} (still links the shared image)")
        print(f"other  still on old shared image={(_package(other) / '__init__.py').resolve() == shared_old_image}")
        print("target site-packages:", _listing(target))
        print("other  site-packages:", _listing(other))

        ok = (
            _version(target) == _NEW
            and _version(other) == _OLD
            and _launcher(target) == (0, _NEW)
            and _launcher(other) == (0, _OLD)
            and new_image.exists()  # the successful retry published the new image
            and (_package(other) / "__init__.py").resolve() == shared_old_image
        )
        print(f"\nresult: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        if keep:
            print(f"workspace kept for inspection at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace for inspection")
    return parser.parse_args()


if __name__ == "__main__":
    keep = _parse_args().keep
    raise SystemExit(main(keep))
