"""Creation must build from the interpreter discovery approved, even when its path is replaced afterwards."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from python_discovery import PythonInfo

from virtualenv.create.pyenv_cfg import PyEnvCfg
from virtualenv.create.via_global_ref.builtin.cpython.common import is_mac_os_framework, is_macos_brew
from virtualenv.discovery.selection import InterpreterPin, PinState
from virtualenv.info import IS_GRAALPY, IS_PYPY, IS_WIN, fs_supports_symlink
from virtualenv.run import session_via_cli
from virtualenv.run.plugin.creators import CreatorSelector
from virtualenv.util.error import InterpreterReplacedError

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

    from virtualenv.run.session import Session

_CURRENT: Final[PythonInfo] = PythonInfo.current_system()
_EXE_NAME: Final[str] = Path(_CURRENT.system_exe).name
_CREATORS: Final[tuple[str, ...]] = tuple(
    name for name in ("builtin", "venv") if name in CreatorSelector.for_interpreter(_CURRENT).key_to_class
)

pytestmark = pytest.mark.skipif(
    IS_WIN
    or IS_PYPY
    or IS_GRAALPY
    or not fs_supports_symlink()
    or is_mac_os_framework(_CURRENT)
    or is_macos_brew(_CURRENT),
    reason="requires a POSIX interpreter whose builtin creator links or copies a plain executable",
)


class _Release:
    """A self-contained interpreter stand-in, distinguishable from the others only by its path and a marker."""

    def __init__(self, root: Path, name: str, marker: bytes, source: Path | None = None) -> None:
        self.path = root / name
        self.marker = marker
        executable = self.path / "bin" / _EXE_NAME
        (self.path / "bin").mkdir(parents=True)
        (self.path / "lib").mkdir()
        shutil.copy2(Path(_CURRENT.system_exe) if source is None else source / "bin" / _EXE_NAME, executable)
        with executable.open("ab") as file:
            file.write(b"\n" + marker + b"\n")
        executable.chmod(0o755)
        # the copied interpreter loads its standard library and shared library from beside it, as the original does
        stdlib = Path(_CURRENT.system_stdlib)
        (self.path / "lib" / stdlib.name).symlink_to(stdlib, target_is_directory=True)
        for lib in stdlib.parent.glob("libpython*"):
            (self.path / "lib" / lib.name).symlink_to(lib)

    @property
    def executable(self) -> Path:
        return self.path / "bin" / _EXE_NAME


@pytest.fixture(scope="module")
def releases(tmp_path_factory: pytest.TempPathFactory) -> tuple[_Release, _Release]:
    root = tmp_path_factory.mktemp("interpreter-selection")
    first = _Release(root, "release_first", b"VIRTUALENV_SELECTION_FIRST")
    second = _Release(root, "release_second", b"VIRTUALENV_SELECTION_SECOND")
    try:
        subprocess.check_output([str(first.executable), "-c", "print(1)"])
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover # platform specific interpreter layout
        pytest.skip("cannot build a runnable interpreter stand-in from this interpreter")
    return first, second


@pytest.fixture
def fixed_path(tmp_path: Path, releases: tuple[_Release, _Release]) -> Path:
    """The fixed path operations points at the approved interpreter, then switches to another release."""
    link = tmp_path / "fixed"
    link.symlink_to(releases[0].path, target_is_directory=True)
    return link


def _request(fixed_path: Path, env: Path, creator: str, mode: str, app_data: Path) -> Session:
    return session_via_cli(
        [
            str(env),
            "--creator",
            creator,
            mode,
            "--no-seed",
            "--no-periodic-update",
            "--activators",
            "",
            "--app-data",
            str(app_data),
            "-p",
            str(fixed_path / "bin" / _EXE_NAME),
        ],
        # keep the logging handlers the capture fixture installs, which the report setup would replace
        setup_logging=False,
    )


def _switch(fixed_path: Path, release: _Release) -> None:
    fixed_path.unlink()
    fixed_path.symlink_to(release.path, target_is_directory=True)


def _run(env: Path, code: str) -> str:
    return subprocess.check_output([str(env / "bin" / "python"), "-c", code], text=True, stderr=subprocess.STDOUT)


@pytest.mark.parametrize("creator", _CREATORS)
@pytest.mark.parametrize("mode", ["--symlinks", "--copies"], ids=["keep-reference", "copy"])
def test_switched_path_keeps_the_approved_interpreter(
    fixed_path: Path,
    releases: tuple[_Release, _Release],
    tmp_path: Path,
    creator: str,
    mode: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    approved, replacement = releases
    session = _request(fixed_path, tmp_path / "env", creator, mode, tmp_path / "app-data")
    assert session.creator.pin is not None
    assert session.creator.pin.state() is PinState.CURRENT

    _switch(fixed_path, replacement)
    assert session.creator.pin.state() is PinState.MOVED
    session.run()

    assert f"continuing with the approved interpreter at {approved.executable}" in caplog.text
    cfg = PyEnvCfg.from_file(session.creator.pyenv_cfg.path)
    assert Path(cfg["executable"]) == approved.executable
    # the environment runs the approved release, not the one the fixed path names now
    assert _run(tmp_path / "env", "import pathlib, sys; print(pathlib.Path(sys.base_prefix))").strip() == str(
        approved.path
    )
    interpreter = tmp_path / "env" / "bin" / "python"
    if mode == "--symlinks":
        # retaining the reference keeps pointing at the approved executable
        assert os.path.realpath(interpreter) == str(approved.executable)
    else:
        # the copy is the approved executable's own bytes, not the replacement's
        assert not interpreter.is_symlink()
        assert approved.marker in Path(os.path.realpath(interpreter)).read_bytes()


@pytest.mark.parametrize("creator", _CREATORS)
@pytest.mark.parametrize("mode", ["--symlinks", "--copies"], ids=["keep-reference", "copy"])
def test_unchanged_path_reuses_the_selected_interpreter(
    fixed_path: Path, tmp_path: Path, creator: str, mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    env, app_data, executable = tmp_path / "env", tmp_path / "app-data", fixed_path / "bin" / _EXE_NAME
    _request(fixed_path, env, creator, mode, app_data).run()

    # a second run over the same environment is the normal reuse, with nothing replaced
    session = _request(fixed_path, env, creator, mode, app_data)
    assert session.creator.pin is not None
    assert session.creator.pin.state() is PinState.CURRENT
    session.run()

    assert "was replaced after discovery" not in caplog.text
    assert Path(PyEnvCfg.from_file(session.creator.pyenv_cfg.path)["executable"]) == Path(os.path.realpath(executable))
    assert _run(env, "print(1)").strip() == "1"


@pytest.mark.parametrize("creator", _CREATORS)
def test_missing_approved_interpreter_requires_a_reselection(
    fixed_path: Path, releases: tuple[_Release, _Release], tmp_path: Path, creator: str
) -> None:
    approved, replacement = releases
    # the module fixture keeps the releases for every test, so the rotation this test needs happens on a copy
    rotated = _Release(tmp_path, "rotated_release", approved.marker, source=approved.path)
    _switch(fixed_path, rotated)
    session = _request(fixed_path, tmp_path / "env", creator, "--symlinks", tmp_path / "app-data")
    # operators rotate the whole approved release away and point the fixed path at a different one
    shutil.rmtree(rotated.path)
    _switch(fixed_path, replacement)
    assert session.creator.pin.state() is PinState.LOST

    with pytest.raises(InterpreterReplacedError) as context:
        session.run()

    assert str(rotated.executable) in str(context.value)
    assert str(fixed_path / "bin" / _EXE_NAME) in str(context.value)
    assert "select the interpreter again" in str(context.value)
    assert not (tmp_path / "env" / "pyvenv.cfg").exists()


def test_pin_state_tracks_the_selected_object(tmp_path: Path, mocker: MockerFixture) -> None:
    approved = tmp_path / "approved"
    approved.write_bytes(b"approved")
    selected = tmp_path / "selected"
    selected.symlink_to(approved)
    info = mocker.create_autospec(PythonInfo, instance=True, system_executable=str(selected))

    pin = InterpreterPin.of(info)
    assert pin is not None
    assert (pin.requested, pin.real) == (str(selected), str(approved))
    assert pin.state() is PinState.CURRENT

    selected.unlink()
    selected.symlink_to(tmp_path / "other")
    assert pin.state() is PinState.MOVED

    approved.unlink()
    assert pin.state() is PinState.LOST


def test_pin_of_a_missing_executable_is_absent(tmp_path: Path, mocker: MockerFixture) -> None:
    info = mocker.create_autospec(PythonInfo, instance=True, system_executable=str(tmp_path / "missing"))
    assert InterpreterPin.of(info) is None


def test_pin_of_an_interpreter_without_paths_is_absent(mocker: MockerFixture) -> None:
    info = mocker.create_autospec(PythonInfo, instance=True, system_executable=None, executable=None)
    assert InterpreterPin.of(info) is None
