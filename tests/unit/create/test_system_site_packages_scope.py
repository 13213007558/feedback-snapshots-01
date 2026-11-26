"""End-to-end checks of the approved system site-packages scope, driven through the public creation API."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from virtualenv.create.via_global_ref import system_site_packages
from virtualenv.info import IS_WIN, fs_supports_symlink
from virtualenv.run import cli_run

if TYPE_CHECKING:
    from collections.abc import Iterator

    from virtualenv.run.session import Session

pytestmark = pytest.mark.usefixtures("session_app_data")


def _build_synthetic_parent(root: Path) -> tuple[Path, Path, Path]:
    """Lay out a parent interpreter with an organization site and a private site added through a ``.pth`` file."""
    prefix = root / "parent"
    (prefix / "bin").mkdir(parents=True)
    stdlib_target = Path(sysconfig.get_path("stdlib"))
    stdlib = prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    stdlib.mkdir(parents=True)
    for entry in stdlib_target.iterdir():
        if entry.name == "site-packages":
            continue
        (stdlib / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    name = f"python{sys.version_info.major}.{sys.version_info.minor}{'.exe' if IS_WIN else ''}"
    exe = prefix / "bin" / name
    exe.write_bytes(Path(sys.executable).read_bytes())
    exe.chmod(0o755)
    libdir, soname = sysconfig.get_config_var("LIBDIR"), sysconfig.get_config_var("INSTSONAME")
    library = Path(libdir) / soname if libdir and soname else None
    if library is not None and library.is_file():
        (prefix / "lib" / library.name).symlink_to(library)
    purelib = stdlib / "site-packages"
    purelib.mkdir()
    organization = prefix / "sites" / "organization"
    private = prefix / "sites" / "private"
    (purelib / "parent.pth").write_text(f"{organization}\n{private}\n", encoding="utf-8")
    return exe, organization, private


def _write_module(directory: Path, name: str, value: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.py").write_text(f"VALUE = {value!r}\n", encoding="utf-8")


@pytest.fixture(scope="module")
def synthetic_parent(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    root = tmp_path_factory.mktemp("synthetic-parent")
    try:
        return _build_synthetic_parent(root)
    except OSError as exception:  # a platform that cannot build the layout skips rather than fails
        pytest.skip(f"cannot build a synthetic parent interpreter: {exception}")


@pytest.fixture
def parent_with_modules(synthetic_parent: tuple[Path, Path, Path]) -> Iterator[tuple[Path, Path, Path]]:
    exe, organization, private = synthetic_parent
    _write_module(organization, "acme_core", "organization")
    _write_module(organization, "shared_tool", "organization")
    _write_module(private, "secret_db", "private")
    _write_module(private, "shared_tool", "private")
    yield exe, organization, private


def _run(env: Session, modules: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    code = "; ".join(f"import {module}" for module in modules)
    values = ", ".join(f"{module}.VALUE" for module in modules)
    return subprocess.run(
        [str(env.creator.exe), "-c", f"{code}; print({values})"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_scoped_new_process_sees_the_approved_names(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "acme_core",
        "shared_tool",
        f"--python={exe}",
    ])
    result = _run(session, ("acme_core", "shared_tool"))
    assert (result.returncode, result.stdout.strip()) == (0, "organization organization")
    blocked = _run(session, ("secret_db",))
    assert (blocked.returncode, "not in the approved inheritance scope" in blocked.stderr) == (1, True)


def test_scoped_new_process_lists_the_scope_in_pyvenv_cfg(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "acme_core",
        f"--python={exe}",
    ])
    cfg = session.creator.pyenv_cfg.content
    assert (
        cfg["include-system-site-packages"],
        cfg["system-site-packages-scope"],
        cfg["system-site-packages-allow"],
    ) == ("false", system_site_packages.SCOPE_MARKER, "acme_core")
    manifest = json.loads((session.creator.purelib / system_site_packages.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["allowed"] == ["acme_core"]
    assert [Path(i) for i in manifest["roots"]] == [
        Path(session.creator.interpreter.sysconfig_path("purelib")),
        organization.resolve(),
        private.resolve(),
    ]


def test_a_module_added_to_an_approved_site_after_creation_becomes_importable(
    tmp_path: Path, parent_with_modules
) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "acme_core",
        "added_later",
        f"--python={exe}",
    ])
    assert _run(session, ("added_later",)).returncode == 1
    _write_module(organization, "added_later", "late")
    result = _run(session, ("added_later",))
    assert (result.returncode, result.stdout.strip()) == (0, "late")


def test_a_name_added_to_a_hidden_site_after_creation_stays_hidden(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "acme_core",
        f"--python={exe}",
    ])
    _write_module(private, "late_private", "private")
    blocked = _run(session, ("late_private",))
    assert (blocked.returncode, "not in the approved inheritance scope" in blocked.stderr) == (1, True)


def test_in_process_activation_applies_the_same_scope(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "acme_core",
        f"--python={exe}",
    ])
    script = session.creator.bin_dir / "activate_this.py"
    code = (
        "import runpy, sys;"
        f"sys.path[:0] = [{str(organization)!r}, {str(private)!r}];"
        f"runpy.run_path({str(script)!r});"
        f"print([p for p in sys.path if p in ({str(organization)!r}, {str(private)!r})]);"
        "import acme_core, secret_db"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", check=False
    )
    assert (result.returncode, result.stdout.strip()) == (1, "[]")
    assert "not in the approved inheritance scope" in result.stderr


def test_full_system_site_packages_still_exposes_everything(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages",
        f"--python={exe}",
    ])
    result = _run(session, ("acme_core", "secret_db"))
    assert (result.returncode, result.stdout.strip()) == (0, "organization private")


def test_isolation_stays_the_default(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([str(tmp_path / "env"), "--no-seed", "--no-download", f"--python={exe}"])
    result = _run(session, ("acme_core",))
    assert (result.returncode, "No module named 'acme_core'" in result.stderr) == (1, True)


def test_the_scope_can_come_from_an_environment_variable(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    env = {**os.environ, "VIRTUALENV_SYSTEM_SITE_PACKAGES_ALLOW": "acme_core,shared_tool"}
    session: Final[Session] = cli_run(
        [str(tmp_path / "env"), "--no-seed", "--no-download", f"--python={exe}"], env=env
    )
    assert session.creator.pyenv_cfg["system-site-packages-allow"] == "acme_core shared_tool"
    result = _run(session, ("acme_core", "shared_tool"))
    assert (result.returncode, result.stdout.strip()) == (0, "organization organization")


def test_the_scope_can_come_from_the_configuration_file(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    config = tmp_path / "virtualenv.ini"
    config.write_text("[virtualenv]\nsystem_site_packages_allow = acme_core, shared_tool\n", encoding="utf-8")
    env = {**os.environ, "VIRTUALENV_CONFIG_FILE": str(config)}
    session: Final[Session] = cli_run(
        [str(tmp_path / "env"), "--no-seed", "--no-download", f"--python={exe}"], env=env
    )
    assert session.creator.pyenv_cfg["system-site-packages-allow"] == "acme_core shared_tool"
    result = _run(session, ("acme_core", "shared_tool"))
    assert (result.returncode, result.stdout.strip()) == (0, "organization organization")


def test_full_access_records_no_scope(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages",
        f"--python={exe}",
    ])
    cfg = session.creator.pyenv_cfg.content
    assert (cfg["include-system-site-packages"], system_site_packages.CFG_SCOPE_KEY in cfg) == ("true", False)
    assert list(session.creator.purelib.glob("_virtualenv_system_site_packages*")) == []


def test_recreating_without_the_scope_drops_the_stale_gate(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    dest = str(tmp_path / "env")
    cli_run([dest, "--no-seed", "--no-download", "--system-site-packages-allow", "acme_core", f"--python={exe}"])
    session: Final[Session] = cli_run([dest, "--no-seed", "--no-download", f"--python={exe}"])
    assert [path.name for path in session.creator.purelib.glob("_virtualenv_system_site_packages*")] == []
    blocked = _run(session, ("acme_core",))
    assert (blocked.returncode, "No module named 'acme_core'" in blocked.stderr) == (1, True)


@pytest.mark.parametrize(
    ("builder", "message"),
    [
        pytest.param(
            lambda exe: ["--system-site-packages", "--system-site-packages-allow", "acme_core"],
            "exclude each other",
            id="both",
        ),
        pytest.param(
            lambda exe: ["--system-site-packages-dir", str(Path(exe).parent.parent)],
            "needs --system-site-packages-allow",
            id="dir-without-approval",
        ),
        pytest.param(
            lambda exe: ["--system-site-packages-allow", "acme.core"],
            "is not a top-level import name",
            id="dotted",
        ),
        pytest.param(
            lambda exe: ["--system-site-packages-allow", "acme_core", "--system-site-packages-dir", "/missing"],
            "does not exist or is not a directory",
            id="missing-directory",
        ),
    ],
)
def test_invalid_scope_options_are_rejected(tmp_path: Path, parent_with_modules, builder, message: str) -> None:
    exe, organization, private = parent_with_modules
    with pytest.raises(ValueError, match=message):
        cli_run([
            str(tmp_path / "env"),
            "--no-seed",
            "--no-download",
            *builder(exe),
            f"--python={exe}",
        ])


@pytest.mark.skipif(not fs_supports_symlink(), reason="symlinks are unavailable")
def test_explicit_site_directory_is_part_of_the_scope(tmp_path: Path, parent_with_modules) -> None:
    exe, organization, private = parent_with_modules
    extra = tmp_path / "extra-site"
    _write_module(extra, "extra_pkg", "extra")
    session: Final[Session] = cli_run([
        str(tmp_path / "env"),
        "--no-seed",
        "--no-download",
        "--system-site-packages-allow",
        "extra_pkg",
        "--system-site-packages-dir",
        str(extra),
        f"--python={exe}",
    ])
    result = _run(session, ("extra_pkg",))
    assert (result.returncode, result.stdout.strip()) == (0, "extra")
    blocked = _run(session, ("acme_core",))
    assert (blocked.returncode, "not in the approved inheritance scope" in blocked.stderr) == (1, True)
