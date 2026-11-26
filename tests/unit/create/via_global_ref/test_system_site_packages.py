from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from virtualenv.create.via_global_ref import system_site_packages

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

GATE = Path(system_site_packages.__file__).parent / f"{system_site_packages.GATE_MODULE}.py"


def _write_module(directory: Path, name: str, value: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.py").write_text(f"VALUE = {value!r}\n", encoding="utf-8")


@pytest.fixture
def two_sites(tmp_path: Path) -> tuple[Path, Path]:
    organization = tmp_path / "organization"
    private = tmp_path / "private"
    _write_module(organization, "acme_core", "org")
    _write_module(organization, "shared_tool", "org")
    _write_module(private, "secret_db", "private")
    _write_module(private, "shared_tool", "private")
    return organization, private


def _write_scope(purelib: Path, allowed: tuple[str, ...], roots: tuple[Path, ...]) -> None:
    purelib.mkdir(parents=True, exist_ok=True)
    system_site_packages.write_scope(purelib, GATE.read_text(encoding="utf-8"), allowed, roots)


def _import(purelib: Path, modules: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    code = "; ".join(f"import {module}" for module in modules)
    printed = ", ".join(f"{module}.VALUE" for module in modules)
    return subprocess.run(
        [sys.executable, "-S", "-c", f"import site; site.addsitedir({str(purelib)!r}); {code}; print({printed})"],
        env={"PATH": ""},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_the_gate_resource_matches_the_module_name_it_is_written_as() -> None:
    module = Path(system_site_packages.__file__)
    assert (GATE.name, GATE.stem, GATE.parent) == (
        f"{system_site_packages.GATE_MODULE}.py",
        system_site_packages.GATE_MODULE,
        module.parent,
    )


def test_approve_sorts_and_deduplicates() -> None:
    assert system_site_packages.approve([" shared_tool ", "acme_core", "acme_core"]) == ("acme_core", "shared_tool")


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("acme.core", id="dotted"),
        pytest.param("acme/core", id="separator"),
        pytest.param("", id="empty"),
        pytest.param(" acme core ", id="space"),
        pytest.param("1acme", id="leading-digit"),
    ],
)
def test_approve_rejects_names_that_are_not_top_level_imports(raw: str) -> None:
    with pytest.raises(ValueError, match="is not a top-level import name"):
        system_site_packages.approve([raw])


def test_check_directories_resolves_and_deduplicates(tmp_path: Path) -> None:
    first = tmp_path / "first"
    first.mkdir()
    assert system_site_packages.check_directories([first, first, first / "."]) == (first.resolve(),)


def test_check_directories_rejects_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist or is not a directory"):
        system_site_packages.check_directories([tmp_path / "missing"])


def test_manifest_records_the_scope(tmp_path: Path) -> None:
    text = system_site_packages.manifest_text(["b", "a"], [tmp_path / "one"])
    assert json.loads(text) == {
        "version": system_site_packages.MANIFEST_VERSION,
        "allowed": ["a", "b"],
        "roots": [str(tmp_path / "one")],
    }


def test_parent_directories_follows_the_interpreter_sites_and_their_pth_directories(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    purelib = tmp_path / "purelib"
    purelib.mkdir()
    added = tmp_path / "added"
    added.mkdir()
    (purelib / "local.pth").write_text(f"# a comment\n{added}\nimport ignored\n", encoding="utf-8")
    interpreter = mocker.MagicMock()
    interpreter.prefix = interpreter.exec_prefix = interpreter.base_prefix = str(tmp_path)
    interpreter.base_exec_prefix = interpreter.system_prefix = interpreter.system_exec_prefix = str(tmp_path)
    interpreter.sysconfig_path.side_effect = lambda key, config_var: str(purelib) if key == "purelib" else ""
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    assert system_site_packages.parent_directories(interpreter, [explicit]) == (purelib, added, explicit)


def test_is_within_compares_resolved_paths(tmp_path: Path) -> None:
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    assert system_site_packages.is_within(child, root) is True
    assert system_site_packages.is_within(tmp_path, root) is False


def test_a_new_process_imports_the_approved_names(tmp_path: Path, two_sites: tuple[Path, Path]) -> None:
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    _write_scope(purelib, ("acme_core", "shared_tool"), two_sites)
    result = _import(purelib, ("acme_core", "shared_tool"))
    assert (result.returncode, result.stdout.strip()) == (0, "org org")


def test_a_new_process_rejects_a_name_only_a_parent_site_provides(
    tmp_path: Path, two_sites: tuple[Path, Path]
) -> None:
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    _write_scope(purelib, ("acme_core",), two_sites)
    result = _import(purelib, ("secret_db",))
    assert (result.returncode, "not in the approved inheritance scope" in result.stderr) == (1, True)


def test_a_new_process_leaves_the_standard_library_alone(tmp_path: Path) -> None:
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    _write_scope(purelib, ("acme_core",), ())
    code = f"import site; site.addsitedir({str(purelib)!r}); import json, pathlib; print('ok')"
    result = subprocess.run(
        [sys.executable, "-S", "-c", code],
        env={"PATH": ""},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert (result.returncode, result.stdout.strip()) == (0, "ok")


def test_an_approved_name_resolves_when_it_appears_after_writing_the_scope(
    tmp_path: Path, two_sites: tuple[Path, Path]
) -> None:
    organization, private = two_sites
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    _write_scope(purelib, ("added_later",), (organization, private))
    assert _import(purelib, ("added_later",)).returncode == 1
    _write_module(organization, "added_later", "late")

    result = _import(purelib, ("added_later",))
    assert (result.returncode, result.stdout.strip()) == (0, "late")


def test_the_first_parent_site_wins_for_an_approved_name(tmp_path: Path, two_sites: tuple[Path, Path]) -> None:
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    organization, private = two_sites
    _write_scope(purelib, ("shared_tool",), (organization, private))
    result = _import(purelib, ("shared_tool",))
    assert (result.returncode, result.stdout.strip()) == (0, "org")


def test_restrict_path_drops_the_parent_sites_from_an_active_process(
    tmp_path: Path, two_sites: tuple[Path, Path]
) -> None:
    purelib = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    organization, private = two_sites
    _write_scope(purelib, ("acme_core",), (organization, private))
    code = (
        "import sys;"
        f"sys.path[:0] = [{str(organization)!r}, {str(private)!r}];"
        f"sys.path.append({str(purelib)!r});"
        "import _virtualenv_system_site_packages;"
        f"print([p for p in sys.path if p in ({str(organization)!r}, {str(private)!r})]);"
        "import acme_core, secret_db"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], env={"PATH": ""}, capture_output=True, text=True, encoding="utf-8", check=False
    )
    assert (result.returncode, result.stdout.strip()) == (1, "[]")
    assert "not in the approved inheritance scope" in result.stderr
