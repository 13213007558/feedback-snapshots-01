"""Build and record the approved system site-packages inheritance scope of an environment.

With ``--system-site-packages`` the environment sees every package of the parent interpreter. This module implements
the narrower mode selected by ``--system-site-packages-allow``: only the named top-level packages resolve from the
parent site directories, and every other name a parent site provides stays hidden.

The scope is written into the environment so it can be audited and enforced at runtime:

- ``pyvenv.cfg`` records ``system-site-packages-scope`` and ``system-site-packages-allow``, and keeps
  ``include-system-site-packages`` at ``false`` so the interpreter never adds the parent directories to ``sys.path``.
- ``_virtualenv_system_site_packages.json`` in the environment's ``purelib`` lists the approved names and the parent
  site directories they resolve from.
- ``_virtualenv_system_site_packages.py`` and ``_virtualenv_system_site_packages.pth`` install the import gate at
  startup and during ``activate_this.py`` activation.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from virtualenv.util.path import remove_file, write_file

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from python_discovery import PythonInfo

#: Name of the runtime gate module written into the environment.
GATE_MODULE: Final[str] = "_virtualenv_system_site_packages"
#: Name of the manifest that lists the approved names and the parent site directories.
MANIFEST: Final[str] = f"{GATE_MODULE}.json"
#: Name of the path configuration file that imports the gate at startup.
PATH_FILE: Final[str] = f"{GATE_MODULE}.pth"
#: Value of the ``system-site-packages-scope`` key in ``pyvenv.cfg``.
SCOPE_MARKER: Final[str] = "allow-list"
#: Name of the ``pyvenv.cfg`` key that marks a scoped environment.
CFG_SCOPE_KEY: Final[str] = "system-site-packages-scope"
#: Name of the ``pyvenv.cfg`` key that records the approved names.
CFG_ALLOW_KEY: Final[str] = "system-site-packages-allow"
#: The manifest format version the runtime gate understands.
MANIFEST_VERSION: Final[int] = 1

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)  # simplint: ignore[module-variable-prefix]  # existing name
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[^\W\d]\w*", re.UNICODE)


def approve(names: Sequence[str]) -> tuple[str, ...]:
    """Validate the approved names and return them sorted and without duplicates.

    :param names: the raw top-level import names

    :returns: the approved names, sorted and unique

    :raises ValueError: when a name is not a top-level import name

    """
    approved = set()
    for raw in names:
        name = str(raw).strip()
        if not name or not _IDENTIFIER.fullmatch(name):
            msg = (
                f"system site package name {raw!r} is not a top-level import name; pass names such as "
                "'acme' or 'acme_core', without dots or path separators"
            )
            raise ValueError(msg)
        approved.add(name)
    return tuple(sorted(approved))


def check_directories(directories: Iterable[Path]) -> tuple[Path, ...]:
    """Validate the explicitly named parent site directories and return them resolved.

    :param directories: the directories passed by the caller

    :returns: the resolved directories, unique and in the given order

    :raises ValueError: when a directory does not exist or is not a directory

    """
    result: list[Path] = []
    for directory in directories:
        path = Path(directory)
        if not path.is_dir():
            msg = f"system site packages directory {str(path)!r} does not exist or is not a directory"
            raise ValueError(msg)
        resolved = path.resolve()
        if resolved not in result:
            result.append(resolved)
    return tuple(result)


def _site_directories(interpreter: PythonInfo) -> list[Path]:
    prefixes = []
    for prefix in (
        interpreter.prefix,
        interpreter.exec_prefix,
        interpreter.base_prefix,
        interpreter.base_exec_prefix,
        interpreter.system_prefix,
        interpreter.system_exec_prefix,
    ):
        if prefix and prefix not in prefixes:
            prefixes.append(prefix)
    result: list[Path] = []
    for prefix in prefixes:
        config_vars = {
            "base": prefix,
            "platbase": prefix,
            "installed_base": prefix,
            "installed_platbase": prefix,
        }
        for key in ("purelib", "platlib"):
            value = interpreter.sysconfig_path(key, config_var=config_vars)
            if value:
                path = Path(value)
                if path.is_dir():
                    resolved = path.resolve()
                    if resolved not in result:
                        result.append(resolved)
    return result


def _pth_directories(site_dir: Path) -> list[Path]:
    result: list[Path] = []
    try:
        entries = sorted(site_dir.glob("*.pth"))
    except OSError:  # an unreadable parent site directory contributes nothing
        return result
    for entry in entries:
        try:
            text = entry.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):  # unreadable or undecodable, as site.py would also skip it
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(("import ", "import\t")):
                continue
            path = Path(line)
            if not path.is_absolute():
                path = site_dir / path
            if path.is_dir():
                resolved = path.resolve()
                if resolved not in result:
                    result.append(resolved)
    return result


def parent_directories(interpreter: PythonInfo, explicit: Iterable[Path] = ()) -> tuple[Path, ...]:
    """Return the parent site directories the scope may resolve from, in resolution order.

    The interpreter's own site directories come first, the directories their ``.pth`` files add next, and the
    explicitly named directories last. Only existing directories are included.

    :param interpreter: the parent interpreter the environment is created from
    :param explicit: directories passed with ``--system-site-packages-dir``

    :returns: the parent site directories, in resolution order

    """
    result: list[Path] = []
    for site_dir in _site_directories(interpreter):
        if site_dir not in result:
            result.append(site_dir)
        for added in _pth_directories(site_dir):
            if added not in result:
                result.append(added)
    for explicit_dir in explicit:
        resolved = Path(explicit_dir).resolve()
        if resolved not in result:
            result.append(resolved)
    return tuple(result)


def is_within(path: Path, root: Path) -> bool:
    """Whether ``path`` is ``root`` or lies below it, comparing resolved paths.

    :param path: the path to check
    :param root: the directory to compare against

    :returns: ``True`` when the path lies within the root

    """
    return path == root or root in path.parents


def manifest_text(allowed: Iterable[str], roots: Iterable[Path]) -> str:
    """Render the scope manifest written beside the runtime gate.

    The same directories are the ones approved names resolve from and the ones the gate keeps off ``sys.path``.

    :param allowed: the approved top-level import names
    :param roots: the parent site directories of the scope

    :returns: the manifest text, sorted and with stable formatting

    """
    data = {
        "version": MANIFEST_VERSION,
        "allowed": sorted(str(i) for i in allowed),
        "roots": [str(i) for i in roots],
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def write_scope(purelib: Path, gate_text: str, allowed: Iterable[str], roots: Iterable[Path]) -> None:
    """Write the runtime gate, the manifest and the path file into the environment's ``purelib``.

    :param purelib: the pure Python library directory of the environment
    :param gate_text: the source text of the runtime gate module
    :param allowed: the approved top-level import names
    :param roots: the parent site directories the approved names resolve from

    """
    roots = tuple(roots)
    write_file(purelib / f"{GATE_MODULE}.py", gate_text.encode("utf-8"))
    write_file(purelib / MANIFEST, manifest_text(allowed, roots).encode("utf-8"))
    write_file(purelib / PATH_FILE, f"import {GATE_MODULE}\n".encode())


def remove_scope(purelib: Path) -> None:
    """Remove a scope left in place by an earlier creation of the same destination.

    Recreating a destination without the scope must not keep enforcing the old approved set, because the artifacts
    live in site-packages, which a non-clear creation reuses.

    :param purelib: the pure Python library directory of the environment

    """
    for name in (f"{GATE_MODULE}.py", MANIFEST, PATH_FILE):
        path = purelib / name
        if path.is_symlink() or path.is_file():
            LOGGER.debug("remove stale system site packages scope file %s", path)
            remove_file(path)


__all__ = [
    "CFG_ALLOW_KEY",
    "CFG_SCOPE_KEY",
    "GATE_MODULE",
    "MANIFEST",
    "MANIFEST_VERSION",
    "PATH_FILE",
    "SCOPE_MARKER",
    "approve",
    "check_directories",
    "is_within",
    "manifest_text",
    "parent_directories",
    "remove_scope",
    "write_scope",
]
