"""Restrict the system site-packages an environment inherits to the approved top-level import names.

virtualenv writes a copy of this module into the environment's ``site-packages`` folder, together with the manifest
naming the approved names and the parent site directories they may come from. A ``.pth`` file imports it at startup,
and ``activate_this.py`` imports it when a process activates the environment later, so both routes see the same set.

The parent site directories are never added to ``sys.path``. An approved top-level name is resolved from them on
demand, and a name available only from them but not approved fails to import. ``restrict_path`` drops them from
``sys.path`` when they are already there, which is the case for an in-process activation.
"""

from __future__ import annotations

import importlib.machinery
import json
import os
import sys

#: Name of the manifest written beside this module.
MANIFEST_NAME = "_virtualenv_system_site_packages.json"
#: The approved names and parent directories, read from the manifest on first use.
_STATE = None


def _norm(path):
    return os.path.normcase(os.path.realpath(path))


def _is_within(path, root):
    path = _norm(path)
    return path == root or path.startswith(root + os.sep)


def _load():
    global _STATE
    if _STATE is None:
        manifest = os.path.join(os.path.dirname(os.path.abspath(__file__)), MANIFEST_NAME)
        with open(manifest, encoding="utf-8") as file:
            data = json.load(file)
        if data.get("version") != 1:
            msg = f"unsupported system site packages manifest version {data.get('version')!r}"
            raise RuntimeError(msg)
        allowed = frozenset(str(i) for i in data["allowed"])
        roots = tuple(str(i) for i in data["roots"])
        _STATE = allowed, roots
    return _STATE


def _search_roots():
    _, roots = _load()
    return [root for root in roots if os.path.isdir(root)]


def _find(fullname):
    return importlib.machinery.PathFinder.find_spec(fullname, _search_roots())


class _RestrictedFinder:
    """Resolve approved top-level names from the parent sites, and reject the others.

    The finder sits at the end of ``sys.meta_path``, so it only runs when nothing else could import the name. That
    keeps it off the path of ordinary imports while still rejecting a name that only a parent site directory provides.
    """

    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        if "." in fullname or fullname in sys.builtin_module_names:
            return None
        allowed, _ = _load()
        if fullname in allowed:
            return _find(fullname)
        if _find(fullname) is None:
            return None
        msg = f"system site package {fullname!r} is not in the approved inheritance scope"
        raise ModuleNotFoundError(msg, name=fullname)


def restrict_path():
    """Drop the parent site directories from ``sys.path``."""
    _, roots = _load()
    hidden = tuple(_norm(root) for root in roots)
    sys.path[:] = [entry for entry in sys.path if not (entry and any(_is_within(entry, i) for i in hidden))]


def install():
    """Remove the parent site directories from ``sys.path`` and install the finder, once per process."""
    restrict_path()
    if _RestrictedFinder not in sys.meta_path:
        sys.meta_path.append(_RestrictedFinder)


install()
