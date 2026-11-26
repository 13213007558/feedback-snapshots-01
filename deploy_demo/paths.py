"""Path and RECORD-prefix helpers shared by plan/destinations/verifier."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def safe_resolve(root: str | os.PathLike[str], path: str) -> Path:
    """Join ``path`` under ``root`` and refuse path traversal / absolute paths.

    Mirrors the containment check used by
    :meth:`installer.destinations.SchemeDictionaryDestination._path_with_destdir`.
    """
    target_dir = Path(os.path.abspath(os.fspath(root)))  # noqa: PTH100
    landed = Path(os.path.abspath(target_dir / path))  # noqa: PTH100
    if not landed.is_relative_to(target_dir):
        raise ValueError(f"Attempting to write {path!r} outside of {target_dir!s}")
    return landed


def record_prefix_for_scheme(
    scheme: str,
    *,
    root_scheme: str,
    scheme_dict: Mapping[str, str | os.PathLike[str]],
) -> str | None:
    """RECORD row prefix, identical in shape to the stock FS destination."""
    if scheme == root_scheme:
        return None
    root = os.path.abspath(os.fspath(scheme_dict[root_scheme]))  # noqa: PTH100
    other = os.path.abspath(os.fspath(scheme_dict[scheme]))  # noqa: PTH100
    return os.path.relpath(other, start=root) + "/"
