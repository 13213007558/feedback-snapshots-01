"""App data store that layers a read-only shared cache over a writable private staging folder.

Build machines hand every project the same pre-filled cache, mounted read-only. A project may still
be missing one of the seed images the shared cache does not ship. This store keeps serving the shared
content directly (read-only, no lock files, no writes), while every cache miss is materialised inside a
private staging folder the project owns, so nothing is ever created next to, or inside, the shared tree.

Lookups for a path use the shared folder first and fall back to the private one. Allocation, locking and
JSON writes go through the private layer only, which keeps the shared folder byte-for-byte unchanged even
when a seed has to be generated on demand.
"""

from __future__ import annotations

__lazy_modules__ = [
    "os",
    "pathlib",
    "virtualenv.util.lock",
    "virtualenv.util.path",
]

import logging
import os
from contextlib import contextmanager, suppress
from typing import TYPE_CHECKING, Final

from virtualenv.util.lock import ReentrantFileLock
from virtualenv.util.path import ensure_within

from .read_only import ReadOnlyAppData
from .via_disk_folder import AppDataDiskFolder, PyInfoStoreDisk

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)  # simplint: ignore[module-variable-prefix]  # existing name


class LayeredAppData(AppDataDiskFolder):
    """Read from a shared read-only cache first, then a private writable staging folder.

    :param shared_folder: the pre-filled cache, opened read-only and never written to
    :param private_folder: the project-owned staging folder holding cache misses and every lock
    :raises RuntimeError: when the shared folder does not exist

    :var can_update: ``True``, the private layer can be updated while the shared one stays read-only
    :var transient: ``False``, the private staging folder persists across runs
    """

    transient = False
    can_update = True

    def __init__(self, shared_folder: str, private_folder: str) -> None:
        # the read-only view validates that the shared folder exists and never allocates locks in it
        self._shared = ReadOnlyAppData(shared_folder)
        os.makedirs(private_folder, mode=0o700, exist_ok=True)
        super().__init__(private_folder)
        # the root lock lives in the private folder, so acquiring it never touches the shared tree
        self.lock = ReentrantFileLock(private_folder)
        self._private_root = self.lock.path.resolve()
        LOGGER.debug("layered app data: shared=%s read-only, private=%s writable", shared_folder, private_folder)

    @property
    def shared(self) -> ReadOnlyAppData:
        """The read-only view of the pre-filled shared cache."""
        return self._shared

    @property
    def shared_root(self) -> Path:
        """The root folder of the shared read-only cache."""
        return self._shared.lock.path

    def __repr__(self) -> str:
        return f"{type(self).__name__}(shared={self.shared_root}, private={self.lock.path})"

    def _relative(self, path: Path) -> Path:
        """Return the cache-relative part of a path from either layer's root.

        :param path: a path located under the shared or the private root
        :returns: the part of the path below the root
        :raises ValueError: when the path belongs to neither layer
        """
        resolved = path.resolve()
        for root in (self._private_root, self.shared_root.resolve()):
            with suppress(ValueError):
                return resolved.relative_to(root)
        msg = f"path {path} belongs to neither the shared cache nor the private staging folder"
        raise ValueError(msg)

    def _private_path(self, path: Path) -> Path:
        """Map a cache path into the private staging folder, refusing to leave it.

        :param path: the path returned by :meth:`wheel_image` or :meth:`py_info_at`
        :returns: the same location inside the private folder
        :raises ValueError: when the resolved location would escape the private folder
        """
        target = (self._private_root / self._relative(path)).resolve()
        ensure_within(self.lock.path, target)
        return target

    def _first_existing(self, path: Path) -> Path:
        """Return the shared copy of ``path`` when present, otherwise the private location.

        :param path: the cache-relative path to look up
        :returns: the readable shared path on a hit, the private path on a miss
        """
        shared_path = self.shared_root / self._relative(path)
        if shared_path.exists():
            LOGGER.debug("cache hit in shared read-only folder %s", shared_path)
            return shared_path
        LOGGER.debug("cache miss, using private staging %s", path)
        return path

    def wheel_image(self, for_py_version: str, name: str) -> Path:
        """Return a cached wheel image path, preferring the shared read-only cache.

        :param for_py_version: the target Python version string
        :param name: the image name (installer class plus wheel stem)
        :returns: the shared image on a hit, otherwise the private image path to build
        """
        private = super().wheel_image(for_py_version, name)
        return self._first_existing(private)

    def lock_target(self, path: Path) -> Path:
        """Map any cache path (including a shared read-only hit) to its private location for locking.

        Seeders build lock paths from whatever :meth:`wheel_image` returns, which on a shared hit points
        inside the read-only tree. Locks must never be created there, so callers route every lock through
        this method to land in the private staging folder instead.

        :param path: the cache path a seeder wants to lock, shared or private
        :returns: the equivalent location inside the private staging folder
        """
        return self._private_path(path)

    def py_info(self, path: Path) -> PyInfoStoreDisk:
        """Return a python-info store that reads shared entries and writes private ones.

        :param path: the interpreter executable path the info describes
        :returns: a layered content store for the interpreter
        """
        return _LayeredPyInfoStore(self, path)

    def reset(self) -> None:
        """Reset only the private staging folder; the shared cache is never touched."""
        LOGGER.debug("reset private app data folder %s, leaving shared %s", self.lock.path, self.shared_root)
        super().reset()

    @contextmanager
    def locked(self, path: Path) -> Generator[None]:
        """Hold a private-folder lock while the caller uses ``path``, which stays inside the staging area.

        :param path: the cache path to guard
        :yields: nothing; the lock is held for the duration of the context
        """
        target = self._private_path(path)
        with super().locked(target):
            yield

    def close(self) -> None:
        """Close both layers without deleting anything."""
        super().close()
        self._shared.close()


class _LayeredPyInfoStore(PyInfoStoreDisk):
    """Python-info store that serves shared JSON on a hit and stores new entries privately."""

    def __init__(self, app_data: LayeredAppData, path: Path) -> None:
        self._app_data = app_data
        self._shared_store = app_data.shared.py_info(path)
        super().__init__(app_data.py_info_at, path)

    def exists(self) -> bool:
        """Report a hit from either the shared cache or the private staging folder."""
        return self._shared_store.exists() or super().exists()

    def read(self):  # noqa: ANN201 - mirrors the untyped JSON content of the base store
        """Read the shared python info on a hit, otherwise the private copy."""
        if self._shared_store.exists():
            return self._shared_store.read()
        return super().read()

    @contextmanager
    def locked(self) -> Generator[None]:
        """Take the lock only inside the private staging folder.

        :yields: nothing; the private lock is held for the duration of the context
        """
        with self._app_data.locked(self.file):
            yield


__all__ = ["LayeredAppData"]
