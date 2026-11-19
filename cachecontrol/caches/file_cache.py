# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from textwrap import dedent
from typing import IO, TYPE_CHECKING
from pathlib import Path

from cachecontrol.cache import BaseCache, SeparateBodyBaseCache
from cachecontrol.controller import CacheController

if TYPE_CHECKING:
    from datetime import datetime

    from filelock import BaseFileLock

# Marker for a metadata envelope that points at a separately stored body.
# The bytes after it are the (relative) file name of the body that belongs to
# this exact metadata version. This indirection is what lets a body and its
# metadata be published as one indivisible version.
_BODY_POINTER_PREFIX = b"cc-body:v1:"
# Suffix of the legacy, fixed-name body file written by older releases.
_LEGACY_BODY_SUFFIX = ".body"


class _FileCacheMixin:
    """Shared implementation for both FileCache variants."""

    def __init__(
        self,
        directory: str | Path,
        forever: bool = False,
        filemode: int = 0o0600,
        dirmode: int = 0o0700,
        lock_class: type[BaseFileLock] | None = None,
    ) -> None:
        try:
            if lock_class is None:
                from filelock import FileLock

                lock_class = FileLock
        except ImportError:
            notice = dedent(
                """
            NOTE: In order to use the FileCache you must have
            filelock installed. You can install it via pip:
              pip install cachecontrol[filecache]
            """
            )
            raise ImportError(notice)

        self.directory = directory
        self.forever = forever
        self.filemode = filemode
        self.dirmode = dirmode
        self.lock_class = lock_class

    @staticmethod
    def encode(x: str) -> str:
        return hashlib.sha224(x.encode()).hexdigest()

    def _fn(self, name: str) -> str:
        # NOTE: This method should not change as some may depend on it.
        #       See: https://github.com/ionrock/cachecontrol/issues/63
        hashed = self.encode(name)
        parts = list(hashed[:5]) + [hashed]
        return os.path.join(self.directory, *parts)

    def get(self, key: str) -> bytes | None:
        name = self._fn(key)
        try:
            with open(name, "rb") as fh:
                return fh.read()

        except FileNotFoundError:
            return None

    def set(
        self, key: str, value: bytes, expires: int | datetime | None = None
    ) -> None:
        name = self._fn(key)
        self._write(name, value)

    def _write(self, path: str, data: bytes) -> None:
        """
        Safely write the data to the given path.
        """
        # Make sure the directory exists
        dirname = os.path.dirname(path)
        os.makedirs(dirname, self.dirmode, exist_ok=True)

        with self.lock_class(path + ".lock"):
            # Write our actual file
            (fd, name) = tempfile.mkstemp(dir=dirname)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            os.chmod(name, self.filemode)
            os.replace(name, path)

    def _delete(self, key: str, suffix: str) -> None:
        name = self._fn(key) + suffix
        if not self.forever:
            try:
                os.remove(name)
            except FileNotFoundError:
                pass


class FileCache(_FileCacheMixin, BaseCache):
    """
    Traditional FileCache: body is stored in memory, so not suitable for large
    downloads.
    """

    def delete(self, key: str) -> None:
        self._delete(key, "")


class SeparateBodyFileCache(_FileCacheMixin, SeparateBodyBaseCache):
    """
    Memory-efficient FileCache: body is stored in a separate file, reducing
    peak memory usage.

    Each cache entry is published as an indivisible version. The body is
    written to a unique, content-addressed file and only referenced once it
    has been fully written and atomically renamed into place; the metadata is
    then atomically replaced with an envelope naming that exact body file.
    As a result a reader can never observe the metadata of one version paired
    with the body of another -- not after an interrupted download and not when
    two processes update the same key concurrently.
    """

    #
    # Metadata envelope helpers
    #
    @staticmethod
    def _pack_pointer(body_name: str) -> bytes:
        return _BODY_POINTER_PREFIX + body_name.encode("utf-8") + b"\n"

    @staticmethod
    def _unpack_pointer(metadata: bytes) -> str | None:
        """Return the body file name recorded in ``metadata``, if any.

        A metadata file stores the pointer, a newline, then the serialized
        response metadata; :meth:`get` passes only the part after the newline.
        """
        if not metadata.startswith(_BODY_POINTER_PREFIX):
            return None
        tail = metadata[len(_BODY_POINTER_PREFIX) :]
        name = tail.split(b"\n", 1)[0].decode("utf-8", "strict")
        return name or None

    def _body_path(self, key: str) -> str | None:
        """Resolve the body file that the current metadata version points at.

        Falls back to the legacy fixed-name ``.body`` file for entries written
        by older releases.
        """
        metadata = super().get(key)
        if metadata is None:
            return None
        body_name = self._unpack_pointer(metadata)
        if body_name is not None:
            return os.path.join(os.path.dirname(self._fn(key)), body_name)
        legacy = self._fn(key) + _LEGACY_BODY_SUFFIX
        return legacy if os.path.exists(legacy) else None

    def get_body(self, key: str) -> IO[bytes] | None:
        path = self._body_path(key)
        if path is None:
            return None
        try:
            return open(path, "rb")
        except FileNotFoundError:
            return None

    def get_with_body(
        self, key: str
    ) -> tuple[bytes, IO[bytes]] | tuple[None, None]:
        """Snapshot one committed version of ``key`` atomically.

        The metadata names an immutable body file. We open that exact file and
        only accept it once the metadata still names it, so a replacement
        landing during the read can never pair one version's metadata with a
        different version's body. If the entry changed (or vanished) mid-read,
        we retry with the newer version.
        """
        for _ in range(100):
            raw_metadata = super().get(key)
            if raw_metadata is None:
                return None, None
            body_name = self._unpack_pointer(raw_metadata)
            if body_name is None:
                # Legacy entry: the fixed-name body is replaced atomically.
                body_path = self._fn(key) + _LEGACY_BODY_SUFFIX
            else:
                body_path = os.path.join(
                    os.path.dirname(self._fn(key)), body_name
                )
            try:
                body_file = open(body_path, "rb")
            except FileNotFoundError:
                # The version we snapshotted was just superseded and its body
                # removed; take the newer version instead.
                continue
            if super().get(key) != raw_metadata:
                body_file.close()
                continue
            return self._strip_envelope(raw_metadata), body_file
        # Extremely unlikely: the key is being rewritten faster than we can
        # read it. Report a miss rather than risk a cross-wired response.
        return None, None

    @staticmethod
    def _strip_envelope(raw_metadata: bytes) -> bytes:
        if SeparateBodyFileCache._unpack_pointer(raw_metadata) is None:
            return raw_metadata
        return raw_metadata.split(b"\n", 1)[1]

    def get(self, key: str) -> bytes | None:
        # Strip the body-pointer envelope so callers keep receiving the raw
        # serialized metadata.
        metadata = super().get(key)
        if metadata is None:
            return None
        return self._strip_envelope(metadata)

    #
    # Writes
    #
    def _write_file(self, path: str, body: bytes) -> None:
        """Write ``body`` to ``path`` atomically.

        The data first lands in a unique temporary file in the same
        directory; it only becomes visible under ``path`` via an atomic
        ``os.replace`` once the whole write has succeeded.
        """
        dirname = os.path.dirname(path)
        os.makedirs(dirname, self.dirmode, exist_ok=True)
        (fd, tmp_name) = tempfile.mkstemp(
            dir=dirname, prefix=".tmp-", suffix=".part"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_name, self.filemode)
            os.replace(tmp_name, path)
        except BaseException:
            # An interrupted download must never leave a body where readers
            # can find it; the unpublished temp file is simply discarded.
            try:
                os.remove(tmp_name)
            except FileNotFoundError:
                pass
            raise

    def set(
        self, key: str, value: bytes, expires: int | datetime | None = None
    ) -> None:
        """Replace only the metadata, keeping the currently committed body.

        This supports header-only refreshes (e.g. a 304 Not Modified): the
        body pointer from the previous version is carried forward so the new
        metadata never ends up without a matching body.
        """
        current = super().get(key)
        body_name = self._unpack_pointer(current) if current is not None else None
        if body_name is None:
            super().set(key, value, expires)
            return
        super().set(key, self._pack_pointer(body_name) + value, expires)

    def set_body(self, key: str, body: bytes) -> None:
        """Write a body without publishing a matching metadata version.

        Retained for backwards compatibility; normal caching goes through
        :meth:`commit`. Uses the legacy fixed-name body file, which is
        atomic on its own (single temp file + rename).
        """
        self._write_file(self._fn(key) + _LEGACY_BODY_SUFFIX, body)

    def commit(
        self,
        key: str,
        metadata: bytes,
        body: bytes,
        expires: int | datetime | None = None,
    ) -> None:
        """Publish ``metadata`` and ``body`` as a single consistent version.

        The body is fully written to a unique, immutable file first and only
        then referenced by the metadata, so a reader can never see the new
        headers together with an old or half-written body.
        """
        shard_dir = os.path.dirname(self._fn(key))
        body_name = f"{self.encode(key)}.{uuid.uuid4().hex}.body"
        body_path = os.path.join(shard_dir, body_name)

        self._write_file(body_path, body)
        try:
            super().set(key, self._pack_pointer(body_name) + metadata, expires)
        except BaseException:
            # The metadata never named this body, so removing it cannot
            # disturb any reader.
            try:
                os.remove(body_path)
            except FileNotFoundError:
                pass
            raise

    def delete(self, key: str) -> None:
        if self.forever:
            # ``forever`` caches never remove entries, including their bodies
            # and the auxiliary lock files.
            return
        # Remove every body that could belong to this key (the current
        # versioned body and the legacy body) along with the metadata.
        body_path = self._body_path(key)
        if body_path is not None:
            try:
                os.remove(body_path)
            except FileNotFoundError:
                pass
        self._delete(key, "")
        self._delete(key, _LEGACY_BODY_SUFFIX)
        for suffix in (".lock", ".body.lock"):
            try:
                os.remove(self._fn(key) + suffix)
            except FileNotFoundError:
                pass

    def gc(self) -> None:
        """Delete versioned body files that no metadata entry references.

        These can accumulate when a process dies after writing a body but
        before (or while) publishing its metadata. Unpublished ``.part``
        temporary files are removed as well. Lock files and legacy
        fixed-name ``.body`` files are left untouched.
        """
        root = os.path.abspath(self.directory)
        if not os.path.isdir(root):
            return

        referenced: set[str] = set()
        stale: list[str] = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                # Unpublished temp files from interrupted downloads are safe
                # to remove straight away. Lock files are left alone because a
                # writer may be actively using them.
                if filename.endswith(".part") or filename.startswith(".tmp-"):
                    stale.append(path)
                    continue
                try:
                    with open(path, "rb") as fh:
                        head = fh.read()
                except OSError:
                    continue
                body_name = self._unpack_pointer(head)
                if body_name is not None:
                    referenced.add(os.path.basename(body_name))

        for path in stale:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                if not self._is_versioned_body(filename):
                    # The legacy fixed-name ``.body`` file and metadata files
                    # are never treated as orphans here.
                    continue
                if filename in referenced:
                    continue
                try:
                    os.remove(os.path.join(dirpath, filename))
                except FileNotFoundError:
                    pass

    @staticmethod
    def _is_versioned_body(filename: str) -> bool:
        """True for the unique ``<hash>.<uuid>.body`` files from :meth:`commit`.

        A versioned body ends in ``.<32 hex chars>.body``; the legacy body is
        simply ``<hash>.body`` (no ``.<uuid>`` segment).
        """
        if not filename.endswith(_LEGACY_BODY_SUFFIX):
            return False
        head = filename[: -len(_LEGACY_BODY_SUFFIX)]
        if "." not in head:
            return False
        middle = head.rsplit(".", 1)[1]
        return len(middle) == 32 and all(
            char in "0123456789abcdef" for char in middle
        )


def url_to_file_path(url: str, filecache: FileCache) -> str:
    """Return the file cache path based on the URL.

    This does not ensure the file exists!
    """
    key = CacheController.cache_url(url)
    return filecache._fn(key)
