# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""
The cache object API for implementing caches. The default is a thread
safe in-memory dictionary.
"""

from __future__ import annotations

from threading import Lock
from typing import IO, TYPE_CHECKING, MutableMapping

if TYPE_CHECKING:
    from datetime import datetime


class BaseCache:
    def get(self, key: str) -> bytes | None:
        raise NotImplementedError()

    def set(
        self, key: str, value: bytes, expires: int | datetime | None = None
    ) -> None:
        raise NotImplementedError()

    def delete(self, key: str) -> None:
        raise NotImplementedError()

    def close(self) -> None:
        pass


class DictCache(BaseCache):
    def __init__(self, init_dict: MutableMapping[str, bytes] | None = None) -> None:
        self.lock = Lock()
        self.data = init_dict or {}

    def get(self, key: str) -> bytes | None:
        return self.data.get(key, None)

    def set(
        self, key: str, value: bytes, expires: int | datetime | None = None
    ) -> None:
        with self.lock:
            self.data.update({key: value})

    def delete(self, key: str) -> None:
        with self.lock:
            if key in self.data:
                self.data.pop(key)


class SeparateBodyBaseCache(BaseCache):
    """
    In this variant, the body is not stored mixed in with the metadata, but is
    passed in (as a bytes-like object) in a separate call to ``set_body()``.

    That is, the expected interaction pattern is::

        cache.set(key, serialized_metadata)
        cache.set_body(key)

    Similarly, the body should be loaded separately via ``get_body()``.

    Implementations are encouraged to override :meth:`commit` so that a body
    and its metadata become visible as a single, indivisible version: a
    reader must never observe the metadata of one version alongside the body
    of another.
    """

    def set_body(self, key: str, body: bytes) -> None:
        raise NotImplementedError()

    def get_body(self, key: str) -> IO[bytes] | None:
        """
        Return the body as file-like object.
        """
        raise NotImplementedError()

    def get_with_body(
        self, key: str
    ) -> tuple[bytes, IO[bytes]] | tuple[None, None]:
        """Return ``(metadata, body_file)`` belonging to a single version.

        A plain sequence of :meth:`get` followed by :meth:`get_body` can be
        interleaved with a concurrent replacement, pairing the metadata of one
        version with the body of another. Implementations that can replace a
        body and its metadata atomically should override this method to
        snapshot the two together. The default implementation preserves the
        historical two-call behaviour for backends that cannot do better
        (e.g. an in-memory dictionary where the body and metadata are one
        value).
        """
        metadata = self.get(key)
        if metadata is None:
            return None, None
        return metadata, self.get_body(key)

    def commit(
        self,
        key: str,
        metadata: bytes,
        body: bytes,
        expires: int | datetime | None = None,
    ) -> None:
        """Store ``metadata`` and ``body`` as one atomic, consistent version.

        After this call returns, any subsequent :meth:`get` /
        :meth:`get_body` pair must return the metadata and body of the same
        version. The default implementation preserves the historical
        ``set()`` then ``set_body()`` ordering; storage backends that can
        guarantee stronger atomicity should override it.
        """
        self.set(key, metadata, expires=expires)
        self.set_body(key, body)
