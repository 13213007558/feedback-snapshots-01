# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


import threading
from typing import Any, AsyncGenerator, Dict, Optional

from ...helpers.errors import ScrollClosedError, ScrollOwnershipError
from ...helpers.scroll import (
    _page_hits,
    _resolve_owner,
    _same_owner,
    _scroll_id_of,
)


class AsyncScrollEntry:
    """Async counterpart of :class:`opensearchpy.helpers.scroll.ScrollEntry`."""

    __slots__ = ("context_id", "owner", "client", "scroll_id", "scroll", "closed")

    def __init__(
        self,
        context_id: str,
        owner: Any,
        client: Any,
        scroll_id: Optional[str],
        scroll: Any,
    ) -> None:
        self.context_id = context_id
        self.owner = owner
        self.client = client
        self.scroll_id = scroll_id
        self.scroll = scroll
        self.closed = False


class AsyncScrollRegistry:
    """Async counterpart of :class:`opensearchpy.helpers.scroll.ScrollRegistry`."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[str, AsyncScrollEntry] = {}

    def register(
        self,
        context_id: str,
        owner: Any,
        client: Any,
        scroll_id: Optional[str],
        scroll: Any,
    ) -> AsyncScrollEntry:
        with self._lock:
            existing = self._entries.get(context_id)
            if existing is not None and not existing.closed:
                raise ScrollOwnershipError(
                    existing.scroll_id,
                    "Scroll context %r is already active" % context_id,
                    owner=owner,
                )
            entry = AsyncScrollEntry(context_id, owner, client, scroll_id, scroll)
            self._entries[context_id] = entry
            return entry

    def get(self, context_id: str) -> Optional[AsyncScrollEntry]:
        with self._lock:
            return self._entries.get(context_id)

    def find(self, identifier: Optional[str]) -> Optional[AsyncScrollEntry]:
        if not identifier:
            return None
        with self._lock:
            entry = self._entries.get(identifier)
            if entry is not None:
                return entry
            for candidate in self._entries.values():
                if candidate.scroll_id == identifier:
                    return candidate
            return None

    def require(self, identifier: Optional[str], owner: Any) -> AsyncScrollEntry:
        entry = self.find(identifier)
        if entry is None or entry.closed:
            raise ScrollOwnershipError(
                entry.scroll_id if entry is not None else None,
                "Scroll context %r is not registered or was already closed"
                % identifier,
                owner=owner,
            )
        if not _same_owner(entry.owner, owner):
            raise ScrollOwnershipError(
                entry.scroll_id,
                "Scroll context %r does not belong to this owner" % identifier,
                owner=owner,
            )
        return entry

    def release(self, context_id: str) -> Optional[AsyncScrollEntry]:
        with self._lock:
            return self._entries.pop(context_id, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


async_scroll_registry = AsyncScrollRegistry()


class AsyncOwnedScroll:
    """
    Async counterpart of :class:`opensearchpy.helpers.scroll.OwnedScroll`.

    Use :meth:`from_response` after the initial ``search`` call, then
    ``await cursor.next_page()`` to advance. ``close`` is a coroutine and
    always targets the client that opened the context.
    """

    def __init__(
        self,
        client: Any,
        response: Any,
        owner: Any = None,
        scroll: Any = "5m",
        context_id: Optional[str] = None,
        registry: Optional[AsyncScrollRegistry] = None,
    ) -> None:
        self._client = client
        self._registry = registry or async_scroll_registry
        self._scroll = scroll
        self._response = response
        self._scroll_id = _scroll_id_of(response)
        self._context_id = context_id or self._scroll_id
        self._owner = owner
        self._closed = False
        if not self._context_id:
            raise ValueError(
                "The initial response has no _scroll_id and no context_id was given"
            )
        self._entry = self._registry.register(
            self._context_id, owner, client, self._scroll_id, scroll
        )

    @property
    def client(self) -> Any:
        """The client pinned to this context; all requests go through it."""
        return self._client

    @classmethod
    async def from_response(
        cls,
        response: Any,
        using: Any = "default",
        actor: Any = None,
        owner: Any = None,
        scroll: Any = "5m",
        context_id: Optional[str] = None,
        registry: Optional[AsyncScrollRegistry] = None,
    ) -> "AsyncOwnedScroll":
        from ...connection.async_connections import get_connection

        client = await get_connection(using)
        return cls(
            client,
            response,
            owner=_resolve_owner(owner, actor),
            scroll=scroll,
            context_id=context_id,
            registry=registry,
        )

    @classmethod
    def resume(
        cls,
        context_id: Optional[str] = None,
        using: Any = None,
        actor: Any = None,
        owner: Any = None,
        scroll: Any = "5m",
        registry: Optional[AsyncScrollRegistry] = None,
        scroll_id: Optional[str] = None,
    ) -> "AsyncOwnedScroll":
        identifier = context_id or scroll_id
        if not identifier:
            raise ValueError("A context_id or scroll_id is required to resume")
        reg = registry or async_scroll_registry
        entry = reg.require(identifier, _resolve_owner(owner, actor))

        cursor = cls.__new__(cls)
        cursor._client = entry.client
        cursor._registry = reg
        cursor._scroll = scroll
        cursor._response = {"_scroll_id": entry.scroll_id}
        cursor._scroll_id = entry.scroll_id
        cursor._context_id = entry.context_id
        cursor._owner = entry.owner
        cursor._closed = False
        cursor._entry = entry
        return cursor

    @property
    def context_id(self) -> str:
        return self._context_id

    @property
    def owner(self) -> Any:
        return self._owner

    @property
    def scroll_id(self) -> Optional[str]:
        return self._scroll_id

    @property
    def closed(self) -> bool:
        """True once this cursor or any sibling sharing the context ended it."""
        if self._closed or self._entry.closed:
            return True
        return self._registry.get(self._context_id) is None

    @property
    def response(self) -> Any:
        return self._response

    @property
    def hits(self) -> Any:
        return _page_hits(self._response)

    def pagination_state(self) -> Dict[str, Any]:
        """Serialisable state an application can store with its pagination state."""
        return {"context_id": self._context_id, "scroll_id": self._scroll_id}

    async def next_page(self, scroll: Any = None, **kwargs: Any) -> Any:
        self._require_live()
        if not self._scroll_id:
            raise ScrollClosedError(None, "Scroll context has no scroll id")

        resp = await self._entry.client.scroll(
            body={"scroll_id": self._scroll_id, "scroll": scroll or self._scroll},
            **kwargs,
        )
        new_scroll_id = _scroll_id_of(resp)
        if new_scroll_id:
            self._scroll_id = new_scroll_id
            self._entry.scroll_id = new_scroll_id
        self._response = resp
        return resp

    async def close(self, **kwargs: Any) -> Any:
        if self._closed:
            return None
        self._closed = True

        entry = self._registry.release(self._context_id)
        if entry is None:
            return None
        entry.closed = True
        self._entry = entry
        self._scroll_id = entry.scroll_id
        if not self._scroll_id:
            return None
        return await entry.client.clear_scroll(
            body={"scroll_id": [self._scroll_id]}, ignore=(404,), **kwargs
        )

    async def __aenter__(self) -> "AsyncOwnedScroll":
        self._require_live()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    def __aiter__(self) -> AsyncGenerator[Any, None]:
        return aiter_owned_scroll(self)

    def _require_live(self) -> None:
        if self._closed or self._entry.closed:
            raise ScrollClosedError(
                self._scroll_id, "Scroll context %r was closed" % self._context_id
            )
        if self._registry.get(self._context_id) is None:
            raise ScrollClosedError(
                self._scroll_id,
                "Scroll context %r was closed by another cursor" % self._context_id,
            )
        current = self._registry.require(self._context_id, self._owner)
        if current is not self._entry:
            self._entry = current
        self._scroll_id = current.scroll_id


async def aiter_owned_scroll(
    cursor: AsyncOwnedScroll, clear: bool = True
) -> AsyncGenerator[Any, None]:
    try:
        while cursor.hits:
            for hit in cursor.hits:
                yield hit
            if cursor.closed:
                return
            await cursor.next_page()
    finally:
        if clear:
            await cursor.close()


__all__ = [
    "AsyncOwnedScroll",
    "AsyncScrollRegistry",
    "AsyncScrollEntry",
    "async_scroll_registry",
    "aiter_owned_scroll",
]
