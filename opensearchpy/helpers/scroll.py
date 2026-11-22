# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


import threading
from typing import Any, Dict, Optional

from .errors import ScrollClosedError, ScrollOwnershipError


class ScrollEntry:
    """
    Internal record describing one live owned scroll context.

    ``client`` is the client that served the initial search. Every later
    scroll and clear request for the context is routed back to this exact
    client, regardless of which alias the caller passes to :meth:`resume`.
    """

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


class ScrollRegistry:
    """
    Process-local registry of live owned scroll contexts.

    The registry stores only bookkeeping. The raw ``_scroll_id`` remains in
    the response handed to the application, so the pagination state the
    backend persists is still a plain identifier that can be resumed later.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[str, ScrollEntry] = {}

    def register(
        self,
        context_id: str,
        owner: Any,
        client: Any,
        scroll_id: Optional[str],
        scroll: Any,
    ) -> ScrollEntry:
        with self._lock:
            existing = self._entries.get(context_id)
            if existing is not None and not existing.closed:
                raise ScrollOwnershipError(
                    existing.scroll_id,
                    "Scroll context %r is already active" % context_id,
                    owner=owner,
                )
            entry = ScrollEntry(context_id, owner, client, scroll_id, scroll)
            self._entries[context_id] = entry
            return entry

    def get(self, context_id: str) -> Optional[ScrollEntry]:
        with self._lock:
            return self._entries.get(context_id)

    def find(self, identifier: Optional[str]) -> Optional[ScrollEntry]:
        """
        Look a context up by its pagination-state identifier.

        Identifiers are normally the initial scroll id, but scroll ids rotate
        as pages advance. Resuming with the *current* scroll id therefore also
        matches, which keeps persisted state usable either way.
        """
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

    def require(self, identifier: Optional[str], owner: Any) -> ScrollEntry:
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

    def release(self, context_id: str) -> Optional[ScrollEntry]:
        with self._lock:
            return self._entries.pop(context_id, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


scroll_registry = ScrollRegistry()


def _same_owner(left: Any, right: Any) -> bool:
    if left is right:
        return True
    try:
        return bool(left == right)
    except Exception:
        return False


def _resolve_owner(owner: Any, actor: Any) -> Any:
    """
    ``actor=`` is the opt-in ownership convention. Applications that already
    carry a request identity can use it directly, while ``owner=`` remains an
    explicit escape hatch for callers that build the cursor themselves.
    """
    if owner is not None and actor is not None and not _same_owner(owner, actor):
        raise ScrollOwnershipError(
            None, "owner and actor refer to different identities", owner=owner
        )
    return owner if owner is not None else actor


def _scroll_id_of(response: Any) -> Optional[str]:
    if response is None:
        return None
    try:
        return response["_scroll_id"]
    except (KeyError, TypeError):
        return None


def _page_hits(response: Any) -> Any:
    if response is None:
        return []
    try:
        return response["hits"]["hits"] or []
    except (KeyError, TypeError):
        return []


class OwnedScroll:
    """
    Opt-in pagination ownership convention for scroll searches.

    A cursor is created from the *initial* scrolled search response and keeps
    the backend-provided search context identifier in :attr:`context_id`
    (defaulting to the initial ``_scroll_id``). Applications can persist that
    identifier in their pagination state and later call :meth:`resume` with
    the same ``actor`` to keep paging.

    Ownership is optional: without ``actor``/``owner`` the context is open to
    any caller that knows its identifier. With it, another operator can
    neither advance nor clear the search.

    Example::

        response = client.search(index="logs", scroll="1m", body=query)
        cursor = OwnedScroll.from_response(
            response, using=client, actor=request.user, scroll="1m"
        )
        while cursor.hits:
            handle(cursor.hits)
            cursor.next_page()
        cursor.close()
    """

    def __init__(
        self,
        client: Any,
        response: Any,
        owner: Any = None,
        scroll: Any = "5m",
        context_id: Optional[str] = None,
        registry: Optional[ScrollRegistry] = None,
    ) -> None:
        self._client = client
        self._registry = registry or scroll_registry
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
    def from_response(
        cls,
        response: Any,
        using: Any = "default",
        actor: Any = None,
        owner: Any = None,
        scroll: Any = "5m",
        context_id: Optional[str] = None,
        registry: Optional[ScrollRegistry] = None,
    ) -> "OwnedScroll":
        """
        Bind a fresh cursor to an initial scrolled search response.

        :arg response: raw response of the initial scrolled search
        :arg using: client or alias that performed the initial search; every
            later scroll and clear request is sent through it
        :arg actor: opt-in ownership identity, for example the authenticated
            user of the request. Cursors resumed with a different actor are
            rejected.
        :arg owner: explicit ownership value when the application does not
            model an ``actor``
        :arg scroll: keep-alive sent with every subsequent scroll request
        :arg context_id: pagination-state identifier; defaults to ``_scroll_id``
        :arg registry: alternate registry, useful for isolated applications
        """
        from ..connection.connections import get_connection

        client = get_connection(using)
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
        registry: Optional[ScrollRegistry] = None,
        scroll_id: Optional[str] = None,
    ) -> "OwnedScroll":
        """
        Re-attach to a context that was started earlier.

        :arg context_id: identifier persisted in the pagination state; the
            current ``scroll_id`` is accepted too
        :arg using: accepted for symmetry with :meth:`from_response`; routing
            is pinned to the client that opened the context
        :arg actor: ownership identity that must match the original caller
        :arg owner: explicit ownership value, see :meth:`from_response`
        :arg scroll: keep-alive sent with every subsequent scroll request
        :arg registry: registry that holds the context
        :arg scroll_id: alias for ``context_id``
        """
        identifier = context_id or scroll_id
        if not identifier:
            raise ValueError("A context_id or scroll_id is required to resume")
        reg = registry or scroll_registry
        resolved_owner = _resolve_owner(owner, actor)
        entry = reg.require(identifier, resolved_owner)

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
        """Identifier applications can persist in their pagination state."""
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
        """The most recent raw response, including this page's ``hits``."""
        return self._response

    def pagination_state(self) -> Dict[str, Any]:
        """
        Serialisable state an application can store with its pagination state.

        The identifier is enough to :meth:`resume` while the process registry
        still holds the context; ``scroll_id`` is included because scroll ids
        rotate as pages advance.
        """
        return {"context_id": self._context_id, "scroll_id": self._scroll_id}

    @property
    def hits(self) -> Any:
        """Hits of the most recent page."""
        return _page_hits(self._response)

    def next_page(self, scroll: Any = None, **kwargs: Any) -> Any:
        """
        Fetch the next page and return the raw response.

        Closed contexts and contexts owned by somebody else raise before any
        request is sent.
        """
        self._require_live()
        if not self._scroll_id:
            raise ScrollClosedError(None, "Scroll context has no scroll id")

        resp = self._entry.client.scroll(
            body={"scroll_id": self._scroll_id, "scroll": scroll or self._scroll},
            **kwargs,
        )
        new_scroll_id = _scroll_id_of(resp)
        if new_scroll_id:
            self._scroll_id = new_scroll_id
            self._entry.scroll_id = new_scroll_id
        self._response = resp
        return resp

    def close(self, **kwargs: Any) -> Any:
        """
        Actively end the search and clear the server-side scroll context.

        The clear request always goes to the client that opened the context,
        even if the cursor was resumed through a different alias. Closing an
        already-ended context is a no-op and sends nothing.
        """
        if self._closed:
            return None
        self._closed = True

        entry = self._registry.release(self._context_id)
        if entry is None:
            # Another cursor sharing this context already ended it.
            return None
        entry.closed = True
        self._entry = entry
        self._scroll_id = entry.scroll_id
        if not self._scroll_id:
            return None
        return entry.client.clear_scroll(
            body={"scroll_id": [self._scroll_id]}, ignore=(404,), **kwargs
        )

    def __iter__(self) -> Any:
        """Iterate over the remaining hits, closing the context at the end."""
        return iter_owned_scroll(self)

    def __enter__(self) -> "OwnedScroll":
        self._require_live()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

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


def iter_owned_scroll(cursor: OwnedScroll, clear: bool = True) -> Any:
    """
    Yield hits page by page from an :class:`OwnedScroll`, closing it when the
    iterator is exhausted or abandoned.
    """
    try:
        while cursor.hits:
            yield from cursor.hits
            if cursor.closed:
                return
            cursor.next_page()
    finally:
        if clear:
            cursor.close()


__all__ = [
    "OwnedScroll",
    "ScrollRegistry",
    "ScrollEntry",
    "scroll_registry",
    "iter_owned_scroll",
]
