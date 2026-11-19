import functools
import logging
from collections.abc import Iterable, Mapping

from asgiref.sync import async_to_sync
from django.core.exceptions import ImproperlyConfigured

from . import DEFAULT_CHANNEL_LAYER
from .db import aclose_old_connections, database_sync_to_async
from .exceptions import StopConsumer
from .layers import get_channel_layer
from .utils import await_many_dispatch

logger = logging.getLogger("django.channels.consumer")

#: Handlers that make up the connection lifecycle for each protocol. They
#: remain available on the connection source even when ``handler_allowlist``
#: is in use, so a connection can always be established and closed cleanly.
PROTOCOL_LIFECYCLE_HANDLERS = {
    "websocket": frozenset({"websocket_connect", "websocket_disconnect"}),
    "http": frozenset({"http_request", "http_disconnect"}),
}

ALLOWLIST_SOURCES = frozenset({"connection", "channel_layer"})

#: Handlers that are part of the dispatch machinery itself and can never be a
#: business handler. Listing one in an allowlist is a configuration error.
RESERVED_HANDLER_NAMES = frozenset({"dispatch", "send"})


def get_handler_name(message):
    """
    Looks at a message, checks it has a sensible type, and returns the
    handler name for that type.
    """
    # Check message looks OK
    if "type" not in message:
        raise ValueError("Incoming message has no 'type' attribute")
    # Extract type and replace . with _
    handler_name = message["type"].replace(".", "_")
    if handler_name.startswith("_"):
        raise ValueError("Malformed type in message (leading underscore)")
    return handler_name


def normalize_handler_name(name):
    """
    Turns a declared handler name or message type into the name dispatch uses.

    Accepting both forms keeps allowlists easy to audit: ``websocket.receive``
    and ``websocket_receive`` identify the same handler.
    """
    if not isinstance(name, str):
        raise ImproperlyConfigured(
            "handler_allowlist entries must be strings, not %r" % type(name)
        )
    if not name:
        raise ImproperlyConfigured("handler_allowlist entries must not be empty")
    try:
        handler_name = get_handler_name({"type": name})
    except ValueError as exc:
        raise ImproperlyConfigured(
            "Invalid handler name in handler_allowlist: %r" % name
        ) from exc
    if not handler_name.isidentifier():
        raise ImproperlyConfigured(
            "handler_allowlist entry %r does not name a handler method" % name
        )
    return handler_name


class AsyncConsumer:
    """
    Base consumer class. Implements the ASGI application spec, and adds on
    channel layer management and routing of events to named methods based
    on their type.
    """

    _sync = False
    channel_layer_alias = DEFAULT_CHANNEL_LAYER

    #: Optional, opt-in per-source handler allowlist. When left as ``None``
    #: (the default) every handler reachable by name is dispatched, preserving
    #: historical behaviour. When set, it must be a mapping with the keys
    #: ``"connection"`` and/or ``"channel_layer"``, each holding an iterable of
    #: handler names or message types::
    #:
    #:     handler_allowlist = {
    #:         "connection": {"websocket.receive", "client.ping"},
    #:         "channel_layer": {"task.created", "shared.task"},
    #:     }
    #:
    #: A handler that is reachable from both sources must be listed in both
    #: sets. The protocol's connection lifecycle handlers (for WebSocket,
    #: ``websocket.connect`` and ``websocket.disconnect``; for HTTP,
    #: ``http.request`` and ``http.disconnect``) are always allowed on the
    #: connection source so connections can be established and closed.
    handler_allowlist = None

    async def __call__(self, scope, receive, send):
        """
        Dispatches incoming messages to type-based handlers asynchronously.
        """
        self.scope = scope
        self.event_source = None
        self._allowed_handlers = self._resolve_handler_allowlist()

        # Initialize channel layer
        self.channel_layer = get_channel_layer(self.channel_layer_alias)
        if self.channel_layer is not None:
            self.channel_name = await self.channel_layer.new_channel()
            self.channel_receive = functools.partial(
                self.channel_layer.receive, self.channel_name
            )
        # Store send function
        if self._sync:
            self.base_send = async_to_sync(send)
        else:
            self.base_send = send
        # Messages arriving through the ASGI ``receive`` callable come from the
        # connection, except in worker mode where that callable feeds a named
        # channel. Messages from ``channel_receive`` always come from the
        # channel layer.
        connection_source = (
            "channel_layer" if scope.get("type") == "channel" else "connection"
        )
        # Connection lifecycle handlers are tied to the protocol in use.
        lifecycle_handlers = PROTOCOL_LIFECYCLE_HANDLERS.get(
            scope.get("type"), frozenset()
        )
        if self._allowed_handlers is not None:
            self._allowed_handlers = {
                **self._allowed_handlers,
                "connection": self._allowed_handlers["connection"]
                | lifecycle_handlers,
            }
        # Pass messages in from channel layer or client to dispatch method,
        # tagging each input with the source that delivered it.
        dispatchers = [
            (
                receive,
                functools.partial(self._dispatch_from_source, connection_source),
            )
        ]
        if self.channel_layer is not None:
            dispatchers.append(
                (self.channel_receive, self._dispatch_from_channel_layer)
            )
        try:
            await await_many_dispatch(dispatchers, self.dispatch)
        except StopConsumer:
            # Exit cleanly
            pass

    def _resolve_handler_allowlist(self):
        """
        Validates ``handler_allowlist`` and returns normalized handler sets.

        Returns ``None`` when the allowlist is disabled, which keeps the
        historical unrestricted dispatch behaviour.
        """
        allowlist = self.handler_allowlist
        if allowlist is None:
            return None
        if not isinstance(allowlist, Mapping):
            raise ImproperlyConfigured(
                "handler_allowlist must be a mapping of source to handler names"
            )
        unknown_sources = set(allowlist) - ALLOWLIST_SOURCES
        if unknown_sources:
            raise ImproperlyConfigured(
                "Unknown handler_allowlist source(s): %s. Valid sources are %s."
                % (
                    ", ".join(sorted(repr(source) for source in unknown_sources)),
                    ", ".join(sorted(ALLOWLIST_SOURCES)),
                )
            )

        allowed = {}
        for source in ALLOWLIST_SOURCES:
            names = allowlist.get(source, ())
            if isinstance(names, str):
                names = (names,)
            if not isinstance(names, Iterable):
                raise ImproperlyConfigured(
                    "handler_allowlist[%r] must be an iterable of handler names"
                    % source
                )
            normalized = set()
            for name in names:
                handler_name = normalize_handler_name(name)
                if handler_name in RESERVED_HANDLER_NAMES:
                    raise ImproperlyConfigured(
                        "handler_allowlist may not grant the reserved handler %r"
                        % handler_name
                    )
                normalized.add(handler_name)
            allowed[source] = frozenset(normalized)
        return allowed

    async def _dispatch_from_source(self, source, message):
        """
        Dispatches a message that arrived from the given source.
        """
        self.event_source = source
        if not self._is_handler_allowed(source, message):
            return
        await self.dispatch(message)

    async def _dispatch_from_channel_layer(self, message):
        """
        Dispatches a message that arrived from the channel layer.
        """
        await self._dispatch_from_source("channel_layer", message)

    def _is_handler_allowed(self, source, message):
        """
        Checks a message's handler against the per-source allowlist.

        Denied events are logged and dropped without invoking consumer code.
        """
        if self._allowed_handlers is None:
            return True
        handler_name = get_handler_name(message)
        if handler_name in self._allowed_handlers[source]:
            return True
        logger.warning(
            "Denied %s event %r: handler %r is not allowed for this source",
            source,
            message.get("type"),
            handler_name,
        )
        return False

    async def dispatch(self, message):
        """
        Works out what to do with a message.
        """
        handler = getattr(self, get_handler_name(message), None)
        if handler:
            await aclose_old_connections()
            await handler(message)
        else:
            raise ValueError("No handler for message type %s" % message["type"])

    async def send(self, message):
        """
        Overrideable/callable-by-subclasses send method.
        """
        await self.base_send(message)

    @classmethod
    def as_asgi(cls, **initkwargs):
        """
        Return an ASGI v3 single callable that instantiates a consumer instance
        per scope. Similar in purpose to Django's as_view().

        initkwargs will be used to instantiate the consumer instance.
        """

        async def app(scope, receive, send):
            consumer = cls(**initkwargs)
            return await consumer(scope, receive, send)

        app.consumer_class = cls
        app.consumer_initkwargs = initkwargs

        # take name and docstring from class
        functools.update_wrapper(app, cls, updated=())
        return app


class SyncConsumer(AsyncConsumer):
    """
    Synchronous version of the consumer, which is what we write most of the
    generic consumers against (for now). Calls handlers in a threadpool and
    uses CallBouncer to get the send method out to the main event loop.

    It would have been possible to have "mixed" consumers and auto-detect
    if a handler was awaitable or not, but that would have made the API
    for user-called methods very confusing as there'd be two types of each.
    """

    _sync = True

    @database_sync_to_async
    def dispatch(self, message):
        """
        Dispatches incoming messages to type-based handlers asynchronously.
        """
        # Get and execute the handler
        handler = getattr(self, get_handler_name(message), None)
        if handler:
            handler(message)
        else:
            raise ValueError("No handler for message type %s" % message["type"])

    def send(self, message):
        """
        Overrideable/callable-by-subclasses send method.
        """
        self.base_send(message)
