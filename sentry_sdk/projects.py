import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sentry_sdk.client import BaseClient, Client
from sentry_sdk.integrations.threading import ThreadingIntegration
from sentry_sdk.scope import Scope, _current_scope, _isolation_scope
from sentry_sdk.transport import Transport
from sentry_sdk.utils import capture_internal_exceptions, logger

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, Generator, List, Optional

    from sentry_sdk._types import Event, EventDataCategory
    from sentry_sdk.envelope import Envelope, Item

PROJECT_TAG = "sentry.project"
DEFAULT_PROJECT = "default"

_PROJECT_OPTIONS: "Dict[str, Any]" = {
    "default_integrations": False,
    "auto_enabling_integrations": False,
    "auto_session_tracking": False,
    "enable_backpressure_handling": False,
    "send_client_reports": False,
    "shutdown_timeout": 0,
}


class _DiscardClient(BaseClient):
    """An active client that intentionally sends nothing.

    ``NonRecordingClient`` is inactive, so the scope lookup would fall through
    to the globally configured client. This client reports itself as active to
    stop that fallback and keeps unmapped events out of every project.
    """

    def __init__(self) -> None:
        BaseClient.__init__(self)

    def is_active(self) -> bool:
        return True


class MemoryTransport(Transport):
    """An in-memory transport that records every captured envelope.

    Useful for tests and for verifying which project an event was sent to.
    """

    def __init__(self, options: "Optional[Dict[str, Any]]" = None) -> None:
        Transport.__init__(self, options)
        self.envelopes: "List[Envelope]" = []

    @property
    def events(self) -> "List[Event]":
        events = []
        for envelope in self.envelopes:
            event = envelope.get_event()
            if event is not None:
                events.append(event)
        return events

    def capture_envelope(self, envelope: "Envelope") -> None:
        self.envelopes.append(envelope)


class ProjectTransport(Transport):
    """A per-project transport that retains envelopes when sending fails.

    A failed envelope stays in this project's queue and is retried by
    :meth:`ProjectTransport.retry_pending`. It is never handed to another
    project or to the default project, so a temporary outage cannot
    reattribute events.
    """

    def __init__(self, transport: "Transport") -> None:
        Transport.__init__(self, getattr(transport, "options", None))
        self.parsed_dsn = getattr(transport, "parsed_dsn", None)
        self._inner = transport
        self._lock = threading.Lock()
        self._pending: "List[Envelope]" = []

    def capture_envelope(self, envelope: "Envelope") -> None:
        if not self._is_available():
            with self._lock:
                self._pending.append(envelope)
            logger.warning(
                "Project transport is unavailable; keeping the envelope for this project's retry."
            )
            return

        try:
            self._inner.capture_envelope(envelope)
        except Exception:
            with self._lock:
                self._pending.append(envelope)
            logger.warning(
                "Project transport failed; keeping the envelope for this project's retry."
            )

    def _is_available(self) -> bool:
        try:
            return self._inner.is_healthy()
        except Exception:
            return True

    def retry_pending(self) -> int:
        """Retry queued envelopes and return how many were delivered."""
        with self._lock:
            pending, self._pending = self._pending, []

        failed: "List[Envelope]" = []
        for envelope in pending:
            try:
                self._inner.capture_envelope(envelope)
            except Exception:
                failed.append(envelope)

        if failed:
            with self._lock:
                self._pending[:0] = failed

        return len(pending) - len(failed)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def flush(
        self,
        timeout: float,
        callback: "Optional[Callable[[int, float], None]]" = None,
    ) -> None:
        self._inner.flush(timeout=timeout, callback=callback)

    def kill(self) -> None:
        self._inner.kill()

    def __getattr__(self, name: str) -> "Any":
        return getattr(self._inner, name)

    def record_lost_event(
        self,
        reason: str,
        data_category: "Optional[EventDataCategory]" = None,
        item: "Optional[Item]" = None,
        *,
        quantity: int = 1,
    ) -> None:
        self._inner.record_lost_event(reason, data_category, item, quantity=quantity)

    def is_healthy(self) -> bool:
        if self.pending_count:
            return False
        return self._inner.is_healthy()


class ProjectRouter:
    """Routes events to the client and transport of an approved project.

    Register every project that may receive events with a key and a transport.
    A project is approved if and only if it is registered here. Bind requests
    and tasks with :meth:`ProjectRouter.scope`, which puts the project's client
    on the isolation scope so the binding follows the request into threads and
    asyncio tasks.

    The default project is not a catch-all: it only receives events captured
    while it is explicitly selected (``router.scope("default")``). Events
    captured without a binding, or with an unregistered project key, are
    dropped instead of being sent to the default project.

    Constructing a router replaces the global scope's client with a client
    that discards events, so unbound events cannot fall back to whichever
    client was configured before. :meth:`ProjectRouter.close` restores it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: "Dict[str, Client]" = {}
        self._transports: "Dict[str, ProjectTransport]" = {}
        self._discard = _DiscardClient()
        self._previous_global_client = Scope.get_global_scope().client
        self._shared_integrations = list(
            getattr(self._previous_global_client, "integrations", {}).values()
        )
        Scope.get_global_scope().set_client(self._discard)

    def register(
        self,
        project: str,
        transport: "Transport",
        dsn: "Optional[str]" = None,
    ) -> Client:
        """Register an approved project with its transport and return its client.

        The project client reuses the integrations already installed by the
        default client so bound background tasks keep being instrumented.
        """
        if not project:
            raise ValueError("Project key must be a non-empty string")

        with self._lock:
            if project in self._clients:
                raise ValueError("Project %r is already registered" % (project,))

            project_transport = ProjectTransport(transport)
            integrations = list(self._shared_integrations)
            if not any(
                isinstance(integration, ThreadingIntegration)
                for integration in integrations
            ):
                integrations.append(ThreadingIntegration())

            client = Client(
                dsn=dsn,
                transport=project_transport,
                integrations=integrations,
                **_PROJECT_OPTIONS,
            )
            self._clients[project] = client
            self._transports[project] = project_transport

        return client

    def get_client(self, project: str) -> "Optional[Client]":
        with self._lock:
            return self._clients.get(project)

    def get_transport(self, project: str) -> "Optional[ProjectTransport]":
        with self._lock:
            return self._transports.get(project)

    @property
    def projects(self) -> "List[str]":
        with self._lock:
            return list(self._clients)

    @contextmanager
    def scope(self, project: "Optional[str]") -> "Generator[Scope, None, None]":
        """Bind the current request or task to an approved project.

        ``project=None`` explicitly clears a binding. Unknown projects are not
        mapped, so events captured inside are dropped.
        """
        client = None if project is None else self.get_client(project)

        if project is not None and client is None:
            logger.warning(
                "Sentry project %r is not approved; not sending its events.", project
            )

        with _bind_client(client if client is not None else self._discard):
            scope = Scope.get_isolation_scope()
            if client is not None:
                scope.set_tag(PROJECT_TAG, project)
            yield scope

    def retry(self, project: "Optional[str]" = None) -> "Dict[str, int]":
        """Retry failed envelopes per project and return delivered counts.

        If ``project`` is given, only that project is retried. Unknown projects
        are ignored.
        """
        with self._lock:
            if project is not None:
                transports = (
                    {project: self._transports[project]}
                    if project in self._transports
                    else {}
                )
            else:
                transports = dict(self._transports)

        retried = {}
        for name, transport in transports.items():
            count = transport.retry_pending()
            if count:
                retried[name] = count
        return retried

    def flush(self, timeout: "Optional[float]" = None) -> None:
        """Flush every project's client, including queued telemetry."""
        with self._lock:
            clients = list(self._clients.values())

        for client in clients:
            with capture_internal_exceptions():
                client.flush(timeout=timeout)

    def close(self) -> None:
        """Close all project clients, flushing queued telemetry first."""
        self.flush()

        with self._lock:
            clients, self._clients = self._clients, {}
            self._transports = {}

        for client in clients.values():
            with capture_internal_exceptions():
                client.close()

        with capture_internal_exceptions():
            Scope.get_global_scope().set_client(self._previous_global_client)


@contextmanager
def _bind_client(client: "BaseClient") -> "Generator[None, None, None]":
    """Fork both scopes and bind the given client on the isolation scope."""
    current_scope = Scope.get_current_scope().fork()
    isolation_scope = Scope.get_isolation_scope().fork()
    isolation_scope.set_client(client)

    current_token = _current_scope.set(current_scope)
    isolation_token = _isolation_scope.set(isolation_scope)

    try:
        yield
    finally:
        with capture_internal_exceptions():
            _current_scope.reset(current_token)
        with capture_internal_exceptions():
            _isolation_scope.reset(isolation_token)
