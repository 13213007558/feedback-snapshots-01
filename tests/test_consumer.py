import asyncio

import pytest
from django.core.exceptions import ImproperlyConfigured

from channels.consumer import AsyncConsumer, SyncConsumer
from channels.exceptions import StopConsumer
from channels.layers import InMemoryChannelLayer, channel_layers
from channels.testing import ApplicationCommunicator, WebsocketCommunicator


class TrackingChannelLayer(InMemoryChannelLayer):
    """
    In-memory layer that records whether a waiting ``receive`` task was
    cancelled, so disconnect cleanup can be observed.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_receives = 0
        self.cancelled_receives = 0

    async def receive(self, channel):
        self.pending_receives += 1
        try:
            return await super().receive(channel)
        except asyncio.CancelledError:
            self.cancelled_receives += 1
            raise
        finally:
            self.pending_receives -= 1


@pytest.fixture
def channel_layer():
    layer = TrackingChannelLayer()
    previous = channel_layers.set("default", layer)
    try:
        yield layer
    finally:
        if previous is None:
            channel_layers.backends.pop("default", None)
        else:
            channel_layers.set("default", previous)


def websocket_scope(path="/testws/"):
    return {
        "type": "websocket",
        "path": path,
        "query_string": b"",
        "headers": [],
        "subprotocols": [],
    }


class AuditedConsumer(AsyncConsumer):
    """
    One consumer fed by both the connection and the channel layer.
    """

    handler_allowlist = {
        "connection": {"client.ping", "shared.event"},
        "channel_layer": {"task.created", "shared.event"},
    }

    def __init__(self):
        self.calls = []
        self.channel_name_seen = None

    async def websocket_connect(self, message):
        self.calls.append(("websocket_connect", self.event_source))
        self.channel_name_seen = self.channel_name
        await self.send({"type": "websocket.accept"})

    async def websocket_disconnect(self, message):
        self.calls.append(("websocket_disconnect", self.event_source))
        raise StopConsumer()

    async def client_ping(self, message):
        self.calls.append(("client_ping", self.event_source, message["value"]))
        await self.send({"type": "pong", "value": message["value"]})

    async def task_created(self, message):
        self.calls.append(("task_created", self.event_source, message["value"]))
        await self.send({"type": "task.done", "value": message["value"]})

    async def shared_event(self, message):
        self.calls.append(("shared_event", self.event_source, message["value"]))
        await self.send(
            {
                "type": "shared.seen",
                "source": self.event_source,
                "value": message["value"],
            }
        )


async def start_consumer(consumer):
    communicator = WebsocketCommunicator(consumer, "/testws/")
    connected, _ = await communicator.connect()
    assert connected
    return communicator


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_allowlist_routes_both_sources_on_one_consumer(channel_layer):
    """
    Real connection and channel layer events reach the handlers each source
    was granted, and a shared handler keeps both grants distinct.
    """
    consumer = AuditedConsumer()
    communicator = await start_consumer(consumer)

    # Connection event -> connection grant.
    await communicator.send_input({"type": "client.ping", "value": "conn-1"})
    response = await communicator.receive_output()
    assert response == {"type": "pong", "value": "conn-1"}

    # Channel layer event -> channel layer grant.
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "task.created", "value": "task-1"}
    )
    response = await communicator.receive_output()
    assert response == {"type": "task.done", "value": "task-1"}

    # Shared handler is explicitly granted on both sources.
    await communicator.send_input({"type": "shared.event", "value": "from-conn"})
    response = await communicator.receive_output()
    assert response["source"] == "connection"
    assert response["value"] == "from-conn"

    await channel_layer.send(
        consumer.channel_name_seen, {"type": "shared.event", "value": "from-layer"}
    )
    response = await communicator.receive_output()
    assert response["source"] == "channel_layer"
    assert response["value"] == "from-layer"

    assert consumer.calls == [
        ("websocket_connect", "connection"),
        ("client_ping", "connection", "conn-1"),
        ("task_created", "channel_layer", "task-1"),
        ("shared_event", "connection", "from-conn"),
        ("shared_event", "channel_layer", "from-layer"),
    ]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_allowlist_rejects_cross_source_events(channel_layer):
    """
    An event type granted to one source never reaches the business handler
    when it arrives from the other source.
    """
    consumer = AuditedConsumer()
    communicator = await start_consumer(consumer)

    # "task.created" is only granted to the channel layer. Send it on the
    # connection first, then a permitted event as a sequencing barrier.
    await communicator.send_input({"type": "task.created", "value": "bad-conn"})
    await communicator.send_input({"type": "client.ping", "value": "conn-ok"})
    assert await communicator.receive_output() == {"type": "pong", "value": "conn-ok"}

    # "client.ping" is only granted to the connection. Send it on the channel
    # layer first, then a permitted channel event as a sequencing barrier.
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "client.ping", "value": "bad-layer"}
    )
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "task.created", "value": "layer-ok"}
    )
    assert await communicator.receive_output() == {
        "type": "task.done",
        "value": "layer-ok",
    }

    handler_names = [call[0] for call in consumer.calls]
    assert "task_created" not in handler_names[:2]
    assert not any(
        call == ("task_created", "connection", "bad-conn") for call in consumer.calls
    )
    assert not any(
        call == ("client_ping", "channel_layer", "bad-layer")
        for call in consumer.calls
    )

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_shared_handler_requires_both_grants(channel_layer):
    """
    A handler shared by both sources must be listed under both grants; a
    single grant does not silently widen access.
    """

    class ConnectionOnlyConsumer(AuditedConsumer):
        handler_allowlist = {
            "connection": {"shared.event"},
            "channel_layer": {"task.created"},
        }

    consumer = ConnectionOnlyConsumer()
    communicator = await start_consumer(consumer)

    # Allowed from the connection.
    await communicator.send_input({"type": "shared.event", "value": "conn"})
    assert (await communicator.receive_output())["source"] == "connection"

    # Denied from the channel layer, then a permitted event proves ordering.
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "shared.event", "value": "layer"}
    )
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "task.created", "value": "ok"}
    )
    assert await communicator.receive_output() == {"type": "task.done", "value": "ok"}

    assert not any(
        call == ("shared_event", "channel_layer", "layer") for call in consumer.calls
    )

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_allowlist_keeps_connection_lifecycle(channel_layer):
    """
    Framework connect/disconnect handling stays available even when the
    connection grant is empty.
    """

    class EmptyConsumer(AsyncConsumer):
        handler_allowlist = {"connection": set(), "channel_layer": set()}

        def __init__(self):
            self.calls = []

        async def websocket_connect(self, message):
            self.calls.append("connect")
            await self.send({"type": "websocket.accept"})

        async def websocket_disconnect(self, message):
            self.calls.append("disconnect")
            raise StopConsumer()

        async def client_ping(self, message):
            self.calls.append("ping")

    consumer = EmptyConsumer()
    communicator = await start_consumer(consumer)

    # Business handlers remain denied on both sources.
    await communicator.send_input({"type": "client.ping"})
    await communicator.send_input({"type": "websocket.receive", "text": "hi"})
    await communicator.receive_nothing()

    await communicator.disconnect()
    assert consumer.calls == ["connect", "disconnect"]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_disconnect_cancels_waiting_tasks(channel_layer):
    """
    Closing the connection still cancels the channel layer receive task and
    drops any pending input, even with an allowlist in effect.
    """
    consumer = AuditedConsumer()
    communicator = await start_consumer(consumer)

    # Leave an event waiting for a handler while the connection closes.
    await channel_layer.send(
        consumer.channel_name_seen, {"type": "client.ping", "value": "rejected"}
    )
    await communicator.receive_nothing()
    assert channel_layer.pending_receives == 1

    await communicator.send_input({"type": "websocket.disconnect", "code": 1000})
    await communicator.wait()

    # The waiting channel layer receive task was cancelled with the consumer.
    assert channel_layer.pending_receives == 0
    assert channel_layer.cancelled_receives >= 1
    assert not any(
        "client_ping" == task.get_coro().__qualname__
        for task in asyncio.all_tasks()
        if not task.done() and hasattr(task.get_coro(), "__qualname__")
    )
    assert not any(
        call[0] == "client_ping" and call[2] == "rejected" for call in consumer.calls
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_allowlist_is_opt_in(channel_layer):
    """
    Consumers without an allowlist keep the historical unrestricted dispatch.
    """

    class LegacyConsumer(AsyncConsumer):
        def __init__(self):
            self.calls = []

        async def websocket_connect(self, message):
            await self.send({"type": "websocket.accept"})

        async def websocket_disconnect(self, message):
            raise StopConsumer()

        async def internal_event(self, message):
            self.calls.append(("internal_event", self.event_source, message["value"]))

    consumer = LegacyConsumer()
    communicator = await start_consumer(consumer)

    await communicator.send_input({"type": "internal_event", "value": "conn"})
    await channel_layer.send(
        consumer.channel_name, {"type": "internal_event", "value": "layer"}
    )
    # No outbound replies: wait for the handler calls themselves.
    for _ in range(50):
        if len(consumer.calls) == 2:
            break
        await asyncio.sleep(0.01)
    assert consumer.calls == [
        ("internal_event", "connection", "conn"),
        ("internal_event", "channel_layer", "layer"),
    ]

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_sync_consumer_allowlist(channel_layer):
    """
    SyncConsumer uses the same per-source selection.
    """

    class SyncAuditedConsumer(SyncConsumer):
        handler_allowlist = {
            "connection": {"client.ping"},
            "channel_layer": {"task.created"},
        }

        def __init__(self):
            self.calls = []

        def websocket_connect(self, message):
            self.calls.append(("connect", self.event_source))
            self.send({"type": "websocket.accept"})

        def websocket_disconnect(self, message):
            self.calls.append(("disconnect", self.event_source))
            raise StopConsumer()

        def client_ping(self, message):
            self.calls.append(("client_ping", self.event_source, message["value"]))

        def task_created(self, message):
            self.calls.append(("task_created", self.event_source, message["value"]))

    consumer = SyncAuditedConsumer()
    communicator = WebsocketCommunicator(consumer, "/testws/")
    connected, _ = await communicator.connect()
    assert connected

    await communicator.send_input({"type": "client.ping", "value": "conn"})
    await channel_layer.send(
        consumer.channel_name, {"type": "task.created", "value": "layer"}
    )
    # Denied direction: task.created over the connection.
    await communicator.send_input({"type": "task.created", "value": "bad"})

    for _ in range(50):
        if len(consumer.calls) >= 3:
            break
        await asyncio.sleep(0.01)

    assert ("client_ping", "connection", "conn") in consumer.calls
    assert ("task_created", "channel_layer", "layer") in consumer.calls
    assert not any(
        call == ("task_created", "connection", "bad") for call in consumer.calls
    )

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_allowlist_accepts_message_type_spelling(channel_layer):
    """
    Both dotted message types and handler names identify the same grant.
    """

    class DottedConsumer(AsyncConsumer):
        handler_allowlist = {"connection": {"client.ping"}}

        def __init__(self):
            self.calls = []

        async def websocket_connect(self, message):
            await self.send({"type": "websocket.accept"})

        async def websocket_disconnect(self, message):
            raise StopConsumer()

        async def client_ping(self, message):
            self.calls.append("ping")

    consumer = DottedConsumer()
    communicator = await start_consumer(consumer)
    await communicator.send_input({"type": "client.ping"})
    for _ in range(50):
        if consumer.calls:
            break
        await asyncio.sleep(0.01)
    assert consumer.calls == ["ping"]
    await communicator.disconnect()


@pytest.mark.asyncio
async def test_allowlist_validation():
    """
    Malformed allowlists fail fast instead of silently widening access.
    """

    async def receive():
        return {"type": "never"}

    async def send(message):
        pass

    class NotAMapping(AsyncConsumer):
        handler_allowlist = ["client.ping"]

    class UnknownSource(AsyncConsumer):
        handler_allowlist = {"clients": {"client.ping"}}

    class BadEntry(AsyncConsumer):
        handler_allowlist = {"connection": {object()}}

    class BadName(AsyncConsumer):
        handler_allowlist = {"connection": {"_private"}}

    class NotAnIdentifier(AsyncConsumer):
        handler_allowlist = {"connection": {"task-created"}}

    for cls in (NotAMapping, UnknownSource, BadEntry, BadName, NotAnIdentifier):
        with pytest.raises(ImproperlyConfigured):
            await cls()(websocket_scope(), receive, send)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_http_consumer_allowlist_keeps_http_lifecycle(channel_layer):
    """
    An HTTP consumer retains its request/disconnect lifecycle while business
    handlers stay scoped to the connection.
    """

    class HttpAuditedConsumer(AsyncConsumer):
        handler_allowlist = {"connection": {"client.ping"}}

        def __init__(self):
            self.calls = []

        async def http_request(self, message):
            self.calls.append(("request", self.event_source))
            await self.send(
                {"type": "http.response.start", "status": 200, "headers": []}
            )
            await self.send({"type": "http.response.body", "body": b"ok"})
            raise StopConsumer()

        async def client_ping(self, message):
            self.calls.append(("ping", self.event_source))

    consumer = HttpAuditedConsumer()
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/test/",
        "query_string": b"",
        "headers": [],
    }
    messages = asyncio.Queue()
    output = []

    async def receive():
        return await messages.get()

    async def send(message):
        output.append(message)

    await messages.put({"type": "http.request", "body": b""})
    await consumer(scope, receive, send)

    assert consumer.calls == [("request", "connection")]
    assert [message["type"] for message in output] == [
        "http.response.start",
        "http.response.body",
    ]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_denied_unknown_type_is_dropped(channel_layer):
    """
    A denied event is dropped even when no handler exists for it, so it does
    not surface as a dispatch error.
    """

    class MinimalConsumer(AsyncConsumer):
        handler_allowlist = {"connection": set()}

        async def websocket_connect(self, message):
            await self.send({"type": "websocket.accept"})

        async def websocket_disconnect(self, message):
            raise StopConsumer()

    consumer = MinimalConsumer()
    communicator = await start_consumer(consumer)
    await communicator.send_input({"type": "totally.unknown"})
    await communicator.receive_nothing()
    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_worker_scope_receive_is_channel_layer(channel_layer):
    """
    In worker mode the ASGI receive callable feeds a named channel, so its
    messages count as channel layer events and use that grant.
    """

    class WorkerConsumer(AsyncConsumer):
        handler_allowlist = {"channel_layer": {"job.created"}}

        def __init__(self):
            self.calls = []

        async def job_created(self, message):
            self.calls.append(("job_created", self.event_source))
            raise StopConsumer()

        async def job_cancelled(self, message):
            self.calls.append(("job_cancelled", self.event_source))
            raise StopConsumer()

    scope = {"type": "channel", "channel": "worker-test"}

    consumer = WorkerConsumer()
    communicator = ApplicationCommunicator(consumer, scope)
    # Start the application task before feeding the input.
    communicator.future
    await communicator.send_input({"type": "job.created"})
    await communicator.wait()
    assert consumer.calls == [("job_created", "channel_layer")]

    # A handler not granted for the channel layer is dropped.
    denied = WorkerConsumer()
    denied.handler_allowlist = {"channel_layer": set()}
    denied_communicator = ApplicationCommunicator(denied, scope)
    denied_communicator.future
    await denied_communicator.send_input({"type": "job_cancelled"})
    await denied_communicator.wait()
    assert denied.calls == []
