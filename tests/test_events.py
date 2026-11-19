import asyncio
import unittest

import pytest

from channels.consumer import AsyncConsumer
from channels.events import (
    AsyncEventConsumer,
    EventBroker,
    Subscription,
    SyncEventConsumer,
    UnknownEventFieldError,
    assert_event_allowed,
    project_event,
)
from channels.exceptions import InvalidSubscription
from channels.layers import InMemoryChannelLayer, get_channel_layer

DUTY_EVENT = {
    "type": "duty.alert",
    "id": 4242,
    "severity": "P1",
    "actor": {
        "id": 7,
        "name": "alice",
        "contact": {"email": "alice@example.com", "phone": "555-0100"},
    },
    "payload": {"raw": "internal diagnostics", "steps": ["ack", "page", "close"]},
}


class ProjectionTests(unittest.TestCase):
    def test_none_fields_returns_full_deep_copy(self):
        projected = project_event(DUTY_EVENT, None)
        assert projected == DUTY_EVENT
        # The projection must be an independent copy.
        projected["actor"]["name"] = "mallory"
        projected["payload"]["steps"].append("tamper")
        assert DUTY_EVENT["actor"]["name"] == "alice"
        assert "tamper" not in DUTY_EVENT["payload"]["steps"]

    def test_nested_field_selection_and_type_kept(self):
        projected = project_event(
            DUTY_EVENT, ["id", "actor.name", "actor.contact.email"]
        )
        assert projected == {
            "type": "duty.alert",
            "id": 4242,
            "actor": {"name": "alice", "contact": {"email": "alice@example.com"}},
        }
        # Declared-but-absent fields are simply omitted.
        assert project_event(DUTY_EVENT, ["id", "actor.missing"]) == {
            "type": "duty.alert",
            "id": 4242,
        }

    def test_projection_never_mutates_source_or_other_projection(self):
        full = project_event(DUTY_EVENT, None)
        summary = project_event(DUTY_EVENT, ["id", "severity", "actor.name"])
        full["payload"]["raw"] = "changed"
        summary["severity"] = "P5"
        # Re-projecting the untouched source still yields the original values.
        again = project_event(DUTY_EVENT, ["id", "severity", "actor.name"])
        assert again["severity"] == "P1"
        assert DUTY_EVENT["payload"]["raw"] == "internal diagnostics"

    def test_invalid_field_declarations(self):
        with pytest.raises(InvalidSubscription):
            project_event(DUTY_EVENT, [])
        with pytest.raises(InvalidSubscription):
            project_event(DUTY_EVENT, [""])
        with pytest.raises(InvalidSubscription):
            project_event(DUTY_EVENT, ["actor..name"])
        with pytest.raises(InvalidSubscription):
            project_event(DUTY_EVENT, [123])

    def test_strict_rejection_of_unknown_top_level_and_nested_fields(self):
        # All top-level fields must be declared.
        with pytest.raises(UnknownEventFieldError, match="severity"):
            assert_event_allowed(DUTY_EVENT, ["id", "actor", "payload"])
        # A wholesale-declared mapping accepts anything nested inside it.
        assert_event_allowed(DUTY_EVENT, ["id", "severity", "actor", "payload"])
        # Selecting only some nested keys means the sibling key is unknown.
        with pytest.raises(UnknownEventFieldError, match="actor.contact.phone"):
            assert_event_allowed(
                DUTY_EVENT,
                ["id", "severity", "payload", "actor.id", "actor.name",
                 "actor.contact.email"],
            )

    def test_strict_check_ignores_routing_type(self):
        assert_event_allowed({"type": "x", "id": 1}, ["id"])


@pytest.fixture()
async def broker():
    layer = InMemoryChannelLayer(capacity=10)
    broker = EventBroker(layer)
    yield broker
    await layer.flush()
    await layer.close()


@pytest.fixture(autouse=True)
def reset_consumer_state():
    for consumer_cls in (
        ConsoleConsumer,
        ScreenConsumer,
        StrictScreenConsumer,
        LegacyConsumer,
        SyncScreenConsumer,
    ):
        consumer_cls.seen = []
        consumer_cls.event_broker = None
    yield


@pytest.mark.asyncio
async def test_two_subscriptions_same_message_are_isolated(broker):
    await broker.subscribe(Subscription("duty", "console"))
    await broker.subscribe(
        Subscription(
            "duty",
            "screen",
            fields=["id", "severity", "actor.name"],
        )
    )
    await broker.publish("duty", DUTY_EVENT)
    console_event = await broker.channel_layer.receive("console")
    screen_event = await broker.channel_layer.receive("screen")
    # Full-permission console keeps the entire event, including nested data.
    assert console_event == DUTY_EVENT
    # Summary screen only receives what it declared (+ routing type).
    assert screen_event == {
        "type": "duty.alert",
        "id": 4242,
        "severity": "P1",
        "actor": {"name": "alice"},
    }
    # Neither delivered object is the source object, and mutating one
    # delivery cannot rewrite what the other subscriber received.
    assert console_event is not DUTY_EVENT
    console_event["payload"]["raw"] = "rewritten"
    console_event["actor"]["name"] = "mallory"
    assert screen_event["actor"]["name"] == "alice"
    assert "payload" not in screen_event
@pytest.mark.asyncio
async def test_nested_data_projected_independently(broker):
    await broker.subscribe(
        Subscription("duty", "a", fields=["actor.contact"])
    )
    await broker.subscribe(
        Subscription("duty", "b", fields=["actor.contact.email"])
    )
    await broker.publish("duty", DUTY_EVENT)
    first = await broker.channel_layer.receive("a")
    second = await broker.channel_layer.receive("b")
    assert first["actor"]["contact"] == DUTY_EVENT["actor"]["contact"]
    assert second["actor"] == {"contact": {"email": "alice@example.com"}}
    first["actor"]["contact"]["phone"] = "000"
    assert second["actor"]["contact"] == {"email": "alice@example.com"}
@pytest.mark.asyncio
async def test_strict_subscription_rejects_unknown_field_atomically(broker):
    await broker.subscribe(Subscription("duty", "console"))
    await broker.subscribe(
        Subscription(
            "duty",
            "screen",
            fields=["id", "actor.name"],
            reject_unknown=True,
        )
    )
    with pytest.raises(UnknownEventFieldError):
        await broker.publish("duty", DUTY_EVENT)

    # The whole fan-out fails: even the permissive console gets nothing.
    with pytest.raises(asyncio.TimeoutError):
        async with asyncio.timeout(0.1):
            await broker.channel_layer.receive("console")


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery(broker):
    await broker.subscribe(Subscription("duty", "ch", fields=["id"]))
    await broker.unsubscribe("duty", "ch")
    await broker.publish("duty", DUTY_EVENT)
    with pytest.raises(asyncio.TimeoutError):
        async with asyncio.timeout(0.1):
            await broker.channel_layer.receive("ch")


@pytest.mark.asyncio
async def test_invalid_subscription_arguments(broker):
    with pytest.raises(InvalidSubscription):
        Subscription(topic="duty", channel_name="ch", fields=[])
    with pytest.raises(InvalidSubscription):
        Subscription(topic="duty", channel_name="ch", reject_unknown="yes")
    with pytest.raises(InvalidSubscription):
        await broker.subscribe(object())


def run_consumer(consumer):
    """
    Drives a consumer through its ASGI lifecycle. The receive callable only
    ever signals disconnect, so the consumer spends its life waiting on the
    channel layer and is cancelled at teardown.
    """

    async def receive():
        await asyncio.Event().wait()

    async def send(message):
        consumer.sent.append(message)

    consumer.sent = []
    task = asyncio.ensure_future(consumer({}, receive, send))
    return task


class ConsoleConsumer(AsyncEventConsumer):
    seen = []

    event_subscriptions = [{"topic": "duty", "reject_unknown": False}]

    async def duty_alert(self, event):
        self.seen.append(event)


class ScreenConsumer(AsyncEventConsumer):
    """Monitoring screen: summary fields only, unknown fields are dropped."""

    seen = []

    event_subscriptions = [
        {
            "topic": "duty",
            "fields": ["id", "severity", "actor.name"],
        }
    ]

    async def duty_alert(self, event):
        self.seen.append(event)


class StrictScreenConsumer(AsyncEventConsumer):
    """Summary screen that also refuses any undeclared field."""

    seen = []

    event_subscriptions = [
        {
            "topic": "duty",
            "fields": ["id", "severity", "actor.name"],
            "reject_unknown": True,
        }
    ]

    async def duty_alert(self, event):
        self.seen.append(event)


class LegacyConsumer(AsyncConsumer):
    """A plain consumer with no declarations must keep working untouched."""

    seen = []

    async def duty_alert(self, event):
        self.seen.append(event)


@pytest.mark.asyncio
async def test_end_to_end_two_consumers_see_their_own_declarations():
    layer = get_channel_layer()
    await layer.flush()
    shared_broker = EventBroker(layer)
    ConsoleConsumer.event_broker = shared_broker
    ScreenConsumer.event_broker = shared_broker

    console = ConsoleConsumer()
    screen = ScreenConsumer()
    tasks = [run_consumer(console), run_consumer(screen)]
    try:
        # Let both consumers join their subscriptions and get channel names.
        await asyncio.sleep(0.05)
        assert console.channel_name != screen.channel_name

        await shared_broker.publish("duty", DUTY_EVENT)
        await asyncio.sleep(0.05)

        assert len(ConsoleConsumer.seen) == 1
        assert len(ScreenConsumer.seen) == 1
        console_event = ConsoleConsumer.seen[-1]
        screen_event = ScreenConsumer.seen[-1]

        # Handlers receive content matching each subscription declaration.
        assert console_event == DUTY_EVENT
        assert screen_event == {
            "type": "duty.alert",
            "id": 4242,
            "severity": "P1",
            "actor": {"name": "alice"},
        }

        # Mutating one handler's view must not rewrite the other handler's.
        console_event["payload"]["raw"] = "rewritten"
        console_event["actor"]["name"] = "mallory"
        assert screen_event["actor"]["name"] == "alice"
        assert "payload" not in screen_event
        # And the original published event stays intact.
        assert DUTY_EVENT["payload"]["raw"] == "internal diagnostics"
    finally:
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await layer.flush()
        await layer.close()


@pytest.mark.asyncio
async def test_end_to_end_strict_consumer_rejects_event_with_undeclared_field():
    layer = get_channel_layer()
    await layer.flush()
    broker = EventBroker(layer)
    StrictScreenConsumer.event_broker = broker

    screen = StrictScreenConsumer()
    task = run_consumer(screen)
    try:
        await asyncio.sleep(0.05)
        # The screen declared only summary fields; the full event violates it.
        with pytest.raises(UnknownEventFieldError):
            await broker.publish("duty", DUTY_EVENT)
        await asyncio.sleep(0.05)
        assert StrictScreenConsumer.seen == []
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await layer.flush()
        await layer.close()


@pytest.mark.asyncio
async def test_end_to_end_legacy_consumer_without_subscription_is_unchanged():
    layer = get_channel_layer()
    await layer.flush()
    consumer = LegacyConsumer()
    task = run_consumer(consumer)
    try:
        await asyncio.sleep(0.05)
        await layer.send(
            consumer.channel_name, {"type": "duty.alert", "id": 1, "extra": True}
        )
        await asyncio.sleep(0.05)
        assert LegacyConsumer.seen == [
            {"type": "duty.alert", "id": 1, "extra": True}
        ]
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await layer.flush()
        await layer.close()


class SyncScreenConsumer(SyncEventConsumer):
    seen = []

    event_subscriptions = [
        {"topic": "duty", "fields": ["id", "severity", "actor.name"]}
    ]

    def duty_alert(self, event):
        self.seen.append(event)


@pytest.mark.asyncio
async def test_end_to_end_sync_event_consumer_projects_fields():
    layer = get_channel_layer()
    await layer.flush()
    broker = EventBroker(layer)
    SyncScreenConsumer.event_broker = broker

    consumer = SyncScreenConsumer()
    task = run_consumer(consumer)
    try:
        await asyncio.sleep(0.05)
        await broker.publish("duty", DUTY_EVENT)
        await asyncio.sleep(0.1)
        assert SyncScreenConsumer.seen == [
            {
                "type": "duty.alert",
                "id": 4242,
                "severity": "P1",
                "actor": {"name": "alice"},
            }
        ]
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await layer.flush()
        await layer.close()
