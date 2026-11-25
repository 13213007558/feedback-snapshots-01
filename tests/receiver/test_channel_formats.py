"""Channel-bound message format selection in the receiver."""

import asyncio
import threading
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from taskiq_dependencies import Depends

from taskiq import ChannelFormat, ChannelFormatPolicy, MultiBroker
from taskiq.abc.broker import AsyncBroker
from taskiq.acks import AckableMessage
from taskiq.brokers.inmemory_broker import InMemoryBroker, InmemoryResultBackend
from taskiq.formatters.json_formatter import JSONFormatter
from taskiq.formatters.proxy_formatter import ProxyFormatter
from taskiq.message import BrokerMessage, TaskiqMessage
from taskiq.receiver import Receiver


class _RecordingFormatter(JSONFormatter):
    """JSON formatter that records every payload it is asked to parse."""

    def __init__(self, name: str, events: list[str]) -> None:
        self.name = name
        self.events = events

    def loads(self, message: bytes) -> TaskiqMessage:
        self.events.append(f"loads:{self.name}")
        return super().loads(message)


def _message(task_name: str, task_id: str = "task-id") -> TaskiqMessage:
    return TaskiqMessage(
        task_id=task_id,
        task_name=task_name,
        labels={},
        args=[],
        kwargs={},
    )


def _producer_formatter(broker: AsyncBroker) -> ProxyFormatter:
    return ProxyFormatter(broker)


def _upgraded_formatter() -> JSONFormatter:
    return JSONFormatter()


def _policy(
    broker: AsyncBroker,
    *,
    old_versions: tuple[str, ...] = ("proxy",),
    new_versions: tuple[str, ...] = ("json",),
) -> ChannelFormatPolicy:
    old = tuple(
        ChannelFormat(_producer_formatter(broker), version=version, legacy=True)
        for version in old_versions
    )
    new = tuple(
        ChannelFormat(_upgraded_formatter(), version=version)
        for version in new_versions
    )
    return ChannelFormatPolicy(
        channels={"legacy": old, "upgraded": new},
        default_channel="upgraded",
    )


class _RecordingBroker(AsyncBroker):
    """Queue broker that lets tests push arbitrary tagged deliveries."""

    def __init__(self) -> None:
        super().__init__()
        self.incoming: asyncio.Queue[bytes | AckableMessage] = asyncio.Queue()

    async def kick(self, message: BrokerMessage) -> None:
        await self.incoming.put(message.message)

    async def listen(self) -> AsyncGenerator[bytes | AckableMessage, None]:
        while True:
            yield await self.incoming.get()


async def _deliver(
    receiver: Receiver,
    broker: AsyncBroker,
    payload: bytes,
    channel: str,
    acks: list[str],
) -> None:
    """Send one tagged delivery through the receiver callback."""
    def ack() -> None:
        acks.append(channel)

    await receiver.callback(
        AckableMessage(data=payload, ack=ack, channel=channel),
    )


async def test_legacy_channel_uses_its_approved_formatter_and_runs_business() -> None:
    """A legacy channel pays the legacy formatter, business and ack."""
    events: list[str] = []
    acks: list[str] = []
    broker = InMemoryBroker()
    broker.with_channel_formats(_policy(broker))
    broker.with_result_backend(InmemoryResultBackend())

    @broker.task
    async def my_task() -> str:
        events.append("business")
        return "ok"

    decisions: list[Any] = []
    receiver = Receiver(broker=broker, on_format_selected=decisions.append)
    payload = _producer_formatter(broker).dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "legacy", acks)

    assert [(d.channel, d.version) for d in decisions] == [("legacy", "proxy")]
    assert decisions[0].legacy is True
    assert events == ["business"]
    assert acks == ["legacy"]


async def test_upgraded_channel_uses_upgraded_formatter_and_runs_business() -> None:
    """An upgraded channel is parsed by the upgraded formatter only."""
    events: list[str] = []
    acks: list[str] = []
    broker = InMemoryBroker()
    proxy = _RecordingFormatter("proxy", events)
    upgraded = _RecordingFormatter("json", events)
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={
                "legacy": (ChannelFormat(_producer_formatter(broker), legacy=True),),
                "upgraded": (ChannelFormat(upgraded),),
            },
            default_channel="upgraded",
        ),
    )
    broker.with_result_backend(InmemoryResultBackend())
    broker.formatter = proxy  # legacy broker-wide formatter must be ignored

    @broker.task
    async def my_task() -> str:
        events.append("business")
        return "ok"

    decisions: list[Any] = []
    receiver = Receiver(broker=broker, on_format_selected=decisions.append)
    payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "upgraded", acks)

    assert [(d.channel, d.version) for d in decisions] == [("upgraded", "json")]
    assert decisions[0].legacy is False
    assert events == ["loads:json", "business"]
    assert acks == ["upgraded"]


async def test_cross_channel_payload_is_rejected_without_business() -> None:
    """A valid payload cannot be accepted through a channel that lacks its format."""
    events: list[str] = []
    acks: list[str] = []
    rejections: list[Any] = []
    broker = InMemoryBroker()
    broker.with_channel_formats(_policy(broker))
    broker.with_result_backend(InmemoryResultBackend())

    @broker.task
    async def my_task() -> str:
        events.append("business")
        return "ok"

    decisions: list[Any] = []
    receiver = Receiver(
        broker=broker,
        on_format_rejected=rejections.append,
        on_format_selected=decisions.append,
    )
    # A genuinely valid upgraded payload sent to the legacy-only channel.
    payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "legacy", acks)

    assert decisions == []
    assert events == []
    assert acks == ["legacy"]
    assert rejections[0].reason == "format-mismatch"
    assert rejections[0].channel == "legacy"
    assert rejections[0].allowed_versions == ("proxy",)


async def test_parse_failure_terminates_without_fallback() -> None:
    """A parse error is terminal: no second formatter, no business, one ack."""
    events: list[str] = []
    acks: list[str] = []
    rejections: list[Any] = []
    broker = InMemoryBroker()
    proxy = _RecordingFormatter("proxy", events)
    upgraded = _RecordingFormatter("json", events)
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={
                "legacy": (ChannelFormat(_producer_formatter(broker), legacy=True),),
                "upgraded": (ChannelFormat(upgraded),),
            },
            default_channel="upgraded",
        ),
    )
    broker.with_result_backend(InmemoryResultBackend())

    @broker.task
    async def my_task() -> str:
        events.append("business")
        return "ok"

    receiver = Receiver(broker=broker, on_format_rejected=rejections.append)

    # Shape-valid prefix but truncated JSON: the selected formatter fails.
    payload = b'{"task_id":"id","task_name":"n"'

    await _deliver(receiver, broker, payload, "upgraded", acks)

    # Exactly one parse attempt by the selected formatter, then a stop.
    assert events == ["loads:json"]
    assert acks == ["upgraded"]
    assert len(rejections) == 1
    assert rejections[0].reason == "parse-error"
    assert rejections[0].version == "json"
    assert rejections[0].generation >= 0
    assert proxy is not None


async def test_unknown_channel_is_rejected_diagnosably() -> None:
    """Deliveries from unmanaged channels never reach a managed formatter."""
    events: list[str] = []
    acks: list[str] = []
    rejections: list[Any] = []
    broker = InMemoryBroker()
    broker.with_channel_formats(_policy(broker))

    @broker.task
    async def my_task() -> None:
        events.append("business")

    receiver = Receiver(broker=broker, on_format_rejected=rejections.append)
    payload = _producer_formatter(broker).dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "unmanaged", acks)

    assert events == []
    assert acks == ["unmanaged"]
    assert rejections[0].reason == "unknown-channel"


def test_reload_during_parse_keeps_old_decision_for_in_flight_message() -> None:
    """A reload mid-parse leaves the in-flight message on its snapshot."""
    events: list[str] = []
    acks: list[str] = []
    broker = InMemoryBroker()
    backend = InmemoryResultBackend()
    broker.with_result_backend(backend)

    entered = threading.Event()
    release = threading.Event()

    class BlockingFormatter(JSONFormatter):
        def loads(self, message: bytes) -> TaskiqMessage:
            entered.set()
            # A reload happens on the main thread while this delivery parses.
            assert release.wait(timeout=5)
            return super().loads(message)

    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={
                "legacy": (ChannelFormat(_producer_formatter(broker), legacy=True),),
                "upgraded": (ChannelFormat(BlockingFormatter()),),
            },
            default_channel="upgraded",
        ),
    )

    @broker.task
    async def my_task() -> str:
        events.append("business")
        return "ok"

    receiver = Receiver(broker=broker)
    first = _upgraded_formatter().dumps(_message(my_task.task_name, "one")).message
    errors: list[BaseException] = []

    def run_first() -> None:
        try:
            asyncio.run(_deliver(receiver, broker, first, "upgraded", acks))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=run_first)
    worker.start()
    assert entered.wait(timeout=5)

    # Retire the upgraded channel while the first message is still parsing.
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={
                "legacy": (ChannelFormat(_producer_formatter(broker), legacy=True),),
            },
            default_channel="legacy",
        ),
    )
    release.set()
    worker.join(timeout=5)

    assert errors == []
    assert events == ["business"]
    assert acks == ["upgraded"]
    # The in-flight message saved its result under the decision it started with.
    assert asyncio.run(backend.is_result_ready("one"))
    assert asyncio.run(backend.get_result("one")).return_value == "ok"

    # Subsequent deliveries follow the new policy: upgraded is now unknown.
    rejections: list[Any] = []
    receiver.on_format_rejected = rejections.append
    second = _upgraded_formatter().dumps(_message(my_task.task_name, "two")).message
    asyncio.run(_deliver(receiver, broker, second, "upgraded", acks))

    assert events == ["business"]
    assert not asyncio.run(backend.is_result_ready("two"))
    assert rejections[0].reason == "unknown-channel"
    assert rejections[0].generation > 1


async def test_transition_keeps_old_producer_on_its_approved_version() -> None:
    """A channel may approve both versions during the migration window."""
    events: list[str] = []
    acks: list[str] = []
    broker = InMemoryBroker()
    legacy_version = ChannelFormat(
        _producer_formatter(broker),
        version="proxy",
        legacy=True,
    )
    upgraded_version = ChannelFormat(_upgraded_formatter(), version="json")
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={"tasks": (legacy_version, upgraded_version)},
            default_channel="tasks",
        ),
    )

    @broker.task
    async def my_task() -> None:
        events.append("business")

    decisions: list[Any] = []
    receiver = Receiver(broker=broker, on_format_selected=decisions.append)
    old_payload = _producer_formatter(broker).dumps(_message(my_task.task_name)).message
    new_payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, old_payload, "tasks", acks)
    await _deliver(receiver, broker, new_payload, "tasks", acks)

    # Each producer stays on its own approved version by wire signature.
    assert [(d.version, d.reason) for d in decisions] == [
        ("proxy", "matched"),
        ("json", "matched"),
    ]
    assert [d.legacy for d in decisions] == [True, False]
    assert events == ["business", "business"]
    assert acks == ["tasks", "tasks"]


async def test_transition_drops_legacy_version_after_reload() -> None:
    """After the transition ends, the old version no longer parses."""
    events: list[str] = []
    acks: list[str] = []
    rejections: list[Any] = []
    broker = InMemoryBroker()
    legacy_version = ChannelFormat(
        _producer_formatter(broker),
        version="proxy",
        legacy=True,
    )
    upgraded_version = ChannelFormat(_upgraded_formatter(), version="json")
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={"tasks": (legacy_version, upgraded_version)},
            default_channel="tasks",
        ),
    )

    @broker.task
    async def my_task() -> None:
        events.append("business")

    receiver = Receiver(broker=broker, on_format_rejected=rejections.append)
    old_payload = _producer_formatter(broker).dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, old_payload, "tasks", acks)
    assert events == ["business"]

    # Reload: the legacy version is retired, only the upgraded one remains.
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={"tasks": (upgraded_version,)},
            default_channel="tasks",
        ),
    )
    await _deliver(receiver, broker, old_payload, "tasks", acks)

    assert events == ["business"]
    assert acks == ["tasks", "tasks"]
    assert rejections[0].reason == "format-mismatch"
    assert rejections[0].allowed_versions == ("json",)


async def test_multi_broker_tags_delivery_with_source_channel() -> None:
    """MultiBroker attributes each merged delivery to its routing label."""
    events: list[str] = []
    acks: list[str] = []

    class DirectBroker(AsyncBroker):
        def __init__(self) -> None:
            super().__init__()
            self.queue: asyncio.Queue[bytes] = asyncio.Queue()

        async def kick(self, message: BrokerMessage) -> None:
            await self.queue.put(message.message)

        async def listen(self) -> AsyncGenerator[bytes, None]:
            while True:
                yield await self.queue.get()

    legacy, upgraded = DirectBroker(), DirectBroker()
    broker = MultiBroker(
        routing={"legacy": legacy, "upgraded": upgraded},
        default_routing_label="upgraded",
    )
    broker.with_channel_formats(_policy(broker))

    @broker.task
    async def my_task() -> None:
        events.append("business")

    receiver = Receiver(broker=broker)
    legacy_payload = _producer_formatter(broker).dumps(
        _message(my_task.task_name),
    ).message
    upgraded_payload = _upgraded_formatter().dumps(
        _message(my_task.task_name),
    ).message
    await legacy.kick(BrokerMessage(
        task_id="1", task_name=my_task.task_name, message=legacy_payload, labels={},
    ))
    await upgraded.kick(BrokerMessage(
        task_id="2", task_name=my_task.task_name, message=upgraded_payload, labels={},
    ))

    listener = broker.listen()
    for expected in ("legacy", "upgraded"):
        delivery = await asyncio.wait_for(listener.__anext__(), timeout=1)
        assert isinstance(delivery, AckableMessage)
        assert delivery.channel == expected
        await _deliver(receiver, broker, delivery.data, delivery.channel or "", acks)
    await listener.aclose()

    assert events == ["business", "business"]
    assert sorted(acks) == ["legacy", "upgraded"]


async def test_business_dependencies_are_not_resolved_on_rejection() -> None:
    """A rejected delivery never expands business dependencies."""
    events: list[str] = []
    broker = InMemoryBroker()
    broker.with_channel_formats(_policy(broker))

    def dependency() -> str:
        events.append("dependency")
        return "opened"

    @broker.task
    async def my_task(value: str = Depends(dependency)) -> None:
        events.append("business")

    receiver = Receiver(broker=broker)
    payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message
    await _deliver(receiver, broker, payload, "legacy", [])

    assert events == []


@pytest.mark.parametrize("reason", ["format-mismatch", "parse-error"])
async def test_rejection_does_not_save_a_result(reason: str) -> None:
    """Rejected deliveries write no result, even when the task exists."""
    broker = InMemoryBroker()
    backend = InmemoryResultBackend()
    broker.with_result_backend(backend)
    broker.with_channel_formats(_policy(broker))

    @broker.task
    async def my_task() -> None: ...

    receiver = Receiver(broker=broker)
    if reason == "format-mismatch":
        payload = b"not-a-managed-format"
    else:
        payload = b'{"task_id":"task-id","task_name":'  # truncated
    await _deliver(receiver, broker, payload, "upgraded", [])

    assert "task-id" not in backend.results


class _OpinionlessFormatter(JSONFormatter):
    """Formatter that never claims or rejects a wire version."""

    def matches(self, message: bytes) -> bool | None:
        return None


async def test_opinionless_formatters_follow_declared_order() -> None:
    """When no formatter claims the payload, declaration order decides."""
    broker = InMemoryBroker()
    first = _OpinionlessFormatter()
    second = _OpinionlessFormatter()
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={
                "tasks": (
                    ChannelFormat(first, version="v2"),
                    ChannelFormat(second, version="v1"),
                ),
            },
            default_channel="tasks",
        ),
    )

    @broker.task
    async def my_task() -> None: ...

    decisions: list[Any] = []
    receiver = Receiver(broker=broker, on_format_selected=decisions.append)
    payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "tasks", [])

    assert len(decisions) == 1
    assert decisions[0].version == "v2"
    assert decisions[0].reason == "unverified"
    assert decisions[0].formatter is first


async def test_unmanaged_channel_falls_back_to_broker_formatter() -> None:
    """Without a policy the legacy broker-wide formatter is used unchanged."""
    broker = InMemoryBroker()
    events: list[str] = []
    broker.formatter = _RecordingFormatter("broker", events)

    @broker.task
    async def my_task() -> None: ...

    decisions: list[Any] = []
    receiver = Receiver(broker=broker, on_format_selected=decisions.append)
    payload = broker.formatter.dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "legacy", [])

    assert [d.reason for d in decisions] == ["unmanaged"]
    assert events == ["loads:broker"]


async def test_mismatched_payload_on_shared_channel_is_rejected_once() -> None:
    """A channel approves a single version: the other version must not parse."""
    events: list[str] = []
    acks: list[str] = []
    rejections: list[Any] = []
    broker = InMemoryBroker()
    broker.with_channel_formats(
        ChannelFormatPolicy(
            channels={"tasks": (ChannelFormat(_producer_formatter(broker)),)},
            default_channel="tasks",
        ),
    )

    @broker.task
    async def my_task() -> None:
        events.append("business")

    receiver = Receiver(broker=broker, on_format_rejected=rejections.append)
    # The upgraded payload is genuine but the channel approves only proxy.
    payload = _upgraded_formatter().dumps(_message(my_task.task_name)).message

    await _deliver(receiver, broker, payload, "tasks", acks)

    assert events == []
    assert acks == ["tasks"]
    assert [r.reason for r in rejections] == ["format-mismatch"]
    assert rejections[0].generation == 1
