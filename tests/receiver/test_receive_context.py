"""Authorization ownership of an inbound delivery channel."""

import asyncio
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from taskiq_dependencies import Depends

from taskiq.abc.broker import AsyncBroker
from taskiq.abc.middleware import TaskiqMiddleware
from taskiq.acks import AckableMessage, SourcedMessage
from taskiq.brokers.inmemory_broker import InmemoryResultBackend
from taskiq.brokers.multi_broker import MultiBroker
from taskiq.context import Context
from taskiq.decor import AsyncTaskiqDecoratedTask
from taskiq.exceptions import SourceNotAuthorizedError
from taskiq.message import BrokerMessage, TaskiqMessage
from taskiq.receive_context import get_receive_context
from taskiq.receiver import Receiver
from taskiq.result import TaskiqResult


class RecordingSource:
    """Fake business connection that records how it was used."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.opened = 0
        self.closed = 0

    def open(self) -> "RecordingSource":
        self.opened += 1
        self.events.append("connection:open")
        return self

    def close(self) -> None:
        self.closed += 1
        self.events.append("connection:close")


class MemorySourceBroker(AsyncBroker):
    """Queue broker that delivers messages like a real listening channel."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        super().__init__()

    async def kick(self, message: BrokerMessage) -> None:
        await self.queue.put(message.message)

    async def listen(self) -> AsyncGenerator[AckableMessage, None]:
        while True:
            data = await self.queue.get()
            yield AckableMessage(data=data, ack=self.queue.task_done)


def make_broker(
    routing: dict[str, AsyncBroker],
) -> MultiBroker:
    broker = MultiBroker(routing=routing)
    broker.with_result_backend(InmemoryResultBackend())
    return broker


def make_receiver(broker: AsyncBroker) -> Receiver:
    return Receiver(
        broker,
        executor=ThreadPoolExecutor(max_workers=2),
        max_async_tasks=1,
    )


def encode(
    broker: AsyncBroker,
    task: AsyncTaskiqDecoratedTask[object, object],
) -> bytes:
    """Encode a delivery for a registered task with a fresh id."""
    message = TaskiqMessage(
        task_id=f"task-{uuid4().hex}",
        task_name=task.task_name,
        labels={},
        args=[],
        kwargs={},
    )
    return broker.formatter.dumps(message).message


def results_of(broker: AsyncBroker) -> list[TaskiqResult[object]]:
    backend = broker.result_backend
    assert isinstance(backend, InmemoryResultBackend)
    return list(backend.results.values())


async def test_approved_source_runs_and_other_source_is_rejected() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})

    @broker.task(allowed_sources=(approved,))
    async def connect() -> str:
        events.append("task:run")
        return "ok"

    receiver = make_receiver(broker)

    await receiver.callback(
        SourcedMessage(encode(broker, connect), approved),
    )
    await receiver.callback(
        SourcedMessage(encode(broker, connect), other),
    )

    assert events == ["task:run"]
    results = results_of(broker)
    assert len(results) == 2
    approved_result = next(result for result in results if not result.is_err)
    rejected_result = next(result for result in results if result.is_err)
    assert approved_result.return_value == "ok"
    assert isinstance(rejected_result.error, SourceNotAuthorizedError)
    assert rejected_result.error.task_name == connect.task_name


async def test_label_rewrite_in_middleware_cannot_grant_access() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})

    class SpoofingMiddleware(TaskiqMiddleware):
        def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
            message.labels["queue_name"] = "approved"
            message.labels["allowed_sources"] = "approved"
            return message

    broker.add_middlewares(SpoofingMiddleware())

    @broker.task(allowed_sources=(approved,))
    async def guarded() -> str:
        events.append("task:run")
        return "ran"

    receiver = make_receiver(broker)

    await receiver.callback(
        SourcedMessage(encode(broker, guarded), other),
    )

    assert events == []
    results = results_of(broker)
    assert len(results) == 1
    assert isinstance(results[0].error, SourceNotAuthorizedError)


async def test_connection_dependency_only_opens_for_approved_source() -> None:
    events: list[str] = []
    connection = RecordingSource(events)
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})

    async def connect_dependency() -> AsyncGenerator[RecordingSource, None]:
        receive_context = get_receive_context()
        assert receive_context is not None
        receive_context.require_source(approved)
        source = connection.open()
        try:
            yield source
        except Exception:
            source.close()
            events.append("dependency:failed")
            raise
        else:
            source.close()
            events.append("dependency:closed")

    @broker.task(allowed_sources=(approved,))
    async def use_connection(
        db: RecordingSource = Depends(connect_dependency),
    ) -> str:
        events.append("task:run")
        return "done"

    receiver = make_receiver(broker)

    await receiver.callback(
        SourcedMessage(encode(broker, use_connection), approved),
    )
    await receiver.callback(
        SourcedMessage(encode(broker, use_connection), other),
    )

    assert connection.opened == 1
    assert connection.closed == 1
    assert events == [
        "connection:open",
        "task:run",
        "connection:close",
        "dependency:closed",
    ]


async def test_business_error_closes_context_and_next_call_works() -> None:
    events: list[str] = []
    connection = RecordingSource(events)
    approved = MemorySourceBroker(events)
    broker = make_broker({"approved": approved})
    run_count = 0

    async def connect_dependency() -> AsyncGenerator[RecordingSource, None]:
        receive_context = get_receive_context()
        assert receive_context is not None
        source = connection.open()
        try:
            yield source
        except Exception:
            events.append("dependency:failed")
            raise
        else:
            events.append("dependency:closed")

    @broker.task(allowed_sources=(approved,))
    async def flaky(
        db: RecordingSource = Depends(connect_dependency),
    ) -> str:
        nonlocal run_count
        run_count += 1
        events.append(f"task:run:{run_count}")
        raise ValueError("business failure")

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, flaky), approved))
    assert get_receive_context() is None
    await receiver.callback(SourcedMessage(encode(broker, flaky), approved))

    assert run_count == 2
    assert connection.opened == 2
    assert events.count("dependency:failed") == 2
    assert get_receive_context() is None
    results = results_of(broker)
    assert len(results) == 2
    assert all(isinstance(result.error, ValueError) for result in results)


async def test_receive_context_is_isolated_between_interleaved_deliveries() -> None:
    events: list[str] = []
    first = MemorySourceBroker(events)
    second = MemorySourceBroker(events)
    broker = make_broker({"first": first, "second": second})
    seen: list[tuple[str, str]] = []

    @broker.task(allowed_sources=(first, second))
    async def probe(context: Context = Depends()) -> str:
        receive_context = context.receive_context
        assert receive_context is not None
        seen.append((id(receive_context.source), receive_context.task_name))
        return "ok"

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, probe), first))
    await receiver.callback(SourcedMessage(encode(broker, probe), second))

    assert seen == [
        (id(first), probe.task_name),
        (id(second), probe.task_name),
    ]
    assert get_receive_context() is None


async def test_rejection_skips_middlewares_and_acknowledges() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})
    acked = False

    class RecordingMiddleware(TaskiqMiddleware):
        def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
            events.append("middleware:pre_execute")
            return message

        def on_error(
            self,
            message: TaskiqMessage,
            result: TaskiqResult[object],
            exception: BaseException,
        ) -> None:
            events.append("middleware:on_error")

    broker.add_middlewares(RecordingMiddleware())

    @broker.task(allowed_sources=(approved,))
    async def guarded() -> None:
        events.append("task:run")

    def ack() -> None:
        nonlocal acked
        acked = True

    receiver = make_receiver(broker)
    denied = encode(broker, guarded)

    await receiver.callback(
        SourcedMessage(AckableMessage(data=denied, ack=ack), other),
    )

    assert events == []
    assert acked
    results = results_of(broker)
    assert len(results) == 1
    assert isinstance(results[0].error, SourceNotAuthorizedError)


async def test_tasks_without_allowed_sources_stay_unrestricted() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})

    @broker.task
    async def plain() -> str:
        events.append("task:run")
        return "ok"

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, plain), other))

    assert events == ["task:run"]
    results = results_of(broker)
    assert results[0].is_err is False
    assert results[0].return_value == "ok"


async def test_middleware_cannot_redirect_task_identity() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})

    @broker.task
    async def unrelated() -> None:
        events.append("task:unrelated")

    class RedirectingMiddleware(TaskiqMiddleware):
        def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
            message.task_name = "tests:unrelated"
            return message

    broker.add_middlewares(RedirectingMiddleware())

    @broker.task(allowed_sources=(approved,))
    async def guarded() -> str:
        events.append("task:run")
        return "ok"

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, guarded), other))

    assert events == []
    results = results_of(broker)
    assert len(results) == 1
    assert isinstance(results[0].error, SourceNotAuthorizedError)


def test_allowed_sources_is_kept_out_of_labels() -> None:
    source = MemorySourceBroker([])
    broker = make_broker({"approved": source})

    @broker.task(allowed_sources=(source,), marker="visible")
    async def guarded() -> None: ...

    assert guarded.allowed_sources == (source,)
    assert "allowed_sources" not in guarded.labels
    assert guarded.labels.get("marker") == "visible"


async def test_receive_context_is_bound_through_thread_execution() -> None:
    events: list[str] = []
    broker = MemorySourceBroker(events)
    broker.with_result_backend(InmemoryResultBackend())
    seen: list[str] = []

    @broker.task(allowed_sources=(broker,))
    def sync_task() -> str:
        receive_context = get_receive_context()
        assert receive_context is not None
        seen.append(receive_context.task_name)
        return "ok"

    receiver = make_receiver(broker)

    result = await receiver.run_task(
        sync_task.original_func,
        TaskiqMessage(
            task_id="task-id",
            task_name=sync_task.task_name,
            labels={},
            args=[],
            kwargs={},
        ),
    )

    assert result.return_value == "ok"
    assert seen == [sync_task.task_name]
    assert get_receive_context() is None


async def test_direct_run_task_rejects_composite_without_approval() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    broker = make_broker({"approved": approved})

    @broker.task(allowed_sources=(approved,))
    def guarded() -> str:
        events.append("task:run")
        return "ok"

    receiver = make_receiver(broker)

    result = await receiver.run_task(
        guarded.original_func,
        TaskiqMessage(
            task_id="task-id",
            task_name=guarded.task_name,
            labels={},
            args=[],
            kwargs={},
        ),
    )

    assert result.is_err
    assert isinstance(result.error, SourceNotAuthorizedError)
    assert events == []
    assert get_receive_context() is None


async def test_interleaved_deliveries_through_real_listener() -> None:
    """Two in-memory brokers deliver the same task name to one receiver."""
    events: list[str] = []
    connection = RecordingSource(events)
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    broker = make_broker({"approved": approved, "other": other})
    executions: list[str] = []

    async def connect_dependency() -> AsyncGenerator[RecordingSource, None]:
        receive_context = get_receive_context()
        assert receive_context is not None
        receive_context.require_source(approved)
        source = connection.open()
        try:
            yield source
        except Exception:
            source.close()
            events.append("dependency:failed")
            raise
        else:
            source.close()
            events.append("dependency:closed")

    @broker.task(allowed_sources=(approved,))
    async def same_name(
        db: RecordingSource = Depends(connect_dependency),
    ) -> str:
        executions.append("run")
        return "ok"

    # Interleave the two channels in strict alternation.
    for index in range(2):
        source = approved if index % 2 == 0 else other
        task_id = f"task-{index}"
        payload = TaskiqMessage(
            task_id=task_id,
            task_name=same_name.task_name,
            labels={},
            args=[],
            kwargs={},
        )
        await source.kick(broker.formatter.dumps(payload))

    receiver = Receiver(
        broker,
        executor=ThreadPoolExecutor(max_workers=2),
        max_async_tasks=1,
        max_prefetch=1,
        run_startup=False,
    )
    finish_event = asyncio.Event()
    listen_task = asyncio.create_task(receiver.listen(finish_event))
    try:
        await asyncio.wait_for(other.queue.join(), timeout=5)
        await asyncio.wait_for(approved.queue.join(), timeout=5)
    finally:
        finish_event.set()
        await asyncio.wait_for(listen_task, timeout=5)

    assert executions == ["run"]
    assert connection.opened == 1
    assert connection.closed == 1
    backend = broker.result_backend
    assert isinstance(backend, InmemoryResultBackend)
    assert backend.results["task-0"].return_value == "ok"
    assert isinstance(backend.results["task-1"].error, SourceNotAuthorizedError)
    assert get_receive_context() is None


async def test_middleware_can_add_ordinary_labels_for_approved_source() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    broker = make_broker({"approved": approved})
    seen_labels: list[dict[str, object]] = []

    class LabelingMiddleware(TaskiqMiddleware):
        def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
            message.labels["tenant"] = "internal"
            return message

    broker.add_middlewares(LabelingMiddleware())

    @broker.task(allowed_sources=(approved,))
    async def labeled(context: Context = Depends()) -> str:
        seen_labels.append(dict(context.message.labels))
        return "ok"

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, labeled), approved))

    assert seen_labels == [{"tenant": "internal"}]
    results = results_of(broker)
    assert results[0].is_err is False


async def test_register_task_supports_allowed_sources() -> None:
    events: list[str] = []
    approved = MemorySourceBroker(events)
    broker = make_broker({"approved": approved})

    async def plain_body() -> str:
        events.append("task:run")
        return "ok"

    task = broker.register_task(
        plain_body,
        task_name="registered:guarded",
        allowed_sources=(approved,),
    )

    receiver = make_receiver(broker)

    await receiver.callback(SourcedMessage(encode(broker, task), approved))

    assert task.allowed_sources == (approved,)
    assert "allowed_sources" not in task.labels
    assert events == ["task:run"]


async def test_two_receivers_share_global_task_name() -> None:
    """Two independent receivers in one worker see the same task name."""
    events: list[str] = []
    approved = MemorySourceBroker(events)
    other = MemorySourceBroker(events)
    approved.with_result_backend(InmemoryResultBackend())
    other.with_result_backend(InmemoryResultBackend())

    @approved.task(task_name="shared:connect", allowed_sources=(approved,))
    async def connect() -> str:
        events.append("task:run")
        return "ok"

    # One worker process, two receive entrypoints, one shared task definition.
    AsyncBroker.global_task_registry[connect.task_name] = connect
    try:
        approved_receiver = make_receiver(approved)
        other_receiver = make_receiver(other)

        approved_delivery = SourcedMessage(encode(approved, connect), approved)
        other_delivery = SourcedMessage(encode(other, connect), other)

        await approved_receiver.callback(approved_delivery)
        await other_receiver.callback(other_delivery)

        assert events == ["task:run"]
        approved_results = results_of(approved)
        other_results = results_of(other)
        assert approved_results[0].return_value == "ok"
        assert isinstance(other_results[0].error, SourceNotAuthorizedError)
    finally:
        AsyncBroker.global_task_registry.pop(connect.task_name, None)
