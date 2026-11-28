"""
Acceptance tests for switching the shared broker's default channel.

A service migrates its shared tasks from an "old" broker generation
to a "new" one, and may roll back. The switch happens while pending
kickers are already created and the same task name is registered on
both generations. Real shared-task decorators, kickers and result
handles are used; only the broker and the result backend are replaced
by independent in-memory doubles.

Both generations deliberately return identical task ids and business
values, so the only way to attribute a task to a channel generation
is the journal: it records a single correlation id at three points -
before sending, when the message is actually stored in the double,
and when the result is fetched.
"""

import uuid
from collections.abc import AsyncGenerator, Generator
from dataclasses import dataclass
from typing import Any

import pytest

from taskiq.abc.broker import AsyncBroker
from taskiq.abc.result_backend import AsyncResultBackend
from taskiq.brokers.shared_broker import async_shared_broker, shared_task
from taskiq.exceptions import SendTaskError
from taskiq.kicker import AsyncKicker
from taskiq.message import BrokerMessage
from taskiq.result import TaskiqResult
from taskiq.task import AsyncTaskiqTask

OLD = "old"
NEW = "new"
PUBLISHER = "publisher"
TASK_NAME = "migration.acceptance.business_task"
BUSINESS_VALUE = "same-business-value"

PRE_SEND = "pre_send"
STORE = "store"
GET_RESULT = "get_result"


@dataclass(frozen=True)
class JournalEntry:
    """A single recorded point of a task's life."""

    channel: str
    point: str
    correlation: str
    task_id: str


class Journal:
    """Ordered publication/fetch log for on-call inspection."""

    def __init__(self) -> None:
        self.entries: list[JournalEntry] = []

    def record(
        self,
        channel: str,
        point: str,
        correlation: str,
        task_id: str,
    ) -> None:
        """Append one observed point of a correlated task."""
        self.entries.append(JournalEntry(channel, point, correlation, task_id))

    def channels(self, point: str, correlation: str) -> list[str]:
        """Channels that recorded a point for a correlation id, in order."""
        return [
            entry.channel
            for entry in self.entries
            if entry.point == point and entry.correlation == correlation
        ]


class ChannelResultBackend(AsyncResultBackend[str]):
    """In-memory result backend double that journals every fetch."""

    def __init__(self, channel: str, journal: Journal) -> None:
        self.channel = channel
        self.journal = journal
        self.results: dict[str, TaskiqResult[str]] = {}

    async def set_result(self, task_id: str, result: TaskiqResult[str]) -> None:
        """Store a result of an execution."""
        self.results[task_id] = result

    async def is_result_ready(self, task_id: str) -> bool:
        """Check that a result is present."""
        return task_id in self.results

    async def get_result(
        self,
        task_id: str,
        with_logs: bool = False,
    ) -> TaskiqResult[str]:
        """Fetch a result and journal the correlation id it carries."""
        result = self.results[task_id]
        self.journal.record(
            self.channel,
            GET_RESULT,
            str(result.labels["correlation"]),
            task_id,
        )
        return result


class ChannelBroker(AsyncBroker):
    """In-memory broker double that journals every stored message."""

    def __init__(
        self,
        channel: str,
        journal: Journal,
        result_backend: ChannelResultBackend,
    ) -> None:
        super().__init__()
        self.channel = channel
        self.journal = journal
        self.outbox: dict[str, BrokerMessage] = {}
        self.failures_left = 0
        self.with_result_backend(result_backend)

    async def kick(self, message: BrokerMessage) -> None:
        """Store the message or fail if the channel is down."""
        if self.failures_left > 0:
            self.failures_left -= 1
            raise ConnectionError(f"{self.channel} channel is not available")
        self.outbox[message.task_id] = message
        correlation = str(message.labels["correlation"])
        self.journal.record(self.channel, STORE, correlation, message.task_id)
        # Simulate a worker on this channel executing the task.
        # Both generations deliberately produce the same business value.
        await self.result_backend.set_result(
            message.task_id,
            TaskiqResult(
                is_err=False,
                return_value=BUSINESS_VALUE,
                execution_time=0.0,
                labels={"correlation": correlation},
            ),
        )

    def listen(self) -> AsyncGenerator[bytes, None]:
        """Channel doubles cannot listen."""
        raise RuntimeError("Channel doubles cannot listen.")


class CurrentDefaultResultHandle:
    """
    Broken migration double.

    It resolves the result backend from the shared broker's *current*
    default instead of the channel that accepted the task. This is the
    mistake the journal-based acceptance checks must catch.
    """

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id

    async def get_result(self) -> TaskiqResult[Any]:
        """Fetch the result from whatever generation is default now."""
        broker = async_shared_broker._default_broker
        assert broker is not None
        return await broker.result_backend.get_result(self.task_id)


class MigrationHarness:
    """Two channel generations behind the real shared broker."""

    def __init__(self) -> None:
        self.journal = Journal()
        self.old_backend = ChannelResultBackend(OLD, self.journal)
        self.new_backend = ChannelResultBackend(NEW, self.journal)
        self.old_broker = ChannelBroker(OLD, self.journal, self.old_backend)
        self.new_broker = ChannelBroker(NEW, self.journal, self.new_backend)

        async def business_task() -> str:
            return BUSINESS_VALUE

        # Publishers use the real shared task decorator, while the same
        # task name is registered on both generations, as it would be
        # during a real migration.
        self.shared = shared_task(task_name=TASK_NAME)(business_task)
        self.old_broker.register_task(business_task, task_name=TASK_NAME)
        self.new_broker.register_task(business_task, task_name=TASK_NAME)


@pytest.fixture
def harness() -> Generator[MigrationHarness, None, None]:
    """Start on the old generation and reset the shared broker after."""
    migration = MigrationHarness()
    async_shared_broker.default_broker(migration.old_broker)
    yield migration
    async_shared_broker._default_broker = None


async def publish(
    harness: MigrationHarness,
    kicker: AsyncKicker[Any, Any],
    correlation: str,
) -> AsyncTaskiqTask[str]:
    """Send one logical task, journaling the correlation id beforehand."""
    harness.journal.record(PUBLISHER, PRE_SEND, correlation, correlation)
    return await kicker.with_task_id(correlation).with_labels(
        correlation=correlation,
    ).kiq()


def assert_stored_on(journal: Journal, correlation: str, channel: str) -> None:
    """The message was stored exactly once, on the expected generation."""
    assert journal.channels(STORE, correlation) == [channel]


def assert_fetched_from(
    journal: Journal,
    correlation: str,
    channels: list[str],
) -> None:
    """Result fetches happened on the expected generations, in order."""
    assert journal.channels(GET_RESULT, correlation) == channels


def test_same_task_name_registered_on_both_generations(
    harness: MigrationHarness,
) -> None:
    assert TASK_NAME in harness.old_broker.local_task_registry
    assert TASK_NAME in harness.new_broker.local_task_registry


async def test_pending_kicker_keeps_old_generation_after_switch(
    harness: MigrationHarness,
) -> None:
    # The pending send handle is created while the old generation
    # is still the default one.
    pending = harness.shared.kicker()

    async_shared_broker.default_broker(harness.new_broker)

    correlation = uuid.uuid4().hex
    task = await publish(harness, pending, correlation)

    assert isinstance(task, AsyncTaskiqTask)
    assert task.task_id == correlation
    assert task.result_backend is harness.old_backend
    assert_stored_on(harness.journal, correlation, OLD)
    assert harness.new_broker.outbox == {}

    result = await task.get_result()
    assert result.return_value == BUSINESS_VALUE
    assert_fetched_from(harness.journal, correlation, [OLD])

    # The whole life of the task is attributable to the old generation.
    assert harness.journal.entries == [
        JournalEntry(PUBLISHER, PRE_SEND, correlation, correlation),
        JournalEntry(OLD, STORE, correlation, correlation),
        JournalEntry(OLD, GET_RESULT, correlation, correlation),
    ]


async def test_fresh_kicker_uses_new_generation_after_switch(
    harness: MigrationHarness,
) -> None:
    async_shared_broker.default_broker(harness.new_broker)

    correlation = uuid.uuid4().hex
    task = await publish(harness, harness.shared.kicker(), correlation)

    assert task.result_backend is harness.new_backend
    assert_stored_on(harness.journal, correlation, NEW)
    assert harness.old_broker.outbox == {}

    result = await task.wait_result(timeout=1.0)
    assert result.return_value == BUSINESS_VALUE
    assert_fetched_from(harness.journal, correlation, [NEW])


async def test_rollback_preserves_fetch_attribution_of_sent_tasks(
    harness: MigrationHarness,
) -> None:
    before_switch = await publish(
        harness,
        harness.shared.kicker(),
        uuid.uuid4().hex,
    )

    async_shared_broker.default_broker(harness.new_broker)
    on_new = await publish(harness, harness.shared.kicker(), uuid.uuid4().hex)

    # Rollback to the old generation.
    async_shared_broker.default_broker(harness.old_broker)
    after_rollback = await publish(
        harness,
        harness.shared.kicker(),
        uuid.uuid4().hex,
    )

    # Explicit-broker control still reaches the new generation
    # while the default points back to the old one.
    explicit = await publish(
        harness,
        harness.shared.kicker().with_broker(harness.new_broker),
        uuid.uuid4().hex,
    )

    for task, channel in (
        (before_switch, OLD),
        (on_new, NEW),
        (after_rollback, OLD),
        (explicit, NEW),
    ):
        result = await task.get_result()
        assert result.return_value == BUSINESS_VALUE
        assert_fetched_from(harness.journal, task.task_id, [channel])


async def test_explicit_broker_control_bypasses_default(
    harness: MigrationHarness,
) -> None:
    via_new = await publish(
        harness,
        harness.shared.kicker().with_broker(harness.new_broker),
        uuid.uuid4().hex,
    )

    async_shared_broker.default_broker(harness.new_broker)
    via_old = await publish(
        harness,
        harness.shared.kicker().with_broker(harness.old_broker),
        uuid.uuid4().hex,
    )

    assert_stored_on(harness.journal, via_new.task_id, NEW)
    assert_stored_on(harness.journal, via_old.task_id, OLD)

    assert (await via_new.get_result()).return_value == BUSINESS_VALUE
    assert (await via_old.get_result()).return_value == BUSINESS_VALUE
    assert_fetched_from(harness.journal, via_new.task_id, [NEW])
    assert_fetched_from(harness.journal, via_old.task_id, [OLD])


async def test_retry_after_failure_and_wrong_backend_detection(
    harness: MigrationHarness,
) -> None:
    pending = harness.shared.kicker()
    correlation = uuid.uuid4().hex
    harness.old_broker.failures_left = 1

    # The first submission to the old generation fails.
    harness.journal.record(PUBLISHER, PRE_SEND, correlation, correlation)
    with pytest.raises(SendTaskError):
        await pending.with_task_id(correlation).with_labels(
            correlation=correlation,
        ).kiq()
    # The failed attempt was never stored on either generation.
    assert harness.journal.channels(STORE, correlation) == []

    # A normal resubmission of the same logical task succeeds.
    retried = await publish(harness, pending, correlation)
    assert_stored_on(harness.journal, correlation, OLD)

    # Migrate, then mirror the same logical task onto the new generation
    # through an explicit-broker control call: identical task id and
    # identical business value on both generations.
    async_shared_broker.default_broker(harness.new_broker)
    mirrored = await publish(
        harness,
        harness.shared.kicker().with_broker(harness.new_broker),
        correlation,
    )
    assert harness.journal.channels(STORE, correlation) == [OLD, NEW]

    old_result = await retried.get_result()
    new_result = await mirrored.get_result()
    assert old_result.return_value == new_result.return_value == BUSINESS_VALUE
    assert_fetched_from(harness.journal, correlation, [OLD, NEW])

    # A broken double that resolves the backend from the *current* default
    # returns the very same value, but silently from the wrong generation.
    broken_result = await CurrentDefaultResultHandle(correlation).get_result()
    assert broken_result.return_value == BUSINESS_VALUE

    # The journal-based acceptance check catches the misattribution...
    with pytest.raises(AssertionError):
        assert_fetched_from(harness.journal, correlation, [OLD, NEW])
    # ...and pinpoints the generation that served the wrong fetch.
    assert harness.journal.channels(GET_RESULT, correlation) == [OLD, NEW, NEW]

