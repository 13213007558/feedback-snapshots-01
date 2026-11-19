import asyncio

import async_timeout
import pytest

from channels.exceptions import ChannelFull
from channels.layers import InMemoryChannelLayer


@pytest.fixture()
async def channel_layer():
    """
    Channel layer fixture that flushes automatically.
    """
    channel_layer = InMemoryChannelLayer(capacity=3)
    yield channel_layer
    await channel_layer.flush()
    await channel_layer.close()


@pytest.mark.asyncio
async def test_send_receive(channel_layer):
    """
    Makes sure we can send a message to a normal channel then receive it.
    """
    await channel_layer.send(
        "test-channel-1", {"type": "test.message", "text": "Ahoy-hoy!"}
    )
    await channel_layer.send(
        "test-channel-1", {"type": "test.message", "text": "Ahoy-hoy!"}
    )
    message = await channel_layer.receive("test-channel-1")
    assert message["type"] == "test.message"
    assert message["text"] == "Ahoy-hoy!"
    # not removed because not empty
    assert "test-channel-1" in channel_layer.channels
    message = await channel_layer.receive("test-channel-1")
    assert message["type"] == "test.message"
    assert message["text"] == "Ahoy-hoy!"
    # removed because empty
    assert "test-channel-1" not in channel_layer.channels


@pytest.mark.asyncio
async def test_race_empty(channel_layer):
    """
    Makes sure the race is handled gracefully.
    """
    receive_task = asyncio.create_task(channel_layer.receive("test-channel-1"))
    await asyncio.sleep(0.1)
    await channel_layer.send(
        "test-channel-1", {"type": "test.message", "text": "Ahoy-hoy!"}
    )
    del channel_layer.channels["test-channel-1"]
    await asyncio.sleep(0.1)
    message = await receive_task
    assert message["type"] == "test.message"
    assert message["text"] == "Ahoy-hoy!"


@pytest.mark.asyncio
async def test_send_capacity(channel_layer):
    """
    Makes sure we get ChannelFull when we hit the send capacity
    """
    await channel_layer.send("test-channel-1", {"type": "test.message"})
    await channel_layer.send("test-channel-1", {"type": "test.message"})
    await channel_layer.send("test-channel-1", {"type": "test.message"})
    with pytest.raises(ChannelFull):
        await channel_layer.send("test-channel-1", {"type": "test.message"})


@pytest.mark.asyncio
async def test_process_local_send_receive(channel_layer):
    """
    Makes sure we can send a message to a process-local channel then receive it.
    """
    channel_name = await channel_layer.new_channel()
    await channel_layer.send(
        channel_name, {"type": "test.message", "text": "Local only please"}
    )
    message = await channel_layer.receive(channel_name)
    assert message["type"] == "test.message"
    assert message["text"] == "Local only please"


@pytest.mark.asyncio
async def test_multi_send_receive(channel_layer):
    """
    Tests overlapping sends and receives, and ordering.
    """
    await channel_layer.send("test-channel-3", {"type": "message.1"})
    await channel_layer.send("test-channel-3", {"type": "message.2"})
    await channel_layer.send("test-channel-3", {"type": "message.3"})
    assert (await channel_layer.receive("test-channel-3"))["type"] == "message.1"
    assert (await channel_layer.receive("test-channel-3"))["type"] == "message.2"
    assert (await channel_layer.receive("test-channel-3"))["type"] == "message.3"


@pytest.mark.asyncio
async def test_groups_basic(channel_layer):
    """
    Tests basic group operation.
    """
    await channel_layer.group_add("test-group", "test-gr-chan-1")
    await channel_layer.group_add("test-group", "test-gr-chan-2")
    await channel_layer.group_add("test-group", "test-gr-chan-3")
    await channel_layer.group_discard("test-group", "test-gr-chan-2")
    await channel_layer.group_send("test-group", {"type": "message.1"})
    # Make sure we get the message on the two channels that were in
    async with async_timeout.timeout(1):
        assert (await channel_layer.receive("test-gr-chan-1"))["type"] == "message.1"
        assert (await channel_layer.receive("test-gr-chan-3"))["type"] == "message.1"
    # Make sure the removed channel did not get the message
    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(1):
            await channel_layer.receive("test-gr-chan-2")


@pytest.mark.asyncio
async def test_groups_channel_full(channel_layer):
    """
    Tests that group_send ignores ChannelFull
    """
    await channel_layer.group_add("test-group", "test-gr-chan-1")
    await channel_layer.group_send("test-group", {"type": "message.1"})
    await channel_layer.group_send("test-group", {"type": "message.1"})
    await channel_layer.group_send("test-group", {"type": "message.1"})
    await channel_layer.group_send("test-group", {"type": "message.1"})
    await channel_layer.group_send("test-group", {"type": "message.1"})


@pytest.mark.asyncio
async def test_expiry_single():
    """
    Tests that a message can expire.
    """
    channel_layer = InMemoryChannelLayer(expiry=0.1)
    await channel_layer.send("test-channel-1", {"type": "message.1"})
    assert len(channel_layer.channels) == 1

    await asyncio.sleep(0.1)

    # Message should have expired and been dropped.
    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.5):
            await channel_layer.receive("test-channel-1")

    # Channel should be cleaned up.
    assert len(channel_layer.channels) == 0


@pytest.mark.asyncio
async def test_expiry_unread():
    """
    Tests that a message on a channel can expire and be cleaned up even if
    the channel is not read from again.
    """
    channel_layer = InMemoryChannelLayer(expiry=0.1)
    await channel_layer.send("test-channel-1", {"type": "message.1"})

    await asyncio.sleep(0.1)

    await channel_layer.send("test-channel-2", {"type": "message.2"})
    assert len(channel_layer.channels) == 2
    assert (await channel_layer.receive("test-channel-2"))["type"] == "message.2"
    # Both channels should be cleaned up.
    assert len(channel_layer.channels) == 0


@pytest.mark.asyncio
async def test_expiry_multi():
    """
    Tests that multiple messages can expire.
    """
    channel_layer = InMemoryChannelLayer(expiry=0.1)
    await channel_layer.send("test-channel-1", {"type": "message.1"})
    await channel_layer.send("test-channel-1", {"type": "message.2"})
    await channel_layer.send("test-channel-1", {"type": "message.3"})
    assert (await channel_layer.receive("test-channel-1"))["type"] == "message.1"

    await asyncio.sleep(0.1)
    await channel_layer.send("test-channel-1", {"type": "message.4"})
    assert (await channel_layer.receive("test-channel-1"))["type"] == "message.4"

    # The second and third message should have expired and been dropped.
    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.5):
            await channel_layer.receive("test-channel-1")

    # Channel should be cleaned up.
    assert len(channel_layer.channels) == 0


class FakeClock:
    """A controllable clock so tests never wait on real time."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.mark.asyncio
async def test_group_budget_rejects_when_room_is_congested():
    """
    A room with an exhausted broadcast budget rejects the whole broadcast
    instead of partially filling member queues.
    """
    clock = FakeClock()
    channel_layer = InMemoryChannelLayer(capacity=10, group_budget=2, clock=clock)
    await channel_layer.group_add("congested", "congested-1")
    await channel_layer.group_add("congested", "congested-2")

    first = await channel_layer.group_send("congested", {"type": "chat.message"})
    assert first.ok
    assert (first.members, first.delivered) == (2, 2)
    assert first.budget_used == 2
    assert first.budget_remaining == 0

    second = await channel_layer.group_send("congested", {"type": "chat.message"})
    assert not second.ok
    assert (second.delivered, second.dropped, second.rejected) == (0, 0, 2)
    assert second.reason == "budget"
    assert set(second.rejected_channels) == {"congested-1", "congested-2"}

    # The rejected broadcast did not leak into member queues.
    assert (await channel_layer.receive("congested-1"))["type"] == "chat.message"
    assert (await channel_layer.receive("congested-2"))["type"] == "chat.message"
    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(0.05):
            await channel_layer.receive("congested-1")


@pytest.mark.asyncio
async def test_group_budget_is_per_room():
    """
    A congested room does not consume the budget of a neighbouring room.
    """
    channel_layer = InMemoryChannelLayer(capacity=10, group_budget=2)
    await channel_layer.group_add("congested", "congested-1")
    await channel_layer.group_add("congested", "congested-2")
    await channel_layer.group_add("normal", "normal-1")

    await channel_layer.group_send("congested", {"type": "chat.message"})
    blocked = await channel_layer.group_send("congested", {"type": "chat.message"})
    assert blocked.rejected == 2

    normal = await channel_layer.group_send("normal", {"type": "chat.message"})
    assert normal.ok
    assert (normal.delivered, normal.rejected) == (1, 0)
    assert normal.budget_used == 1
    assert (await channel_layer.receive("normal-1"))["type"] == "chat.message"


@pytest.mark.asyncio
async def test_group_send_reports_slow_consumer_capacity_drops():
    """
    Once a broadcast is admitted, the existing per-channel capacity behaviour
    still applies: a full member queue drops its copy and is reported.
    """
    channel_layer = InMemoryChannelLayer(capacity=1, group_budget=10)
    await channel_layer.group_add("room", "slow-1")
    await channel_layer.group_add("room", "fast-1")

    first = await channel_layer.group_send("room", {"type": "chat.message"})
    assert first.ok
    await channel_layer.receive("fast-1")

    second = await channel_layer.group_send("room", {"type": "chat.message"})
    assert not second.ok
    assert (second.delivered, second.dropped) == (1, 1)
    assert second.reason == "capacity"
    assert second.dropped_channels == ("slow-1",)

    # The dropped copy never occupied the room budget.
    assert second.budget_used == 2
    await channel_layer.receive("slow-1")
    assert channel_layer.get_group_budget_used("room") == 1


@pytest.mark.asyncio
async def test_group_budget_released_on_group_discard():
    """
    A member leaving the room releases the budget held by its queued copies.
    """
    channel_layer = InMemoryChannelLayer(capacity=10, group_budget=2)
    await channel_layer.group_add("room", "member-1")
    await channel_layer.group_add("room", "member-2")

    await channel_layer.group_send("room", {"type": "chat.message"})
    assert channel_layer.get_group_budget_used("room") == 2
    blocked = await channel_layer.group_send("room", {"type": "chat.message"})
    assert blocked.reason == "budget"
    rejected = await channel_layer.group_send("room", {"type": "chat.message"})
    assert rejected.reason == "budget"

    await channel_layer.group_discard("room", "member-2")
    assert channel_layer.get_group_budget_used("room") == 1

    recovered = await channel_layer.group_send("room", {"type": "chat.message"})
    assert recovered.ok
    assert (recovered.delivered, recovered.rejected) == (1, 0)
    assert recovered.budget_used == 2


@pytest.mark.asyncio
async def test_group_budget_released_on_message_expiry():
    """
    Unread broadcasts release their budget when the clock advances past the
    message expiry, without sleeping.
    """
    clock = FakeClock()
    channel_layer = InMemoryChannelLayer(expiry=10, group_budget=2, clock=clock)
    await channel_layer.group_add("room", "member-1")
    await channel_layer.group_add("room", "member-2")

    await channel_layer.group_send("room", {"type": "chat.message"})
    blocked = await channel_layer.group_send("room", {"type": "chat.message"})
    assert blocked.reason == "budget"

    clock.advance(11)
    channel_layer._clean_expired()
    assert channel_layer.get_group_budget_used("room") == 0
    assert channel_layer.groups == {}

    # Reconnecting after the expiry finds a fresh budget.
    await channel_layer.group_add("room", "member-3")
    recovered = await channel_layer.group_send("room", {"type": "chat.message"})
    assert recovered.ok
    assert recovered.delivered == 1


@pytest.mark.asyncio
async def test_group_budget_released_on_group_membership_expiry():
    """
    Group membership expiry releases budget even when queued messages are
    still alive.
    """
    clock = FakeClock()
    channel_layer = InMemoryChannelLayer(
        expiry=600, group_expiry=30, group_budget=2, clock=clock
    )
    await channel_layer.group_add("room", "member-1")
    await channel_layer.group_add("room", "member-2")

    await channel_layer.group_send("room", {"type": "chat.message"})
    assert channel_layer.get_group_budget_used("room") == 2

    clock.advance(31)
    channel_layer._clean_expired()
    assert channel_layer.groups == {}
    assert channel_layer.get_group_budget_used("room") == 0

    await channel_layer.group_add("room", "member-3")
    recovered = await channel_layer.group_send("room", {"type": "chat.message"})
    assert recovered.ok
    assert recovered.delivered == 1


@pytest.mark.asyncio
async def test_group_budget_per_room_patterns():
    """
    Per-room budgets can be configured with the same glob patterns used for
    channel capacities.
    """
    channel_layer = InMemoryChannelLayer(
        group_budget=10, group_budgets={"congested*": 1}
    )
    await channel_layer.group_add("congested-room", "congested-1")
    await channel_layer.group_add("congested-room", "congested-2")

    result = await channel_layer.group_send("congested-room", {"type": "chat.message"})
    assert result.reason == "budget"
    assert result.rejected == 2

    await channel_layer.group_add("normal-room", "normal-1")
    normal = await channel_layer.group_send("normal-room", {"type": "chat.message"})
    assert normal.ok


@pytest.mark.asyncio
async def test_group_budget_unlimited_by_default():
    """
    Without a configured budget the historical behaviour is unchanged:
    group_send returns delivered/dropped counts and never rejects for budget.
    """
    channel_layer = InMemoryChannelLayer(capacity=10)
    await channel_layer.group_add("room", "member-1")
    result = await channel_layer.group_send("room", {"type": "chat.message"})
    assert result.ok
    assert result.budget_remaining is None
    assert channel_layer.get_group_budget("room") is None


def test_group_budget_must_not_be_negative():
    with pytest.raises(ValueError):
        InMemoryChannelLayer(group_budget=-1)
    with pytest.raises(ValueError):
        InMemoryChannelLayer(group_budgets={"room": -1})


@pytest.mark.asyncio
async def test_group_budget_released_on_leave_then_rejoin():
    """
    Messages left behind by a departed member must not release the budget of
    a later membership that reuses the same channel name.
    """
    channel_layer = InMemoryChannelLayer(capacity=10, group_budget=4)
    await channel_layer.group_add("room", "member-1")

    # One queued copy, then the member leaves with that message still queued.
    await channel_layer.group_send("room", {"type": "chat.message"})
    await channel_layer.group_discard("room", "member-1")
    assert channel_layer.get_group_budget_used("room") == 0

    # Rejoin and spend the budget again.
    await channel_layer.group_add("room", "member-1")
    await channel_layer.group_send("room", {"type": "chat.message"})
    assert channel_layer.get_group_budget_used("room") == 1

    # Draining the stale first message must not release the new membership's
    # budget.
    stale = await channel_layer.receive("member-1")
    assert stale["type"] == "chat.message"
    assert channel_layer.get_group_budget_used("room") == 1

    fresh = await channel_layer.receive("member-1")
    assert fresh["type"] == "chat.message"
    assert channel_layer.get_group_budget_used("room") == 0


@pytest.mark.asyncio
async def test_group_budget_demo_congested_and_normal_rooms():
    """
    Walks through the pre-launch scenario with a handful of messages and a
    controllable clock: one congested room starts rejecting broadcasts, a
    neighbouring room keeps working, and a member leaving frees budget for
    later broadcasts - all without sleeping on real time.
    """
    clock = FakeClock()
    channel_layer = InMemoryChannelLayer(
        expiry=60,
        group_expiry=600,
        capacity=10,
        group_budget=4,
        clock=clock,
    )

    # Congested room: two members sharing four units of broadcast budget.
    await channel_layer.group_add("room.congested", "congested.alice")
    await channel_layer.group_add("room.congested", "congested.bob")
    # Normal room: one member with its own independent budget.
    await channel_layer.group_add("room.normal", "normal.carol")

    # Two broadcasts fit exactly (2 members x 2 messages = 4 units).
    first = await channel_layer.group_send("room.congested", {"type": "m.1"})
    second = await channel_layer.group_send("room.congested", {"type": "m.2"})
    assert first.ok and second.ok
    assert channel_layer.get_group_budget_remaining("room.congested") == 0

    # The third broadcast is rejected outright; nothing is queued.
    rejected = await channel_layer.group_send("room.congested", {"type": "m.3"})
    assert rejected.reason == "budget"
    assert (rejected.delivered, rejected.rejected) == (0, 2)
    assert rejected.budget_remaining == 0

    # The neighbouring room is unaffected by the congested room's budget.
    normal = await channel_layer.group_send("room.normal", {"type": "n.1"})
    assert normal.ok
    assert normal.delivered == 1
    assert (await channel_layer.receive("normal.carol"))["type"] == "n.1"
    assert channel_layer.get_group_budget_used("room.normal") == 0

    # Bob leaves: his queued copies return their budget immediately.
    await channel_layer.group_discard("room.congested", "congested.bob")
    assert channel_layer.get_group_budget_used("room.congested") == 2

    # Recovery: the previously rejected broadcast now fits for Alice.
    recovered = await channel_layer.group_send("room.congested", {"type": "m.3"})
    assert recovered.ok
    assert (recovered.delivered, recovered.rejected) == (1, 0)

    # Advancing the clock past message expiry drains the remaining budget
    # without any real waiting.
    clock.advance(61)
    channel_layer._clean_expired()
    assert channel_layer.get_group_budget_used("room.congested") == 0


@pytest.mark.asyncio
async def test_channel_capacity_is_honoured_per_channel():
    """
    The existing per-channel capacity semantics still apply, including glob
    overrides, and are independent from the room broadcast budget.
    """
    channel_layer = InMemoryChannelLayer(
        capacity=5, channel_capacity={"slow-*": 1}, group_budget=10
    )
    assert channel_layer.get_capacity("slow-consumer") == 1
    assert channel_layer.get_capacity("other") == 5

    await channel_layer.group_add("room", "slow-consumer")
    await channel_layer.group_add("room", "fast-consumer")

    first = await channel_layer.group_send("room", {"type": "chat.message"})
    assert first.ok
    # The slow consumer is at its per-channel capacity of one.
    second = await channel_layer.group_send("room", {"type": "chat.message"})
    assert second.reason == "capacity"
    assert second.dropped_channels == ("slow-consumer",)
