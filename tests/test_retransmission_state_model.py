"""
Model-based tests for the OPC UA publish / retransmit / acknowledge state machine.

The production ``RetransmissionQueue`` is compared against an independent
reference model written from the protocol rules (Part 4, sections 5.13 and
5.14.5). A bounded retransmission capacity, fixed synthetic notifications and a
manually driven "publish clock" (no wall clock, no sockets) make the scenarios
fully deterministic:

* duplicate Republish of an unacknowledged sequence stays legal and idempotent;
* unknown, evicted and acknowledged sequences never consume another notification;
* out-of-order acknowledgements only remove their own sequence;
* capacity overflow exposes a real gap instead of renumbering into a fake
  contiguous sequence.
"""

from __future__ import annotations

import pytest

from asyncua import ua
from asyncua.client.ua_session import UaSession
from asyncua.common.utils import ServiceError
from asyncua.server.address_space import AddressSpace
from asyncua.server.internal_subscription import InternalSubscription, RetransmissionQueue
from asyncua.server.subscription_service import SubscriptionService
from asyncua.server.uaprocessor import PublishRequestData


class ReferenceRetransmissionQueue:
    """Plain-set reference model, independent of the production implementation."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.retained: dict[int, ua.PublishResult] = {}
        self.acknowledged: set[int] = set()
        self.evicted: set[int] = set()

    def store(self, result: ua.PublishResult) -> list[int]:
        seq = result.NotificationMessage.SequenceNumber
        if seq == 0 or not result.NotificationMessage.NotificationData:
            return []
        self.retained[seq] = result
        dropped: list[int] = []
        while len(self.retained) > self.capacity:
            oldest = min(self.retained)
            del self.retained[oldest]
            self.evicted.add(oldest)
            dropped.append(oldest)
        return dropped

    def republish(self, seq: int) -> str:
        if seq in self.retained:
            return "retained"
        if seq in self.acknowledged or seq in self.evicted:
            return "BadMessageNotAvailable"
        return "BadSequenceNumberUnknown"

    def acknowledge(self, seq: int) -> str:
        if seq in self.retained:
            del self.retained[seq]
            self.acknowledged.add(seq)
            return "Good"
        if seq in self.acknowledged or seq in self.evicted:
            return "BadMessageNotAvailable"
        return "BadSequenceNumberUnknown"


def _make_result(seq: int) -> ua.PublishResult:
    result = ua.PublishResult()
    result.SubscriptionId = 1
    result.NotificationMessage.SequenceNumber = seq
    result.NotificationMessage.NotificationData = [
        ua.DataChangeNotification(
            MonitoredItems=[ua.MonitoredItemNotification(ClientHandle=seq)]
        )
    ]
    return result


def _service_error_name(exc: ServiceError) -> str:
    return ua.StatusCode(exc.code).name


def _assert_matches_reference(queue: RetransmissionQueue, reference: ReferenceRetransmissionQueue) -> None:
    assert queue.available_sequence_numbers == sorted(reference.retained)
    assert queue.retained_sequence_numbers == set(reference.retained)
    assert queue.acknowledged_sequence_numbers == reference.acknowledged
    assert queue.evicted_sequence_numbers == reference.evicted
    assert len(queue) == len(reference.retained)


def test_store_and_capacity_eviction_matches_reference() -> None:
    capacity = 3
    queue = RetransmissionQueue(capacity)
    reference = ReferenceRetransmissionQueue(capacity)
    produced_evictions: list[list[int]] = []
    for seq in range(1, 8):
        result = _make_result(seq)
        produced_evictions.append(queue.store(result))
        reference.store(result)
        _assert_matches_reference(queue, reference)
    assert queue.available_sequence_numbers == [5, 6, 7]
    assert queue.evicted_sequence_numbers == {1, 2, 3, 4}
    assert queue.has_gap() is True
    assert produced_evictions == [[], [], [], [1], [2], [3], [4]]


def test_republish_is_idempotent_and_keeps_notification() -> None:
    queue = RetransmissionQueue(5)
    reference = ReferenceRetransmissionQueue(5)
    result = _make_result(4)
    queue.store(result)
    reference.store(result)

    first = queue.republish(4)
    second = queue.republish(4)
    assert first is result.NotificationMessage
    assert second is result.NotificationMessage
    assert 4 in queue
    assert queue.available_sequence_numbers == [4]
    _assert_matches_reference(queue, reference)


def test_republish_distinguishes_evicted_acknowledged_and_unknown() -> None:
    queue = RetransmissionQueue(2)
    reference = ReferenceRetransmissionQueue(2)
    for seq in range(1, 5):
        result = _make_result(seq)
        queue.store(result)
        reference.store(result)

    queue.acknowledge(3)
    reference.acknowledge(3)

    for seq in (1, 2, 3, 99):
        expected = reference.republish(seq)
        if expected == "retained":
            assert queue.republish(seq).SequenceNumber == seq
        else:
            with pytest.raises(ServiceError) as exc_info:
                queue.republish(seq)
            assert _service_error_name(exc_info.value) == expected
        _assert_matches_reference(queue, reference)


def test_out_of_order_acknowledgements_remove_only_their_sequence() -> None:
    capacity = 10
    queue = RetransmissionQueue(capacity)
    reference = ReferenceRetransmissionQueue(capacity)
    for seq in range(1, 6):
        result = _make_result(seq)
        queue.store(result)
        reference.store(result)

    for seq in (5, 2, 4, 1, 3):
        assert queue.acknowledge(seq).name == reference.acknowledge(seq)
        _assert_matches_reference(queue, reference)
    assert queue.available_sequence_numbers == []
    assert queue.acknowledged_sequence_numbers == {1, 2, 3, 4, 5}


def test_invalid_acknowledgements_do_not_consume_another_notification() -> None:
    queue = RetransmissionQueue(5)
    reference = ReferenceRetransmissionQueue(5)
    for seq in range(1, 4):
        result = _make_result(seq)
        queue.store(result)
        reference.store(result)
    queue.acknowledge(1)
    reference.acknowledge(1)
    queue.store(_make_result(6))
    reference.store(_make_result(6))

    for bad_ack in (1, 55):
        expected = reference.acknowledge(bad_ack)
        assert queue.acknowledge(bad_ack).name == expected
        _assert_matches_reference(queue, reference)
    assert queue.available_sequence_numbers == [2, 3, 6]


def test_eviction_gap_is_visible_not_renumbered() -> None:
    queue = RetransmissionQueue(2)
    for seq in range(1, 5):
        queue.store(_make_result(seq))
    assert queue.available_sequence_numbers == [3, 4]
    assert queue.has_gap() is True
    with pytest.raises(ServiceError) as exc_info:
        queue.republish(1)
    assert _service_error_name(exc_info.value) == "BadMessageNotAvailable"
    assert queue.republish(3).SequenceNumber == 3
    assert queue.republish(4).SequenceNumber == 4


async def _make_subscription(
    capacity: int,
) -> tuple[SubscriptionService, InternalSubscription, list[ua.PublishResult]]:
    responses: list[ua.PublishResult] = []

    async def collect_callback(result: ua.PublishResult, _request: PublishRequestData | None = None) -> None:
        responses.append(result)

    service = SubscriptionService(AddressSpace())
    params = ua.CreateSubscriptionParameters()
    params.PublishingEnabled = True
    params.RequestedLifetimeCount = 10_000
    params.RequestedMaxKeepAliveCount = 10_000
    result = await service.create_subscription(params, collect_callback, ua.NodeId(1), _provide_request)
    sub = service.subscriptions[result.SubscriptionId]
    sub.retransmission_queue.capacity = capacity
    return service, sub, responses


def _provide_request(_subscription_id: int) -> PublishRequestData:
    return PublishRequestData()


def _enqueue_fixed_notification(sub: InternalSubscription, seq: int) -> None:
    sub._triggered_datachanges = {
        seq: [ua.MonitoredItemNotification(ClientHandle=seq)],
    }


@pytest.mark.asyncio
async def test_subscription_publish_clock_matches_model_with_overflow() -> None:
    capacity = 3
    _service, sub, responses = await _make_subscription(capacity)
    reference = ReferenceRetransmissionQueue(capacity)

    for tick in range(1, 8):
        _enqueue_fixed_notification(sub, tick)
        assert await sub.publish_results() is True
        response = responses[-1]
        assert response.NotificationMessage.SequenceNumber == tick
        reference.store(response)
        assert response.AvailableSequenceNumbers == sorted(reference.retained)
        _assert_matches_reference(sub.retransmission_queue, reference)

    assert sub.retransmission_queue.available_sequence_numbers == [5, 6, 7]
    assert sub.retransmission_queue.evicted_sequence_numbers == {1, 2, 3, 4}


@pytest.mark.asyncio
async def test_subscription_duplicate_republish_returns_same_notification() -> None:
    _service, sub, _responses = await _make_subscription(5)
    _enqueue_fixed_notification(sub, 1)
    assert await sub.publish_results() is True

    first = sub.republish(1)
    second = sub.republish(1)
    assert first.SequenceNumber == 1
    assert second.SequenceNumber == 1
    assert first.NotificationData[0].MonitoredItems[0].ClientHandle == 1
    assert second.NotificationData[0].MonitoredItems[0].ClientHandle == 1
    assert sub.retransmission_queue.available_sequence_numbers == [1]


@pytest.mark.asyncio
async def test_subscription_republish_unknown_and_stale_fail_explicitly() -> None:
    _service, sub, _responses = await _make_subscription(2)
    for tick in range(1, 4):
        _enqueue_fixed_notification(sub, tick)
        assert await sub.publish_results() is True

    with pytest.raises(ServiceError) as evicted:
        sub.republish(1)
    assert _service_error_name(evicted.value) == "BadMessageNotAvailable"
    with pytest.raises(ServiceError) as unknown:
        sub.republish(42)
    assert _service_error_name(unknown.value) == "BadSequenceNumberUnknown"
    assert sub.republish(3).SequenceNumber == 3


@pytest.mark.asyncio
async def test_subscription_service_faults_for_old_subscription() -> None:
    service, sub, _responses = await _make_subscription(5)
    _enqueue_fixed_notification(sub, 1)
    await sub.publish_results()
    params = ua.RepublishParameters(SubscriptionId=999, RetransmitSequenceNumber=1)
    with pytest.raises(ServiceError) as exc_info:
        service.republish(params)
    assert _service_error_name(exc_info.value) == "BadSubscriptionIdInvalid"


@pytest.mark.asyncio
async def test_subscription_service_acknowledgement_results_are_per_sequence() -> None:
    service, sub, _responses = await _make_subscription(5)
    for tick in range(1, 4):
        _enqueue_fixed_notification(sub, tick)
        await sub.publish_results()

    acks = [
        ua.SubscriptionAcknowledgement(SubscriptionId=sub.data.SubscriptionId, SequenceNumber=2),
        ua.SubscriptionAcknowledgement(SubscriptionId=sub.data.SubscriptionId, SequenceNumber=2),
        ua.SubscriptionAcknowledgement(SubscriptionId=sub.data.SubscriptionId, SequenceNumber=99),
        ua.SubscriptionAcknowledgement(SubscriptionId=999, SequenceNumber=1),
    ]
    _count, results = service.publish(acks)
    assert [code.name for code in results] == [
        "Good",
        "BadMessageNotAvailable",
        "BadSequenceNumberUnknown",
        "BadSubscriptionIdInvalid",
    ]
    assert sub.retransmission_queue.available_sequence_numbers == [1, 3]


@pytest.mark.asyncio
async def test_available_sequence_numbers_never_fakes_continuity() -> None:
    _service, sub, _responses = await _make_subscription(2)
    seen_available: list[list[int]] = []
    for tick in range(1, 6):
        _enqueue_fixed_notification(sub, tick)
        await sub.publish_results()
        seen_available.append(sub.retransmission_queue.available_sequence_numbers)
    assert seen_available == [[1], [1, 2], [2, 3], [3, 4], [4, 5]]
    assert sub.retransmission_queue.evicted_sequence_numbers == {1, 2, 3}
    assert sub.retransmission_queue.has_gap() is True


@pytest.mark.asyncio
async def test_keepalive_uses_sequence_zero_and_is_not_retained() -> None:
    _service, sub, responses = await _make_subscription(5)
    keepalive = sub._pop_publish_result()
    assert keepalive.NotificationMessage.SequenceNumber == 0
    assert keepalive.NotificationMessage.NotificationData == []
    assert sub.retransmission_queue.available_sequence_numbers == []

    _enqueue_fixed_notification(sub, 1)
    await sub.publish_results()
    notification = responses[-1]
    assert notification.NotificationMessage.SequenceNumber == 1
    assert sub.retransmission_queue.available_sequence_numbers == [1]

    keepalive_again = sub._pop_publish_result()
    assert keepalive_again.NotificationMessage.SequenceNumber == 0
    assert sub._notification_seq == 2
    assert sub.retransmission_queue.available_sequence_numbers == [1]


def test_retransmission_queue_ignores_keepalive_results() -> None:
    queue = RetransmissionQueue(3)
    keepalive = ua.PublishResult()
    keepalive.NotificationMessage.SequenceNumber = 0
    assert queue.store(keepalive) == []
    assert queue.available_sequence_numbers == []
    real = _make_result(1)
    assert queue.store(real) == []
    assert queue.available_sequence_numbers == [1]


class _FakeUaSession(UaSession):
    """Minimal stand-in for UaSession exposing only republish for gap replay."""

    def __init__(self, queue: RetransmissionQueue) -> None:
        self._queue = queue
        self.calls: list[int] = []

    async def republish(self, subscription_id: int, seq: int) -> ua.NotificationMessage:
        self.calls.append(seq)
        return self._queue.republish(seq)


@pytest.mark.asyncio
async def test_gap_replay_skips_evicted_holes_and_recovers_retained() -> None:
    from asyncua.common.subscription import Subscription

    queue = RetransmissionQueue(3)
    for seq in range(1, 6):
        queue.store(_make_result(seq))
    assert queue.evicted_sequence_numbers == {1, 2}
    available = queue.available_sequence_numbers
    assert available == [3, 4, 5]

    fake_session = _FakeUaSession(queue)
    replayed: list[int] = []

    async def deliver(result: ua.PublishResult) -> None:
        seq = int(result.NotificationMessage.SequenceNumber)
        if seq != 0:
            subscription.last_sequence_number = seq
        replayed.append(seq)

    subscription = Subscription.__new__(Subscription)
    subscription.server = fake_session
    subscription.subscription_id = 1
    subscription._replaying = False
    subscription.last_sequence_number = 0
    subscription.publish_callback = deliver

    ok = await subscription._republish_gaps(available)
    assert ok is True
    assert replayed == [3, 4, 5]
    assert fake_session.calls == [3, 4, 5]
    assert queue.available_sequence_numbers == [3, 4, 5]
