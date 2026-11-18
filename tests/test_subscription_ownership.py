"""Subscription ownership admission and TransferSubscriptions policy.

Covers the server-side Subscription Service Set with several authenticated
sessions on one InternalServer. All scenarios run in memory: sessions are
driven directly through ``InternalSession`` so no socket is required.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from asyncua import ua
from asyncua.common.shortcuts import Shortcuts
from asyncua.server.internal_server import InternalServer
from asyncua.server.subscription_access import (
    AllowAllTransferPolicy,
    CallableTransferPolicy,
    SamePrincipalTransferPolicy,
)
from asyncua.server.uaprocessor import PublishRequestData

pytestmark = pytest.mark.asyncio

PublishCallback = Callable[..., Awaitable[None]]


def _login_token(username: str) -> ua.UserNameIdentityToken:
    token = ua.UserNameIdentityToken()
    token.UserName = username
    token.Password = username.encode()
    return token


async def _start_server() -> InternalServer:
    srv = InternalServer()
    await srv.init()
    return srv


def _activate(srv: InternalServer, name: str, username: str) -> Any:
    session = srv.create_session(name, external=True)
    params = ua.ActivateSessionParameters()
    params.UserIdentityToken = _login_token(username)
    session.activate_session(params, None)
    return session


def _create_params() -> ua.CreateSubscriptionParameters:
    params = ua.CreateSubscriptionParameters()
    params.RequestedPublishingInterval = 100_000
    params.RequestedLifetimeCount = 1_000
    params.RequestedMaxKeepAliveCount = 10
    params.MaxNotificationsPerPublish = 0
    params.PublishingEnabled = True
    params.Priority = 0
    return params


async def _subscribe(session: Any, variable: Any, callback: PublishCallback) -> int:
    result = await session.create_subscription(_create_params(), callback, request_callback=lambda _sid: None)
    sub_id = result.SubscriptionId
    params = ua.CreateMonitoredItemsParameters()
    params.SubscriptionId = sub_id
    item = ua.MonitoredItemCreateRequest()
    item.ItemToMonitor = ua.ReadValueId()
    item.ItemToMonitor.NodeId = variable.nodeid
    item.ItemToMonitor.AttributeId = ua.AttributeIds.Value
    item.MonitoringMode = ua.MonitoringMode.Reporting
    item.RequestedParameters = ua.MonitoringParameters()
    item.RequestedParameters.ClientHandle = 1
    params.ItemsToCreate = [item]
    results = await session.create_monitored_items(params)
    assert results[0].StatusCode.is_good()
    return sub_id


async def _make_server_with_two_users() -> tuple[InternalServer, Any, Any, Any, list[tuple[str, int]]]:
    srv = await _start_server()
    alice = _activate(srv, "alice", "alice")
    bob = _activate(srv, "bob", "bob")
    variable = await Shortcuts(srv.isession).objects.add_variable(2, "OwnershipVar", 0)
    delivered: list[tuple[str, int]] = []

    async def alice_cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
        delivered.append(("alice", int(result.NotificationMessage.SequenceNumber)))

    await _subscribe(alice, variable, alice_cb)
    return srv, alice, bob, variable, delivered


def _expect_service_error(exc_info: pytest.ExceptionInfo[Any], code: ua.StatusCodes) -> None:
    assert exc_info.value.code == code


async def test_foreign_session_cannot_touch_subscription_by_id() -> None:
    srv, alice, bob, variable, _ = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        assert srv.subscription_service.subscriptions[sub_id].principal == "user:alice"

        create = ua.CreateMonitoredItemsParameters()
        create.SubscriptionId = sub_id
        item = ua.MonitoredItemCreateRequest()
        item.ItemToMonitor = ua.ReadValueId()
        item.ItemToMonitor.NodeId = variable.nodeid
        item.ItemToMonitor.AttributeId = ua.AttributeIds.Value
        item.MonitoringMode = ua.MonitoringMode.Reporting
        item.RequestedParameters = ua.MonitoringParameters()
        item.RequestedParameters.ClientHandle = 99
        create.ItemsToCreate = [item]

        with pytest.raises(Exception) as exc:
            await bob.create_monitored_items(create)
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)

        with pytest.raises(Exception) as exc:
            bob.republish(ua.RepublishParameters(SubscriptionId=sub_id, RetransmitSequenceNumber=1))
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)

        with pytest.raises(Exception) as exc:
            bob.modify_subscription(ua.ModifySubscriptionParameters(SubscriptionId=sub_id))
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)

        with pytest.raises(Exception) as exc:
            await bob.delete_monitored_items(
                ua.DeleteMonitoredItemsParameters(SubscriptionId=sub_id, MonitoredItemIds=[112])
            )
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)

        with pytest.raises(Exception) as exc:
            await bob.set_monitoring_mode(
                ua.SetMonitoringModeParameters(
                    SubscriptionId=sub_id, MonitoringMode=ua.MonitoringMode.Disabled, MonitoredItemIds=[112]
                )
            )
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)

        delete_status = await bob.delete_subscriptions([sub_id])
        assert delete_status[0].value == ua.StatusCodes.BadUserAccessDenied
        publishing_status = await bob.set_publishing_mode(
            ua.SetPublishingModeParameters(SubscriptionIds=[sub_id], PublishingEnabled=False)
        )
        assert publishing_status[0].value == ua.StatusCodes.BadUserAccessDenied
        bob_only_params = ua.CreateSubscriptionParameters()
        bob_only_params.RequestedPublishingInterval = 100_000
        await bob.create_subscription(bob_only_params, _noop_callback, request_callback=lambda _sid: None)
        _, ack_status = bob.publish([ua.SubscriptionAcknowledgement(SubscriptionId=sub_id, SequenceNumber=1)])
        assert ack_status[0].value == ua.StatusCodes.BadUserAccessDenied

        assert sub_id in srv.subscription_service.subscriptions
        assert 112 in srv.subscription_service.subscriptions[sub_id].monitored_item_srv._monitored_items
    finally:
        await srv.stop()


async def test_foreign_session_cannot_acknowledge_or_republish_owned_message() -> None:
    srv, alice, bob, variable, delivered = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        sub = srv.subscription_service.subscriptions[sub_id]
        await variable.write_value(5)
        await sub.publish_results(PublishRequestData())
        assert delivered == [("alice", 1)]
        sequence = next(iter(sub._not_acknowledged_results))

        bob_only_params = ua.CreateSubscriptionParameters()
        bob_only_params.RequestedPublishingInterval = 100_000
        await bob.create_subscription(bob_only_params, _noop_callback, request_callback=lambda _sid: None)
        _, ack_status = bob.publish([ua.SubscriptionAcknowledgement(SubscriptionId=sub_id, SequenceNumber=sequence)])
        assert ack_status[0].value == ua.StatusCodes.BadUserAccessDenied
        assert sequence in sub._not_acknowledged_results

        with pytest.raises(Exception) as exc:
            bob.republish(ua.RepublishParameters(SubscriptionId=sub_id, RetransmitSequenceNumber=sequence))
        _expect_service_error(exc, ua.StatusCodes.BadUserAccessDenied)
        assert sequence in sub._not_acknowledged_results
    finally:
        await srv.stop()


async def test_cross_principal_transfer_refused_by_default() -> None:
    srv, alice, bob, _, _ = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)
        result = await bob.transfer_subscriptions(params, alice_callback)
        assert result[0].StatusCode.value == ua.StatusCodes.BadUserAccessDenied
        assert srv.subscription_service.subscriptions[sub_id].is_owned_by(alice.session_id)
    finally:
        await srv.stop()


async def test_same_principal_reconnect_may_transfer() -> None:
    srv, alice, _, variable, _ = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        reconnected = _activate(srv, "alice-again", "alice")
        delivered: list[tuple[str, int]] = []

        async def new_cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            delivered.append(("new", int(result.NotificationMessage.SequenceNumber)))

        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)
        result = await reconnected.transfer_subscriptions(params, new_cb, request_callback=lambda _sid: None)
        assert result[0].StatusCode.is_good()
        sub = srv.subscription_service.subscriptions[sub_id]
        assert sub.is_owned_by(reconnected.session_id)
        assert sub.principal == "user:alice"

        await variable.write_value(7)
        await sub.publish_results(PublishRequestData())
        assert delivered and delivered[0][0] == "new"

        old_status = await alice.delete_subscriptions([sub_id])
        assert old_status[0].value == ua.StatusCodes.BadUserAccessDenied
        assert sub_id in srv.subscription_service.subscriptions
    finally:
        await srv.stop()


async def test_publish_in_flight_during_transfer_does_not_reach_old_owner() -> None:
    srv, alice, _, variable, delivered = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        sub = srv.subscription_service.subscriptions[sub_id]
        reconnected = _activate(srv, "alice-again", "alice")
        new_delivery: list[int] = []

        async def new_cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            new_delivery.append(int(result.NotificationMessage.SequenceNumber))

        gate = asyncio.Event()

        async def old_cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            delivered.append(("alice", int(result.NotificationMessage.SequenceNumber)))
            await gate.wait()

        sub.pub_result_callback = old_cb
        await variable.write_value(3)
        inflight = asyncio.create_task(sub.publish_results(PublishRequestData()))
        await asyncio.sleep(0)

        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)
        result = await reconnected.transfer_subscriptions(params, new_cb, request_callback=lambda _sid: None)
        assert result[0].StatusCode.is_good()

        gate.set()
        await inflight
        delivered.clear()
        await variable.write_value(4)
        await sub.publish_results(PublishRequestData())
        assert [seq for _, seq in delivered] == []
        assert new_delivery
    finally:
        await srv.stop()


async def test_anonymous_principals_are_not_interchangeable() -> None:
    srv = await _start_server()
    try:
        first = srv.create_session("anon-1", external=True)
        second = srv.create_session("anon-2", external=True)
        for session in (first, second):
            session.activate_session(ua.ActivateSessionParameters(), None)
        variable = await Shortcuts(srv.isession).objects.add_variable(2, "AnonVar", 0)

        async def cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            return None

        sub_id = await _subscribe(first, variable, cb)
        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)
        result = await second.transfer_subscriptions(params, cb)
        assert result[0].StatusCode.value == ua.StatusCodes.BadUserAccessDenied
    finally:
        await srv.stop()


async def test_transfer_policy_is_configurable() -> None:
    srv, alice, bob, variable, _ = await _make_server_with_two_users()
    try:
        sub_id = next(iter(srv.subscription_service.subscriptions))
        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)
        delivered: list[str] = []

        async def bob_cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            delivered.append("bob")

        srv.subscription_service.transfer_policy = AllowAllTransferPolicy()
        result = await bob.transfer_subscriptions(params, bob_cb)
        assert result[0].StatusCode.is_good()
        assert srv.subscription_service.subscriptions[sub_id].is_owned_by(bob.session_id)

        await variable.write_value(11)
        await srv.subscription_service.subscriptions[sub_id].publish_results(PublishRequestData())
        assert delivered == ["bob"]
    finally:
        await srv.stop()


async def test_callable_policy_receives_real_identities() -> None:
    srv, alice, bob, _, _ = await _make_server_with_two_users()
    seen: list[tuple[str | None, str | None, bool]] = []

    def decide(request: Any) -> bool:
        seen.append((request.owner.principal, request.requester_principal, request.same_session))
        return request.requester_principal == "user:bob" and request.owner.principal == "user:alice"

    try:
        srv.subscription_service.transfer_policy = CallableTransferPolicy(decide)
        sub_id = next(iter(srv.subscription_service.subscriptions))
        params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub_id], SendInitialValues=False)

        async def cb(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
            return None

        result = await bob.transfer_subscriptions(params, cb)
        assert result[0].StatusCode.is_good()
        assert seen == [("user:alice", "user:bob", False)]
    finally:
        await srv.stop()


async def test_default_policy_rejects_already_owned_by_other_principal() -> None:
    policy = SamePrincipalTransferPolicy()
    from asyncua.server.subscription_access import SubscriptionOwner, SubscriptionTransferRequest

    owner = SubscriptionOwner(session_id=ua.NodeId(1), principal="user:alice")
    foreign = SubscriptionTransferRequest(
        subscription_id=7,
        owner=owner,
        requester_session_id=ua.NodeId(2),
        requester_principal="user:bob",
    )
    same_principal = SubscriptionTransferRequest(
        subscription_id=7,
        owner=owner,
        requester_session_id=ua.NodeId(3),
        requester_principal="user:alice",
    )
    unnamed = SubscriptionTransferRequest(
        subscription_id=7,
        owner=SubscriptionOwner(session_id=ua.NodeId(4), principal=None),
        requester_session_id=ua.NodeId(5),
        requester_principal=None,
    )
    assert policy.can_transfer(same_principal)
    assert not policy.can_transfer(foreign)
    assert not policy.can_transfer(unnamed)


async def alice_callback(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
    return None


async def _noop_callback(result: ua.PublishResult, requestdata: PublishRequestData | None = None) -> None:
    return None
