#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test COV Subscriptions On A Virtual Network
-------------------------------------------

End-to-end tests for the subscription context checks using two real BACnet
applications on an in-memory VLAN:

* two subscriber devices create subscriptions with the *same* subscriber
  process identifier against one publisher, proving the identifier alone is
  not enough to accept a notification - the source/object context is,
* canceling one subscription leaves the other one fully working,
* a late notification for the canceled subscription cannot update the
  consumer and the publisher gets an Error (not a Simple ACK) for it,
* an expired subscription rejects late notifications the same way.
"""

import asyncio
from typing import Callable, List, Tuple

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier, Real
from bacpypes3.apdu import (
    ConfirmedCOVNotificationRequest,
    UnconfirmedCOVNotificationRequest,
)
from bacpypes3.basetypes import PropertyValue
from bacpypes3.constructeddata import Any

from .conftest import (
    ANALOG_VALUE_ID,
    PUBLISHER_ADDRESS,
    PUBLISHER_INSTANCE,
    SUBSCRIBER_A_ADDRESS,
)
from bacpypes3.service.cov import (
    COV_DIAG_ACCEPTED,
    COV_DIAG_DUPLICATE_NOTIFICATION,
    COV_DIAG_SUBSCRIPTION_EXPIRED,
    COV_DIAG_UNKNOWN_SUBSCRIPTION,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# both subscribers deliberately use the same process identifier
SHARED_PROCESS_ID = 42


async def _drain_values(scm, count: int) -> List[Tuple]:
    """Read count interpreted (identifier, value) pairs from a context."""
    values = []
    for _ in range(count):
        values.append(await asyncio.wait_for(scm.get_value(), timeout=2.0))
    return values


def _present_value_notification(
    confirmed: bool,
    *,
    process_identifier: int,
    device_instance: int,
    value: float,
):
    """Build a COV notification as if the publisher had just emitted it.

    The source is set to the publisher's address; the destination (and an
    invoke ID for confirmed requests) is assigned when the test drives the
    notification through the receiving application.
    """
    klass = (
        ConfirmedCOVNotificationRequest
        if confirmed
        else UnconfirmedCOVNotificationRequest
    )
    request = klass(
        subscriberProcessIdentifier=process_identifier,
        initiatingDeviceIdentifier=ObjectIdentifier(("device", device_instance)),
        monitoredObjectIdentifier=ObjectIdentifier(ANALOG_VALUE_ID),
        timeRemaining=0,
        listOfValues=[
            PropertyValue(
                propertyIdentifier="present-value",
                value=Any(Real(value)),
            )
        ],
    )
    request.pduSource = Address(PUBLISHER_ADDRESS)
    return request


@bacpypes_debugging
class TestVLANCOVSubscription:
    _debug: Callable[..., None]

    async def test_two_devices_same_process_identifier(self, cov_apps) -> None:
        """Two devices using the same process identifier each receive their
        own notifications independently."""
        if _debug:
            TestVLANCOVSubscription._debug("test_two_devices_same_process_identifier")

        subscriber_a = cov_apps["subscriber_a"]
        subscriber_b = cov_apps["subscriber_b"]
        publisher = cov_apps["publisher"]
        obj_id = ObjectIdentifier(ANALOG_VALUE_ID)

        scm_a = subscriber_a.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, SHARED_PROCESS_ID, True, 0
        )
        scm_b = subscriber_b.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, SHARED_PROCESS_ID, True, 0
        )

        async with scm_a, scm_b:
            # the contexts are registered per application, so the shared
            # process identifier never collides between the two devices
            assert (
                subscriber_a._cov_contexts[
                    (Address(PUBLISHER_ADDRESS), SHARED_PROCESS_ID)
                ]
                is scm_a
            )
            assert (
                subscriber_b._cov_contexts[
                    (Address(PUBLISHER_ADDRESS), SHARED_PROCESS_ID)
                ]
                is scm_b
            )

            # each gets the initial notification (presentValue + statusFlags)
            initial_a = await _drain_values(scm_a, 2)
            initial_b = await _drain_values(scm_b, 2)
            assert initial_a[0] == (initial_a[0][0], 10.0)
            assert initial_b[0] == (initial_b[0][0], 10.0)

            # a value change fans out to both subscribers
            publisher.get_object_id(obj_id).presentValue = 30.0
            changed_a = await _drain_values(scm_a, 2)
            changed_b = await _drain_values(scm_b, 2)
            assert changed_a[0][1] == 30.0
            assert changed_b[0][1] == 30.0

    async def test_cancel_one_subscription_keeps_the_other(self, cov_apps) -> None:
        """After subscriber A cancels, its late notifications are rejected
        while subscriber B's identical subscription keeps working."""
        if _debug:
            TestVLANCOVSubscription._debug(
                "test_cancel_one_subscription_keeps_the_other"
            )

        subscriber_a = cov_apps["subscriber_a"]
        subscriber_b = cov_apps["subscriber_b"]
        publisher = cov_apps["publisher"]
        obj_id = ObjectIdentifier(ANALOG_VALUE_ID)

        scm_a = subscriber_a.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, SHARED_PROCESS_ID, True, 0
        )
        scm_b = subscriber_b.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, SHARED_PROCESS_ID, True, 0
        )

        async with scm_b:
            async with scm_a:
                await _drain_values(scm_a, 2)
                await _drain_values(scm_b, 2)

                # exiting this inner block cancels only A's subscription

            # scm_a is now canceled; scm_b stays open for the rest of the test
            assert (Address(PUBLISHER_ADDRESS), SHARED_PROCESS_ID) not in (
                subscriber_a._cov_contexts
            )
            assert scm_a.is_active() is False
            assert scm_b.is_active() is True

            # a late confirmed notification for the canceled subscription is
            # turned into an Error PDU by the application's dispatch layer,
            # never a Simple ACK and never a queued value
            late = _present_value_notification(
                True,
                process_identifier=SHARED_PROCESS_ID,
                device_instance=PUBLISHER_INSTANCE,
                value=40.0,
            )
            late.pduDestination = Address(SUBSCRIBER_A_ADDRESS)

            error_pdus = []
            original_response = subscriber_a.response

            async def _capture_response(apdu):
                error_pdus.append(apdu)

            subscriber_a.response = _capture_response  # type: ignore[method-assign]
            try:
                await subscriber_a.indication(late)
                await asyncio.sleep(0)
            finally:
                subscriber_a.response = original_response  # type: ignore[method-assign]

            # exactly one Error PDU (services / unknownSubscription), no ACK
            assert len(error_pdus) == 1
            assert str(error_pdus[0].errorClass) == "services"
            assert str(error_pdus[0].errorCode) == "unknown-subscription"

            # nothing landed in A's consumer and the rejection is diagnosable
            assert scm_a.queue.qsize() == 0
            reasons_a = [d.reason for d in subscriber_a.cov_diagnostics]
            assert COV_DIAG_UNKNOWN_SUBSCRIPTION in reasons_a

            # subscriber B's subscription is unaffected and still receives values
            publisher.get_object_id(obj_id).presentValue = 40.0
            changed_b = await _drain_values(scm_b, 2)
            assert changed_b[0][1] == 40.0
            assert scm_b.is_active() is True

    async def test_late_notification_after_expiry_is_rejected(self, cov_apps) -> None:
        """A subscription whose lifetime has expired rejects a late
        notification and removes the stale context."""
        if _debug:
            TestVLANCOVSubscription._debug(
                "test_late_notification_after_expiry_is_rejected"
            )

        subscriber_a = cov_apps["subscriber_a"]
        obj_id = ObjectIdentifier(ANALOG_VALUE_ID)

        scm = subscriber_a.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, 99, False, 10
        )

        async with scm:
            await _drain_values(scm, 2)
            assert scm.is_active() is True

            # simulate the lifetime deadline passing without a renewal
            scm.expires_at = asyncio.get_running_loop().time() - 1.0
            assert scm.is_active() is False

            late = _present_value_notification(
                False,
                process_identifier=99,
                device_instance=PUBLISHER_INSTANCE,
                value=50.0,
            )

            # an unconfirmed notification cannot be answered: capture any
            # response and assert the rejection sends nothing back
            sent = []
            original_response = subscriber_a.response

            async def _capture(apdu):
                sent.append(apdu)

            subscriber_a.response = _capture  # type: ignore[method-assign]
            try:
                await subscriber_a.do_UnconfirmedCOVNotificationRequest(late)
            finally:
                subscriber_a.response = original_response  # type: ignore[method-assign]

            assert sent == []
            assert scm.queue.qsize() == 0
            assert (Address(PUBLISHER_ADDRESS), 99) not in (subscriber_a._cov_contexts)
            reasons = [d.reason for d in subscriber_a.cov_diagnostics]
            assert COV_DIAG_SUBSCRIPTION_EXPIRED in reasons

    async def test_lifetime_deadline_expires_under_clock(
        self, cov_apps, clocked_test
    ) -> None:
        """Drive the real loop clock past a subscription lifetime and show
        the context goes inactive without any manual state changes."""
        if _debug:
            TestVLANCOVSubscription._debug("test_lifetime_deadline_expires_under_clock")

        subscriber_a = cov_apps["subscriber_a"]
        obj_id = ObjectIdentifier(ANALOG_VALUE_ID)

        # a short-lived unconfirmed subscription; its refresh would only run
        # at lifetime-2, so advancing the clock past the lifetime without
        # reaching a renewal still leaves a deadline in the past
        scm = subscriber_a.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, 98, False, 5
        )

        async with scm:
            await _drain_values(scm, 2)
            assert scm.is_active() is True

            # cancel the auto-refresh so nothing extends the deadline, then
            # move the clock beyond it
            if scm.refresh_subscription_handle:
                scm.refresh_subscription_handle.cancel()
                scm.refresh_subscription_handle = None
            await clocked_test.advance(6.0)

            assert scm.is_active() is False

            late = _present_value_notification(
                False,
                process_identifier=98,
                device_instance=PUBLISHER_INSTANCE,
                value=70.0,
            )
            await subscriber_a.do_UnconfirmedCOVNotificationRequest(late)

            assert scm.queue.qsize() == 0
            reasons = [d.reason for d in subscriber_a.cov_diagnostics]
            assert COV_DIAG_SUBSCRIPTION_EXPIRED in reasons

    async def test_duplicate_notification_acknowledged_once_queued(
        self, cov_apps
    ) -> None:
        """A retransmitted confirmed notification is ACKed but its values are
        only delivered once, over the real stack."""
        if _debug:
            TestVLANCOVSubscription._debug(
                "test_duplicate_notification_acknowledged_once_queued"
            )

        subscriber_a = cov_apps["subscriber_a"]
        obj_id = ObjectIdentifier(ANALOG_VALUE_ID)

        scm = subscriber_a.change_of_value(
            Address(PUBLISHER_ADDRESS), obj_id, 77, True, 0
        )

        async with scm:
            await _drain_values(scm, 2)

            first = _present_value_notification(
                True,
                process_identifier=77,
                device_instance=PUBLISHER_INSTANCE,
                value=60.0,
            )
            # the retransmitted copy has the same values but a new invoke ID
            duplicate = _present_value_notification(
                True,
                process_identifier=77,
                device_instance=PUBLISHER_INSTANCE,
                value=60.0,
            )
            first.pduDestination = Address(SUBSCRIBER_A_ADDRESS)
            duplicate.pduDestination = Address(SUBSCRIBER_A_ADDRESS)
            # the retransmitted copy has a new invoke ID but identical values
            first.apduInvokeID = 200
            duplicate.apduInvokeID = 201

            # neither dispatch raises: both are accepted (the duplicate is
            # suppressed) and each gets its Simple ACK through the real stack
            await subscriber_a.indication(first)
            await subscriber_a.indication(duplicate)
            await asyncio.sleep(0)

            # but only one present-value was enqueued
            values = await _drain_values(scm, 1)
            assert values[0][1] == 60.0
            assert scm.queue.qsize() == 0

            reasons = [d.reason for d in subscriber_a.cov_diagnostics]
            assert COV_DIAG_DUPLICATE_NOTIFICATION in reasons
            assert COV_DIAG_ACCEPTED in reasons
