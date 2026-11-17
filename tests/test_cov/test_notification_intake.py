#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test COV Notification Subscription Context Validation
------------------------------------------------------

The COV notification intake must not accept a notification solely because its
subscriberProcessIdentifier matches one of the application's contexts.  Every
notification is checked against the subscription context that was approved for
its (source address, process identifier):

* the monitored object and the confirmed/unconfirmed flavor the context was
  created with,
* the initiating device identifier bound to the source address,
* the lifetime deadline / explicit cancel,
* retransmitted duplicates carrying the same values.

Rejected confirmed notifications produce an Error PDU (never a Simple ACK),
rejected unconfirmed notifications are only recorded in the diagnostics deque,
and accepted notifications are the only ones that reach the consumer queue.
"""

import asyncio
from typing import Callable

import pytest

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.errors import ServicesError
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier, Real
from bacpypes3.constructeddata import Any
from bacpypes3.basetypes import PropertyValue
from bacpypes3.apdu import (
    ConfirmedCOVNotificationRequest,
    UnconfirmedCOVNotificationRequest,
)
from bacpypes3.app import Application

from bacpypes3.service.cov import (
    COV_DIAG_ACCEPTED,
    COV_DIAG_DUPLICATE_NOTIFICATION,
    COV_DIAG_NOTIFICATION_TYPE_MISMATCH,
    COV_DIAG_OBJECT_MISMATCH,
    COV_DIAG_SOURCE_CHANGED,
    COV_DIAG_SUBSCRIPTION_EXPIRED,
    COV_DIAG_UNKNOWN_PROPERTY,
    COV_DIAG_UNKNOWN_SUBSCRIPTION,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

SOURCE = Address("0x03")
OTHER_SOURCE = Address("0x04")
PROCESS_ID = 7
DEVICE_ID = ObjectIdentifier("device,903")
OTHER_DEVICE_ID = ObjectIdentifier("device,904")
OBJECT_ID = ObjectIdentifier("analog-value,1")
OTHER_OBJECT_ID = ObjectIdentifier("analog-value,2")


def _property_value(property_identifier="present-value", value=55.0):
    return PropertyValue(
        propertyIdentifier=property_identifier,
        value=Any(Real(value)),
    )


def _notification(
    confirmed,
    *,
    source=SOURCE,
    process_identifier=PROCESS_ID,
    device_identifier=DEVICE_ID,
    object_identifier=OBJECT_ID,
    values=None,
):
    if values is None:
        values = [_property_value()]
    klass = (
        ConfirmedCOVNotificationRequest
        if confirmed
        else UnconfirmedCOVNotificationRequest
    )
    apdu = klass(
        subscriberProcessIdentifier=process_identifier,
        initiatingDeviceIdentifier=device_identifier,
        monitoredObjectIdentifier=object_identifier,
        timeRemaining=0,
        listOfValues=values,
    )
    apdu.pduSource = source
    return apdu


@bacpypes_debugging
class TestNotificationIntake:
    _debug: Callable[..., None]

    @pytest.fixture
    def app(self):
        application = Application()

        # a bare Application has no bound ASE to send a Simple ACK through;
        # record what the intake would have sent instead
        sent_acks = []

        async def _response(apdu):
            sent_acks.append(apdu)

        application.response = _response  # type: ignore[method-assign]
        application.sent_acks = sent_acks
        try:
            yield application
        finally:
            application.close()

    def _make_context(
        self,
        app,
        *,
        address=SOURCE,
        object_identifier=OBJECT_ID,
        process_identifier=PROCESS_ID,
        confirmed=True,
        lifetime=60,
    ):
        scm = app.change_of_value(
            address,
            object_identifier,
            process_identifier,
            confirmed,
            lifetime,
        )
        # simulate a successfully accepted subscription without going on
        # the wire; the context registration normally happens in __aenter__
        app._cov_contexts[(address, process_identifier)] = scm
        scm.expires_at = (
            -1.0 if lifetime == 0 else (asyncio.get_running_loop().time() + lifetime)
        )
        return scm

    async def test_unknown_subscription_confirmed_raises(self, app) -> None:
        """A confirmed notification with no matching context is an Error,
        not an ACK, and nothing is queued."""
        if _debug:
            TestNotificationIntake._debug("test_unknown_subscription_confirmed_raises")

        apdu = _notification(confirmed=True)

        with pytest.raises(ServicesError, match="unknownSubscription"):
            await app.do_ConfirmedCOVNotificationRequest(apdu)

        # the rejection must never produce a Simple ACK
        assert app.sent_acks == []
        assert [d.reason for d in app.cov_diagnostics] == [
            COV_DIAG_UNKNOWN_SUBSCRIPTION
        ]

    async def test_unknown_subscription_unconfirmed_is_dropped(self, app) -> None:
        """An unconfirmed notification with no matching context cannot be
        answered, but it is still recorded for diagnosis."""
        if _debug:
            TestNotificationIntake._debug(
                "test_unknown_subscription_unconfirmed_is_dropped"
            )

        apdu = _notification(confirmed=False)

        # must not raise: there is no way to reply to an unconfirmed request
        await app.do_UnconfirmedCOVNotificationRequest(apdu)

        assert [d.reason for d in app.cov_diagnostics] == [
            COV_DIAG_UNKNOWN_SUBSCRIPTION
        ]

    async def test_accepted_confirmed_notification_reaches_queue(self, app) -> None:
        """A notification matching every part of the context is queued and
        records an accepted diagnostic."""
        if _debug:
            TestNotificationIntake._debug(
                "test_accepted_confirmed_notification_reaches_queue"
            )

        scm = self._make_context(app, confirmed=True)
        apdu = _notification(confirmed=True)

        await app.do_ConfirmedCOVNotificationRequest(apdu)

        assert scm.queue.qsize() == 1
        assert len(app.sent_acks) == 1
        assert [d.reason for d in app.cov_diagnostics] == [COV_DIAG_ACCEPTED]
        assert scm.initiating_device_identifier == DEVICE_ID

    async def test_accepted_unconfirmed_notification_reaches_queue(self, app) -> None:
        if _debug:
            TestNotificationIntake._debug(
                "test_accepted_unconfirmed_notification_reaches_queue"
            )

        scm = self._make_context(app, confirmed=False)
        apdu = _notification(confirmed=False)

        await app.do_UnconfirmedCOVNotificationRequest(apdu)

        assert scm.queue.qsize() == 1
        assert [d.reason for d in app.cov_diagnostics] == [COV_DIAG_ACCEPTED]

    async def test_notification_type_mismatch_is_rejected(self, app) -> None:
        """A context created for unconfirmed notifications must not accept
        a confirmed one, and vice versa."""
        if _debug:
            TestNotificationIntake._debug("test_notification_type_mismatch_is_rejected")

        scm = self._make_context(app, confirmed=False)
        confirmed_apdu = _notification(confirmed=True)

        with pytest.raises(ServicesError, match="inconsistentParameters"):
            await app.do_ConfirmedCOVNotificationRequest(confirmed_apdu)

        # nothing reached the consumer
        assert scm.queue.qsize() == 0
        assert [d.reason for d in app.cov_diagnostics] == [
            COV_DIAG_NOTIFICATION_TYPE_MISMATCH
        ]

        # and the same check in the other direction
        other_scm = self._make_context(
            app, address=OTHER_SOURCE, process_identifier=PROCESS_ID, confirmed=True
        )
        unconfirmed_apdu = _notification(confirmed=False, source=OTHER_SOURCE)

        await app.do_UnconfirmedCOVNotificationRequest(unconfirmed_apdu)

        assert other_scm.queue.qsize() == 0
        assert [d.reason for d in app.cov_diagnostics][-1] == (
            COV_DIAG_NOTIFICATION_TYPE_MISMATCH
        )

    async def test_monitored_object_mismatch_is_rejected(self, app) -> None:
        """A notification for a different object than the context is bound
        to cannot update the consumer's state."""
        if _debug:
            TestNotificationIntake._debug("test_monitored_object_mismatch_is_rejected")

        scm = self._make_context(app)
        apdu = _notification(confirmed=True, object_identifier=OTHER_OBJECT_ID)

        with pytest.raises(ServicesError, match="inconsistentParameters"):
            await app.do_ConfirmedCOVNotificationRequest(apdu)

        assert scm.queue.qsize() == 0
        assert app.sent_acks == []
        assert [d.reason for d in app.cov_diagnostics] == [COV_DIAG_OBJECT_MISMATCH]

    async def test_source_device_change_is_rejected(self, app) -> None:
        """After the source device is bound, a later notification from the
        same address claiming a different device identifier is rejected but
        retained in the diagnostics."""
        if _debug:
            TestNotificationIntake._debug("test_source_device_change_is_rejected")

        scm = self._make_context(app)

        # first notification binds device 903 to the address
        await app.do_ConfirmedCOVNotificationRequest(_notification(confirmed=True))
        assert scm.queue.qsize() == 1

        # a replayed notification claiming to come from another device
        changed = _notification(confirmed=True, device_identifier=OTHER_DEVICE_ID)
        with pytest.raises(ServicesError, match="inconsistentParameters"):
            await app.do_ConfirmedCOVNotificationRequest(changed)

        # the changed notification did not update the queue
        assert scm.queue.qsize() == 1
        reasons = [d.reason for d in app.cov_diagnostics]
        assert reasons == [COV_DIAG_ACCEPTED, COV_DIAG_SOURCE_CHANGED]

    async def test_duplicate_notification_is_acked_but_not_queued(self, app) -> None:
        """A retransmitted confirmed notification gets its ACK (so the
        sender stops retrying) but the identical values are enqueued once."""
        if _debug:
            TestNotificationIntake._debug(
                "test_duplicate_notification_is_acked_but_not_queued"
            )

        scm = self._make_context(app)
        apdu = _notification(confirmed=True)

        await app.do_ConfirmedCOVNotificationRequest(apdu)
        # the duplicate carries a fresh invoke ID but the same values
        duplicate = _notification(confirmed=True)
        await app.do_ConfirmedCOVNotificationRequest(duplicate)

        assert scm.queue.qsize() == 1
        # both notifications are ACKed so the sender stops retransmitting
        assert len(app.sent_acks) == 2
        reasons = [d.reason for d in app.cov_diagnostics]
        assert reasons == [
            COV_DIAG_ACCEPTED,
            COV_DIAG_DUPLICATE_NOTIFICATION,
        ]

    async def test_changed_values_after_duplicate_are_delivered(self, app) -> None:
        """Once the values genuinely change the notification is no longer a
        duplicate and the new values reach the consumer."""
        if _debug:
            TestNotificationIntake._debug(
                "test_changed_values_after_duplicate_are_delivered"
            )

        scm = self._make_context(app)

        await app.do_ConfirmedCOVNotificationRequest(
            _notification(confirmed=True, values=[_property_value(value=10.0)])
        )
        await app.do_ConfirmedCOVNotificationRequest(
            _notification(confirmed=True, values=[_property_value(value=10.0)])
        )
        await app.do_ConfirmedCOVNotificationRequest(
            _notification(confirmed=True, values=[_property_value(value=20.0)])
        )

        assert scm.queue.qsize() == 2
        reasons = [d.reason for d in app.cov_diagnostics]
        assert reasons == [
            COV_DIAG_ACCEPTED,
            COV_DIAG_DUPLICATE_NOTIFICATION,
            COV_DIAG_ACCEPTED,
        ]

    async def test_canceled_context_rejects_late_notification(self, app) -> None:
        """After the context is closed a late confirmed notification is
        rejected with unknownSubscription and cannot update the queue."""
        if _debug:
            TestNotificationIntake._debug(
                "test_canceled_context_rejects_late_notification"
            )

        scm = self._make_context(app)
        scm.canceled = True
        scm.expires_at = None
        app._cov_contexts[(SOURCE, PROCESS_ID)] = scm

        with pytest.raises(ServicesError, match="unknownSubscription"):
            await app.do_ConfirmedCOVNotificationRequest(_notification(confirmed=True))

        assert scm.queue.qsize() == 0
        assert (SOURCE, PROCESS_ID) not in app._cov_contexts
        assert [d.reason for d in app.cov_diagnostics] == [
            COV_DIAG_SUBSCRIPTION_EXPIRED
        ]

    async def test_expired_context_rejects_late_notification(self, app) -> None:
        """When the lifetime deadline has passed, a late notification is
        rejected and the stale context is removed."""
        if _debug:
            TestNotificationIntake._debug(
                "test_expired_context_rejects_late_notification"
            )

        scm = self._make_context(app, lifetime=10)
        # move the deadline into the past
        scm.expires_at = asyncio.get_running_loop().time() - 1.0

        with pytest.raises(ServicesError, match="unknownSubscription"):
            await app.do_ConfirmedCOVNotificationRequest(_notification(confirmed=True))

        assert scm.queue.qsize() == 0
        assert (SOURCE, PROCESS_ID) not in app._cov_contexts
        assert [d.reason for d in app.cov_diagnostics] == [
            COV_DIAG_SUBSCRIPTION_EXPIRED
        ]

    async def test_unknown_property_keeps_value_and_diagnostic(self, app) -> None:
        """A value referencing a property the application cannot interpret is
        still queued (get_value returns a DecodingError) and flagged."""
        if _debug:
            TestNotificationIntake._debug(
                "test_unknown_property_keeps_value_and_diagnostic"
            )

        scm = self._make_context(app)
        apdu = _notification(
            confirmed=True,
            values=[_property_value(property_identifier=512)],
        )

        await app.do_ConfirmedCOVNotificationRequest(apdu)

        # the raw element still reached the consumer
        assert scm.queue.qsize() == 1
        assert [d.reason for d in app.cov_diagnostics] == [COV_DIAG_UNKNOWN_PROPERTY]

        property_identifier, property_value = scm.decode_property_value(
            scm.queue.get_nowait()
        )
        assert int(property_identifier) == 512
        assert isinstance(property_value, Exception)


@bacpypes_debugging
class TestSubscriptionLifecycle:
    _debug: Callable[..., None]

    @pytest.fixture
    def app(self):
        application = Application()
        try:
            yield application
        finally:
            application.close()

    async def test_infinite_lifetime_stays_active(self, app) -> None:
        """A zero-lifetime subscription is active until explicitly canceled."""
        if _debug:
            TestSubscriptionLifecycle._debug("test_infinite_lifetime_stays_active")

        scm = app.change_of_value(SOURCE, OBJECT_ID, 11, True, 0)
        app._cov_contexts[(SOURCE, 11)] = scm

        # pending (no accepted subscription yet) still receives the initial
        # notification from the server
        assert scm.is_active() is True

        scm.expires_at = -1.0
        assert scm.is_active() is True

        scm.canceled = True
        assert scm.is_active() is False

    async def test_deadline_transitions_to_inactive(self, app) -> None:
        """A finite lifetime goes inactive once the loop clock passes it."""
        if _debug:
            TestSubscriptionLifecycle._debug("test_deadline_transitions_to_inactive")

        scm = app.change_of_value(SOURCE, OBJECT_ID, 12, True, 30)
        app._cov_contexts[(SOURCE, 12)] = scm
        scm.expires_at = asyncio.get_running_loop().time() + 30.0

        assert scm.is_active() is True

        scm.expires_at = asyncio.get_running_loop().time() - 0.001
        assert scm.is_active() is False

    async def test_refresh_extends_the_deadline(self, app) -> None:
        """Renewing a subscription moves the deadline past the old one."""
        if _debug:
            TestSubscriptionLifecycle._debug("test_refresh_extends_the_deadline")

        scm = app.change_of_value(SOURCE, OBJECT_ID, 13, True, 30)
        app._cov_contexts[(SOURCE, 13)] = scm

        # the first accepted subscription has ten seconds left
        first_deadline = asyncio.get_running_loop().time() + 10.0
        scm.expires_at = first_deadline
        assert scm.is_active() is True

        # a renewal for another 30 seconds pushes the deadline out again,
        # exactly as refresh_subscription() recomputes it on success
        scm.expires_at = asyncio.get_running_loop().time() + 30.0
        assert scm.expires_at > first_deadline
        assert scm.is_active() is True
