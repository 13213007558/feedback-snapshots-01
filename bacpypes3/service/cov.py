"""
Change Of Value Services
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from functools import partial

from typing import (
    Any as _Any,
    Callable,
    Deque,
    Optional,
    Tuple,
)

from ..settings import settings
from ..debugging import bacpypes_debugging, DebugContents, ModuleLogger

from ..pdu import Address

from ..errors import (
    DecodingError,
    ExecutionError,
    ServicesError,
)
from ..primitivedata import Unsigned, ObjectIdentifier
from ..constructeddata import Array
from ..basetypes import PropertyIdentifier, PropertyValue
from ..apdu import (
    SimpleAckPDU,
    ErrorRejectAbortNack,
    SubscribeCOVRequest,
    ConfirmedCOVNotificationRequest,
    UnconfirmedCOVNotificationRequest,
)
from ..vendor import get_vendor_info

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   Diagnostic reason codes recorded when an incoming COV notification is
#   accepted, rejected or partially processed.  They are kept as plain
#   strings rather than an enum so the diagnostic deque serializes without
#   additional machinery.
#

# no subscription context matches the (source address, process identifier)
COV_DIAG_UNKNOWN_SUBSCRIPTION = "unknownSubscription"

# a context exists but it has been canceled or its lifetime has expired
COV_DIAG_SUBSCRIPTION_EXPIRED = "subscriptionExpired"

# the notification type (confirmed/unconfirmed) does not match the
# issueConfirmedNotifications flag the subscription was created with
COV_DIAG_NOTIFICATION_TYPE_MISMATCH = "notificationTypeMismatch"

# the monitored object identifier in the notification does not match the one
# the context was bound to
COV_DIAG_OBJECT_MISMATCH = "monitoredObjectMismatch"

# the initiating device identifier changed for an address the context is
# already bound to
COV_DIAG_SOURCE_CHANGED = "initiatingDeviceChanged"

# an identical notification was already delivered to this context
COV_DIAG_DUPLICATE_NOTIFICATION = "duplicateNotification"

# one or more of the values in the notification references a property the
# receiving application cannot interpret
COV_DIAG_UNKNOWN_PROPERTY = "unknownProperty"

# the notification passed every check and its values were queued
COV_DIAG_ACCEPTED = "accepted"

# number of diagnostic entries retained per application
COV_DIAGNOSTICS_MAXLEN = 128


@dataclass
class COVDiagnostic:
    """
    Record of how an incoming COV notification was handled.

    Every notification the application receives produces one of these,
    including the ones that are rejected and therefore never update any
    subscription state, so a management client can explain why an expected
    value never arrived.
    """

    reason: str
    confirmed: bool
    source_address: Optional[Address]
    subscriber_process_identifier: Optional[int]
    monitored_object_identifier: Optional[ObjectIdentifier]
    initiating_device_identifier: Optional[ObjectIdentifier] = None
    detail: Optional[str] = None
    loop_time: float = field(default_factory=lambda: asyncio.get_running_loop().time())


@bacpypes_debugging
class SubscriptionContextManager:
    _debug: Callable[..., None]

    app: "Application"  # noqa: F821
    address: Address
    monitored_object_identifier: ObjectIdentifier
    subscriber_process_identifier: int
    issue_confirmed_notifications: bool
    lifetime: int

    def __init__(
        self,
        app: "Application",  # noqa: F821
        address: Address,
        monitored_object_identifier: ObjectIdentifier,
        subscriber_process_identifier: int,
        issue_confirmed_notifications: bool,
        lifetime: int,
    ):
        if _debug:
            SubscriptionContextManager._debug("__init__ ...")

        # reference to the application for sending requests
        self.app = app

        # keep a copy of the request parameters
        self.address = address
        self.monitored_object_identifier = monitored_object_identifier
        self.subscriber_process_identifier = subscriber_process_identifier
        self.issue_confirmed_notifications = issue_confirmed_notifications
        self.lifetime = lifetime

        # queue of PropertyValue returned
        self.queue = asyncio.Queue()

        # timer handle to refresh the subscription
        self.refresh_subscription_handle = None

        # result of refresh task to check if exception occurred
        self.refresh_subscription_task = None

        # loop time at which the subscription is considered expired; None
        # means no subscription request has been accepted yet, and a
        # negative value marks an infinite lifetime subscription
        self.expires_at: Optional[float] = None

        # device identifier of the source that accepted the subscription,
        # bound when the first notification arrives so a later notification
        # claiming a different device for the same address can be detected
        self.initiating_device_identifier: Optional[ObjectIdentifier] = None

        # signature of the values from the last accepted notification, used
        # to suppress retransmitted duplicates
        self.last_notification_signature: Optional[tuple] = None

        # set once the context has been closed via __aexit__, so a late
        # notification arriving during the cancel request is rejected
        self.canceled: bool = False

    async def __aenter__(self) -> SubscriptionContextManager:
        if _debug:
            SubscriptionContextManager._debug("__aenter__")

        # save this in the app before sending the subscription request:
        # the server is allowed to send the initial notification as soon as
        # it accepts the request, and Application.request() schedules the
        # send as a separate task, so the notification can be processed
        # before this coroutine resumes
        scm_key = (self.address, self.subscriber_process_identifier)
        if scm_key in self.app._cov_contexts:
            raise ValueError("existing context")
        self.app._cov_contexts[scm_key] = self

        try:
            # kick off the subscription
            await self.refresh_subscription()
        except Exception:
            # the subscription was not accepted, don't leave a dead
            # context behind that would swallow notifications
            self.app._cov_contexts.pop(scm_key, None)
            raise

        return self

    async def __aexit__(self, *exc_details):
        """
        Exiting the context, cancel the subscription.
        """
        if _debug:
            SubscriptionContextManager._debug("__aexit__ %r", exc_details)

        # cancel the refresh
        if self.refresh_subscription_handle:
            if _debug:
                SubscriptionContextManager._debug("    - cancel refresh")
            self.refresh_subscription_handle.cancel()
            self.refresh_subscription_handle = None

        # the context is no longer active so late notifications must not
        # update the consumer's state
        self.canceled = True
        self.expires_at = None

        # delete the reference to this context; an expired context may have
        # already been removed when its late notification was rejected
        self.app._cov_contexts.pop(
            (self.address, self.subscriber_process_identifier), None
        )

        if exc_details != (None, None, None):
            if _debug:
                SubscriptionContextManager._debug("    - abandon context")
            return

        # create a request to cancel the subscription
        unsubscribe_cov_request = SubscribeCOVRequest(
            subscriberProcessIdentifier=self.subscriber_process_identifier,
            monitoredObjectIdentifier=self.monitored_object_identifier,
            destination=self.address,
        )

        # send the request, wait for the response
        response = await self.app.request(unsubscribe_cov_request)
        if _debug:
            SubscriptionContextManager._debug("    - response: %r", response)
        if isinstance(response, ErrorRejectAbortNack):
            if _debug:
                SubscriptionContextManager._debug(
                    "    - error/reject/abort: %r", response
                )

    def is_active(self) -> bool:
        """
        Return True when the context is bound to a subscription that has
        neither been canceled nor reached its lifetime deadline.
        """
        if _debug:
            SubscriptionContextManager._debug("is_active")

        # an explicit cancel always wins, including over a notification
        # that races the outgoing unsubscribe request
        if self.canceled:
            return False

        # no accepted subscription yet: the context is registered before
        # the subscribe request is sent so the server's initial
        # notification still has somewhere to land
        if self.expires_at is None:
            return True

        # negative value marks an infinite lifetime subscription
        if self.expires_at < 0:
            return True

        return asyncio.get_running_loop().time() < self.expires_at

    async def refresh_subscription(self):
        """
        Send a subscription request.
        """
        if _debug:
            SubscriptionContextManager._debug("refresh_subscription")

        # create a request
        subscribe_cov_request = SubscribeCOVRequest(
            subscriberProcessIdentifier=self.subscriber_process_identifier,
            monitoredObjectIdentifier=self.monitored_object_identifier,
            issueConfirmedNotifications=self.issue_confirmed_notifications,
            lifetime=self.lifetime,
            destination=self.address,
        )
        if _debug:
            SubscriptionContextManager._debug(
                "    - subscribe_cov_request: %r", subscribe_cov_request
            )

        # send the request, wait for the response
        response = await self.app.request(subscribe_cov_request)
        if _debug:
            SubscriptionContextManager._debug("    - response: %r", response)
        if isinstance(response, ErrorRejectAbortNack):
            if _debug:
                SubscriptionContextManager._debug(
                    "    - error/reject/abort: %r", response
                )
            raise response

        # get the loop to schedule a time to refresh
        loop = asyncio.get_event_loop()
        if _debug:
            SubscriptionContextManager._debug("    - loop time: %r", loop.time())

        # the subscription is now active, record the deadline using the
        # event loop clock so clocked tests can drive it deterministically.
        # a negative value marks an infinite lifetime subscription.
        if self.lifetime == 0:
            if _debug:
                SubscriptionContextManager._debug("    - infinite lifetime")
            self.expires_at = -1.0
        else:
            self.expires_at = loop.time() + self.lifetime
            if _debug:
                SubscriptionContextManager._debug(
                    "    - expires_at: %r", self.expires_at
                )

        # check for infinite lifetime
        if self.lifetime == 0:
            return

        # refresh time before it expires
        self.refresh_subscription_handle = loop.call_later(
            max(1.0, self.lifetime - 2.0), self.create_refresh_task
        )
        if _debug:
            SubscriptionContextManager._debug(
                "    - refresh_subscription_handle: %r",
                self.refresh_subscription_handle,
            )

        return

    def create_refresh_task(self):
        """
        Create a refresh task.  The `loop.call_later()` function does
        not take a coroutine so this function creates a task wrapping
        the `refresh_subscription()` coroutine.
        """
        if _debug:
            SubscriptionContextManager._debug("create_refresh_task")

        self.refresh_subscription_task = asyncio.create_task(
            self.refresh_subscription()
        )

    async def put(self, property_value: PropertyValue) -> None:
        """
        Add a property value to that has been received from a notification
        to the queue."""
        if _debug:
            SubscriptionContextManager._debug("put %r", property_value)

        await self.queue.put(property_value)

    async def get(self) -> PropertyValue:
        """
        Get the next property value from the queue or wait until one
        is available.  See `get_value()` for a specialized version.
        """
        if _debug:
            SubscriptionContextManager._debug("get")

        return await self.queue.get()

    async def get_value(self) -> Tuple[PropertyIdentifier, _Any]:
        """
        Get the next property value from the queue and interpret the
        propertyValue element to simplify the result.  Note that this
        will drop the property-index and priority elements after the
        interpretation.
        """
        if _debug:
            SubscriptionContextManager._debug("get_value")

        # get the next thing in the queue
        property_value_element = await self.get()

        property_identifier, property_value = self.decode_property_value(
            property_value_element
        )
        if _debug:
            SubscriptionContextManager._debug(
                "    - property_identifier, property_value: %r, %r",
                property_identifier,
                property_value,
            )

        return property_identifier, property_value

    def _get_vendor_info(self):
        """
        Look up the vendor information for the source device, falling back
        to the standard (vendor 0) information when the device has not been
        cached yet.
        """
        if _debug:
            SubscriptionContextManager._debug("_get_vendor_info")

        # get information about the device from the application cache
        device_info = self.app.device_info_cache.address_cache.get(self.address, None)
        if _debug:
            SubscriptionContextManager._debug("    - device_info: %r", device_info)

        # using the device info, look up the vendor information
        if device_info:
            vendor_info = get_vendor_info(device_info.vendor_identifier)
        else:
            vendor_info = get_vendor_info(0)
        if _debug:
            SubscriptionContextManager._debug(
                "    - vendor_info (%d): %r", vendor_info.vendor_identifier, vendor_info
            )

        return vendor_info

    def _resolve_property_type(self, property_value_element: PropertyValue):
        """
        Resolve the Python type used to decode a property value element.

        Returns a (property_type, error_message) tuple.  When the monitored
        object type or the property is not known to the receiving
        application property_type is None and error_message explains why,
        so the caller can record a diagnostic while the element is still
        queued for the consumer.
        """
        if _debug:
            SubscriptionContextManager._debug(
                "_resolve_property_type %r", property_value_element
            )

        vendor_info = self._get_vendor_info()

        # using the vendor information, look up the class
        object_class = vendor_info.get_object_class(self.monitored_object_identifier[0])
        if not object_class:
            error_message = f"no object class: {self.monitored_object_identifier[0]}"
            if _debug:
                SubscriptionContextManager._debug("    - %s", error_message)
            return None, error_message

        # now get the property type from the class
        property_type = object_class.get_property_type(
            property_value_element.propertyIdentifier
        )
        if _debug:
            SubscriptionContextManager._debug("    - property_type: %r", property_type)
        if not property_type:
            error_message = (
                f"no property type: {property_value_element.propertyIdentifier}"
            )
            return None, error_message

        # filter the array index reference
        if issubclass(property_type, Array):
            if property_value_element.propertyArrayIndex is None:
                pass
            elif property_value_element.propertyArrayIndex == 0:
                property_type = Unsigned
            else:
                property_type = property_type._subtype
            if _debug:
                SubscriptionContextManager._debug(
                    "    - other property_type: %r", property_type
                )

        return property_type, None

    def decode_property_value(
        self, property_value_element: PropertyValue
    ) -> Tuple[PropertyIdentifier, _Any]:
        """
        Interpret a property value element from a notification.  When the
        property cannot be interpreted a DecodingError is returned in place
        of the value rather than raised, so the consumer keeps a diagnosable
        result instead of losing the notification.
        """
        if _debug:
            SubscriptionContextManager._debug(
                "decode_property_value %r", property_value_element
            )

        property_type, error_message = self._resolve_property_type(
            property_value_element
        )
        if not property_type:
            return (
                property_value_element.propertyIdentifier,
                DecodingError(error_message),
            )

        # cast it out of the Any
        property_value = property_value_element.value.cast_out(property_type)
        if _debug:
            SubscriptionContextManager._debug(
                "    - property_value: %r %r", property_value, property_type.__class__
            )

        return (property_value_element.propertyIdentifier, property_value)


#
#   Subscription
#


@bacpypes_debugging
class Subscription(DebugContents):
    _debug_contents = (
        "obj_ref",
        "client_addr",
        "proc_id",
        "obj_id",
        "confirmed",
        "lifetime",
    )

    cancel_handle: Optional[asyncio.TimerHandle]

    def __init__(
        self, obj_ref, client_addr, proc_id, obj_id, confirmed, lifetime, cov_inc
    ):
        if _debug:
            Subscription._debug(
                "__init__ %r %r %r %r %r %r %r",
                obj_ref,
                client_addr,
                proc_id,
                obj_id,
                confirmed,
                lifetime,
                cov_inc,
            )
        # save the reference to the related object
        self.obj_ref = obj_ref

        # save the parameters
        self.client_addr = client_addr
        self.proc_id = proc_id
        self.obj_id = obj_id
        self.confirmed = confirmed
        self.lifetime = lifetime
        self.covIncrement = cov_inc

        # if lifetime is zero this is a permanent subscription
        if lifetime > 0:
            loop = asyncio.get_running_loop()
            self.cancel_handle = loop.call_later(
                lifetime, self.obj_ref._app.cancel_subscription, self
            )
        else:
            self.cancel_handle = None

    def cancel_subscription(self):
        if _debug:
            Subscription._debug("cancel_subscription")

        # if this is scheduled to call later, cancel it
        if self.cancel_handle:
            self.cancel_handle.cancel()
            self.cancel_handle = None

        # break the object reference
        self.obj_ref = None

    def renew_subscription(self, lifetime):
        if _debug:
            Subscription._debug("renew_subscription %r", lifetime)

        # if this is scheduled to call later, cancel it
        if self.cancel_handle:
            self.cancel_handle.cancel()
            self.cancel_handle = None

        # save the new lifetime
        self.lifetime = lifetime

        # reschedule a cancel if it's not infinite
        if lifetime > 0:
            loop = asyncio.get_running_loop()
            self.cancel_handle = loop.call_later(
                lifetime, self.obj_ref._app.cancel_subscription, self
            )


#
#   Change Of Value
#


@bacpypes_debugging
class ChangeOfValueServices:
    def __init__(self):
        if _debug:
            ChangeOfValueServices._debug("__init__")

        self._cov_next_id = 1
        self._cov_contexts = {}
        self._cov_detections = {}

        # rolling record of how incoming notifications were handled,
        # including the rejected ones that never reached a consumer
        self.cov_diagnostics: Deque[COVDiagnostic] = deque(
            maxlen=COV_DIAGNOSTICS_MAXLEN
        )

    def _record_cov_diagnostic(
        self,
        reason: str,
        apdu,
        detail: Optional[str] = None,
    ) -> COVDiagnostic:
        """
        Append a diagnostic entry describing how a notification was handled.
        """
        if _debug:
            ChangeOfValueServices._debug("_record_cov_diagnostic %r %r", reason, detail)

        diagnostic = COVDiagnostic(
            reason=reason,
            confirmed=isinstance(apdu, ConfirmedCOVNotificationRequest),
            source_address=apdu.pduSource,
            subscriber_process_identifier=apdu.subscriberProcessIdentifier,
            monitored_object_identifier=apdu.monitoredObjectIdentifier,
            initiating_device_identifier=apdu.initiatingDeviceIdentifier,
            detail=detail,
        )
        self.cov_diagnostics.append(diagnostic)

        return diagnostic

    # -----

    def change_of_value(
        self,
        address: Address,
        monitored_object_identifier: ObjectIdentifier,
        subscriber_process_identifier: Optional[int] = None,
        issue_confirmed_notifications: Optional[bool] = True,
        lifetime: Optional[int] = None,
    ) -> SubscriptionContextManager:
        """
        Create and return an async subscription context manager.
        """
        if _debug:
            ChangeOfValueServices._debug(
                "change_of_value %r %r %r %r %r",
                address,
                monitored_object_identifier,
                subscriber_process_identifier,
                issue_confirmed_notifications,
                lifetime,
            )

        if subscriber_process_identifier is None:
            while True:
                subscriber_process_identifier = self._cov_next_id
                self._cov_next_id = (self._cov_next_id + 1) % (1 << 22)
                if (address, subscriber_process_identifier) not in self._cov_contexts:
                    break
            if _debug:
                ChangeOfValueServices._debug(
                    "    - subscriber_process_identifier: %r",
                    subscriber_process_identifier,
                )

        if lifetime is None:
            lifetime = settings.cov_lifetime
            if _debug:
                ChangeOfValueServices._debug("    - lifetime: %r", lifetime)

        scm = SubscriptionContextManager(
            self,
            address,
            monitored_object_identifier,
            subscriber_process_identifier,
            issue_confirmed_notifications,
            lifetime,
        )
        if _debug:
            ChangeOfValueServices._debug("    - scm: %r", scm)

        return scm

    @staticmethod
    def _notification_signature(apdu) -> tuple:
        """
        Build a value-based signature for a notification so a retransmitted
        copy carrying exactly the same property values can be recognized as
        a duplicate even though it has a new invoke ID.
        """
        if _debug:
            ChangeOfValueServices._debug("_notification_signature")

        signature = []
        for property_value in apdu.listOfValues:
            value_tags = tuple(
                (
                    tag.tag_class,
                    tag.tag_number,
                    tag.tag_lvt,
                    tag.tag_data,
                )
                for tag in property_value.value.tagList
            )
            signature.append(
                (
                    property_value.propertyIdentifier,
                    property_value.propertyArrayIndex,
                    value_tags,
                )
            )

        return tuple(signature)

    async def _process_cov_notification(self, apdu, confirmed: bool) -> None:
        """
        Validate an incoming COV notification against the subscription
        context it claims to belong to and, only when every check passes,
        deliver its values to the consumer.

        The source address, subscriber process identifier, monitored
        object, notification type (confirmed vs. unconfirmed), source
        device identifier and lifetime deadline are all checked against
        what was approved when the subscription was created.  Every outcome
        is recorded in cov_diagnostics so rejected notifications remain
        diagnosable.
        """
        if _debug:
            ChangeOfValueServices._debug("_process_cov_notification %r", apdu)

        address = apdu.pduSource
        subscriber_process_identifier = apdu.subscriberProcessIdentifier

        # find the context that was approved for this source and process
        scm = self._cov_contexts.get((address, subscriber_process_identifier), None)
        if not scm:
            self._record_cov_diagnostic(
                COV_DIAG_UNKNOWN_SUBSCRIPTION,
                apdu,
                "no subscription context for source/process identifier",
            )
            raise ServicesError(errorCode="unknownSubscription")

        # the subscription was canceled or its lifetime has expired, so a
        # late notification must not update the consumer's state
        if not scm.is_active():
            self._record_cov_diagnostic(
                COV_DIAG_SUBSCRIPTION_EXPIRED,
                apdu,
                "subscription canceled or lifetime expired",
            )
            # drop the stale context, keeping the diagnostic as the record
            self._cov_contexts.pop((address, subscriber_process_identifier), None)
            raise ServicesError(errorCode="unknownSubscription")

        # the notification type must match the one the subscription asked
        # for so a confirmed/unconfirmed mismatch cannot sneak values in
        if scm.issue_confirmed_notifications != confirmed:
            expected = (
                "confirmed" if scm.issue_confirmed_notifications else "unconfirmed"
            )
            received = "confirmed" if confirmed else "unconfirmed"
            self._record_cov_diagnostic(
                COV_DIAG_NOTIFICATION_TYPE_MISMATCH,
                apdu,
                f"subscription expects {expected} notification, got {received}",
            )
            raise ServicesError(errorCode="inconsistentParameters")

        # the notification must be for the object the context is bound to
        if apdu.monitoredObjectIdentifier != scm.monitored_object_identifier:
            self._record_cov_diagnostic(
                COV_DIAG_OBJECT_MISMATCH,
                apdu,
                f"context bound to {scm.monitored_object_identifier}",
            )
            raise ServicesError(errorCode="inconsistentParameters")

        # bind the source device on the first notification, then make sure
        # later notifications from the same address still claim that device
        initiating_device_identifier = apdu.initiatingDeviceIdentifier
        if scm.initiating_device_identifier is None:
            scm.initiating_device_identifier = initiating_device_identifier
        elif initiating_device_identifier != scm.initiating_device_identifier:
            self._record_cov_diagnostic(
                COV_DIAG_SOURCE_CHANGED,
                apdu,
                f"address previously sent notifications as "
                f"{scm.initiating_device_identifier}",
            )
            raise ServicesError(errorCode="inconsistentParameters")

        # suppress retransmitted duplicates; they must not enqueue the same
        # values twice, but a confirmed duplicate still gets its ACK so the
        # sender stops retransmitting
        signature = self._notification_signature(apdu)
        if signature == scm.last_notification_signature:
            self._record_cov_diagnostic(
                COV_DIAG_DUPLICATE_NOTIFICATION,
                apdu,
                "identical to the previous notification",
            )
            return
        scm.last_notification_signature = signature

        # queue the property values, flagging the ones this application
        # cannot interpret without dropping the rest of the notification
        unknown_properties = []
        for property_value in apdu.listOfValues:
            property_type, error_message = scm._resolve_property_type(property_value)
            if not property_type:
                unknown_properties.append(
                    (property_value.propertyIdentifier, error_message)
                )
            await scm.put(property_value)

        if unknown_properties:
            self._record_cov_diagnostic(
                COV_DIAG_UNKNOWN_PROPERTY,
                apdu,
                "; ".join(
                    f"{property_identifier}: {error_message}"
                    for property_identifier, error_message in unknown_properties
                ),
            )
        else:
            self._record_cov_diagnostic(COV_DIAG_ACCEPTED, apdu)

    async def do_ConfirmedCOVNotificationRequest(
        self, apdu: ConfirmedCOVNotificationRequest
    ) -> None:
        if _debug:
            ChangeOfValueServices._debug("do_ConfirmedCOVNotificationRequest %r", apdu)

        # validate against the subscription context and deliver the values
        await self._process_cov_notification(apdu, confirmed=True)

        # success - the simple ACK is also sent for duplicates so a
        # retransmitting device stops, and is never sent when the request
        # was rejected because that path raised an error
        resp = SimpleAckPDU(context=apdu)
        if _debug:
            ChangeOfValueServices._debug("    - resp: %r", resp)

        # return the result
        await self.response(resp)

    async def do_UnconfirmedCOVNotificationRequest(
        self, apdu: UnconfirmedCOVNotificationRequest
    ) -> None:
        if _debug:
            ChangeOfValueServices._debug(
                "do_UnconfirmedCOVNotificationRequest %r", apdu
            )

        # validate against the subscription context and deliver the values;
        # rejections are only recorded because there is no way to ACK an
        # unconfirmed notification
        try:
            await self._process_cov_notification(apdu, confirmed=False)
        except ServicesError:
            return

    # -----

    def add_subscription(self, cov):
        if _debug:
            ChangeOfValueServices._debug("add_subscription %r", cov)

        # let the detection algorithm know this is a new or additional subscription
        self._cov_detections[cov.obj_ref.objectIdentifier].add_subscription(cov)

    def cancel_subscription(self, cov):
        if _debug:
            ChangeOfValueServices._debug("cancel_subscription %r", cov)

        # stash the object identifier
        object_identifier = cov.obj_ref.objectIdentifier

        # get the detection algorithm object
        cov_detection = self._cov_detections[object_identifier]

        # let the detection algorithm know this subscription is going away
        cov_detection.cancel_subscription(cov)

        # if the detection algorithm doesn't have any subscriptions, remove it
        if not len(cov_detection.cov_subscriptions):
            if _debug:
                ChangeOfValueServices._debug("    - no more subscriptions")

            # unbind all the hooks into the object
            cov_detection.unbind()

            # delete it from the object map
            del self._cov_detections[object_identifier]

    # -----

    def cov_notification(self, cov, apdu):
        """
        Schedule a task to send out a notification related to a COV subscription.
        """
        if _debug:
            ChangeOfValueServices._debug("cov_notification %r %r", cov, apdu)

        # if this is a confirmed service, this function call will return an
        # APDUFuture and the callback will get the error/reject/abort that
        # comes back, otherwise this is None.
        confirmed_service = self.request(apdu)
        if confirmed_service:
            confirmed_service.add_done_callback(partial(self.cov_confirmation, cov))

    def cov_confirmation(self, cov, future) -> None:
        """
        Callback function for sending out notifications.
        """
        if _debug:
            ChangeOfValueServices._debug("cov_confirmation %r %r", cov, future)

        apdu = future.result()
        if _debug:
            ChangeOfValueServices._debug("    - apdu: %r", apdu)
        if not apdu:
            ChangeOfValueServices._debug("    - simple ack")
            return

    # -----

    async def do_SubscribeCOVRequest(self, apdu):
        if _debug:
            ChangeOfValueServices._debug("do_SubscribeCOVRequest %r", apdu)

        # extract the pieces
        client_addr = apdu.pduSource
        proc_id = apdu.subscriberProcessIdentifier
        obj_id = apdu.monitoredObjectIdentifier
        confirmed = apdu.issueConfirmedNotifications
        lifetime = apdu.lifetime

        # request is to cancel the subscription
        cancel_subscription = (confirmed is None) and (lifetime is None)

        # find the object
        obj = self.get_object_id(obj_id)
        if _debug:
            ChangeOfValueServices._debug("    - object: %r", obj)
        if not obj:
            if cancel_subscription:
                # always return a Result(+), the subscription may have been
                # previously successful and the object deleted, then this
                # cancelation would have been successful
                await self.response(SimpleAckPDU(context=apdu))
                return
            else:
                raise ExecutionError(errorClass="object", errorCode="unknownObject")

        # look for an algorithm already associated with this object
        cov_detection = self._cov_detections.get(obj_id, None)

        # if there isn't one, make one and associate it with the object
        if not cov_detection:
            # look for an associated class and if it's not there it's not supported
            criteria_class = getattr(obj, "_cov_criteria", None)
            if _debug:
                ChangeOfValueServices._debug("    - criteria_class: %r", criteria_class)

            if not criteria_class:
                raise ExecutionError(
                    errorClass="services", errorCode="covSubscriptionFailed"
                )

            # make one of these and bind it to the object
            cov_detection = criteria_class(obj)

            # keep track of it for other subscriptions
            self._cov_detections[obj_id] = cov_detection
        if _debug:
            ChangeOfValueServices._debug("    - cov_detection: %r", cov_detection)

        # can a match be found?
        for cov in cov_detection.cov_subscriptions:
            all_equal = (
                (cov.client_addr == client_addr)
                and (cov.proc_id == proc_id)
                and (cov.obj_id == obj_id)
            )
            if _debug:
                ChangeOfValueServices._debug(
                    "    - cov, all_equal: %r %r", cov, all_equal
                )

            if all_equal:
                break
        else:
            cov = None
        if _debug:
            ChangeOfValueServices._debug("    - cov: %r", cov)

        # if a match was found, update the subscription
        if cov:
            if cancel_subscription:
                if _debug:
                    ChangeOfValueServices._debug("    - cancel the subscription")
                self.cancel_subscription(cov)
            else:
                if _debug:
                    ChangeOfValueServices._debug("    - renew the subscription")
                cov.renew_subscription(lifetime)
        else:
            if cancel_subscription:
                if _debug:
                    ChangeOfValueServices._debug(
                        "    - cancel a subscription that doesn't exist"
                    )
            else:
                if _debug:
                    ChangeOfValueServices._debug("    - create a subscription")

                # make a subscription
                cov = Subscription(
                    obj, client_addr, proc_id, obj_id, confirmed, lifetime, None
                )
                if _debug:
                    ChangeOfValueServices._debug("    - cov: %r", cov)

                # add it to our subscriptions lists
                self.add_subscription(cov)

        # success
        response = SimpleAckPDU(context=apdu)

        # return the result
        await self.response(response)

        # if the subscription is not being canceled, it is new or renewed,
        # so send it a notification when you get a chance.
        if not cancel_subscription:
            if _debug:
                ChangeOfValueServices._debug("    - send a notification")
            loop = asyncio.get_running_loop()
            loop.call_soon(cov_detection.send_cov_notifications, cov)
