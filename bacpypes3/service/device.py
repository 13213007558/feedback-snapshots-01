"""
Application Module
"""

from __future__ import annotations

import asyncio
import hmac

from typing import (
    Callable,
    Dict,
    List,
    Optional,
)

from ..debugging import bacpypes_debugging, ModuleLogger

from ..pdu import Address, GlobalBroadcast

from ..errors import (
    ExecutionError,
    InconsistentParameters,
    MissingRequiredParameter,
    ParameterOutOfRange,
)
from ..primitivedata import (
    CharacterString,
    ObjectIdentifier,
)
from ..basetypes import WhoHasLimits, WhoHasObject
from ..apdu import (
    WhoIsRequest,
    IAmRequest,
    WhoHasRequest,
    IHaveRequest,
    DeviceCommunicationControlRequest,
    ReinitializeDeviceRequest,
    SimpleAckPDU,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# service timeouts
WHO_IS_TIMEOUT = 3.0  # how long to wait for I-Am's
WHO_HAS_TIMEOUT = 3.0  # how long to wait for I-Have's


@bacpypes_debugging
class WhoIsFuture:
    _debug: Callable[..., None]

    low_limit: Optional[int]
    high_limit: Optional[int]
    timeout: Optional[int]
    future: asyncio.Future

    i_ams: Dict[int, IAmRequest]
    only_one: bool

    def __init__(
        self,
        app: WhoIsIAmServices,
        address: Optional[Address],
        low_limit: Optional[int],
        high_limit: Optional[int],
        timeout: Optional[int],
    ) -> None:
        if _debug:
            WhoIsFuture._debug(
                "__init__ %r %r %r %r %r",
                app,
                address,
                low_limit,
                high_limit,
                timeout,
            )

        self.app = app
        self.address = address
        self.low_limit = low_limit
        self.high_limit = high_limit
        self.timeout = timeout

        self.i_ams = {}
        self.only_one = (address is not None) or (
            (low_limit == high_limit) and (low_limit is not None)
        )

        # create a future and add a callback when it is resolved
        self.future = asyncio.Future()
        self.future.add_done_callback(self.who_is_done)
        if _debug:
            WhoIsFuture._debug("    - future: %r", self.future)

        # get the loop to schedule a time to stop looking
        loop = asyncio.get_event_loop()
        if _debug:
            WhoIsFuture._debug("    - loop time: %r", loop.time())

        # schedule a call
        self.who_is_timeout_handle = loop.call_later(self.timeout, self.who_is_timeout)
        if _debug:
            WhoIsFuture._debug(
                "    - who_is_timeout_handle: %r", self.who_is_timeout_handle
            )

    def match(self, apdu: IAmRequest) -> None:
        """
        This function is called for each incoming IAmRequest to see if it
        matches the criteria.
        """
        if _debug:
            WhoIsFuture._debug("match %r", apdu)

        # extract the device instance number
        device_instance = apdu.iAmDeviceIdentifier[1]
        if _debug:
            WhoIsFuture._debug("    - device_instance: %r", device_instance)

        # filter out those that don't match
        if self.address is not None:
            if apdu.pduSource != self.address:
                return
        if (self.low_limit is not None) and (device_instance < self.low_limit):
            return
        if (self.high_limit is not None) and (device_instance > self.high_limit):
            return

        # if we're only looking for one we found it - but the future may
        # already be resolved: who_is_timeout() can fire (or a previous
        # matching I-Am can arrive) before who_is_done() has had a chance
        # to run and remove this future from app._who_is_futures, because
        # add_done_callback() schedules that removal rather than running
        # it synchronously with set_result(). A duplicate/retransmitted
        # I-Am, or simply more than one device replying to the same
        # Who-Is, hits this every time without the guard.
        if self.only_one:
            if self.future.done():
                if _debug:
                    WhoIsFuture._debug("    - already resolved, ignoring")
                return
            if _debug:
                WhoIsFuture._debug("    - found it")
            self.future.set_result([apdu])
        else:
            if _debug:
                WhoIsFuture._debug("    - found one")
            # add this to the dictionary that was found
            self.i_ams[device_instance] = apdu

        # provide this to the application device information cache
        asyncio.ensure_future(self.app.device_info_cache.set_device_info(apdu))

    def who_is_done(self, future: asyncio.Future) -> None:
        """The future has been completed or canceled."""
        if _debug:
            WhoIsFuture._debug("who_is_done %r", future)

        # remove ourselves from the pending requests
        self.app._who_is_futures.remove(self)

        # if the timeout is still scheduled, cancel it
        self.who_is_timeout_handle.cancel()

    def who_is_timeout(self):
        """The timeout has elapsed, save the I-Am messages we found in the
        future."""
        if _debug:
            WhoIsFuture._debug("who_is_timeout")

        # match() may have already resolved this future (see the comment
        # there) if an I-Am arrived in the same event loop iteration that
        # the timeout was scheduled to fire in
        if self.future.done():
            if _debug:
                WhoIsFuture._debug("    - already resolved, ignoring")
            return

        self.future.set_result(list(self.i_ams.values()))


#
#   Who-Is I-Am Services
#


@bacpypes_debugging
class WhoIsIAmServices:
    _who_is_futures: List[WhoIsFuture]

    def who_is(
        self,
        low_limit: Optional[int] = None,
        high_limit: Optional[int] = None,
        address: Optional[Address] = None,
        timeout: Optional[int] = WHO_IS_TIMEOUT,
    ) -> asyncio.Future:
        if _debug:
            WhoIsIAmServices._debug("who_is")

        # should be __init__
        if not hasattr(self, "_who_is_futures"):
            self._who_is_futures = []

        # build a request
        who_is = WhoIsRequest(destination=address or GlobalBroadcast())

        # check for consistent parameters
        if low_limit is not None:
            if high_limit is None:
                raise MissingRequiredParameter("high_limit required")
            if (low_limit < 0) or (low_limit > 4194303):
                raise ParameterOutOfRange("low_limit out of range")

            # low limit is fine
            who_is.deviceInstanceRangeLowLimit = low_limit

        if high_limit is not None:
            if low_limit is None:
                raise MissingRequiredParameter("low_limit required")
            if (high_limit < 0) or (high_limit > 4194303):
                raise ParameterOutOfRange("high_limit out of range")

            # high limit is fine
            who_is.deviceInstanceRangeHighLimit = high_limit

        if _debug:
            WhoIsIAmServices._debug("    - who_is: %r", who_is)

        # create a future, store a reference to it to be resolved
        who_is_future = WhoIsFuture(
            self,
            address
            if address and (address.is_localstation or address.is_remotestation)
            else None,
            low_limit,
            high_limit,
            timeout,
        )
        self._who_is_futures.append(who_is_future)

        # function returns a finished future that can be ignored
        self.request(who_is)

        return who_is_future.future

    async def do_WhoIsRequest(self, apdu) -> None:
        """Respond to a Who-Is request."""
        if _debug:
            WhoIsIAmServices._debug("do_WhoIsRequest %r", apdu)

        # ignore this if there's no local device
        if not self.device_object:
            if _debug:
                WhoIsIAmServices._debug("    - no local device")
            return

        # extract the parameters
        low_limit = apdu.deviceInstanceRangeLowLimit
        high_limit = apdu.deviceInstanceRangeHighLimit

        # check for consistent parameters
        if low_limit is not None:
            if high_limit is None:
                raise MissingRequiredParameter("deviceInstanceRangeHighLimit required")
            if (low_limit < 0) or (low_limit > 4194303):
                raise ParameterOutOfRange("deviceInstanceRangeLowLimit out of range")
        if high_limit is not None:
            if low_limit is None:
                raise MissingRequiredParameter("deviceInstanceRangeLowLimit required")
            if (high_limit < 0) or (high_limit > 4194303):
                raise ParameterOutOfRange("deviceInstanceRangeHighLimit out of range")

        # see we should respond
        if low_limit is not None:
            if self.device_object.objectIdentifier[1] < low_limit:
                return
        if high_limit is not None:
            if self.device_object.objectIdentifier[1] > high_limit:
                return

        # generate an I-Am
        self.i_am(address=apdu.pduSource)

    def i_am(self, address=None) -> None:
        if _debug:
            WhoIsIAmServices._debug("i_am %r", address)

        # this requires a local device
        if not self.device_object:
            if _debug:
                WhoIsIAmServices._debug("    - no local device")
            return

        # create a I-Am "response" back to the source
        i_am = IAmRequest(
            iAmDeviceIdentifier=self.device_object.objectIdentifier,
            maxAPDULengthAccepted=self.device_object.maxApduLengthAccepted,
            segmentationSupported=self.device_object.segmentationSupported,
            vendorID=self.device_object.vendorIdentifier,
            destination=address or GlobalBroadcast(),
        )
        if _debug:
            WhoIsIAmServices._debug("    - i_am: %r", i_am)

        # function returns a finished future that can be ignored
        self.request(i_am)

    async def do_IAmRequest(self, apdu) -> None:
        """Respond to an I-Am request."""
        if _debug:
            WhoIsIAmServices._debug("do_IAmRequest %r", apdu)

        # should be __init__
        if not hasattr(self, "_who_is_futures"):
            self._who_is_futures = []

        # check for required parameters
        if apdu.iAmDeviceIdentifier is None:
            raise MissingRequiredParameter("iAmDeviceIdentifier required")
        if apdu.maxAPDULengthAccepted is None:
            raise MissingRequiredParameter("maxAPDULengthAccepted required")
        if apdu.segmentationSupported is None:
            raise MissingRequiredParameter("segmentationSupported required")
        if apdu.vendorID is None:
            raise MissingRequiredParameter("vendorID required")

        # see if we're waiting for this "response"
        for who_is_future in self._who_is_futures:
            who_is_future.match(apdu)


@bacpypes_debugging
class WhoHasFuture:
    _debug: Callable[..., None]

    app: WhoHasIHaveServices
    low_limit: Optional[int]
    high_limit: Optional[int]
    object_identifier: Optional[ObjectIdentifier]
    object_name: Optional[CharacterString]
    timeout: Optional[int]
    future: asyncio.Future

    i_haves: List[IHaveRequest]
    only_one: bool

    def __init__(
        self,
        app: WhoHasIHaveServices,
        low_limit: Optional[int],
        high_limit: Optional[int],
        object_identifier: Optional[ObjectIdentifier],
        object_name: Optional[CharacterString],
        timeout: Optional[int],
    ) -> None:
        if _debug:
            WhoHasFuture._debug(
                "__init__ %r %r %r %r %r %r",
                app,
                low_limit,
                high_limit,
                object_identifier,
                object_name,
                timeout,
            )

        self.app = app
        self.low_limit = low_limit
        self.high_limit = high_limit
        self.object_identifier = object_identifier
        self.object_name = object_name
        self.timeout = timeout

        self.i_haves = []
        self.only_one = (low_limit == high_limit) and (low_limit is not None)

        # create a future and add a callback when it is resolved
        self.future = asyncio.Future()
        self.future.add_done_callback(self.who_has_done)
        if _debug:
            WhoHasFuture._debug("    - future: %r", self.future)

        # get the loop to schedule a time to stop looking
        loop = asyncio.get_event_loop()
        if _debug:
            WhoHasFuture._debug("    - loop time: %r", loop.time())

        # schedule a call
        self.who_has_timeout_handle = loop.call_later(
            self.timeout, self.who_has_timeout
        )
        if _debug:
            WhoHasFuture._debug(
                "    - who_has_timeout_handle: %r", self.who_has_timeout_handle
            )

    def match(self, apdu: IHaveRequest) -> None:
        """
        This function is called for each incoming IHaveRequest to see if it
        matches the criteria.
        """
        if _debug:
            WhoHasFuture._debug("match %r", apdu)

        # extract the device instance number
        device_instance = apdu.deviceIdentifier[1]
        if _debug:
            WhoHasFuture._debug("    - device_instance: %r", device_instance)

        # filter out those that don't match
        if (self.low_limit is not None) and (device_instance < self.low_limit):
            return
        if (self.high_limit is not None) and (device_instance > self.high_limit):
            return
        if self.object_identifier is not None:
            if apdu.objectIdentifier != self.object_identifier:
                return
        if self.object_name is not None:
            if apdu.objectName != self.object_name:
                return

        # if we're only looking for one we found it
        if self.only_one:
            if _debug:
                WhoHasFuture._debug("    - found it")
            self.future.set_result([apdu])
        else:
            if _debug:
                WhoHasFuture._debug("    - found one")
            # add this to the list that was found
            self.i_haves.append(apdu)

    def who_has_done(self, future: asyncio.Future) -> None:
        """The future has been completed or canceled."""
        if _debug:
            WhoHasFuture._debug("who_has_done %r", future)

        # remove ourselves from the pending requests
        self.app._who_has_futures.remove(self)

        # if the timeout is still scheduled, cancel it
        self.who_has_timeout_handle.cancel()

    def who_has_timeout(self):
        """The timeout has elapsed, save the I-Am messages we found in the
        future."""
        if _debug:
            WhoHasFuture._debug("who_has_timeout")

        self.future.set_result(self.i_haves)


#
#   Who-Has I-Have Services
#


@bacpypes_debugging
class WhoHasIHaveServices:
    _debug: Callable[..., None]

    _who_has_futures: List[WhoHasFuture]

    def who_has(
        self,
        low_limit: Optional[int] = None,
        high_limit: Optional[int] = None,
        object_identifier: Optional[ObjectIdentifier] = None,
        object_name: Optional[CharacterString] = None,
        address=None,
        timeout: Optional[int] = WHO_HAS_TIMEOUT,
    ):
        if _debug:
            WhoHasIHaveServices._debug(
                "who_has %r %r %r %r address=%r timeout=%r",
                low_limit,
                high_limit,
                object_identifier,
                object_name,
                address,
                timeout,
            )

        # should be __init__
        if not hasattr(self, "_who_has_futures"):
            self._who_has_futures = []

        # build a request
        who_has = WhoHasRequest(destination=address or GlobalBroadcast())

        if (low_limit is not None) or (high_limit is not None):
            who_has_limits = WhoHasLimits()
            # check for consistent parameters
            if low_limit is not None:
                if high_limit is None:
                    raise MissingRequiredParameter("high_limit required")
                if (low_limit < 0) or (low_limit > 4194303):
                    raise ParameterOutOfRange("low_limit out of range")

                # low limit is fine
                who_has_limits.deviceInstanceRangeLowLimit = low_limit

            if high_limit is not None:
                if low_limit is None:
                    raise MissingRequiredParameter("low_limit required")
                if (high_limit < 0) or (high_limit > 4194303):
                    raise ParameterOutOfRange("high_limit out of range")

                # high limit is fine
                who_has_limits.deviceInstanceRangeHighLimit = high_limit

            who_has.limits = who_has_limits

        if object_identifier is not None:
            who_has.object = WhoHasObject(objectIdentifier=object_identifier)
        if object_name is not None:
            who_has.object = WhoHasObject(objectName=object_name)

        if _debug:
            WhoIsIAmServices._debug("    - who_has: %r", who_has)

        # create a future, store a reference to it to be resolved
        who_has_future = WhoHasFuture(
            self,
            low_limit,
            high_limit,
            object_identifier,
            object_name,
            timeout,
        )
        self._who_has_futures.append(who_has_future)

        # function returns a finished future that can be ignored
        self.request(who_has)

        return who_has_future.future

    async def do_WhoHasRequest(self, apdu: WhoHasRequest) -> None:
        """Respond to a Who-Has request."""
        if _debug:
            WhoHasIHaveServices._debug("do_WhoHasRequest, %r", apdu)

        # ignore this if there's no local device
        if not self.device_object:
            if _debug:
                WhoHasIHaveServices._debug("    - no local device")
            return

        # if this has limits, check them like Who-Is
        if apdu.limits is not None:
            # extract the parameters
            low_limit = apdu.limits.deviceInstanceRangeLowLimit
            high_limit = apdu.limits.deviceInstanceRangeHighLimit

            # check for consistent parameters
            if low_limit is None:
                raise MissingRequiredParameter("deviceInstanceRangeLowLimit required")
            if (low_limit < 0) or (low_limit > 4194303):
                raise ParameterOutOfRange("deviceInstanceRangeLowLimit out of range")
            if high_limit is None:
                raise MissingRequiredParameter("deviceInstanceRangeHighLimit required")
            if (high_limit < 0) or (high_limit > 4194303):
                raise ParameterOutOfRange("deviceInstanceRangeHighLimit out of range")

            # see we should respond
            if self.device_object.objectIdentifier[1] < low_limit:
                return
            if self.device_object.objectIdentifier[1] > high_limit:
                return

        # check the search criteria
        if (apdu.object.objectIdentifier is None) and (apdu.object.objectName is None):
            raise InconsistentParameters("object identifier or object name required")

        # find the object by identifier
        obj_id = None
        if apdu.object.objectIdentifier is not None:
            obj_id = self.objectIdentifier.get(apdu.object.objectIdentifier, None)
            if _debug:
                WhoHasIHaveServices._debug("    - obj_id: %r", obj_id)
            if not obj_id:
                return

        # find the object by name
        obj_name = None
        if apdu.object.objectName is not None:
            obj_name = self.objectName.get(apdu.object.objectName, None)
            if _debug:
                WhoHasIHaveServices._debug("    - obj_name: %r", obj_name)
            if not obj_name:
                return

        # either both refer to the same object, or search was just for one
        # of the two criteria to match
        if obj_id and obj_name:
            if obj_id is obj_name:
                obj = obj_id
        else:
            obj = obj_id or obj_name

        # maybe we don't have it
        if not obj:
            return

        # send out the response
        self.i_have(obj.objectIdentifier, obj.objectName, address=apdu.pduSource)

    def i_have(
        self,
        object_identifier: ObjectIdentifier,
        object_name: CharacterString,
        address=None,
    ) -> None:
        if _debug:
            WhoHasIHaveServices._debug(
                "i_have %r %r address=%r", object_identifier, object_name, address
            )

        # ignore this if there's no local device
        if not self.device_object:
            if _debug:
                WhoHasIHaveServices._debug("    - no local device")
            return

        # build the request
        i_have = IHaveRequest(
            deviceIdentifier=self.device_object.objectIdentifier,
            objectIdentifier=object_identifier,
            objectName=object_name,
            destination=address or GlobalBroadcast(),
        )

        # function returns a finished future that can be ignored
        self.request(i_have)

    async def do_IHaveRequest(self, apdu: IHaveRequest) -> None:
        """Respond to a I-Have request."""
        if _debug:
            WhoHasIHaveServices._debug("do_IHaveRequest %r", apdu)

        # should be __init__
        if not hasattr(self, "_who_has_futures"):
            self._who_has_futures = []

        # check for required parameters
        if apdu.deviceIdentifier is None:
            raise MissingRequiredParameter("deviceIdentifier required")
        if apdu.objectIdentifier is None:
            raise MissingRequiredParameter("objectIdentifier required")
        if apdu.objectName is None:
            raise MissingRequiredParameter("objectName required")

        # see if we're waiting for this "response"
        for who_has_future in self._who_has_futures:
            who_has_future.match(apdu)


#
#   Maintenance Service Access
#


@bacpypes_debugging
class MaintenanceServiceContext:
    """
    The decision basis for admitting a sensitive maintenance service
    request (DeviceCommunicationControl, ReinitializeDevice).  This is
    what gets logged and what an external authorizer sees; it deliberately
    does not carry the password value, only whether one was provided.
    """

    _debug: Callable[..., None]

    service: str
    source: Optional[Address]
    enable_disable: Optional[str]
    time_duration: Optional[int]
    reinitialized_state: Optional[str]
    password_provided: bool

    def __init__(
        self,
        service: str,
        source: Optional[Address],
        *,
        enable_disable: Optional[str] = None,
        time_duration: Optional[int] = None,
        reinitialized_state: Optional[str] = None,
        password_provided: bool = False,
    ) -> None:
        if _debug:
            MaintenanceServiceContext._debug(
                "__init__ %r %r ...", service, source
            )

        self.service = service
        self.source = source
        self.enable_disable = enable_disable
        self.time_duration = time_duration
        self.reinitialized_state = reinitialized_state
        self.password_provided = password_provided

    def __repr__(self) -> str:
        contents = "service={!r} source={!r}".format(self.service, self.source)
        if self.enable_disable is not None:
            contents += " enable/disable={!r}".format(self.enable_disable)
        if self.time_duration is not None:
            contents += " timeDuration={!r}".format(self.time_duration)
        if self.reinitialized_state is not None:
            contents += " reinitializedState={!r}".format(self.reinitialized_state)
        contents += " passwordProvided={!r}".format(self.password_provided)
        return "<{} {}>".format(self.__class__.__name__, contents)


@bacpypes_debugging
class MaintenanceAccessServices:
    """
    Pluggable admission boundary for sensitive maintenance services.

    Two independent credentials are recognized:

    * an externally confirmed identity - set ``maintenance_authorizer``
      to a callable that receives the MaintenanceServiceContext (service,
      source, control mode, duration) and returns true if the identity
      established outside of the protocol (client certificate, operator
      session, ...) is allowed to perform the request;

    * the protocol carried password - matched against the secret
      configured as ``_dcc_password`` on the local device object.

    When no secret is configured an absent or empty password is not an
    authorization; the request is denied unless the external authorizer
    grants it.
    """

    _debug: Callable[..., None]

    # hook for an externally confirmed identity
    maintenance_authorizer: Optional[Callable[[MaintenanceServiceContext], bool]] = (
        None
    )

    # policy limit for DeviceCommunicationControl timeDuration (minutes),
    # None for no limit
    maintenance_max_time_duration: Optional[int] = None

    def maintenance_password(self) -> Optional[str]:
        """Return the configured maintenance secret, if any."""
        if _debug:
            MaintenanceAccessServices._debug("maintenance_password")

        device_object = getattr(self, "device_object", None)
        if device_object is None:
            return None

        password = getattr(device_object, "_dcc_password", None)
        if not password:
            return None
        return str(password)

    def authorize_maintenance(
        self, context: MaintenanceServiceContext, password: Optional[str]
    ) -> None:
        """
        Raise an ExecutionError if the request described by the context is
        not admitted; returns normally when it is.  Only the decision
        basis is logged, never the password value.
        """
        if _debug:
            MaintenanceAccessServices._debug("authorize_maintenance %r", context)

        # policy check on the requested duration
        max_time_duration = self.maintenance_max_time_duration
        if (
            (context.time_duration is not None)
            and (max_time_duration is not None)
            and (context.time_duration > max_time_duration)
        ):
            _log.info(
                "maintenance request denied: %r duration over limit %r",
                context,
                max_time_duration,
            )
            raise ExecutionError(
                errorClass="services", errorCode="serviceRequestDenied"
            )

        # an externally confirmed identity can admit the request
        authorizer = self.maintenance_authorizer
        if (authorizer is not None) and authorizer(context):
            _log.info("maintenance request granted: %r external identity", context)
            return

        # a protocol carried password can admit the request, but only
        # against a configured secret
        secret = self.maintenance_password()
        if secret is not None:
            if (password is not None) and hmac.compare_digest(
                str(password), secret
            ):
                _log.info("maintenance request granted: %r password", context)
                return
            _log.info("maintenance request denied: %r password failure", context)
            raise ExecutionError(errorClass="security", errorCode="passwordFailure")

        # no secret configured, no external identity - an absent or empty
        # password is not an authorization
        _log.info("maintenance request denied: %r no credentials configured", context)
        raise ExecutionError(errorClass="services", errorCode="serviceRequestDenied")


#
#   Device Communication Control
#


@bacpypes_debugging
class DeviceCommunicationControlServices(MaintenanceAccessServices):
    _dcc_enable_handle: Optional[asyncio.TimerHandle] = None
    _dcc_control_epoch: int = 0

    async def do_DeviceCommunicationControlRequest(
        self, apdu: DeviceCommunicationControlRequest
    ) -> None:
        if _debug:
            DeviceCommunicationControlServices._debug(
                "do_CommunicationControlRequest, %r", apdu
            )

        # the control mode is required to interpret the request
        if apdu.enableDisable is None:
            raise MissingRequiredParameter("enableDisable required")
        enable_disable = apdu.enableDisable.attr
        if enable_disable not in ("enable", "disable", "disableInitiation"):
            raise ParameterOutOfRange("enableDisable out of range")

        # a time duration is only meaningful when communications are
        # being disabled
        if (enable_disable == "enable") and (apdu.timeDuration is not None):
            raise InconsistentParameters("timeDuration only when disabling")

        # check the admission boundary before any state change
        context = MaintenanceServiceContext(
            "deviceCommunicationControl",
            apdu.pduSource,
            enable_disable=enable_disable,
            time_duration=apdu.timeDuration,
            password_provided=apdu.password is not None,
        )
        self.authorize_maintenance(context, apdu.password)

        if enable_disable == "enable":
            self.enable_communications()

        else:
            # disable or disableInitiation
            self.disable_communications(enable_disable)

            # if there is a time duration, it's in minutes
            if apdu.timeDuration:
                epoch = self._dcc_control_epoch
                self._dcc_enable_handle = asyncio.get_event_loop().call_later(
                    apdu.timeDuration * 60, self._dcc_enable_expired, epoch
                )
                if _debug:
                    DeviceCommunicationControlServices._debug(
                        "    - enable scheduled, epoch %r", epoch
                    )

        # respond with a simple ack
        await self.response(SimpleAckPDU(context=apdu))

    def _dcc_enable_expired(self, epoch: int) -> None:
        """A scheduled re-enable fired; ignore it if a newer control has
        been authorized since it was scheduled."""
        if _debug:
            DeviceCommunicationControlServices._debug(
                "_dcc_enable_expired %r (current %r)", epoch, self._dcc_control_epoch
            )

        if epoch != self._dcc_control_epoch:
            if _debug:
                DeviceCommunicationControlServices._debug("    - superseded")
            return

        self._dcc_enable_handle = None
        self.enable_communications()

    def enable_communications(self):
        if _debug:
            DeviceCommunicationControlServices._debug("enable_communications")

        # a new control supersedes any previously scheduled re-enable
        self._dcc_control_epoch += 1

        # tell the State Machine Access Point
        self.asap.dccEnableDisable = "enable"

        # if an enable task was scheduled, cancel it
        if self._dcc_enable_handle:
            self._dcc_enable_handle.cancel()
            self._dcc_enable_handle = None

    def disable_communications(self, enable_disable):
        if _debug:
            DeviceCommunicationControlServices._debug(
                "disable_communications %r", enable_disable
            )

        # a new control supersedes any previously scheduled re-enable
        self._dcc_control_epoch += 1

        # tell the State Machine Access Point
        self.asap.dccEnableDisable = enable_disable

        # if an enable task was scheduled, cancel it
        if self._dcc_enable_handle:
            self._dcc_enable_handle.cancel()
            self._dcc_enable_handle = None


#
#   Reinitialize Device
#


@bacpypes_debugging
class ReinitializeDeviceServices(MaintenanceAccessServices):
    async def do_ReinitializeDeviceRequest(
        self, apdu: ReinitializeDeviceRequest
    ) -> None:
        if _debug:
            ReinitializeDeviceServices._debug("do_ReinitializeDeviceRequest %r", apdu)

        if apdu.reinitializedStateOfDevice is None:
            raise MissingRequiredParameter("reinitializedStateOfDevice required")

        # check the admission boundary before any state change
        context = MaintenanceServiceContext(
            "reinitializeDevice",
            apdu.pduSource,
            reinitialized_state=apdu.reinitializedStateOfDevice.attr,
            password_provided=apdu.password is not None,
        )
        self.authorize_maintenance(context, apdu.password)

        # respond with a simple ack first, the reinitialization follows
        await self.response(SimpleAckPDU(context=apdu))

        # controlled callback, the default only simulates the request
        self.reinitialize_device(apdu.reinitializedStateOfDevice.attr)

    def reinitialize_device(self, reinitialized_state: str) -> None:
        """
        Controlled reinitialization callback.  The default implementation
        only simulates the request by logging the decision basis; override
        this to hook a supervised reinitialization of the application.
        """
        if _debug:
            ReinitializeDeviceServices._debug(
                "reinitialize_device %r", reinitialized_state
            )
        _log.info("reinitialize device simulated: %r", reinitialized_state)
