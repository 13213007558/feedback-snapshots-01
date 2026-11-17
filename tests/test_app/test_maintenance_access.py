"""
Test Maintenance Service Access
-------------------------------

Sensitive maintenance services (DeviceCommunicationControl,
ReinitializeDevice) must pass a pluggable admission boundary before they
are allowed to change the communication state of a device:

* an externally confirmed identity (the ``maintenance_authorizer`` hook)
  is checked independently of the protocol carried password;
* a protocol carried password is only honored when a secret is actually
  configured - an absent or empty password is never an authorization;
* rejections and verification failures leave the device communication
  state untouched;
* the expiry callback of a superseded control must not override a newer
  authorized control;
* ReinitializeDevice is only simulated through a controlled callback.

All passwords in this file are fake and everything runs in memory - no
test touches a real device or network.
"""

from __future__ import annotations

from typing import List, Optional

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger

from bacpypes3.pdu import Address, GlobalBroadcast
from bacpypes3.apdu import (
    APDU,
    DeviceCommunicationControlRequest,
    UnconfirmedServiceChoice,
    ErrorPDU,
    IAmRequest,
    ReinitializeDeviceRequest,
    SimpleAckPDU,
    WhoIsRequest,
)
from bacpypes3.app import Application
from bacpypes3.local.device import DeviceObject
from bacpypes3.service.device import MaintenanceServiceContext

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# fake credentials, used for testing only
MAINTENANCE_STATION = Address("10.0.0.1")
ORDINARY_STATION = Address("10.0.0.2")
FAKE_PASSWORD = "fake-maintenance-password"
WRONG_PASSWORD = "fake-wrong-password"


@bacpypes_debugging
class MaintenanceApplication(Application):
    """
    An in-memory application that collects its responses, records
    reinitialization callbacks, and traps the post-gate traffic of its
    application service access point so tests can observe what the
    communication control state lets through.
    """

    responses: List[APDU]
    reinitializations: List[str]
    inbound: List[APDU]
    outbound: List[APDU]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.responses = []
        self.reinitializations = []
        self.inbound = []
        self.outbound = []

    async def response(self, apdu: APDU) -> None:  # type: ignore[override]
        self.responses.append(apdu)

    def reinitialize_device(self, reinitialized_state: str) -> None:
        """Controlled callback, simulated only."""
        self.reinitializations.append(reinitialized_state)

    def trap_gates(self) -> None:
        """Replace the ASAP boundary methods with collectors so tests can
        see what passes the communication control gate in each direction."""
        inbound, outbound = self.inbound, self.outbound

        async def sap_request(apdu: APDU) -> None:
            inbound.append(apdu)

        async def request(apdu: APDU) -> None:
            outbound.append(apdu)

        self.asap.sap_request = sap_request  # type: ignore[method-assign]
        self.asap.request = request  # type: ignore[method-assign]


def make_app(
    *,
    password: Optional[str] = None,
    authorizer=None,
    max_time_duration: Optional[int] = None,
) -> MaintenanceApplication:
    """Build an in-memory application with a local device object."""
    app = MaintenanceApplication.from_object_list(
        [
            DeviceObject(
                objectIdentifier=("device", 599),
                objectName="maintenance-test-device",
                vendorIdentifier=999,
            )
        ]
    )
    if password is not None:
        app.device_object._dcc_password = password
    app.maintenance_authorizer = authorizer
    app.maintenance_max_time_duration = max_time_duration
    return app


def maintenance_authorizer(context: MaintenanceServiceContext) -> bool:
    """Admit only the maintenance station based on an identity confirmed
    outside of the protocol."""
    return context.source == MAINTENANCE_STATION


def dcc_request(
    source: Address,
    enable_disable: str,
    time_duration: Optional[int] = None,
    password: Optional[str] = None,
) -> DeviceCommunicationControlRequest:
    request = DeviceCommunicationControlRequest(
        enableDisable=enable_disable,
        timeDuration=time_duration,
        password=password,
    )
    request.pduSource = source
    request.apduInvokeID = 1
    return request


def rd_request(
    source: Address,
    password: Optional[str] = None,
) -> ReinitializeDeviceRequest:
    request = ReinitializeDeviceRequest(
        reinitializedStateOfDevice="coldstart",
        password=password,
    )
    request.pduSource = source
    request.apduInvokeID = 1
    return request


def i_am(source: Address) -> IAmRequest:
    request = IAmRequest(
        iAmDeviceIdentifier=("device", 1001),
        maxAPDULengthAccepted=1024,
        segmentationSupported="noSegmentation",
        vendorID=999,
    )
    request.pduSource = source
    return request


@bacpypes_debugging
class TestMaintenanceAccess:
    async def test_maintenance_source_admitted_by_external_identity(self) -> None:
        """A request from the maintenance station is admitted by the
        external authorizer and changes the communication state."""
        app = make_app(authorizer=maintenance_authorizer)
        try:
            await app.indication(dcc_request(MAINTENANCE_STATION, "disable"))

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], SimpleAckPDU)
            assert app.asap.dccEnableDisable == "disable"
        finally:
            app.close()

    async def test_ordinary_source_denied_and_state_unchanged(self) -> None:
        """A request from an ordinary client is denied and the
        communication state is left untouched."""
        app = make_app(authorizer=maintenance_authorizer)
        try:
            await app.indication(dcc_request(ORDINARY_STATION, "disable"))

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], ErrorPDU)
            assert app.responses[0].errorCode.attr == "serviceRequestDenied"
            assert app.asap.dccEnableDisable == "enable"
        finally:
            app.close()

    async def test_wrong_password_denied_and_state_unchanged(self) -> None:
        """A wrong protocol password fails verification without changing
        the communication state."""
        app = make_app(password=FAKE_PASSWORD)
        try:
            await app.indication(
                dcc_request(MAINTENANCE_STATION, "disable", password=WRONG_PASSWORD)
            )

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], ErrorPDU)
            assert app.responses[0].errorClass.attr == "security"
            assert app.responses[0].errorCode.attr == "passwordFailure"
            assert app.asap.dccEnableDisable == "enable"
        finally:
            app.close()

    async def test_empty_password_not_authorized_without_secret(self) -> None:
        """With no secret configured, an absent or empty password is not
        an authorization."""
        app = make_app()
        try:
            # no password at all
            await app.indication(dcc_request(MAINTENANCE_STATION, "disable"))
            # an empty password value
            await app.indication(
                dcc_request(MAINTENANCE_STATION, "disable", password="")
            )

            assert len(app.responses) == 2
            for response in app.responses:
                assert isinstance(response, ErrorPDU)
                assert response.errorCode.attr == "serviceRequestDenied"
            assert app.asap.dccEnableDisable == "enable"
        finally:
            app.close()

    async def test_correct_password_admitted(self) -> None:
        """The configured secret admits a request carrying the matching
        protocol password, from any source."""
        app = make_app(password=FAKE_PASSWORD)
        try:
            await app.indication(
                dcc_request(ORDINARY_STATION, "disable", password=FAKE_PASSWORD)
            )

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], SimpleAckPDU)
            assert app.asap.dccEnableDisable == "disable"
        finally:
            app.close()

    async def test_duration_over_policy_limit_denied(self) -> None:
        """A time duration beyond the policy limit is denied even for an
        otherwise admitted source."""
        app = make_app(authorizer=maintenance_authorizer, max_time_duration=5)
        try:
            await app.indication(
                dcc_request(MAINTENANCE_STATION, "disable", time_duration=10)
            )

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], ErrorPDU)
            assert app.responses[0].errorCode.attr == "serviceRequestDenied"
            assert app.asap.dccEnableDisable == "enable"
        finally:
            app.close()

    async def test_expired_control_callback_does_not_override_newer_control(
        self,
    ) -> None:
        """The scheduled re-enable of a superseded control must not fire
        over a newer authorized control."""
        app = make_app(authorizer=maintenance_authorizer)
        try:
            await app.indication(
                dcc_request(MAINTENANCE_STATION, "disable", time_duration=1)
            )
            first_epoch = app._dcc_control_epoch
            assert app.asap.dccEnableDisable == "disable"

            # a newer authorized control supersedes the first one
            await app.indication(
                dcc_request(MAINTENANCE_STATION, "disable", time_duration=5)
            )
            second_epoch = app._dcc_control_epoch
            assert second_epoch != first_epoch

            # the expiry callback of the old control changes nothing
            app._dcc_enable_expired(first_epoch)
            assert app.asap.dccEnableDisable == "disable"

            # the expiry callback of the current control re-enables
            app._dcc_enable_expired(second_epoch)
            assert app.asap.dccEnableDisable == "enable"
        finally:
            if app._dcc_enable_handle is not None:
                app._dcc_enable_handle.cancel()
            app.close()

    async def test_reinitialize_device_requires_authorization(self) -> None:
        """ReinitializeDevice is denied for ordinary clients and only
        simulated through the controlled callback for admitted ones."""
        app = make_app(authorizer=maintenance_authorizer)
        try:
            # ordinary client: denied, no ack, no callback
            await app.indication(rd_request(ORDINARY_STATION))
            assert len(app.responses) == 1
            assert isinstance(app.responses[0], ErrorPDU)
            assert app.reinitializations == []

            # maintenance station: acked, simulated via the callback
            await app.indication(rd_request(MAINTENANCE_STATION))
            assert len(app.responses) == 2
            assert isinstance(app.responses[1], SimpleAckPDU)
            assert app.reinitializations == ["coldstart"]
        finally:
            app.close()

    async def test_reinitialize_device_wrong_password_no_callback(self) -> None:
        """A failed verification must not trigger the reinitialization
        callback."""
        app = make_app(password=FAKE_PASSWORD)
        try:
            await app.indication(rd_request(MAINTENANCE_STATION, WRONG_PASSWORD))

            assert len(app.responses) == 1
            assert isinstance(app.responses[0], ErrorPDU)
            assert app.responses[0].errorCode.attr == "passwordFailure"
            assert app.reinitializations == []
        finally:
            app.close()

    async def test_communication_gates_follow_control_mode(self) -> None:
        """After an authorized control, the state machine access point
        actually gates traffic per the protocol: when disabled only the
        necessary management services are received and nothing is
        initiated; when initiation is disabled only I-Am goes out."""
        app = make_app(authorizer=maintenance_authorizer)
        try:
            app.trap_gates()

            who_is = WhoIsRequest(destination=GlobalBroadcast())
            who_is.pduSource = ORDINARY_STATION

            # communications enabled: everything passes
            await app.asap.confirmation(who_is.encode().encode())
            await app.asap.confirmation(i_am(ORDINARY_STATION).encode().encode())
            await app.asap.sap_indication(i_am(MAINTENANCE_STATION))
            assert len(app.inbound) == 2
            assert len(app.outbound) == 1

            # disable all communication
            await app.indication(dcc_request(MAINTENANCE_STATION, "disable"))
            assert app.asap.dccEnableDisable == "disable"
            app.inbound.clear()
            app.outbound.clear()

            # Who-Is is a necessary management service and still received,
            # an I-Am is not; nothing is initiated
            await app.asap.confirmation(who_is.encode().encode())
            await app.asap.confirmation(i_am(ORDINARY_STATION).encode().encode())
            await app.asap.sap_indication(i_am(MAINTENANCE_STATION))
            assert len(app.inbound) == 1
            assert isinstance(app.inbound[0], WhoIsRequest)
            assert len(app.outbound) == 0

            # disable initiation only
            await app.indication(dcc_request(MAINTENANCE_STATION, "disableInitiation"))
            assert app.asap.dccEnableDisable == "disableInitiation"
            app.inbound.clear()
            app.outbound.clear()

            # reception is unaffected; only I-Am may be initiated
            await app.asap.confirmation(i_am(ORDINARY_STATION).encode().encode())
            await app.asap.sap_indication(i_am(MAINTENANCE_STATION))
            await app.asap.sap_indication(who_is)
            assert len(app.inbound) == 1
            assert len(app.outbound) == 1
            assert app.outbound[0].apduService == UnconfirmedServiceChoice.iAm

            # re-enable restores full communication
            await app.indication(dcc_request(MAINTENANCE_STATION, "enable"))
            assert app.asap.dccEnableDisable == "enable"
            app.inbound.clear()
            app.outbound.clear()

            await app.asap.confirmation(i_am(ORDINARY_STATION).encode().encode())
            await app.asap.sap_indication(who_is)
            assert len(app.inbound) == 1
            assert len(app.outbound) == 1
        finally:
            app.close()
