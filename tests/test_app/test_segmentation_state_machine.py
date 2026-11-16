"""
Segmentation State Machine Regression
-------------------------------------

A segmented message is scoped to the pair ``(source address, invoke ID)``.
A segment that merely carries the right sequence number must never be spliced
into a transaction that belongs to another endpoint, or to another request.

These tests drive the ``ClientSSM`` and ``ServerSSM`` directly and pin down
the behaviour required of a receiver/sender of segmented APDUs:

* a retransmitted (duplicate) segment inside the window is positively
  acknowledged, never appended a second time;
* a segment that leaves a gap inside the window is negatively acknowledged
  with the last sequence number received *in order*, so the sender resumes
  from the gap;
* a segment whose sequence number is outside the negotiated window cannot be
  merged into the half-assembled message;
* a stale duplicate window acknowledgement must not change the negotiated
  window size while a transaction is in flight;
* after an Abort (or completion) a late segment is ignored, the timer is
  stopped, the transaction leaves the active list, and no partially
  reassembled APDU is ever handed to the application.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from bacpypes3.apdu import (
    AbortPDU,
    AbortReason,
    ComplexAckPDU,
    ConfirmedRequestPDU,
    ReadPropertyRequest,
    SegmentAckPDU,
)
from bacpypes3.appservice import (
    ABORTED,
    AWAIT_RESPONSE,
    COMPLETED,
    SEGMENTED_CONFIRMATION,
    SEGMENTED_REQUEST,
    SEGMENTED_RESPONSE,
    ClientSSM,
    ServerSSM,
)
from bacpypes3.basetypes import PropertyIdentifier, Segmentation
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier

# some debugging
_debug = 0
_log = ModuleLogger(globals())

PEER_A = Address("10.0.0.1")
PEER_B = Address("10.0.0.2")
INVOKE_ID = 7
SERVICE = 12


class _NullDeviceInfoCache:
    """The SSM only needs an async lookup; an empty cache models an unknown
    peer so the machines fall back to their own segmentation limits."""

    async def get_device_info(self, address):
        return None

    def update_device_info(self, device_info):
        return None


def make_sap() -> MagicMock:
    sap = MagicMock()
    sap.device_object = None
    sap.numberOfApduRetries = 3
    sap.apduTimeout = 3000
    sap.segmentationSupported = Segmentation.segmentedBoth
    sap.segmentTimeout = 1500
    sap.maxSegmentsAccepted = 16
    sap.maxApduLengthAccepted = 1024
    sap.proposedWindowSize = 2
    sap.applicationTimeout = 3000
    sap.device_info_cache = _NullDeviceInfoCache()
    sap.request = AsyncMock()
    sap.response = AsyncMock()
    sap.sap_request = AsyncMock()
    sap.sap_response = AsyncMock()
    sap.serverTransactions = []
    sap.clientTransactions = []
    return sap


def request_segment(
    sequence: int,
    more: bool,
    data: bytes,
    *,
    invoke_id: int = INVOKE_ID,
    source: Address = PEER_A,
    window: int = 2,
) -> ConfirmedRequestPDU:
    apdu = ConfirmedRequestPDU(SERVICE, invoke_id)
    apdu.apduSeg = True
    apdu.apduMor = more
    apdu.apduSeq = sequence
    apdu.apduWin = window
    apdu.apduSA = True
    apdu.apduMaxSegs = 4
    apdu.apduMaxResp = 4
    apdu.put_data(data)
    apdu.pduSource = source
    return apdu


def complex_ack_segment(
    sequence: int,
    more: bool,
    data: bytes,
    *,
    invoke_id: int = INVOKE_ID,
    source: Address = PEER_B,
    window: int = 2,
) -> ComplexAckPDU:
    apdu = ComplexAckPDU(SERVICE, invoke_id)
    apdu.apduSeg = True
    apdu.apduMor = more
    apdu.apduSeq = sequence
    apdu.apduWin = window
    apdu.put_data(data)
    apdu.pduSource = source
    return apdu


def make_receiving_server(sap: MagicMock) -> ServerSSM:
    """A server that has accepted segment 0 and is waiting for segment 1."""
    ssm = ServerSSM(sap, PEER_A)
    sap.serverTransactions.append(ssm)

    first = request_segment(0, True, b"AA")
    # mimic the idle() bookkeeping without going through the whole method:
    # the context starts empty and the first segment is appended into it
    context = ConfirmedRequestPDU(SERVICE, INVOKE_ID)
    ssm.invokeID = INVOKE_ID
    ssm.set_segmentation_context(context)
    ssm.append_segment(first)
    # a three-segment window leaves room for an in-window gap at sequence 2
    ssm.actualWindowSize = 3
    ssm.lastSequenceNumber = 0
    ssm.initialSequenceNumber = 0
    ssm.state = SEGMENTED_REQUEST
    ssm.segmentRetryCount = 0
    return ssm


def make_receiving_client(sap: MagicMock) -> ClientSSM:
    """A client that has accepted complex-ack segment 0 and is waiting for
    segment 1."""
    ssm = ClientSSM(sap, PEER_B)
    sap.clientTransactions.append(ssm)

    first = complex_ack_segment(0, True, b"AA")
    context = ComplexAckPDU(SERVICE, INVOKE_ID)
    ssm.invokeID = INVOKE_ID
    ssm.set_segmentation_context(context)
    ssm.append_segment(first)
    ssm.actualWindowSize = 3
    ssm.lastSequenceNumber = 0
    ssm.initialSequenceNumber = 0
    ssm.state = SEGMENTED_CONFIRMATION
    ssm.segmentRetryCount = 0
    ssm.sentAllSegments = True
    return ssm


def latest_device_pdu(ssm):
    """Return the most recent APDU sent toward the peer device.

    Both SSM roles deliver device-bound traffic through the SAP's
    ``request`` (ServerSSM.response and ClientSSM.request both land there).
    """
    ssmm = ssm.ssmSAP
    assert ssmm.request.await_count
    return ssmm.request.await_args.args[0]


# --------------------------------------------------------------------------
# ServerSSM: receiving the segments of a segmented request
# --------------------------------------------------------------------------


@bacpypes_debugging
class TestServerSegmentReception:
    async def test_duplicate_segment_is_positively_acked_not_appended(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        try:
            duplicate = request_segment(0, True, b"AA")
            await ssm.segmented_request(duplicate)

            ack = latest_device_pdu(ssm)
            assert isinstance(ack, SegmentAckPDU)
            assert not ack.apduNak
            # the positive ack repeats the last segment received in order
            assert ack.apduSeq == 0
            assert ack.apduSrv == 1

            # the payload is present once, not twice
            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            assert ssm.lastSequenceNumber == 0
        finally:
            ssm.stop_timer()

    async def test_gap_segment_is_nakd_with_last_in_order_sequence(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        try:
            # segment 2 arrives while segment 1 is still missing
            gap = request_segment(2, True, b"CC")
            await ssm.segmented_request(gap)

            ack = latest_device_pdu(ssm)
            assert isinstance(ack, SegmentAckPDU)
            assert ack.apduNak
            # the NAK names the last segment received in order (0), which is
            # where the sender must retransmit from - not the window base
            assert ack.apduSeq == 0

            # the out-of-order payload is never buffered
            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            assert ssm.lastSequenceNumber == 0
        finally:
            ssm.stop_timer()

    async def test_in_order_segment_resumes_after_nak(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        try:
            gap = request_segment(2, True, b"CC")
            await ssm.segmented_request(gap)
            sap.request.reset_mock()

            good = request_segment(1, True, b"BB")
            await ssm.segmented_request(good)

            assert bytes(ssm.segmentAPDU.pduData) == b"AABB"
            assert ssm.lastSequenceNumber == 1
            # segment 1 fills the window; the boundary ack is emitted when the
            # next segment of the group arrives, so only the timer is running
            assert ssm.initialSequenceNumber == 0
        finally:
            ssm.stop_timer()

    async def test_outside_window_segment_aborts_without_app_delivery(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        try:
            # the negotiated window only covers sequences 0..1; a jump to
            # sequence 9 cannot belong to this window
            wild = request_segment(9, True, b"ZZ")
            await ssm.segmented_request(wild)

            # the half-assembled data is untouched and never delivered
            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            assert ssm.state == ABORTED
            assert ssm not in sap.serverTransactions

            # an abort went both to the device (request) and the
            # application (sap_request)
            device_pdus = [c.args[0] for c in sap.request.await_args_list]
            assert any(isinstance(pdu, AbortPDU) for pdu in device_pdus)
            assert sap.sap_request.await_count == 1
            assert isinstance(sap.sap_request.await_args.args[0], AbortPDU)
        finally:
            ssm.stop_timer()

    async def test_abort_then_late_segment_is_ignored(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        try:
            # the client aborts mid-request
            abort = AbortPDU(False, INVOKE_ID, AbortReason.other)
            abort.pduSource = PEER_A
            await ssm.segmented_request(abort)
            assert ssm.state == COMPLETED
            assert ssm not in sap.serverTransactions
            assert ssm._timer_handle is None
            sap.request.reset_mock()
            sap.sap_request.reset_mock()

            # a segment already in flight when the abort landed
            late = request_segment(1, True, b"BB")
            # routed the way ApplicationServiceAccessPoint would route it
            await ssm.indication(late)

            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            # no new device traffic and no application delivery
            assert sap.request.await_count == 0
            assert sap.sap_request.await_count == 0
        finally:
            ssm.stop_timer()

    async def test_duplicate_final_segment_does_not_redeliver(self):
        sap = make_sap()
        ssm = make_receiving_server(sap)
        # replace the raw bytes with a payload that decodes as a real service
        request = ReadPropertyRequest(
            objectIdentifier=ObjectIdentifier("device,1"),
            propertyIdentifier=PropertyIdentifier("objectName"),
        )
        request.apduInvokeID = INVOKE_ID
        payload = bytes(request.encode().pduData)
        first_half, second_half = payload[:4], payload[4:]
        ssm.segmentAPDU = ConfirmedRequestPDU(SERVICE, INVOKE_ID)
        ssm.segmentAPDU.put_data(first_half)
        try:
            # finish the request properly with the final segment
            final = request_segment(1, False, second_half)
            await ssm.segmented_request(final)
            assert ssm.state == AWAIT_RESPONSE
            app_calls = sap.sap_request.await_count
            assert app_calls == 1

            # the application received the complete, correctly reassembled
            # request, decoded into the matching service sequence
            delivered = sap.sap_request.await_args.args[0]
            assert isinstance(delivered, ReadPropertyRequest)
            assert delivered.objectIdentifier == ObjectIdentifier("device,1")
            assert delivered.propertyIdentifier == PropertyIdentifier("objectName")

            # the sender retransmits the final segment after losing the ack
            retransmitted = request_segment(1, False, second_half)
            await ssm.indication(retransmitted)

            # the application still saw the request exactly once
            assert sap.sap_request.await_count == app_calls
            assert ssm.state == AWAIT_RESPONSE
        finally:
            ssm.stop_timer()


# --------------------------------------------------------------------------
# ClientSSM: receiving the segments of a segmented (complex-ack) response
# --------------------------------------------------------------------------


@bacpypes_debugging
class TestClientSegmentReception:
    async def test_duplicate_ack_segment_is_positively_acked(self):
        sap = make_sap()
        ssm = make_receiving_client(sap)
        try:
            duplicate = complex_ack_segment(0, True, b"AA")
            await ssm.segmented_confirmation(duplicate)

            ack = latest_device_pdu(ssm)
            assert isinstance(ack, SegmentAckPDU)
            assert not ack.apduNak
            assert ack.apduSrv == 0
            assert ack.apduSeq == 0
            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
        finally:
            ssm.stop_timer()

    async def test_gap_ack_segment_is_nakd_from_last_in_order(self):
        sap = make_sap()
        ssm = make_receiving_client(sap)
        try:
            gap = complex_ack_segment(2, True, b"CC")
            await ssm.segmented_confirmation(gap)

            ack = latest_device_pdu(ssm)
            assert ack.apduNak
            assert ack.apduSeq == 0
            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
        finally:
            ssm.stop_timer()

    async def test_outside_window_ack_segment_aborts_without_response(self):
        sap = make_sap()
        ssm = make_receiving_client(sap)
        try:
            wild = complex_ack_segment(9, True, b"ZZ")
            await ssm.segmented_confirmation(wild)

            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            assert ssm.state == ABORTED
            assert ssm not in sap.clientTransactions
            # only the abort reached the application, never the half-built ack
            delivered = sap.sap_response.await_args.args[0]
            assert isinstance(delivered, AbortPDU)
            assert sap.sap_response.await_count == 1
        finally:
            ssm.stop_timer()

    async def test_late_segment_after_abort_is_ignored(self):
        sap = make_sap()
        ssm = make_receiving_client(sap)
        try:
            ssm.set_state(ABORTED)
            assert ssm._timer_handle is None
            sap.request.reset_mock()
            sap.response.reset_mock()

            late = complex_ack_segment(1, True, b"BB")
            # must not raise "invalid state" and must not append data
            await ssm.confirmation(late)

            assert bytes(ssm.segmentAPDU.pduData) == b"AA"
            assert ssm.state == ABORTED
            assert ssm not in sap.clientTransactions
            assert sap.request.await_count == 0
            assert sap.response.await_count == 0
        finally:
            ssm.stop_timer()


# --------------------------------------------------------------------------
# Sending side: a stale duplicate window ack must not resize the window
# --------------------------------------------------------------------------


@bacpypes_debugging
class TestSenderWindowProtection:
    async def test_client_keeps_window_when_duplicate_ack_arrives(self):
        sap = make_sap()
        ssm = ClientSSM(sap, PEER_B)
        request = ConfirmedRequestPDU(SERVICE, INVOKE_ID)
        request.put_data(b"x" * 60)
        ssm.set_segmentation_context(request)
        ssm.invokeID = INVOKE_ID
        ssm.segmentSize = 10
        ssm.segmentCount = 6
        ssm.state = SEGMENTED_REQUEST
        ssm.sentAllSegments = False
        ssm.initialSequenceNumber = 2
        ssm.actualWindowSize = 2
        ssm.segmentRetryCount = 0
        try:
            # stale ack from a previous window, proposing a window of one
            stale = SegmentAckPDU(0, 1, INVOKE_ID, 0, 1)
            stale.pduSource = PEER_B
            await ssm.segmented_request(stale)

            assert ssm.actualWindowSize == 2
            assert ssm.initialSequenceNumber == 2
            # the stale ack only refreshed the timer, no segments were resent
            assert sap.request.await_count == 0
        finally:
            ssm.stop_timer()

    async def test_server_keeps_window_when_duplicate_ack_arrives(self):
        sap = make_sap()
        ssm = ServerSSM(sap, PEER_A)
        response = ComplexAckPDU(SERVICE, INVOKE_ID)
        response.put_data(b"y" * 60)
        ssm.set_segmentation_context(response)
        ssm.invokeID = INVOKE_ID
        ssm.segmentSize = 10
        ssm.segmentCount = 6
        ssm.state = SEGMENTED_RESPONSE
        ssm.sentAllSegments = False
        ssm.initialSequenceNumber = 2
        ssm.actualWindowSize = 2
        ssm.segmentRetryCount = 0
        try:
            stale = SegmentAckPDU(0, 0, INVOKE_ID, 0, 1)
            stale.pduSource = PEER_A
            await ssm.segmented_response(stale)

            assert ssm.actualWindowSize == 2
            assert ssm.initialSequenceNumber == 2
            assert sap.request.await_count == 0
        finally:
            ssm.stop_timer()

    async def test_in_window_ack_still_advances_client_window(self):
        sap = make_sap()
        ssm = ClientSSM(sap, PEER_B)
        request = ConfirmedRequestPDU(SERVICE, INVOKE_ID)
        request.put_data(b"x" * 60)
        ssm.set_segmentation_context(request)
        ssm.invokeID = INVOKE_ID
        ssm.segmentSize = 10
        ssm.segmentCount = 6
        ssm.state = SEGMENTED_REQUEST
        ssm.sentAllSegments = False
        # the current window starts at sequence 0; an ack for sequence 1
        # is therefore inside it and may legitimately resize the window
        ssm.initialSequenceNumber = 0
        ssm.actualWindowSize = 2
        ssm.segmentRetryCount = 0
        try:
            # legitimate ack for sequence 1, proposing a smaller window
            good = SegmentAckPDU(0, 1, INVOKE_ID, 1, 1)
            good.pduSource = PEER_B
            await ssm.segmented_request(good)

            assert ssm.actualWindowSize == 1
            assert ssm.initialSequenceNumber == 2
            # one segment re-sent to fill the now single-slot window
            assert sap.request.await_count == 1
        finally:
            ssm.stop_timer()
