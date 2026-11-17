"""Test explicit read-only request policy for servers."""

import asyncio
from unittest import mock

from pymodbus.constants import ExcCodes
from pymodbus.framer import FramerType
from pymodbus.pdu import ExceptionResponse, ModbusPDU
from pymodbus.server import ModbusBaseServer, ReadOnlyRequestPolicy
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.transport import CommParams, CommType


class RecordingContext:
    """In-memory device recording every datastore access."""

    def __init__(self, inner):
        """Wrap a real context."""
        self.inner = inner
        self.calls = []

    async def async_getValues(self, device_id, func_code, address, count):
        """Record and delegate a read."""
        self.calls.append(("get", device_id, func_code, address, count))
        return await self.inner.async_getValues(device_id, func_code, address, count)

    async def async_setValues(self, device_id, func_code, address, values):
        """Record and delegate a write."""
        self.calls.append(("set", device_id, func_code, address, values))
        return await self.inner.async_setValues(device_id, func_code, address, values)

    def device_ids(self):
        """Delegate device id listing."""
        return self.inner.device_ids()


class CustomTelemetryRequest(ModbusPDU):
    """Custom function code whose side effects cannot be confirmed."""

    function_code = 0x64

    @classmethod
    def x_calculateRtuFrameSize(cls, data):
        """Calculate the size of a PDU."""
        return 8

    def x_encode(self):
        """Encode the message."""
        return b"\x00\x00"

    def x_decode(self, data):
        """Decode data part of the message."""

    async def datastore_update(self, context, device_id):
        """Echo the request."""
        return CustomTelemetryRequest(
            dev_id=device_id, transaction_id=self.transaction_id
        )


READ_HOLDING = bytes.fromhex("000100000006010300000002")
READ_WRITE_COMBO = bytes.fromhex("00020000000D01170000000100000001020007")
MASK_WRITE = bytes.fromhex("0003000000080116000000FFFF00")
WRITE_FILE_RECORD = bytes.fromhex("00040000000C011509060001000000011234")
DIAG_RESTART = bytes.fromhex("000500000006010800010000")
DIAG_CLEAR_COUNTERS = bytes.fromhex("0006000000060108000A0000")
DIAG_RETURN_QUERY = bytes.fromhex("0007000000060108000000A5")
CUSTOM_FUNCTION = bytes.fromhex("00080000000401640000")
BROADCAST_WRITE_COIL = bytes.fromhex("00090000000600050000FF00")
BROADCAST_READ_HOLDING = bytes.fromhex("000A00000006000300000002")
WRITE_SINGLE_REGISTER = bytes.fromhex("000B00000006010600001234")
MEI_READ_DEVICE_INFO = bytes.fromhex("000C00000005012B0E0100")


def build_handler(*, policy=None, broadcast_enable=False, custom_pdu=None):
    """Build a request handler with a recording in-memory device."""
    server = ModbusBaseServer(
        CommParams(
            comm_type=CommType.TCP,
            comm_name="server_listener",
            reconnect_delay=0.0,
            reconnect_delay_max=0.0,
            timeout_connect=0.0,
            source_address=("0", 0),
        ),
        SimDevice(0, SimData(0, datatype=DataType.REGISTERS, values=[17] * 100)),
        False,
        broadcast_enable,
        None,
        FramerType.SOCKET,
        None,
        None,
        None,
        custom_pdu,
        request_policy=policy,
    )
    context = RecordingContext(server.context)
    server.context = context
    handler = server.callback_new_connection()
    handler.pdu_send = mock.Mock(return_value=True)  # type: ignore[method-assign]
    return handler, context


async def dispatch(handler, frame):
    """Drive a real frame through PDU dispatch."""
    assert handler.callback_data(frame, None) == len(frame)
    await asyncio.sleep(0.1)
    return handler.pdu_send.call_args.args[0] if handler.pdu_send.called else None


class TestReadOnlyPolicy:
    """Test read-only policy enforcement during PDU dispatch."""

    async def test_legit_read_allowed(self):
        """A plain read reaches the datastore and returns values."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, READ_HOLDING)
        assert not response.isError()
        assert response.function_code == 0x03
        assert ("get", 1, 3, 0, 2) in context.calls

    async def test_readonly_diagnostic_allowed(self):
        """Return query data is a side-effect-free diagnostic."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, DIAG_RETURN_QUERY)
        assert not response.isError()
        assert response.function_code == 0x08

    async def test_mei_read_device_info_allowed(self):
        """Read device information is a pure read."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, MEI_READ_DEVICE_INFO)
        assert not response.isError()
        assert response.function_code == 0x2B

    async def test_read_write_combo_denied(self):
        """Read/write multiple registers only pretends to be a read."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, READ_WRITE_COMBO)
        assert isinstance(response, ExceptionResponse)
        assert response.function_code == 0x80 | 0x17
        assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert context.calls == []

    async def test_mask_write_denied(self):
        """Mask write register is denied before the datastore."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, MASK_WRITE)
        assert isinstance(response, ExceptionResponse)
        assert response.function_code == 0x80 | 0x16
        assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert context.calls == []

    async def test_write_file_record_denied(self):
        """File record writes are denied before the datastore."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        response = await dispatch(handler, WRITE_FILE_RECORD)
        assert isinstance(response, ExceptionResponse)
        assert response.function_code == 0x80 | 0x15
        assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert context.calls == []

    async def test_state_changing_diagnostics_denied(self):
        """Diagnostics that change device state are denied."""
        handler, context = build_handler(policy=ReadOnlyRequestPolicy())
        for frame in (DIAG_RESTART, DIAG_CLEAR_COUNTERS):
            response = await dispatch(handler, frame)
            assert isinstance(response, ExceptionResponse)
            assert response.function_code == 0x88
            assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert context.calls == []

    async def test_unknown_custom_function_denied(self):
        """Custom extensions with unconfirmable side effects are denied."""
        handler, context = build_handler(
            policy=ReadOnlyRequestPolicy(), custom_pdu=[CustomTelemetryRequest]
        )
        response = await dispatch(handler, CUSTOM_FUNCTION)
        assert isinstance(response, ExceptionResponse)
        assert response.function_code == 0x80 | 0x64
        assert response.exception_code == ExcCodes.ILLEGAL_FUNCTION
        assert context.calls == []

    async def test_broadcast_write_denied(self):
        """Broadcast writes are denied before any device callback."""
        handler, context = build_handler(
            policy=ReadOnlyRequestPolicy(), broadcast_enable=True
        )
        response = await dispatch(handler, BROADCAST_WRITE_COIL)
        assert response is None
        assert context.calls == []

    async def test_broadcast_read_allowed(self):
        """Broadcast reads are executed on all devices without a response."""
        handler, context = build_handler(
            policy=ReadOnlyRequestPolicy(), broadcast_enable=True
        )
        response = await dispatch(handler, BROADCAST_READ_HOLDING)
        assert response is None
        assert context.calls == [("get", 0, 3, 0, 2)]

    async def test_policy_disabled_keeps_normal_behavior(self):
        """Without a policy, writes and combos work as before."""
        handler, context = build_handler()
        response = await dispatch(handler, WRITE_SINGLE_REGISTER)
        assert not response.isError()
        assert response.function_code == 0x06
        assert ("set", 1, 6, 0, [0x1234]) in context.calls

        handler, context = build_handler()
        response = await dispatch(handler, READ_WRITE_COMBO)
        assert not response.isError()
        assert response.function_code == 0x17
        assert ("set", 1, 23, 0, [0x0007]) in context.calls
        assert ("get", 1, 23, 0, 1) in context.calls
