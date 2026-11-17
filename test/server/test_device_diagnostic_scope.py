"""Per-device scoping of the control block and diagnostic handling.

These tests drive several in-memory SimDevice instances through the real
ServerRequestHandler. No socket or serial port is opened: the connection
object is created directly and pdu_send is captured, so a device is
considered to have processed a request only when a response is emitted.
"""

from unittest import mock

import pytest

from pymodbus.framer import FramerType
from pymodbus.pdu.bit_message import WriteSingleCoilRequest
from pymodbus.pdu.device import ModbusControlBlock
from pymodbus.pdu.diag_message import (
    ClearCountersRequest,
    ForceListenOnlyModeRequest,
    RestartCommunicationsOptionRequest,
    ReturnBusMessageCountRequest,
    ReturnDeviceMessageCountRequest,
    ReturnDiagnosticRegisterRequest,
)
from pymodbus.pdu.register_message import ReadHoldingRegistersRequest
from pymodbus.server import ModbusBaseServer
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.transport import CommParams, CommType


DEVICES = [
    SimDevice(1, SimData(0, count=10, datatype=DataType.REGISTERS, values=11)),
    SimDevice(2, SimData(0, count=10, datatype=DataType.REGISTERS, values=22)),
]


@pytest.fixture()
async def handler():
    """Provide a request handler backed by two in-memory devices."""
    ModbusControlBlock().reset_all()
    server = ModbusBaseServer(
        CommParams(
            comm_type=CommType.TCP,
            comm_name="scope_server",
            reconnect_delay=0.0,
            reconnect_delay_max=0.0,
            timeout_connect=0.0,
            source_address=("0", 0),
        ),
        DEVICES,
        False,
        False,
        None,
        FramerType.SOCKET,
        None,
        None,
        None,
        [],
    )
    conn = server.callback_new_connection()
    conn.pdu_send = mock.Mock(return_value=True)
    yield conn
    ModbusControlBlock().reset_all()


def bus_count(device_id):
    """Return the bus message counter kept for one device."""
    return ModbusControlBlock().get_device(device_id).counters.BusMessage


def device_count(device_id):
    """Return the device message counter kept for one device."""
    return ModbusControlBlock().get_device(device_id).counters.DeviceMessage


async def send(handler, pdu):
    """Deliver one PDU and return the captured response, if any."""
    before = handler.pdu_send.call_count
    await handler.handle_request(pdu)
    if handler.pdu_send.call_count == before:
        return None
    return handler.pdu_send.call_args.args[0]


def read_request(device_id):
    """Build a normal read request addressed to one device."""
    return ReadHoldingRegistersRequest(address=0, count=2, dev_id=device_id)


async def read_wire_count(handler, request_cls, device_id):
    """Read a diagnostic counter from one device through a diagnostic PDU."""
    response = await send(handler, request_cls(dev_id=device_id))
    return response.message


class TestDeviceDiagnosticScope:
    """Verify diagnostic state never leaks between device contexts."""

    async def test_control_blocks_are_distinct_per_device(self):
        """Each device id resolves to its own diagnostic control block."""
        control = ModbusControlBlock()
        control.reset_all()
        first = control.get_device(1)
        second = control.get_device(2)
        assert first is not second
        assert first.counters is not second.counters
        assert first is control.get_device(1)

    async def test_listen_only_does_not_leak_to_other_device(self, handler):
        """Forcing device 1 listen-only leaves device 2 fully responsive."""
        # shortest interleave: force listen-only on 1, then probe both.
        await send(handler, ForceListenOnlyModeRequest(dev_id=1))

        assert ModbusControlBlock().get_device(1).listen_only is True
        assert ModbusControlBlock().get_device(2).listen_only is False

        silenced = await send(handler, read_request(1))
        answered = await send(handler, read_request(2))

        assert silenced is None, "listen-only device must not answer"
        assert answered is not None
        assert answered.registers == [22, 22]

    async def test_normal_requests_keep_counting_per_device(self, handler):
        """Counters only move for the device actually processing requests."""
        await send(handler, read_request(1))
        await send(handler, read_request(1))
        await send(handler, read_request(2))

        assert bus_count(1) == 2
        assert device_count(1) == 2
        assert bus_count(2) == 1
        assert device_count(2) == 1

        # the same counters are what the diagnostic PDUs return
        wire = await read_wire_count(handler, ReturnBusMessageCountRequest, 1)
        assert wire == bus_count(1)
        wire = await read_wire_count(handler, ReturnDeviceMessageCountRequest, 2)
        assert wire == device_count(2)

    async def test_listen_only_request_is_not_counted(self, handler):
        """A request dropped because of listen-only must not increment counters."""
        await send(handler, ForceListenOnlyModeRequest(dev_id=1))
        counted_after_force = bus_count(1)
        assert counted_after_force == 1  # the diagnostic request itself counted
        await send(handler, read_request(1))
        await send(handler, read_request(1))

        assert bus_count(1) == counted_after_force
        # device 2 is untouched and keeps a zero counter as well
        assert bus_count(2) == 0

    async def test_clear_counters_is_scoped_to_one_device(self, handler):
        """Clearing device 1 counters must not reset device 2 counters."""
        for _ in range(3):
            await send(handler, read_request(1))
        for _ in range(2):
            await send(handler, read_request(2))

        await send(handler, ClearCountersRequest(dev_id=1))

        assert bus_count(1) == 0
        assert bus_count(2) == 2
        assert ModbusControlBlock().get_device(2).getDiagnosticRegister() == (
            [False] * 16
        )

    async def test_restart_communication_clears_only_addressed_device(self, handler):
        """Restart communication exits listen mode and resets one device."""
        await send(handler, ForceListenOnlyModeRequest(dev_id=1))
        await send(handler, read_request(2))

        await send(
            handler,
            RestartCommunicationsOptionRequest(message=0xFF00, dev_id=1),
        )

        assert ModbusControlBlock().get_device(1).listen_only is False
        assert ModbusControlBlock().get_device(2).listen_only is False

        recovered = await send(handler, read_request(1))
        assert recovered is not None
        assert recovered.registers == [11, 11]
        # device 2 kept its counters, device 1 counters were restarted
        assert bus_count(1) == 1
        assert bus_count(2) == 1

    async def test_diagnostic_register_is_per_device(self, handler):
        """The 16-bit diagnostic register is independent for each device."""
        control = ModbusControlBlock()
        control.get_device(1).setDiagnostic({3: True})

        one = await send(handler, ReturnDiagnosticRegisterRequest(dev_id=1))
        two = await send(handler, ReturnDiagnosticRegisterRequest(dev_id=2))

        assert one.message != two.message
        assert control.get_device(2).getDiagnostic(3) is False

    async def test_broadcast_listen_only_silences_every_device(self, handler):
        """Broadcast explicitly forces every configured device listen-only."""
        handler.server.broadcast_enable = True
        broadcast = ForceListenOnlyModeRequest(dev_id=0)

        await handler.handle_request(broadcast)

        control = ModbusControlBlock()
        assert control.get_device(1).listen_only is True
        assert control.get_device(2).listen_only is True
        # broadcast never produces a response
        assert handler.pdu_send.call_count == 0
        # and afterwards neither device processes normal requests
        assert await send(handler, read_request(1)) is None
        assert await send(handler, read_request(2)) is None

    async def test_broadcast_clear_counters_hits_all_devices(self, handler):
        """Broadcast clear counters is the explicit all-device behaviour."""
        await send(handler, read_request(1))
        await send(handler, read_request(2))
        handler.server.broadcast_enable = True

        await handler.handle_request(ClearCountersRequest(dev_id=0))

        assert handler.pdu_send.call_count == 2  # only the earlier reads answered
        assert bus_count(1) == 0
        assert bus_count(2) == 0

    async def test_unicast_diagnostic_does_not_touch_other_device(self, handler):
        """The full unicast interleave leaves the second device untouched."""
        # 1. normal traffic on both devices
        await send(handler, read_request(1))
        await send(handler, read_request(2))
        # 2. device 1 enters listen-only, then its counters are cleared
        await send(handler, ForceListenOnlyModeRequest(dev_id=1))
        await send(handler, ClearCountersRequest(dev_id=1))
        # 3. device 1 drops normal traffic, device 2 keeps serving
        assert await send(handler, read_request(1)) is None
        answered = await send(handler, read_request(2))
        assert answered.registers == [22, 22]
        # 4. device 1 is restarted, device 2 history survives
        await send(
            handler,
            RestartCommunicationsOptionRequest(message=0xFF00, dev_id=1),
        )
        assert await send(handler, read_request(1)) is not None
        assert bus_count(1) == 1
        assert bus_count(2) == 2

    async def test_writes_are_dropped_while_in_listen_only(self, handler):
        """Listen-only must also swallow write requests, not just reads."""
        await send(handler, ForceListenOnlyModeRequest(dev_id=1))
        result = await send(
            handler, WriteSingleCoilRequest(address=0, bits=[True], dev_id=1)
        )
        assert result is None
        # device 2 writes still go through
        other = await send(
            handler, WriteSingleCoilRequest(address=0, bits=[True], dev_id=2)
        )
        assert other is not None
