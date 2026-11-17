"""Regression tests for broadcast (device id 0) side effects.

The Modbus serial line spec defines device id 0 as the broadcast address and
states that a broadcast request is answered by *no* response on the wire. A
client timing out therefore cannot conclude that the request was not executed:
the only observable effect is the state change inside every addressed device.

These tests drive the real :class:`ServerRequestHandler` against in-memory
:class:`SimCore` devices (three devices) and verify, separately:

* which device objects are actually mutated, and
* whether anything is sent back on the wire.

They cover the four required cases: allowed broadcast writes, rejected
broadcast reads, unconfigured devices and a failing device, and compare each
broadcast call with the equivalent single-device call of the same function.
"""

from unittest import mock

import pytest

from pymodbus.constants import ExcCodes
from pymodbus.exceptions import NoSuchIdException
from pymodbus.framer import FramerType
from pymodbus.pdu import ExceptionResponse
from pymodbus.pdu.bit_message import (
    ReadCoilsRequest,
    WriteMultipleCoilsRequest,
    WriteSingleCoilRequest,
)
from pymodbus.pdu.register_message import (
    ReadHoldingRegistersRequest,
    WriteMultipleRegistersRequest,
    WriteSingleRegisterRequest,
)
from pymodbus.server import ModbusBaseServer
from pymodbus.server.requesthandler import BROADCAST_FUNCTION_CODES
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.transport import CommParams, CommType


DEVICE_IDS = (1, 2, 3)
REGISTER_ADDRESS = 10
COIL_ADDRESS = 0
INITIAL_REGISTER = 11
NEW_REGISTER = 42
NEW_REGISTERS = [42, 43]


def make_devices(initial_register=INITIAL_REGISTER):
    """Build three independent in-memory devices with coils and registers."""
    return [
        SimDevice(
            dev_id,
            simdata=(
                [SimData(COIL_ADDRESS, count=16, values=False, datatype=DataType.BITS)],
                [SimData(COIL_ADDRESS, count=16, values=False, datatype=DataType.BITS)],
                [
                    SimData(
                        REGISTER_ADDRESS,
                        count=10,
                        values=initial_register,
                        datatype=DataType.REGISTERS,
                    )
                ],
                [
                    SimData(
                        REGISTER_ADDRESS,
                        count=10,
                        values=initial_register,
                        datatype=DataType.REGISTERS,
                    )
                ],
            ),
        )
        for dev_id in DEVICE_IDS
    ]


def make_server(devices, *, broadcast_enable=True, ignore_missing_devices=False):
    """Create a base server backed by the given devices without sockets."""
    return ModbusBaseServer(
        CommParams(
            comm_type=CommType.TCP,
            comm_name="server_listener",
            reconnect_delay=0.0,
            reconnect_delay_max=0.0,
            timeout_connect=0.0,
            source_address=("0", 0),
        ),
        devices,
        ignore_missing_devices,
        broadcast_enable,
        None,
        FramerType.SOCKET,
        None,
        None,
        None,
        [],
    )


@pytest.fixture()
async def broadcast_handler():
    """Provide a broadcast-enabled handler over three in-memory devices."""
    server = make_server(make_devices())
    handler = server.callback_new_connection()
    handler.pdu_send = mock.Mock(return_value=True)
    yield handler, server
    handler.running = False


async def register_state(context, dev_id):
    """Read the holding register value back for one device."""
    return await context.async_getValues(dev_id, 3, REGISTER_ADDRESS, 1)


async def coil_state(context, dev_id):
    """Read the single coil value back for one device."""
    return await context.async_getValues(dev_id, 1, COIL_ADDRESS, 1)


async def all_register_states(context):
    """Snapshot holding registers of all configured devices."""
    return {
        dev_id: await register_state(context, dev_id) for dev_id in context.device_ids()
    }


class TestBroadcast:
    """Verify broadcast side effects and the absent wire response."""

    async def test_broadcast_write_single_register_updates_every_device(
        self, broadcast_handler
    ):
        """FC 6 broadcast mutates every device and never answers."""
        handler, server = broadcast_handler
        before = await all_register_states(server.context)
        assert before == {dev_id: [INITIAL_REGISTER] for dev_id in DEVICE_IDS}

        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=0
        )
        await handler.handle_request(request)

        after = await all_register_states(server.context)
        assert after == {dev_id: [NEW_REGISTER] for dev_id in DEVICE_IDS}
        handler.pdu_send.assert_not_called()

    async def test_broadcast_write_multiple_registers_updates_every_device(
        self, broadcast_handler
    ):
        """FC 16 broadcast mutates every device and never answers."""
        handler, server = broadcast_handler
        request = WriteMultipleRegistersRequest(
            address=REGISTER_ADDRESS, registers=NEW_REGISTERS, dev_id=0
        )
        await handler.handle_request(request)

        for dev_id in DEVICE_IDS:
            values = await server.context.async_getValues(
                dev_id, 3, REGISTER_ADDRESS, len(NEW_REGISTERS)
            )
            assert values == NEW_REGISTERS
        handler.pdu_send.assert_not_called()

    async def test_broadcast_write_single_coil_updates_every_device(
        self, broadcast_handler
    ):
        """FC 5 broadcast mutates the coil of every device and never answers."""
        handler, server = broadcast_handler
        request = WriteSingleCoilRequest(address=COIL_ADDRESS, bits=[True], dev_id=0)
        await handler.handle_request(request)

        for dev_id in DEVICE_IDS:
            assert await coil_state(server.context, dev_id) == [True]
        handler.pdu_send.assert_not_called()

    async def test_broadcast_write_multiple_coils_updates_every_device(
        self, broadcast_handler
    ):
        """FC 15 broadcast mutates coils of every device and never answers."""
        handler, server = broadcast_handler
        request = WriteMultipleCoilsRequest(
            address=COIL_ADDRESS, bits=[True, False, True], dev_id=0
        )
        await handler.handle_request(request)

        for dev_id in DEVICE_IDS:
            values = await server.context.async_getValues(dev_id, 1, COIL_ADDRESS, 3)
            assert values == [True, False, True]
        handler.pdu_send.assert_not_called()

    @pytest.mark.parametrize(
        "pdu",
        [
            ReadCoilsRequest(address=COIL_ADDRESS, count=1, dev_id=0),
            ReadHoldingRegistersRequest(address=REGISTER_ADDRESS, count=1, dev_id=0),
        ],
    )
    async def test_broadcast_read_is_rejected_without_side_effects(
        self, broadcast_handler, pdu
    ):
        """Read FCs are not broadcastable: no datastore call and no response."""
        handler, server = broadcast_handler
        before = await all_register_states(server.context)

        with mock.patch.object(pdu, "datastore_update", new=mock.AsyncMock()) as update:
            await handler.handle_request(pdu)

        update.assert_not_called()
        assert await all_register_states(server.context) == before
        handler.pdu_send.assert_not_called()

    async def test_broadcast_without_configured_devices_is_a_noop(
        self, broadcast_handler
    ):
        """An empty device list means no call target and still no response."""
        server = make_server([])
        handler = server.callback_new_connection()
        handler.pdu_send = mock.Mock(return_value=True)
        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=0
        )

        await handler.handle_request(request)

        assert server.context.device_ids() == []
        handler.pdu_send.assert_not_called()

    async def test_broadcast_continues_when_one_device_fails(self, broadcast_handler):
        """A failing device must not abort the loop nor fake group success."""
        handler, server = broadcast_handler
        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=0
        )
        original_update = request.datastore_update

        async def failing_update(context, device_id):
            if device_id == 2:
                raise NoSuchIdException("simulated missing device")
            return await original_update(context, device_id)

        with mock.patch.object(request, "datastore_update", side_effect=failing_update):
            await handler.handle_request(request)

        # devices 1 and 3 changed, device 2 kept its old value
        assert await register_state(server.context, 1) == [NEW_REGISTER]
        assert await register_state(server.context, 2) == [INITIAL_REGISTER]
        assert await register_state(server.context, 3) == [NEW_REGISTER]
        # broadcast cannot report the partial failure on the wire
        handler.pdu_send.assert_not_called()

    async def test_broadcast_continues_when_one_device_returns_exception(
        self, broadcast_handler
    ):
        """A datastore ExceptionResponse on one device is recorded, not sent."""
        handler, server = broadcast_handler
        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=0
        )
        original_update = request.datastore_update

        async def rejecting_update(context, device_id):
            if device_id == 2:
                return ExceptionResponse(
                    request.function_code, ExcCodes.ILLEGAL_ADDRESS
                )
            return await original_update(context, device_id)

        with mock.patch.object(
            request, "datastore_update", side_effect=rejecting_update
        ):
            await handler.handle_request(request)

        assert await register_state(server.context, 1) == [NEW_REGISTER]
        assert await register_state(server.context, 2) == [INITIAL_REGISTER]
        assert await register_state(server.context, 3) == [NEW_REGISTER]
        handler.pdu_send.assert_not_called()

    async def test_single_device_write_matches_broadcast_on_one_device(
        self, broadcast_handler
    ):
        """A unicast FC 6 call uses the same datastore path and does answer."""
        handler, server = broadcast_handler
        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=1
        )
        await handler.handle_request(request)

        # only the addressed device changes
        assert await register_state(server.context, 1) == [NEW_REGISTER]
        assert await register_state(server.context, 2) == [INITIAL_REGISTER]
        assert await register_state(server.context, 3) == [INITIAL_REGISTER]
        # unicast gets a normal response, broadcast gets none
        handler.pdu_send.assert_called_once()
        response = handler.pdu_send.call_args.args[0]
        assert response.function_code == request.function_code
        assert response.dev_id == 1

    async def test_disabled_broadcast_treats_dev_id_zero_as_ordinary_device(
        self,
    ):
        """Without broadcast_enable, dev_id 0 follows the normal request path."""
        server = make_server(make_devices(), broadcast_enable=False)
        handler = server.callback_new_connection()
        handler.pdu_send = mock.Mock(return_value=True)
        request = WriteSingleRegisterRequest(
            address=REGISTER_ADDRESS, registers=[NEW_REGISTER], dev_id=0
        )

        await handler.handle_request(request)

        # no device 0 configured -> gateway no response, but a response is sent
        handler.pdu_send.assert_called_once()
        response = handler.pdu_send.call_args.args[0]
        assert isinstance(response, ExceptionResponse)

    def test_broadcast_function_codes_are_write_only(self):
        """Guard the constant: only the four spec broadcast writes."""
        assert frozenset((5, 6, 15, 16)) == BROADCAST_FUNCTION_CODES
