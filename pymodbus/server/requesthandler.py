"""Implementation of a Threaded Modbus Server."""

from __future__ import annotations

import asyncio
import traceback
from functools import partial

from ..constants import ExcCodes
from ..exceptions import ModbusIOException, NoSuchIdException
from ..logging import Log
from ..pdu import ExceptionResponse, ModbusPDU
from ..transaction import TransactionManager
from ..transport import CommParams


#: Modbus function codes allowed on the broadcast address (dev_id 0).
#: Per the Modbus over serial line spec only write requests may be broadcast;
#: read requests cannot be answered on a multi-drop line.
BROADCAST_FUNCTION_CODES = frozenset((5, 6, 15, 16))


class ServerRequestHandler(TransactionManager):
    """Handle client connection."""

    def __init__(self, owner, trace_packet, trace_pdu, trace_connect):
        """Initialize."""
        params = CommParams(
            comm_name="server",
            comm_type=owner.comm_params.comm_type,
            reconnect_delay=0.0,
            reconnect_delay_max=0.0,
            timeout_connect=0.0,
            host=owner.comm_params.source_address[0],
            port=owner.comm_params.source_address[1],
            handle_local_echo=owner.comm_params.handle_local_echo,
        )
        self.server = owner
        self.running = False
        framer = owner.framer(owner.decoder)
        super().__init__(
            params,
            framer,
            0,
            True,
            trace_packet,
            trace_pdu,
            trace_connect,
        )

    def callback_disconnected(self, exc: Exception | None) -> None:
        """Call when connection is lost."""
        super().callback_disconnected(exc)
        if exc is None:
            Log.debug(
                "Handler for stream [{}] has been canceled", self.comm_params.comm_name
            )
        else:
            Log.debug(
                "Client Disconnection {} due to {}",
                self.comm_params.comm_name,
                exc,
            )
        self.running = False

    def callback_data(self, data: bytes, addr: tuple | None = None) -> int:
        """Handle received data."""
        used_len = 0
        tot_len = len(data)
        while True:
            if used_len >= tot_len:
                break
            try:
                new_len = super().callback_data(data[used_len:], addr)
            except ModbusIOException as exc:
                function_code = 0x00 if exc.fcode is None else exc.fcode
                response = ExceptionResponse(
                    function_code,
                    exception_code=ExcCodes.ILLEGAL_FUNCTION,
                    device_id=exc.dev_id,
                    transaction=exc.transaction_id,
                )
                new_len = exc.used_len
                self.server_send(response, addr)
            used_len += new_len
            if self.last_pdu:
                self.loop.call_soon(partial(self.handle_later, self.last_pdu))
            if not new_len:
                break
        return used_len

    def handle_later(self, pdu: ModbusPDU) -> None:
        """Change sync (async not allowed in call_soon) to async."""
        asyncio.run_coroutine_threadsafe(self.handle_request(pdu), self.loop)

    async def handle_request(self, pdu: ModbusPDU) -> None:
        """Handle request."""
        try:
            if self.server.broadcast_enable and not pdu.dev_id:
                await self.handle_broadcast(pdu)
                return
            response = await pdu.datastore_update(self.server.context, pdu.dev_id)

        except NoSuchIdException:
            if self.server.ignore_missing_devices:
                Log.debug("ignoring request for unknown device id: {}", pdu.dev_id)
                return  # the client will simply timeout waiting for a response
            Log.error("requested device id does not exist: {}", pdu.dev_id)
            response = ExceptionResponse(
                pdu.function_code, ExcCodes.GATEWAY_NO_RESPONSE
            )
        except Exception as exc:  # pylint: disable=broad-except
            Log.error(
                "Datastore unable to fulfill request: {}; {}",
                exc,
                traceback.format_exc(),
            )
            response = ExceptionResponse(pdu.function_code, ExcCodes.DEVICE_FAILURE)
        response.transaction_id = pdu.transaction_id
        response.dev_id = pdu.dev_id
        self.server_send(response, self.last_addr)

    async def handle_broadcast(self, pdu: ModbusPDU) -> None:
        """Apply a broadcast write (dev_id 0) to every configured device.

        The protocol defines no response for broadcast requests, so nothing
        is sent back on the wire regardless of the outcome. Only write
        function codes may be broadcast; reads are rejected without touching
        the datastores. A failure on one device neither aborts the remaining
        devices nor hides the failure: it is logged and the loop continues.
        """
        if pdu.function_code not in BROADCAST_FUNCTION_CODES:
            Log.warning(
                "Broadcast request with function code {} rejected: "
                "only write function codes {} are allowed",
                pdu.function_code,
                sorted(BROADCAST_FUNCTION_CODES),
            )
            return
        failed_devices: list[int] = []
        for dev_id in self.server.context.device_ids():
            try:
                result = await pdu.datastore_update(self.server.context, dev_id)
            except Exception as exc:  # pylint: disable=broad-except
                Log.error(
                    "Broadcast update failed on device {}: {}; {}",
                    dev_id,
                    exc,
                    traceback.format_exc(),
                )
                failed_devices.append(dev_id)
                continue
            if isinstance(result, ExceptionResponse):
                Log.error(
                    "Broadcast update rejected on device {} with exception {}",
                    dev_id,
                    result.exception_code,
                )
                failed_devices.append(dev_id)
        if failed_devices:
            Log.error(
                "Broadcast function code {} not applied to devices {}; "
                "no response is sent for broadcast requests",
                pdu.function_code,
                failed_devices,
            )

    def server_send(self, pdu, addr):
        """Send message."""
        if not pdu:
            Log.debug("Skipping sending response!!")
        else:
            self.pdu_send(pdu, addr=addr)
