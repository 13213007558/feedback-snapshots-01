"""Collection of transaction based abstractions."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from threading import RLock
from time import monotonic

from ..exceptions import ConnectionException, ModbusIOException
from ..framer import FramerAscii, FramerBase, FramerRTU
from ..logging import Log
from ..pdu import ModbusPDU
from ..transport import CommParams, CommType, ModbusProtocol


#: Max number of abandoned transaction ids remembered to avoid reuse.
#: Bounded on purpose: a late response older than this many abandoned
#: transactions (and a full tid wrap) can no longer be told apart from a
#: new transaction with the same 16-bit tid.
STALE_TID_LIMIT = 100


class TransactionManager(ModbusProtocol):  # pylint: disable=too-many-instance-attributes
    """Transaction manager.

    This is the central class of the library, providing a separation between API and communication:
    - clients/servers calls the manager to execute requests/responses
    - transport/framer/pdu is by the manager to communicate with the devices

    Transaction manager handles:
    - Execution of requests (client), with retries and locking
    - Sending of responses (server), with retries
    - Connection management (on top of what transport offers)
    - No response (temporarily) from a device

    Transaction manager offers:
    - a simple execute interface for requests (client)
    - a simple send interface for responses (server)
    - external trace methods tracing outgoing/incoming packets/PDUs (byte stream)
    """

    def __init__(
        self,
        params: CommParams,
        framer: FramerBase,
        retries: int,
        is_server: bool,
        trace_packet: Callable[[bool, bytes], bytes] | None,
        trace_pdu: Callable[[bool, ModbusPDU], ModbusPDU] | None,
        trace_connect: Callable[[bool], None] | None,
        sync_client=None,
    ) -> None:
        """Initialize an instance of the ModbusTransactionManager."""
        self.is_sync = bool(sync_client)
        super().__init__(params, is_server, is_sync=self.is_sync)
        self.max_buffer_size = framer.MAX_SIZE
        self.framer = framer
        self.retries = retries
        self.next_tid: int = 0
        self.stale_tids: deque[int] = deque(maxlen=STALE_TID_LIMIT)
        self.connection_epoch: int = 0
        self.request_epoch: int = 0
        self.request_dev_id: int = 0
        self.request_transaction_id: int = 0
        self.request_function_code: int = 0
        self.trace_packet = trace_packet or self.dummy_trace_packet
        self.trace_pdu = trace_pdu or self.dummy_trace_pdu
        self.trace_connect = trace_connect or self.dummy_trace_connect
        self.max_until_disconnect = self.count_until_disconnect = retries + 3
        if sync_client:
            self.sync_client = sync_client
            self._sync_lock = RLock()
            self.low_level_send = self.sync_client.send
        else:
            self._lock = asyncio.Lock()
            self.low_level_send = self.send
            self.response_future: asyncio.Future = asyncio.Future()
            self.cancelled_requests: dict[
                tuple[int, int], tuple[asyncio.Future, float]
            ] = {}
            self.last_pdu: ModbusPDU | None = None
            self.last_addr: tuple | None = None

    def dummy_trace_packet(self, sending: bool, data: bytes) -> bytes:
        """Do dummy trace."""
        _ = sending
        return data

    def dummy_trace_pdu(self, sending: bool, pdu: ModbusPDU) -> ModbusPDU:
        """Do dummy trace."""
        _ = sending
        return pdu

    def dummy_trace_connect(self, connect: bool) -> None:
        """Do dummy trace."""
        _ = connect

    def sync_get_response(self, dev_id, tid) -> ModbusPDU:
        """Receive until PDU is correct or timeout."""
        databuffer = b""
        deadline = monotonic() + self.comm_params.timeout_connect
        while True:
            if not (data := self.sync_client.recv(None)):
                raise asyncio.exceptions.TimeoutError()

            if self.sent_buffer:
                if data.startswith(self.sent_buffer):
                    Log.debug(
                        "sync recv skipping (local_echo): {}",
                        self.sent_buffer,
                        ":hex",
                    )
                    data = data[len(self.sent_buffer) :]
                    self.sent_buffer = b""
                elif self.sent_buffer.startswith(data):
                    Log.debug(
                        "sync recv skipping (partial local_echo): {}", data, ":hex"
                    )
                    self.sent_buffer = self.sent_buffer[len(data) :]
                    continue
                else:
                    Log.debug("did not sync receive local echo: {}", data, ":hex")
                    self.sent_buffer = b""
                if not data:
                    continue

            databuffer += data
            used_len, pdu = self.framer.handleFrame(
                self.trace_packet(False, databuffer), dev_id, tid
            )
            databuffer = databuffer[used_len:]
            if pdu:
                return self.trace_pdu(False, pdu)
            if monotonic() >= deadline:
                raise asyncio.exceptions.TimeoutError()

    @staticmethod
    def _io_exception_from_request(
        message: str, request: ModbusPDU
    ) -> ModbusIOException:
        """Build ModbusIOException from an outstanding request."""
        return ModbusIOException(
            message,
            function_code=request.function_code,
            transaction_id=request.transaction_id,
            dev_id=request.dev_id,
        )

    def _mark_stale_tid(self, tid: int) -> None:
        """Remember an abandoned transaction id, so it is not reused soon.

        A late response to an abandoned request must never complete a new
        transaction, so the tid is skipped until it leaves the bounded history.
        """
        if tid and tid not in self.stale_tids:
            self.stale_tids.append(tid)

    def _no_response(self, request: ModbusPDU) -> ModbusIOException:
        """Count a request that got no response, and build the exception to raise."""
        self._mark_stale_tid(request.transaction_id)
        if self.count_until_disconnect < 0:
            if self.comm_params.comm_type != CommType.SERIAL:
                self.connection_lost(asyncio.TimeoutError("Server not responding"))
            return self._io_exception_from_request(
                "ERROR: No response received of the last requests (default: retries+3), CLOSING CONNECTION.",
                request,
            )
        self.count_until_disconnect -= 1
        txt = f"No response received after {self.retries} retries, continue with next request"
        Log.error(txt)
        return self._io_exception_from_request(txt, request)

    def sync_execute(self, no_response_expected: bool, request: ModbusPDU) -> ModbusPDU:
        """Execute requests asynchronously.

        REMARK: this method is identical to execute, apart from the lock and sync_receive.
                any changes in either method MUST be mirrored !!!
        """
        if not self.sync_client.connect():
            raise ConnectionException(
                "Client cannot connect (automatic retry continuing) !!"
            )
        with self._sync_lock:
            request.transaction_id = self.getNextTID()
            count_retries = 0
            while count_retries <= self.retries:
                self.pdu_send(request)
                if no_response_expected:
                    return None  # type: ignore[return-value]
                try:
                    response = self.sync_get_response(
                        request.dev_id, request.transaction_id
                    )
                    self.count_until_disconnect = self.max_until_disconnect
                    if response.dev_id != request.dev_id:
                        raise self._io_exception_from_request(
                            f"ERROR: request uses device id={request.dev_id} but received {response.dev_id}.",
                            request,
                        )
                    if response.transaction_id != request.transaction_id:
                        raise self._io_exception_from_request(
                            f"ERROR: request uses transaction id={request.transaction_id} but received {response.transaction_id}.",
                            request,
                        )
                    if (response.function_code & 0x7F) != request.function_code:
                        Log.error(
                            f"ERROR: request ask for fc={request.function_code} but got fc={response.function_code}, Skipping."
                        )
                        continue
                    response.retries = count_retries
                    return response
                except asyncio.exceptions.TimeoutError:
                    count_retries += 1
            raise self._no_response(request)

    async def _connect_if_needed(self) -> None:
        """Connect if there is no transport."""
        if not self.transport:
            Log.warning("Not connected, trying to connect!")
            if not await self.connect():
                raise ConnectionException(
                    "Client cannot connect (automatic retry continuing) !!"
                )

    async def execute(
        self, no_response_expected: bool, request: ModbusPDU
    ) -> ModbusPDU:
        """Execute requests asynchronously.

        REMARK: this method is identical to sync_execute, apart from the lock, try/except
                and the wait after a cancel. any changes in either method MUST be mirrored !!!
        """
        await self._connect_if_needed()
        async with self._lock:
            cancel_key = (request.dev_id, request.function_code)
            if cancelled := self.cancelled_requests.pop(cancel_key, None):
                late_response, until = cancelled
                await asyncio.wait([late_response], timeout=until - monotonic())
            request.transaction_id = self.getNextTID()
            count_retries = 0
            while count_retries <= self.retries:
                self.recv_buffer = b""
                self.response_future = asyncio.Future()
                self.pdu_send(request)
                if no_response_expected:
                    return None  # type: ignore[return-value]
                try:
                    response: ModbusPDU = await asyncio.wait_for(
                        self.response_future, timeout=self.comm_params.timeout_connect
                    )
                    self.count_until_disconnect = self.max_until_disconnect
                    if (request.dev_id and response.dev_id != request.dev_id) or (
                        response.function_code & 0x7F
                    ) != request.function_code:
                        Log.error(
                            f"ERROR: request ask for id/fc={request.dev_id}/{request.function_code}  but got {response.dev_id}/{response.function_code}, Skipping."
                        )
                        continue
                    if (
                        response.transaction_id
                        and response.transaction_id != request.transaction_id
                    ):
                        raise self._io_exception_from_request(
                            f"ERROR: request uses transaction id={request.transaction_id} but received {response.transaction_id}.",
                            request,
                        )
                    response.retries = count_retries
                    return response
                except asyncio.exceptions.TimeoutError:
                    count_retries += 1
                except asyncio.exceptions.CancelledError:
                    # RTU/ASCII responses carry no transaction id, so the next
                    # request to this device with this function code first
                    # waits for the response to this one. A response from
                    # another device or with another function code is skipped,
                    # so other requests are not delayed.
                    self._mark_stale_tid(request.transaction_id)
                    if not request.transaction_id:
                        self.response_future = asyncio.Future()
                        self.cancelled_requests[cancel_key] = (
                            self.response_future,
                            monotonic() + self.comm_params.timeout_connect,
                        )
                    raise
            raise self._no_response(request)

    def pdu_send(self, pdu: ModbusPDU, addr: tuple | None = None) -> None:
        """Build byte stream and send."""
        if not self.is_server:
            self.request_dev_id = pdu.dev_id
            self.request_transaction_id = pdu.transaction_id
            self.request_function_code = pdu.function_code
            self.request_epoch = self.connection_epoch
        packet = self.framer.buildFrame(self.trace_pdu(True, pdu))
        if self.is_sync and self.comm_params.handle_local_echo:
            self.sent_buffer = packet
        self.low_level_send(self.trace_packet(True, packet), addr=addr)

    def callback_new_connection(self):
        """Call when listener receive new connection request."""

    def callback_connected(self) -> None:
        """Call when connection is successful."""
        self.count_until_disconnect = self.max_until_disconnect
        # New connection generation: transaction ids keep increasing (no
        # reset), so a late response from a previous connection cannot alias
        # a transaction id of this generation.
        self.connection_epoch += 1
        self.trace_connect(True)

    def callback_disconnected(self, exc: Exception | None) -> None:
        """Call when connection is lost."""
        self.trace_connect(False)

    def callback_data(self, data: bytes, addr: tuple | None = None) -> int:
        """Handle received data."""
        self.last_pdu = self.last_addr = None
        used_len, pdu = self.framer.handleFrame(
            self.trace_packet(False, data),
            self.request_dev_id,
            self.request_transaction_id,
        )
        if pdu:
            self.last_pdu = self.trace_pdu(False, pdu)
            self.last_addr = addr
            if not self.is_server:
                if self.request_epoch != self.connection_epoch:
                    Log.warning(
                        "ERROR: received pdu for a request sent on a previous connection, IGNORING"
                    )
                elif (
                    not self.response_future
                    or self.response_future.done()
                    or self.response_future.cancelled()
                ):
                    Log.warning(
                        "ERROR: received pdu without a corresponding request, IGNORING"
                    )
                elif (
                    self.request_function_code
                    and (pdu.function_code & 0x7F) != self.request_function_code
                ):
                    Log.error(
                        f"ERROR: request ask for fc={self.request_function_code} but got fc={pdu.function_code}, Skipping."
                    )
                else:
                    self.response_future.set_result(self.last_pdu)
        return used_len

    def getNextTID(self) -> int:
        """Retrieve the next transaction identifier.

        Ids increase monotonically (across reconnects) and wrap at 65000.
        Ids of recently abandoned transactions (stale_tids, bounded) are
        skipped, so a late response cannot complete a new transaction.
        """
        if isinstance(self.framer, (FramerAscii, FramerRTU)):
            self.next_tid = 0
            return 0
        tid = self.next_tid
        while (tid := 1 if tid >= 65000 else tid + 1) in self.stale_tids:
            pass
        self.next_tid = tid
        return tid
