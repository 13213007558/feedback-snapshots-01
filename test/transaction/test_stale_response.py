"""Regression: a late response must not complete a newly issued request.

Modbus/TCP long-lived connections reuse 16-bit transaction ids (they wrap at
65000, and used to restart at 1 on every reconnect). These tests interleave
late ("old") responses with fresh ones through a pausable transport double
and assert which PDU the caller actually gets.

Guarantees verified here (sync and async transaction paths):

- responses are matched on transaction id, device id and function code;
- transaction ids increase monotonically across reconnects (connection
  generation), they are not reset to 1;
- data arriving for a request sent on a previous connection generation is
  ignored (async path);
- tids of abandoned (timed out / cancelled) requests are kept in a bounded
  history (STALE_TID_LIMIT) and skipped when allocating, so reuse after a
  wrap cannot alias a recent abandoned transaction;
- exception responses (fc | 0x80) with matching ids are delivered normally;
- legal serial (RTU) traffic keeps working.

Known integration limits (documented, not silently "fixed"):

- RTU/ASCII frames carry no transaction id. A late response with the same
  device id AND function code as the current request is indistinguishable
  and still accepted; only cancelled requests are drained explicitly
  (cancelled_requests). On genuine serial lines frames are ordered, so this
  is a theoretical concern mainly for RTU-over-TCP/UDP.
- the stale-tid history is bounded (100 entries, FIFO). A response delayed
  beyond 100 abandoned transactions plus a full 65000 tid wrap can still
  alias; closing that would require unbounded history, which is rejected
  by design.
- UDP has no ordering: guarantees rely on tid matching only.
"""

import asyncio
from unittest import mock

import pytest

from pymodbus.client import ModbusBaseSyncClient
from pymodbus.exceptions import ModbusIOException
from pymodbus.framer import FramerRTU, FramerSocket, FramerType
from pymodbus.pdu import DecodePDU, ExceptionResponse
from pymodbus.pdu.register_message import (
    ReadHoldingRegistersRequest,
    ReadHoldingRegistersResponse,
    ReadInputRegistersRequest,
    ReadInputRegistersResponse,
)
from pymodbus.transaction import TransactionManager
from pymodbus.transaction.transaction import STALE_TID_LIMIT


async def _wait_writes(transport, count):
    """Wait until the pausable transport recorded count writes."""
    for _ in range(200):
        if transport.write.call_count >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected {count} writes, got {transport.write.call_count}")


@pytest.mark.parametrize("use_port", [5198])
class TestAsyncStaleResponse:
    """Async transaction path: old responses must not change new results."""

    def _manager(self, use_clc, framer=None):
        """Create a client transaction manager with a pausable transport."""
        transact = TransactionManager(
            use_clc,
            framer or FramerSocket(DecodePDU(False)),
            0,
            False,
            None,
            None,
            None,
        )
        transact.retries = 0
        transact.comm_params.timeout_connect = 0.2
        transact.comm_params.reconnect_delay = 0
        return transact

    async def test_reconnect_does_not_reuse_tid(self, use_clc):
        """Late response from before a reconnect must not complete a new request."""
        transact = self._manager(use_clc)
        transport = mock.Mock()
        transact.connection_made(transport)
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        with pytest.raises(ModbusIOException):
            await transact.execute(False, req_a)
        tid_a = req_a.transaction_id

        transact.connection_lost(None)
        new_transport = mock.Mock()
        transact.connection_made(new_transport)

        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, req_b))
        await _wait_writes(new_transport, 1)
        tid_b = req_b.transaction_id
        assert tid_b != tid_a, "tid reused across reconnect"

        late = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=tid_a, registers=[9, 9, 9, 9]
        )
        transact.data_received(transact.framer.buildFrame(late))
        await asyncio.sleep(0.1)
        assert not task.done(), "late response completed the new request"

        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=tid_b, registers=[1, 2, 3, 4]
        )
        transact.data_received(transact.framer.buildFrame(good))
        assert (await task).registers == [1, 2, 3, 4]

    async def test_response_from_previous_connection_ignored(self, use_clc):
        """A response for a request sent before a reconnect is dropped."""
        transact = self._manager(use_clc)
        transport = mock.Mock()
        transact.connection_made(transport)
        request = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, request))
        await _wait_writes(transport, 1)

        transact.connection_lost(None)
        new_transport = mock.Mock()
        transact.connection_made(new_transport)

        late = ReadHoldingRegistersResponse(
            dev_id=1,
            transaction_id=request.transaction_id,
            registers=[9, 9, 9, 9],
        )
        transact.data_received(transact.framer.buildFrame(late))
        await asyncio.sleep(0.1)
        assert not task.done(), "response from old connection completed request"
        with pytest.raises(ModbusIOException):
            await task

    async def test_tid_wrap_skips_stale_tid(self, use_clc):
        """After a tid wrap, an abandoned tid is not reused immediately."""
        transact = self._manager(use_clc)
        transport = mock.Mock()
        transact.connection_made(transport)
        transact.next_tid = 64999
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        with pytest.raises(ModbusIOException):
            await transact.execute(False, req_a)
        assert req_a.transaction_id == 65000
        assert 65000 in transact.stale_tids
        assert transact.stale_tids.maxlen == STALE_TID_LIMIT

        transact.next_tid = 64999  # emulate a full request cycle since
        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, req_b))
        await _wait_writes(transport, 2)
        assert req_b.transaction_id == 1, "stale tid 65000 not skipped"

        late = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=65000, registers=[9, 9, 9, 9]
        )
        transact.data_received(transact.framer.buildFrame(late))
        await asyncio.sleep(0.1)
        assert not task.done(), "wrapped late response completed new request"

        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=1, registers=[1, 2, 3, 4]
        )
        transact.data_received(transact.framer.buildFrame(good))
        assert (await task).registers == [1, 2, 3, 4]

    async def test_late_response_after_timeout_ignored(self, use_clc):
        """A late response to a timed-out request never reaches the next caller."""
        transact = self._manager(use_clc)
        transport = mock.Mock()
        transact.connection_made(transport)
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        with pytest.raises(ModbusIOException):
            await transact.execute(False, req_a)

        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, req_b))
        await _wait_writes(transport, 2)
        late = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=req_a.transaction_id, registers=[9, 9, 9, 9]
        )
        transact.data_received(transact.framer.buildFrame(late))
        await asyncio.sleep(0.1)
        assert not task.done()
        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=req_b.transaction_id, registers=[1, 2, 3, 4]
        )
        transact.data_received(transact.framer.buildFrame(good))
        assert (await task).registers == [1, 2, 3, 4]

    async def test_exception_response_matching_and_stale(self, use_clc):
        """Exception responses flow to their caller; stale ones are dropped."""
        transact = self._manager(use_clc)
        transport = mock.Mock()
        transact.connection_made(transport)
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, req_a))
        await _wait_writes(transport, 1)
        exc = ExceptionResponse(
            function_code=req_a.function_code,
            exception_code=2,
            device_id=1,
            transaction=req_a.transaction_id,
        )
        transact.data_received(transact.framer.buildFrame(exc))
        result = await task
        assert result.isError()
        assert result.exception_code == 2

        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, req_b))
        await _wait_writes(transport, 2)
        stale_exc = ExceptionResponse(
            function_code=req_b.function_code,
            exception_code=4,
            device_id=1,
            transaction=req_a.transaction_id,
        )
        transact.data_received(transact.framer.buildFrame(stale_exc))
        await asyncio.sleep(0.1)
        assert not task.done(), "stale exception response completed new request"
        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=req_b.transaction_id, registers=[1, 2, 3, 4]
        )
        transact.data_received(transact.framer.buildFrame(good))
        assert (await task).registers == [1, 2, 3, 4]

    async def test_serial_rtu_roundtrip_ok(self, use_clc):
        """Legal RTU serial traffic keeps working (tid is always 0)."""
        transact = self._manager(use_clc, framer=FramerRTU(DecodePDU(False)))
        transport = mock.Mock()
        transact.connection_made(transport)
        request = ReadHoldingRegistersRequest(dev_id=1, count=4)
        task = asyncio.create_task(transact.execute(False, request))
        await _wait_writes(transport, 1)
        assert request.transaction_id == 0
        response = ReadHoldingRegistersResponse(dev_id=1, registers=[1, 2, 3, 4])
        transact.data_received(transact.framer.buildFrame(response))
        assert (await task).registers == [1, 2, 3, 4]


@pytest.mark.parametrize("use_port", [5198])
class TestSyncStaleResponse:
    """Sync transaction path: old responses must not change new results."""

    class DummySyncClient(ModbusBaseSyncClient):
        """Pausable sync client double: recv is scripted by the test."""

        def send(self, request: bytes, addr: tuple | None = None) -> int:
            """Send request."""
            return 0

        def recv(self, size: int | None) -> bytes:
            """Receive request."""
            return b""

    def _manager(self, use_clc, framer):
        """Create a sync transaction manager with a scripted client."""
        client = self.DummySyncClient(FramerType.SOCKET, 0, use_clc, None, None, None)
        transact = TransactionManager(
            use_clc,
            framer,
            0,
            False,
            None,
            None,
            None,
            sync_client=client,
        )
        transact.retries = 0
        transact.comm_params.timeout_connect = 0.2
        transact.sync_client.connect = mock.Mock(return_value=True)
        transact.sync_client.send = mock.Mock()
        return transact

    def test_sync_late_response_wrong_fc_skipped(self, use_clc):
        """RTU: a late response with another function code is not returned."""
        transact = self._manager(use_clc, FramerRTU(DecodePDU(False)))
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        transact.sync_client.recv = mock.Mock(return_value=b"")
        with pytest.raises(ModbusIOException):
            transact.sync_execute(False, req_a)

        late = ReadHoldingRegistersResponse(dev_id=1, registers=[9, 9, 9, 9])
        good = ReadInputRegistersResponse(dev_id=1, registers=[1, 2, 3, 4, 5])
        transact.sync_client.recv = mock.Mock(
            side_effect=[
                transact.framer.buildFrame(late),
                transact.framer.buildFrame(good),
            ]
        )
        req_b = ReadInputRegistersRequest(dev_id=1, count=5)
        transact.low_level_send = mock.Mock()  # type: ignore[method-assign]
        result = transact.sync_execute(False, req_b)
        assert isinstance(result, ReadInputRegistersResponse)
        assert result.registers == [1, 2, 3, 4, 5]
        assert transact.low_level_send.call_count == 2

    def test_sync_socket_stale_tid_skipped(self, use_clc):
        """Socket framer: a late response with an old tid is filtered out."""
        transact = self._manager(use_clc, FramerSocket(DecodePDU(False)))
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        transact.sync_client.recv = mock.Mock(return_value=b"")
        with pytest.raises(ModbusIOException):
            transact.sync_execute(False, req_a)
        tid_a = req_a.transaction_id

        late = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=tid_a, registers=[9, 9, 9, 9]
        )
        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=tid_a + 1, registers=[1, 2, 3, 4]
        )
        transact.sync_client.recv = mock.Mock(
            side_effect=[
                transact.framer.buildFrame(late),
                transact.framer.buildFrame(good),
            ]
        )
        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        result = transact.sync_execute(False, req_b)
        assert req_b.transaction_id == tid_a + 1
        assert result.registers == [1, 2, 3, 4]

    def test_sync_tid_wrap_skips_stale_tid(self, use_clc):
        """Sync path: after a wrap the abandoned tid is skipped."""
        transact = self._manager(use_clc, FramerSocket(DecodePDU(False)))
        transact.next_tid = 64999
        req_a = ReadHoldingRegistersRequest(dev_id=1, count=4)
        transact.sync_client.recv = mock.Mock(return_value=b"")
        with pytest.raises(ModbusIOException):
            transact.sync_execute(False, req_a)
        assert req_a.transaction_id == 65000

        transact.next_tid = 64999  # emulate a full request cycle since
        late = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=65000, registers=[9, 9, 9, 9]
        )
        good = ReadHoldingRegistersResponse(
            dev_id=1, transaction_id=1, registers=[1, 2, 3, 4]
        )
        transact.sync_client.recv = mock.Mock(
            side_effect=[
                transact.framer.buildFrame(late),
                transact.framer.buildFrame(good),
            ]
        )
        req_b = ReadHoldingRegistersRequest(dev_id=1, count=4)
        result = transact.sync_execute(False, req_b)
        assert req_b.transaction_id == 1, "stale tid 65000 not skipped"
        assert result.registers == [1, 2, 3, 4]

    def test_sync_exception_response_delivered(self, use_clc):
        """Exception responses with matching ids reach the caller."""
        transact = self._manager(use_clc, FramerRTU(DecodePDU(False)))
        request = ReadHoldingRegistersRequest(dev_id=1, count=4)
        exc = ExceptionResponse(
            function_code=request.function_code, exception_code=2, device_id=1
        )
        transact.sync_client.recv = mock.Mock(
            return_value=transact.framer.buildFrame(exc)
        )
        result = transact.sync_execute(False, request)
        assert result.isError()
        assert result.exception_code == 2

    def test_sync_serial_roundtrip_ok(self, use_clc):
        """Legal RTU serial traffic keeps working."""
        transact = self._manager(use_clc, FramerRTU(DecodePDU(False)))
        request = ReadHoldingRegistersRequest(dev_id=1, count=4)
        response = ReadHoldingRegistersResponse(dev_id=1, registers=[1, 2, 3, 4])
        transact.sync_client.recv = mock.Mock(
            return_value=transact.framer.buildFrame(response)
        )
        result = transact.sync_execute(False, request)
        assert result.registers == [1, 2, 3, 4]
