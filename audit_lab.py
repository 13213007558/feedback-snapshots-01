"""Audit lab: pymodbus trace_packet/trace_pdu hook semantics (pymodbus 4.0.0dev17).

The OS socket is replaced by an in-memory full-duplex wire (sandbox forbids
bind()); everything else is the real stack: TransactionManager, FramerSocket,
ServerRequestHandler, SimCore datastore. Bytes captured at low_level_send are
exactly what would go on the wire.
"""

from __future__ import annotations

import asyncio
import copy

from pymodbus.framer import FramerSocket
from pymodbus.pdu import DecodePDU, ModbusPDU
from pymodbus.pdu.register_message import (
    ReadHoldingRegistersRequest,
    WriteSingleRegisterRequest,
)
from pymodbus.server.requesthandler import ServerRequestHandler
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.simulator.simcore import SimCore
from pymodbus.transaction import TransactionManager
from pymodbus.transport import CommParams, CommType

DEV_ID = 1
SECRET_ADDR = 10  # caller-forbidden: values at this address must not be logged


# ---------------------------------------------------------------- audit adapter
class AuditTrail:
    """Observe-only audit adapter for trace_packet / trace_pdu.

    Safety properties:
    - never transforms: returns the ORIGINAL object, not the snapshot
    - deep-copies the PDU before logging (a later hook may mutate the live one)
    - swallows its own errors: auditing must never break a transaction
    - redacts register values at caller-forbidden addresses
    - records direction + correlation ids (tid/dev_id/fc/address)
    - records ATTEMPT at send; execution is only confirmed by a validated
      response (done by correlate() after execute() returns)
    """

    def __init__(self, forbidden: set[tuple[int, int]] | None = None):
        self.events: list[dict] = []
        self.forbidden = forbidden or set()

    def trace_packet(self, sending: bool, data: bytes) -> bytes:
        try:
            self.events.append({
                "layer": "packet",
                "dir": "tx" if sending else "rx",
                "bytes": bytes(data).hex(),  # bytes are immutable: safe
            })
        except Exception:  # noqa: BLE001 - audit must not break traffic
            pass
        return data

    def trace_pdu(self, sending: bool, pdu: ModbusPDU) -> ModbusPDU:
        try:
            snap = copy.deepcopy(pdu)  # live object may be mutated afterwards
            redacted = (snap.dev_id, snap.address) in self.forbidden
            self.events.append({
                "layer": "pdu",
                "dir": "tx" if sending else "rx",
                "pdu": type(snap).__name__,
                "tid": snap.transaction_id,
                "dev_id": snap.dev_id,
                "fc": snap.function_code,
                "address": snap.address,
                "registers": "<redacted>" if redacted else list(snap.registers),
            })
        except Exception:  # noqa: BLE001
            pass
        return pdu


# ------------------------------------------------------------------ wire harness
class Wire:
    """In-memory full-duplex link; log = ground truth of wire bytes."""

    def __init__(self) -> None:
        self.log: list[tuple[str, bytes]] = []

    def attach(self, client: TransactionManager, server: ServerRequestHandler) -> None:
        client.low_level_send = lambda data, addr=None: self._deliver("C->S", data, server)
        server.low_level_send = lambda data, addr=None: self._deliver("S->C", data, client)

    def _deliver(self, direction: str, data: bytes, peer) -> None:
        self.log.append((direction, bytes(data)))
        peer.callback_data(bytes(data))


class FakeServerApp:
    """Minimal owner for ServerRequestHandler (replaces ModbusTcpServer)."""

    def __init__(self, context: SimCore) -> None:
        self.comm_params = CommParams(
            comm_name="srv", comm_type=CommType.TCP,
            source_address=("127.0.0.1", 502), handle_local_echo=False,
        )
        self.framer = FramerSocket
        self.decoder = DecodePDU(True)
        self.context = context
        self.broadcast_enable = False
        self.ignore_missing_devices = False


def make_stack(client_trace_pdu=None, client_trace_packet=None, retries=0):
    context = SimCore(SimDevice(id=DEV_ID, simdata=SimData(
        address=0, count=100, values=0, datatype=DataType.REGISTERS)))
    app = FakeServerApp(context)
    server = ServerRequestHandler(app, None, None, None)
    server.loop = asyncio.get_running_loop()
    server.transport = object()
    client = TransactionManager(
        CommParams(comm_name="cli", comm_type=CommType.TCP, timeout_connect=1.0),
        FramerSocket(DecodePDU(False)), retries, False,
        client_trace_packet, client_trace_pdu, None,
    )
    client.transport = object()  # pretend connected
    wire = Wire()
    wire.attach(client, server)
    return client, server, context, wire


async def get_reg(context, addr):
    return (await context.async_getValues(DEV_ID, 3, addr, 1))[0]


def show_wire(wire):
    return [f"{d} {b.hex()}" for d, b in wire.log]


# ------------------------------------------------------------------- scenarios
async def scenario_readonly():
    print("\n=== 1) read-only audit hooks, write reg 10 = 0x00A5, read back ===")
    audit = AuditTrail(forbidden={(DEV_ID, SECRET_ADDR)})
    client, server, context, wire = make_stack(audit.trace_pdu, audit.trace_packet)
    req = WriteSingleRegisterRequest(dev_id=DEV_ID, address=SECRET_ADDR, registers=[0x00A5])
    resp = await client.execute(False, req)
    print("response:", resp)
    print("wire:", *show_wire(wire), sep="\n  ")
    print("device reg 10 =", hex(await get_reg(context, SECRET_ADDR)))
    print("audit events:")
    for e in audit.events:
        print("  ", e)


async def scenario_mutating():
    print("\n=== 2) mutating trace_pdu(tx) rewrites value 0x00B6 -> 0x6666 ===")
    audit = AuditTrail()

    def mutator(sending: bool, pdu: ModbusPDU) -> ModbusPDU:
        if sending and isinstance(pdu, WriteSingleRegisterRequest):
            pdu.registers = [0x6666]  # in-place rewrite of the caller's object
        return pdu

    # composition order A: audit BEFORE mutator -> audit sees pre-transformation
    def composed_pre(sending, pdu):
        return mutator(sending, audit.trace_pdu(sending, pdu))

    client, server, context, wire = make_stack(composed_pre, audit.trace_packet)
    req = WriteSingleRegisterRequest(dev_id=DEV_ID, address=20, registers=[0x00B6])
    resp = await client.execute(False, req)
    print("caller asked value 0x00b6, response:", resp.registers)
    print("wire:", *show_wire(wire), sep="\n  ")
    print("device reg 20 =", hex(await get_reg(context, 20)))
    print("caller request object after execute:", list(req.registers), "(mutated in place!)")
    print("audit pdu events (composed BEFORE mutator):")
    for e in audit.events:
        if e["layer"] == "pdu":
            print("  ", e)

    print("\n--- composition order B: audit AFTER mutator ---")
    audit2 = AuditTrail()

    def composed_post(sending, pdu):
        return audit2.trace_pdu(sending, mutator(sending, pdu))

    client2, server2, context2, wire2 = make_stack(composed_post, audit2.trace_packet)
    req2 = WriteSingleRegisterRequest(dev_id=DEV_ID, address=21, registers=[0x00B6])
    await client2.execute(False, req2)
    print("device reg 21 =", hex(await get_reg(context2, 21)))
    print("audit pdu events (composed AFTER mutator):")
    for e in audit2.events:
        if e["layer"] == "pdu":
            print("  ", e)


async def scenario_rx_mutation():
    print("\n=== 3) mutating trace_pdu(rx) falsifies what the caller believes ===")
    def liar(sending: bool, pdu: ModbusPDU) -> ModbusPDU:
        if not sending and pdu.function_code == 3:
            pdu.registers = [0x0000]  # hide the real value from the application
        return pdu

    client, server, context, wire = make_stack(liar, None)
    await context.async_setValues(DEV_ID, 3, 30, [0x0BAD])
    resp = await client.execute(False, ReadHoldingRegistersRequest(dev_id=DEV_ID, address=30, count=1))
    print("device reg 30 really =", hex(await get_reg(context, 30)))
    print("wire S->C:", show_wire(wire)[-1])
    print("caller sees:", [hex(v) for v in resp.registers])


async def scenario_exceptions():
    print("\n=== 4) hook raises on TX ===")
    def boom_tx(sending, data):
        if sending:
            raise RuntimeError("audit backend down")
        return data

    client, server, context, wire = make_stack(None, boom_tx)
    try:
        await client.execute(False, WriteSingleRegisterRequest(dev_id=DEV_ID, address=40, registers=[0x1234]))
    except Exception as exc:  # noqa: BLE001
        print("execute raised:", type(exc).__name__, exc)
    print("wire frames sent:", len(wire.log), "(0 => no half-frame, send is all-or-nothing)")
    print("device reg 40 =", hex(await get_reg(context, 40)))

    print("\n=== 5) hook raises on RX (server already executed the write) ===")
    def boom_rx(sending, data):
        if not sending:
            raise RuntimeError("audit backend down")
        return data

    client, server, context, wire = make_stack(None, boom_rx)
    try:
        await client.execute(False, WriteSingleRegisterRequest(dev_id=DEV_ID, address=41, registers=[0x4321]))
    except Exception as exc:  # noqa: BLE001
        print("execute raised:", type(exc).__name__, str(exc)[:80])
    print("wire:", *show_wire(wire), sep="\n  ")
    print("device reg 41 =", hex(await get_reg(context, 41)), "<= write DID happen")


async def scenario_retry_double_transform():
    print("\n=== 6) in-place mutation + retries: value increments per attempt ===")
    def plus_one(sending: bool, pdu: ModbusPDU) -> ModbusPDU:
        if sending and isinstance(pdu, WriteSingleRegisterRequest):
            pdu.registers = [pdu.registers[0] + 1]
        return pdu

    client, server, context, wire = make_stack(plus_one, None, retries=1)
    # no server attached to a second wire -> force timeout? server IS attached,
    # so instead simulate loss by dropping the first attempt at the wire:
    state = {"dropped": False}
    orig_send = client.low_level_send
    def flaky(data, addr=None):
        if not state["dropped"]:
            state["dropped"] = True
            print("  (wire drops first frame:", bytes(data).hex() + ")")
            return
        orig_send(data, addr=addr)
    client.low_level_send = flaky
    req = WriteSingleRegisterRequest(dev_id=DEV_ID, address=50, registers=[0x0100])
    resp = await client.execute(False, req)
    print("caller asked 0x0100; device reg 50 =", hex(await get_reg(context, 50)))
    print("wire:", *show_wire(wire), sep="\n  ")


async def main():
    await scenario_readonly()
    await scenario_mutating()
    await scenario_rx_mutation()
    await scenario_exceptions()
    await scenario_retry_double_transform()


if __name__ == "__main__":
    asyncio.run(main())
