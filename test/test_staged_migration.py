# Copyright 2026-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test a staged replica set migration with interleaved updates and requests.

A staged migration brings new nodes into a replica set before they are
approved to serve application traffic. For the driver, "the node appears in
the topology" and "the node is approved to serve" are distinct states:

- Retirement rule: an approved node's in-flight operations finish on their
  checked-out connections after the node is decommissioned, but no new
  operations are routed to it and its pool is closed.
- Admission rule: a node that is not yet approved (server type Unknown)
  must never receive application operations.

This test drives a Topology directly with fake hello responses, deliberately
interleaving topology updates, member "approvals" (a member's own hello
confirming its role), and operation execution. Every issued command,
connection checkin, failover, and rejection is recorded in an audit trail
and cross-checked against SDAM events so the whole migration is traceable.
"""

from __future__ import annotations

import contextlib
import itertools
import sys
import weakref

sys.path[0:0] = [""]

from pymongo import common
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from pymongo.hello import Hello, HelloCompat
from pymongo.lock import _create_lock
from pymongo.monitoring import (
    ServerClosedEvent,
    ServerDescriptionChangedEvent,
    TopologyDescriptionChangedEvent,
    _EventListeners,
)
from pymongo.operations import _Op
from pymongo.pool_options import PoolOptions
from pymongo.pool_shared import _CancellationContext, _PoolGeneration
from pymongo.server_description import ServerDescription
from pymongo.server_selectors import secondary_server_selector, writable_server_selector
from pymongo.server_type import SERVER_TYPE
from pymongo.synchronous.settings import TopologySettings
from pymongo.synchronous.topology import Topology
from pymongo.topology_description import TOPOLOGY_TYPE
from pymongo.topology_shared import process_events_queue
from test import client_knobs, unittest
from test.pymongo_mocks import DummyMonitor
from test.utils_shared import ServerAndTopologyEventListener

A = ("a", 27017)
B = ("b", 27017)
C = ("c", 27017)


def primary_hello(hosts):
    return {
        "ok": 1,
        HelloCompat.LEGACY_CMD: True,
        "setName": "rs",
        "hosts": hosts,
        "maxWireVersion": common.MIN_SUPPORTED_WIRE_VERSION,
    }


def secondary_hello(hosts):
    return {
        "ok": 1,
        HelloCompat.LEGACY_CMD: False,
        "secondary": True,
        "setName": "rs",
        "hosts": hosts,
        "maxWireVersion": common.MIN_SUPPORTED_WIRE_VERSION,
    }


class RecordingConnection:
    """A fake pooled connection that records the commands issued on it."""

    _ids = itertools.count(1)

    def __init__(self, pool):
        self.pool = pool
        self.id = next(RecordingConnection._ids)
        self.cancel_context = _CancellationContext()
        self.more_to_come = False
        self.is_sdam = False
        self.server_connection_id = self.id
        self.commands: list[str] = []
        self.closed_reason = None

    def close_conn(self, reason):
        self.closed_reason = reason

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class RecordingPool:
    """A Pool stand-in that records checkouts, checkins, and lifecycle events.

    A connection checked out before the pool was reset or closed is retired
    (recorded in ``discarded``) on checkin instead of being recycled for
    reuse, mirroring the real Pool's stale-generation behavior.
    """

    def __init__(self, address, options, is_sdam=False, client_id=None):
        self.address = address
        self.gen = _PoolGeneration()
        self._lock = _create_lock()
        self.opts = options
        self.operation_count = 0
        self.conns = []
        self.closed = False
        self.reset_count = 0
        self.checkouts: list[RecordingConnection] = []
        self.recycled: list[RecordingConnection] = []
        self.discarded: list[RecordingConnection] = []

    def stale_generation(self, gen, service_id):
        return self.gen.stale(gen, service_id)

    @contextlib.contextmanager
    def checkout(self, handler=None):
        if self.closed:
            raise ConnectionFailure(f"pool for {self.address} is closed")
        conn = RecordingConnection(self)
        self.checkouts.append(conn)
        reset_count = self.reset_count
        try:
            yield conn
        finally:
            if self.closed or self.reset_count != reset_count:
                self.discarded.append(conn)
            else:
                self.recycled.append(conn)

    def checkin(self, *args, **kwargs):
        pass

    def _reset(self, service_id=None):
        with self._lock:
            self.reset_count += 1
            self.gen.inc(service_id)

    def ready(self):
        pass

    def reset(self, service_id=None, interrupt_connections=False):
        self._reset()

    def reset_without_pause(self):
        self._reset()

    def close(self):
        self.closed = True
        self._reset()

    def update_is_writable(self, is_writable):
        pass

    def remove_stale_sockets(self, *args, **kwargs):
        pass


class TestStagedMigration(unittest.TestCase):
    """Disables periodic monitoring, to make tests deterministic."""

    def setUp(self):
        super().setUp()
        self.client_knobs = client_knobs(heartbeat_frequency=999999)
        self.client_knobs.enable()
        self.addCleanup(self.client_knobs.disable)
        self.listener = ServerAndTopologyEventListener()
        topology_settings = TopologySettings(
            [A],
            replica_set_name="rs",
            pool_class=RecordingPool,  # type: ignore[arg-type]
            pool_options=PoolOptions(event_listeners=_EventListeners([self.listener])),
            monitor_class=DummyMonitor,
        )
        self.topology = Topology(topology_settings)
        self.topology.open()
        self.addCleanup(self.topology.close)
        self.audit: list[tuple] = []

    def apply_hello(self, address, response):
        """Apply a fake topology update: a hello response from address."""
        if response.get(HelloCompat.LEGACY_CMD):
            role = "primary"
        elif response.get("secondary"):
            role = "secondary"
        else:
            role = "unknown"
        self.audit.append(("hello", address, role))
        self.topology.on_change(ServerDescription(address, Hello(response), 0))
        self.drain_events()

    def apply_unknown(self, address):
        """Apply a fake topology update: address stopped responding."""
        self.audit.append(("hello", address, "unknown"))
        self.topology.on_change(ServerDescription(address))
        self.drain_events()

    def drain_events(self):
        # Deliver queued SDAM events to the listener synchronously.
        process_events_queue(weakref.ref(self.topology._events))

    def run_operation(self, selector, command_name):
        """Select a server and issue one command on a checked-out connection."""
        server = self.topology.select_server(selector, _Op.TEST, server_selection_timeout=0)
        address = server.description.address
        with server.pool.checkout() as conn:
            conn.commands.append(command_name)
            self.audit.append(("command", command_name, address, conn.id))
        self.audit.append(("checkin", address, conn.id))
        return server, conn

    def assert_selection_rejected(self, selector, command_name):
        with self.assertRaises(ServerSelectionTimeoutError) as ctx:
            self.topology.select_server(selector, _Op.TEST, server_selection_timeout=0)
        self.audit.append(("rejected", command_name, str(ctx.exception)))

    def test_interleaved_staged_migration(self):
        t = self.topology

        # Phase 0: nothing is approved yet; a write is rejected.
        self.assert_selection_rejected(writable_server_selector, "insert")

        # Phase 1: A is approved as primary; B is known but unapproved.
        self.apply_hello(A, primary_hello(["a", "b"]))
        self.assertEqual(TOPOLOGY_TYPE.ReplicaSetWithPrimary, t.description.topology_type)

        # Phase 2: a fake topology update makes new node C appear in the
        # host list. C is in the topology but not approved to serve.
        self.apply_hello(A, primary_hello(["a", "b", "c"]))
        server_c = t.get_server_by_address(C)
        self.assertIsNotNone(server_c)
        assert server_c is not None
        self.assertEqual(SERVER_TYPE.Unknown, server_c.description.server_type)

        # Phase 3: B is approved as a secondary.
        self.apply_hello(B, secondary_hello(["a", "b", "c"]))

        # Phase 4: exactly one read and one write are issued.
        read_server, read_conn = self.run_operation(secondary_server_selector, "find")
        self.assertEqual(B, read_server.description.address)
        write_server, write_conn = self.run_operation(writable_server_selector, "insert")
        self.assertEqual(A, write_server.description.address)

        server_a = t.get_server_by_address(A)
        server_b = t.get_server_by_address(B)
        assert server_a is not None and server_b is not None
        pool_a: RecordingPool = server_a.pool
        pool_b: RecordingPool = server_b.pool
        pool_c: RecordingPool = server_c.pool

        # The unapproved node received no application traffic, and both
        # connections were recycled for reuse (not leaked, not discarded).
        self.assertEqual([], pool_c.checkouts)
        self.assertEqual([read_conn], pool_b.recycled)
        self.assertEqual([write_conn], pool_a.recycled)

        # Phase 5: A drops out before its retirement is announced. Writes
        # are rejected until B is approved as the new primary (failover).
        self.apply_unknown(A)
        self.assertEqual(TOPOLOGY_TYPE.ReplicaSetNoPrimary, t.description.topology_type)
        self.assert_selection_rejected(writable_server_selector, "insert")
        self.apply_hello(B, primary_hello(["a", "b", "c"]))
        self.assertEqual(B, t.get_primary())

        # Phase 6: A is decommissioned. An approved caller still holds a
        # connection checked out before the retirement...
        checkout = server_a.pool.checkout()
        in_flight = checkout.__enter__()
        # ...when B's hello removes A from the host list.
        self.apply_hello(B, primary_hello(["b", "c"]))
        self.assertIsNone(t.get_server_by_address(A))
        self.assertTrue(pool_a.closed)
        # New checkouts from the retired pool fail...
        with self.assertRaises(ConnectionFailure):
            with pool_a.checkout():
                pass
        # ...but the in-flight connection checks in cleanly and is retired
        # (discarded), not recycled for new operations.
        checkout.__exit__(None, None, None)
        self.audit.append(("checkin", A, in_flight.id))
        self.assertEqual([in_flight], pool_a.discarded)
        self.assertEqual([write_conn], pool_a.recycled)

        # Phase 7: C is still not approved, so a read finds no secondary...
        self.assert_selection_rejected(secondary_server_selector, "find")
        self.assertEqual([], pool_c.checkouts)
        # ...until C's own hello approves it; now it is selectable. Note
        # that selection alone issues no command on C.
        self.apply_hello(C, secondary_hello(["b", "c"]))
        selected = t.select_servers(secondary_server_selector, _Op.TEST, server_selection_timeout=0)
        self.assertEqual([C], [s.description.address for s in selected])
        self.assertEqual([], pool_c.checkouts)

        # --- Traceability: the audit trail and SDAM events tell the story.

        # Exactly one read and one write were issued, to B and A.
        commands = [entry for entry in self.audit if entry[0] == "command"]
        self.assertEqual(
            [("command", "find", B, read_conn.id), ("command", "insert", A, write_conn.id)],
            commands,
        )
        # The commands were really issued on the pooled connections.
        self.assertEqual(["find"], read_conn.commands)
        self.assertEqual(["insert"], write_conn.commands)

        # Every checked-out connection was checked back in exactly once.
        checked_out = [c.id for c in pool_a.checkouts + pool_b.checkouts + pool_c.checkouts]
        checked_in = [entry[2] for entry in self.audit if entry[0] == "checkin"]
        self.assertEqual(sorted(checked_out), sorted(checked_in))

        # All three rejections are recorded with their reasons.
        rejections = [entry for entry in self.audit if entry[0] == "rejected"]
        self.assertEqual(3, len(rejections))

        # The failover is traceable through SDAM events: A's demotion and
        # B's promotion were both published.
        server_changes = [
            e for e in self.listener.results if isinstance(e, ServerDescriptionChangedEvent)
        ]
        self.assertTrue(
            any(
                e.server_address == A
                and e.previous_description.server_type == SERVER_TYPE.RSPrimary
                and e.new_description.server_type == SERVER_TYPE.Unknown
                for e in server_changes
            )
        )
        self.assertTrue(
            any(
                e.server_address == B
                and e.previous_description.server_type == SERVER_TYPE.RSSecondary
                and e.new_description.server_type == SERVER_TYPE.RSPrimary
                for e in server_changes
            )
        )
        topo_transitions = [
            (e.previous_description.topology_type, e.new_description.topology_type)
            for e in self.listener.results
            if isinstance(e, TopologyDescriptionChangedEvent)
        ]
        self.assertIn(
            (TOPOLOGY_TYPE.ReplicaSetWithPrimary, TOPOLOGY_TYPE.ReplicaSetNoPrimary),
            topo_transitions,
        )
        self.assertIn(
            (TOPOLOGY_TYPE.ReplicaSetNoPrimary, TOPOLOGY_TYPE.ReplicaSetWithPrimary),
            topo_transitions,
        )
        # A's retirement was published as a server closed event.
        closed = [
            e.server_address for e in self.listener.results if isinstance(e, ServerClosedEvent)
        ]
        self.assertIn(A, closed)


if __name__ == "__main__":
    unittest.main()
