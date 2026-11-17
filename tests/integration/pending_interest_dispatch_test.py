# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
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
# -----------------------------------------------------------------------------
"""Regression tests for pending-Interest result dispatch.

Two backend requests may wait on data sharing a name prefix at the same time.
Each waiter must finish according to its own conditions (CanBePrefix,
MustBeFresh, implicit digest) and its own validator verdict. One waiter's
validation failure, cancellation or Nack must never change what another waiter
receives, and a still-pending waiter must keep its PIT name node alive so that
a later, acceptable packet can reach it.
"""
import asyncio as aio
from dataclasses import dataclass, field

from ndn import app as ndn_app
from ndn import encoding as enc
from ndn import types
from ndn.encoding import ndn_format_0_3 as fmt
from ndn.encoding import ndnlp_v2 as ndnlp
from ndn.transport.face import Face
from ndn import security as sec


class PausableMemoryFace(Face):
    """In-memory Face whose inbound delivery is fully controlled by the test.

    Outgoing Interests are captured (never auto-answered). Inbound packets are
    delivered one at a time through :meth:`deliver`, letting the test decide the
    exact arrival order and interleave validation, cancellation and late data.
    """

    def __init__(self):
        super().__init__()
        self.sent_interests: list[bytes] = []

    async def open(self):
        self.running = True

    def shutdown(self):
        self.running = False

    def send(self, data: bytes):
        self.sent_interests.append(bytes(data))

    async def run(self):
        while self.running:
            await aio.sleep(0.005)

    async def isLocalFace(self):
        return True

    async def deliver(self, packet):
        packet = memoryview(packet)
        typ, _ = enc.parse_tl_num(packet)
        await self.callback(typ, packet)

    async def deliver_nack(self, encoded_interest, reason):
        await self.deliver(ndnlp.make_network_nack(encoded_interest, reason))


@dataclass
class CallRecord:
    """Everything a single waiter observed at the end of its request."""
    tag: str
    status: str = 'pending'          # ok | validation_failure | timeout | canceled | nack
    name: enc.FormalName | None = None
    content: bytes | None = None
    result: types.ValidResult | None = None
    nack_reason: int | None = None
    validator_calls: list[bytes] = field(default_factory=list)


class RecordingValidator:
    """Validator that records every packet it is asked to judge.

    ``policy`` maps a Data name string to a verdict or an exception instance.
    Each waiter owns its own recorder, so shared names never share a verdict.
    """

    def __init__(self, record, policy, gate=None):
        self.record = record
        self.policy = policy
        self.gate = gate          # optional aio.Event to pause/resume validation

    async def __call__(self, name, sig, context):
        key = enc.Name.to_str(name)
        self.record.validator_calls.append(key)
        if self.gate is not None:
            await self.gate.wait()
        verdict = self.policy.get(key, types.ValidResult.FAIL)
        if isinstance(verdict, Exception):
            raise verdict
        return verdict


class DispatchTestSuite:
    """Harness: drive an NDNApp over a PausableMemoryFace inside one event loop."""

    app = None
    face = None
    records: dict[str, CallRecord] = None

    async def start(self):
        self.face = PausableMemoryFace()
        self.app = ndn_app.NDNApp(self.face)
        self._main = aio.ensure_future(self.app.main_loop())
        await aio.sleep(0)
        self.records = {}
        self._tasks = {}

    async def stop(self):
        self.app.shutdown()
        try:
            await self._main
        except (aio.CancelledError, types.InterestCanceled):
            pass

    def express(self, tag, name, policy, *, can_be_prefix=False, must_be_fresh=False,
                lifetime=4000, gate=None):
        record = CallRecord(tag=tag)
        self.records[tag] = record
        validator = RecordingValidator(record, policy, gate=gate)
        task = aio.ensure_future(self.app.express(
            name, validator, can_be_prefix=can_be_prefix,
            must_be_fresh=must_be_fresh, lifetime=lifetime))
        self._tasks[tag] = task
        return task

    @staticmethod
    def make_data(name, content, *, freshness_period=None):
        meta = fmt.MetaInfo(freshness_period=freshness_period)
        return fmt.make_data(name, meta, content, signer=sec.NullSigner())

    async def settle(self, tag):
        """Await one waiter and translate its outcome into its CallRecord."""
        task = self._tasks[tag]
        record = self.records[tag]
        try:
            data_name, content, _ = await aio.wait_for(task, timeout=1.0)
            record.status = 'ok'
            record.name = data_name
            record.content = bytes(content)
        except types.ValidationFailure as exc:
            record.status = 'validation_failure'
            record.name = exc.name
            record.content = bytes(exc.content) if exc.content is not None else None
            record.result = exc.result
        except types.InterestTimeout:
            record.status = 'timeout'
        except types.InterestCanceled:
            record.status = 'canceled'
        except types.InterestNack as exc:
            record.status = 'nack'
            record.nack_reason = exc.reason

    def pit_has(self, name):
        return enc.Name.normalize(name) in self.app._pit

    def pending_count(self, name):
        node = self.app._pit.get(enc.Name.normalize(name))
        return len(node.pending_list) if node is not None else 0


class _ScenarioRunner:
    def run(self, scenario):
        aio.run(scenario())


class TestIndependentValidation:
    """Same prefix, different validators: verdicts must never be shared."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        try:
            # All three waiters match the same prefix Data, but each judges it with
            # its own validator. gated is paused inside validation so it is still in
            # flight when the other two settle, forcing the node to be retained.
            gate = aio.Event()
            suite.express('strict', '/sec',
                          {'/sec/obj': types.ValidResult.FAIL}, can_be_prefix=True)
            suite.express('loose', '/sec',
                          {'/sec/obj': types.ValidResult.PASS}, can_be_prefix=True)
            suite.express('gated', '/sec',
                          {'/sec/obj': types.ValidResult.PASS}, can_be_prefix=True,
                          gate=gate)
            await aio.sleep(0.02)
            assert suite.pending_count('/sec') == 3

            await suite.face.deliver(suite.make_data('/sec/obj', b'shared',
                                                      freshness_period=1000))
            await aio.sleep(0.05)
            await suite.settle('strict')
            await suite.settle('loose')

            strict, loose = suite.records['strict'], suite.records['loose']
            # The failing waiter is not rescued by the passing waiter's verdict.
            assert strict.status == 'validation_failure'
            assert strict.result == types.ValidResult.FAIL
            assert strict.content == b'shared'
            # The passing waiter independently receives the same legal data.
            assert loose.status == 'ok'
            assert loose.content == b'shared'
            # Each validator judged the packet itself; no verdict was reused.
            assert strict.validator_calls == ['/sec/obj']
            assert loose.validator_calls == ['/sec/obj']

            # The gated waiter is still in flight, so the node must not have been
            # deleted merely because two other waiters already terminated.
            assert suite.pit_has('/sec')
            assert suite.records['gated'].status == 'pending'
            gate.set()
            await suite.settle('gated')
            assert suite.records['gated'].status == 'ok'
            assert suite.records['gated'].content == b'shared'
            assert not suite.pit_has('/sec')
        finally:
            gate.set()
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestValidatorRaisingIsNotPass:
    """A validator that raises neither passes the packet nor hangs the waiter."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        try:
            # crash's validator throws; witness needs an exact fresh name and stays
            # pending, proving the crashing verdict does not corrupt a co-waiter.
            suite.express('crash', '/boom',
                          {'/boom/obj': RuntimeError('policy engine failure')},
                          can_be_prefix=True)
            suite.express('witness', '/boom', {'/boom': types.ValidResult.PASS},
                          can_be_prefix=False, must_be_fresh=True)
            await aio.sleep(0.02)

            await suite.face.deliver(suite.make_data('/boom/obj', b'data',
                                                      freshness_period=1000))
            await suite.settle('crash')

            record = suite.records['crash']
            assert record.status == 'validation_failure'
            assert record.result == types.ValidResult.FAIL
            assert record.content == b'data'

            # The witness never matched the prefix object and the node is retained.
            assert suite.pit_has('/boom')
            assert suite.records['witness'].status == 'pending'
            await suite.face.deliver(suite.make_data('/boom', b'exact',
                                                      freshness_period=1000))
            await suite.settle('witness')
            assert suite.records['witness'].status == 'ok'
            assert suite.records['witness'].content == b'exact'
        finally:
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestMustBeFreshKeepsNodeForLaterFreshData:
    """A stale packet cannot satisfy MustBeFresh; a later fresh one still can."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        try:
            suite.express('fresh_only', '/mbf',
                          {'/mbf': types.ValidResult.PASS}, must_be_fresh=True)
            await aio.sleep(0.02)

            stale = suite.make_data('/mbf', b'old', freshness_period=None)
            await suite.face.deliver(stale)
            await aio.sleep(0.05)
            # Rejected for staleness, the waiter and its node must remain in place.
            assert suite.pit_has('/mbf')
            assert suite.records['fresh_only'].status == 'pending'
            assert suite.records['fresh_only'].validator_calls == []

            fresh = suite.make_data('/mbf', b'new', freshness_period=1000)
            await suite.face.deliver(fresh)
            await suite.settle('fresh_only')

            record = suite.records['fresh_only']
            assert record.status == 'ok'
            assert record.content == b'new'
            assert not suite.pit_has('/mbf')
        finally:
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestSiblingCompletionDoesNotRemoveSharedNode:
    """One waiter finishing on prefix data must not evict a stricter co-waiter."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        gate = aio.Event()
        try:
            # exact_fresh needs an exact, fresh name and rejects the stale prefix data.
            suite.express('exact_fresh', '/p', {'/p': types.ValidResult.PASS},
                          can_be_prefix=False, must_be_fresh=True)
            # prefix_any accepts fresh-or-stale prefix data immediately.
            suite.express('prefix_any', '/p', {'/p/child': types.ValidResult.PASS},
                          can_be_prefix=True, must_be_fresh=False)
            # gated matches the same prefix data but pauses inside validation, keeping
            # an in-flight waiter alive when prefix_any settles.
            suite.express('gated', '/p', {'/p/child': types.ValidResult.PASS},
                          can_be_prefix=True, gate=gate)
            await aio.sleep(0.02)

            # Stale data under a longer prefix: prefix_any and gated match it,
            # exact_fresh does not.
            await suite.face.deliver(
                suite.make_data('/p/child', b'stale', freshness_period=None))
            await aio.sleep(0.05)
            await suite.settle('prefix_any')
            assert suite.records['prefix_any'].status == 'ok'
            assert suite.records['prefix_any'].content == b'stale'
            # Both gated (in flight) and exact_fresh (never matched) still need the node.
            assert suite.pit_has('/p')
            assert suite.pending_count('/p') == 2
            assert suite.records['exact_fresh'].status == 'pending'
            assert suite.records['gated'].status == 'pending'

            # A fresh, exact-name Data now reaches exact_fresh independently.
            await suite.face.deliver(
                suite.make_data('/p', b'fresh', freshness_period=1000))
            await suite.settle('exact_fresh')
            assert suite.records['exact_fresh'].status == 'ok'
            assert suite.records['exact_fresh'].content == b'fresh'
            # Gated is still parked, so the node remains until it resolves too.
            assert suite.pit_has('/p')
            gate.set()
            await suite.settle('gated')
            assert suite.records['gated'].status == 'ok'
            assert not suite.pit_has('/p')
        finally:
            gate.set()
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestCancelOneWaiterKeepsSharedNode:
    """Cancelling one waiter removes only that waiter, never the shared node."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        try:
            suite.express('give_up', '/c', {'/c': types.ValidResult.PASS})
            suite.express('kept', '/c', {'/c': types.ValidResult.PASS})
            await aio.sleep(0.02)
            assert suite.pending_count('/c') == 2

            suite._tasks['give_up'].cancel()
            for _ in range(20):
                await aio.sleep(0.01)
                if suite._tasks['give_up'].done():
                    break
            await suite.settle('give_up')
            assert suite.records['give_up'].status == 'canceled'
            # The node and the surviving waiter are untouched.
            assert suite.pit_has('/c')
            assert suite.pending_count('/c') == 1

            await suite.face.deliver(
                suite.make_data('/c', b'late', freshness_period=1000))
            await suite.settle('kept')
            assert suite.records['kept'].status == 'ok'
            assert suite.records['kept'].content == b'late'
            assert not suite.pit_has('/c')
        finally:
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestNackAffectsAllOnNodeButNotOtherNodes:
    """A Nack ends every waiter on its exact-name node; other name nodes survive.

    Nack handling uses an exact-name PIT lookup and never walks prefixes, so it was
    not vulnerable to the dispatch-based node deletion. This test therefore acts as a
    non-regression guard ensuring the new retention logic keeps that scoping correct.
    """

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        gate = aio.Event()
        try:
            # Two waiters share the exact name that will be Nacked.
            suite.express('n1', '/nack', {'/nack': types.ValidResult.PASS})
            suite.express('n2', '/nack', {'/nack': types.ValidResult.PASS})
            # A different name node: one waiter stays in flight, one waits for data.
            suite.express('gated', '/other', {'/other/leaf': types.ValidResult.PASS},
                          can_be_prefix=True, gate=gate)
            suite.express('other', '/other', {'/other/leaf': types.ValidResult.PASS},
                          can_be_prefix=True)
            await aio.sleep(0.02)

            await suite.face.deliver_nack(suite.face.sent_interests[0], 150)
            await aio.sleep(0.05)
            await suite.settle('n1')
            await suite.settle('n2')
            assert suite.records['n1'].status == 'nack'
            assert suite.records['n1'].nack_reason == 150
            assert suite.records['n2'].status == 'nack'
            assert not suite.pit_has('/nack')
            # The different-name node, including its in-flight waiter, is untouched.
            assert suite.pit_has('/other')
            assert suite.pending_count('/other') == 2
            assert suite.records['other'].status == 'pending'

            # Late Data still reaches the unaffected prefix waiters.
            await suite.face.deliver(
                suite.make_data('/other/leaf', b'alive', freshness_period=1000))
            await aio.sleep(0.05)
            await suite.settle('other')
            assert suite.records['other'].status == 'ok'
            assert suite.records['other'].content == b'alive'
            # Gated is still parked, so the node is retained until it resolves.
            assert suite.pit_has('/other')
            gate.set()
            await suite.settle('gated')
            assert suite.records['gated'].status == 'ok'
            assert not suite.pit_has('/other')
        finally:
            gate.set()
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestLateDataAfterValidationFailureOfSibling:
    """A sibling's failed validation must not prevent a pending waiter's late Data."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        gate = aio.Event()
        try:
            # strict's policy rejects the object; this failure is terminal for strict.
            suite.express('strict', '/d',
                          {'/d/first': types.ValidResult.FAIL}, can_be_prefix=True)
            suite.express('loose', '/d',
                          {'/d/first': types.ValidResult.PASS}, can_be_prefix=True)
            # inflight matches the object but is paused inside validation, so it is
            # still pending (and the node still needed) when strict and loose settle.
            suite.express('inflight', '/d',
                          {'/d/first': types.ValidResult.PASS},
                          can_be_prefix=True, gate=gate)
            await aio.sleep(0.02)

            await suite.face.deliver(
                suite.make_data('/d/first', b'first', freshness_period=1000))
            await aio.sleep(0.05)
            await suite.settle('loose')
            assert suite.records['loose'].status == 'ok'
            await suite.settle('strict')
            assert suite.records['strict'].status == 'validation_failure'

            # Two waiters terminated, but inflight still needs the shared node.
            assert suite.pit_has('/d')
            assert suite.pending_count('/d') == 1
            assert suite.records['inflight'].status == 'pending'

            # Releasing the validator lets the in-flight waiter finish on the same data.
            gate.set()
            await suite.settle('inflight')
            assert suite.records['inflight'].status == 'ok'
            assert suite.records['inflight'].content == b'first'
            assert not suite.pit_has('/d')
        finally:
            gate.set()
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)


class TestPausedValidatorArrivalOrdering:
    """Use a gate to fix arrival/validation order and prove independent resolution."""

    async def scenario(self):
        suite = DispatchTestSuite()
        await suite.start()
        try:
            gate_a = aio.Event()
            suite.express('a', '/g', {'/g': types.ValidResult.PASS}, gate=gate_a)
            suite.express('b', '/g', {'/g': types.ValidResult.PASS})
            await aio.sleep(0.02)

            await suite.face.deliver(
                suite.make_data('/g', b'payload', freshness_period=1000))
            await aio.sleep(0.05)
            # B (ungated) finishes while A is paused inside its own validator.
            await suite.settle('b')
            assert suite.records['b'].status == 'ok'
            assert suite.records['b'].content == b'payload'
            assert suite.pit_has('/g')           # A still pending -> node retained
            assert suite.records['a'].status == 'pending'

            gate_a.set()                        # release A's validator
            await suite.settle('a')
            assert suite.records['a'].status == 'ok'
            assert suite.records['a'].content == b'payload'
            assert suite.records['a'].validator_calls == ['/g']
            assert not suite.pit_has('/g')
        finally:
            await suite.stop()

    def test(self):
        _ScenarioRunner().run(self.scenario)
