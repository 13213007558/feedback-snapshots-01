# -----------------------------------------------------------------------------
# Copyright (C) 2023-2023 The python-ndn authors
#
# This file is part of python-ndn.
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
"""
Security hardening tests for the State Vector Sync instance.

The tests run entirely in memory: two legitimate SVS nodes share an allowlist
of trusted identities while a third, forged node is not listed. Sync Interests
are delivered by invoking the receiving instance's Interest handler directly,
and every data fetch a node *would* issue is derived from
:meth:`SvsInst.missing_data_ranges`, giving an auditable record of the actual
requested sequence ranges.
"""
import asyncio as aio

import pytest

from ndn import app as ndn_app
from ndn import encoding as enc
from ndn import security as sec
from ndn.app_support import svs
from ndn.app_support.svs import policy
from ndn.app_support.svs.tlv import StateVec, StateVecEntry, StateVecWrapper


GROUP_PREFIX = '/test/svs'
NODE_A = enc.Name.from_str('/node/a')
NODE_B = enc.Name.from_str('/node/b')
NODE_EVE = enc.Name.from_str('/node/eve')
NODE_A_BYTES = enc.Name.to_bytes(NODE_A)
NODE_B_BYTES = enc.Name.to_bytes(NODE_B)
NODE_EVE_BYTES = enc.Name.to_bytes(NODE_EVE)

# Keep the jump bound tight so tests stay small while exercising the policy.
MAX_JUMP = 10


class FakeApp:
    """Minimal NDNApp stand-in recording the sync Interests a node emits."""

    def __init__(self):
        self.expressed = []
        self.handler = None

    def express(self, name, _validator, signer=None, no_response=False):
        self.expressed.append(list(name))

    def attach_handler(self, _prefix, handler, _validator):
        self.handler = handler

    def detach_handler(self, _prefix):
        self.handler = None


def make_svs(node_id, verifier=None, max_seq_jump=MAX_JUMP):
    missing = []

    def on_missing(inst):
        # Non-blocking callback: just record that a fetch is warranted. The
        # actual ranges are pulled later via missing_data_ranges().
        missing.append(inst.local_sv.copy())

    inst = svs.SvsInst(
        GROUP_PREFIX, node_id, on_missing,
        sec.DigestSha256Signer(), ndn_app.pass_all,
        sync_interval=0.05, suppression_interval=0.02,
        source_verifier=verifier,
        update_policy=policy.BoundedUpdatePolicy(max_seq_jump),
    )
    return inst, missing


def trusted_verifier():
    return svs.AllowlistSourceVerifier([NODE_A, NODE_B])


def sv_interest(entries):
    """Build a sync Interest name carrying the given (node, seq) entries."""
    pkt = StateVecWrapper()
    pkt.val = StateVec()
    pkt.val.entries = [
        StateVecEntry(node_id=node, seq_no=seq) for node, seq in entries
    ]
    return enc.Name.normalize(
        enc.Name.from_str(GROUP_PREFIX)
        + [enc.tlv_encode(pkt), enc.Component.from_str('sync')]
    )


def deliver(inst, entries):
    inst.sync_handler(sv_interest(entries), None, None, None)


def fetch_ranges(inst, fetched):
    """Return missing ranges with human-readable node names for assertions."""
    ranges = inst.missing_data_ranges(fetched)
    return {enc.Name.to_str(node_id): rng for node_id, rng in ranges.items()}


def test_legitimate_updates_still_propagate():
    inst_a, missing_a = make_svs(NODE_A, trusted_verifier())
    inst_b, missing_b = make_svs(NODE_B, trusted_verifier())

    # Node B publishes three pieces of data.
    for _ in range(3):
        inst_b.new_data()
    assert inst_b.local_sv[NODE_B_BYTES] == 3

    # B's sync Interest reaches A and must be admitted in full.
    deliver(inst_a, [(NODE_B, 3)])
    assert inst_a.local_sv[NODE_B_BYTES] == 3
    assert len(missing_a) == 1
    assert inst_a.reject_counts[policy.RejectReason.UNVERIFIED_SOURCE] == 0

    fetched_b = {}
    assert fetch_ranges(inst_a, fetched_b) == {'/node/b': (1, 3)}
    # Once the application has retrieved through seq 3 nothing remains.
    fetched_b[NODE_B_BYTES] = 3
    assert fetch_ranges(inst_a, fetched_b) == {}

    # A publishes and B learns about it symmetrically.
    inst_a.new_data()
    deliver(inst_b, [(NODE_A, 1)])
    assert inst_b.local_sv[NODE_A_BYTES] == 1
    assert fetch_ranges(inst_b, {}) == {'/node/a': (1, 1)}


def test_forged_high_sequence_is_refused_and_isolated():
    inst_a, missing_a = make_svs(NODE_A, trusted_verifier())
    inst_b, _ = make_svs(NODE_B, trusted_verifier())

    # A single packet mixes a legitimate B update with a forged huge sequence.
    deliver(inst_a, [(NODE_B, 2), (NODE_EVE, 1_000_000)])

    # The legitimate entry is still applied ...
    assert inst_a.local_sv[NODE_B_BYTES] == 2
    # ... while the forged entry never enters the formal state.
    assert NODE_EVE_BYTES not in inst_a.local_sv
    assert inst_a.reject_counts[policy.RejectReason.UNVERIFIED_SOURCE] == 1
    rejection = inst_a.rejected_entries[-1]
    assert rejection.node_id == NODE_EVE_BYTES
    assert rejection.seq_no == 1_000_000
    assert rejection.reason == policy.RejectReason.UNVERIFIED_SOURCE

    # The fetch plan only covers the legitimate node and its real range.
    ranges = fetch_ranges(inst_a, {})
    assert ranges == {'/node/b': (1, 2)}
    assert '/node/eve' not in ranges

    # A's own advertisement never leaks the forged identity or sequence.
    fake_app = FakeApp()
    inst_a.ndn_app = fake_app
    inst_a.express_sync_interest()
    advertised = bytes(fake_app.expressed[-1][-1])
    parsed = enc.tlv_parse(StateVecWrapper, advertised).val
    advertised_nodes = {enc.Name.to_bytes(e.node_id) for e in parsed.entries}
    assert NODE_EVE_BYTES not in advertised_nodes
    assert {e.seq_no for e in parsed.entries if enc.Name.to_bytes(e.node_id) == NODE_B_BYTES} == {2}

    # Node B, which only ever hears A's confirmed state, is not polluted either.
    deliver(inst_b, [(NODE_A, 0), (NODE_B, 2)])
    assert NODE_EVE_BYTES not in inst_b.local_sv


def test_huge_jump_does_not_trigger_unbounded_backfill():
    inst_a, missing_a = make_svs(NODE_A, trusted_verifier())

    # A legitimate node that suddenly claims an enormous jump must be bounded.
    deliver(inst_a, [(NODE_B, MAX_JUMP + 1 + 1)])
    assert NODE_B_BYTES not in inst_a.local_sv
    assert inst_a.reject_counts[policy.RejectReason.JUMP_TOO_LARGE] == 1
    assert missing_a == []
    assert fetch_ranges(inst_a, {}) == {}

    # A jump exactly at the bound is still accepted and yields a bounded range.
    deliver(inst_a, [(NODE_B, MAX_JUMP)])
    assert inst_a.local_sv[NODE_B_BYTES] == MAX_JUMP
    assert fetch_ranges(inst_a, {}) == {'/node/b': (1, MAX_JUMP)}

    # Another jump beyond the newly confirmed progress is refused again.
    deliver(inst_a, [(NODE_B, MAX_JUMP * 3)])
    assert inst_a.local_sv[NODE_B_BYTES] == MAX_JUMP
    assert inst_a.reject_counts[policy.RejectReason.JUMP_TOO_LARGE] == 2

    # Moderate, honest increments continue to flow after a refusal.
    deliver(inst_a, [(NODE_B, MAX_JUMP + 1)])
    assert inst_a.local_sv[NODE_B_BYTES] == MAX_JUMP + 1


def test_duplicate_and_rollback_never_drive_fetching():
    inst_a, missing_a = make_svs(NODE_A, trusted_verifier())
    deliver(inst_a, [(NODE_B, 4)])
    assert inst_a.local_sv[NODE_B_BYTES] == 4
    missing_before = len(missing_a)

    # Replaying the same vector is a duplicate: no state change, no fetch.
    deliver(inst_a, [(NODE_B, 4)])
    assert inst_a.local_sv[NODE_B_BYTES] == 4
    assert inst_a.reject_counts[policy.RejectReason.DUPLICATE_SEQ] == 1
    assert len(missing_a) == missing_before

    # A rolled-back sequence is stale: the confirmed progress stays intact.
    deliver(inst_a, [(NODE_B, 2)])
    assert inst_a.local_sv[NODE_B_BYTES] == 4
    assert inst_a.reject_counts[policy.RejectReason.STALE_SEQ] == 1
    assert len(missing_a) == missing_before

    # A fresh, in-bound update still works.
    deliver(inst_a, [(NODE_B, 5)])
    assert inst_a.local_sv[NODE_B_BYTES] == 5
    assert len(missing_a) == missing_before + 1


def test_self_conflict_and_invalid_sequence_are_refused():
    inst_a, _ = make_svs(NODE_A, trusted_verifier())
    inst_a.new_data()
    assert inst_a.self_seq == 1

    # Nobody else may advance the local node's own sequence.
    deliver(inst_a, [(NODE_A, 99)])
    assert inst_a.local_sv[NODE_A_BYTES] == 1
    assert inst_a.reject_counts[policy.RejectReason.SELF_CONFLICT] == 1

    # A malformed entry carrying a negative sequence cannot poison the state.
    # TLV numbers are non-negative on the wire, so this path is reached via a
    # directly supplied entry (e.g. a custom transport or programmatic caller).
    # Use an allowlisted node so the request reaches the sequence policy.
    inspection = inst_a._admit_entry(NODE_B_BYTES, -1)
    assert inspection.accepted is False
    assert inspection.reason == policy.RejectReason.INVALID_SEQ

    # Exercise the same refusal through the handler's per-entry pipeline by
    # stubbing the parse result with a negative-seq entry.
    class BadEntry:
        node_id = NODE_B
        seq_no = -1

    pkt = StateVecWrapper()
    pkt.val = StateVec()
    pkt.val.entries = [BadEntry()]
    name = sv_interest([])
    original_parse = enc.tlv_parse
    enc.tlv_parse = lambda model, wire: pkt if model is StateVecWrapper else original_parse(model, wire)
    try:
        inst_a.sync_handler(name, None, None, None)
    finally:
        enc.tlv_parse = original_parse
    # B is known but the negative sequence is refused, so progress is unchanged.
    assert inst_a.local_sv.get(NODE_B_BYTES, 0) == 0
    assert inst_a.reject_counts[policy.RejectReason.INVALID_SEQ] == 1


def test_rejected_log_is_bounded():
    small_inst = svs.SvsInst(
        GROUP_PREFIX, NODE_A, lambda _i: None,
        sec.DigestSha256Signer(), ndn_app.pass_all,
        source_verifier=trusted_verifier(),
        update_policy=policy.BoundedUpdatePolicy(MAX_JUMP),
        rejected_log_size=3,
    )
    for seq in range(1, 8):
        deliver(small_inst, [(NODE_EVE, seq)])
    assert len(small_inst.rejected_entries) == 3
    # Counts are not truncated, only the detail log is bounded.
    assert small_inst.reject_counts[policy.RejectReason.UNVERIFIED_SOURCE] == 7
    assert [e.seq_no for e in small_inst.rejected_entries] == [5, 6, 7]


def test_policy_inspection_matrix():
    p = policy.BoundedUpdatePolicy(max_seq_jump=5)
    assert p.inspect(NODE_B_BYTES, 0, 0).reason == policy.RejectReason.DUPLICATE_SEQ
    assert p.inspect(NODE_B_BYTES, -1, 0).reason == policy.RejectReason.INVALID_SEQ
    assert p.inspect(NODE_B_BYTES, 3, 5).reason == policy.RejectReason.STALE_SEQ
    assert p.inspect(NODE_B_BYTES, 6, 0).reason == policy.RejectReason.JUMP_TOO_LARGE
    assert p.inspect(NODE_B_BYTES, 5, 0).accepted is True
    assert p.inspect(NODE_B_BYTES, 1, 0).accepted is True
    with pytest.raises(ValueError):
        policy.BoundedUpdatePolicy(0)


def test_allowlist_verifier_membership():
    verifier = trusted_verifier()
    assert verifier(NODE_A_BYTES) is True
    assert verifier(NODE_B_BYTES) is True
    assert verifier(NODE_EVE_BYTES) is False
    verifier.add(NODE_EVE)
    assert verifier(NODE_EVE_BYTES) is True
    verifier.discard(NODE_EVE)
    assert verifier(NODE_EVE_BYTES) is False


@pytest.mark.asyncio
async def test_timer_advances_without_carrying_forged_state():
    inst_a, _ = make_svs(NODE_A, trusted_verifier())
    fake_app = FakeApp()
    inst_a.start(fake_app)
    try:
        # Forged packet: nothing admissible, but the timer must keep running.
        deliver(inst_a, [(NODE_EVE, 500)])
        assert NODE_EVE_BYTES not in inst_a.local_sv
        # Legitimate update enters suppression, then the timer fires and emits a
        # sync Interest containing only confirmed state.
        deliver(inst_a, [(NODE_B, 1)])
        assert inst_a.state == svs.SvsState.SyncSuppression
        await aio.sleep(0.2)
        assert fake_app.expressed
        advertised = bytes(fake_app.expressed[-1][-1])
        parsed = enc.tlv_parse(StateVecWrapper, advertised).val
        nodes = {enc.Name.to_bytes(e.node_id) for e in parsed.entries}
        assert NODE_EVE_BYTES not in nodes
        assert NODE_B_BYTES in nodes
    finally:
        inst_a.stop()


@pytest.mark.asyncio
async def test_two_legitimate_and_one_forged_node_end_to_end():
    """Full narrative: honest traffic propagates, attacker cannot pollute."""
    verifier = trusted_verifier()
    node_a, fetch_a = make_svs(NODE_A, verifier)
    node_b, fetch_b = make_svs(NODE_B, verifier)
    fetched_a: dict[bytes, int] = {}
    fetched_b: dict[bytes, int] = {}

    # B produces data and A learns the confirmed range through a sync Interest.
    node_b.new_data()
    node_b.new_data()
    deliver(node_a, [(NODE_B, node_b.self_seq)])
    ranges_a = fetch_ranges(node_a, fetched_a)
    assert ranges_a == {'/node/b': (1, 2)}
    # Simulate the application actually requesting only that bounded range.
    for low, high in ranges_a.values():
        for seq in range(low, high + 1):
            assert 1 <= seq <= 2
    fetched_a[NODE_B_BYTES] = 2
    assert fetch_ranges(node_a, fetched_a) == {}

    # Eve floods both honest nodes with a forged, gigantic state vector.
    deliver(node_a, [(NODE_EVE, 10_000_000)])
    deliver(node_b, [(NODE_EVE, 10_000_000)])
    for node in (node_a, node_b):
        assert NODE_EVE_BYTES not in node.local_sv
        assert node.reject_counts[policy.RejectReason.UNVERIFIED_SOURCE] == 1

    # Honest progress continues undisturbed.
    node_a.new_data()
    deliver(node_b, [(NODE_A, 1)])
    assert fetch_ranges(node_b, fetched_b) == {'/node/a': (1, 1)}
    fetched_b[NODE_A_BYTES] = 1
    assert fetch_ranges(node_b, fetched_b) == {}

    # Neither node's confirmed state ever contains Eve, and neither fetch plan
    # ever requests a sequence beyond what honest nodes confirmed.
    assert fetch_ranges(node_a, fetched_a) == {}
    assert fetch_ranges(node_b, fetched_b) == {}
    assert all(NODE_EVE_BYTES not in n.local_sv for n in (node_a, node_b))
