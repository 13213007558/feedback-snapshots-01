#  BSD 3-Clause License
#
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import gzip
import json
import threading
import time
from datetime import timedelta

import pytest

from elasticapm.base import Client
from elasticapm.transport.base import Transport
from elasticapm.transport.discard import DiscardPolicy
from elasticapm.transport.exceptions import TransportException


class _StubConfig(object):
    server_url = "http://localhost:8200/"

    def __init__(self, api_request_time=timedelta(seconds=10), api_request_size=768 * 1024) -> None:
        self.api_request_time = api_request_time
        self.api_request_size = api_request_size


class _StubClient(object):
    def __init__(self, **config) -> None:
        self.config = _StubConfig(**config)

    def build_metadata(self):
        return {"service": {"name": "discard-test", "agent": {"name": "python", "version": "test"}}}


class MemoryTransport(Transport):
    """Transport whose sender is an in-memory list, with controllable failures."""

    def __init__(self, *args, **kwargs) -> None:
        self.sent = []
        self.attempts = []
        self.fail_plan = []
        self._send_started = threading.Event()
        self.send_gate = None
        self._records_lock = threading.Lock()
        super(MemoryTransport, self).__init__(*args, **kwargs)

    def wait_until_sending(self, timeout=5) -> None:
        assert self._send_started.wait(timeout)

    def _decode(self, data):
        if not data:
            return []
        raw = gzip.decompress(bytes(data)).decode("utf-8")
        return [json.loads(line) for line in raw.splitlines() if line]

    def send(self, data, forced_flush=False):
        records = self._decode(data)
        if records:
            self._send_started.set()
            with self._records_lock:
                self.attempts.append(records)
        gate = self.send_gate
        if gate is not None:
            gate.wait(5)
        with self._records_lock:
            should_fail = self.fail_plan.pop(0) if self.fail_plan else False
        if should_fail:
            raise TransportException("planned failure")
        if records:
            with self._records_lock:
                self.sent.append(records)


def _event_types(records):
    types = []
    for record in records:
        for key in record:
            if key != "metadata":
                types.append(key)
    return types


def _metadata_of(records):
    assert records
    return records[0]["metadata"]


def _discard_of(records):
    metadata = _metadata_of(records)
    return (metadata or {}).get("discard")


def _start(transport):
    transport.start_thread()
    return transport


def _wait_for(predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def test_low_load_keeps_original_batching():
    transport = _start(MemoryTransport(client=_StubClient(), discard_policy={"max_queue_size": 100}))
    try:
        for index in range(10):
            event_type = "transaction" if index % 2 else "metricset"
            transport.queue(event_type, {"id": index})
        transport.flush()
    finally:
        transport.close()

    assert len(transport.sent) == 1
    records = transport.sent[0]
    assert len(_event_types(records)) == 10
    # No gap exists, so the payload is byte-for-byte the historical shape:
    # a metadata record without a discard section.
    assert _discard_of(records) is None


def test_queue_bound_and_classified_discards_under_backpressure():
    transport = _start(MemoryTransport(client=_StubClient(), discard_policy={"max_queue_size": 4}))
    gate = threading.Event()
    transport.send_gate = gate
    try:
        # Park the consumer inside the first send so producers fill the queue.
        transport.queue("metricset", {"id": "initial"}, flush=True)
        transport.wait_until_sending()

        max_depth = 0
        # Interleave the two ordinary record types during the pressure period.
        for index in range(20):
            event_type = "transaction" if index % 2 == 0 else "metricset"
            transport.queue(event_type, {"id": index})
            max_depth = max(max_depth, transport._queued_events())

        # The queue is bounded (not merely the formed batch), and the bound is
        # respected for every accepted record.
        assert max_depth == 4
        assert transport._queued_events() == 4

        snapshot = transport.get_discard_report()
        # Four interleaved records fit in the bound; every later record evicts
        # one same-class survivor, so exactly the overflow is discarded.
        assert snapshot["discarded"]["total"] == 16
        assert snapshot["discarded"]["by_event_type"] == {"transaction": 8, "metricset": 8}
        assert snapshot["discarded"]["by_reason"] == {"queue_high_water": 16}

        gate.set()
        transport.flush()
        assert _wait_for(lambda: len(transport.sent) == 2)
    finally:
        gate.set()
        transport.close()

    # The acceptance criterion is the set of records that really went out:
    # the parked initial one plus exactly the survivors of the bound.
    exported = [event_type for records in transport.sent for event_type in _event_types(records)]
    assert len(exported) == 5
    assert exported.count("transaction") + exported.count("metricset") == 5

    final_report = _discard_of(transport.sent[-1])
    assert final_report["discarded"]["by_event_type"] == {"transaction": 8, "metricset": 8}
    assert final_report["queue"]["max_size"] == 4
    # Accepted = the parked initial record + all 20 interleaved records.
    assert final_report["accepted"]["total"] == 21
    # The embedded report is a snapshot taken before this batch was confirmed,
    # so the live ledger is the source for the post-acknowledgement count.
    assert transport.get_discard_report()["confirmed"]["total"] == 5


def test_recovery_first_send_failure_keeps_gap_until_acknowledged():
    transport = _start(MemoryTransport(client=_StubClient(), discard_policy={"max_queue_size": 4}))
    gate = threading.Event()
    transport.send_gate = gate
    try:
        transport.queue("metricset", {"id": "initial"}, flush=True)
        transport.wait_until_sending()

        for index in range(8):
            transport.queue("transaction" if index % 2 else "metricset", {"id": index})
        assert transport._queued_events() <= 4
        gap = transport.discard_ledger.snapshot()["discarded"]["by_event_type"]
        assert gap == {"transaction": 2, "metricset": 2}

        # Let the first batch through, then make the first post-recovery send
        # fail and the following one succeed.
        gate.set()
        assert _wait_for(lambda: len(transport.sent) == 1)
        transport.fail_plan = [True]

        transport.queue("transaction", {"id": "recovery-1"}, flush=True)
        transport.flush()
        assert _wait_for(lambda: len(transport.attempts) == 2)
        assert transport.discard_ledger.pending
        assert transport.discard_ledger.last_acknowledged is None
        failed_attempt = transport.attempts[-1]
        failed_report = _discard_of(failed_attempt)
        assert failed_report is not None
        assert failed_report["discarded"]["by_event_type"] == gap
        snapshot = transport.discard_ledger.snapshot()
        assert snapshot["unconfirmed"]["total"] > 0
        assert snapshot["discarded"]["by_event_type"] == gap

        transport.queue("metricset", {"id": "recovery-2"}, flush=True)
        transport.flush()
        assert _wait_for(lambda: len(transport.sent) == 2)
        assert _wait_for(lambda: not transport.discard_ledger.pending)
    finally:
        gate.set()
        transport.close()

    assert not transport.discard_ledger.pending
    acknowledged = transport.last_discard_report
    assert acknowledged["acknowledged"] is True
    assert acknowledged["discarded"]["by_event_type"] == gap
    assert acknowledged["unconfirmed"]["total"] > 0

    # The successful batch really carried the same cumulative gap again, so a
    # later reconnect can verify it from the exported payload.
    success_report = _discard_of(transport.sent[-1])
    assert success_report["discarded"]["by_event_type"] == gap
    assert success_report["unconfirmed"]["total"] == acknowledged["unconfirmed"]["total"]

    # The exact real exports: the initial batch, then the failed recovery
    # batch (never appended to ``sent``), then the successful recovery batch.
    assert len(transport.attempts) == 3
    # The failed attempt drained the four bounded survivors plus recovery-1.
    failed_types = _event_types(transport.attempts[1])
    assert len(failed_types) == 5
    assert failed_types.count("transaction") + failed_types.count("metricset") == 5
    assert "error" not in failed_types
    assert _event_types(transport.attempts[2]) == ["metricset"]
    assert len(transport.sent) == 2

    final = transport.get_discard_report()
    assert final["pending"] is False
    assert final["discarded"]["total"] == sum(gap.values()) == 4
    # The failed batch's five records stay as undetermined sends; they are not
    # reported as discarded and not counted as delivered.
    assert final["unconfirmed"]["by_reason"] == {"send_failed": 5}
    assert final["unconfirmed"]["total"] == 5
    # Confirmed count comes from successful sends only.
    assert final["confirmed"]["total"] == 2


def test_back_off_batch_is_discarded_not_unconfirmed():
    transport = _start(MemoryTransport(client=_StubClient(), discard_policy={"max_queue_size": 10}))
    gate = threading.Event()
    transport.send_gate = gate
    try:
        transport.queue("metricset", {"id": "initial"}, flush=True)
        transport.wait_until_sending()
        # Force the transport into the back-off state while the second batch
        # is being formed.  Two failures put the retry interval at 1s, so the
        # next flush is dropped before it ever reaches send().
        transport.fail_plan = [True]
        gate.set()
        assert _wait_for(lambda: len(transport.attempts) == 1)
        transport.send_gate = None
        transport.state.set_fail()
        transport.state.set_fail()
        assert not transport.state.should_try()
        transport.queue("transaction", {"id": "formed"}, flush=True)
        transport.flush()
    finally:
        gate.set()
        transport.close()

    report = transport.get_discard_report()
    # The formed batch was dropped before send() because of back-off: a known
    # discard, not an undetermined send.
    assert report["discarded"]["by_reason"] == {"transport_back_off": 1}
    assert report["discarded"]["by_event_type"] == {"transaction": 1}
    # Only the genuinely attempted (and failed) send stays unconfirmed.
    assert report["unconfirmed"]["by_event_type"] == {"metricset": 1}


def test_security_records_are_not_displaced_by_ordinary_traffic():
    policy = DiscardPolicy(max_queue_size=4)
    transport = _start(MemoryTransport(client=_StubClient(), discard_policy=policy))
    gate = threading.Event()
    transport.send_gate = gate
    try:
        transport.queue("metricset", {"id": "initial"}, flush=True)
        transport.wait_until_sending()

        for index in range(4):
            transport.queue("transaction", {"id": index})
        transport.queue("error", {"id": "audit"})
        for index in range(4):
            transport.queue("metricset", {"id": index})

        snapshot = transport.discard_ledger.snapshot()
        assert snapshot["discarded"]["by_event_type"].get("error", 0) == 0
        assert snapshot["discarded"]["by_event_type"]["transaction"] == 4
        assert transport._queued_events() <= 4

        gate.set()
        transport.flush()
        assert _wait_for(lambda: len(transport.sent) == 2)
    finally:
        gate.set()
        transport.close()

    exported = [event_type for records in transport.sent for event_type in _event_types(records)]
    assert exported.count("error") == 1


def test_client_parses_policy_and_exposes_report():
    client = Client(
        {
            "SERVICE_NAME": "discard-test",
            "TRANSPORT_CLASS": "tests.transports.test_discard.MemoryTransport",
            "TRANSPORT_DISCARD_POLICY": '{"max_queue_size": 6, "event_classes": {"error": "audit"}}',
            "CENTRAL_CONFIG": "false",
            "METRICS_INTERVAL": "0ms",
            "CLOUD_PROVIDER": "false",
        }
    )
    try:
        transport = client._transport
        assert isinstance(transport, MemoryTransport)
        assert transport.discard_policy.max_queue_size == 6
        assert transport.discard_policy.event_class("error") == "audit"
        assert client.get_discard_report()["queue"]["max_size"] == 6
        assert client.get_discard_report()["discarded"]["total"] == 0
    finally:
        client.close()


def test_without_policy_report_is_none_and_queue_unbounded():
    transport = _start(MemoryTransport(client=_StubClient()))
    try:
        assert transport.discard_policy is None
        assert transport.discard_ledger is None
        assert transport.get_discard_report() is None
        transport.queue("metricset", {"id": 1})
        transport.flush()
    finally:
        transport.close()
    assert len(transport.sent) == 1
    assert _discard_of(transport.sent[0]) is None


def test_discard_policy_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        DiscardPolicy(max_queue_size=0)
    with pytest.raises(ValueError):
        DiscardPolicy.from_value({"max_queue_size": 1, "unknown": True})
    policy = DiscardPolicy.from_value('{"max_queue_size": 3, "event_classes": {"error": "audit"}}')
    assert policy.max_queue_size == 3
    assert policy.event_class("error") == "audit"
