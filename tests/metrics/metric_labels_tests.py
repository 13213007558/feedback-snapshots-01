#  BSD 3-Clause License
#
#  Copyright (c) 2026, Elasticsearch BV
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
import time

import pytest

from elasticapm.base import Client
from elasticapm.metrics.redaction import MetricLabelPolicy, merge_metricsets, policy_from_config
from elasticapm.transport.base import Transport


def test_disabled_allowlist_hides_every_label():
    policy = MetricLabelPolicy(allowlist=[])
    assert policy.active
    assert not policy.allows("span.type", "db")


class MetricBatchTransport(Transport):
    """Record the exact NDJSON batches a transport would publish."""

    def __init__(self, *args, **kwargs) -> None:
        self.payloads = []
        super(MetricBatchTransport, self).__init__(*args, **kwargs)

    def send(self, data, forced_flush=False):
        if data:
            self.payloads.append(bytes(data))

    def batches(self):
        result = []
        for payload in self.payloads:
            batch = []
            raw = gzip.decompress(payload).decode("utf-8")
            for line in raw.splitlines():
                if line:
                    batch.append(json.loads(line))
            result.append(batch)
        return result

    def metricsets(self):
        return [
            record["metricset"]
            for batch in self.batches()
            for record in batch
            if "metricset" in record
        ]


class MetricBatchClient(Client):
    def __init__(self, config=None, **inline) -> None:
        inline.setdefault("transport_class", "tests.metrics.metric_labels_tests.MetricBatchTransport")
        super(MetricBatchClient, self).__init__(config, **inline)


@pytest.fixture()
def metric_client():
    client = MetricBatchClient(
        service_name="labels",
        central_config=False,
        metrics_interval="0ms",
        cloud_provider=False,
        disable_send=False,
    )
    yield client
    client.close()


def _set_policy(client, allowlist=None, denylist=None):
    client.config.update(
        version=str(client.config.config_version or "") + "+policy",
        metric_labels_allowlist=allowlist,
        metric_labels_denylist=denylist,
    )


def _breakdown(client):
    return client.metrics.get_metricset("elasticapm.metrics.sets.breakdown.BreakdownMetricSet")


def _add_bucket(metricset, span_type, count=1, duration_us=1000000, transaction="tx", span_subtype=None):
    labels = {"span.type": span_type, "transaction.name": transaction, "transaction.type": "request"}
    if span_subtype:
        labels["span.subtype"] = span_subtype
    metricset.timer("span.self_time", reset_on_collect=True, unit="us", **labels).update(duration_us, count)


def test_policy_from_config_accepts_patterns_and_mappings():
    policy = MetricLabelPolicy(allowlist=["span.type", "transaction.*"], denylist=["transaction.name=secret"])
    assert policy.allows("span.type", "db")
    assert policy.allows("transaction.type", "request")
    assert not policy.allows("transaction.name", "secret")
    assert not policy.allows("span.subtype", "mysql")

    class Config(object):
        metric_labels_allowlist = {"span.type": ["db", "app"], "transaction.type": None}
        metric_labels_denylist = ["span.type=app"]

    mapped = policy_from_config(Config())
    assert mapped.allows("span.type", "db")
    assert not mapped.allows("span.type", "app")
    assert mapped.allows("transaction.type", "request")
    assert not mapped.allows("span.subtype", "mysql")


def test_public_projection_merges_colliding_buckets_without_losing_totals():
    policy = MetricLabelPolicy(allowlist=["span.type", "transaction.*"])

    def bucket(span_type, subtype, count, duration):
        return {
            "samples": {"span.self_time.count": {"value": count}, "span.self_time.sum.us": {"value": duration}},
            "timestamp": 1,
            "tags": {"span.type": span_type, "span.subtype": subtype},
        }

    merged = merge_metricsets(
        [
            bucket("db", "mysql", 2, 500),
            bucket("db", "postgresql", 3, 700),
            bucket("template", "django", 4, 900),
        ],
        policy,
    )
    assert len(merged) == 2
    db = [item for item in merged if item["tags"].get("span.type") == "db"][0]
    # The restricted subtype is gone, but both contributions survive.
    assert "span.subtype" not in db["tags"]
    assert db["samples"]["span.self_time.count"]["value"] == 5
    assert db["samples"]["span.self_time.sum.us"]["value"] == 1200

    template = [item for item in merged if item["tags"].get("span.type") == "template"][0]
    assert "span.subtype" not in template["tags"]
    assert template["samples"]["span.self_time.sum.us"]["value"] == 900


def test_breakdown_public_view_respects_revoked_label_and_keeps_internal_store(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "span.subtype", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")
    _add_bucket(breakdown, "template", count=4, duration_us=900, span_subtype="django")

    # Every bucket is still tracked internally with its full label set.
    assert len(breakdown._timers) == 3

    # Revoke the permission for one of the two labels that were visible at
    # the start of the collection cycle.
    _set_policy(metric_client, allowlist=["span.type", "transaction.*"])

    public = list(breakdown.collect_public())
    assert len(public) == 2
    db = [item for item in public if item["span"]["type"] == "db"][0]
    assert "subtype" not in db["span"]
    # The revoked bucket still contributes its count and duration.
    assert db["samples"]["span.self_time.count"]["value"] == 5
    assert db["samples"]["span.self_time.sum.us"]["value"] == 1200

    template = [item for item in public if item["span"]["type"] == "template"][0]
    assert "subtype" not in template["span"]
    assert template["samples"]["span.self_time.count"]["value"] == 4

    # A second collection cycle continues from the internal metric stores.
    _add_bucket(breakdown, "db", count=1, duration_us=100, span_subtype="mysql")
    second = list(breakdown.collect_public())
    second_db = [item for item in second if item["span"]["type"] == "db"][0]
    assert second_db["samples"]["span.self_time.count"]["value"] == 1
    assert second_db["samples"]["span.self_time.sum.us"]["value"] == 100


def test_pending_batch_is_rechecked_against_config_at_send_time(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "span.subtype", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")
    _add_bucket(breakdown, "template", count=4, duration_us=900, span_subtype="django")

    # Collect while both label values are still allowed.  The transport
    # consumes the events into its buffer without flushing them yet.
    metric_client.metrics.collect()
    deadline = time.time() + 5
    while time.time() < deadline and metric_client._transport._counts.get("metricset", 0) < 3:
        time.sleep(0.005)
    assert metric_client._transport._counts.get("metricset", 0) == 3
    assert metric_client._transport.batches() == []

    # The permission for one value is withdrawn after collection but before
    # the batch is actually flushed.
    _set_policy(metric_client, allowlist=["span.type", "transaction.*"])
    metric_client._transport.flush()

    batches = metric_client._transport.batches()
    after = metric_client._transport.metricsets()
    assert len(after) == 2
    db = [item for item in after if item["span"]["type"] == "db"][0]
    assert "subtype" not in db["span"]
    assert db["samples"]["span.self_time.count"]["value"] == 5
    assert db["samples"]["span.self_time.sum.us"]["value"] == 1200
    template = [item for item in after if item["span"]["type"] == "template"][0]
    assert template["samples"]["span.self_time.count"]["value"] == 4

    # Nothing leaked into the public batch.
    for item in after:
        assert "postgresql" not in json.dumps(item)

    # The next collection cycle only sends the newer sample, not the totals of
    # the already published batch.
    _add_bucket(breakdown, "db", count=1, duration_us=100, span_subtype="mysql")
    metric_client.metrics.collect()
    metric_client._transport.flush()
    metricsets = metric_client._transport.metricsets()
    latest = metricsets[-1]
    assert latest["span"]["type"] == "db"
    assert latest["samples"]["span.self_time.count"]["value"] == 1
    assert latest["samples"]["span.self_time.sum.us"]["value"] == 100


def test_internal_collection_keeps_the_revoked_labels(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")

    internal = list(breakdown.collect_internal())
    assert len(internal) == 2
    subtypes = {item["span"]["subtype"] for item in internal}
    assert subtypes == {"mysql", "postgresql"}


def test_revocation_after_capture_is_applied_before_the_batch_is_sent(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "span.subtype", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")
    _add_bucket(breakdown, "template", count=4, duration_us=900, span_subtype="django")

    # Both label values are visible when the batch is captured.
    metric_client.metrics.collect()
    deadline = time.time() + 5
    while time.time() < deadline and metric_client._transport._counts.get("metricset", 0) < 3:
        time.sleep(0.005)
    assert metric_client._transport._counts.get("metricset", 0) == 3
    assert metric_client._transport.batches() == []

    # The permission for one value is withdrawn while the batch is still
    # buffered.  It must not be published.
    _set_policy(metric_client, allowlist=["span.type", "transaction.*"])
    metric_client._transport.flush()

    published = metric_client._transport.metricsets()
    assert len(published) == 2
    db = [item for item in published if item["span"]["type"] == "db"][0]
    assert "subtype" not in db["span"]
    assert db["samples"]["span.self_time.count"]["value"] == 5
    assert db["samples"]["span.self_time.sum.us"]["value"] == 1200
    assert all("postgresql" not in json.dumps(item) for item in published)
    # The internal stores were not modified by the redaction.
    assert len(breakdown._timers) == 3


def test_no_label_policy_keeps_historical_payload(metric_client):
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")
    metric_client.metrics.collect()
    metric_client._transport.flush()
    published = metric_client._transport.metricsets()
    assert len(published) == 2
    assert {item["span"]["subtype"] for item in published} == {"mysql", "postgresql"}


def test_histogram_and_gauge_collisions():
    policy = MetricLabelPolicy(allowlist=["kind"])
    histogram_a = {
        "samples": {"latency": {"counts": [1, 2], "values": [1.0, 2.0], "type": "histogram"}},
        "timestamp": 1,
        "tags": {"kind": "a"},
    }
    histogram_b = {
        "samples": {"latency": {"counts": [3, 4], "values": [1.0, 2.0], "type": "histogram"}},
        "timestamp": 1,
        "tags": {"kind": "a"},
    }
    [merged] = merge_metricsets([histogram_a, histogram_b], policy)
    assert merged["samples"]["latency"]["counts"] == [4, 6]

    gauge_a = {"samples": {"g": {"value": 1.0, "type": "gauge"}}, "timestamp": 1, "tags": {"kind": "a"}}
    gauge_b = {"samples": {"g": {"value": 9.0, "type": "gauge"}}, "timestamp": 1, "tags": {"kind": "a"}}
    [gauge] = merge_metricsets([gauge_a, gauge_b], policy)
    assert gauge["samples"]["g"]["value"] == 9.0


def test_dummy_transport_sees_merged_public_series(elasticapm_client):
    elasticapm_client.config.update(
        version="policy",
        metric_labels_allowlist=["span.type", "transaction.*"],
    )
    breakdown = _breakdown(elasticapm_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")
    _add_bucket(breakdown, "template", count=4, duration_us=900, span_subtype="django")

    elasticapm_client.metrics.collect()
    events = elasticapm_client.events["metricset"]
    assert len(events) == 2
    db = [item for item in events if item["span"]["type"] == "db"][0]
    assert "subtype" not in db["span"]
    assert db["samples"]["span.self_time.count"]["value"] == 5
    assert db["samples"]["span.self_time.sum.us"]["value"] == 1200
    # No event carries the revoked value.
    assert all("postgresql" not in json.dumps(item) for item in events)


def test_two_batches_keep_cycle_totals_and_do_not_double_count(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "span.subtype", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=2, duration_us=500, span_subtype="mysql")
    _add_bucket(breakdown, "db", count=3, duration_us=700, span_subtype="postgresql")

    # First cycle: both buckets are visible; flush publishes them separately.
    metric_client.metrics.collect()
    metric_client._transport.flush()
    first_batch = metric_client._transport.batches()[0]
    first_batch = [record["metricset"] for record in first_batch if "metricset" in record]
    assert len(first_batch) == 2
    assert sum(item["samples"]["span.self_time.count"]["value"] for item in first_batch) == 5
    assert sum(item["samples"]["span.self_time.sum.us"]["value"] for item in first_batch) == 1200

    # The permission for one value is withdrawn before the next cycle.  The
    # already published totals must not be repeated; only the new sample is
    # in the second batch and it merges into the surviving series.
    _set_policy(metric_client, allowlist=["span.type", "transaction.*"])
    _add_bucket(breakdown, "db", count=1, duration_us=100, span_subtype="mysql")
    metric_client.metrics.collect()
    metric_client._transport.flush()
    second_batch = metric_client._transport.batches()[-1]
    second_batch = [record["metricset"] for record in second_batch if "metricset" in record]
    assert len(second_batch) == 1
    assert second_batch[0]["samples"]["span.self_time.count"]["value"] == 1
    assert second_batch[0]["samples"]["span.self_time.sum.us"]["value"] == 100
    assert "subtype" not in second_batch[0]["span"]

    total_count = sum(
        item["samples"]["span.self_time.count"]["value"] for batch in (first_batch, second_batch) for item in batch
    )
    total_duration = sum(
        item["samples"]["span.self_time.sum.us"]["value"] for batch in (first_batch, second_batch) for item in batch
    )
    assert total_count == 6
    assert total_duration == 1300


def test_batches_are_recorded_per_flush(metric_client):
    _set_policy(metric_client, allowlist=["span.type", "span.subtype", "transaction.*"])
    breakdown = _breakdown(metric_client)
    _add_bucket(breakdown, "db", count=1, duration_us=100, span_subtype="mysql")
    metric_client.metrics.collect()
    metric_client._transport.flush()
    _add_bucket(breakdown, "db", count=2, duration_us=200, span_subtype="mysql")
    metric_client.metrics.collect()
    metric_client._transport.flush()
    assert len(metric_client._transport.payloads) == 2
    first, second = metric_client._transport.batches()
    assert [record.get("metadata") is not None for record in first] == [True, False]
    assert [record.get("metadata") is not None for record in second] == [True, False]


def test_batch_reprojection_keeps_non_metric_lines_byte_identical():
    from elasticapm.metrics.redaction import reproject_batch_entries

    transaction_line = b'{"transaction": {"id": "abc", "context": {"tags": {"span.type": "db"}}}}\n'
    metric_line = b'{"metricset": {"samples": {"x": {"value": 1}}, "tags": {"span.subtype": "mysql"}}}\n'
    entries = [
        ("transaction", transaction_line, None),
        ("metricset", metric_line, {"samples": {"x": {"value": 1}}, "tags": {"span.subtype": "mysql"}}),
    ]
    policy = MetricLabelPolicy(allowlist=["span.type"])
    [transaction, metricset] = reproject_batch_entries(entries, policy)
    assert transaction == ("transaction", transaction_line, None)
    assert metricset[0] == "metricset"
    assert "tags" not in metricset[2]
    assert metricset[2]["samples"]["x"]["value"] == 1
