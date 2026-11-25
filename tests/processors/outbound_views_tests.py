#  BSD 3-Clause License
#
#  Copyright (c) 2012, the Sentry Team, see AUTHORS for more details
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


import gzip
import json

import pytest

import elasticapm
from elasticapm.base import Client
from elasticapm.conf.constants import ERROR, MASK, TRANSACTION
from elasticapm.transport.base import Transport
from elasticapm.transport.exceptions import TransportException

INTERNAL_MARKER = "SYNTHETIC-INTERNAL-MARKER-7f3a"
SECOND_MARKER = "SYNTHETIC-SECOND-MARKER-91c2"
RESPONSE_MARKER = "SYNTHETIC-RESPONSE-MARKER-4d8e"

ALL_MARKERS = (INTERNAL_MARKER, SECOND_MARKER, RESPONSE_MARKER)


class PausedCaptureTransport(Transport):
    """
    Real transport that keeps the fully serialized NDJSON in memory rather than
    opening a socket. While ``paused``, ``send`` records the exact bytes that
    would have left the process and then fails, mirroring an unavailable APM
    Server.
    """

    def __init__(self, url, client, *args, **kwargs):
        self.sent_payloads = []
        self.paused = True
        super(PausedCaptureTransport, self).__init__(client, *args, **kwargs)

    def send(self, data, forced_flush=False):
        self.sent_payloads.append(bytes(data))
        if self.paused:
            raise TransportException("transport paused for test", bytes(data))
        return None

    def ndjson(self):
        lines = []
        for payload in self.sent_payloads:
            lines.extend(json.loads(line) for line in gzip.decompress(payload).decode("utf-8").splitlines() if line)
        return lines

    def events_of(self, event_type):
        return [line[event_type] for line in self.ndjson() if event_type in line]


@pytest.fixture()
def paused_client():
    client = Client(
        service_name="myapp",
        secret_token="test_key",
        central_config="false",
        transport_class="tests.processors.outbound_views_tests.PausedCaptureTransport",
        include_paths=("*/tests/*",),
        span_stack_trace_min_duration="0ms",
        metrics_interval="0ms",
        cloud_provider="false",
        span_compression_exact_match_max_duration="0ms",
        span_compression_same_kind_max_duration="0ms",
        exit_span_min_duration="0ms",
        capture_body="all",
    )
    try:
        yield client
    finally:
        client._transport.close()


def _capture_synthetic_error(client):
    transaction = client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "url": {
                "full": "https://example.test/submit?password=" + INTERNAL_MARKER,
                "search": "?password=" + INTERNAL_MARKER,
            },
            "headers": {"authorization": "Bearer " + INTERNAL_MARKER, "x-trace": "kept"},
            "cookies": {"sessionid": INTERNAL_MARKER},
            "body": "username=alice&password=" + INTERNAL_MARKER,
        },
        "request",
    )
    elasticapm.set_context(
        {
            "status_code": 500,
            "headers": {"set-cookie": "sessionid=" + RESPONSE_MARKER, "x-result": "ok"},
            "body": json.dumps({"access_token": RESPONSE_MARKER, "detail": "kept"}),
        },
        "response",
    )
    elasticapm.set_custom_context({"trace_hint": "kept", "secret": SECOND_MARKER})

    try:
        local_password = INTERNAL_MARKER
        api_token = SECOND_MARKER
        raise ValueError("synthetic failure")
    except ValueError:
        event_id = client.capture_exception(handled=True)

    client.end_transaction("POST /submit", "HTTP 5xx")
    return transaction, event_id


def test_internal_and_outbound_error_views(paused_client):
    client = paused_client
    transport = client._transport

    transaction, event_id = _capture_synthetic_error(client)

    # The event is queued but the transport has not serialized anything yet.
    assert not transport.sent_payloads
    assert event_id in client.error_diagnostics

    # An in-process consumer reads the retained view while the outbound path
    # is still waiting.
    internal = client.get_error_diagnostic(event_id)
    assert internal is not None
    assert internal["id"] == event_id
    assert internal["transaction_id"] == transaction.id
    assert internal["trace_id"] == transaction.trace_parent.trace_id
    assert internal["context"]["request"]["body"] == "username=alice&password=" + INTERNAL_MARKER
    assert internal["context"]["request"]["url"]["search"] == "?password=" + INTERNAL_MARKER
    assert internal["context"]["request"]["headers"]["authorization"] == "Bearer " + INTERNAL_MARKER
    assert internal["context"]["request"]["cookies"]["sessionid"] == INTERNAL_MARKER
    assert internal["context"]["response"]["headers"]["set-cookie"] == "sessionid=" + RESPONSE_MARKER
    assert internal["context"]["custom"] == {"trace_hint": "kept", "secret": SECOND_MARKER}
    assert json.loads(internal["context"]["response"]["body"])["access_token"] == RESPONSE_MARKER
    frame_vars = internal["exception"]["stacktrace"][0]["vars"]
    assert frame_vars["local_password"] == INTERNAL_MARKER
    assert frame_vars["api_token"] == SECOND_MARKER

    # A second in-process reader gets an independent copy; mutating it must not
    # change what later readers see.
    internal_again = client.get_error_diagnostic(event_id)
    assert internal_again == internal
    internal_again["context"]["request"]["body"] = "mutated"
    assert client.get_error_diagnostic(event_id)["context"]["request"]["body"].endswith(INTERNAL_MARKER)

    # Release the paused path: processors run and the transport writes real
    # gzip NDJSON.
    client._transport.flush()

    errors = transport.events_of(ERROR)
    transactions = transport.events_of(TRANSACTION)
    assert len(errors) == 1
    assert len(transactions) == 1

    outbound_error = errors[0]
    serialized_error = json.dumps(outbound_error)
    for marker in ALL_MARKERS:
        assert marker not in serialized_error

    # The same sensitive field sources are masked in the outbound view.
    assert outbound_error["context"]["request"]["body"] == "username=alice&password=" + MASK
    assert outbound_error["context"]["request"]["url"]["search"] == "?password=" + MASK
    assert outbound_error["context"]["request"]["url"]["full"] == "https://example.test/submit?password=" + MASK
    assert outbound_error["context"]["request"]["headers"]["authorization"] == MASK
    assert outbound_error["context"]["request"]["headers"]["x-trace"] == "kept"
    assert outbound_error["context"]["request"]["cookies"]["sessionid"] == MASK
    # The default cookie processor masks the whole set-cookie header once it
    # has been rewritten; either form is acceptable as long as the marker is gone.
    assert outbound_error["context"]["response"]["headers"]["set-cookie"] in (MASK, "sessionid=" + MASK)
    assert json.loads(outbound_error["context"]["response"]["body"]) == {"access_token": MASK, "detail": "kept"}
    assert outbound_error["context"]["custom"] == {"trace_hint": "kept", "secret": MASK}
    outbound_vars = outbound_error["exception"]["stacktrace"][0]["vars"]
    assert outbound_vars["local_password"] == MASK
    assert outbound_vars["api_token"] == MASK

    # Approved correlation is preserved in the outbound event.
    assert outbound_error["transaction_id"] == transaction.id
    assert outbound_error["trace_id"] == transaction.trace_parent.trace_id

    # The related business event (transaction) also carries only the public
    # view, while keeping its own ID for correlation.
    outbound_transaction = transactions[0]
    assert outbound_transaction["id"] == transaction.id
    serialized_transaction = json.dumps(outbound_transaction)
    for marker in ALL_MARKERS:
        assert marker not in serialized_transaction
    assert outbound_transaction["context"]["request"]["url"]["search"] == "?password=" + MASK


def test_retained_diagnostic_survives_processor_pass(paused_client):
    client = paused_client
    transaction, event_id = _capture_synthetic_error(client)

    # The default processors redact stacktrace locals on the queued event, but
    # the retained diagnostic was copied before they ran.
    client._transport.flush()

    retained = client.get_error_diagnostic(event_id)
    assert retained["exception"]["stacktrace"][0]["vars"]["local_password"] == INTERNAL_MARKER
    assert retained["context"]["request"]["body"].endswith(INTERNAL_MARKER)

    errors = client._transport.events_of(ERROR)
    assert len(errors) == 1
    assert errors[0]["exception"]["stacktrace"][0]["vars"]["local_password"] == MASK


def test_resubmitted_event_cannot_restore_retained_fields(paused_client):
    client = paused_client
    transport = client._transport
    transaction, event_id = _capture_synthetic_error(client)
    client._transport.flush()

    # Simulate a caller re-submitting the retained in-process view (e.g. a
    # retry path) and reusing the approved transaction correlation.
    retained = client.get_error_diagnostic(event_id)
    resent = json.loads(json.dumps(retained))
    resent["id"] = "b" * 32
    assert resent["transaction_id"] == transaction.id
    client.queue(ERROR, resent)
    client._transport.flush()

    errors = transport.events_of(ERROR)
    assert len(errors) == 2
    for error in errors:
        serialized = json.dumps(error)
        for marker in ALL_MARKERS:
            assert marker not in serialized
        assert error["transaction_id"] == transaction.id
        assert error["id"] in (event_id, "b" * 32)

    # The retained original is still the unredacted diagnostic, and replaying
    # the outbound view again does not pick up its values.
    assert client.get_error_diagnostic(event_id)["context"]["request"]["body"].endswith(INTERNAL_MARKER)


def test_diagnostic_store_is_bounded_and_copy_on_read(paused_client):
    client = paused_client
    client.error_diagnostics = type(client.error_diagnostics)(capacity=2)
    first = client.capture_message("first")
    second = client.capture_message("second")
    third = client.capture_message("third")

    assert first not in client.error_diagnostics
    assert second in client.error_diagnostics
    assert third in client.error_diagnostics

    consumed = client.get_error_diagnostic(third, consume=True)
    assert consumed["log"]["message"] == "third"
    assert third not in client.error_diagnostics


def test_projection_alone_redacts_when_processors_disabled(paused_client):
    client = paused_client
    transport = client._transport
    # Bypass the default processor chain entirely: the serialization-time
    # projection must still protect every source on its own.
    transport._processors = []

    transaction, event_id = _capture_synthetic_error(client)
    client._transport.flush()

    errors = transport.events_of(ERROR)
    assert len(errors) == 1
    outbound = errors[0]
    assert outbound["transaction_id"] == transaction.id
    assert outbound["trace_id"] == transaction.trace_parent.trace_id
    assert outbound["context"]["request"]["body"] == "username=alice&password=" + MASK
    assert outbound["context"]["request"]["url"]["search"] == "?password=" + MASK
    assert outbound["context"]["request"]["headers"]["authorization"] == MASK
    assert outbound["context"]["request"]["cookies"]["sessionid"] == MASK
    assert outbound["context"]["response"]["headers"]["set-cookie"] == "sessionid=" + MASK
    assert json.loads(outbound["context"]["response"]["body"]) == {"access_token": MASK, "detail": "kept"}
    assert outbound["exception"]["stacktrace"][0]["vars"]["local_password"] == MASK
    serialized = json.dumps(outbound)
    for marker in ALL_MARKERS:
        assert marker not in serialized


def _restore_secret_processor(client, event):
    """A deliberately hostile processor that re-adds retained values."""
    event["context"]["request"]["body"] = "username=alice&password=" + INTERNAL_MARKER
    event["context"]["request"]["url"]["search"] = "?password=" + INTERNAL_MARKER
    event["context"]["response"]["body"] = json.dumps({"access_token": RESPONSE_MARKER})
    for frame in event["exception"]["stacktrace"]:
        frame.setdefault("vars", {})["local_password"] = INTERNAL_MARKER
        frame["vars"]["api_token"] = SECOND_MARKER
    return event


def test_projection_after_custom_processor(paused_client):
    client = paused_client
    transport = client._transport
    client._transport._processors = [_restore_secret_processor]

    transaction, event_id = _capture_synthetic_error(client)
    client._transport.flush()

    errors = transport.events_of(ERROR)
    assert len(errors) == 1
    serialized = json.dumps(errors[0])
    for marker in ALL_MARKERS:
        assert marker not in serialized
    assert errors[0]["exception"]["stacktrace"][0]["vars"]["local_password"] == MASK
    assert errors[0]["context"]["request"]["body"].endswith(MASK)


def _rewrite_correlation_processor(client, event):
    event["transaction_id"] = "0" * 16
    event["trace_id"] = "1" * 32
    event["parent_id"] = "2" * 16
    return event


def test_processor_cannot_rewrite_approved_correlation(paused_client):
    client = paused_client
    transport = client._transport
    transport._processors = [transport._processors[0], _rewrite_correlation_processor]

    transaction, event_id = _capture_synthetic_error(client)
    client._transport.flush()

    outbound = transport.events_of(ERROR)[0]
    assert outbound["transaction_id"] == transaction.id
    assert outbound["trace_id"] == transaction.trace_parent.trace_id
    assert outbound["parent_id"] != "2" * 16
    assert outbound["id"] == event_id


def test_resubmitted_retained_payload_is_not_restored_by_correlation(paused_client):
    client = paused_client
    transport = client._transport
    transaction, event_id = _capture_synthetic_error(client)
    client._transport.flush()

    # A retry path re-submits the in-process diagnostic. Its payload may still
    # hold the original marker, but the outbound projection must redact it and
    # only reuse the approved correlation.
    retained = client.get_error_diagnostic(event_id)
    retained["id"] = "c" * 32
    client.queue(ERROR, retained)
    client._transport.flush()

    resent = [event for event in transport.events_of(ERROR) if event["id"] == "c" * 32][0]
    serialized = json.dumps(resent)
    for marker in ALL_MARKERS:
        assert marker not in serialized
    # A new ID has no capture-time correlation record. Any correlation already
    # serialized in the submitted copy comes from that copy itself, but the
    # retained payload must not be appended from the diagnostic store.
    assert client.error_diagnostics.correlation("c" * 32) is None
    assert resent["context"]["request"]["body"] == "username=alice&password=" + MASK


def test_projection_redacts_dict_repr_and_nested_body(paused_client):
    client = paused_client
    transport = client._transport
    transport._processors = []

    client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "{'username': 'alice', 'password': '%s'}" % INTERNAL_MARKER,
            "headers": {"x-nested": "kept"},
        },
        "request",
    )
    try:
        payload_password = INTERNAL_MARKER
        raise ValueError("nested")
    except ValueError:
        event_id = client.capture_exception()
    client.end_transaction("POST /nested", "HTTP 5xx")
    client._transport.flush()

    outbound = transport.events_of(ERROR)[0]
    assert outbound["context"]["request"]["body"] == "{'username': 'alice', 'password': '%s'}" % MASK
    assert outbound["exception"]["stacktrace"][0]["vars"]["payload_password"] == MASK
    assert INTERNAL_MARKER not in json.dumps(outbound)


def test_close_clears_diagnostics(paused_client):
    client = paused_client
    event_id = client.capture_message("before close")
    assert event_id in client.error_diagnostics
    client.close()
    assert event_id not in client.error_diagnostics


def test_projection_failure_drops_event_closed(paused_client, monkeypatch):
    import elasticapm.transport.base

    client = paused_client
    transport = client._transport

    def broken_projection(client, event_type, event):
        raise RuntimeError("projection exploded")

    monkeypatch.setattr(elasticapm.transport.base, "project_event_for_export", broken_projection)
    client.capture_message("must not leak", handled=True)
    client._transport.flush()

    assert transport.events_of(ERROR) == []


def test_projection_handles_unicode_and_bytes_bodies(paused_client):
    client = paused_client
    transport = client._transport
    transport._processors = []

    client.begin_transaction("request")
    elasticapm.set_context(
        {
            "body": ("username=josé&password=" + INTERNAL_MARKER).encode("utf-8"),
        },
        "request",
    )
    try:
        raise ValueError("bytes")
    except ValueError:
        client.capture_exception()
    client.end_transaction("POST /bytes", "HTTP 5xx")
    client._transport.flush()

    outbound = transport.events_of(ERROR)[0]
    assert "josé" in outbound["context"]["request"]["body"]
    assert INTERNAL_MARKER not in json.dumps(outbound)


def test_projection_leaves_non_string_values_alone(paused_client):
    client = paused_client
    transport = client._transport
    transport._processors = []

    client.begin_transaction("request")
    elasticapm.set_context(
        {
            "headers": {"x-count": 5, "x-flag": True},
            "url": {"search": "?page=2"},
            "body": {"page": 2, "tags": ["a", "b"]},
        },
        "request",
    )
    try:
        raise ValueError("typed")
    except ValueError:
        client.capture_exception()
    client.end_transaction("POST /typed", "HTTP 5xx")
    client._transport.flush()

    outbound = transport.events_of(ERROR)[0]
    assert outbound["context"]["request"]["headers"]["x-count"] == 5
    assert outbound["context"]["request"]["headers"]["x-flag"] is True
    assert outbound["context"]["request"]["url"]["search"] == "?page=2"
    assert outbound["context"]["request"]["body"]["page"] == 2


def test_correlation_record_excludes_payload():
    from elasticapm.diagnostics import ErrorDiagnosticStore

    store = ErrorDiagnosticStore(capacity=2)
    event = {
        "id": "a" * 32,
        "trace_id": "b" * 32,
        "transaction_id": "c" * 16,
        "parent_id": "d" * 16,
        "context": {"request": {"body": "password=" + INTERNAL_MARKER}},
    }
    store.retain(event)

    correlation = store.correlation("a" * 32)
    assert correlation == {"id": "a" * 32, "trace_id": "b" * 32, "transaction_id": "c" * 16, "parent_id": "d" * 16}
    assert INTERNAL_MARKER not in json.dumps(correlation)

    # A replayed event cannot overwrite the capture-time record.
    store.retain({"id": "a" * 32, "trace_id": "e" * 32})
    assert store.correlation("a" * 32)["trace_id"] == "b" * 32
