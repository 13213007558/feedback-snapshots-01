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

"""End-to-end tests for the local disclosure ceiling.

The tests drive the real export path (transport buffer -> flush -> HTTP send)
and assert on the decoded NDJSON payloads.  This proves the ceiling is applied
to what actually leaves the process, not only to in-memory helpers.
"""

import gzip
import json

import pytest

import elasticapm
from elasticapm.conf.constants import ERROR, MASK, SPAN, TRANSACTION
from elasticapm.transport.base import Transport


class CapturingTransport(Transport):
    """A transport that serialises exactly like the HTTP transport.

    The compressed payloads are stored so tests can decode the exported NDJSON
    and assert on the bytes that would have been sent.
    """

    def __init__(self, *args, **kwargs):
        self.payloads = []
        super(CapturingTransport, self).__init__(*args, **kwargs)

    def send(self, data, forced_flush=False, custom_url=None, custom_headers=None):
        self.payloads.append(bytes(data))

    def exported_events(self):
        events = []
        for payload in self.payloads:
            if not payload:
                continue
            raw = gzip.decompress(payload).decode("utf-8")
            for line in raw.split("\n"):
                if not line:
                    continue
                item = json.loads(line)
                if "metadata" in item:
                    continue
                event_type, event = next(iter(item.items()))
                events.append((event_type, event))
        return events

    def exported_of_type(self, event_type):
        return [event for typ, event in self.exported_events() if typ == event_type]


@pytest.fixture()
def ceiling_client(request):
    """A client that stores events, with central config driving the values."""
    config = getattr(request, "param", {})
    config.setdefault("service_name", "myapp")
    config.setdefault("secret_token", "test_key")
    config.setdefault("central_config", "true")
    config.setdefault("include_paths", ("*/tests/*",))
    config.setdefault("metrics_interval", "0ms")
    config.setdefault("cloud_provider", False)
    config.setdefault("span_stack_trace_min_duration", 0)
    config.setdefault("span_compression_exact_match_max_duration", "0ms")
    config.setdefault("span_compression_same_kind_max_duration", "0ms")
    config.setdefault("exit_span_min_duration", "0ms")
    # Local deployment policy: error bodies only.
    config.setdefault("capture_body", "errors")
    # Use the real (file-transfer-free) transport base but capture the payloads.
    from elasticapm.base import Client

    class _Client(Client):
        def __init__(self, **kwargs):
            kwargs.setdefault("transport_class", "tests.config.disclosure_ceiling_tests.CapturingTransport")
            super(_Client, self).__init__(**kwargs)

    client = _Client(**config)
    yield client
    client.close()


def _central_update(client, **values):
    """Apply a central config update, as the config updater thread would."""
    return client.config.update_central("central-1", **values)


def test_two_phase_ceiling_is_enforced_on_export(ceiling_client):
    # Phase 1: local policy allows error bodies only. Central tries to widen.
    _central_update(ceiling_client, capture_body="all", capture_headers=True)
    ceiling_client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret&ok=1",
            "headers": {"authorization": "Bearer topsecret", "x-api-version": "1"},
            "url": {"full": "http://example.com/phase1"},
        },
        "request",
    )
    ceiling_client.end_transaction("phase1", "200")
    ceiling_client._transport.flush()

    phase1_payloads = list(ceiling_client._transport.payloads)
    assert len(phase1_payloads) == 1

    # Phase 2 begins. Central config receives an even wider value, then the
    # local deployment tightens one additional item.
    _central_update(
        ceiling_client,
        capture_body="all",
        capture_headers=True,
        span_stack_trace_min_duration="0",
    )
    ceiling_client.config.tighten_ceiling(capture_headers=False)

    ceiling_client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret&ok=1",
            "headers": {"authorization": "Bearer topsecret", "x-api-version": "1"},
            "url": {"full": "http://example.com/phase2"},
        },
        "request",
    )
    ceiling_client.end_transaction("phase2", "200")
    ceiling_client._transport.flush()

    transactions = ceiling_client._transport.exported_of_type(TRANSACTION)
    assert len(transactions) == 2
    phase1, phase2 = transactions

    # capture_body="errors" locally: transaction bodies must be redacted even
    # though central requested "all".
    assert phase1["context"]["request"]["body"] == MASK
    # capture_headers was still allowed when phase1 was exported.
    assert phase1["context"]["request"]["headers"]["x-api-version"] == "1"

    # After the local tightening, headers are gone and bodies stay masked.
    assert phase2["context"]["request"]["body"] == MASK
    assert "headers" not in phase2["context"]["request"]


def test_late_local_tightening_applies_to_buffered_events(ceiling_client):
    # Phase 1: capture everything locally, transaction starts, event is buffered.
    _central_update(ceiling_client, capture_body="all", capture_headers=True)
    ceiling_client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret&ok=1",
            "headers": {"authorization": "Bearer topsecret", "x-api-version": "1"},
            "url": {"full": "http://example.com/buffered"},
        },
        "request",
    )
    ceiling_client.end_transaction("buffered", "200")

    # The ceiling tightens after the event was already queued/buffered.
    ceiling_client.config.tighten_ceiling(capture_body="off", capture_headers=False)
    ceiling_client._transport.flush()

    transactions = ceiling_client._transport.exported_of_type(TRANSACTION)
    assert len(transactions) == 1
    request = transactions[0]["context"]["request"]
    # The buffered body is re-checked before egress: payload must not leak.
    assert request["body"] == MASK
    assert "headers" not in request
    # Diagnostics that are still legitimate remain available.
    assert transactions[0]["name"] == "buffered"
    assert transactions[0]["type"] == "request"


def test_config_snapshot_matches_effective_central_values(ceiling_client):
    _central_update(ceiling_client, capture_body="all", collect_local_variables="all", stack_trace_limit="100")
    transaction = ceiling_client.begin_transaction("test")
    snapshot = transaction.config_disclosure
    # Central values that widen are clamped in the snapshot.
    assert snapshot["capture_body"] == "error"
    assert snapshot["collect_local_variables"] == "errors"
    assert snapshot["stack_trace_limit"] == 50
    ceiling_client.end_transaction("test", "200")
    ceiling_client._transport.flush()

    transaction_payload = ceiling_client._transport.exported_of_type(TRANSACTION)[0]
    # The internal snapshot must never leak into the exported payload.
    assert "disclosure" not in transaction_payload


def test_offline_restore_late_central_values_respect_local_ceiling(ceiling_client):
    # Simulate an offline period: the local ceiling tightens while disconnected.
    ceiling_client.config.tighten_ceiling(capture_body="errors", capture_headers=False)

    # A late central value arrives afterwards and tries to widen again.
    _central_update(ceiling_client, capture_body="all", capture_headers=True)

    assert ceiling_client.config.capture_body == "error"
    assert ceiling_client.config.capture_headers is False

    ceiling_client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret",
            "headers": {"x-api-version": "1"},
            "url": {"full": "http://example.com/late"},
        },
        "request",
    )
    ceiling_client.end_transaction("late", "200")
    ceiling_client._transport.flush()

    request = ceiling_client._transport.exported_of_type(TRANSACTION)[0]["context"]["request"]
    assert request["body"] == MASK
    assert "headers" not in request


def test_central_config_can_tighten_within_local_range(ceiling_client):
    # Local policy allows all bodies and headers.
    ceiling_client.config.update("local-1", capture_body="all", capture_headers=True)
    # Central selects a stricter, but locally allowed, value.
    _central_update(ceiling_client, capture_body="errors", capture_headers=False)

    assert ceiling_client.config.capture_body == "error"
    assert ceiling_client.config.capture_headers is False

    ceiling_client.begin_transaction("request")
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret&ok=1",
            "headers": {"x-api-version": "1"},
            "url": {"full": "http://example.com/tighten"},
        },
        "request",
    )
    ceiling_client.end_transaction("tighten", "200")
    ceiling_client._transport.flush()

    request = ceiling_client._transport.exported_of_type(TRANSACTION)[0]["context"]["request"]
    assert request["body"] == MASK
    assert "headers" not in request


def test_central_config_wide_value_still_collects_legitimate_diagnostics(ceiling_client):
    # Sanity/control: a central value inside the approved range is effective.
    ceiling_client.config.update(
        "local-2",
        capture_body="all",
        capture_headers=True,
        collect_local_variables="all",
        local_var_max_length=50,
    )
    _central_update(
        ceiling_client,
        capture_body="all",
        capture_headers=True,
        collect_local_variables="all",
        local_var_max_length=50,
        stack_trace_limit="25",
    )

    ceiling_client.begin_transaction("test")
    with elasticapm.capture_span("diagnostic-span"):
        diagnostic_local = "x" * 200
        assert diagnostic_local
    ceiling_client.end_transaction("control", "200")
    ceiling_client._transport.flush()

    spans = ceiling_client._transport.exported_of_type(SPAN)
    assert len(spans) == 1
    span = spans[0]
    # Stack traces and (shortened) locals remain available.
    assert span["name"] == "diagnostic-span"
    assert "stacktrace" in span
    frame = span["stacktrace"][0]
    assert "vars" in frame
    shortened = [value for key, value in frame["vars"].items() if key == "diagnostic_local"]
    assert shortened and len(shortened[0]) <= 50
    assert len(span["stacktrace"]) <= 25


def test_central_config_wider_value_reaches_shared_config_but_not_transaction(ceiling_client):
    """The shared config snapshot and the final export agree on the allowance.

    Central asks for ``all``; the local ceiling allows only error bodies.  The
    effective config value (what a new transaction snapshots) must already be
    the clamped value, so there is no window in which the agent believes a
    wider policy is in effect.
    """
    _central_update(ceiling_client, capture_body="all")
    assert ceiling_client.config.capture_body == "error"

    transaction = ceiling_client.begin_transaction("request")
    assert transaction.config_disclosure["capture_body"] == "error"
    elasticapm.set_context(
        {
            "method": "POST",
            "body": "token=topsecret&ok=1",
            "headers": {"x-api-version": "1"},
            "url": {"full": "http://example.com/shared"},
        },
        "request",
    )
    ceiling_client.end_transaction("shared", "200")
    ceiling_client._transport.flush()

    exported = ceiling_client._transport.exported_of_type(TRANSACTION)[0]
    assert exported["context"]["request"]["body"] == MASK
    assert exported["context"]["request"]["headers"]["x-api-version"] == "1"


def test_span_stack_trace_ceiling_is_applied_on_export(ceiling_client):
    """A stricter local stack-trace threshold removes span frames at egress."""
    ceiling_client.config.update("local-4", span_stack_trace_min_duration="100")
    _central_update(ceiling_client, span_stack_trace_min_duration="0")

    ceiling_client.begin_transaction("test")
    with elasticapm.capture_span("short", duration=0.01):
        pass
    with elasticapm.capture_span("long", duration=0.2):
        pass
    ceiling_client.end_transaction("traces", "200")
    ceiling_client._transport.flush()

    spans = {span["name"]: span for span in ceiling_client._transport.exported_of_type(SPAN)}
    assert "stacktrace" not in spans["short"]
    assert "stacktrace" in spans["long"]


def test_error_in_transaction_uses_transaction_snapshot(ceiling_client):
    """Errors are clamped by the same ceiling as the surrounding transaction."""
    # Locally, locals are collected for errors but not transactions. Central
    # tries to widen it to "all"; the local ceiling keeps it at "errors".
    _central_update(ceiling_client, collect_local_variables="all")
    assert ceiling_client.config.collect_local_variables == "errors"

    ceiling_client.begin_transaction("request")
    with elasticapm.capture_span("diagnostic-span"):
        span_local = "span-secret"
        assert span_local
    try:
        error_local = "error-secret"
        assert error_local
        1 / 0
    except ZeroDivisionError:
        ceiling_client.capture_exception()
    ceiling_client.end_transaction("with-error", "500")
    ceiling_client._transport.flush()

    errors = ceiling_client._transport.exported_of_type(ERROR)
    assert len(errors) == 1
    frames = errors[0]["exception"]["stacktrace"]
    assert frames
    # Errors may expose locals; that is within the local ceiling.
    assert any("vars" in frame for frame in frames)

    spans = ceiling_client._transport.exported_of_type(SPAN)
    assert len(spans) == 1
    # Transactions/spans may not expose locals under this local ceiling.
    for frame in spans[0].get("stacktrace", []):
        assert "vars" not in frame


def test_local_widening_reopens_previously_clamped_central_value(ceiling_client):
    # Local starts at "errors", central asks for "all" -> clamped.
    _central_update(ceiling_client, capture_body="all")
    assert ceiling_client.config.capture_body == "error"
    # A local reconfiguration is authoritative and may widen the ceiling again.
    ceiling_client.config.update("local-widen", capture_body="all")
    # The still-requested central value can now apply, but never more than what
    # the local deployment allows.
    assert ceiling_client.config.capture_body == "all"
    # A later central request to widen beyond the new ceiling is still clamped
    # only by the new local value, which is now "all".
    _central_update(ceiling_client, capture_body="all")
    assert ceiling_client.config.capture_body == "all"


def test_tighten_ceiling_never_widens(ceiling_client):
    _central_update(ceiling_client, capture_body="all")
    assert ceiling_client.config.capture_body == "error"
    # tighten_ceiling is a one-way operation and must not widen the ceiling.
    ceiling_client.config.tighten_ceiling(capture_body="all")
    assert ceiling_client.config.capture_body == "error"


def test_report_identifies_only_controlled_option(ceiling_client):
    _central_update(ceiling_client, capture_body="all", capture_headers=False)
    report = ceiling_client.config.disclosure_report()
    assert report["capture_body"]["clamped"] is True
    assert report["capture_body"]["central"] == "all"
    assert report["capture_body"]["effective"] == "error"
    # capture_headers was tightened by central and matches the local ceiling, so
    # it is not clamped; it simply took effect.
    assert report["capture_headers"]["clamped"] is False
    assert report["capture_headers"]["effective"] is False


def test_sanitize_field_names_cannot_be_narrowed_by_central(ceiling_client):
    ceiling_client.config.update("local-3", sanitize_field_names=["password", "session"])
    _central_update(ceiling_client, sanitize_field_names=["password"])
    # The union keeps the local "session" pattern, so it still redacts.
    patterns = [pattern.pattern for pattern in ceiling_client.config.sanitize_field_names]
    assert len(patterns) == 2
