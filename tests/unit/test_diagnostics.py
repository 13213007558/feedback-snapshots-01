# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import io
import json

import pytest
from urllib3.exceptions import ReadTimeoutError as URLLib3ReadTimeoutError

from botocore.awsrequest import AWSPreparedRequest
from botocore.diagnostics import (
    EVIDENCE_GAP,
    REDACTED,
    REQUEST_FAILED,
    REQUEST_PREPARED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    TICKET_CLOSED,
    TICKET_OPENED,
    BaseDiagnosticSink,
    DiagnosticRecorder,
    DiagnosticTicket,
    FileDiagnosticSink,
    InMemoryDiagnosticSink,
    NullDiagnosticTicket,
    build_body_facts,
    build_request_facts,
    sanitize_error_message,
    sanitize_headers,
    sanitize_url,
)
from botocore.endpoint import Endpoint
from botocore.model import ServiceId
from tests import mock, unittest

SECRET_HEADER = "AKIASECRETMARKER123"
SECRET_QUERY = "sig-secret-value-456"
SECRET_BODY = "TOP-SECRET-PAYLOAD-789"


def request_dict(**kwargs):
    base = {
        "headers": {},
        "body": "",
        "url_path": "/",
        "query_string": "",
        "method": "POST",
        "url": "https://example.com",
        "context": {},
    }
    base.update(kwargs)
    return base


def make_signed_prepared_request():
    return AWSPreparedRequest(
        method="POST",
        url=(
            "https://s3.us-west-2.amazonaws.com/bucket/key"
            f"?X-Amz-Signature={SECRET_QUERY}&X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&prefix=reports"
        ),
        headers={
            "Authorization": f"AWS4-HMAC-SHA256 Credential={SECRET_HEADER}",
            "X-Amz-Security-Token": SECRET_HEADER,
            "X-Amz-Date": "20261124T000000Z",
            "Content-Type": "application/json",
        },
        body=SECRET_BODY.encode("utf-8"),
        stream_output=False,
        context={},
    )


def make_operation():
    operation = mock.Mock()
    operation.name = "PutObject"
    operation.has_streaming_output = False
    operation.has_event_stream_output = False
    operation.has_streaming_input = True
    operation.metadata = {"protocol": "rest-xml"}
    operation.service_model.service_id = ServiceId("S3")
    return operation


class FixedClock:
    def __init__(self):
        self.ticks = 0

    def __call__(self):
        self.ticks += 1
        return f"2026-11-24T00:00:0{self.ticks}+00:00"


class TestSanitizers:
    def test_sanitize_headers_redacts_credential_values(self):
        sanitized = sanitize_headers(
            {
                "Authorization": SECRET_HEADER,
                "X-Amz-SECURITY-TOKEN": SECRET_HEADER,
                "Content-Type": "application/json",
                b"X-Amz-Date": b"20261124T000000Z",
            }
        )
        assert sanitized["Authorization"] == REDACTED
        assert sanitized["X-Amz-SECURITY-TOKEN"] == REDACTED
        assert sanitized["X-Amz-Date"] == REDACTED
        assert sanitized["Content-Type"] == "application/json"
        assert SECRET_HEADER not in json.dumps(sanitized)

    def test_sanitize_url_redacts_signature_query_only(self):
        safe_url = sanitize_url(
            "https://example.com/path"
            f"?X-Amz-Signature={SECRET_QUERY}&name=ok"
        )
        assert SECRET_QUERY not in safe_url
        assert "X-Amz-Signature=" + REDACTED in safe_url
        assert "name=ok" in safe_url

    def test_sanitize_url_without_query_is_unchanged(self):
        url = "https://example.com/path"
        assert sanitize_url(url) == url

    def test_build_body_facts_never_holds_body_bytes(self):
        facts = build_body_facts(SECRET_BODY.encode("utf-8"))
        assert facts == {
            "present": True,
            "type": "bytes",
            "length": len(SECRET_BODY.encode("utf-8")),
            "length_known": True,
        }
        assert SECRET_BODY not in json.dumps(facts)
        assert build_body_facts(None)["present"] is False

    def test_build_body_facts_describes_streams_without_consuming(self):
        stream = io.BytesIO(b"stream-bytes")
        facts = build_body_facts(stream)
        assert facts["type"] == "BytesIO"
        assert facts["length"] == 12
        assert stream.tell() == 0

    def test_build_request_facts_contains_no_raw_request_or_secret(self):
        facts = build_request_facts(make_signed_prepared_request())
        serialized = json.dumps(facts)
        assert SECRET_HEADER not in serialized
        assert SECRET_QUERY not in serialized
        assert SECRET_BODY not in serialized
        assert facts["method"] == "POST"
        assert facts["headers"]["Authorization"] == REDACTED
        assert facts["body"]["length"] == len(SECRET_BODY.encode("utf-8"))
        assert not isinstance(facts, AWSPreparedRequest)

    def test_sanitize_error_message_redacts_signature_material(self):
        message = (
            "read timed out for https://example.com/path"
            f"?X-Amz-Signature={SECRET_QUERY}&ok=1"
        )
        sanitized = sanitize_error_message(message)
        assert SECRET_QUERY not in sanitized
        assert REDACTED in sanitized
        assert "ok=1" in sanitized


class TestInMemorySink:
    def test_failing_sink_counts_failures_then_recovers(self):
        sink = InMemoryDiagnosticSink(fail_times=2)
        with pytest.raises(OSError):
            sink.write({"event": "a"})
        with pytest.raises(OSError):
            sink.write({"event": "b"})
        sink.write({"event": "c", "ticket_id": "t1"})
        assert sink.write_failures == 2
        assert [record["event"] for record in sink.records] == ["c"]
        assert sink.records_for_ticket("t1") == [
            {"event": "c", "ticket_id": "t1"}
        ]
        assert sink.records_for_ticket("other") == []


class TestDiagnosticTicket:
    def _ticket(self, sink, clock=None):
        return DiagnosticTicket(
            ticket_id="ticket-1",
            operation_name="PutObject",
            service_id="s3",
            sink=sink,
            clock=clock or FixedClock(),
        )

    def test_records_are_plain_serializable_facts(self):
        sink = InMemoryDiagnosticSink()
        ticket = self._ticket(sink)
        ticket.record_preparation(make_signed_prepared_request(), attempt=1)
        ticket.record_dispatch(attempt=1, dispatch_source="http_session")
        ticket.close(outcome="succeeded", attempts=1)
        serialized = json.dumps(sink.records)
        assert SECRET_HEADER not in serialized
        assert SECRET_QUERY not in serialized
        assert SECRET_BODY not in serialized
        assert all(isinstance(record, dict) for record in sink.records)

    def test_sink_outage_leaves_gap_and_business_facts_continue(self):
        sink = InMemoryDiagnosticSink(fail_times=1)
        ticket = self._ticket(sink)
        ticket.record_preparation(make_signed_prepared_request(), attempt=1)
        ticket.record_dispatch(attempt=1, dispatch_source="http_session")
        ticket.close(outcome="succeeded", attempts=1)

        events = [record["event"] for record in sink.records]
        assert events[0] == EVIDENCE_GAP
        gap = sink.records[0]
        assert gap["ticket_id"] == "ticket-1"
        assert gap["missed_event"] == TICKET_OPENED
        assert gap["reason"] == "OSError"
        assert REQUEST_PREPARED in events
        assert TICKET_CLOSED in events
        assert ticket.gap_count == 1
        assert ticket.dropped_records == 1
        assert ticket.preparations == 1
        assert ticket.dispatches == 1

    def test_sustained_outage_keeps_counting_gaps_without_raising(self):
        sink = InMemoryDiagnosticSink(fail_times=100)
        ticket = self._ticket(sink)
        ticket.record_preparation(make_signed_prepared_request(), attempt=1)
        ticket.record_failure(
            attempt=1, exception=URLLib3ReadTimeoutError(None, None, None)
        )
        ticket.close(outcome="failed", attempts=1)
        assert sink.records == []
        assert ticket.gap_count == 4
        assert ticket.dropped_records == 4

    def test_recovery_flushes_single_gap_then_resumes_facts(self):
        sink = InMemoryDiagnosticSink(fail_times=3)
        ticket = self._ticket(sink)
        ticket.record_preparation(make_signed_prepared_request(), attempt=1)
        ticket.record_dispatch(attempt=1, dispatch_source="http_session")
        ticket.close(outcome="succeeded", attempts=1)

        events = [record["event"] for record in sink.records]
        assert events == [EVIDENCE_GAP, TICKET_CLOSED]
        assert events.count(EVIDENCE_GAP) == 1
        assert sink.records[0]["missed_event"] == TICKET_OPENED
        assert ticket.gap_count == 3
        assert ticket.dropped_records == 3

    def test_tickets_are_isolated_per_operation(self):
        sink = InMemoryDiagnosticSink(fail_times=1)
        recorder = DiagnosticRecorder(sink=sink)
        ticket_a = recorder.open_ticket("PutObject", "s3")
        ticket_a.record_dispatch(attempt=1, dispatch_source="http_session")
        ticket_a.close(outcome="succeeded", attempts=1)

        ticket_b = recorder.open_ticket("GetObject", "s3")
        ticket_b.record_dispatch(attempt=1, dispatch_source="http_session")
        ticket_b.close(outcome="succeeded", attempts=1)

        assert ticket_a.ticket_id != ticket_b.ticket_id
        a_records = sink.records_for_ticket(ticket_a.ticket_id)
        b_records = sink.records_for_ticket(ticket_b.ticket_id)
        assert any(record["event"] == EVIDENCE_GAP for record in a_records)
        assert all(
            record["ticket_id"] == ticket_b.ticket_id
            and record["event"] != EVIDENCE_GAP
            for record in b_records
        )


class TestFileDiagnosticSink:
    def test_appends_one_json_record_per_line(self, tmp_path):
        path = tmp_path / "diagnostics.jsonl"
        sink = FileDiagnosticSink(str(path))
        sink.write({"event": "a", "ticket_id": "t1"})
        sink.write({"event": "b", "ticket_id": "t1"})
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert [json.loads(line)["event"] for line in lines] == ["a", "b"]

    def test_unwritable_destination_propagates_error(self, tmp_path):
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        sink = FileDiagnosticSink(str(blocker / "diagnostics.jsonl"))
        with pytest.raises(OSError):
            sink.write({"event": "a"})


class TestRecorder:
    def test_recorder_without_sink_returns_null_ticket(self):
        recorder = DiagnosticRecorder()
        ticket = recorder.open_ticket("PutObject", "s3")
        assert isinstance(ticket, NullDiagnosticTicket)
        ticket.record_preparation(make_signed_prepared_request(), 1)
        ticket.close(outcome="succeeded", attempts=1)

    def test_recorder_opens_distinct_tickets(self):
        recorder = DiagnosticRecorder(sink=InMemoryDiagnosticSink())
        first = recorder.open_ticket("PutObject", "s3")
        second = recorder.open_ticket("PutObject", "s3")
        assert isinstance(first, DiagnosticTicket)
        assert first.ticket_id != second.ticket_id


class TestEndpointDiagnostics(unittest.TestCase):
    def _endpoint(self, recorder, retry_on_first_exception=True):
        factory_patch = mock.patch("botocore.parsers.ResponseParserFactory")
        factory = factory_patch.start()
        parser = mock.Mock()
        parser.parse.return_value = {"ResponseMetadata": {}}
        factory.return_value.create_parser.return_value = parser
        self.addCleanup(factory_patch.stop)

        event_emitter = mock.Mock()
        needs_retry_calls = {"count": 0}

        def emit(event_name, **kwargs):
            if event_name.startswith("needs-retry"):
                needs_retry_calls["count"] += 1
                if (
                    retry_on_first_exception
                    and needs_retry_calls["count"] == 1
                    and kwargs.get("caught_exception") is not None
                ):
                    return [(None, 0)]
            return []

        event_emitter.emit.side_effect = emit
        endpoint = Endpoint(
            "https://s3.us-west-2.amazonaws.com/",
            endpoint_prefix="s3",
            event_emitter=event_emitter,
            diagnostic_recorder=recorder,
        )
        return endpoint

    def _signed_request_dict(self):
        return request_dict(
            url="https://s3.us-west-2.amazonaws.com/bucket/key",
            headers={
                "Authorization": f"AWS4-HMAC-SHA256 {SECRET_HEADER}",
                "X-Amz-Security-Token": SECRET_HEADER,
                "Content-Type": "application/json",
            },
            body=SECRET_BODY.encode("utf-8"),
            context={"client_config": mock.Mock(read_timeout=60)},
        )

    def test_timeout_then_retry_success_records_full_ticket(self):
        sink = InMemoryDiagnosticSink()
        recorder = DiagnosticRecorder(sink=sink)
        endpoint = self._endpoint(recorder)
        http_session = mock.Mock()
        http_session.send.side_effect = [
            URLLib3ReadTimeoutError(None, None, None),
            mock.Mock(status_code=200, headers={}, content=b"{}"),
        ]
        endpoint.http_session = http_session

        response = endpoint.make_request(
            make_operation(), self._signed_request_dict()
        )
        assert response[1] == {"ResponseMetadata": {"RetryAttempts": 1}}
        assert http_session.send.call_count == 2

        ticket_ids = {
            record["ticket_id"]
            for record in sink.records
            if "ticket_id" in record
        }
        assert len(ticket_ids) == 1
        events = [record["event"] for record in sink.records]
        assert events == [
            TICKET_OPENED,
            REQUEST_PREPARED,
            REQUEST_FAILED,
            REQUEST_PREPARED,
            REQUEST_SENT,
            RESPONSE_RECEIVED,
            TICKET_CLOSED,
        ]

        failure = sink.records[events.index(REQUEST_FAILED)]
        assert failure["attempt"] == 1
        assert failure["error_type"] == "ReadTimeoutError"

        first_prepared = sink.records[events.index(REQUEST_PREPARED)]
        assert first_prepared["attempt"] == 1
        assert (
            first_prepared["request"]["headers"]["Authorization"] == REDACTED
        )
        assert (
            first_prepared["request"]["headers"]["X-Amz-Security-Token"]
            == REDACTED
        )
        assert first_prepared["request"]["body"]["length"] == len(
            SECRET_BODY.encode("utf-8")
        )

        sent_events = [
            record
            for record in sink.records
            if record["event"] == REQUEST_SENT
        ]
        assert [record["attempt"] for record in sent_events] == [2]
        assert all(
            record["dispatch_source"] == "http_session"
            for record in sent_events
        )

        response_record = sink.records[events.index(RESPONSE_RECEIVED)]
        assert response_record["status_code"] == 200

        closed = sink.records[events.index(TICKET_CLOSED)]
        assert closed["outcome"] == "succeeded"
        assert closed["attempts"] == 2
        assert closed["preparations"] == 2
        assert closed["dispatches"] == 1
        assert closed["evidence_gaps"] == 0

        serialized = json.dumps(sink.records)
        assert SECRET_HEADER not in serialized
        assert SECRET_BODY not in serialized
        assert not any(
            isinstance(record, AWSPreparedRequest) for record in sink.records
        )

    def test_recorder_outage_does_not_stop_business_and_marks_gap(self):
        sink = InMemoryDiagnosticSink(fail_times=1)
        recorder = DiagnosticRecorder(sink=sink)
        endpoint = self._endpoint(recorder)
        http_session = mock.Mock()
        http_session.send.side_effect = [
            URLLib3ReadTimeoutError(None, None, None),
            mock.Mock(status_code=200, headers={}, content=b"{}"),
        ]
        endpoint.http_session = http_session

        response = endpoint.make_request(
            make_operation(), self._signed_request_dict()
        )
        assert response[1] == {"ResponseMetadata": {"RetryAttempts": 1}}

        gap_records = [
            record
            for record in sink.records
            if record["event"] == EVIDENCE_GAP
        ]
        assert len(gap_records) == 1
        assert gap_records[0]["reason"] == "OSError"
        closed = [
            record
            for record in sink.records
            if record["event"] == TICKET_CLOSED
        ][0]
        assert closed["evidence_gaps"] == 1
        assert closed["dropped_records"] == 1
        assert closed["preparations"] == 2

    def test_no_http_response_still_leaves_local_facts(self):
        sink = InMemoryDiagnosticSink()
        recorder = DiagnosticRecorder(sink=sink)
        endpoint = self._endpoint(recorder, retry_on_first_exception=False)
        http_session = mock.Mock()
        http_session.send.side_effect = URLLib3ReadTimeoutError(
            None, None, None
        )
        endpoint.http_session = http_session

        with pytest.raises(URLLib3ReadTimeoutError):
            endpoint.make_request(
                make_operation(), self._signed_request_dict()
            )

        events = [record["event"] for record in sink.records]
        assert events == [
            TICKET_OPENED,
            REQUEST_PREPARED,
            REQUEST_FAILED,
            TICKET_CLOSED,
        ]
        failure = sink.records[events.index(REQUEST_FAILED)]
        assert failure["error_type"] == "ReadTimeoutError"
        closed = sink.records[events.index(TICKET_CLOSED)]
        assert closed["outcome"] == "failed"
        assert closed["attempts"] == 1

    def test_default_endpoint_without_sink_records_nothing(self):
        endpoint = self._endpoint(DiagnosticRecorder())
        endpoint.http_session = mock.Mock()
        endpoint.http_session.send.return_value = mock.Mock(
            status_code=200, headers={}, content=b"{}"
        )
        endpoint.make_request(make_operation(), self._signed_request_dict())

    def test_sink_implementation_contract(self):
        class BrokenSink(BaseDiagnosticSink):
            pass

        with pytest.raises(NotImplementedError):
            BrokenSink().write({})
