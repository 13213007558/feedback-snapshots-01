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
"""Restricted diagnostic records for on-call incident investigations.

The records produced by this module intentionally never hold an
``AWSPreparedRequest`` (or any equivalent object).  Signed requests carry
credentials in their headers and query strings, so only a fixed set of
non-sensitive facts is extracted: the HTTP method, sanitized URL and
headers, and a description of the body.  Credential-bearing values are
replaced in place by a redaction marker.

Each API operation gets its own :class:`DiagnosticTicket`.  When the
configured destination cannot be written to, the ticket records an explicit
evidence gap and the business request continues normally.  Gaps and the
events that follow a recovery are always contained within the ticket that
experienced them; records are never carried over to another operation.
"""

import json
import logging
import threading
import uuid
from datetime import datetime, timezone

from botocore.compat import parse_qsl, urlsplit, urlunsplit
from botocore.utils import determine_content_length

logger = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

# Header names whose values authenticate the request.
SENSITIVE_HEADER_NAMES = frozenset(
    [
        "authorization",
        "proxy-authorization",
        "x-amz-security-token",
        "x-amz-credential",
        "x-amz-signature",
        "x-amz-signedheaders",
        "x-amz-date",
        "x-amz-content-sha256",
    ]
)

# Query parameters used by presigned URLs and signature material.
SENSITIVE_QUERY_PARAMS = frozenset(
    [
        "x-amz-security-token",
        "x-amz-credential",
        "x-amz-signature",
        "x-amz-date",
        "x-amz-signedheaders",
        "x-amz-expires",
        "x-amz-algorithm",
    ]
)

# Event types written by a ticket.
TICKET_OPENED = "TICKET_OPENED"
REQUEST_PREPARED = "REQUEST_PREPARED"
REQUEST_SENT = "REQUEST_SENT"
RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
REQUEST_FAILED = "REQUEST_FAILED"
TICKET_CLOSED = "TICKET_CLOSED"
EVIDENCE_GAP = "EVIDENCE_GAP"

GLOBAL_DIAGNOSTIC_RECORDER = None


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _to_text(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return REDACTED
    return str(value)


def sanitize_headers(headers):
    """Return header facts with credential-bearing values redacted."""
    sanitized = {}
    for name, value in headers.items():
        text_name = _to_text(name)
        if text_name.lower() in SENSITIVE_HEADER_NAMES:
            sanitized[text_name] = REDACTED
        else:
            sanitized[text_name] = _to_text(value)
    return sanitized


def sanitize_url(url):
    """Return a URL whose signature query parameters are redacted."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    safe_pairs = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in SENSITIVE_QUERY_PARAMS:
            safe_pairs.append((name, REDACTED))
        else:
            safe_pairs.append((name, value))
    safe_query = "&".join(f"{name}={value}" for name, value in safe_pairs)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, safe_query, parts.fragment)
    )


def build_body_facts(body):
    """Describe a request body without retaining any of its bytes."""
    body_type = type(body).__name__
    if body is None:
        return {"present": False, "type": "NoneType", "length": 0}
    length = determine_content_length(body)
    return {
        "present": True,
        "type": body_type,
        "length": length,
        "length_known": length is not None,
    }


def build_request_facts(prepared_request):
    """Extract the safe, serializable facts of a prepared request."""
    return {
        "method": prepared_request.method,
        "url": sanitize_url(prepared_request.url),
        "headers": sanitize_headers(prepared_request.headers),
        "body": build_body_facts(prepared_request.body),
    }


def sanitize_error_message(message):
    """Redact signature material that can appear in transport errors."""
    text = _to_text(message)
    for param in SENSITIVE_QUERY_PARAMS:
        marker = f"{param}="
        lowered = text.lower()
        start = lowered.find(marker)
        while start != -1:
            end = start + len(marker)
            while end < len(text) and text[end] not in "&? ":
                end += 1
            text = text[:start] + marker + REDACTED + text[end:]
            lowered = text.lower()
            start = lowered.find(marker, start + len(marker))
    return text


class BaseDiagnosticSink:
    """Destination that receives already-sanitized diagnostic records."""

    def write(self, record):
        raise NotImplementedError("write()")


class InMemoryDiagnosticSink(BaseDiagnosticSink):
    """Keep every record in memory.

    ``fail_times`` makes the sink raise on the first ``fail_times`` writes
    so tests can exercise a temporarily unwritable destination.
    """

    def __init__(
        self, fail_times=0, exc=OSError("diagnostic sink unavailable")
    ):
        self.records = []
        self._fail_times = fail_times
        self._exc = exc
        self.write_failures = 0
        self._lock = threading.Lock()

    def write(self, record):
        with self._lock:
            if self._fail_times > 0:
                self._fail_times -= 1
                self.write_failures += 1
                raise self._exc
            self.records.append(record)

    def records_for_ticket(self, ticket_id):
        return [
            record
            for record in self.records
            if record.get("ticket_id") == ticket_id
        ]


class FileDiagnosticSink(BaseDiagnosticSink):
    """Append one JSON record per line to a file.

    A failed append (for example an unwritable directory or a full disk)
    propagates to the recorder, which records an evidence gap instead of
    affecting the business request.
    """

    def __init__(self, path):
        self.path = path

    def write(self, record):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str))
            handle.write("\n")


class DiagnosticTicket:
    """The diagnostic history of a single API operation invocation."""

    def __init__(
        self,
        ticket_id,
        operation_name,
        service_id,
        sink,
        clock=_utc_now,
    ):
        self.ticket_id = ticket_id
        self.operation_name = operation_name
        self.service_id = service_id
        self._sink = sink
        self._clock = clock
        self._lock = threading.Lock()
        self.preparations = 0
        self.dispatches = 0
        self.gap_count = 0
        self.dropped_records = 0
        self._pending_gaps = []
        self._open = True
        self._emit(
            TICKET_OPENED,
            {
                "operation": operation_name,
                "service": service_id,
            },
        )

    def _make_record(self, event_type, payload):
        record = {
            "ticket_id": self.ticket_id,
            "event": event_type,
            "timestamp": self._clock(),
            "operation": self.operation_name,
            "service": self.service_id,
        }
        record.update(payload)
        return record

    def _emit(self, event_type, payload):
        record = self._make_record(event_type, payload)
        with self._lock:
            try:
                # Flush any gap markers accumulated while the destination
                # was unwritable before writing the new fact.
                while self._pending_gaps:
                    self._sink.write(self._pending_gaps[0])
                    del self._pending_gaps[0]
                self._sink.write(record)
            except Exception as error:
                logger.debug(
                    "Diagnostic sink could not accept %s for ticket %s.",
                    event_type,
                    self.ticket_id,
                    exc_info=True,
                )
                self.gap_count += 1
                self.dropped_records += 1
                # Keep only the earliest outstanding gap so a prolonged
                # outage cannot grow memory without bound; it names the first
                # event that has no durable evidence.
                if not self._pending_gaps:
                    self._pending_gaps.append(
                        self._make_record(
                            EVIDENCE_GAP,
                            {
                                "reason": type(error).__name__,
                                "detail": sanitize_error_message(str(error)),
                                "missed_event": event_type,
                            },
                        )
                    )

    def record_preparation(self, prepared_request, attempt):
        """Record that a request was prepared (once per signing attempt)."""
        with self._lock:
            self.preparations += 1
        self._emit(
            REQUEST_PREPARED,
            {
                "attempt": attempt,
                "request": build_request_facts(prepared_request),
            },
        )

    def record_dispatch(self, attempt, dispatch_source):
        """Record that the prepared request was actually handed off."""
        with self._lock:
            self.dispatches += 1
        self._emit(
            REQUEST_SENT,
            {
                "attempt": attempt,
                "dispatch_source": dispatch_source,
            },
        )

    def record_response(self, attempt, http_response):
        self._emit(
            RESPONSE_RECEIVED,
            {
                "attempt": attempt,
                "status_code": http_response.status_code,
                "headers": sanitize_headers(http_response.headers),
            },
        )

    def record_failure(self, attempt, exception):
        self._emit(
            REQUEST_FAILED,
            {
                "attempt": attempt,
                "error_type": type(exception).__name__,
                "error": sanitize_error_message(str(exception)),
            },
        )

    def close(self, outcome, attempts):
        if not self._open:
            return
        self._open = False
        self._emit(
            TICKET_CLOSED,
            {
                "outcome": outcome,
                "attempts": attempts,
                "preparations": self.preparations,
                "dispatches": self.dispatches,
                "evidence_gaps": self.gap_count,
                "dropped_records": self.dropped_records,
            },
        )


class NullDiagnosticTicket:
    """No-op ticket used when no diagnostic sink is configured."""

    def record_preparation(self, prepared_request, attempt):
        pass

    def record_dispatch(self, attempt, dispatch_source):
        pass

    def record_response(self, attempt, http_response):
        pass

    def record_failure(self, attempt, exception):
        pass

    def close(self, outcome, attempts):
        pass


class DiagnosticRecorder:
    """Opens per-operation tickets and routes records to a sink."""

    def __init__(self, sink=None, clock=_utc_now):
        self._sink = sink
        self._clock = clock

    def open_ticket(self, operation_name, service_id=None):
        if self._sink is None:
            return NullDiagnosticTicket()
        ticket_id = str(uuid.uuid4())
        return DiagnosticTicket(
            ticket_id=ticket_id,
            operation_name=operation_name,
            service_id=service_id,
            sink=self._sink,
            clock=self._clock,
        )


def get_global_diagnostic_recorder():
    global GLOBAL_DIAGNOSTIC_RECORDER
    if GLOBAL_DIAGNOSTIC_RECORDER is None:
        GLOBAL_DIAGNOSTIC_RECORDER = DiagnosticRecorder()
    return GLOBAL_DIAGNOSTIC_RECORDER
