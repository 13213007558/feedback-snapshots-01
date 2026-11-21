import io
import threading
import time

import pytest

import sentry_sdk
from sentry_sdk import Client
from sentry_sdk.envelope import Envelope, parse_json
from sentry_sdk.transport import HttpTransport


class _FakeResponse:
    def __init__(self, status, headers=None):
        self.status = status
        # real HTTP header lookups are case-insensitive
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.data = b""

    def close(self):
        pass


class InMemoryTransport(HttpTransport):
    """An HttpTransport with a scriptable, fully in-memory request layer.

    `script` holds one outcome per HTTP attempt: an Exception instance to
    raise, a status code to respond with, or a (status, headers) tuple.
    Once the script is exhausted, requests respond 200. Failed requests are
    retried inside `_request` (like the real HTTP layers do), so the SDK
    only observes the final outcome of each envelope send.
    """

    def __init__(self, options=None):
        super().__init__(options)
        self.script = []
        self.attempts = 0
        self.sent_bodies = []
        self.block = None
        self.request_started = threading.Event()

    def _request(self, method, endpoint_type, body, headers):
        if self.block is not None:
            self.request_started.set()
            self.block.wait(timeout=10)

        self.sent_bodies.append(bytes(body))

        last_error = None
        for _ in range(3):
            self.attempts += 1
            outcome = self.script.pop(0) if self.script else 200
            if isinstance(outcome, Exception):
                last_error = outcome
                continue
            if isinstance(outcome, tuple):
                status, response_headers = outcome
            else:
                status, response_headers = outcome, {}
            return _FakeResponse(status, headers=response_headers)
        raise last_error


def make_client(script=(), **kwargs):
    kwargs.setdefault("_experiments", {"transport_compression_level": 0})
    kwargs.setdefault("auto_session_tracking", False)
    client = Client(
        "http://foo@localhost/123", transport=InMemoryTransport, **kwargs
    )
    client.transport.script.extend(script)
    return client


def sent_client_report(transport):
    (report_body,) = [
        body for body in transport.sent_bodies if b'"type":"client_report"' in body
    ]
    envelope = Envelope.deserialize_from(io.BytesIO(report_body))
    (item,) = envelope.items
    assert item.type == "client_report"
    return parse_json(item.get_bytes())


@pytest.mark.tests_internal_exceptions
def test_network_failure_counted_once_per_envelope():
    client = make_client(script=[ConnectionError("boom")] * 3)

    client.capture_event({"message": "sensitive details"})
    client.flush()

    # 3 retried attempts on the failing envelope, then 1 attempt sending
    # the client report itself
    assert client.transport.attempts == 4

    # the lost envelope is counted exactly once, not once per attempt
    report = sent_client_report(client.transport)
    assert report["discarded_events"] == [
        {"reason": "network_error", "category": "error", "quantity": 1}
    ]

    # the report only carries aggregates: no event payload, no exception text
    assert set(report) == {"timestamp", "discarded_events"}
    for entry in report["discarded_events"]:
        assert set(entry) == {"reason", "category", "quantity"}
    (report_body,) = [
        body
        for body in client.transport.sent_bodies
        if b'"type":"client_report"' in body
    ]
    assert b"sensitive details" not in report_body
    assert b"boom" not in report_body

    # the counters were reset when the report went out: no double reporting
    assert client.transport._discarded_events == {}


@pytest.mark.tests_internal_exceptions
def test_retry_success_not_counted():
    client = make_client(script=[ConnectionError(), ConnectionError(), 200])

    client.capture_event({"message": "retried"})
    client.flush()

    assert client.transport.attempts == 3
    assert client.transport._discarded_events == {}
    (event_body,) = client.transport.sent_bodies
    assert b'"type":"client_report"' not in event_body


def test_local_policy_drops():
    client = make_client(before_send=lambda event, hint: None)
    client.capture_event({"message": "dropped by user callback"})
    client.flush()
    # the event never hit the wire, only the report did
    (report_body,) = client.transport.sent_bodies
    assert b'"type":"client_report"' in report_body
    assert sent_client_report(client.transport)["discarded_events"] == [
        {"reason": "before_send", "category": "error", "quantity": 1}
    ]

    client = make_client(sample_rate=0.0)
    client.capture_event({"message": "out of sample"})
    client.flush()
    assert sent_client_report(client.transport)["discarded_events"] == [
        {"reason": "sample_rate", "category": "error", "quantity": 1}
    ]

    client = make_client()
    old_processors = sentry_sdk.scope.global_event_processors
    sentry_sdk.scope.global_event_processors = old_processors.copy()
    try:
        @sentry_sdk.scope.add_global_event_processor
        def drop(event, hint):
            return None

        client.capture_event(
            {"message": "dropped by processor"}, scope=sentry_sdk.Scope()
        )
        client.flush()
        assert sent_client_report(client.transport)["discarded_events"] == [
            {"reason": "event_processor", "category": "error", "quantity": 1}
        ]
    finally:
        sentry_sdk.scope.global_event_processors = old_processors


def test_429_not_double_counted_and_backoff():
    # Relay already records an outcome for a 429, so the SDK must not count it
    client = make_client(script=[429])
    client.capture_event({"message": "rate limited"})
    client.flush()
    assert client.transport._discarded_events == {}
    (event_body,) = client.transport.sent_bodies
    assert b'"type":"client_report"' not in event_body

    # a category-specific rate limit drops error events locally, while the
    # client report itself (category "internal") is still allowed out
    client = make_client(
        script=[(200, {"X-Sentry-Rate-Limits": "4711:error:organization"})]
    )
    client.capture_event({"message": "installs backoff"})
    client.flush()
    client.capture_event({"message": "dropped by local backoff"})
    client.flush()
    assert sent_client_report(client.transport)["discarded_events"] == [
        {"reason": "ratelimit_backoff", "category": "error", "quantity": 1}
    ]


def test_queue_overflow():
    client = make_client(transport_queue_size=1)
    transport = client.transport
    transport.block = threading.Event()

    client.capture_event({"message": "occupies worker"})
    assert transport.request_started.wait(timeout=5)

    client.capture_event({"message": "queued"})
    client.capture_event({"message": "overflow"})

    # counted synchronously on the caller thread, before any send happens
    assert transport._discarded_events == {("error", "queue_overflow"): 1}

    transport.block.set()

    # wait until both queued envelopes are sent, otherwise the still-full
    # queue could swallow the flush task itself
    deadline = time.time() + 5
    while len(transport.sent_bodies) < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert len(transport.sent_bodies) == 2

    client.flush()

    assert sent_client_report(transport)["discarded_events"] == [
        {"reason": "queue_overflow", "category": "error", "quantity": 1}
    ]
    # the counters were reset when the report went out: no double reporting
    assert transport._discarded_events == {}
