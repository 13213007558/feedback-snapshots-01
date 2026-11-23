"""One-shot expiry for Sentry attachments.

These tests pin the contract that an attachment's deadline is computed once,
when the attachment is created, and is then immutable. Queueing the envelope,
retrying a failed send and re-batching all measure against that same deadline;
an event that crosses the deadline while sitting in the queue cannot regain the
attachment. Expiry is decided from timestamps only (the backing file is never
opened to decide), and an expired attachment releases its resources and is
never opened or sent again, while the still-allowed event and any non-expired
attachments keep going.
"""

import builtins
import threading

import pytest

import sentry_sdk
from sentry_sdk.attachments import Attachment
from sentry_sdk.envelope import Envelope
from sentry_sdk.transport import BaseHttpTransport
from sentry_sdk.worker import BackgroundWorker


class FakeClock:
    """Deterministic, thread-safe stand-in for the monotonic clock."""

    def __init__(self, start=100.0):
        self._value = float(start)
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            return self._value

    def advance(self, seconds):
        with self._lock:
            self._value += float(seconds)
        return self._value

    @property
    def value(self):
        with self._lock:
            return self._value


class FirstSendGate:
    """Blocks the very first send attempt until released, mimicking a hung
    network call, then lets every later attempt through."""

    def __init__(self):
        self._engaged = threading.Event()
        self._released = threading.Event()

    def maybe_block(self):
        if not self._engaged.is_set():
            self._engaged.set()
            # Wait until the test advances the clock and releases us.
            self._released.wait()

    def release(self):
        self._released.set()

    def wait_engaged(self, timeout=5):
        return self._engaged.wait(timeout)


def make_in_memory_transport_cls(clock, gate, evidence):
    """Build an HttpTransportCore subclass that never touches the network.

    It keeps the real prepare/serialize/prune machinery (so expiry is exercised
    end to end) but swaps the worker, pool and HTTP request for in-memory
    equivalents and records evidence about every send attempt.
    """

    class InMemoryTransport(BaseHttpTransport):
        def _create_worker(self, options):
            return BackgroundWorker(queue_size=options["transport_queue_size"])

        def _make_pool(self):
            return None

        def _get_pool_options(self):
            return {}

        def _request(self, method, endpoint_type, body, headers):  # pragma: no cover
            raise AssertionError("in-memory transport must not perform HTTP")

        def _send_request(self, body, headers, endpoint_type, envelope=None):
            gate.maybe_block()
            record = {
                "at": clock(),
                "item_types": [item.type for item in envelope.items],
                "filenames": [
                    item.headers.get("filename")
                    for item in envelope.items
                    if item.type == "attachment"
                ],
            }
            evidence["sent"].append(record)
            evidence["envelopes"].append(envelope)

        def record_lost_event(self, reason, data_category=None, item=None,
                              *, quantity=1):
            evidence["lost"].append(
                {
                    "at": clock(),
                    "reason": reason,
                    "category": (
                        item.data_category if item is not None else data_category
                    ),
                    "filename": (
                        item.headers.get("filename")
                        if item is not None
                        else None
                    ),
                    "quantity": quantity,
                }
            )

    return InMemoryTransport


@pytest.fixture
def fake_clock(monkeypatch):
    clock = FakeClock()
    # Both modules read the clock through this single function.
    monkeypatch.setattr("sentry_sdk.envelope._now", clock)
    monkeypatch.setattr("sentry_sdk.attachments._now", clock)
    return clock


def _attachments_by_filename(envelope):
    return {
        item.headers.get("filename"): item
        for item in envelope.items
        if item.type == "attachment"
    }


def test_short_lived_attachment_expires_across_a_hung_first_send(
    sentry_init, fake_clock, monkeypatch, tmp_path
):
    # Two short-lived local files. The short attachment outlives neither the
    # clock jump below; the long one does.
    short_path = tmp_path / "short.log"
    short_path.write_bytes(b"short-lived crash dump")
    long_path = tmp_path / "long.log"
    long_path.write_bytes(b"still-allowed context")

    open_counts = {str(short_path): 0, str(long_path): 0}
    evidence = {
        "sent": [],
        "envelopes": [],
        "lost": [],
        "open_times": {},
        "timeline": [],
    }
    real_open = builtins.open

    def tracking_open(file, *args, **kwargs):
        name = file if isinstance(file, str) else getattr(file, "name", None)
        if name in open_counts:
            open_counts[name] += 1
            evidence["open_times"].setdefault(name, []).append(fake_clock())
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracking_open)

    gate = FirstSendGate()

    transport_cls = make_in_memory_transport_cls(fake_clock, gate, evidence)
    sentry_init(
        dsn="http://foo@sentry.io/123",
        transport=transport_cls,
        send_client_reports=False,
    )

    scope = sentry_sdk.get_isolation_scope()
    scope.add_attachment(path=str(short_path), ttl=5.0)
    scope.add_attachment(path=str(long_path), ttl=1000.0)

    created_deadline_short = scope._attachments[0].expires_at
    created_deadline_long = scope._attachments[1].expires_at
    assert created_deadline_short == fake_clock.value + 5.0
    assert created_deadline_long == fake_clock.value + 1000.0

    # First event: queued while both attachments are still valid. Its send
    # attempt hangs on the gate before anything is delivered.
    evidence["timeline"].append(("capture_event_1", fake_clock()))
    sentry_sdk.capture_message("event one")
    assert gate.wait_engaged(), "first send attempt never started"
    evidence["timeline"].append(("first_send_blocked", fake_clock()))

    # Network recovers after a delay long enough to expire the short
    # attachment but not the long one.
    fake_clock.advance(50.0)
    evidence["timeline"].append(("clock_advanced", fake_clock()))
    gate.release()

    # Second event is captured *after* the deadline has already passed.
    evidence["timeline"].append(("capture_event_2", fake_clock()))
    sentry_sdk.capture_message("event two")

    sentry_sdk.get_client().flush(timeout=5)

    # --- Evidence: both core events still arrive ---------------------------
    delivered_messages = [
        envelope.get_event()["message"]
        for envelope in evidence["envelopes"]
        if envelope.get_event() is not None
    ]
    assert delivered_messages == ["event one", "event two"]

    # Two send attempts (one per captured event) actually went out.
    assert len(evidence["envelopes"]) == 2
    first_envelope, second_envelope = evidence["envelopes"]

    # First envelope was prepared before the jump: both attachments allowed.
    first_files = _attachments_by_filename(first_envelope)
    assert set(first_files) == {"short.log", "long.log"}

    # Second envelope crossed the deadline in the queue: short dropped, long sent.
    second_files = _attachments_by_filename(second_envelope)
    assert set(second_files) == {"long.log"}

    # --- Evidence: the expired file is opened exactly once and never resent -
    assert open_counts[str(short_path)] == 1
    assert open_counts[str(long_path)] == 2

    # Time-point evidence: the short file was only read while still valid
    # (clock == 100, before the jump to 150); the long one is read on both
    # sends because its deadline (1100) still lies in the future.
    assert evidence["open_times"][str(short_path)] == [100.0]
    assert evidence["open_times"][str(long_path)] == [100.0, 150.0]

    # The short attachment was recorded as an expiry loss, not a network loss.
    short_losses = [
        loss for loss in evidence["lost"] if loss["filename"] == "short.log"
    ]
    assert len(short_losses) == 1
    assert short_losses[0]["reason"] == "expired_attachment"
    assert short_losses[0]["category"] == "attachment"

    # --- Evidence: released resources cannot be re-opened on a retry --------
    # A payload marked released after expiry returns empty bytes without ever
    # touching its backing file, even if something retries the item.
    rebuilt = Attachment(path=str(short_path), ttl=5.0).to_envelope_item()
    rebuilt.payload.expires_at = created_deadline_short
    rebuilt.payload._released = True
    assert rebuilt.is_expired(now=fake_clock())
    assert rebuilt.get_bytes() == b""
    assert open_counts[str(short_path)] == 1  # still no extra open

    # --- Evidence: the deadline never moved --------------------------------
    assert scope._attachments[0].expires_at == created_deadline_short
    assert scope._attachments[1].expires_at == created_deadline_long


def test_deadline_is_computed_once_and_survives_rebatching(fake_clock):
    attachment = Attachment(
        bytes=b"in-memory body", filename="mem.bin", ttl=10.0
    )
    first_deadline = attachment.expires_at
    assert first_deadline == fake_clock() + 10.0

    # Producing items repeatedly (queue -> retry -> re-batch) always inherits
    # the same absolute deadline; advancing the clock does not extend it.
    item_one = attachment.to_envelope_item()
    fake_clock.advance(100.0)
    item_two = attachment.to_envelope_item()

    assert item_one.payload.expires_at == first_deadline
    assert item_two.payload.expires_at == first_deadline
    assert item_one.is_expired() and item_two.is_expired()


def test_attachment_without_ttl_never_expires(fake_clock):
    item = Attachment(bytes=b"keep me", filename="keep.bin").to_envelope_item()
    assert item.payload.expires_at is None
    fake_clock.advance(10_000.0)
    assert not item.is_expired()


def test_expired_in_memory_payload_releases_bytes_without_file_io(
    fake_clock, monkeypatch, tmp_path
):
    path = tmp_path / "lazy.bin"
    path.write_bytes(b"on-disk body")

    item = Attachment(path=str(path), ttl=1.0).to_envelope_item()
    payload = item.payload

    # Expiry is a pure timestamp comparison: no file read happens here.
    fake_clock.advance(2.0)
    assert item.is_expired()
    assert payload.bytes is None  # never eagerly loaded

    def boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("released payload must not open its file")

    monkeypatch.setattr(builtins, "open", boom)

    item.release()
    item.release()  # idempotent
    assert item.get_bytes() == b""
    assert payload._released is True


def test_rebatching_does_not_reset_an_expired_attachment(fake_clock):
    attachment = Attachment(bytes=b"x", filename="x.bin", ttl=5.0)
    envelope = Envelope()
    envelope.add_item(attachment.to_envelope_item())

    fake_clock.advance(6.0)

    # Simulate the transport rebuilding the envelope (re-batch) from the same
    # items: the expired item is still expired against the original deadline.
    rebatched = Envelope(headers=envelope.headers, items=list(envelope.items))
    (item,) = list(rebatched)
    assert item.is_expired()
