from collections import defaultdict

import pytest

import sentry_sdk
from sentry_sdk.consts import DIAGNOSTIC_ITEM_HEADER
from sentry_sdk.envelope import Envelope, Item, PayloadRef
from sentry_sdk.transport import HttpTransport
from sentry_sdk.worker import AsyncWorker, BackgroundWorker


def _make_transport(queue_size=100):
    transport = HttpTransport(
        defaultdict(
            lambda: None,
            {
                "dsn": "https://123abc@example.com/123",
                "transport_queue_size": queue_size,
                "send_client_reports": True,
            },
        )
    )
    return transport


def _envelope(*, diagnostic=False, item_type="attachment"):
    item = Item(payload=PayloadRef(json={"detail": "sensitive"}), type=item_type)
    if diagnostic:
        item.mark_diagnostic()
    return Envelope(items=[item])


def _mixed_envelope():
    permitted = Item(payload=PayloadRef(json={"message": "boom"}), type="event")
    diagnostic = Item(
        payload=PayloadRef(json={"detail": "sensitive"}), type="attachment"
    ).mark_diagnostic()
    return Envelope(items=[permitted, diagnostic])


class _PausedWorker(BackgroundWorker):
    """A worker whose consumer thread never runs, so jobs stay queued."""

    def start(self):
        # Deliberately do not start the background thread.
        self._thread = None
        self._thread_for_pid = None

    def _ensure_thread(self):
        pass

    def resume(self):
        """Run every queued job synchronously, simulating a resumed worker."""
        while True:
            try:
                callback = self._queue.get_nowait()
            except Exception:
                break
            try:
                callback()
            finally:
                self._queue.task_done()


@pytest.fixture
def paused_transport(monkeypatch):
    transport = _make_transport()
    sent = []
    monkeypatch.setattr(transport, "_create_worker", lambda options: _PausedWorker(100))
    monkeypatch.setattr(
        transport, "_send_envelope", lambda envelope: sent.append(envelope)
    )
    transport._worker = transport._create_worker(transport.options)
    transport.sent = sent
    return transport


def test_disabling_purges_queued_diagnostics_but_keeps_permitted(paused_transport):
    transport = paused_transport

    transport.capture_envelope(_envelope(diagnostic=True))
    transport.capture_envelope(_envelope(diagnostic=False, item_type="event"))
    assert transport._worker._queue.qsize() == 2

    changes = []
    transport.set_on_diagnostic_state_change(changes.append)

    transport.set_detailed_diagnostics_enabled(False)

    assert transport._worker._queue.qsize() == 1
    assert changes == [False]

    transport._worker.resume()
    assert len(transport.sent) == 1
    (sent_envelope,) = transport.sent
    assert sent_envelope.items[0].type == "event"
    assert not sent_envelope.items[0].is_diagnostic


def test_new_diagnostic_event_dropped_while_disabled(paused_transport):
    transport = paused_transport
    transport.set_detailed_diagnostics_enabled(False)

    transport.capture_envelope(_envelope(diagnostic=True))
    assert transport._worker._queue.qsize() == 0
    assert transport.sent == []


def test_mixed_envelope_splits_by_authorization(paused_transport):
    transport = paused_transport
    transport.set_detailed_diagnostics_enabled(False)

    transport.capture_envelope(_mixed_envelope())

    transport._worker.resume()
    assert len(transport.sent) == 1
    (sent_envelope,) = transport.sent
    assert [item.type for item in sent_envelope.items] == ["event"]


def test_purged_entries_do_not_reappear_on_reenable(paused_transport):
    transport = paused_transport

    transport.capture_envelope(_envelope(diagnostic=True))
    transport.capture_envelope(_envelope(diagnostic=True))
    assert transport._worker._queue.qsize() == 2

    transport.set_detailed_diagnostics_enabled(False)
    assert transport._worker._queue.qsize() == 0

    transport.set_detailed_diagnostics_enabled(True)
    transport._worker.resume()

    assert transport.sent == []

    # Newly captured diagnostic data flows again once re-enabled.
    transport.capture_envelope(_envelope(diagnostic=True))
    transport._worker.resume()
    assert len(transport.sent) == 1


def test_error_counts_and_client_reports_retained(monkeypatch):
    transport = _make_transport()
    monkeypatch.setattr(transport, "_worker", BackgroundWorker(100))
    monkeypatch.setattr(
        transport._worker, "submit", lambda callback: callback() or True
    )
    sent = []
    monkeypatch.setattr(
        transport, "_send_envelope", lambda envelope: sent.append(envelope)
    )

    transport.set_detailed_diagnostics_enabled(False)
    transport.capture_envelope(_envelope(diagnostic=True))
    transport.capture_envelope(_envelope(diagnostic=False, item_type="event"))

    assert len(sent) == 1
    assert sent[0].items[0].type == "event"

    # The dropped diagnostic item is accounted for in client reports.
    report = transport._fetch_pending_client_report(force=True, interval=0)
    assert report is not None
    discarded = report.payload.json["discarded_events"]
    assert ("attachment", "ratelimit_backoff") in {
        (entry["category"], entry["reason"]) for entry in discarded
    }


def test_diagnostic_marker_is_not_serialized():
    envelope = _envelope(diagnostic=True)
    assert envelope.items[0].is_diagnostic
    serialized = envelope.serialize().decode("utf-8")
    assert DIAGNOSTIC_ITEM_HEADER not in serialized


def test_public_api_delegates_to_transport(monkeypatch):
    transport = _make_transport()
    client = sentry_sdk.Client(
        dsn="https://123abc@example.com/123", transport=transport
    )
    monkeypatch.setattr(
        sentry_sdk.scope.Scope, "get_client", classmethod(lambda cls: client)
    )

    changes = []
    sentry_sdk.set_on_diagnostic_state_change(changes.append)
    sentry_sdk.set_detailed_diagnostics_enabled(False)

    assert transport.detailed_diagnostics_enabled is False
    assert changes == [False]


@pytest.mark.asyncio
async def test_async_worker_drain_filter_removes_only_selected():
    worker = AsyncWorker(queue_size=100)
    worker.start()

    ran = []
    for index in range(4):
        worker.submit(lambda index=index: ran.append(index))

    drained = worker.drain_filter(lambda callback: True)
    assert drained == 4
    assert worker._queue is not None
    assert worker._queue.qsize() == 0

    # join() must not hang: removed items were accounted for via task_done.
    await worker._queue.join()

    worker.kill()
