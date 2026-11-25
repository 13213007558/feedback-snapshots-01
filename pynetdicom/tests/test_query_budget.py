"""Tests for query concurrency budgets and cancellation cleanup.

The scenarios in this module use :class:`threading.Event` as deterministic
local signals instead of real network delays.
"""

from __future__ import annotations

import threading
import time
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import pytest
from pydicom.uid import ImplicitVRLittleEndian

from pynetdicom import build_context
from pynetdicom.dimse_primitives import C_FIND
from pynetdicom.query_budget import (
    QueryBudget,
    QueryBudgetCancelled,
    QueryBudgetExceeded,
    QueryBudgetTimeout,
)
from pynetdicom.service_class import QueryRetrieveServiceClass, evt
from pynetdicom.status import QR_FIND_SERVICE_CLASS_STATUS


def wait_until(predicate, timeout: float = 2.0) -> bool:
    """Wait for a local state change without adding network delay."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.001)
    return predicate()


def start_waiting_lease(
    budget: QueryBudget, association_id: str, query_id: str
) -> tuple[threading.Event, dict[str, Any], threading.Thread]:
    """Start a thread that blocks until a budget lease is available."""
    acquired = threading.Event()
    result: dict[str, Any] = {}

    def worker() -> None:
        try:
            result["lease"] = budget.acquire(
                association_id, query_id, poll_interval=0.001
            )
            acquired.set()
        except BaseException as exc:  # pragma: no cover - failure reporter
            result["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return acquired, result, thread


class RecordingImageDirectoryQuery:
    """A synthetic image-directory query with observable lifecycle events."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.waiting_before_first = threading.Event()
        self.cleanup_finished = threading.Event()
        self.composed: list[str] = []
        self.cleanup_count = 0

    def __call__(
        self,
        first_gate: threading.Event | None = None,
        cancellation: threading.Event | None = None,
    ):
        self.entered.set()
        try:
            if first_gate is not None:
                self.waiting_before_first.set()
                if not first_gate.wait(2):
                    raise RuntimeError("Timed out waiting for first-result gate")

            if cancellation is not None and cancellation.is_set():
                return

            self.composed.append("synthetic-image-1")
            yield ("0xFF00", {"ImageID": "synthetic-image-1"})

            if cancellation is not None and cancellation.is_set():
                return

            self.composed.append("synthetic-image-2")
            yield ("0xFF00", {"ImageID": "synthetic-image-2"})
        finally:
            self.cleanup_count += 1
            self.cleanup_finished.set()


class FakeFindDIMSE:
    def __init__(self) -> None:
        self.cancel_req: dict[int, object] = {}
        self.sent: list[C_FIND] = []
        self.sent_statuses: list[int] = []

    def send_msg(self, rsp: C_FIND, context_id: int) -> None:
        self.sent.append(rsp)
        self.sent_statuses.append(rsp.Status)


class FakeFindAssociation:
    def __init__(self, budget: QueryBudget | None, timeout: float | None = None):
        self.dimse = FakeFindDIMSE()
        self.is_established = True
        self.ae = SimpleNamespace(
            query_budget=budget,
            query_budget_timeout=timeout,
            query_budget_poll_interval=0.001,
        )
        self.acse = SimpleNamespace(
            is_aborted=lambda: False,
            is_release_requested=lambda: False,
        )
        self._abort_nonblocking = lambda: None
        self._abort_blocking = lambda: None


class CloseProbe:
    """Iterator wrapper that records explicit close calls."""

    def __init__(self, inner):
        self.inner = inner
        self.close_count = 0

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.inner)

    def close(self):
        self.close_count += 1
        self.inner.close()


def find_request() -> C_FIND:
    req = C_FIND()
    req.MessageID = 7
    req.MessageIDBeingRespondedTo = None
    req.AffectedSOPClassUID = "1.2.840.10008.5.1.4.1.2.1.1"
    req.Identifier = BytesIO(b"")
    return req


def find_context():
    context = build_context(
        "1.2.840.10008.5.1.4.1.2.1.1", ImplicitVRLittleEndian
    )
    context.context_id = 1
    return context


def test_hierarchical_budget_tracks_association_and_server_capacity():
    budget = QueryBudget(association_limit=1, server_limit=2)

    first_a = budget.try_acquire("assoc-a", "a-1")
    assert budget.available("assoc-a") == {"association": 0, "server": 1}

    with pytest.raises(QueryBudgetExceeded):
        budget.try_acquire("assoc-a", "a-2")

    first_b = budget.try_acquire("assoc-b", "b-1")
    assert budget.available("assoc-a") == {"association": 0, "server": 0}

    with pytest.raises(QueryBudgetExceeded):
        budget.try_acquire("assoc-c", "c-1")

    snapshot = budget.snapshot("assoc-a")
    assert snapshot.association_active == 1
    assert snapshot.server_active == 2

    first_a.release()
    first_b.release()

    assert budget.available("assoc-a") == {"association": 1, "server": 2}
    assert budget.snapshot("assoc-a").server_active == 0


def test_invalid_budget_limits_are_rejected():
    with pytest.raises(ValueError):
        QueryBudget(association_limit=0)
    with pytest.raises(ValueError):
        QueryBudget(server_limit=False)  # type: ignore[arg-type]


def test_closing_association_query_wakes_waiter_for_same_association():
    budget = QueryBudget(association_limit=1, server_limit=2)
    active = budget.acquire("assoc-a", "active")

    acquired, result, thread = start_waiting_lease(
        budget, "assoc-a", "replacement"
    )
    assert wait_until(
        lambda: budget.snapshot("assoc-a").association_waiting == 1
    )

    released = active.release()
    assert released is not None
    assert released.association_available == 1

    assert acquired.wait(2)
    thread.join(2)
    assert not thread.is_alive()
    assert "error" not in result

    result["lease"].release()
    assert budget.available("assoc-a") == {"association": 1, "server": 2}


def test_closing_server_query_wakes_waiter_from_another_association():
    budget = QueryBudget(association_limit=2, server_limit=1)
    active = budget.acquire("assoc-a", "active")

    acquired, result, thread = start_waiting_lease(
        budget, "assoc-b", "replacement"
    )
    assert wait_until(lambda: budget.snapshot("assoc-b").server_waiting == 1)

    active.release()

    assert acquired.wait(2)
    thread.join(2)
    assert not thread.is_alive()
    assert "error" not in result
    assert budget.active_count() == 1
    assert budget.active_count("assoc-b") == 1

    result["lease"].release()
    assert budget.available("assoc-b") == {"association": 2, "server": 1}


def test_acquisition_timeout_and_external_cancellation_are_distinct():
    budget = QueryBudget(server_limit=1)
    active = budget.acquire("assoc-a", "active")

    with pytest.raises(QueryBudgetTimeout):
        budget.acquire("assoc-b", "waiting", timeout=0)

    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(QueryBudgetCancelled):
        budget.acquire(
            "assoc-b",
            "cancelled",
            cancel_check=cancelled.is_set,
            poll_interval=0.001,
        )

    active.release()


def test_cancel_while_waiting_for_budget_clears_waiter_without_lease():
    budget = QueryBudget(server_limit=1)
    active = budget.acquire("assoc-a", "active")
    cancellation = threading.Event()
    failure: dict[str, BaseException] = {}

    def wait_for_budget() -> None:
        try:
            budget.acquire(
                "assoc-b",
                "cancelled-waiter",
                cancel_check=cancellation.is_set,
                poll_interval=0.001,
            )
        except QueryBudgetCancelled as exc:
            failure["error"] = exc

    waiter = threading.Thread(target=wait_for_budget, daemon=True)
    waiter.start()

    assert wait_until(lambda: budget.snapshot("assoc-b").server_waiting == 1)
    cancellation.set()

    waiter.join(2)
    assert not waiter.is_alive()
    assert isinstance(failure.get("error"), QueryBudgetCancelled)
    snapshot = budget.snapshot("assoc-b")
    assert snapshot.server_waiting == 0
    assert snapshot.server_active == 1

    active.release()


def test_cancel_after_emitted_response_records_close_and_restores_quota():
    association_id = "assoc-after-response"
    budget = QueryBudget(association_limit=1, server_limit=1)
    active = budget.acquire(association_id, "cancelled-query")

    replacement_ready, replacement_result, replacement_thread = (
        start_waiting_lease(budget, association_id, "replacement-query")
    )
    assert wait_until(
        lambda: budget.snapshot(association_id).association_waiting == 1
    )

    query = RecordingImageDirectoryQuery()
    iterator = query()

    # The handler has composed and yielded one response, and the server has
    # actually passed that response to its DIMSE sink.
    first_response = next(iterator)
    emitted: list[Any] = []
    emitted.append(first_response)

    # Client cancellation after the first response causes prompt iterator
    # closure; no second result is composed.
    iterator.close()

    assert query.cleanup_finished.wait(2)
    assert query.cleanup_count == 1
    assert query.composed == ["synthetic-image-1"]
    assert len(emitted) == 1
    assert emitted[0][0] == "0xFF00"

    after_release = active.release()
    assert after_release is not None
    record = {
        "stage": "after_response_emitted",
        "iterator_cleanup_count": query.cleanup_count,
        "emitted_result_count": len(emitted),
        "composed_result_count": len(query.composed),
        "available_after_close": after_release.available(),
    }
    assert record == {
        "stage": "after_response_emitted",
        "iterator_cleanup_count": 1,
        "emitted_result_count": 1,
        "composed_result_count": 1,
        "available_after_close": {"association": 1, "server": 1},
    }

    assert replacement_ready.wait(2)
    replacement_thread.join(2)
    assert not replacement_thread.is_alive()
    replacement_result["lease"].release()
    assert budget.available(association_id) == {
        "association": 1,
        "server": 1,
    }


def test_cancel_before_sink_discards_already_produced_response():
    association_id = "assoc-produced-not-emitted"
    budget = QueryBudget(association_limit=1, server_limit=1)
    lease = budget.acquire(association_id, "produced-query")

    query = RecordingImageDirectoryQuery()
    iterator = query()
    produced = next(iterator)

    # Cancellation wins before the response is handed to the DIMSE sink.
    iterator.close()

    assert query.cleanup_finished.wait(2)
    emitted: list[Any] = []
    record = {
        "stage": "produced_but_not_emitted",
        "produced_result_count": len(query.composed),
        "emitted_result_count": len(emitted),
        "iterator_cleanup_count": query.cleanup_count,
    }
    assert record == {
        "stage": "produced_but_not_emitted",
        "produced_result_count": 1,
        "emitted_result_count": 0,
        "iterator_cleanup_count": 1,
    }
    assert produced[0] == "0xFF00"

    snapshot = lease.release()
    assert snapshot is not None
    assert snapshot.available() == {"association": 1, "server": 1}


def test_cancel_while_waiting_before_first_response_emits_nothing():
    association_id = "assoc-waiting-first"
    budget = QueryBudget(association_limit=1, server_limit=1)
    active = budget.acquire(association_id, "waiting-query")

    replacement_ready, replacement_result, replacement_thread = (
        start_waiting_lease(budget, association_id, "replacement-query")
    )
    assert wait_until(
        lambda: budget.snapshot(association_id).association_waiting == 1
    )

    query = RecordingImageDirectoryQuery()
    first_gate = threading.Event()
    cancellation = threading.Event()
    iterator = query(first_gate=first_gate, cancellation=cancellation)

    pull_result: dict[str, Any] = {}

    def pull_first() -> None:
        try:
            pull_result["value"] = next(iterator)
        except StopIteration:
            pull_result["stopped"] = True

    consumer = threading.Thread(target=pull_first, daemon=True)
    consumer.start()

    assert query.waiting_before_first.wait(2)
    assert query.entered.is_set()

    # The local cancellation signal stands in for a network C-CANCEL and also
    # releases the synthetic directory lookup wait.
    cancellation.set()
    first_gate.set()

    consumer.join(2)
    assert not consumer.is_alive()
    assert pull_result.get("stopped") is True

    # Closing an already-stopped iterator is idempotent.
    iterator.close()

    assert query.cleanup_finished.wait(2)
    assert query.cleanup_count == 1
    assert query.composed == []
    emitted: list[Any] = []
    assert emitted == []

    after_release = active.release()
    assert after_release is not None
    record = {
        "stage": "waiting_before_first_response",
        "iterator_cleanup_count": query.cleanup_count,
        "emitted_result_count": len(emitted),
        "composed_result_count": len(query.composed),
        "available_after_close": after_release.available(),
    }
    assert record == {
        "stage": "waiting_before_first_response",
        "iterator_cleanup_count": 1,
        "emitted_result_count": 0,
        "composed_result_count": 0,
        "available_after_close": {"association": 1, "server": 1},
    }

    assert replacement_ready.wait(2)
    replacement_thread.join(2)
    assert not replacement_thread.is_alive()
    replacement_result["lease"].release()
    assert budget.available(association_id) == {
        "association": 1,
        "server": 1,
    }


def test_ae_constructor_builds_hierarchical_query_budget():
    from pynetdicom import AE

    ae = AE(
        max_concurrent_queries=3,
        max_queries_per_association=1,
        query_budget_timeout=0.25,
    )
    assert isinstance(ae.query_budget, QueryBudget)
    assert ae.query_budget.server_limit == 3
    assert ae.query_budget.association_limit == 1
    assert ae.query_budget_timeout == 0.25


def test_c_find_closes_handler_and_releases_budget(monkeypatch):
    budget = QueryBudget(association_limit=1, server_limit=1)
    assoc = FakeFindAssociation(budget)
    service = QueryRetrieveServiceClass(assoc)

    cleaned = threading.Event()

    def handler():
        try:
            yield 0xFE00, None
        finally:
            cleaned.set()

    generator = handler()
    probes: list[CloseProbe] = []
    real_wrap = QueryRetrieveServiceClass._wrap_handler

    def spy_wrap(self, handler):
        probe = CloseProbe(real_wrap(self, handler))
        probes.append(probe)
        return probe

    def fake_trigger(association, event, data):
        return generator

    monkeypatch.setattr(evt, "trigger", fake_trigger)
    monkeypatch.setattr(
        QueryRetrieveServiceClass, "_wrap_handler", spy_wrap
    )

    service._c_find_scp(find_request(), find_context())

    assert cleaned.wait(2)
    assert len(probes) == 1
    assert probes[0].close_count == 1
    assert len(assoc.dimse.sent) == 1
    assert assoc.dimse.sent[0].Status == 0xFE00
    assert budget.active_count() == 0
    assert budget.available(assoc) == {"association": 1, "server": 1}


def test_c_find_normal_completion_sends_success_and_releases_budget(
    monkeypatch,
):
    budget = QueryBudget(association_limit=1, server_limit=1)
    assoc = FakeFindAssociation(budget)
    service = QueryRetrieveServiceClass(assoc)
    cleaned = threading.Event()

    def handler():
        try:
            return
            yield  # pragma: no cover - makes this a generator
        finally:
            cleaned.set()

    def fake_trigger(association, event, data):
        return handler()

    monkeypatch.setattr(evt, "trigger", fake_trigger)

    service._c_find_scp(find_request(), find_context())

    assert cleaned.wait(2)
    assert assoc.dimse.sent[-1].Status == 0x0000
    assert budget.active_count() == 0


def test_c_find_stops_before_emitting_result_composed_after_cancel(
    monkeypatch,
):
    assoc = FakeFindAssociation(None)
    service = QueryRetrieveServiceClass(assoc)
    service.statuses = QR_FIND_SERVICE_CLASS_STATUS
    cleanup = threading.Event()
    composed: list[int] = []

    def handler():
        try:
            yield 0xB001, None

            # The cancel arrives after the warning was emitted and while the
            # handler is producing another response.
            assoc.dimse.cancel_req[7] = object()
            composed.append(2)
            yield 0xFF00, None
        finally:
            cleanup.set()

    monkeypatch.setattr(evt, "trigger", lambda *args: handler())

    service._c_find_scp(find_request(), find_context())

    assert cleanup.wait(2)
    assert composed == [2]
    assert assoc.dimse.sent_statuses == [0xB001, 0xFE00]


def test_c_find_budget_full_returns_out_of_resources(monkeypatch):
    budget = QueryBudget(association_limit=1, server_limit=1)
    assoc = FakeFindAssociation(budget, timeout=0)
    other = budget.acquire("other-association", "other-query")

    triggered = False

    def fake_trigger(*args, **kwargs):
        nonlocal triggered
        triggered = True
        return None

    monkeypatch.setattr(evt, "trigger", fake_trigger)

    QueryRetrieveServiceClass(assoc)._c_find_scp(
        find_request(), find_context()
    )

    assert triggered is False
    assert assoc.dimse.sent[-1].Status == 0xA700
    other.release()


def test_c_find_cancelled_while_waiting_for_budget(monkeypatch):
    budget = QueryBudget(association_limit=1, server_limit=1)
    assoc = FakeFindAssociation(budget)
    other = budget.acquire("other-association", "other-query")
    assoc.dimse.cancel_req[7] = object()

    def fake_trigger(*args, **kwargs):
        raise AssertionError("Handler should not start before admission")

    monkeypatch.setattr(evt, "trigger", fake_trigger)

    QueryRetrieveServiceClass(assoc)._c_find_scp(
        find_request(), find_context()
    )

    assert assoc.dimse.sent[-1].Status == 0xFE00
    assert budget.active_count() == 1
    other.release()
    assert budget.active_count() == 0
