import asyncio
import logging
import threading

import pytest

import sentry_sdk
from sentry_sdk.projects import (
    DEFAULT_PROJECT,
    PROJECT_TAG,
    MemoryTransport,
    ProjectRouter,
)
from sentry_sdk.transport import Transport


class FailingTransport(Transport):
    """A transport that can be switched between failing and working."""

    def __init__(self):
        Transport.__init__(self)
        self.fail = True
        self.envelopes = []

    def is_healthy(self):
        return not self.fail

    def capture_envelope(self, envelope):
        if self.fail:
            raise RuntimeError("transport unavailable")
        self.envelopes.append(envelope)

    @property
    def events(self):
        events = []
        for envelope in self.envelopes:
            event = envelope.get_event()
            if event is not None:
                events.append(event)
        return events


def _messages(transport):
    return [event["message"] for event in transport.events]


def test_routes_requests_and_background_tasks_to_projects(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()
    transport_b = MemoryTransport()

    router = ProjectRouter()
    router.register("a", transport_a)
    router.register("b", transport_b)

    try:
        with router.scope("a"):
            sentry_sdk.capture_message("a-main")

            thread = threading.Thread(
                target=lambda: sentry_sdk.capture_message("a-thread")
            )
            thread.start()
            thread.join()

        with router.scope("b"):
            sentry_sdk.capture_message("b-main")

            async def run_task():
                sentry_sdk.capture_message("b-async-task")

            asyncio.run(run_task())
    finally:
        router.close()

    assert _messages(transport_a) == ["a-main", "a-thread"]
    assert _messages(transport_b) == ["b-main", "b-async-task"]

    assert [event["tags"][PROJECT_TAG] for event in transport_a.events] == ["a", "a"]
    assert [event["tags"][PROJECT_TAG] for event in transport_b.events] == ["b", "b"]


def test_failed_project_keeps_its_events_and_retries_them(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()
    transport_b = MemoryTransport()
    failing = FailingTransport()

    router = ProjectRouter()
    router.register("a", transport_a)
    router.register("b", transport_b)
    router.register("broken", failing)

    try:
        with router.scope("broken"):
            sentry_sdk.capture_message("broken-1")
            sentry_sdk.capture_message("broken-2")

        with router.scope("a"):
            sentry_sdk.capture_message("a-still-works")

        # The failing project keeps its envelopes instead of reattributing them.
        assert failing.events == []
        assert router.get_transport("broken").pending_count == 2
        assert _messages(transport_a) == ["a-still-works"]
        assert transport_b.envelopes == []

        failing.fail = False
        assert router.retry("broken") == {"broken": 2}
        assert router.get_transport("broken").pending_count == 0
        assert _messages(failing) == ["broken-1", "broken-2"]
        assert _messages(transport_a) == ["a-still-works"]
        assert transport_b.envelopes == []
    finally:
        router.close()


def test_unknown_project_is_not_sent_anywhere(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()
    default_transport = MemoryTransport()

    router = ProjectRouter()
    router.register("a", transport_a)
    router.register(DEFAULT_PROJECT, default_transport)

    try:
        with router.scope("not-approved"):
            assert sentry_sdk.capture_message("unknown") is None

        assert transport_a.envelopes == []
        assert default_transport.envelopes == []
    finally:
        router.close()


def test_default_project_only_receives_explicitly_selected_events(sentry_init):
    sentry_init()

    default_transport = MemoryTransport()
    transport_a = MemoryTransport()

    router = ProjectRouter()
    router.register(DEFAULT_PROJECT, default_transport)
    router.register("a", transport_a)

    try:
        # No binding: the default project is not a catch-all.
        assert sentry_sdk.capture_message("implicit") is None

        with router.scope(DEFAULT_PROJECT):
            sentry_sdk.capture_message("explicit-default")

        with router.scope("a"):
            sentry_sdk.capture_message("explicit-a")

        assert _messages(default_transport) == ["explicit-default"]
        assert _messages(transport_a) == ["explicit-a"]
    finally:
        router.close()


def test_scope_restores_previous_binding(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()
    transport_b = MemoryTransport()

    router = ProjectRouter()
    router.register("a", transport_a)
    router.register("b", transport_b)

    try:
        with router.scope("a"):
            sentry_sdk.capture_message("outer")

            with router.scope("b"):
                sentry_sdk.capture_message("inner")

            sentry_sdk.capture_message("outer-again")

        # Leaving the scope clears the binding again.
        assert sentry_sdk.capture_message("unbound") is None
    finally:
        router.close()

    assert _messages(transport_a) == ["outer", "outer-again"]
    assert _messages(transport_b) == ["inner"]


def test_duplicate_registration_is_rejected(sentry_init):
    sentry_init()

    router = ProjectRouter()
    router.register("a", MemoryTransport())

    try:
        with pytest.raises(ValueError, match="already registered"):
            router.register("a", MemoryTransport())
    finally:
        router.close()


def test_logging_integration_follows_the_bound_project(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()

    router = ProjectRouter()
    router.register("a", transport_a)

    try:
        logger = logging.getLogger("test_projects")

        logger.error("unbound-log")
        with router.scope("a"):
            logger.error("project-log")
    finally:
        router.close()

    assert len(transport_a.events) == 1
    assert transport_a.events[0]["logentry"]["formatted"] == "project-log"


def test_retry_only_targets_the_named_project(sentry_init):
    sentry_init()

    failing_a = FailingTransport()
    failing_b = FailingTransport()

    router = ProjectRouter()
    router.register("a", failing_a)
    router.register("b", failing_b)

    try:
        with router.scope("a"):
            sentry_sdk.capture_message("a-queued")
        with router.scope("b"):
            sentry_sdk.capture_message("b-queued")

        failing_a.fail = False
        failing_b.fail = False

        assert router.retry("a") == {"a": 1}
        assert _messages(failing_a) == ["a-queued"]
        assert failing_b.events == []
        assert router.get_transport("b").pending_count == 1
        assert router.retry("missing") == {}
    finally:
        router.close()


def test_default_project_transport_failure_does_not_spill_to_other_projects(
    sentry_init,
):
    sentry_init()

    failing_default = FailingTransport()
    transport_a = MemoryTransport()

    router = ProjectRouter()
    router.register(DEFAULT_PROJECT, failing_default)
    router.register("a", transport_a)

    try:
        with router.scope(DEFAULT_PROJECT):
            sentry_sdk.capture_message("default-broken")

        with router.scope("a"):
            sentry_sdk.capture_message("a-ok")

        assert failing_default.events == []
        assert router.get_transport(DEFAULT_PROJECT).pending_count == 1
        assert _messages(transport_a) == ["a-ok"]
    finally:
        router.close()


def test_router_flush_drains_project_telemetry(sentry_init):
    sentry_init()

    transport_a = MemoryTransport()

    router = ProjectRouter()
    router.register("a", transport_a)

    try:
        with router.scope("a"):
            sentry_sdk.metrics.count("clicks", 2)

        # Metrics are buffered on the project's client.
        assert transport_a.envelopes == []
        router.flush()
        assert [
            item.type for envelope in transport_a.envelopes for item in envelope
        ] == ["trace_metric"]
    finally:
        router.close()
