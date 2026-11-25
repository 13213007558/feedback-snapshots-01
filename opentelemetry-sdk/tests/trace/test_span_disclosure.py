# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import unittest

from opentelemetry import trace as trace_api
from opentelemetry.sdk import trace
from opentelemetry.sdk.trace import SpanDisclosurePolicy
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import Status, StatusCode


class InventoryShortage(Exception):
    """Application exception that carries its own, non standard, payload."""

    def __init__(self, sku: str, message: str) -> None:
        super().__init__(message)
        self.sku = sku


def _exporters(provider, internal_policy=None):
    internal = InMemorySpanExporter()
    external = InMemorySpanExporter()
    if internal_policy is None:
        provider.add_span_processor(SimpleSpanProcessor(internal))
    else:
        provider.add_span_processor(
            SimpleSpanProcessor(internal),
            disclosure_policy=internal_policy,
        )
    provider.add_span_processor(SimpleSpanProcessor(external))
    return internal, external


def _single(exporter):
    (span,) = exporter.get_finished_spans()
    return span


class TestInterleavedStatusAndExceptionDisclosure(unittest.TestCase):
    def test_business_catches_one_exception_and_another_escapes(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        caught_by_business = None
        escaped_and_caught_by_business = None
        try:
            with tracer.start_as_current_span("reserve-stock") as span:
                span.set_attribute("inventory.sku", "SKU-1")
                # Explicit status before any exception handling.
                span.set_status(StatusCode.ERROR, "explicit: partial reservation")
                try:
                    raise InventoryShortage("SKU-1", "only 2 left")
                except InventoryShortage as exc:
                    caught_by_business = exc
                    # Explicit exception and status interleaved with the
                    # automatic handling that will run when the context exits.
                    span.record_exception(exc, {"inventory.sku": "SKU-1"})
                    span.set_status(StatusCode.ERROR, "explicit: handled")
                raise InventoryShortage("SKU-2", "out of stock")
        except InventoryShortage as exc:
            escaped_and_caught_by_business = exc

        # The business side keeps the original exception objects untouched.
        self.assertIsInstance(caught_by_business, InventoryShortage)
        self.assertEqual(caught_by_business.sku, "SKU-1")
        self.assertEqual(str(caught_by_business), "only 2 left")
        self.assertEqual(caught_by_business.args, ("only 2 left",))
        self.assertIsNotNone(caught_by_business.__traceback__)

        self.assertIsInstance(escaped_and_caught_by_business, InventoryShortage)
        self.assertEqual(escaped_and_caught_by_business.sku, "SKU-2")
        self.assertEqual(str(escaped_and_caught_by_business), "out of stock")

        for name, exporter, detailed in (
            ("internal", internal, True),
            ("external", external, False),
        ):
            with self.subTest(subscriber=name):
                exported = _single(exporter)
                self.assertEqual(exported.name, "reserve-stock")
                self.assertEqual(dict(exported.attributes), {"inventory.sku": "SKU-1"})
                self.assertIs(exported.status.status_code, StatusCode.ERROR)

                # Only the subscriber with permission reads the free-form
                # description that the application set explicitly.
                # The first description that was recorded wins, matching the
                # status precedence the SDK already applies.
                if detailed:
                    self.assertEqual(
                        exported.status.description,
                        "explicit: partial reservation",
                    )
                else:
                    self.assertIsNone(exported.status.description)

                self.assertEqual(len(exported.events), 2)
                manual, automatic = exported.events
                self.assertEqual(manual.name, "exception")
                self.assertEqual(automatic.name, "exception")

                for event in exported.events:
                    self.assertTrue(
                        event.attributes["exception.type"].endswith("InventoryShortage")
                    )
                    # The category and status are always available.
                    self.assertEqual(event.attributes["exception.escaped"], "False")

                if detailed:
                    self.assertEqual(manual.attributes["exception.message"], "only 2 left")
                    self.assertEqual(automatic.attributes["exception.message"], "out of stock")
                    self.assertIn(
                        "InventoryShortage: only 2 left",
                        manual.attributes["exception.stacktrace"],
                    )
                    self.assertIn(
                        "InventoryShortage: out of stock",
                        automatic.attributes["exception.stacktrace"],
                    )
                    self.assertEqual(manual.attributes["inventory.sku"], "SKU-1")
                else:
                    for event in exported.events:
                        self.assertNotIn("exception.message", event.attributes)
                        self.assertNotIn("exception.stacktrace", event.attributes)
                        self.assertNotIn("inventory.sku", event.attributes)

    def test_ok_status_is_final_but_the_exception_event_is_still_recorded(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_as_current_span("checked-out") as span:
                span.set_status(StatusCode.OK)
                raise InventoryShortage("SKU-3", "already shipped")

        for exporter in (internal, external):
            exported = _single(exporter)
            # OK is final, so the automatic ERROR does not replace it.
            self.assertIs(exported.status.status_code, StatusCode.OK)
            (event,) = exported.events
            self.assertTrue(
                event.attributes["exception.type"].endswith("InventoryShortage")
            )
            self.assertEqual(event.attributes["exception.escaped"], "False")

        self.assertNotIn("exception.message", _single(external).events[0].attributes)

    def test_span_context_manager_marks_the_exception_as_escaped(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_span("escaped") as span:
                raise InventoryShortage("SKU-4", "escaped the span")

        internal_event = _single(internal).events[0]
        external_event = _single(external).events[0]
        self.assertEqual(internal_event.attributes["exception.escaped"], "True")
        self.assertEqual(external_event.attributes["exception.escaped"], "True")
        self.assertIn("exception.message", internal_event.attributes)
        self.assertNotIn("exception.message", external_event.attributes)


class TestSubscriberViewIsolation(unittest.TestCase):
    def test_mutating_one_view_does_not_change_the_other(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        seen_by_mutating_processor = []

        class MutatingProcessor(trace.SpanProcessor):
            def on_end(self, span):
                # A subscriber that redacts and enriches its own view.
                span._attributes["inventory.sku"] = "REDACTED"
                span._events[0].attributes["exception.message"] = "REDACTED"
                span._events.append(trace.Event("internal-only", {"leak": True}))
                span._status = Status(StatusCode.ERROR, "internal-only")
                span._name = "internal-only"
                seen_by_mutating_processor.append(span)

        provider.add_span_processor(MutatingProcessor())
        with tracer.start_as_current_span("mutated") as span:
            span.set_attribute("inventory.sku", "SKU-5")
            span.set_status(StatusCode.ERROR, "kept")
            span.record_exception(InventoryShortage("SKU-5", "internal"))

        (mutated_view,) = seen_by_mutating_processor
        self.assertEqual(mutated_view.name, "internal-only")
        self.assertEqual(mutated_view.attributes["inventory.sku"], "REDACTED")
        self.assertEqual(
            mutated_view.events[0].attributes["exception.message"],
            "REDACTED",
        )
        self.assertEqual(
            [event.name for event in mutated_view.events],
            ["exception", "internal-only"],
        )

        for name, exporter, detailed in (
            ("internal", internal, True),
            ("external", external, False),
        ):
            with self.subTest(subscriber=name):
                exported = _single(exporter)
                self.assertEqual(exported.name, "mutated")
                self.assertIs(exported.status.status_code, StatusCode.ERROR)
                if detailed:
                    self.assertEqual(exported.status.description, "kept")
                else:
                    self.assertIsNone(exported.status.description)
                self.assertEqual([event.name for event in exported.events], ["exception"])
                self.assertEqual(exported.attributes["inventory.sku"], "SKU-5")

    def test_a_subscriber_cannot_escalate_past_the_provider_policy(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.summary())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_as_current_span("restricted"):
                raise InventoryShortage("SKU-6", "secret detail")

        for exporter in (internal, external):
            event = _single(exporter).events[0]
            self.assertEqual(
                set(event.attributes),
                {"exception.type", "exception.escaped"},
            )
            self.assertIsNone(_single(exporter).status.description)

    def test_subscriber_policy_can_select_individual_fields(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        policy = SpanDisclosurePolicy(
            exception_message=True,
            exception_attributes=True,
        )
        internal, external = _exporters(provider, policy)
        tracer = provider.get_tracer(__name__)

        span = tracer.start_span("selective")
        span.record_exception(InventoryShortage("SKU-7", "partial"), {"region": "eu"})
        span.set_status(StatusCode.ERROR, "selective description")
        span.end()

        event = _single(internal).events[0]
        self.assertIn("exception.message", event.attributes)
        self.assertNotIn("exception.stacktrace", event.attributes)
        self.assertEqual(event.attributes["region"], "eu")

        external_span = _single(external)
        self.assertEqual(
            set(external_span.events[0].attributes),
            {"exception.type", "exception.escaped"},
        )
        self.assertIsNone(external_span.status.description)


class TestAutomaticStatusDescription(unittest.TestCase):
    def test_description_generated_by_the_context_exit_is_disclosed_conditionally(self):
        provider = trace.TracerProvider(span_disclosure_policy=SpanDisclosurePolicy.full())
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_as_current_span("auto-only"):
                raise InventoryShortage("SKU-9", "auto generated")

        internal_span = _single(internal)
        external_span = _single(external)
        self.assertEqual(internal_span.status.description, "InventoryShortage: auto generated")
        self.assertIsNone(external_span.status.description)

        internal_event = internal_span.events[0]
        external_event = external_span.events[0]
        self.assertEqual(internal_event.attributes["exception.message"], "auto generated")
        self.assertNotIn("exception.message", external_event.attributes)
        self.assertEqual(
            internal_event.attributes["exception.escaped"],
            external_event.attributes["exception.escaped"],
        )
        self.assertEqual(internal_event.attributes["exception.type"], external_event.attributes["exception.type"])


class TestConcurrentProcessorIsolation(unittest.TestCase):
    def test_concurrent_subscribers_each_get_their_own_view(self):
        provider = trace.TracerProvider(
            span_disclosure_policy=SpanDisclosurePolicy.full(),
            active_span_processor=trace.ConcurrentMultiSpanProcessor(2),
        )
        internal, external = _exporters(provider, SpanDisclosurePolicy.full())
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_as_current_span("concurrent"):
                raise InventoryShortage("SKU-10", "concurrent detail")

        internal_span = _single(internal)
        external_span = _single(external)
        self.assertIsNot(internal_span, external_span)
        self.assertEqual(
            internal_span.events[0].attributes["exception.message"],
            "concurrent detail",
        )
        self.assertNotIn("exception.message", external_span.events[0].attributes)
        self.assertEqual(
            external_span.status.status_code,
            internal_span.status.status_code,
        )
        provider.shutdown()


class TestDisclosureBackwardCompatibility(unittest.TestCase):
    def test_without_a_policy_the_span_is_not_copied_or_filtered(self):
        provider = trace.TracerProvider()
        internal, external = _exporters(provider)
        tracer = provider.get_tracer(__name__)

        with self.assertRaises(InventoryShortage):
            with tracer.start_as_current_span("legacy"):
                raise InventoryShortage("SKU-8", "legacy detail")

        internal_span = _single(internal)
        external_span = _single(external)
        self.assertIs(internal_span, external_span)
        for exported in (internal_span, external_span):
            event = exported.events[0]
            self.assertEqual(event.attributes["exception.message"], "legacy detail")
            self.assertIn("exception.stacktrace", event.attributes)
            self.assertEqual(exported.status.description, "InventoryShortage: legacy detail")


if __name__ == "__main__":
    unittest.main()
