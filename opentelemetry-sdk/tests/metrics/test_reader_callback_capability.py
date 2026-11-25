# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Capability gating of asynchronous (callback based) instruments per reader.

An internal reader is allowed to run callbacks that read restricted storage,
while a public reader may only collect ordinary measurements. The SDK must:

* confirm that capability *before* the callback runs, so an unauthorized reader
  never touches restricted storage;
* drop measurements when the permission is revoked while the callback is in
  flight instead of caching them in the reader's storage;
* keep every reader's storage independent, so data collected for the internal
  reader can never leak into the public reader's next collection.
"""

# pylint: disable=protected-access

from threading import Event, Thread
from unittest import TestCase
from unittest.mock import Mock

from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics._internal.instrument import _Asynchronous
from opentelemetry.sdk.metrics.export import InMemoryMetricReader


class RestrictedStorage:
    """Stand-in for a storage backend that only internal readers may access."""

    def __init__(self):
        self.read_count = 0

    def read(self):
        self.read_count += 1
        return 42


class CapabilityGate:
    """Mutable permission decision shared by the gated readers."""

    def __init__(self, internal_allowed=True):
        self._internal_allowed = internal_allowed

    def revoke(self):
        self._internal_allowed = False

    @property
    def internal_allowed(self):
        return self._internal_allowed


class _MidFlightControl:
    """One-shot synchronization for the mid-flight revocation collection."""

    def __init__(self):
        self.armed = False
        self.started = Event()
        self.release = Event()

    def arm(self):
        self.armed = True
        self.started.clear()
        self.release.clear()

    def disarm(self):
        self.armed = False
        self.release.set()


class GatedInMemoryMetricReader(InMemoryMetricReader):
    def __init__(self, gate, is_internal):
        super().__init__()
        self._gate = gate
        self._is_internal = is_internal

    def _allows_async_instrument(self, instrument):
        if instrument.name != "restricted.gauge":
            # Ordinary asynchronous instruments are collectable by every reader.
            return True
        return self._is_internal and self._gate.internal_allowed


def _point_counts(metrics_data):
    """Return ``{metric_name: number_of_data_points}`` for a collection."""
    counts = {}
    if metrics_data is None:
        return counts
    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                counts[metric.name] = len(list(metric.data.data_points))
    return counts


class TestReaderCallbackCapability(TestCase):
    def test_default_reader_allows_all_async_instruments(self):
        # The base hook is permissive so existing readers keep collecting every
        # asynchronous instrument without any configuration.
        reader = InMemoryMetricReader()
        instrument = Mock(spec=_Asynchronous)
        self.assertTrue(reader._allows_async_instrument(instrument))

    def _build(self):
        gate = CapabilityGate(internal_allowed=True)
        internal_reader = GatedInMemoryMetricReader(gate, is_internal=True)
        public_reader = GatedInMemoryMetricReader(gate, is_internal=False)

        provider = MeterProvider(metric_readers=[internal_reader, public_reader])
        meter = provider.get_meter("capability-test")

        restricted_storage = RestrictedStorage()
        # Only the dedicated revocation collection blocks the callback. The
        # events stay un-armed for every other collection so ordinary
        # collections return immediately.
        control = _MidFlightControl()

        def restricted_callback(_options):
            # The restricted read happens as soon as the callback starts,
            # before the permission is tightened below.
            value = restricted_storage.read()
            if control.armed:
                control.started.set()
                # Block until the test has revoked the permission, simulating a
                # callback whose permission changes while it is still running.
                control.release.wait(5)
            return [Observation(value=value)]

        meter.create_observable_gauge(
            "restricted.gauge",
            callbacks=[restricted_callback],
        )
        meter.create_observable_gauge(
            "plain.gauge",
            callbacks=[lambda _options: [Observation(value=7)]],
        )
        counter = meter.create_counter("plain.counter")

        return {
            "gate": gate,
            "internal_reader": internal_reader,
            "public_reader": public_reader,
            "restricted_storage": restricted_storage,
            "control": control,
            "counter": counter,
            "provider": provider,
        }

    def test_reader_capability_gating_and_storage_isolation(self):
        harness = self._build()
        gate = harness["gate"]
        control = harness["control"]
        internal_reader = harness["internal_reader"]
        public_reader = harness["public_reader"]
        restricted_storage = harness["restricted_storage"]
        counter = harness["counter"]
        provider = harness["provider"]
        try:
            # 1. While access is permitted, the internal reader computes and
            #    keeps the restricted point alongside the ordinary metrics.
            internal_data_1 = internal_reader.get_metrics_data()
            self.assertEqual(restricted_storage.read_count, 1)
            self.assertEqual(
                _point_counts(internal_data_1),
                {"restricted.gauge": 1, "plain.gauge": 1},
            )

            # 2. The public reader must never run the restricted callback: the
            #    capability is rejected before the callback executes, so the
            #    restricted storage is not read again and no restricted point is
            #    present. Ordinary metrics are still collected normally.
            counter.add(3, {"kind": "a"})
            public_data_1 = public_reader.get_metrics_data()
            self.assertEqual(restricted_storage.read_count, 1)
            self.assertEqual(
                _point_counts(public_data_1),
                {"plain.gauge": 1, "plain.counter": 1},
            )

            # 3. Interleave back to the internal reader. The previously
            #    restricted value must not have leaked through the public
            #    reader's storage: each reader keeps an independent storage, so
            #    the internal reader still owns its restricted stream.
            counter.add(2, {"kind": "a"})
            internal_data_2 = internal_reader.get_metrics_data()
            self.assertEqual(restricted_storage.read_count, 2)
            self.assertEqual(
                _point_counts(internal_data_2),
                {"restricted.gauge": 1, "plain.gauge": 1, "plain.counter": 1},
            )

            # 4. Mid-flight revocation: tighten the permission as soon as the
            #    internal callback starts. The callback is allowed to run and
            #    reads the storage once, but its result is abandoned because the
            #    gate is closed before the measurement is accepted.
            control.arm()
            thread = _CollectThread(internal_reader)
            thread.start()
            # Wait until the callback has performed the restricted read.
            self.assertTrue(control.started.wait(5))
            gate.revoke()
            # Release the callback; the re-check now discards its observation.
            control.release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "internal collection thread did not finish")
            self.assertIsNone(thread.error)
            control.disarm()
            self.assertEqual(restricted_storage.read_count, 3)
            # The callback ran and read once, but its point was abandoned: only
            # the ordinary metrics are returned, with no restricted stream.
            self.assertEqual(
                _point_counts(thread.metrics_data),
                {"plain.gauge": 1, "plain.counter": 1},
            )

            # 5. After revocation the internal reader also refuses up front: the
            #    callback is not invoked at all, so the storage is not read.
            internal_data_4 = internal_reader.get_metrics_data()
            self.assertEqual(restricted_storage.read_count, 3)
            self.assertEqual(
                _point_counts(internal_data_4),
                # Cumulative state keeps the ordinary metrics; no restricted
                # point is produced or cached during the denied collection.
                {"plain.gauge": 1, "plain.counter": 1},
            )

            # 6. The public reader continues collecting ordinary metrics and
            #    still never observes the restricted instrument, even though it
            #    was collected earlier by the internal reader.
            public_data_3 = public_reader.get_metrics_data()
            self.assertEqual(restricted_storage.read_count, 3)
            self.assertEqual(
                _point_counts(public_data_3),
                {"plain.gauge": 1, "plain.counter": 1},
            )

            # The cumulative counter is tracked independently per reader and
            # never contains the restricted stream.
            self.assertEqual(_counter_value(public_data_3, "plain.counter"), 5)
            self.assertNotIn("restricted.gauge", _point_counts(public_data_1))
            self.assertNotIn("restricted.gauge", _point_counts(public_data_3))
        finally:
            control.disarm()
            provider.shutdown()


class _CollectThread(Thread):
    """Run a reader collection on a worker and capture its outcome."""

    def __init__(self, reader):
        super().__init__()
        self._reader = reader
        self.metrics_data = None
        self.error = None

    def run(self):
        try:
            self.metrics_data = self._reader.get_metrics_data()
        except Exception as error:  # pylint: disable=broad-except
            self.error = error


def _counter_value(metrics_data, metric_name):
    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name == metric_name:
                    return sum(point.value for point in metric.data.data_points)
    return None
