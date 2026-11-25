# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=protected-access

from unittest import TestCase

from opentelemetry.sdk.metrics import Counter, MeterProvider
from opentelemetry.sdk.metrics.cardinality_accounting import (
    CardinalityAccountant,
    snapshot_series_occupancy,
)
from opentelemetry.sdk.metrics.export import (
    AggregationTemporality,
    MetricReader,
)
from opentelemetry.sdk.metrics.view import View

_OVERFLOW = "otel.metric.overflow"
_WIDE = "requests_wide"
_NARROW = "requests_by_region"
_BUDGETS = {_WIDE: 2, _NARROW: 2}


class ScriptedReportReader(MetricReader):
    def __init__(self, *args, accountant=None, reader_name=None, fail_first=False, **kwargs):
        super().__init__(*args, **kwargs)
        self._accountant = accountant
        self._reader_name = reader_name or type(self).__name__
        self._fail_next = fail_first
        self.received = []

    def _receive_metrics(self, metrics_data, timeout_millis=10000, **kwargs):
        if self._accountant is None:
            if self._fail_next:
                self._fail_next = False
                raise RuntimeError("report failed after collect")
            self.received.append(metrics_data)
            return

        with self._accountant.report(metrics_data, reader=self._reader_name):
            if self._fail_next:
                self._fail_next = False
                raise RuntimeError("report failed after collect")
            self.received.append(metrics_data)

    def shutdown(self, timeout_millis=30000, **kwargs):
        return None

    def force_flush(self, timeout_millis=10000):
        return True


def _views(budget=2):
    return [
        View(
            instrument_name="requests",
            name=_WIDE,
            attribute_keys={"service", "region", "route"},
            aggregation_cardinality_limit=budget,
        ),
        View(
            instrument_name="requests",
            name=_NARROW,
            attribute_keys={"service", "region"},
            aggregation_cardinality_limit=budget,
        ),
    ]


def _occupancy_by_stream(provider, reader, name):
    return {item.stream: item for item in snapshot_series_occupancy(provider, reader, reader_name=name)}


def _point_values_by_attributes(metrics_data, stream_name):
    metric = next(
        metric
        for scope_metrics in metrics_data.resource_metrics[0].scope_metrics
        for metric in scope_metrics.metrics
        if metric.name == stream_name
    )
    return {tuple(sorted(point.attributes.items())): point.value for point in metric.data.data_points}


class CardinalityBudgetAccountingTest(TestCase):
    # pylint: disable=too-many-locals,too-many-statements
    def test_two_views_delta_failure_and_cumulative_reconciliation(self):
        accountant = CardinalityAccountant(budgets=_BUDGETS)
        delta_reader = ScriptedReportReader(
            reader_name="delta",
            accountant=accountant,
            fail_first=True,
            preferred_temporality={Counter: AggregationTemporality.DELTA},
        )
        cumulative_reader = ScriptedReportReader(
            reader_name="cumulative",
            accountant=accountant,
        )
        provider = MeterProvider(
            metric_readers=[delta_reader, cumulative_reader],
            views=_views(),
        )
        counter = provider.get_meter("billing").create_counter("requests")

        first_measurements = [
            (1, {"service": "api", "region": "cn", "route": "/a"}),
            (1, {"service": "api", "region": "cn", "route": "/b"}),
            (1, {"service": "web", "region": "us", "route": "/c"}),
        ]
        for value, attributes in first_measurements:
            counter.add(value, attributes)

        delta_before = _occupancy_by_stream(provider, delta_reader, "delta")
        cumulative_before = _occupancy_by_stream(provider, cumulative_reader, "cumulative")

        self.assertEqual((delta_before[_WIDE].admitted_series, delta_before[_WIDE].overflow_series), (2, 1))
        self.assertEqual(delta_before[_WIDE].active_series, 3)
        self.assertTrue(delta_before[_WIDE].reset_on_collect)
        self.assertEqual(
            (delta_before[_NARROW].admitted_series, delta_before[_NARROW].overflow_series),
            (2, 0),
        )
        self.assertEqual(delta_before[_NARROW].active_series, 2)
        self.assertTrue(delta_before[_NARROW].reset_on_collect)
        self.assertEqual(cumulative_before[_WIDE].active_series, 3)
        self.assertEqual(cumulative_before[_NARROW].active_series, 2)
        self.assertFalse(cumulative_before[_WIDE].reset_on_collect)

        with self.assertRaisesRegex(RuntimeError, "report failed after collect"):
            delta_reader.collect()

        delta_after_failure = _occupancy_by_stream(provider, delta_reader, "delta")
        cumulative_after_delta_collect = _occupancy_by_stream(provider, cumulative_reader, "cumulative")

        self.assertEqual(delta_after_failure[_WIDE].active_series, 0)
        self.assertEqual(delta_after_failure[_NARROW].active_series, 0)
        self.assertEqual(cumulative_after_delta_collect[_WIDE].active_series, 3)
        self.assertEqual(cumulative_after_delta_collect[_NARROW].active_series, 2)
        self.assertEqual(delta_reader.received, [])

        self.assertEqual(len(accountant.failed_reports), 1)
        self.assertEqual(accountant.successful_reports, ())
        failed_report = accountant.failed_reports[0]
        self.assertEqual(failed_report.reader, "delta")
        self.assertFalse(failed_report.succeeded)
        self.assertIn("RuntimeError", failed_report.error)

        failed_wide = failed_report.stream(_WIDE)
        self.assertIs(failed_wide.temporality, AggregationTemporality.DELTA)
        self.assertEqual((failed_wide.admitted.series, failed_wide.admitted.value), (2, 2))
        self.assertEqual((failed_wide.overflow.series, failed_wide.overflow.value), (1, 1))
        self.assertEqual((failed_wide.series, failed_wide.value), (3, 3))
        self.assertTrue(failed_wide.budget_respected)
        self.assertEqual(failed_wide.budget_headroom, 0)

        failed_narrow = failed_report.stream(_NARROW)
        self.assertEqual((failed_narrow.admitted.series, failed_narrow.admitted.value), (2, 3))
        self.assertEqual((failed_narrow.overflow.series, failed_narrow.overflow.value), (0, 0))
        self.assertEqual((failed_narrow.series, failed_narrow.value), (2, 3))

        counter.add(2, {"service": "worker", "region": "eu", "route": "/jobs/42"})
        counter.add(3, {"service": "api", "region": "cn", "route": "/a", "mesh": "regular"})

        delta_with_new_labels = _occupancy_by_stream(provider, delta_reader, "delta")
        cumulative_with_new_labels = _occupancy_by_stream(provider, cumulative_reader, "cumulative")

        self.assertEqual(delta_with_new_labels[_WIDE].active_series, 2)
        self.assertEqual(delta_with_new_labels[_WIDE].overflow_series, 0)
        self.assertEqual(delta_with_new_labels[_NARROW].active_series, 2)
        self.assertEqual(delta_with_new_labels[_NARROW].overflow_series, 0)
        self.assertEqual(
            (cumulative_with_new_labels[_WIDE].admitted_series, cumulative_with_new_labels[_WIDE].overflow_series),
            (2, 1),
        )
        self.assertEqual(cumulative_with_new_labels[_WIDE].active_series, 3)
        self.assertEqual(
            (cumulative_with_new_labels[_NARROW].admitted_series, cumulative_with_new_labels[_NARROW].overflow_series),
            (2, 1),
        )
        self.assertEqual(cumulative_with_new_labels[_NARROW].active_series, 3)

        cumulative_reader.collect()

        self.assertEqual(len(cumulative_reader.received), 1)
        self.assertEqual(len(accountant.successful_reports), 1)
        cumulative_report = accountant.successful_reports[0]
        self.assertEqual(cumulative_report.reader, "cumulative")
        self.assertIs(cumulative_report.stream(_WIDE).temporality, AggregationTemporality.CUMULATIVE)

        cumulative_wide = cumulative_report.stream(_WIDE)
        self.assertEqual((cumulative_wide.admitted.series, cumulative_wide.admitted.value), (2, 5))
        self.assertEqual((cumulative_wide.overflow.series, cumulative_wide.overflow.value), (1, 3))
        self.assertEqual((cumulative_wide.series, cumulative_wide.value), (3, 8))
        self.assertEqual(cumulative_wide.budget, 2)

        cumulative_narrow = cumulative_report.stream(_NARROW)
        self.assertEqual((cumulative_narrow.admitted.series, cumulative_narrow.admitted.value), (2, 6))
        self.assertEqual((cumulative_narrow.overflow.series, cumulative_narrow.overflow.value), (1, 2))
        self.assertEqual((cumulative_narrow.series, cumulative_narrow.value), (3, 8))

        cumulative_data = cumulative_reader.received[0]
        self.assertEqual(
            _point_values_by_attributes(cumulative_data, _WIDE),
            {
                (("region", "cn"), ("route", "/a"), ("service", "api")): 4,
                (("region", "cn"), ("route", "/b"), ("service", "api")): 1,
                ((_OVERFLOW, True),): 3,
            },
        )
        self.assertEqual(
            _point_values_by_attributes(cumulative_data, _NARROW),
            {
                (("region", "cn"), ("service", "api")): 5,
                (("region", "us"), ("service", "web")): 1,
                ((_OVERFLOW, True),): 2,
            },
        )

        cumulative_after_collect = _occupancy_by_stream(provider, cumulative_reader, "cumulative")
        self.assertEqual(cumulative_after_collect[_WIDE].active_series, 3)
        self.assertEqual(cumulative_after_collect[_NARROW].active_series, 3)

        delta_reader.collect()
        self.assertEqual(len(delta_reader.received), 1)
        delta_second_report = accountant.reports[-1]
        self.assertTrue(delta_second_report.succeeded)
        second_wide = delta_second_report.stream(_WIDE)
        second_narrow = delta_second_report.stream(_NARROW)
        self.assertEqual((second_wide.series, second_wide.value), (2, 5))
        self.assertEqual((second_wide.overflow.series, second_wide.overflow.value), (0, 0))
        self.assertEqual((second_narrow.series, second_narrow.value), (2, 5))

        delta_final = _occupancy_by_stream(provider, delta_reader, "delta")
        self.assertEqual(delta_final[_WIDE].active_series, 0)
        self.assertEqual(delta_final[_NARROW].active_series, 0)

        provider.shutdown()

    def test_normal_small_load_uses_exact_projected_series_without_overflow(self):
        accountant = CardinalityAccountant(budgets={_WIDE: 10, _NARROW: 10})
        delta_reader = ScriptedReportReader(
            reader_name="delta",
            accountant=accountant,
            preferred_temporality={Counter: AggregationTemporality.DELTA},
        )
        cumulative_reader = ScriptedReportReader(
            reader_name="cumulative",
            accountant=accountant,
        )
        provider = MeterProvider(
            metric_readers=[delta_reader, cumulative_reader],
            views=_views(budget=10),
        )
        counter = provider.get_meter("billing").create_counter("requests")

        for attributes in (
            {"service": "api", "region": "cn", "route": "/a"},
            {"service": "api", "region": "cn", "route": "/b"},
            {"service": "web", "region": "us", "route": "/c"},
        ):
            counter.add(1, attributes)

        delta_reader.collect()
        cumulative_reader.collect()

        self.assertEqual(len(accountant.reports), 2)
        for report in accountant.reports:
            self.assertTrue(report.succeeded)
            for stream in report.streams:
                self.assertTrue(stream.budget_respected)
                self.assertEqual(stream.budget_headroom, 7 if stream.metric == _WIDE else 8)
                self.assertEqual(stream.overflow.series, 0)
                self.assertEqual(stream.overflow.value, 0)

        delta_report = next(report for report in accountant.reports if report.reader == "delta")
        self.assertEqual((delta_report.stream(_WIDE).series, delta_report.stream(_WIDE).value), (3, 3))
        self.assertEqual((delta_report.stream(_NARROW).series, delta_report.stream(_NARROW).value), (2, 3))

        delta_occupancy = _occupancy_by_stream(provider, delta_reader, "delta")
        cumulative_occupancy = _occupancy_by_stream(provider, cumulative_reader, "cumulative")
        self.assertEqual(delta_occupancy[_WIDE].active_series, 0)
        self.assertEqual(delta_occupancy[_NARROW].active_series, 0)
        self.assertEqual(cumulative_occupancy[_WIDE].active_series, 3)
        self.assertEqual(cumulative_occupancy[_NARROW].active_series, 2)

        provider.shutdown()
