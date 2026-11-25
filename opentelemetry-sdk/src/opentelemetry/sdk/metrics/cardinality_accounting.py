# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Opt-in reconciliation helpers for metric stream cardinality budgets.

The helpers in this module do not change SDK aggregation. They make the cost of
a collection observable so a service can reconcile exported values, overflow
points, configured per-stream budgets, and the number of live series held by a
reader.

Example usage from a custom reader::

    accountant = CardinalityAccountant({"requests_wide": 2})

    class AccountingReader(MetricReader):
        def _receive_metrics(self, metrics_data, timeout_millis=10_000, **kwargs):
            with accountant.report(metrics_data, reader="delta"):
                deliver_to_server(metrics_data)

Call :func:`snapshot_series_occupancy` around collection to attribute live
series slots to a specific provider and reader.
"""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from time import time_ns
from typing import Any

from opentelemetry.sdk.metrics._internal._view_instrument_match import (
    _OVERFLOW_ATTRIBUTES,
    _OVERFLOW_KEY,
)
from opentelemetry.sdk.metrics._internal.aggregation import AggregationTemporality

_OVERFLOW_ATTRIBUTE_NAME = next(iter(_OVERFLOW_ATTRIBUTES))


@dataclass(frozen=True)
class PointVolume:
    """Volume carried by one class of data points in one metric stream."""

    series: int = 0
    value: int | float = 0
    count: int = 0

    def __add__(self, other: "PointVolume") -> "PointVolume":
        if not isinstance(other, PointVolume):
            return NotImplemented
        return PointVolume(
            series=self.series + other.series,
            value=self.value + other.value,
            count=self.count + other.count,
        )


@dataclass(frozen=True)
class StreamAccount:
    """Cardinality and value accounting for one collected metric stream."""

    reader: str
    scope: str
    metric: str
    temporality: AggregationTemporality
    budget: int | None
    admitted: PointVolume
    overflow: PointVolume

    @property
    def series(self) -> int:
        """Number of exported series, including the overflow series."""
        return self.admitted.series + self.overflow.series

    @property
    def value(self) -> int | float:
        """Sum of admitted and overflow numeric values."""
        return self.admitted.value + self.overflow.value

    @property
    def observation_count(self) -> int:
        """Histogram observation count, including overflow observations."""
        return self.admitted.count + self.overflow.count

    @property
    def budget_respected(self) -> bool:
        """Whether non-overflow series fit the configured budget."""
        return self.budget is None or self.admitted.series <= self.budget

    @property
    def budget_headroom(self) -> int | None:
        """Unused non-overflow slots; zero once a stream is at its budget."""
        if self.budget is None:
            return None
        return max(0, self.budget - self.admitted.series)


@dataclass(frozen=True)
class ReportAccount:
    """Accounting record for one reader collection/report attempt."""

    sequence: int
    reader: str
    succeeded: bool
    error: str | None
    created_ns: int
    streams: tuple[StreamAccount, ...]

    def stream(self, metric: str) -> StreamAccount:
        for stream in self.streams:
            if stream.metric == metric:
                return stream
        raise KeyError(metric)


@dataclass(frozen=True)
class SeriesOccupancy:
    """Live series slots in one reader's storage for one matched View."""

    reader: str
    scope: str
    instrument: str
    stream: str
    temporality: AggregationTemporality
    budget: int
    active_series: int
    overflow_series: int
    reset_on_collect: bool

    @property
    def admitted_series(self) -> int:
        """Live series that retain their original attribute projection."""
        return self.active_series - self.overflow_series

    @property
    def budget_available(self) -> int:
        """Slots that can still admit a new projected attribute set."""
        return max(0, self.budget - self.admitted_series)

    @property
    def at_budget(self) -> bool:
        return self.admitted_series >= self.budget


class CardinalityAccountant:
    """Collects reconcilable report records for opt-in cardinality accounting.

    A single accountant can be shared by several readers. Budget overrides can
    be supplied per report or given to the constructor keyed by metric/View
    stream name.
    """

    def __init__(self, budgets: Mapping[str, int] | None = None) -> None:
        self._budgets = dict(budgets or {})
        self._reports: list[ReportAccount] = []
        self._lock = RLock()
        self._next_sequence = 1

    @property
    def reports(self) -> tuple[ReportAccount, ...]:
        with self._lock:
            return tuple(self._reports)

    @property
    def successful_reports(self) -> tuple[ReportAccount, ...]:
        return tuple(report for report in self.reports if report.succeeded)

    @property
    def failed_reports(self) -> tuple[ReportAccount, ...]:
        return tuple(report for report in self.reports if not report.succeeded)

    def account(
        self,
        metrics_data: Any,
        *,
        reader: str = "reader",
        succeeded: bool = True,
        error: BaseException | str | None = None,
        budgets: Mapping[str, int] | None = None,
    ) -> ReportAccount:
        """Account for a collected batch and its report outcome."""
        resolved_budgets = {**self._budgets, **dict(budgets or {})}
        streams = tuple(_iter_stream_accounts(metrics_data, reader, resolved_budgets))
        error_text = _error_text(error)
        created_ns = time_ns()
        with self._lock:
            account = ReportAccount(
                sequence=self._next_sequence,
                reader=reader,
                succeeded=succeeded,
                error=error_text,
                created_ns=created_ns,
                streams=streams,
            )
            self._next_sequence += 1
            self._reports.append(account)
        return account

    @contextmanager
    def report(
        self,
        metrics_data: Any,
        *,
        reader: str = "reader",
        budgets: Mapping[str, int] | None = None,
    ) -> Iterator[None]:
        """Mark the report block successful, or record a failed attempt.

        The exception is always re-raised after the failed report is recorded.
        """
        try:
            yield
        except Exception as exc:
            self.account(
                metrics_data,
                reader=reader,
                succeeded=False,
                error=exc,
                budgets=budgets,
            )
            raise

        self.account(
            metrics_data,
            reader=reader,
            succeeded=True,
            budgets=budgets,
        )


def snapshot_series_occupancy(
    provider: Any, reader: Any, *, reader_name: str | None = None
) -> tuple[SeriesOccupancy, ...]:
    """Return live series counts for every View matched to a reader.

    This reads SDK-private storage because live occupancy before a collection
    is not represented in exported data. It is a diagnostic snapshot and does
    not mutate aggregation state.
    """
    consumer = provider._measurement_consumer  # pylint: disable=protected-access
    storage = consumer._reader_storages[reader]  # pylint: disable=protected-access
    name = reader_name or type(reader).__name__
    result: list[SeriesOccupancy] = []

    with storage._lock:  # pylint: disable=protected-access
        matches_snapshot = list(
            storage._instrument_view_instrument_matches.items()  # pylint: disable=protected-access
        )
        for instrument, view_matches in matches_snapshot:
            temporality = storage._instrument_class_temporality[instrument.__class__]  # pylint: disable=protected-access
            for view_match in view_matches:
                with view_match._lock:  # pylint: disable=protected-access
                    aggregations = view_match._attributes_aggregation  # pylint: disable=protected-access
                    active_series = len(aggregations)
                    overflow_series = int(_OVERFLOW_KEY in aggregations)
                result.append(
                    SeriesOccupancy(
                        reader=name,
                        scope=instrument.instrumentation_scope.name,
                        instrument=instrument.name,
                        stream=view_match._name,  # pylint: disable=protected-access
                        temporality=temporality,
                        budget=view_match._cardinality_limit,  # pylint: disable=protected-access
                        active_series=active_series,
                        overflow_series=overflow_series,
                        reset_on_collect=view_match._reset_on_collect,  # pylint: disable=protected-access
                    )
                )
    return tuple(result)


def _iter_stream_accounts(
    metrics_data: Any, reader: str, budgets: Mapping[str, int]
) -> Iterator[StreamAccount]:
    if metrics_data is None:
        return

    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            scope_name = scope_metrics.scope.name
            for metric in scope_metrics.metrics:
                admitted = PointVolume()
                overflow = PointVolume()
                temporality = getattr(
                    metric.data,
                    "aggregation_temporality",
                    AggregationTemporality.CUMULATIVE,
                )
                for data_point in metric.data.data_points:
                    cost = _point_volume(data_point)
                    if _is_overflow(data_point):
                        overflow += cost
                    else:
                        admitted += cost

                yield StreamAccount(
                    reader=reader,
                    scope=scope_name,
                    metric=metric.name,
                    temporality=temporality,
                    budget=budgets.get(metric.name),
                    admitted=admitted,
                    overflow=overflow,
                )


def _point_volume(data_point: Any) -> PointVolume:
    if hasattr(data_point, "value"):
        return PointVolume(series=1, value=data_point.value)
    if hasattr(data_point, "count"):
        return PointVolume(
            series=1,
            value=getattr(data_point, "sum", 0) or 0,
            count=data_point.count,
        )
    return PointVolume(series=1)


def _is_overflow(data_point: Any) -> bool:
    attributes = getattr(data_point, "attributes", None) or {}
    return attributes.get(_OVERFLOW_ATTRIBUTE_NAME) is True


def _error_text(error: BaseException | str | None) -> str | None:
    if error is None:
        return None
    if isinstance(error, str):
        return error
    return f"{type(error).__name__}: {error}"
