# SPDX-License-Identifier: Apache-2.0

import copy

import pytest
from opentelemetry import context
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider as SdkLoggerProvider
from opentelemetry.sdk._logs.export import (
    BatchLogRecordProcessor,
    InMemoryLogRecordExporter,
)
from opentelemetry.sdk.diagnostic_correlation import (
    CorrelatedLogRecordExporter,
    CorrelatedSpanExporter,
    CorrelationWindow,
    PublicCorrelationBook,
    can_pair,
    correlation_id_of,
)
from opentelemetry.sdk.metrics import MeterProvider as SdkMeterProvider
from opentelemetry.sdk.metrics._internal.exemplar import (
    AlwaysOnExemplarFilter,
    SimpleFixedSizeExemplarReservoir,
)
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider as SdkTracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import format_span_id, format_trace_id


class FakeClock:
    def __init__(self) -> None:
        self.instant = 0.0

    def __call__(self) -> float:
        return self.instant

    def advance(self, seconds: float) -> float:
        self.instant += seconds
        return self.instant


def _exemplar_for_current_span(reservoir):
    reservoir.offer(1.25, 1_700_000_000_000_000_000, {"sample": "measurement"}, context.get_current())
    exemplars = reservoir.collect({})
    assert len(exemplars) == 1
    return exemplars[0]


def _assert_identifier_fields_are_null(value):
    identifier_keys = {"trace_id", "span_id", "parent_id"}
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in identifier_keys:
                assert child is None
            else:
                _assert_identifier_fields_are_null(child)
    elif isinstance(value, list):
        for child in value:
            _assert_identifier_fields_are_null(child)


def test_two_telemetry_groups_keep_approval_scoped_and_remove_old_public_ids():
    clock = FakeClock()
    window = CorrelationWindow(ttl_seconds=10, clock=clock)
    book = PublicCorrelationBook(window, clock=clock)

    clock.advance(1)
    decision_a = window.open(
        at=clock(),
        correlation_id="approved-correlation-a",
        decision_id="approved-decision-a",
    )

    tracer_provider = SdkTracerProvider()
    raw_span_exporter = InMemorySpanExporter()
    tracer_provider.add_span_processor(SimpleSpanProcessor(raw_span_exporter))
    tracer_provider.add_span_processor(SimpleSpanProcessor(CorrelatedSpanExporter(book)))
    tracer = tracer_provider.get_tracer("diagnostic-correlation-test")

    raw_log_exporter = InMemoryLogRecordExporter()
    batch_options = {
        "schedule_delay_millis": 600_000,
        "max_export_batch_size": 10,
        "max_queue_size": 100,
    }
    logger_provider = SdkLoggerProvider()
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(raw_log_exporter, **batch_options))
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(CorrelatedLogRecordExporter(book), **batch_options)
    )
    otel_logger = logger_provider.get_logger("diagnostic-correlation-test")

    reservoir_a = SimpleFixedSizeExemplarReservoir(1)
    with tracer.start_as_current_span("group-a") as span_a:
        trace_a = span_a.get_span_context().trace_id
        span_a_id = span_a.get_span_context().span_id
        book.registry.bind_span(span_a, decision_a)
        exemplar_a = _exemplar_for_current_span(reservoir_a)
        assert exemplar_a.trace_id == trace_a
        otel_logger.emit(
            body="old log delayed until after rotation",
            severity_number=SeverityNumber.INFO,
        )

    active_span_a = copy.deepcopy(book.documents("trace")[0])
    exemplar_a_artifact = book.publish_exemplar(exemplar_a, at=clock())
    active_exemplar_a = copy.deepcopy(exemplar_a_artifact.payload)
    assert correlation_id_of(active_span_a) == decision_a.correlation_id
    assert correlation_id_of(active_exemplar_a) == decision_a.correlation_id

    # Rotation opens group B while group A's short window is still valid.
    # The first log remains queued through this rotation.
    clock.advance(4)
    decision_b = book.rotate(
        at=clock(),
        ttl_seconds=10,
        correlation_id="approved-correlation-b",
        decision_id="approved-decision-b",
    )

    reservoir_b = SimpleFixedSizeExemplarReservoir(1)
    with tracer.start_as_current_span("group-b") as span_b:
        trace_b = span_b.get_span_context().trace_id
        span_b_id = span_b.get_span_context().span_id
        book.registry.bind_span(span_b, decision_b)
        exemplar_b = _exemplar_for_current_span(reservoir_b)
        otel_logger.emit(
            body="current group b log",
            severity_number=SeverityNumber.INFO,
        )

    active_exemplar_b_artifact = book.publish_exemplar(exemplar_b, at=clock())

    # Collection happens now: the batch contains both the delayed old log and
    # the current group-B log. Export time must not relabel the old record.
    assert logger_provider.force_flush(5_000) is True
    raw_records = raw_log_exporter.get_finished_logs()
    assert len(raw_records) == 2
    raw_logs = {record.log_record.body: record for record in raw_records}
    raw_old_log = raw_logs["old log delayed until after rotation"]
    raw_new_log = raw_logs["current group b log"]
    assert raw_old_log.log_record.trace_id == trace_a
    assert raw_new_log.log_record.trace_id == trace_b

    public_logs = {document["body"]: document for document in book.documents("log")}
    old_log_document = public_logs["old log delayed until after rotation"]
    new_log_document = public_logs["current group b log"]
    old_log_artifact = next(
        artifact
        for artifact in book.artifacts
        if artifact.signal == "log" and artifact.payload["body"] == old_log_document["body"]
    )
    new_log_artifact = next(
        artifact
        for artifact in book.artifacts
        if artifact.signal == "log" and artifact.payload["body"] == new_log_document["body"]
    )

    trace_a_artifact = next(
        artifact for artifact in book.artifacts if artifact.signal == "trace" and artifact.epoch == 1
    )
    trace_b_artifact = next(
        artifact for artifact in book.artifacts if artifact.signal == "trace" and artifact.epoch == 2
    )

    # After rotation but before A expires, the delayed log keeps decision A and
    # can still join the old trace/exemplar. It must not be relabelled into B.
    assert correlation_id_of(old_log_document) == decision_a.correlation_id
    assert can_pair(old_log_artifact, trace_a_artifact)
    assert can_pair(old_log_artifact, exemplar_a_artifact)
    assert can_pair(trace_a_artifact, exemplar_a_artifact)

    # Group B's trace/log/exemplar share the second approval.
    assert can_pair(trace_b_artifact, new_log_artifact)
    assert can_pair(new_log_artifact, active_exemplar_b_artifact)
    assert can_pair(trace_b_artifact, active_exemplar_b_artifact)

    # No A/B cross-window pairing is possible.
    assert not can_pair(old_log_artifact, new_log_artifact)
    assert not can_pair(old_log_artifact, active_exemplar_b_artifact)
    assert not can_pair(old_log_artifact, trace_b_artifact)
    assert not can_pair(trace_a_artifact, trace_b_artifact)
    assert sorted(book.correlation_ids()) == sorted([decision_a.correlation_id] * 3 + [decision_b.correlation_id] * 3)
    groups = book.pair_groups()
    assert set(groups[(1, decision_a.correlation_id)]) == {
        "trace",
        "log",
        "metric_exemplar",
    }
    assert set(groups[(2, decision_b.correlation_id)]) == {
        "trace",
        "log",
        "metric_exemplar",
    }

    # When A's window expires, only A's identifiers are sealed; B remains active.
    clock.advance(6)
    assert clock() == decision_a.expires_at
    book.seal_expired(at=clock())
    assert decision_a.correlation_id not in book.correlation_ids()
    assert book.correlation_ids() == (decision_b.correlation_id,) * 3
    assert correlation_id_of(book.artifacts[0]) is None
    assert not can_pair(old_log_artifact, trace_a_artifact)
    assert can_pair(trace_b_artifact, new_log_artifact)
    assert book.pair_groups() == {(2, decision_b.correlation_id): groups[(2, decision_b.correlation_id)]}

    # Expiry seals the remaining active group-B public projections.
    clock.advance(5)
    book.expire(at=clock())
    assert book.correlation_ids() == ()
    assert book.pair_groups() == {}

    public_text = book.json_documents()
    old_secret_values = [
        decision_a.correlation_id,
        decision_a.decision_id,
        decision_b.correlation_id,
        decision_b.decision_id,
        format_trace_id(trace_a),
        f"0x{format_trace_id(trace_a)}",
        str(trace_a),
        format_span_id(span_a_id),
        f"0x{format_span_id(span_a_id)}",
        str(span_a_id),
        format_trace_id(trace_b),
        f"0x{format_trace_id(trace_b)}",
        str(trace_b),
        format_span_id(span_b_id),
        f"0x{format_span_id(span_b_id)}",
        str(span_b_id),
    ]
    for secret in old_secret_values:
        assert secret not in public_text
    for document in book.documents():
        _assert_identifier_fields_are_null(document)
    assert "redacted-identifier" not in public_text

    # The raw SDK records remain complete for ordinary internal operation.
    assert raw_old_log.log_record.trace_id == trace_a
    assert raw_old_log.log_record.span_id == span_a_id
    assert decision_a.correlation_id not in raw_old_log.to_json()
    assert f"0x{format_trace_id(trace_a)}" in raw_old_log.to_json()
    assert span_a.get_span_context().trace_id == trace_a
    assert exemplar_a.trace_id == trace_a
    raw_spans = raw_span_exporter.get_finished_spans()
    assert len(raw_spans) == 2
    assert {span.get_span_context().trace_id for span in raw_spans} == {trace_a, trace_b}
    assert f"0x{format_trace_id(trace_a)}" in raw_spans[0].to_json()

    report = book.pairing_report()
    assert report["public_correlation_ids"] == []
    assert report["active_groups"] == []

    logger_provider.shutdown()
    tracer_provider.shutdown()


def test_window_requires_positive_ttl():
    with pytest.raises(ValueError, match="ttl_seconds"):
        CorrelationWindow(ttl_seconds=0)


def test_metrics_data_exemplars_are_annotated_and_then_redacted():
    clock = FakeClock()
    window = CorrelationWindow(ttl_seconds=10, clock=clock)
    book = PublicCorrelationBook(window, clock=clock)
    decision = window.open(at=0, correlation_id="metric-correlation", decision_id="metric-decision")

    metric_reader = InMemoryMetricReader()
    meter_provider = SdkMeterProvider(
        metric_readers=[metric_reader],
        exemplar_filter=AlwaysOnExemplarFilter(),
    )
    tracer_provider = SdkTracerProvider()
    meter = meter_provider.get_meter("diagnostic-correlation-metrics")
    histogram = meter.create_histogram("diagnostic.latency")
    tracer = tracer_provider.get_tracer("diagnostic-correlation-metrics")

    with tracer.start_as_current_span("measured") as span:
        trace_id = span.get_span_context().trace_id
        book.registry.bind_span(span, decision)
        histogram.record(4.0, {"outcome": "ok"}, context=context.get_current())

    metrics_data = metric_reader.get_metrics_data()
    artifacts = book.publish_metrics_data(metrics_data, at=1)
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.signal == "metric_exemplar"
    assert correlation_id_of(artifact) == decision.correlation_id
    assert artifact.payload["trace_id"] == f"0x{format_trace_id(trace_id)}"

    book.expire(at=decision.expires_at)
    assert correlation_id_of(artifact) is None
    assert artifact.payload["trace_id"] is None
    assert f"0x{format_trace_id(trace_id)}" not in book.json_documents()

    meter_provider.shutdown()
    tracer_provider.shutdown()
