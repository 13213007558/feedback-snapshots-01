# SPDX-License-Identifier: Apache-2.0
"""Time-boxed approval for cross-signal diagnostic correlation.

The OpenTelemetry SDK keeps trace, log, and metric/exemplar pipelines independent.
During a compliance incident, an application may nevertheless need one approved
decision that makes all three public artifacts joinable for a short interval.

This module implements an opt-in publication boundary:

* internal SDK objects and exporters are untouched and keep their ordinary IDs;
* public JSON projections receive the same ``correlation_id`` only while the
  decision that was current when the telemetry was created is active;
* rotating or expiring a decision seals controlled in-memory public documents by
  removing the correlation attribute and raw trace/span identifiers.

Already-dispatched external exports cannot be recalled; this boundary applies to
documents published through :class:`PublicCorrelationBook`.
"""

from __future__ import annotations

import copy
import json
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from time import time
from typing import Any, Literal

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import (
    LogRecordExporter,
    LogRecordExportResult,
)
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import format_span_id, format_trace_id

SignalName = Literal["trace", "log", "metric_exemplar"]

CORRELATION_ID_ATTRIBUTE = "diagnostic.correlation.id"
DECISION_ID_ATTRIBUTE = "diagnostic.correlation.decision_id"
EPOCH_ATTRIBUTE = "diagnostic.correlation.epoch"

ALL_SIGNALS: frozenset[str] = frozenset(("trace", "log", "metric_exemplar"))

_CORRELATION_ATTRIBUTE_KEYS = frozenset(
    (
        CORRELATION_ID_ATTRIBUTE,
        DECISION_ID_ATTRIBUTE,
        EPOCH_ATTRIBUTE,
    )
)
_IDENTIFIER_KEYS = frozenset(
    (
        "trace_id",
        "span_id",
        "parent_id",
        "traceid",
        "spanid",
        "parentid",
    )
)


def _new_hex_id() -> str:
    return secrets.token_hex(16)


def _valid_identifier(value: int | None) -> int | None:
    return value if value else None


def _formatted_trace_id(trace_id: int | None) -> str | None:
    trace_id = _valid_identifier(trace_id)
    return f"0x{format_trace_id(trace_id)}" if trace_id is not None else None


def _formatted_span_id(span_id: int | None) -> str | None:
    span_id = _valid_identifier(span_id)
    return f"0x{format_span_id(span_id)}" if span_id is not None else None


@dataclass(frozen=True, slots=True)
class CorrelationDecision:
    """One approved, time-boxed decision shared by all signal types."""

    decision_id: str
    correlation_id: str
    epoch: int
    issued_at: float
    expires_at: float
    ttl_seconds: float
    signals: frozenset[str] = ALL_SIGNALS
    revoked_at: float | None = None

    def is_active(self, at: float | None = None) -> bool:
        instant = time() if at is None else at
        if not (self.issued_at <= instant < self.expires_at):
            return False
        return self.revoked_at is None or instant < self.revoked_at

    def revoke(self, at: float) -> CorrelationDecision:
        return CorrelationDecision(
            decision_id=self.decision_id,
            correlation_id=self.correlation_id,
            epoch=self.epoch,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            ttl_seconds=self.ttl_seconds,
            signals=self.signals,
            revoked_at=at,
        )

    def attributes(self) -> dict[str, str | int]:
        return {
            CORRELATION_ID_ATTRIBUTE: self.correlation_id,
            DECISION_ID_ATTRIBUTE: self.decision_id,
            EPOCH_ATTRIBUTE: self.epoch,
        }


# Readable aliases for callers modeling the approval rather than the timer.
ApprovedCorrelation = CorrelationDecision
CorrelationGrant = CorrelationDecision


class CorrelationWindow:
    """Issues and rotates the single decision used by public artifacts."""

    def __init__(
        self,
        ttl_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = time,
        id_factory: Callable[[], str] = _new_hex_id,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._id_factory = id_factory
        self._decisions: list[CorrelationDecision] = []

    @property
    def current(self) -> CorrelationDecision | None:
        return self._decisions[-1] if self._decisions else None

    @property
    def history(self) -> tuple[CorrelationDecision, ...]:
        return tuple(self._decisions)

    def decision_for_epoch(self, epoch: int) -> CorrelationDecision | None:
        for decision in self._decisions:
            if decision.epoch == epoch:
                return decision
        return None

    def open(
        self,
        *,
        at: float | None = None,
        ttl_seconds: float | None = None,
        correlation_id: str | None = None,
        decision_id: str | None = None,
        signals: frozenset[str] = ALL_SIGNALS,
    ) -> CorrelationDecision:
        instant = self.clock() if at is None else at
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValueError("ttl_seconds must be positive")

        current = self.current
        epoch = current.epoch + 1 if current is not None else 1
        suffix = self._id_factory()
        decision = CorrelationDecision(
            decision_id=decision_id or f"decision-{epoch}-{suffix}",
            correlation_id=correlation_id or f"correlation-{epoch}-{suffix}",
            epoch=epoch,
            issued_at=instant,
            expires_at=instant + ttl,
            ttl_seconds=ttl,
            signals=signals,
        )
        self._decisions.append(decision)
        return decision

    def rotate(
        self,
        *,
        at: float | None = None,
        ttl_seconds: float | None = None,
        correlation_id: str | None = None,
        decision_id: str | None = None,
    ) -> CorrelationDecision:
        """Open the next group's decision without relabelling old records.

        The previous decision remains usable for records already bound to it
        until that decision expires or is explicitly revoked.
        """

        return self.open(
            at=at,
            ttl_seconds=ttl_seconds,
            correlation_id=correlation_id,
            decision_id=decision_id,
        )

    def expire(
        self,
        at: float | None = None,
        *,
        epoch: int | None = None,
    ) -> CorrelationDecision | None:
        instant = self.clock() if at is None else at
        if epoch is not None:
            for index, decision in enumerate(self._decisions):
                if decision.epoch == epoch:
                    revoked = decision if decision.revoked_at is not None else decision.revoke(instant)
                    self._decisions[index] = revoked
                    return revoked
            return None

        current = self.current
        if current is None or current.revoked_at is not None:
            return current
        revoked = current.revoke(instant)
        self._decisions[-1] = revoked
        return revoked

    def revoke(self, decision: CorrelationDecision, at: float | None = None) -> CorrelationDecision:
        instant = self.clock() if at is None else at
        return self.expire(instant, epoch=decision.epoch) or decision.revoke(instant)


CorrelationAuthority = CorrelationWindow
DiagnosticCorrelationWindow = CorrelationWindow


class CorrelationRegistry:
    """Maps ordinary internal trace IDs to the decision approved for them."""

    def __init__(self, window: CorrelationWindow | None = None) -> None:
        self.window = window
        self._decisions_by_trace_id: dict[int, CorrelationDecision] = {}

    def bind_trace_id(
        self,
        trace_id: int,
        decision: CorrelationDecision | None = None,
    ) -> CorrelationDecision:
        selected = decision or (self.window.current if self.window else None)
        if selected is None:
            raise ValueError("an active CorrelationDecision is required")
        trace_id = _valid_identifier(trace_id)
        if trace_id is None:
            raise ValueError("a valid non-zero trace_id is required")
        self._decisions_by_trace_id[trace_id] = selected
        return selected

    def bind_span(
        self,
        span: ReadableSpan,
        decision: CorrelationDecision | None = None,
    ) -> CorrelationDecision:
        context = span.get_span_context()
        if context is None:
            raise ValueError("span has no SpanContext")
        return self.bind_trace_id(context.trace_id, decision)

    def decision_for_trace_id(self, trace_id: int | None) -> CorrelationDecision | None:
        trace_id = _valid_identifier(trace_id)
        if trace_id is None:
            return None
        return self._decisions_by_trace_id.get(trace_id)


@dataclass(slots=True)
class PublicArtifact:
    signal: SignalName
    epoch: int | None
    payload: dict[str, Any]
    published_at: float
    trace_id: int | None = None
    span_id: int | None = None
    correlation_id: str | None = None
    sealed: bool = False
    decision: CorrelationDecision | None = field(default=None, repr=False, compare=False)


def _secret_values(
    decision: CorrelationDecision | None,
    trace_id: int | None = None,
    span_id: int | None = None,
) -> set[str]:
    secrets: set[str] = set()
    if decision is not None:
        secrets.update((decision.correlation_id, decision.decision_id))
    trace_id = _valid_identifier(trace_id)
    span_id = _valid_identifier(span_id)
    if trace_id is not None:
        formatted = format_trace_id(trace_id)
        secrets.update((formatted, f"0x{formatted}", str(trace_id)))
    if span_id is not None:
        formatted = format_span_id(span_id)
        secrets.update((formatted, f"0x{formatted}", str(span_id)))
    secrets.discard("")
    secrets.discard("0")
    return secrets


def redact_public_payload(
    payload: dict[str, Any],
    decision: CorrelationDecision | None = None,
    *,
    trace_id: int | None = None,
    span_id: int | None = None,
) -> dict[str, Any]:
    """Remove correlation attributes and raw identifiers from a JSON payload."""

    secrets = _secret_values(decision, trace_id, span_id)

    def scrub(value: Any, key: str | None = None) -> Any:
        if key is not None and key in _CORRELATION_ATTRIBUTE_KEYS:
            return None
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for child_key, child_value in value.items():
                if child_key in _CORRELATION_ATTRIBUTE_KEYS:
                    continue
                if (
                    isinstance(child_key, str)
                    and child_key.lower() in _IDENTIFIER_KEYS
                    and child_value not in (None, "", 0)
                ):
                    result[child_key] = None
                    continue
                scrubbed = scrub(child_value, child_key if isinstance(child_key, str) else None)
                if scrubbed is not None:
                    result[child_key] = scrubbed
            return result
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, tuple):
            return tuple(scrub(item) for item in value)
        if isinstance(value, str):
            result = value
            for secret in secrets:
                if secret in result:
                    result = result.replace(secret, "")
            return result
        return value

    redacted = scrub(payload)
    return redacted if isinstance(redacted, dict) else {}


def correlation_id_of(artifact_or_payload: PublicArtifact | dict[str, Any]) -> str | None:
    payload = getattr(artifact_or_payload, "payload", artifact_or_payload)
    if not isinstance(payload, dict):
        return None
    for container_name in ("attributes", "filtered_attributes"):
        attributes = payload.get(container_name)
        if isinstance(attributes, dict):
            value = attributes.get(CORRELATION_ID_ATTRIBUTE)
            if isinstance(value, str):
                return value
    return None


def can_pair(
    left: PublicArtifact | dict[str, Any],
    right: PublicArtifact | dict[str, Any],
) -> bool:
    left_id = correlation_id_of(left)
    right_id = correlation_id_of(right)
    return left_id is not None and left_id == right_id


class PublicCorrelationBook:
    """In-memory store of policy-projected public telemetry documents."""

    def __init__(
        self,
        window: CorrelationWindow | None = None,
        registry: CorrelationRegistry | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.window = window or CorrelationWindow(clock=clock or time)
        self.clock = clock or self.window.clock
        self.registry = registry or CorrelationRegistry(self.window)
        if self.registry.window is None:
            self.registry.window = self.window
        self._artifacts: list[PublicArtifact] = []

    def _at(self, at: float | None) -> float:
        return self.clock() if at is None else at

    def _decision(
        self,
        decision: CorrelationDecision | None,
        trace_id: int | None,
    ) -> CorrelationDecision | None:
        if decision is not None:
            return decision
        return self.registry.decision_for_trace_id(trace_id)

    def _publish(
        self,
        signal: SignalName,
        payload: dict[str, Any],
        *,
        at: float | None,
        trace_id: int | None,
        span_id: int | None,
        decision: CorrelationDecision | None,
    ) -> PublicArtifact:
        instant = self._at(at)
        selected = self._decision(decision, trace_id)
        trace_id = _valid_identifier(trace_id)
        span_id = _valid_identifier(span_id)
        active = selected is not None and selected.is_active(instant)

        if active and selected is not None:
            attributes = payload.get("attributes")
            if not isinstance(attributes, dict):
                attributes = {}
            attributes.update(selected.attributes())
            payload["attributes"] = attributes
            correlation_id = selected.correlation_id
            epoch = selected.epoch
        else:
            payload = redact_public_payload(
                payload,
                selected,
                trace_id=trace_id,
                span_id=span_id,
            )
            correlation_id = None
            epoch = selected.epoch if selected is not None else None

        artifact = PublicArtifact(
            signal=signal,
            epoch=epoch,
            payload=payload,
            published_at=instant,
            trace_id=trace_id,
            span_id=span_id,
            correlation_id=correlation_id,
            decision=selected,
        )
        self._artifacts.append(artifact)
        return artifact

    def publish_span(
        self,
        span: ReadableSpan,
        decision: CorrelationDecision | None = None,
        *,
        at: float | None = None,
    ) -> PublicArtifact:
        context = span.get_span_context()
        trace_id = _valid_identifier(context.trace_id if context else None)
        span_id = _valid_identifier(context.span_id if context else None)
        selected = decision or self.registry.decision_for_trace_id(trace_id)
        if selected is not None and trace_id is not None:
            self.registry.bind_trace_id(trace_id, selected)
        payload = json.loads(span.to_json())
        return self._publish(
            "trace",
            payload,
            at=at,
            trace_id=trace_id,
            span_id=span_id,
            decision=selected,
        )

    def publish_log(
        self,
        record: ReadableLogRecord,
        decision: CorrelationDecision | None = None,
        *,
        at: float | None = None,
    ) -> PublicArtifact:
        log_record = record.log_record
        trace_id = _valid_identifier(getattr(log_record, "trace_id", None))
        span_id = _valid_identifier(getattr(log_record, "span_id", None))
        payload = json.loads(record.to_json())
        return self._publish(
            "log",
            payload,
            at=at,
            trace_id=trace_id,
            span_id=span_id,
            decision=decision,
        )

    def publish_exemplar(
        self,
        exemplar: Any,
        decision: CorrelationDecision | None = None,
        *,
        at: float | None = None,
    ) -> PublicArtifact:
        trace_id = _valid_identifier(getattr(exemplar, "trace_id", None))
        span_id = _valid_identifier(getattr(exemplar, "span_id", None))
        payload = {
            "value": exemplar.value,
            "time_unix_nano": exemplar.time_unix_nano,
            "filtered_attributes": dict(getattr(exemplar, "filtered_attributes", None) or {}),
            "trace_id": _formatted_trace_id(trace_id),
            "span_id": _formatted_span_id(span_id),
        }
        return self._publish(
            "metric_exemplar",
            payload,
            at=at,
            trace_id=trace_id,
            span_id=span_id,
            decision=decision,
        )

    def publish_metrics_data(
        self,
        metrics_data: Any,
        decision: CorrelationDecision | None = None,
        *,
        at: float | None = None,
    ) -> tuple[PublicArtifact, ...]:
        published: list[PublicArtifact] = []
        for resource_metrics in getattr(metrics_data, "resource_metrics", ()):  # noqa: SIM117
            for scope_metrics in getattr(resource_metrics, "scope_metrics", ()):
                for metric in getattr(scope_metrics, "metrics", ()):
                    data = getattr(metric, "data", None)
                    for point in getattr(data, "data_points", ()) or ():
                        exemplars = getattr(point, "exemplars", ()) or ()
                        for exemplar in exemplars:
                            published.append(self.publish_exemplar(exemplar, decision, at=at))
        return tuple(published)

    def rotate(
        self,
        *,
        at: float | None = None,
        ttl_seconds: float | None = None,
        correlation_id: str | None = None,
        decision_id: str | None = None,
    ) -> CorrelationDecision:
        instant = self._at(at)
        decision = self.window.rotate(
            at=instant,
            ttl_seconds=ttl_seconds,
            correlation_id=correlation_id,
            decision_id=decision_id,
        )
        self.seal_expired(instant)
        return decision

    def expire(self, at: float | None = None, *, epoch: int | None = None) -> None:
        instant = self._at(at)
        self.window.expire(instant, epoch=epoch)
        self.seal_expired(instant)

    def seal_expired(self, at: float | None = None) -> None:
        instant = self._at(at)
        for artifact in self._artifacts:
            decision = self.window.decision_for_epoch(artifact.epoch or -1)
            if decision is None:
                decision = artifact.decision
            if decision is None or decision.is_active(instant):
                continue
            artifact.payload = redact_public_payload(
                artifact.payload,
                decision,
                trace_id=artifact.trace_id,
                span_id=artifact.span_id,
            )
            artifact.correlation_id = None
            artifact.sealed = True

    @property
    def artifacts(self) -> tuple[PublicArtifact, ...]:
        return tuple(self._artifacts)

    def documents(self, signal: SignalName | None = None) -> tuple[dict[str, Any], ...]:
        return tuple(
            copy.deepcopy(artifact.payload)
            for artifact in self._artifacts
            if signal is None or artifact.signal == signal
        )

    def json_documents(self) -> str:
        return json.dumps(self.documents(), sort_keys=True, default=str)

    def correlation_ids(self) -> tuple[str, ...]:
        return tuple(
            correlation_id
            for artifact in self._artifacts
            if (correlation_id := correlation_id_of(artifact)) is not None
        )

    def contains_value(self, value: str) -> bool:
        return value in self.json_documents()

    def pair_groups(self) -> dict[tuple[int | None, str], dict[str, PublicArtifact]]:
        groups: dict[tuple[int | None, str], dict[str, PublicArtifact]] = {}
        for artifact in self._artifacts:
            correlation_id = correlation_id_of(artifact)
            if correlation_id is None:
                continue
            groups.setdefault((artifact.epoch, correlation_id), {})[artifact.signal] = artifact
        return groups

    def pairing_report(self) -> dict[str, Any]:
        groups = self.pair_groups()
        active_pairs: list[dict[str, Any]] = []
        for (epoch, correlation_id), signals in groups.items():
            active_pairs.append(
                {
                    "epoch": epoch,
                    "correlation_id": correlation_id,
                    "signals": sorted(signals),
                    "all_three_signals": ALL_SIGNALS.issubset(signals),
                }
            )
        return {
            "active_groups": active_pairs,
            "public_correlation_ids": list(self.correlation_ids()),
            "artifact_count": len(self._artifacts),
        }


class CorrelatedSpanExporter(SpanExporter):
    """Span exporter that stores only policy-projected public documents."""

    def __init__(self, book: PublicCorrelationBook) -> None:
        self._book = book
        self._stopped = False

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self._stopped:
            return SpanExportResult.FAILURE
        for span in spans:
            self._book.publish_span(span)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self._stopped = True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class CorrelatedLogRecordExporter(LogRecordExporter):
    """Log exporter that applies the shared decision at actual collection time."""

    def __init__(self, book: PublicCorrelationBook) -> None:
        self._book = book
        self._stopped = False

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        if self._stopped:
            return LogRecordExportResult.FAILURE
        for record in batch:
            self._book.publish_log(record)
        return LogRecordExportResult.SUCCESS

    def shutdown(self) -> None:
        self._stopped = True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


# Deprecated-style alias matching OTel's former LogExporter naming.
CorrelatedLogExporter = CorrelatedLogRecordExporter
