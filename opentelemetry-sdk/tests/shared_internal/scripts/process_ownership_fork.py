# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Process-isolation fixture for batch processor ownership after fork.

The JSON-lines exporter in this module is a real (local, file-backed) exporter.
It writes one record per export call and one acknowledgement when ``export``
returns successfully.  A child process reopens the file in
``recover_after_fork`` so its writes do not rely on the inherited object's PID
or file state.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Sequence

from opentelemetry._logs import LogRecord
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.process_ownership import (
    ForkRecoveryBoundary,
    ProcessOwnership,
    current_process_ownership,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

SCHEDULE_DELAY_MILLIS = 30_000
MAX_EXPORT_BATCH_SIZE = 10
PARENT_LABELS = ("parent-1", "parent-2", "parent-3")
SINGLE_LABELS = ("single-1", "single-2", "single-3")
CHILD_LABEL = "child-1"


class JsonLinesProcessExporter:
    def __init__(self, path: str | Path) -> None:
        self.path = os.fspath(path)
        self._file = open(self.path, "a", encoding="utf-8", buffering=1)
        self._ownership: ProcessOwnership | None = None
        self.export_calls = 0
        self.ack_calls = 0

    def write_event(self, event: dict[str, Any]) -> None:
        event.setdefault("pid", os.getpid())
        self._file.write(json.dumps(event, sort_keys=True) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())

    def bind_process_ownership(self, ownership: ProcessOwnership) -> None:
        self._ownership = ownership

    def recover_after_fork(self, boundary: ForkRecoveryBoundary) -> None:
        self._file.close()
        self._file = open(self.path, "a", encoding="utf-8", buffering=1)
        self._ownership = boundary.owner
        self.export_calls = 0
        self.ack_calls = 0
        self.write_event(
            {
                "event": "recovery",
                "boundary_id": boundary.boundary_id,
                "owner": asdict(boundary.owner),
                "owner_pid": boundary.owner.pid,
                "previous_owner": asdict(boundary.previous_owner),
                "previous_owner_pid": boundary.previous_owner.pid,
                "detached_inherited_records": boundary.detached_inherited_records,
                "inherited_batch_owner_pid": boundary.inherited_batch_owner_pid,
                "inherited_batch_finalizer": boundary.inherited_batch_finalizer,
                "exporter_recovered": True,
            }
        )

    @staticmethod
    def _label(record: Any) -> str:
        name = getattr(record, "name", None)
        if name is not None:
            return str(name)
        body = getattr(record, "body", None)
        if body is not None:
            return str(body)
        log_record = getattr(record, "log_record", None)
        if log_record is not None and getattr(log_record, "body", None) is not None:
            return str(log_record.body)
        raise TypeError(f"Unable to determine telemetry label for {record!r}")

    def export(self, batch: Sequence[Any]) -> int:
        self.export_calls += 1
        context_ownership = current_process_ownership()
        if context_ownership is not None and context_ownership.pid != os.getpid():
            raise RuntimeError("Export ownership PID does not match the exporting process")
        ownership = context_ownership or self._ownership
        if ownership is None:
            raise RuntimeError("Exporter has no process ownership binding")

        labels = [self._label(record) for record in batch]
        self.write_event(
            {
                "event": "export",
                "owner": asdict(ownership),
                "owner_pid": ownership.pid,
                "owner_generation": ownership.generation,
                "boundary_id": ownership.boundary_id,
                "write_pid": os.getpid(),
                "batch_size": len(batch),
                "labels": labels,
                "export_call": self.export_calls,
            }
        )
        self.ack_calls += 1
        self.write_event(
            {
                "event": "ack",
                "owner": asdict(ownership),
                "owner_pid": ownership.pid,
                "owner_generation": ownership.generation,
                "boundary_id": ownership.boundary_id,
                "write_pid": os.getpid(),
                "batch_size": len(batch),
                "labels": labels,
                "ack_call": self.ack_calls,
            }
        )
        return 0

    def shutdown(self) -> None:
        self._file.close()


def build_pipeline(signal: str, records_path: str) -> tuple[Any, Any, JsonLinesProcessExporter, Any]:
    exporter = JsonLinesProcessExporter(records_path)
    if signal == "trace":
        provider = TracerProvider()
        processor = BatchSpanProcessor(
            exporter,
            max_queue_size=100,
            max_export_batch_size=MAX_EXPORT_BATCH_SIZE,
            schedule_delay_millis=SCHEDULE_DELAY_MILLIS,
            export_timeout_millis=5_000,
            enable_process_ownership=True,
        )
        provider.add_span_processor(processor)
        tracer = provider.get_tracer("process-ownership-test")

        def emit_trace(label: str) -> None:
            with tracer.start_as_current_span(label):
                pass

        return provider, processor, exporter, emit_trace

    provider = LoggerProvider()
    processor = BatchLogRecordProcessor(
        exporter,
        max_queue_size=100,
        max_export_batch_size=MAX_EXPORT_BATCH_SIZE,
        schedule_delay_millis=SCHEDULE_DELAY_MILLIS,
        export_timeout_millis=5_000,
        enable_process_ownership=True,
    )
    provider.add_log_record_processor(processor)
    logger = provider.get_logger("process-ownership-test")

    def emit_log(label: str) -> None:
        logger.emit(LogRecord(body=label))

    return provider, processor, exporter, emit_log


def emit_and_checkpoint(
    processor: Any,
    exporter: JsonLinesProcessExporter,
    emit: Any,
    labels: tuple[str, ...],
) -> None:
    for label in labels:
        emit(label)
    checkpoint = processor.checkpoint_process_ownership()
    if checkpoint.admitted_uncommitted_records != len(labels):
        raise RuntimeError(
            f"Expected {len(labels)} admitted records, got " f"{checkpoint.admitted_uncommitted_records}"
        )
    exporter.write_event(
        {
            "event": "checkpoint",
            "owner": asdict(checkpoint.owner),
            "owner_pid": checkpoint.owner.pid,
            "owner_generation": checkpoint.owner.generation,
            "boundary_id": checkpoint.boundary_id,
            "admitted_uncommitted_records": checkpoint.admitted_uncommitted_records,
        }
    )


def run_single(signal: str, records_path: str) -> int:
    _provider, processor, exporter, emit = build_pipeline(signal, records_path)
    emit_and_checkpoint(processor, exporter, emit, SINGLE_LABELS)
    if not processor.force_flush(10_000):
        raise RuntimeError("Single-process force_flush returned False")
    processor.shutdown()
    return 0


def run_fork(signal: str, records_path: str) -> int:
    _provider, processor, exporter, emit = build_pipeline(signal, records_path)
    emit_and_checkpoint(processor, exporter, emit, PARENT_LABELS)
    parent_ownership = processor.process_ownership

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        result: dict[str, Any]
        try:
            emit(CHILD_LABEL)
            ownership = processor.process_ownership
            recovery = processor.process_ownership_boundary.recovery
            if ownership.pid != os.getpid():
                raise RuntimeError("Child ownership PID was not refreshed")
            if ownership.generation != parent_ownership.generation + 1:
                raise RuntimeError("Child ownership generation was not incremented")
            if recovery is None:
                raise RuntimeError("Child did not record a fork recovery boundary")
            if recovery.detached_inherited_records != len(PARENT_LABELS):
                raise RuntimeError("Child detached the wrong number of inherited records")
            if recovery.inherited_batch_owner_pid != parent_ownership.pid:
                raise RuntimeError("Recovery boundary assigned the inherited batch to the wrong PID")
            if not recovery.exporter_recovered:
                raise RuntimeError("Exporter did not complete fork recovery")
            if not processor.force_flush(10_000):
                raise RuntimeError("Child force_flush returned False")
            if exporter.export_calls != 1 or exporter.ack_calls != 1:
                raise RuntimeError("Child exporter did not receive exactly one export and ack")
            result = {"status": "ok", "pid": os.getpid(), "ownership": asdict(ownership)}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            result = {"status": "error", "error": repr(exc)}
        try:
            os.write(write_fd, json.dumps(result).encode("utf-8"))
        finally:
            os.close(write_fd)
            os._exit(0)  # pylint: disable=protected-access

    os.close(write_fd)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_fd, 65_536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_fd)
    child_result = json.loads(b"".join(chunks).decode("utf-8"))
    _, status = os.waitpid(pid, 0)
    if child_result.get("status") != "ok" or status != 0:
        raise RuntimeError(f"Child fork scenario failed: result={child_result!r}, status={status}")

    if processor.process_ownership != parent_ownership:
        raise RuntimeError("Parent process ownership changed after child recovery")
    exporter.write_event({"event": "parent_resume", "owner_pid": os.getpid()})
    if not processor.force_flush(10_000):
        raise RuntimeError("Parent force_flush returned False")
    if exporter.export_calls != 1 or exporter.ack_calls != 1:
        raise RuntimeError("Parent exporter did not receive exactly one export and ack")
    processor.shutdown()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal", choices=("logs", "traces"), required=True)
    parser.add_argument("--mode", choices=("fork", "single"), required=True)
    parser.add_argument("--records-path", required=True)
    args = parser.parse_args()

    if args.mode == "single":
        return run_single(args.signal, args.records_path)
    return run_fork(args.signal, args.records_path)


if __name__ == "__main__":
    sys.exit(main())
