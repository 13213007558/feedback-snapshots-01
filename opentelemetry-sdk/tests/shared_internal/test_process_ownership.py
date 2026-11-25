# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import Mock

import pytest

from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.process_ownership import (
    ForkRecoveryBoundary,
    ProcessOwnership,
    current_process_ownership,
    process_ownership_context,
)
from opentelemetry.sdk.trace.export import BatchSpanProcessor

SCRIPT = Path(__file__).parent / "scripts" / "process_ownership_fork.py"
fork_required = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")


def _read_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as records_file:
        return [json.loads(line) for line in records_file if line.strip()]


def _run_script(signal: str, mode: str, records_path: Path) -> list[dict]:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--signal",
            signal,
            "--mode",
            mode,
            "--records-path",
            str(records_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    return _read_events(records_path)


@fork_required
@pytest.mark.parametrize("signal", ["logs", "traces"])
def test_fork_keeps_inherited_batch_with_parent_and_acks_each_side_once(tmp_path: Path, signal: str) -> None:
    records_path = tmp_path / f"{signal}-fork.jsonl"
    events = _run_script(signal, "fork", records_path)

    checkpoints = [event for event in events if event["event"] == "checkpoint"]
    recoveries = [event for event in events if event["event"] == "recovery"]
    exports = [event for event in events if event["event"] == "export"]
    acks = [event for event in events if event["event"] == "ack"]
    resumes = [event for event in events if event["event"] == "parent_resume"]

    assert len(checkpoints) == 1
    assert len(recoveries) == 1
    assert len(exports) == 2
    assert len(acks) == 2
    assert len(resumes) == 1

    checkpoint = checkpoints[0]
    recovery = recoveries[0]
    parent_pid = checkpoint["owner_pid"]
    child_pid = recovery["owner_pid"]
    boundary_id = checkpoint["boundary_id"]

    assert checkpoint["admitted_uncommitted_records"] == 3
    assert parent_pid == checkpoint["pid"]
    assert child_pid != parent_pid
    assert recovery["previous_owner_pid"] == parent_pid
    assert recovery["inherited_batch_owner_pid"] == parent_pid
    assert recovery["detached_inherited_records"] == 3
    assert recovery["inherited_batch_finalizer"] == "parent_processor"
    assert recovery["exporter_recovered"] is True
    assert recovery["boundary_id"] == boundary_id

    parent_acks = [ack for ack in acks if ack["owner_pid"] == parent_pid]
    child_acks = [ack for ack in acks if ack["owner_pid"] == child_pid]
    assert len(parent_acks) == 1
    assert len(child_acks) == 1

    parent_ack = parent_acks[0]
    child_ack = child_acks[0]
    assert parent_ack["ack_call"] == 1
    assert child_ack["ack_call"] == 1
    assert parent_ack["write_pid"] == parent_pid
    assert child_ack["write_pid"] == child_pid
    assert parent_ack["owner_generation"] == 0
    assert child_ack["owner_generation"] == 1
    assert parent_ack["boundary_id"] == boundary_id
    assert child_ack["boundary_id"] == boundary_id
    assert parent_ack["labels"] == ["parent-1", "parent-2", "parent-3"]
    assert child_ack["labels"] == ["child-1"]

    labels = Counter(label for export in exports for label in export["labels"])
    assert labels == Counter({"parent-1": 1, "parent-2": 1, "parent-3": 1, "child-1": 1})
    assert all(export["write_pid"] == export["owner_pid"] for export in exports)
    assert all(export["boundary_id"] == boundary_id for export in exports)

    def index_of(predicate) -> int:
        return next(index for index, event in enumerate(events) if predicate(event))

    recovery_index = index_of(lambda event: event["event"] == "recovery")
    child_export_index = index_of(lambda event: event["event"] == "export" and event["owner_pid"] == child_pid)
    child_ack_index = events.index(child_ack)
    resume_index = events.index(resumes[0])
    parent_export_index = index_of(lambda event: event["event"] == "export" and event["owner_pid"] == parent_pid)
    parent_ack_index = events.index(parent_ack)

    assert recovery_index < child_export_index < child_ack_index < resume_index < parent_export_index < parent_ack_index


@pytest.mark.parametrize("signal", ["logs", "traces"])
def test_single_process_control_has_one_owner_and_one_ack(tmp_path: Path, signal: str) -> None:
    records_path = tmp_path / f"{signal}-single.jsonl"
    events = _run_script(signal, "single", records_path)

    checkpoints = [event for event in events if event["event"] == "checkpoint"]
    recoveries = [event for event in events if event["event"] == "recovery"]
    exports = [event for event in events if event["event"] == "export"]
    acks = [event for event in events if event["event"] == "ack"]

    assert len(checkpoints) == 1
    assert len(recoveries) == 0
    assert len(exports) == 1
    assert len(acks) == 1

    checkpoint = checkpoints[0]
    ack = acks[0]
    export = exports[0]
    pid = checkpoint["owner_pid"]

    assert checkpoint["admitted_uncommitted_records"] == 3
    assert checkpoint["owner_generation"] == 0
    assert ack["owner_pid"] == pid
    assert ack["write_pid"] == pid
    assert export["owner_pid"] == pid
    assert ack["ack_call"] == 1
    assert ack["labels"] == ["single-1", "single-2", "single-3"]
    assert ack["boundary_id"] == checkpoint["boundary_id"]


class _OwnershipAwareExporter:
    def bind_process_ownership(self, ownership: ProcessOwnership) -> None:
        pass

    def recover_after_fork(self, boundary: ForkRecoveryBoundary) -> None:
        pass

    def export(self, batch):
        return 0

    def shutdown(self) -> None:
        pass


@pytest.mark.parametrize("processor_class", [BatchLogRecordProcessor, BatchSpanProcessor])
def test_process_ownership_is_explicit_opt_in(processor_class) -> None:
    disabled = processor_class(Mock())
    try:
        assert disabled.process_ownership_enabled is False
    finally:
        disabled.shutdown()

    automatic = processor_class(_OwnershipAwareExporter())
    try:
        assert automatic.process_ownership_enabled is True
    finally:
        automatic.shutdown()

    enabled = processor_class(Mock(), enable_process_ownership=True)
    try:
        assert enabled.process_ownership_enabled is True
        assert enabled.process_ownership.pid == os.getpid()
        checkpoint = enabled.checkpoint_process_ownership()
        assert checkpoint.admitted_uncommitted_records == 0
    finally:
        enabled.shutdown()


def test_process_ownership_context_is_scoped() -> None:
    ownership = ProcessOwnership.current()

    assert current_process_ownership() is None
    with process_ownership_context(ownership) as active:
        assert active is ownership
        assert current_process_ownership() is ownership
    assert current_process_ownership() is None
