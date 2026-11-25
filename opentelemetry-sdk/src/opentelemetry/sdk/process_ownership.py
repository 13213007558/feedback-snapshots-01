# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterator, Protocol, runtime_checkable
from uuid import uuid4

__all__ = [
    "ForkRecoveryBoundary",
    "InheritedBatchFinalizer",
    "PendingBatchCheckpoint",
    "ProcessOwnership",
    "ProcessOwnershipAwareExporter",
    "ProcessOwnershipBoundary",
    "current_process_ownership",
    "process_ownership_context",
]


@dataclass(frozen=True)
class ProcessOwnership:
    """Identity of the process generation that owns a batch processor queue."""

    pid: int
    generation: int
    boundary_id: str
    parent_pid: int | None = None

    @classmethod
    def current(cls) -> ProcessOwnership:
        return cls(pid=os.getpid(), generation=0, boundary_id=uuid4().hex)

    @property
    def owner_id(self) -> str:
        return f"{self.boundary_id}:{self.pid}:{self.generation}"

    def after_fork_in_child(self) -> ProcessOwnership:
        return replace(
            self,
            pid=os.getpid(),
            generation=self.generation + 1,
            parent_pid=os.getppid(),
        )


class InheritedBatchFinalizer(str, Enum):
    """Who finalizes queue items admitted before a fork."""

    PARENT_PROCESSOR = "parent_processor"


@dataclass(frozen=True)
class PendingBatchCheckpoint:
    """Point-in-time count of records admitted but not submitted to an exporter."""

    boundary_id: str
    owner: ProcessOwnership
    admitted_uncommitted_records: int


@dataclass(frozen=True)
class ForkRecoveryBoundary:
    """Recovery result for the forked child's copy of a batch processor."""

    boundary_id: str
    previous_owner: ProcessOwnership
    owner: ProcessOwnership
    detached_inherited_records: int
    inherited_batch_owner_pid: int
    inherited_batch_finalizer: str
    exporter_recovered: bool = False


_current_process_ownership: ContextVar[ProcessOwnership | None] = ContextVar(
    "otel_current_process_ownership", default=None
)


def current_process_ownership() -> ProcessOwnership | None:
    """Return the ownership associated with the current exporter call, if any."""

    return _current_process_ownership.get()


@contextmanager
def process_ownership_context(ownership: ProcessOwnership) -> Iterator[ProcessOwnership]:
    token = _current_process_ownership.set(ownership)
    try:
        yield ownership
    finally:
        _current_process_ownership.reset(token)


class ProcessOwnershipBoundary:
    """Track ownership and the most recent fork recovery for one processor."""

    def __init__(self, ownership: ProcessOwnership | None = None) -> None:
        self._ownership = ownership or ProcessOwnership.current()
        self._checkpoint: PendingBatchCheckpoint | None = None
        self._recovery: ForkRecoveryBoundary | None = None

    @property
    def ownership(self) -> ProcessOwnership:
        return self._ownership

    @property
    def checkpoint(self) -> PendingBatchCheckpoint | None:
        return self._checkpoint

    @property
    def recovery(self) -> ForkRecoveryBoundary | None:
        return self._recovery

    def checkpoint_pending(self, admitted_uncommitted_records: int) -> PendingBatchCheckpoint:
        self._checkpoint = PendingBatchCheckpoint(
            boundary_id=self._ownership.boundary_id,
            owner=self._ownership,
            admitted_uncommitted_records=admitted_uncommitted_records,
        )
        return self._checkpoint

    def recover_in_child(
        self,
        detached_inherited_records: int,
        *,
        exporter_recovered: bool = False,
    ) -> ForkRecoveryBoundary:
        previous_owner = self._ownership
        new_owner = previous_owner.after_fork_in_child()
        recovery = ForkRecoveryBoundary(
            boundary_id=previous_owner.boundary_id,
            previous_owner=previous_owner,
            owner=new_owner,
            detached_inherited_records=detached_inherited_records,
            inherited_batch_owner_pid=previous_owner.pid,
            inherited_batch_finalizer=InheritedBatchFinalizer.PARENT_PROCESSOR.value,
            exporter_recovered=exporter_recovered,
        )
        self._ownership = new_owner
        self._recovery = recovery
        return recovery

    def mark_exporter_recovered(self) -> ForkRecoveryBoundary | None:
        if self._recovery is None:
            return None
        self._recovery = replace(self._recovery, exporter_recovered=True)
        return self._recovery


@runtime_checkable
class ProcessOwnershipAwareExporter(Protocol):
    """Optional exporter hooks for process attribution and fork recovery."""

    def bind_process_ownership(self, ownership: ProcessOwnership) -> None:
        """Bind the current process ownership before exports are processed."""

    def recover_after_fork(self, boundary: ForkRecoveryBoundary) -> None:
        """Reset process-local exporter state after the child's queue is detached."""
