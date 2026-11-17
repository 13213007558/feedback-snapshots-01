"""Durable, minimal per-UID progress records.

This is deliberately not a mail-management system: one JSON document holds one
record per *approved* source UID, plus the fixed mailbox anchors. Every state
transition is written through :meth:`ProgressStore.save` before the next wire
command, so a crash or disconnect always resumes from explicit evidence.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .evidence import MigrationStatus, TERMINAL_STATES, MailboxAnchor


@dataclass
class MigrationRecord:
    """Everything an operator needs to understand one UID without re-discovery."""

    source_uid: int
    status: str = MigrationStatus.PENDING.value
    attempts: int = 0
    # Fixed identity of the message captured before any mutation.
    fingerprint: Optional[dict] = None
    # Server-issued evidence.
    copyuid: Optional[dict] = None          # parsed COPYUID response code
    target_uid: Optional[int] = None
    last_command: Optional[str] = None      # last verb actually put on the wire
    last_error: Optional[str] = None
    review_reason: Optional[str] = None
    # Free-form human audit trail (one entry per state transition).
    log: List[str] = field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        return MigrationStatus(self.status) in TERMINAL_STATES


@dataclass
class JobState:
    """Fixed source/destination identity plus the per-UID records."""

    source: dict
    destination: dict
    records: Dict[str, MigrationRecord] = field(default_factory=dict)

    def anchor(self, which: str) -> MailboxAnchor:
        data = getattr(self, which)
        return MailboxAnchor(**data)


class ProgressStore:
    """Atomic JSON persistence for a :class:`JobState`."""

    def __init__(self, path: str):
        self.path = path
        self.state = self._load() if os.path.exists(path) else None

    def init_job(self, source: MailboxAnchor, destination: MailboxAnchor) -> JobState:
        if self.state is not None:
            raise ValueError(f"job already initialised at {self.path}")
        self.state = JobState(source=asdict(source), destination=asdict(destination))
        self._flush()
        return self.state

    def require_state(self) -> JobState:
        if self.state is None:
            raise ValueError("job not initialised")
        return self.state

    def add_approved_uid(self, uid: int) -> MigrationRecord:
        state = self.require_state()
        key = str(uid)
        if key not in state.records:
            state.records[key] = MigrationRecord(source_uid=uid)
            self._flush()
        return state.records[key]

    def get(self, uid: int) -> Optional[MigrationRecord]:
        return self.require_state().records.get(str(uid))

    def all_records(self) -> List[MigrationRecord]:
        return list(self.require_state().records.values())

    def save(self, record: MigrationRecord, note: str) -> None:
        """Persist a transition. Terminal states become immutable."""
        stored = self.require_state().records.get(str(record.source_uid))
        if stored is not None and stored.is_terminal and stored.status != record.status:
            raise ValueError(
                f"uid {record.source_uid} already terminal ({stored.status}); "
                "manual resolution required"
            )
        record.log.append(note)
        self.require_state().records[str(record.source_uid)] = record
        self._flush()

    def _flush(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        payload = {
            "source": self.state.source,
            "destination": self.state.destination,
            "records": {key: asdict(rec) for key, rec in self.state.records.items()},
        }
        # Atomic replace: a crash never leaves a half-written progress file.
        fd, tmp = tempfile.mkstemp(prefix=".progress-", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise

    def _load(self) -> JobState:
        with open(self.path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        records = {
            key: MigrationRecord(**values) for key, values in payload["records"].items()
        }
        return JobState(source=payload["source"], destination=payload["destination"],
                        records=records)
