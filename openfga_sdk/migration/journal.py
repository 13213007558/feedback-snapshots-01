"""
Durable batch journal for resumable relationship migrations.

The journal records, for every batch, whether the corresponding write has
definitely completed. Because an OpenFGA write is a single transaction, a
batch is atomic on the server side:

* ``PENDING``   - never sent
* ``IN_FLIGHT`` - sent, no definitive response yet
* ``SUCCEEDED`` - the server acknowledged the write; do not resend
* ``FAILED``    - the server rejected the write; nothing was applied

A crash or lost response while a batch is ``IN_FLIGHT`` leaves it in that
state on disk. On recovery the runner reconciles ``IN_FLIGHT`` batches by
reading the store instead of blindly retrying the write.
"""

import enum
import json
import os
import tempfile

from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.migration.tuple_key import tuple_identity


class BatchStatus(str, enum.Enum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class BatchOperation(str, enum.Enum):
    WRITE = "write"
    DELETE = "delete"


class BatchRecord:
    """
    Persisted state of one write batch.

    :param index: Zero-based position of the batch in the migration.
    :param tuples: Relationship tuples belonging to the batch.
    :param status: Current :class:`BatchStatus`.
    :param operation: Whether the batch writes approved tuples or deletes
        revoked tuples.
    :param attempts: Number of write attempts performed.
    :param last_error: Last observed error message, if any.
    """

    def __init__(
        self,
        index: int,
        tuples: list[ClientTuple],
        status: BatchStatus = BatchStatus.PENDING,
        operation: BatchOperation = BatchOperation.WRITE,
        attempts: int = 0,
        last_error: str | None = None,
    ) -> None:
        self.index = index
        self.tuples = list(tuples)
        self.status = status
        self.operation = operation
        self.attempts = attempts
        self.last_error = last_error

    @property
    def identities(self) -> list[str]:
        return [tuple_identity(item) for item in self.tuples]

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "status": self.status.value,
            "operation": self.operation.value,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "tuples": [
                {
                    "user": item.user,
                    "relation": item.relation,
                    "object": item.object,
                }
                for item in self.tuples
            ],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "BatchRecord":
        return cls(
            index=payload["index"],
            status=BatchStatus(payload["status"]),
            operation=BatchOperation(payload.get("operation", BatchOperation.WRITE)),
            attempts=payload.get("attempts", 0),
            last_error=payload.get("last_error"),
            tuples=[ClientTuple(**item) for item in payload.get("tuples", [])],
        )


class MigrationJournal:
    """
    JSON-file backed journal with atomic replacement on every update.

    The journal is the durable memory of the migration. Writes go to a temp
    file in the same directory and are ``os.replace``-d into place so a crash
    never leaves a half-written journal behind.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: str) -> None:
        self.path = path
        self._batches: dict[int, BatchRecord] = {}

    @classmethod
    def initialize(
        cls,
        path: str,
        batches: list[list[ClientTuple]],
        operations: list[BatchOperation] | None = None,
    ) -> "MigrationJournal":
        journal = cls(path)
        journal._batches = {
            index: BatchRecord(
                index=index,
                tuples=tuples,
                operation=(operations[index] if operations else BatchOperation.WRITE),
            )
            for index, tuples in enumerate(batches)
        }
        journal.persist()
        return journal

    @classmethod
    def load(cls, path: str) -> "MigrationJournal":
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)

        if payload.get("schema_version") != cls.SCHEMA_VERSION:
            raise ValueError(
                f"unsupported journal schema version: {payload.get('schema_version')}"
            )

        journal = cls(path)
        journal._batches = {
            record.index: record
            for record in (
                BatchRecord.from_dict(item) for item in payload.get("batches", [])
            )
        }
        return journal

    def records(self) -> list[BatchRecord]:
        return [self._batches[index] for index in sorted(self._batches)]

    def get(self, index: int) -> BatchRecord:
        return self._batches[index]

    def mark_in_flight(self, index: int) -> None:
        record = self._batches[index]
        record.status = BatchStatus.IN_FLIGHT
        record.attempts += 1
        record.last_error = None
        self.persist()

    def mark_succeeded(self, index: int) -> None:
        record = self._batches[index]
        record.status = BatchStatus.SUCCEEDED
        record.last_error = None
        self.persist()

    def mark_failed(self, index: int, error: Exception) -> None:
        record = self._batches[index]
        record.status = BatchStatus.FAILED
        record.last_error = str(error)
        self.persist()

    def reset_to_pending(self, index: int) -> None:
        """
        Move an ``IN_FLIGHT`` batch back to ``PENDING`` after reconciliation
        proves the server never applied it.
        """
        record = self._batches[index]
        record.status = BatchStatus.PENDING
        record.last_error = None
        self.persist()

    def counts(self) -> dict[BatchStatus, int]:
        result = {status: 0 for status in BatchStatus}
        for record in self._batches.values():
            result[record.status] += 1
        return result

    def is_complete(self) -> bool:
        return all(
            record.status == BatchStatus.SUCCEEDED
            for record in self._batches.values()
        )

    def persist(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "batches": [record.to_dict() for record in self.records()],
        }

        fd, tmp_path = tempfile.mkstemp(
            prefix=".migration-journal-", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
