from __future__ import annotations

from aws_lambda_powertools.utilities.idempotency.exceptions import (
    IdempotencyItemAlreadyExistsError,
    IdempotencyItemNotFoundError,
)
from aws_lambda_powertools.utilities.idempotency.persistence.base import (
    BasePersistenceLayer,
    DataRecord,
)


class InMemoryPersistenceLayer(BasePersistenceLayer):
    """In-memory persistence layer that mirrors the conditional-write semantics of a real backend."""

    def __init__(self) -> None:
        self.records: dict[str, DataRecord] = {}
        super().__init__()

    def _put_record(self, data_record: DataRecord) -> None:
        existing_record = self.records.get(data_record.idempotency_key)
        if existing_record is not None and not existing_record.is_expired:
            raise IdempotencyItemAlreadyExistsError(old_data_record=existing_record)
        self.records[data_record.idempotency_key] = data_record

    def _get_record(self, idempotency_key: str) -> DataRecord:
        try:
            return self.records[idempotency_key]
        except KeyError:
            raise IdempotencyItemNotFoundError from None

    def _update_record(self, data_record: DataRecord) -> None:
        self.records[data_record.idempotency_key] = data_record

    def _delete_record(self, data_record: DataRecord) -> None:
        self.records.pop(data_record.idempotency_key, None)
