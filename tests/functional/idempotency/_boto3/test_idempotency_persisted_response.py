import json
from dataclasses import dataclass

from aws_lambda_powertools.utilities.idempotency import (
    IdempotencyConfig,
    PersistedResponse,
    idempotent_function,
)
from aws_lambda_powertools.utilities.idempotency.exceptions import (
    IdempotencyItemAlreadyExistsError,
    IdempotencyItemNotFoundError,
)
from aws_lambda_powertools.utilities.idempotency.persistence.base import (
    BasePersistenceLayer,
    DataRecord,
)
from aws_lambda_powertools.utilities.idempotency.serialization.dataclass import (
    DataclassSerializer,
)


class InMemoryPersistenceLayer(BasePersistenceLayer):
    """In-memory persistence backend keeping raw DataRecords for byte-level inspection."""

    def __init__(self):
        self.records: dict[str, DataRecord] = {}
        super().__init__()

    def _put_record(self, data_record: DataRecord) -> None:
        existing_record = self.records.get(data_record.idempotency_key)
        if existing_record is not None and not existing_record.is_expired:
            raise IdempotencyItemAlreadyExistsError(old_data_record=existing_record)
        self.records[data_record.idempotency_key] = data_record

    def _get_record(self, idempotency_key) -> DataRecord:
        try:
            return self.records[idempotency_key]
        except KeyError:
            raise IdempotencyItemNotFoundError

    def _update_record(self, data_record: DataRecord) -> None:
        self.records[data_record.idempotency_key] = data_record

    def _delete_record(self, data_record: DataRecord) -> None:
        self.records.pop(data_record.idempotency_key, None)


@dataclass
class OrderInput:
    order_id: str
    customer_id: str


@dataclass
class Receipt:
    """Full business object, including temporary personal fields."""

    order_id: str
    status: str
    download_url: str
    customer_email: str


@dataclass
class PersistedReceipt:
    """Explicit persisted shape: only fields safe to keep and replay."""

    order_id: str
    status: str


def _build_receipt(order: OrderInput, token: str) -> Receipt:
    return Receipt(
        order_id=order.order_id,
        status="PAID",
        download_url=f"https://example.com/one-time-download/{token}",
        customer_email="customer@example.com",
    )


def test_persisted_response_stores_only_persisted_fields():
    # GIVEN a function returning a PersistedResponse envelope
    config = IdempotencyConfig()
    persistence_layer = InMemoryPersistenceLayer()
    executions = []

    @idempotent_function(
        data_keyword_argument="order",
        persistence_store=persistence_layer,
        config=config,
        output_serializer=DataclassSerializer(model=PersistedReceipt),
    )
    def collect_payment(order: OrderInput) -> PersistedResponse:
        executions.append(order.order_id)
        return PersistedResponse(
            response=_build_receipt(order, token="secret-token"),
            persisted=PersistedReceipt(order_id=order.order_id, status="PAID"),
        )

    order = OrderInput(order_id="order-1", customer_id="customer-1")

    # WHEN the function executes the first time
    first_call = collect_payment(order=order)

    # THEN the caller receives the full business object, including temporary fields
    assert isinstance(first_call, Receipt)
    assert first_call.download_url == "https://example.com/one-time-download/secret-token"
    assert first_call.customer_email == "customer@example.com"

    # AND the actual saved bytes contain only the persisted shape
    assert len(persistence_layer.records) == 1
    saved_record = next(iter(persistence_layer.records.values()))
    saved_bytes = saved_record.response_data.encode("utf-8")
    assert b"download_url" not in saved_bytes
    assert b"one-time-download" not in saved_bytes
    assert b"customer_email" not in saved_bytes
    assert b"customer@example.com" not in saved_bytes
    assert json.loads(saved_bytes) == {"order_id": "order-1", "status": "PAID"}

    # WHEN the same payload is replayed
    second_call = collect_payment(order=order)

    # THEN the function does not run again and the persisted shape is rehydrated from the record
    assert executions == ["order-1"]
    assert isinstance(second_call, PersistedReceipt)
    assert second_call.order_id == "order-1"
    assert second_call.status == "PAID"
    assert not hasattr(second_call, "download_url")
    assert not hasattr(second_call, "customer_email")


def test_persisted_response_replays_records_stored_by_previous_version():
    # GIVEN a record written by the previous version of the function,
    # which persisted the full response including temporary personal fields
    config = IdempotencyConfig()
    persistence_layer = InMemoryPersistenceLayer()

    @idempotent_function(
        data_keyword_argument="order",
        persistence_store=persistence_layer,
        config=config,
        output_serializer=DataclassSerializer(model=Receipt),
        key_prefix="collect_payment",
    )
    def collect_payment_legacy(order: OrderInput) -> Receipt:
        return _build_receipt(order, token="secret-token")

    order = OrderInput(order_id="order-2", customer_id="customer-2")
    collect_payment_legacy(order=order)

    saved_record = next(iter(persistence_layer.records.values()))
    assert b"one-time-download" in saved_record.response_data.encode("utf-8")

    # AND a new version of the function that only persists an explicit subset
    executions = []

    @idempotent_function(
        data_keyword_argument="order",
        persistence_store=persistence_layer,
        config=config,
        output_serializer=DataclassSerializer(model=PersistedReceipt),
        key_prefix="collect_payment",
    )
    def collect_payment_v2(order: OrderInput) -> PersistedResponse:
        executions.append(order.order_id)
        return PersistedResponse(
            response=_build_receipt(order, token="other-token"),
            persisted=PersistedReceipt(order_id=order.order_id, status="PAID"),
        )

    # WHEN the same payload is replayed against the old record
    replayed = collect_payment_v2(order=order)

    # THEN the old record is still honored: the function does not run again,
    # and the replayed result only exposes the fields of the persisted shape
    assert executions == []
    assert isinstance(replayed, PersistedReceipt)
    assert replayed.order_id == "order-2"
    assert replayed.status == "PAID"
    assert not hasattr(replayed, "download_url")
    assert not hasattr(replayed, "customer_email")
