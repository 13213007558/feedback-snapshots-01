import os
from dataclasses import dataclass

from aws_lambda_powertools.utilities.idempotency import (
    DynamoDBPersistenceLayer,
    IdempotencyConfig,
    PersistedResponse,
    idempotent_function,
)
from aws_lambda_powertools.utilities.idempotency.serialization.dataclass import (
    DataclassSerializer,
)
from aws_lambda_powertools.utilities.typing import LambdaContext

table = os.getenv("IDEMPOTENCY_TABLE", "")
dynamodb = DynamoDBPersistenceLayer(table_name=table)
config = IdempotencyConfig(event_key_jmespath="order_id")


@dataclass
class Order:
    order_id: str
    customer_id: str


@dataclass
class Receipt:
    order_id: str
    status: str
    download_url: str  # temporary, personal; must not be persisted


@dataclass
class PersistedReceipt:
    order_id: str
    status: str


@idempotent_function(
    data_keyword_argument="order",
    config=config,
    persistence_store=dynamodb,
    output_serializer=DataclassSerializer(model=PersistedReceipt),  # (1)!
)
def issue_receipt(order: Order) -> PersistedResponse:  # (2)!
    receipt = issue_receipt_with_download_url(order)
    return PersistedResponse(
        response=receipt,  # (3)!
        persisted=PersistedReceipt(order_id=receipt.order_id, status=receipt.status),  # (4)!
    )


def issue_receipt_with_download_url(order: Order) -> Receipt:
    return Receipt(
        order_id=order.order_id,
        status="PAID",
        download_url=f"https://example.com/one-time-download/{order.order_id}",
    )


def lambda_handler(event: dict, context: LambdaContext):
    # see Lambda timeouts section
    config.register_lambda_context(context)

    order = Order(order_id="order-1", customer_id="customer-1")

    # first call returns the full Receipt; replays return PersistedReceipt
    issue_receipt(order=order)
