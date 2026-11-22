import os
import uuid

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.idempotency import (
    DynamoDBPersistenceLayer,
    IdempotencyConfig,
    IdempotencyPermissionDeniedError,
    idempotent_function,
)
from aws_lambda_powertools.utilities.idempotency.persistence.datarecord import (
    DataRecord,
)
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()


# Authorization state lives outside the idempotency record and is re-checked on every replay.
# In a real application this would call your IAM, token or internal authorization service.
AUTHORIZED_CALLERS = {"merchant-a", "merchant-b"}


def authorize_replay(response: dict, idempotent_data: DataRecord) -> bool:
    # The stored record only proves the operation completed; verify the caller's current
    # authorization before handing back the receipt cached for this idempotency key.
    caller_id = response.get("caller_id")
    return caller_id in AUTHORIZED_CALLERS


table = os.getenv("IDEMPOTENCY_TABLE", "")
dynamodb = DynamoDBPersistenceLayer(table_name=table)
config = IdempotencyConfig(response_permission_check=authorize_replay)


@idempotent_function(data_keyword_argument="payment", config=config, persistence_store=dynamodb)
def process_payment(payment: dict) -> dict:
    receipt_id = str(uuid.uuid4())
    return {"receipt_id": receipt_id, "status": "PAID", "caller_id": payment["caller_id"]}


def lambda_handler(event: dict, context: LambdaContext):
    config.register_lambda_context(context)  # see Lambda timeouts section
    try:
        logger.info(f"Processing payment id {event.get('payment_id')}")
        return process_payment(payment=event.get("payment"))
    except IdempotencyPermissionDeniedError:
        # The receipt stays cached and the payment is not processed again; tell the caller
        # they are no longer allowed to retrieve it.
        logger.warning("Replay denied: caller is not authorized to receive the stored receipt")
        return {"status_code": 403, "error": "Not authorized to retrieve this payment receipt"}
