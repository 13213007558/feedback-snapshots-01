"""
Explicit response shapes for idempotent functions
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

ResponseT = TypeVar("ResponseT")
PersistedT = TypeVar("PersistedT")


@dataclass(frozen=True)
class PersistedResponse(Generic[ResponseT, PersistedT]):
    """
    Response envelope that separates what the caller receives from what the
    idempotency store persists.

    Use it when a response carries temporary or personal fields that must not
    be kept in the persistence layer (e.g. one-time download URLs, verification
    codes). The idempotency handler unwraps it transparently:

    - On the first execution, the caller receives ``response`` (the normal
      business object) while only ``persisted`` is serialized into the
      idempotency record.
    - On replay, the caller receives ``persisted`` rehydrated from the stored
      record, via the configured output serializer. Fields left out of
      ``persisted`` are never stored and never provided again.

    Parameters
    ----------
    response: ResponseT
        Full business object returned to the caller on the first execution.
    persisted: PersistedT
        Subset persisted in the idempotency store and returned on replay.

    Example
    --------
    **Persist only non-sensitive fields of a payment receipt**

        from aws_lambda_powertools.utilities.idempotency import (
            idempotent_function,
            PersistedResponse,
        )

        @idempotent_function(
            data_keyword_argument="order",
            persistence_store=persistence_layer,
            output_serializer=PydanticSerializer(model=PersistedReceipt),
        )
        def collect_payment(order: Order) -> Receipt:
            receipt = issue_receipt(order)  # includes a temporary download URL
            return PersistedResponse(
                response=receipt,
                persisted=PersistedReceipt(order_id=receipt.order_id, status=receipt.status),
            )
    """

    response: ResponseT
    persisted: PersistedT
