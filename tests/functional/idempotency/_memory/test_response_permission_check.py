from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from aws_lambda_powertools.utilities.idempotency import (
    IdempotencyConfig,
    IdempotencyPermissionDeniedError,
    idempotent,
    idempotent_function,
)
from tests.functional.idempotency._memory.in_memory_persistence import (
    InMemoryPersistenceLayer,
)

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.idempotency.persistence.datarecord import DataRecord


class LambdaContext:
    def __init__(self) -> None:
        self.function_name = "test-func"
        self.memory_limit_in_mb = 128
        self.invoked_function_arn = "arn:aws:lambda:eu-west-1:809313241234:function:test-func"
        self.aws_request_id = "52fdfc07-2182-154f-163f-5f0f9a621d72"

    def get_remaining_time_in_millis(self) -> int:
        return 1000


def payment_callback(payload: dict, authorized_callers: set[str]) -> Any:
    """Return True when the current caller may receive the replayed payment receipt."""

    def is_authorized(response: Any, idempotent_data: DataRecord) -> bool:
        assert idempotent_data.idempotency_key
        return payload["caller_id"] in authorized_callers

    return is_authorized


def build_config(use_local_cache: bool, permission_check: Any | None) -> IdempotencyConfig:
    return IdempotencyConfig(
        event_key_jmespath="payment_id",
        use_local_cache=use_local_cache,
        response_permission_check=permission_check,
    )


@pytest.mark.parametrize("use_local_cache", [False, True])
def test_first_execution_runs_business_action_once(use_local_cache: bool):
    # GIVEN a fresh in-memory store and an optional response permission check
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    authorized_callers = {"merchant-a"}
    payload = {"payment_id": "pay-123", "caller_id": "merchant-a"}

    def permission_check(response: Any, idempotent_data: DataRecord) -> bool:
        return payload["caller_id"] in authorized_callers

    config = build_config(use_local_cache=use_local_cache, permission_check=permission_check)

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # WHEN the payment callback is executed for the first time
    result = process_payment(payment=payload)

    # THEN the business action runs exactly once, the receipt is returned and persisted
    assert run_count == 1
    assert result == {"receipt_id": "receipt-123", "status": "PAID"}
    assert len(persistence_layer.records) == 1
    stored_record = next(iter(persistence_layer.records.values()))
    assert stored_record.status == "COMPLETED"


@pytest.mark.parametrize("use_local_cache", [False, True])
def test_authorized_replay_returns_stored_receipt_without_running_again(use_local_cache: bool):
    # GIVEN a completed payment record and a still authorized caller
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    authorized_callers = {"merchant-a"}
    payload = {"payment_id": "pay-123", "caller_id": "merchant-a"}
    config = build_config(
        use_local_cache=use_local_cache,
        permission_check=payment_callback(payload, authorized_callers),
    )

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # WHEN the same payment callback is executed twice by the authorized caller
    first_result = process_payment(payment=payload)
    replayed_result = process_payment(payment=payload)

    # THEN the stored receipt is returned on replay and the business action never runs again
    assert first_result == replayed_result == {"receipt_id": "receipt-123", "status": "PAID"}
    assert run_count == 1
    assert len(persistence_layer.records) == 1


@pytest.mark.parametrize("use_local_cache", [False, True])
def test_revoked_permission_blocks_replay_without_returning_receipt_or_rerunning(use_local_cache: bool):
    # GIVEN a completed payment record whose caller had authorization revoked
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    authorized_callers = {"merchant-a"}
    payload = {"payment_id": "pay-123", "caller_id": "merchant-a"}
    config = build_config(
        use_local_cache=use_local_cache,
        permission_check=payment_callback(payload, authorized_callers),
    )

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # AND the first execution stores the receipt
    process_payment(payment=payload)
    assert run_count == 1

    # WHEN authorization is revoked before the replay
    authorized_callers.remove("merchant-a")

    # THEN the replay is denied, no receipt is returned and the business action does not run again
    with pytest.raises(IdempotencyPermissionDeniedError):
        process_payment(payment=payload)
    assert run_count == 1
    assert len(persistence_layer.records) == 1
    assert next(iter(persistence_layer.records.values())).status == "COMPLETED"


@pytest.mark.parametrize("use_local_cache", [False, True])
def test_revoked_permission_does_not_swallow_later_authorized_replay(use_local_cache: bool):
    # GIVEN a revoked replay followed by authorization being granted again
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    authorized_callers = {"merchant-a"}
    payload = {"payment_id": "pay-123", "caller_id": "merchant-a"}
    config = build_config(
        use_local_cache=use_local_cache,
        permission_check=payment_callback(payload, authorized_callers),
    )

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    process_payment(payment=payload)
    authorized_callers.remove("merchant-a")
    with pytest.raises(IdempotencyPermissionDeniedError):
        process_payment(payment=payload)

    # WHEN the caller is authorized again
    authorized_callers.add("merchant-a")
    result = process_payment(payment=payload)

    # THEN the stored receipt can still be delivered, still without re-running the business action
    assert result == {"receipt_id": "receipt-123", "status": "PAID"}
    assert run_count == 1


def test_replay_without_permission_check_keeps_default_behavior():
    # GIVEN a config without a response permission check
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    config = IdempotencyConfig(event_key_jmespath="payment_id")

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # WHEN the same payment is replayed
    process_payment(payment={"payment_id": "pay-123"})
    result = process_payment(payment={"payment_id": "pay-123"})

    # THEN the stored receipt is returned without invoking any permission check
    assert result == {"receipt_id": "receipt-123", "status": "PAID"}
    assert run_count == 1


def test_permission_check_receives_deserialized_response_and_data_record():
    # GIVEN a permission check that inspects the stored response and record
    persistence_layer = InMemoryPersistenceLayer()
    seen: list[tuple[Any, DataRecord]] = []

    def permission_check(response: Any, idempotent_data: DataRecord) -> bool:
        seen.append((response, idempotent_data))
        return True

    config = IdempotencyConfig(
        event_key_jmespath="payment_id",
        response_permission_check=permission_check,
    )

    @idempotent_function(data_keyword_argument="payment", config=config, persistence_store=persistence_layer)
    def process_payment(payment: dict) -> dict:
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # WHEN the payment is replayed
    payload = {"payment_id": "pay-123"}
    process_payment(payment=payload)
    process_payment(payment=payload)

    # THEN the check runs only on replay and receives the deserialized response and a COMPLETED record
    assert len(seen) == 1
    response, record = seen[0]
    assert response == {"receipt_id": "receipt-123", "status": "PAID"}
    assert record.status == "COMPLETED"


def test_idempotent_decorator_enforces_permission_check_on_replay():
    # GIVEN the idempotent Lambda decorator with a response permission check
    persistence_layer = InMemoryPersistenceLayer()
    run_count = 0
    authorized_callers = {"merchant-a"}
    payload = {"payment_id": "pay-123", "caller_id": "merchant-a"}
    config = IdempotencyConfig(
        event_key_jmespath="payment_id",
        response_permission_check=payment_callback(payload, authorized_callers),
    )

    @idempotent(config=config, persistence_store=persistence_layer)
    def lambda_handler(event: dict, context: LambdaContext) -> dict:
        nonlocal run_count
        run_count += 1
        return {"receipt_id": "receipt-123", "status": "PAID"}

    # WHEN the handler runs first and is replayed after permission revocation
    lambda_handler(payload, LambdaContext())
    authorized_callers.remove("merchant-a")

    # THEN the replay is denied and the handler is not invoked a second time
    with pytest.raises(IdempotencyPermissionDeniedError):
        lambda_handler(payload, LambdaContext())
    assert run_count == 1
