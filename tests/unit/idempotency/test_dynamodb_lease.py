"""
Lease tests for the DynamoDB idempotency persistence layer.

When a function times out, its in-progress lease expires and the persistence layer lets a
later request take over the unfinished operation. These tests prove that the earlier
execution, even if it finishes late, cannot overwrite the state owned by the new execution.

A controllable clock drives the expiry timestamps and a fake DynamoDB client enforces the
write conditions sent by the layer, so each test shows which attempt was granted the
execution permit, which attempt actually committed, and who owns the completion record
observed afterwards.
"""

from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError

from aws_lambda_powertools.utilities.idempotency import (
    DynamoDBPersistenceLayer,
    IdempotencyConfig,
)
from aws_lambda_powertools.utilities.idempotency.exceptions import (
    IdempotencyItemAlreadyExistsError,
    IdempotencyStaleExecutionError,
)
from aws_lambda_powertools.utilities.idempotency.persistence import (
    base as persistence_base,
)
from aws_lambda_powertools.utilities.idempotency.persistence import (
    dynamodb as persistence_dynamodb,
)

TABLE_NAME = "idempotency-lease-test"
PAYLOAD = {"order_id": "order-1"}
LEASE_MS = 30_000  # each execution leases the record for its 30s of remaining time


class ControllableClock:
    """Deterministic clock injected into the persistence layer modules."""

    def __init__(self):
        self._now = dt.datetime.now()

    def now(self, tz=None) -> dt.datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += dt.timedelta(seconds=seconds)


class FakeDynamoDBClient:
    """In-memory DynamoDB double that enforces the write conditions sent by the layer."""

    def __init__(self):
        self.items: dict[str, dict] = {}
        self.granted_leases: list[int] = []  # in-progress lease of every accepted put (execution permit)
        self.rejected_leases: list[int] = []  # in-progress lease of every rejected put
        self.committed_responses: list[str] = []  # response data of every accepted update (actual commit)
        self.rejected_commits: list[str] = []  # response data of every rejected update

    @staticmethod
    def _key(key: dict[str, Any]) -> str:
        return next(iter(key.values()))["S"]

    def stored_item(self) -> dict:
        assert len(self.items) == 1
        return next(iter(self.items.values()))

    def put_item(
        self,
        *,
        TableName: str,
        Item: dict,
        ConditionExpression: str,
        ExpressionAttributeNames: dict,
        ExpressionAttributeValues: dict,
        **kwargs,
    ) -> dict:
        names = ExpressionAttributeNames
        values = ExpressionAttributeValues
        key = self._key({names["#id"]: Item[names["#id"]]})
        lease = int(Item[names["#in_progress_expiry"]]["N"])
        existing = self.items.get(key)

        # Same semantics as the layer's put condition:
        # the key does not exist, the record expired, or the in-progress lease expired
        allowed = (
            existing is None
            or int(existing[names["#expiry"]]["N"]) < int(values[":now"]["N"])
            or (
                existing[names["#status"]]["S"] == values[":inprogress"]["S"]
                and names["#in_progress_expiry"] in existing
                and int(existing[names["#in_progress_expiry"]]["N"]) < int(values[":now_in_millis"]["N"])
            )
        )
        if not allowed:
            self.rejected_leases.append(lease)
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException"}, "Item": existing},
                "PutItem",
            )

        self.items[key] = dict(Item)
        self.granted_leases.append(lease)
        return {}

    def update_item(
        self,
        *,
        TableName: str,
        Key: dict,
        UpdateExpression: str,
        ExpressionAttributeNames: dict,
        ExpressionAttributeValues: dict,
        ConditionExpression: str | None = None,
        **kwargs,
    ) -> dict:
        names = ExpressionAttributeNames
        values = ExpressionAttributeValues
        key = self._key(Key)
        existing = self.items.get(key)
        response_data = values[":response_data"]["S"]

        if ConditionExpression is not None:
            # Same semantics as the layer's lease fencing condition:
            # the record is still INPROGRESS and the caller presents the lease it wrote
            status_matches = existing is not None and existing[names["#status"]]["S"] == values[":inprogress"]["S"]
            lease_matches = True
            if ":in_progress_expiry" in values:
                lease_attr = names["#in_progress_expiry"]
                lease_matches = existing is not None and existing.get(lease_attr, {}).get("N") == values[
                    ":in_progress_expiry"
                ]["N"]
            if not (status_matches and lease_matches):
                self.rejected_commits.append(response_data)
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")

        item = dict(existing or {})
        item[names["#status"]] = values[":status"]
        item[names["#response_data"]] = values[":response_data"]
        item[names["#expiry"]] = values[":expiry"]
        self.items[key] = item
        self.committed_responses.append(response_data)
        return {}

    def get_item(self, *, TableName: str, Key: dict, **kwargs) -> dict:
        item = self.items.get(self._key(Key))
        return {"Item": item} if item is not None else {}

    def delete_item(self, *, TableName: str, Key: dict, **kwargs) -> dict:
        self.items.pop(self._key(Key), None)
        return {}


@pytest.fixture
def clock(monkeypatch):
    controllable_clock = ControllableClock()
    fake_datetime_module = SimpleNamespace(datetime=controllable_clock, timedelta=dt.timedelta)
    monkeypatch.setattr(persistence_base, "dt", fake_datetime_module)
    monkeypatch.setattr(persistence_dynamodb, "dt", fake_datetime_module)
    return controllable_clock


def new_execution(client: FakeDynamoDBClient) -> DynamoDBPersistenceLayer:
    """A persistence layer as seen by one execution (its own Lambda environment)."""
    layer = DynamoDBPersistenceLayer(table_name=TABLE_NAME, boto3_client=client)
    layer.configure(config=IdempotencyConfig(event_key_jmespath="order_id"), function_name="lease_test")
    return layer


def committed_results(client: FakeDynamoDBClient) -> list[dict]:
    return [json.loads(response) for response in client.committed_responses]


def test_lease_allows_new_execution_to_take_over_after_timeout(clock):
    # GIVEN two executions of the same idempotent function sharing one table
    client = FakeDynamoDBClient()
    first_execution = new_execution(client)
    second_execution = new_execution(client)

    # WHEN the first execution starts, it is granted the execution permit
    first_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    assert len(client.granted_leases) == 1
    first_lease = client.granted_leases[0]

    # AND the first execution times out, so its in-progress lease expires
    clock.advance(seconds=LEASE_MS / 1000 + 1)

    # WHEN a new execution arrives, it is allowed to take over the unfinished operation
    second_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)

    # THEN the second execution got the permit and the record now carries its lease
    assert len(client.granted_leases) == 2
    second_lease = client.granted_leases[1]
    assert second_lease > first_lease
    assert client.stored_item()["in_progress_expiration"]["N"] == str(second_lease)


def test_lease_rejects_new_execution_while_previous_lease_is_alive(clock):
    # GIVEN a first execution that just started and holds a valid lease
    client = FakeDynamoDBClient()
    first_execution = new_execution(client)
    second_execution = new_execution(client)
    first_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)

    # WHEN a new execution arrives before the in-progress lease expired
    clock.advance(seconds=1)

    # THEN it is denied the execution permit and the record still belongs to the first execution
    with pytest.raises(IdempotencyItemAlreadyExistsError):
        second_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    assert len(client.granted_leases) == 1
    assert len(client.rejected_leases) == 1
    assert client.stored_item()["in_progress_expiration"]["N"] == str(client.granted_leases[0])


def test_stale_execution_cannot_overwrite_record_completed_by_new_execution(clock):
    # GIVEN a first execution that timed out and a second execution that took over and committed
    client = FakeDynamoDBClient()
    first_execution = new_execution(client)
    second_execution = new_execution(client)
    first_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    clock.advance(seconds=LEASE_MS / 1000 + 1)
    second_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    second_execution.save_success(data=PAYLOAD, result={"execution": "second"})

    # WHEN the stale first execution finishes late and tries to commit its own result
    # THEN it is fenced off and cannot overwrite the record owned by the second execution
    with pytest.raises(IdempotencyStaleExecutionError):
        first_execution.save_success(data=PAYLOAD, result={"execution": "first"})

    # AND only the second execution ever committed
    assert committed_results(client) == [{"execution": "second"}]

    # AND the completion record observed afterwards belongs to the second execution
    record = new_execution(client).get_record(data=PAYLOAD)
    assert record.status == "COMPLETED"
    assert record.response_json_as_dict() == {"execution": "second"}


def test_stale_execution_cannot_overwrite_record_in_progress_by_new_execution(clock):
    # GIVEN a first execution that timed out and a second execution that took over and is still running
    client = FakeDynamoDBClient()
    first_execution = new_execution(client)
    second_execution = new_execution(client)
    first_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    clock.advance(seconds=LEASE_MS / 1000 + 1)
    second_execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)

    # WHEN the stale first execution finishes late and tries to commit
    # THEN it is fenced off and the record stays INPROGRESS with the second execution's lease
    with pytest.raises(IdempotencyStaleExecutionError):
        first_execution.save_success(data=PAYLOAD, result={"execution": "first"})
    item = client.stored_item()
    assert item["status"]["S"] == "INPROGRESS"
    assert item["in_progress_expiration"]["N"] == str(client.granted_leases[1])

    # AND the new owner can still commit, so the completion record belongs to it
    second_execution.save_success(data=PAYLOAD, result={"execution": "second"})
    assert committed_results(client) == [{"execution": "second"}]
    record = new_execution(client).get_record(data=PAYLOAD)
    assert record.status == "COMPLETED"
    assert record.response_json_as_dict() == {"execution": "second"}


def test_execution_commits_within_its_own_lease(clock):
    # GIVEN an execution that finishes before its in-progress lease expires
    client = FakeDynamoDBClient()
    execution = new_execution(client)
    execution.save_inprogress(data=PAYLOAD, remaining_time_in_millis=LEASE_MS)
    clock.advance(seconds=1)

    # WHEN it commits, the lease fencing does not block the legitimate owner
    execution.save_success(data=PAYLOAD, result={"execution": "first"})

    # THEN its result is committed and visible to later requests
    assert committed_results(client) == [{"execution": "first"}]
    record = new_execution(client).get_record(data=PAYLOAD)
    assert record.status == "COMPLETED"
    assert record.response_json_as_dict() == {"execution": "first"}
