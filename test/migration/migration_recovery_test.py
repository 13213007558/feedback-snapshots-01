"""
End-to-end tests for journaled, recoverable OpenFGA role migration.

The fake service is mounted at the REST transport layer, so the real
OpenFgaClient serialization, write/read flows and exception handling all run
unchanged. Tests inject a single lost write response to prove that an
interrupted migration can be resumed without reviving withdrawn relationships.
"""

import json
import os
import tempfile

from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import pytest

from openfga_sdk import rest
from openfga_sdk.client import ClientConfiguration
from openfga_sdk.client.client import OpenFgaClient
from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.migration import (
    BatchOperation,
    BatchStatus,
    FakeOpenFgaService,
    LostResponseError,
    MigrationJournal,
    MigrationPlan,
    MigrationPlanError,
    MigrationRecoveryError,
    MigrationRunner,
    tuple_identity,
)


STORE_ID = "01YCP46JKYM8FJCQ37NMBYHE5X"
API_URL = "http://api.fga.example"


def approved_tuples(count: int) -> list[dict[str, str]]:
    return [
        {
            "user": f"user:approved-{index}",
            "relation": "viewer",
            "object": "document:budget",
        }
        for index in range(count)
    ]


def revoked_tuples(count: int) -> list[dict[str, str]]:
    return [
        {
            "user": f"user:revoked-{index}",
            "relation": "viewer",
            "object": "document:budget",
        }
        for index in range(count)
    ]


def identity_of(tuple_key: dict[str, str]) -> str:
    return tuple_identity(tuple_key)


def write_only_requests(fake: FakeOpenFgaService) -> list[dict]:
    return [
        request
        for request in fake.write_requests
        if (request.get("writes") or {}).get("tuple_keys")
    ]


def delete_only_requests(fake: FakeOpenFgaService) -> list[dict]:
    return [
        request
        for request in fake.write_requests
        if (request.get("deletes") or {}).get("tuple_keys")
    ]


class TestMigrationRecovery(IsolatedAsyncioTestCase):
    def setUp(self):
        self.configuration = ClientConfiguration(api_url=API_URL)
        self.configuration.store_id = STORE_ID
        self.fake = FakeOpenFgaService()
        self._patcher = patch.object(
            rest.RESTClientObject,
            "request",
            side_effect=self.fake.handle_request,
        )
        self._patcher.start()
        self.temp_dir = tempfile.mkdtemp(prefix="openfga-migration-test-")
        self.journal_path = os.path.join(self.temp_dir, "migration.journal.json")

    def tearDown(self):
        self._patcher.stop()
        for name in os.listdir(self.temp_dir):
            os.unlink(os.path.join(self.temp_dir, name))
        os.rmdir(self.temp_dir)

    def _client(self) -> OpenFgaClient:
        return OpenFgaClient(self.configuration)

    def _plan(self, approved_count=5, revoked_count=2) -> MigrationPlan:
        return MigrationPlan(
            approved=approved_tuples(approved_count),
            revoked=revoked_tuples(revoked_count),
        )

    def _runner(self, plan, batch_size=2) -> MigrationRunner:
        return MigrationRunner(
            client=self._client(),
            plan=plan,
            journal_path=self.journal_path,
            batch_size=batch_size,
        )

    async def test_happy_path_writes_approved_and_deletes_revoked(self):
        plan = self._plan(approved_count=4, revoked_count=2)
        runner = self._runner(plan, batch_size=2)

        async with runner.client:
            result = await runner.run_async()

        # Two approved write batches plus one revoked delete batch.
        assert result.complete is True
        assert result.total_batches == 3
        assert result.succeeded_batches == 3
        assert self.fake.stored_identities == plan.approved_ids
        assert self.fake.stored_identities.isdisjoint(plan.revoked_ids)

        journal = MigrationJournal.load(self.journal_path)
        operations = [record.operation for record in journal.records()]
        assert operations == [
            BatchOperation.WRITE,
            BatchOperation.WRITE,
            BatchOperation.DELETE,
        ]
        assert all(
            record.status == BatchStatus.SUCCEEDED for record in journal.records()
        )

    async def test_lost_response_after_partial_success_is_reconciled(self):
        plan = self._plan(approved_count=5, revoked_count=2)
        runner = self._runner(plan, batch_size=2)

        # Batches 0 and 1 commit cleanly; the response for the third approved
        # write batch (sequence 2) is lost even though the server applied it.
        self.fake.lose_write_response_at(sequence=2, applied=True)

        async with runner.client:
            result = await runner.run_async()

        # The interrupted run stops on the ambiguous batch; the delete batch
        # never runs because the writes are not yet confirmed complete.
        assert result.complete is False
        assert result.succeeded_batches == 2
        assert result.in_flight_batches == 1

        journal = MigrationJournal.load(self.journal_path)
        statuses = [record.status for record in journal.records()]
        assert statuses == [
            BatchStatus.SUCCEEDED,
            BatchStatus.SUCCEEDED,
            BatchStatus.IN_FLIGHT,
            BatchStatus.PENDING,
        ]

        assert self.fake.stored_identities == plan.approved_ids
        write_count_after_first_run = len(self.fake.write_requests)

        # Resume with a fresh client but the same durable journal.
        resumed = self._runner(plan, batch_size=2)
        async with resumed.client:
            resumed_result = await resumed.run_async()

        assert resumed_result.complete is True
        assert resumed_result.succeeded_batches == 4

        # Reconciliation saw the tuples already existed, so the ambiguous
        # write was not re-sent; only the revoke delete batch is new.
        assert len(write_only_requests(self.fake)) == 3
        assert len(self.fake.write_requests) == write_count_after_first_run + 1

        journal = MigrationJournal.load(self.journal_path)
        assert all(
            record.status == BatchStatus.SUCCEEDED for record in journal.records()
        )
        assert self.fake.stored_identities == plan.approved_ids
        assert self.fake.stored_identities.isdisjoint(plan.revoked_ids)

    async def test_lost_response_without_commit_retries_once_then_succeeds(self):
        plan = self._plan(approved_count=2, revoked_count=1)
        runner = self._runner(plan, batch_size=2)

        # The connection drops before the server applies the single write.
        self.fake.lose_next_write_response(applied=False)

        async with runner.client:
            first = await runner.run_async()

        assert first.complete is False
        assert first.in_flight_batches == 1
        assert self.fake.stored_identities == set()

        resumed = self._runner(plan, batch_size=2)
        async with resumed.client:
            second = await resumed.run_async()

        assert second.complete is True
        assert self.fake.stored_identities == plan.approved_ids

        # The first attempt lost its response; the resumed run retries once.
        assert len(write_only_requests(self.fake)) == 2
        journal = MigrationJournal.load(self.journal_path)
        assert journal.get(0).attempts == 2

    async def test_lost_delete_response_is_reconciled_without_reviving(self):
        plan = self._plan(approved_count=2, revoked_count=2)
        self.fake.seed(revoked_tuples(2))
        runner = self._runner(plan, batch_size=2)

        # One approved write batch, then the revoke delete batch loses its
        # response after the server applied the deletion.
        self.fake.lose_write_response_at(sequence=1, applied=True)

        async with runner.client:
            first = await runner.run_async()

        assert first.complete is False
        journal = MigrationJournal.load(self.journal_path)
        assert journal.get(1).operation == BatchOperation.DELETE
        assert journal.get(1).status == BatchStatus.IN_FLIGHT
        # The revoked tuples were actually removed despite the lost response.
        assert self.fake.stored_identities.isdisjoint(plan.revoked_ids)

        resumed = self._runner(plan, batch_size=2)
        async with resumed.client:
            second = await resumed.run_async()

        assert second.complete is True
        # Reconciliation confirmed the deletes landed; no duplicate delete.
        assert len(delete_only_requests(self.fake)) == 1
        assert self.fake.stored_identities == plan.approved_ids
        assert self.fake.stored_identities.isdisjoint(plan.revoked_ids)

    async def test_recovery_never_revives_revoked_relationships(self):
        plan = self._plan(approved_count=3, revoked_count=2)

        # The store still holds the legacy (revoked) relationships when the
        # migration starts.
        self.fake.seed(revoked_tuples(2))
        runner = self._runner(plan, batch_size=2)
        self.fake.lose_write_response_at(sequence=1, applied=True)

        async with runner.client:
            await runner.run_async()

        resumed = self._runner(plan, batch_size=2)
        async with resumed.client:
            result = await resumed.run_async()

        assert result.complete is True
        stored = self.fake.stored_identities
        assert stored.isdisjoint(plan.revoked_ids)
        assert stored == plan.approved_ids

        # Every write batch must only contain approved tuples, never revoked.
        for request in write_only_requests(self.fake):
            for key in request["writes"]["tuple_keys"]:
                assert plan.is_approved(identity_of(key))
                assert not plan.is_revoked(identity_of(key))

        # The revoked tuples are removed through explicit delete batches only.
        deleted = {
            identity_of(key)
            for request in delete_only_requests(self.fake)
            for key in request["deletes"]["tuple_keys"]
        }
        assert deleted == plan.revoked_ids

    async def test_writes_and_deletes_are_idempotent_on_conflict(self):
        plan = self._plan(approved_count=2, revoked_count=1)
        runner = self._runner(plan, batch_size=2)

        async with runner.client:
            await runner.run_async()

        for request in write_only_requests(self.fake):
            assert request["writes"].get("on_duplicate") == "ignore"
        for request in delete_only_requests(self.fake):
            assert request["deletes"].get("on_missing") == "ignore"

    async def test_plan_rejects_tuple_both_approved_and_revoked(self):
        tuple_key = {"user": "user:x", "relation": "viewer", "object": "doc:1"}
        with pytest.raises(MigrationPlanError):
            MigrationPlan(approved=[tuple_key], revoked=[dict(tuple_key)])

    async def test_runner_refuses_to_write_unapproved_tuple(self):
        plan = self._plan(approved_count=2, revoked_count=1)
        runner = self._runner(plan, batch_size=2)

        # Tamper with the journal so a write batch contains a revoked tuple.
        journal = MigrationJournal.initialize(
            self.journal_path,
            [plan.approved[:1], plan.approved[1:]],
            operations=[BatchOperation.WRITE, BatchOperation.WRITE],
        )
        journal.get(1).tuples.append(
            ClientTuple(
                user="user:revoked-0",
                relation="viewer",
                object="document:budget",
            )
        )
        journal.persist()

        async with runner.client:
            with pytest.raises(MigrationRecoveryError):
                await runner.run_async()

        # Nothing was written because the guard runs before any request.
        assert self.fake.write_requests == []

    async def test_partial_ambiguous_batch_requires_intervention(self):
        plan = self._plan(approved_count=4, revoked_count=1)
        runner = self._runner(plan, batch_size=2)

        async with runner.client:
            journal = runner._load_or_initialize_journal()
            journal.mark_in_flight(1)

            # Simulate only one tuple of write batch 1 actually landing.
            partially_applied = journal.get(1).tuples[:1]
            self.fake.seed(
                [
                    {
                        "user": item.user,
                        "relation": item.relation,
                        "object": item.object,
                    }
                    for item in partially_applied
                ]
            )

            with pytest.raises(MigrationRecoveryError):
                await runner._reconcile_in_flight(journal)

    async def test_journal_is_durable_json_with_atomic_state(self):
        plan = self._plan(approved_count=2, revoked_count=1)
        runner = self._runner(plan, batch_size=1)

        async with runner.client:
            journal = runner._load_or_initialize_journal()
            journal.mark_in_flight(0)
            journal.mark_succeeded(0)

        with open(self.journal_path, encoding="utf-8") as handle:
            payload = json.load(handle)

        assert payload["schema_version"] == MigrationJournal.SCHEMA_VERSION
        assert payload["batches"][0]["status"] == BatchStatus.SUCCEEDED.value
        assert payload["batches"][1]["status"] == BatchStatus.PENDING.value
        assert payload["batches"][-1]["operation"] == BatchOperation.DELETE.value

    async def test_fake_service_enforces_duplicate_and_missing_conflicts(self):
        tuple_key = {
            "user": "user:a",
            "relation": "viewer",
            "object": "doc:1",
        }
        self.fake.seed([tuple_key])

        with pytest.raises(Exception):
            await self.fake.handle_request(
                "POST",
                f"{API_URL}/stores/{STORE_ID}/write",
                body={
                    "writes": {
                        "tuple_keys": [tuple_key],
                        "on_duplicate": "error",
                    }
                },
            )

        # on_duplicate=ignore tolerates the existing tuple.
        response = await self.fake.handle_request(
            "POST",
            f"{API_URL}/stores/{STORE_ID}/write",
            body={
                "writes": {
                    "tuple_keys": [tuple_key],
                    "on_duplicate": "ignore",
                }
            },
        )
        assert response.status == 200

        other = {"user": "user:missing", "relation": "viewer", "object": "doc:1"}
        with pytest.raises(Exception):
            await self.fake.handle_request(
                "POST",
                f"{API_URL}/stores/{STORE_ID}/write",
                body={
                    "deletes": {
                        "tuple_keys": [other],
                        "on_missing": "error",
                    }
                },
            )

    async def test_lost_response_fault_fires_once_then_clears(self):
        plan = self._plan(approved_count=4, revoked_count=1)
        runner = self._runner(plan, batch_size=2)
        self.fake.lose_next_write_response(applied=True)

        async with runner.client:
            await runner.run_async()

        journal = MigrationJournal.load(self.journal_path)
        assert journal.get(0).status == BatchStatus.IN_FLIGHT
        # The runner halts at the ambiguous batch; later batches stay pending
        # rather than executing out of order.
        assert journal.get(1).status == BatchStatus.PENDING
        assert self.fake._lose_next is None

        with pytest.raises(LostResponseError):
            self.fake.lose_next_write_response(applied=False)
            await self.fake.handle_request(
                "POST",
                f"{API_URL}/stores/{STORE_ID}/write",
                body={"writes": {"tuple_keys": [], "on_duplicate": "ignore"}},
            )
