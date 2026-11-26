"""
Resumable runner for an OpenFGA role migration.

The runner turns a :class:`MigrationPlan` into durable, fixed-size batches:

* approved relationships become ``write`` batches (the new role grants)
* revoked relationships become ``delete`` batches, scheduled after every
  approved write so an interrupted run never removes an old grant before its
  replacement is safely in place

Each batch is driven through a :class:`MigrationJournal`.

Recovery model
--------------
Each batch is one transactional OpenFGA write. The journal transition is:

    PENDING -> IN_FLIGHT -> SUCCEEDED
                          \\-> FAILED

A response that never comes back (timeout, reset, lost connection) leaves the
batch recorded as ``IN_FLIGHT``: the write may or may not have landed. On the
next run the runner never blindly retries such a batch. Instead it reads the
store and reconciles:

* write batch, every approved tuple present  -> mark ``SUCCEEDED``
* write batch, no tuples present             -> reset to ``PENDING`` and retry
* delete batch, no tuples remain             -> mark ``SUCCEEDED``
* delete batch, all tuples remain            -> reset to ``PENDING`` and retry
* any partial/ambiguous presence             -> raise :class:`MigrationRecoveryError`

Writes carry ``on_duplicate=ignore`` and deletes ``on_missing=ignore`` so an
acknowledged-but-retried batch stays idempotent. The plan guard refuses to
write anything outside the approved set, so a withdrawn relationship can never
be revived, and revoked tuples are only ever removed through explicit deletes.
"""

import os

from openfga_sdk.client.client import OpenFgaClient
from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.client.models.write_conflict_opts import (
    ClientWriteRequestOnDuplicateWrites,
    ClientWriteRequestOnMissingDeletes,
    ConflictOptions,
)
from openfga_sdk.client.models.write_request import ClientWriteRequest
from openfga_sdk.migration.fake_service import LostResponseError
from openfga_sdk.migration.journal import (
    BatchOperation,
    BatchStatus,
    MigrationJournal,
)
from openfga_sdk.migration.plan import MigrationPlan, MigrationPlanError
from openfga_sdk.migration.tuple_key import tuple_identity
from openfga_sdk.models.read_request_tuple_key import ReadRequestTupleKey
from openfga_sdk.models.read_response import ReadResponse


class MigrationRecoveryError(RuntimeError):
    """
    Raised when an ``IN_FLIGHT`` batch cannot be reconciled against the store,
    or when the final store state does not match the approved plan.
    """


class MigrationResult:
    """Summary of a migration run."""

    def __init__(self, journal: MigrationJournal) -> None:
        counts = journal.counts()
        self.total_batches = len(journal.records())
        self.succeeded_batches = counts[BatchStatus.SUCCEEDED]
        self.failed_batches = counts[BatchStatus.FAILED]
        self.in_flight_batches = counts[BatchStatus.IN_FLIGHT]
        self.pending_batches = counts[BatchStatus.PENDING]
        self.complete = journal.is_complete()

    def __repr__(self) -> str:
        return (
            "MigrationResult("
            f"total={self.total_batches}, succeeded={self.succeeded_batches}, "
            f"failed={self.failed_batches}, in_flight={self.in_flight_batches}, "
            f"pending={self.pending_batches}, complete={self.complete})"
        )


class MigrationRunner:
    """
    Execute and recover a batched relationship migration.

    :param client: Connected :class:`OpenFgaClient`.
    :param plan: The approved/revoked relationship plan.
    :param journal_path: Filesystem path of the durable batch journal.
    :param batch_size: Maximum number of tuples per write batch.
    """

    def __init__(
        self,
        client: OpenFgaClient,
        plan: MigrationPlan,
        journal_path: str,
        batch_size: int = 10,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")

        self.client = client
        self.plan = plan
        self.journal_path = journal_path
        self.batch_size = batch_size

    def run(self) -> MigrationResult:
        """
        Entry point kept synchronous for callers that already manage an event
        loop; delegates to the async implementation.
        """
        import asyncio

        return asyncio.run(self.run_async())

    async def run_async(self) -> MigrationResult:
        journal = self._load_or_initialize_journal()
        await self._reconcile_in_flight(journal)

        for record in journal.records():
            if record.status == BatchStatus.SUCCEEDED:
                continue
            if record.status == BatchStatus.IN_FLIGHT:
                # Reconciliation could not settle it; stop rather than guess.
                raise MigrationRecoveryError(
                    f"batch {record.index} remains ambiguous after reconciliation"
                )

            await self._write_batch(journal, record.index)

            # A lost response leaves the batch IN_FLIGHT. Do not touch any
            # later batch: its state on the server is unknown and the next run
            # must reconcile this one first.
            if journal.get(record.index).status == BatchStatus.IN_FLIGHT:
                return MigrationResult(journal)

        if journal.is_complete():
            await self._verify_final_state(journal)
        return MigrationResult(journal)

    def _load_or_initialize_journal(self) -> MigrationJournal:
        if os.path.exists(self.journal_path):
            journal = MigrationJournal.load(self.journal_path)
            self._validate_journal_matches_plan(journal)
            return journal

        batches: list[list[ClientTuple]] = []
        operations: list[BatchOperation] = []

        for start in range(0, len(self.plan.approved), self.batch_size):
            batches.append(self.plan.approved[start : start + self.batch_size])
            operations.append(BatchOperation.WRITE)

        # Revoked relationships are removed only after all approved writes are
        # journaled, so an interrupted run never leaves a half-migrated store
        # without the replacement relationships in place.
        for start in range(0, len(self.plan.revoked), self.batch_size):
            batches.append(self.plan.revoked[start : start + self.batch_size])
            operations.append(BatchOperation.DELETE)

        return MigrationJournal.initialize(
            self.journal_path, batches, operations=operations
        )

    def _validate_journal_matches_plan(self, journal: MigrationJournal) -> None:
        write_ids: set[str] = set()
        delete_ids: set[str] = set()
        for record in journal.records():
            if record.operation == BatchOperation.DELETE:
                self._assert_in_plan(record, revoked=True)
                delete_ids.update(record.identities)
            else:
                self._assert_in_plan(record, revoked=False)
                write_ids.update(record.identities)

        missing_writes = self.plan.approved_ids - write_ids
        if missing_writes:
            raise MigrationRecoveryError(
                "journal is missing approved tuples: "
                + ", ".join(sorted(missing_writes))
            )

        missing_deletes = self.plan.revoked_ids - delete_ids
        if missing_deletes:
            raise MigrationRecoveryError(
                "journal is missing revoked tuples: "
                + ", ".join(sorted(missing_deletes))
            )

    def _assert_in_plan(self, record, *, revoked: bool) -> None:
        try:
            if revoked:
                for tuple_key in record.tuples:
                    if not self.plan.is_revoked(tuple_identity(tuple_key)):
                        raise MigrationPlanError("tuple is not in the revoked set")
            else:
                self.plan.assert_safe_to_write(record.tuples)
        except MigrationPlanError as err:
            raise MigrationRecoveryError(
                f"journal batch {record.index} is inconsistent with the "
                f"migration plan: {err}"
            ) from err

    async def _write_batch(self, journal: MigrationJournal, index: int) -> None:
        record = journal.get(index)
        if record.operation == BatchOperation.DELETE:
            self._assert_in_plan(record, revoked=True)
        else:
            self.plan.assert_safe_to_write(record.tuples)
        journal.mark_in_flight(index)

        try:
            if record.operation == BatchOperation.DELETE:
                request = ClientWriteRequest(deletes=record.tuples)
                options = {
                    "conflict": ConflictOptions(
                        on_missing_deletes=ClientWriteRequestOnMissingDeletes.IGNORE
                    )
                }
            else:
                request = ClientWriteRequest(writes=record.tuples)
                options = {
                    "conflict": ConflictOptions(
                        on_duplicate_writes=ClientWriteRequestOnDuplicateWrites.IGNORE
                    )
                }
            await self.client.write(request, options=options)
        except LostResponseError:
            # The response is gone but the write may have landed. Leave the
            # batch IN_FLIGHT and reconcile on the next run instead of retrying.
            return
        except Exception as err:
            journal.mark_failed(index, err)
            return

        journal.mark_succeeded(index)

    async def _reconcile_in_flight(self, journal: MigrationJournal) -> None:
        for record in journal.records():
            if record.status != BatchStatus.IN_FLIGHT:
                continue

            present = await self._which_tuples_exist(record.tuples)
            expected = set(record.identities)

            if record.operation == BatchOperation.DELETE:
                # A delete is confirmed when none of its tuples remain. If they
                # all remain the request never landed and must be retried.
                if not present:
                    journal.mark_succeeded(record.index)
                elif present == expected:
                    journal.reset_to_pending(record.index)
                else:
                    raise MigrationRecoveryError(
                        f"delete batch {record.index} is partially applied "
                        f"({len(present)}/{len(expected)} tuples still present); "
                        "manual intervention required"
                    )
                continue

            if present == expected:
                journal.mark_succeeded(record.index)
            elif not present:
                journal.reset_to_pending(record.index)
            else:
                raise MigrationRecoveryError(
                    f"batch {record.index} is partially applied "
                    f"({len(present)}/{len(expected)} tuples present); "
                    "manual intervention required"
                )

    async def _which_tuples_exist(
        self, tuples: list[ClientTuple]
    ) -> set[str]:
        present: set[str] = set()
        for tuple_key in tuples:
            response: ReadResponse = await self.client.read(
                ReadRequestTupleKey(
                    user=tuple_key.user,
                    relation=tuple_key.relation,
                    object=tuple_key.object,
                )
            )
            if response.tuples:
                present.add(tuple_identity(tuple_key))
        return present

    async def _verify_final_state(self, journal: MigrationJournal) -> None:
        if not journal.is_complete():
            raise MigrationRecoveryError(
                "migration did not finish; unresolved batches remain"
            )

        stored = await self._read_all_tuple_identities()

        revived = stored & self.plan.revoked_ids
        if revived:
            raise MigrationRecoveryError(
                "revoked relationships are present after migration: "
                + ", ".join(sorted(revived))
            )

        missing = self.plan.approved_ids - stored
        if missing:
            raise MigrationRecoveryError(
                "approved relationships are missing after migration: "
                + ", ".join(sorted(missing))
            )

    async def _read_all_tuple_identities(self) -> set[str]:
        identities: set[str] = set()
        continuation_token = None

        while True:
            options = {"page_size": 100}
            if continuation_token:
                options["continuation_token"] = continuation_token

            response: ReadResponse = await self.client.read(
                ReadRequestTupleKey(), options=options
            )
            for stored_tuple in response.tuples or []:
                key = stored_tuple.key
                identities.add(
                    tuple_identity(
                        {
                            "user": key.user,
                            "relation": key.relation,
                            "object": key.object,
                        }
                    )
                )

            continuation_token = response.continuation_token
            if not continuation_token:
                break

        return identities
