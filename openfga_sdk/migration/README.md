# Resumable relationship migration

Helpers for moving OpenFGA role relationships in safe, journaled batches when
individual write responses can be lost.

## Components

- `MigrationPlan` — the target state. `approved` tuples are the only
  relationships the migration may create; `revoked` tuples must be removed and
  can never be re-created. A tuple present in both sets is rejected up front.
- `MigrationJournal` — durable, atomically replaced JSON state machine
  (`pending -> in_flight -> succeeded/failed`) for every write and delete batch.
- `MigrationRunner` — splits the plan into batches, executes them through the
  journal, and reconciles any `in_flight` batch by reading the store on the
  next run instead of blindly retrying.
- `FakeOpenFgaService` — in-process, stateful fake server (mounted by patching
  `RESTClientObject.request`) that honours `on_duplicate`/`on_missing` and can
  lose a single write response to simulate an ambiguous outage.

## Recovery semantics

Each batch is one transactional OpenFGA write, so it is atomic on the server.

- A write batch found fully present after a lost response is marked
  `succeeded`; if none of its tuples landed it is reset to `pending` and
  retried; a partial result raises `MigrationRecoveryError`.
- A delete batch is `succeeded` once none of its tuples remain; it is retried
  if all tuples are still present.
- Writes use `on_duplicate=ignore` and deletes `on_missing=ignore`, making
  retries idempotent.
- Revoked tuples are only sent in delete batches; the plan guard rejects any
  attempt to write a tuple outside the approved set.

## Minimal usage

```python
from openfga_sdk.client import ClientConfiguration
from openfga_sdk.client.client import OpenFgaClient
from openfga_sdk.migration import MigrationPlan, MigrationRunner

configuration = ClientConfiguration(api_url="http://localhost:8080")
configuration.store_id = "01YCP46JKYM8FJCQ37NMBYHE5X"

plan = MigrationPlan(
    approved=[{"user": "user:anne", "relation": "writer", "object": "doc:1"}],
    revoked=[{"user": "user:bob", "relation": "writer", "object": "doc:1"}],
)

async with OpenFgaClient(configuration) as client:
    runner = MigrationRunner(client, plan, "migration.journal.json", batch_size=10)
    result = await runner.run_async()
    # Re-call run_async() with the same journal path after any interruption.
```

The end-to-end behaviour, including the lost-response interruption and the
subsequent recovery, is exercised in
`test/migration/migration_recovery_test.py`.
