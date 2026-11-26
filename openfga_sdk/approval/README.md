# Approval-scoped temporary relationships

This package lets an approval service attach temporary (contextual)
relationships to an OpenFGA check while keeping the existing
`OpenFgaClient.check` / `OpenFgaClient.batch_check` interfaces unchanged.

Temporary relationships are only ever taken from an `Approval` issued for that
check, may be restricted to an object/relation `TupleScope`, and are recorded
in an audit trail at the moment they are dispatched.

## Concepts

- `TupleScope` — optional object/relation range. Any tuple outside the scope is
  rejected with `ScopeViolation` when the approval is issued.
- `Approval` — snapshots the approved tuples on creation and enforces a TTL.
  The snapshot is deep-copied, so later mutation of the caller's list never
  affects an in-flight check or a retry. `materialize()` re-checks expiry on
  every attempt and raises `ApprovalExpiredError` once lapsed.
- `ApprovalRegistry` — in-memory store of issued approvals plus a dispatch log
  (`ApprovalDispatchRecord`) capturing the exact tuples sent for every attempt.
- `ApprovalService` — wraps an `OpenFgaClient` (or any object exposing the same
  `check` / `batch_check` methods) and builds scoped, audited requests.

## Guarantees

- Data actually sent always comes from the corresponding approval's snapshot,
  never the caller's mutable list.
- Each retry re-materializes the snapshot and re-checks expiry; an approval
  that lapses while waiting blocks the retry rather than sending stale data.
- Checks without an approval keep working and send no temporary tuples.
- Temporary tuples are never written persistently and never leak into another
  single check or another batch row.

## Example

```python
from datetime import timedelta

from openfga_sdk.approval import ApprovalService, TupleScope
from openfga_sdk.client.models.check_request import ClientCheckRequest
from openfga_sdk.client.models.tuple import ClientTuple

service = ApprovalService(openfga_client)

approval = service.issue_approval(
    contextual_tuples=[
        ClientTuple(user="user:anne", relation="reader", object="document:budget")
    ],
    scope=TupleScope(object="document:budget", relation="reader"),
    ttl=timedelta(minutes=5),
)

await service.check(
    ClientCheckRequest(user="user:anne", relation="reader", object="document:budget"),
    approval,
)

# Every dispatched temporary tuple is traceable to the approval.
for record in service.registry.dispatches_for(approval.id):
    ...
```
