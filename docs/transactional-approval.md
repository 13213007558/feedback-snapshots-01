# Transactional approval

`Sidekiq::TransactionAwareClient` joins job publication to the outermost
database commit. It is enabled globally with `Sidekiq.transactional_push!`;
the examples below show direct use with an injectable transaction backend.

## Approval snapshot and JIDs

`approve` validates, normalizes, runs client middleware, verifies JSON
arguments, then deep-duplicates and freezes the payload. The returned
`Sidekiq::Approval` exposes the pre-allocated `jid` and exact approved
`payload`. Later mutation of the caller's original nested arguments cannot
change what is published. Redis adds the usual top-level `enqueued_at`
delivery metadata, but `args`, `jid`, class, queue, and all approval options
are otherwise the approved values.

```ruby
approval = client.approve(
  "class" => "InvoiceJob",
  "args" => [{"invoice_id" => invoice.id, "lines" => lines}]
)
approval.jid     # known before commit
approval.payload # frozen final job payload
client.push(approval)
```

## Savepoints and commits

The backend must provide `after_commit { ... }` or be a callable object whose
`call { ... }` registers an after-commit callback. With ActiveRecord 7.2+, the
default uses `ActiveRecord.after_all_transactions_commit`; older ActiveRecord
uses `AfterCommitEverywhere`.

A callback enlisted inside a savepoint belongs to that savepoint. Rolling the
savepoint back discards its approvals; releasing it merges them into the
outermost transaction. Approvals still pending when the outermost transaction
rolls back are discarded and are never sent to Redis. Only the outermost
commit starts publication.

Backends may implement `current_token` (or `transaction_id`) so an approval
records which transaction/savepoint scope owned it.

## Small approved batches

Use `approve_batch` plus `push_approved_batch`, or opt in through
`push_bulk(..., "transactional" => true)`.

- The fixed hard limit is `Sidekiq::TransactionAwareClient::MAX_APPROVED_BATCH_SIZE`,
  currently **10 job argument arrays** per approval.
- A lower `limit:`/`max:` may be supplied; a higher limit is rejected.
- The limit counts jobs (`args.size`), not total nested values or JSON bytes.
  Payloads must still satisfy normal Sidekiq/Redis size guidance.
- All JIDs and frozen payloads are available before commit. The group uses one
  `push_prepared_bulk` raw Redis push after commit.
- Use ordinary `Sidekiq::Client#push_bulk` for hundreds or thousands of jobs.
  Its existing slicing, lazy enumerator, return values, and immediate/non-
  transactional behavior are unchanged. `TransactionAwareClient#push_bulk`
  also preserves that behavior unless transactional approval is explicitly
  requested.

## Interrupted publication

Publication runs after the database commit. Therefore a Redis failure cannot
roll the database transaction back. The exception is re-raised from the
backend's commit/callback boundary and retains its original class (for example
`RedisClient::Error`). It is extended with
`Sidekiq::ApprovalPublishFailure`, exposing `jids`, `attempted_jids`, and
`approved_payloads`. The returned `ApprovedBatch` is marked `failed?` and also
retains the error.

An empty `confirmed_jids` list means publication was not confirmed; it does
not prove that Redis never executed an ambiguous interrupted command. Callers
can retry with `Client#push_prepared_bulk(batch.payloads)` and the same
pre-allocated JIDs, using the usual at-least-once/idempotent job strategy.
