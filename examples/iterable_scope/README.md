# Approval-scoped iterable jobs

This example demonstrates how a chunked `Sidekiq::IterableJob` can resume
safely when its approval scope changes. It runs entirely in-process with
`Sidekiq::Job::Iterable::MemoryStateStore`, so no Redis server or Sidekiq
process is needed.

```sh
ruby -Ilib examples/iterable_scope/demo.rb
```

The job defines two hooks:

- `approval_scope` returns a JSON-serializable descriptor of what has been
  approved, for example `{"record_ids" => [...], "ticket" => "..."}`.
- `iteration_commit_key(record_id)` returns a stable identity, recorded in a
  commit ledger after the record's business effect.

## What the demo shows

1. **Committed but not saved**: record 103 is applied, then the progress write
   fails. The retry keeps the same approval, sees 103 in the commit ledger,
   and does not apply it twice. Diagnostics report one recovered record.
2. **Scope narrowed midway**: the approval shrinks from six records to two.
   The old cursor is discarded (`c = null`) and only the newly approved
   records run. The wider cursor is never treated as permission.
3. **Legal resume**: an interruption with an unchanged approval resumes from
   the persisted cursor and finishes the remainder exactly once.

## Separation of concerns

- The **cursor** is a position, not a permission.
- The **scope digest** (`sd`) proves which approval the position belongs to.
- The **commit ledger** proves which effects already happened. It can only
  suppress duplicate work, never authorize an item.
- **Diagnostics** (`diag`) contain counters and a 12-character scope digest.
  Cursors and record payloads are never logged or rendered.
