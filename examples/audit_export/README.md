# Annual audit export on SQLite

This example runs a realistic annual review against a self-contained SQLite
database. The review is allowed to see **when** a tracked object changed,
**what kind** of change it was and the object's **internal association
number** — nothing else. Original fields and historical snapshots never
enter an export file.

## What the dataset demonstrates

The seed command (`auditcase/management/commands/seed_audit_demo.py`) creates
ten historical rows covering every tricky case:

- **Multiple changes at the same timestamp** — two approved `LEGAL` changes
  share `2026-03-01T09:00:00Z`. Ordering falls back to the deterministic
  `history_id`, so both rows survive pagination in a stable order and the
  tie group can straddle a page boundary without loss.
- **A history author that has been deleted** — `former-officer` is removed
  after writing one change. `history_user_id` becomes `NULL` via
  `SET_NULL`; the exporter never reads the user relation, so the event is
  still exported.
- **Records the auditor cannot access** — `EXEC` department rows are
  filtered out by the `Q(department="LEGAL")` rule, including their
  deletion/change events. The rule runs against history columns, so it
  keeps working after the live object is gone.
- **Approved vs. unapproved snapshots** — rows whose `approved` flag is
  false are excluded; the half-open time window
  `[2026-01-01, 2027-01-01)` bounds the rest.

## Running it

```bash
bash run_demo.sh
```

The script builds `audit.sqlite3`, applies migrations, seeds the data and
writes two JSON Lines pages (three rows each) into `sample/`:

- `sample/audit-page-0001.jsonl`
- `sample/audit-page-0002.jsonl`
- `sample/export-summary.json` — the opaque cursor for resuming, written to
  stderr so it never mixes with data rows.

`verify_demo.py` then re-runs the export and asserts:

1. every row has exactly the keys `event_time`, `change_type`, `object_ref`;
2. no raw field name or field value (`case_secret`, `*-RAW-RECORD`, …)
   appears anywhere in the output;
3. the allowed event order is fully preserved, including the same-timestamp
   pair;
4. the second run is byte-identical to the checked-in pages.

## Why re-runs are stable

Pagination is keyset-based on the total ordering
`(history_date, history_id)`. The cursor returned for the next page is an
opaque base64 token encoding that pair; passing it back via `--cursor`
resumes the export without offset drift, skipped rows or duplicates. As long
as the underlying history table is unchanged, every run emits the same
bytes.

## Running individual commands

```bash
python manage.py makemigrations auditcase
python manage.py migrate
python manage.py seed_audit_demo
python manage.py export_audit auditcase.casefile \
  --page-size 3 --max-pages 10 \
  --start-time 2026-01-01T00:00:00Z --end-time 2027-01-01T00:00:00Z \
  --access-callback auditcase.access.legal_department_access \
  --out-dir sample
```

The same queryset machinery is available directly in Python through
`simple_history.audit.iter_audit_pages` for callers that build their own
access rules.
