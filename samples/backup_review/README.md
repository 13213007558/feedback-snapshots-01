# Backup review — scoped Atomic Read/Write File adapter

A BACpypes3 service adapter for a backup review interface that only reads an
approved range of a BACnet File object.  It implements the AtomicReadFile
and AtomicWriteFile services (ASHRAE 135 §15.6/§15.7) directly on the
BACpypes3 APDU structures and keeps record access separate from byte
(stream) access.

## Files

- `backup_file_adapter.py` — transport-independent mixin plus in-memory files
  and the authorization context.
- `backup_review_server.py` — a full `Application` wiring the mixin to a live
  stack and registering two review File objects.
- `../../tests/test_backup_review/test_backup_file_adapter.py` — off-network
  tests that capture the response APDUs and re-encode/decode them on the wire.

## Authorization model

A `ReadGrant` fixes, per File object:

- the object identifier,
- exactly one access method (`streamAccess` or `recordAccess`),
- a half-open readable window `[range_start, range_end)` in that method's own
  unit (octets for stream, record indices for record).

A `WritePolicy` defaults to deny and only allows a write when an explicit
`WriteGrant` covers it **and** it stays inside the read grant using the same
access method. Switching the access method on a request never widens the
approved scope.

## Protocol results

| Condition | Result |
| --- | --- |
| Unknown File object | Error, object / `unknownObject` |
| No read grant | Error, services / `fileAccessDenied` |
| Request mode differs from the granted mode | Error, services / `invalidFileAccessMethod` |
| Negative start position/record | Error, services / `invalidFileStartPosition` |
| Start at/beyond the window end | Error, services / `invalidFileStartPosition` |
| Request extends past the window | ACK clamped to the window (no data leaks) |
| Missing/unknown access method | Reject, `missingRequiredParameter` |
| Record write `recordCount` mismatch | Reject, `inconsistentParameters` |
| Any write without an explicit grant | Error, services / `writeAccessDenied` |

## Stream vs record addressing

The two modes are different address spaces and are backed by different
in-memory classes:

- `StreamBackupFile` is one `bytes` buffer; a position is an octet offset and
  the ACK returns `fileStartPosition` + `fileData` (an `OctetString`).
- `RecordBackupFile` is a list of `OctetString` records; a position is a record
  index and the ACK returns `fileStartRecord`, `returnedRecordCount` and
  `fileRecordData`.

The same numeric offset therefore names different content: offset 4 in stream
mode is the single octet at byte 4, while offset 4 in record mode is the whole
record at index 4. The test
`test_same_offset_is_octet_range_vs_record_range` pins this distinction and
asserts the wire-decoded start, content and end-of-file flag.

## Run the tests

```bash
pytest tests/test_backup_review/
```
