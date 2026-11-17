# Metadata stream-table policy

dnfile reads the CLR metadata stream table as evidence, not as a simple name
dictionary.  Two stream headers can declare the same name, the same range, a
partially overlapping range, a zero-length range, or a range outside the
metadata directory.  Which stream a caller sees must not depend on the order in
which headers were walked.

## Selection options

`dnPE(..., stream_policy=...)` accepts `dnfile.StreamPolicy` or its string value.

| Policy | Behavior |
| --- | --- |
| `StreamPolicy.FORENSIC` (default) | Preserve every decoded header in header order. Keep the conflicting streams available as **candidate** bytes, report every conflict as a warning, and do not use a damaged entry for a name shortcut or for table/heap parsing when a structurally valid entry exists. |
| `StreamPolicy.STRICT` | Reject the whole stream table and expose `net.metadata = None` if any header is unreadable, duplicated, zero-length, overlapping, truncated, recovered, or declares a range outside the metadata directory. The reason is reported through `dn.get_warnings()` and `dn.net.stream_report.rejection_reason`. |

Strict rejection is intentionally not a partial parse: callers that require a
defensible success signal must not receive a half-populated `mdtables`, heaps,
or resource list.

## Preserved facts

Every decoded header produces a `dnfile.StreamTableEntry` in
`dn.net.stream_report.entries` (also available as
`dn.net.metadata.stream_report` when the metadata object survives):

- `slot`: position declared by `NumberOfStreams`; an unreadable slot leaves a
  gap but later headers keep their real slot.
- `header_rva` / `header_offset`: where the header itself was read.
- `offset` / `size`: the declared offset and size relative to the metadata root.
- `declared_rva` / `declared_end_rva`: the range the header claims.
- `read_size` / `read_end_rva`: the range actually read from the file, bounded
  by the metadata directory and by the bytes that exist.
- `statuses`: `duplicate_name`, `overlap_exact`, `overlap_partial`,
  `zero_length`, `outside_metadata`, `truncated`, `parse_error`, etc.
- `resolution`: `selected`, `shadowed`, `candidate`, or `alias`.
- `evidence`: `confirmed`, `candidate`, `empty`, or `rejected`.

The same fields are copied onto each `ClrStream` as
`stream.declared_range`, `stream.read_range`, `stream.statuses`, and
`stream.evidence`.  `net.stream_report.legacy_name_winners()` deliberately
reproduces the old last-header-wins map so the difference is observable.

## Evidence rules

- `confirmed`: the selected header is structurally valid, not a duplicate of
  another structurally valid header, fully readable, and inside the metadata
  directory.  Only confirmed `#~`/`#-` bytes together with confirmed
  `#Strings`, `#GUID`, and `#Blob` bytes make `net.type_evidence` confirmed.
- `candidate`: bytes exist but cannot be attributed to the stream alone (exact
  or partial overlap), were only partly readable (truncation), are zero-length,
  belong to an ambiguous duplicate name, or were recovered after a bad header.
  Candidate bytes are still exposed for inspection, but table rows, type names,
  method names, signatures, and resources derived from them are **not**
  confirmed evidence.
- `empty`: a selected zero-length stream.  It can be a legitimate empty heap,
  but it proves nothing by itself.
- `rejected`: no usable stream object for that header.

Derived evidence is exposed as:

- `net.type_evidence`: metadata tables plus the heaps that resolve type/member
  names and signatures.
- `net.resource_evidence`: resources, because their names and offsets come from
  `ManifestResource` rows in the table stream.
- `table.evidence` and `resource.evidence` inherit the corresponding value.

Only the selected stream for each name is parsed.  A malformed duplicate that
appears later cannot replace an earlier valid stream, and it cannot cause a
"complete" report through its name.

## Header-only samples and comparison

`examples/stream-policy/demo.py` copies the hello-world fixture and patches
only stream-table fields (name, offset, size).  Representative outcomes:

```text
clean                forensic: all streams confirmed; complete=True
                     strict:   accepted
exact-alias          forensic: #Strings and #US both candidate; type/resource candidate
                     strict:   rejected (overlap_exact)
partial-overlap      forensic: both ranges candidate; read ranges preserved
                     strict:   rejected (overlap_partial)
zero-length #GUID    forensic: #GUID evidence=empty; type/resource candidate
                     strict:   rejected (zero_length)
#Blob outside MD     forensic: #Blob candidate, read_size=0, no bytes taken from next section
                     strict:   rejected (outside_metadata)
duplicate-bad-last   forensic: legacy map picks the bad last #GUID, but the earlier
                              valid #GUID is selected and confirmed; complete=False
                     strict:   rejected (outside_metadata)
duplicate+zero #US   forensic: first #US selected; second shadowed as empty candidate
                     strict:   rejected (duplicate_name, zero_length)
```

In all cases the report keeps the original header order, the true header
offsets, the declared ranges, and the read ranges.  The warnings distinguish
"the bytes are present but ambiguous" from "the table as a whole is rejected".

## What candidates may be used for

Candidate bytes may be inspected, hashed, displayed, or compared with other
samples.  They must not be promoted to:

- confirmed type, method, field, or parameter names;
- confirmed signatures or coded-index targets;
- confirmed resource names or resource payload identities;
- a successful "fully parsed" status.

Callers that need a binary success/failure result should use the strict policy
and treat `net.metadata is None` / `net.stream_report.rejected` as failure.
Callers that need maximum forensic visibility should keep the default forensic
policy and gate their conclusions on `net.type_evidence`,
`net.resource_evidence`, and per-entry `evidence`.
