# Manifest conflict diagnosis for `dissect.etl`

Reproducible, offline investigation of one symptom: **two collection machines
export ETL with the same provider GUID, but the field interpretation differs.**

Everything here runs against the checked-in `dissect.etl` source, a small
hand-built ETL writer, and XML manifests committed in this directory. No
network, no external ETL, no template service.

## Quick start

```sh
.venv/bin/python diagnostics/build_fixtures.py     # regenerate fixtures
bash diagnostics/run_all.sh                        # run every scenario, write diagnostics/out/*
.venv/bin/python diagnostics/two_machines.py       # the two-machine sequence in one process
.venv/bin/python -m pytest -q -o addopts= tests/test_manifest_conflict_diagnostics.py
```

Outputs land in `diagnostics/out/` (text tables plus JSON for machine use).

## Contents

| Path | Purpose |
| --- | --- |
| `diagnose.py` | CLI: `inspect`, `compare`, `cache-order`, `probe` |
| `build_fixtures.py` | Byte-exact writer for the small ETL fixtures |
| `two_machines.py` | Same process reads exporter A then B, and the reverse |
| `manifests/*.xml` | Conflicting and probe manifests for the same GUIDs |
| `fixtures/*.etl` | Committed ETL inputs (hundreds of bytes each) |
| `out/*` | Captured reports from `run_all.sh` |

## The four things worth recording

For every event record the tool records these independently, because each can
mislead on its own:

1. **Manifest provenance** – which module answered the GUID lookup
   (`origin`, absolute location, SHA-256, provider name/symbol, event count).
2. **Event descriptor** – `id`, `version`, `channel`, `level`, `opcode`, `task`,
   `keywords` from the record header, plus the `(opcode, version)` lookup key.
3. **Layout** – static size, every field name/type/offset, dynamic fields, and
   the `EtwPointer` width at parse time.
4. **Byte accounting** – bytes consumed, bytes left unconsumed, per-field
   dynamic sizes.

`fit` in the tables is `exact`, `padded`, `truncated`, `abi-error`, or
`no-entry`. It describes the bytes, **not** whether the manifest is correct.

## What the fixtures show

### `manifest_v1_v2.etl` — the actual conflict

One 29-byte payload, provider GUID `13976d09-…` (also present in the bundled
manifest set), descriptor `id=32 op=32 ver=2`. Three manifests consume it
exactly and raise nothing:

| candidate | origin | layout | result |
| --- | --- | --- | --- |
| `repo` | bundled resource | `Component:u32, Level:u32, Message:str` | exact, 0 left |
| `v1` | `provider_v1.xml` | `Component:u32, Level:u32, Message:str` | exact, 0 left |
| `v2` | `provider_v2.xml` | `SessionId:GUID, Sequence:u64, Bytes:u32, Detail:str` | exact, 0 left |

`v1` and `v2` are byte-for-byte indistinguishable by "did it parse" and by
"did it consume everything". Only the declared field layout differs, and bytes
cannot rank one above the other. This is the `caller-must-choose` case.

### `exporter_a.etl` / `exporter_b.etl` — load order decides

`two_machines.py` reads the two files in one process:

- A first: B is parsed with A's v1 template; B's GUID/sequence bytes are
  reinterpreted as `Component`/`Level` and a 20-byte "Message". No exception.
- B first: A fails with `EOFError` against the 24-byte fixed prefix.
- Fresh cache per file: both parse correctly.

The cache is keyed by GUID only (`manifest.CACHE`), so **the first manifest
loaded in a process wins for every later file with that GUID**, regardless of
which exporter produced it.

### `alpc_conflict.etl` — key space and exactness are different questions

Uses real GUID `45d8cccd-…` (ALPC) with candidate manifests `repo`, `b`, `c`,
plus probes:

- record 1 (4 B): `repo` and `probe34` both fit exactly → ambiguous.
- record 2 (24 B): `b` and `c` both fit exactly with different layouts →
  ambiguous.
- record 3 (28 B): every candidate leaves bytes → no exact answer.
- record 4 (id 34): only `repo` has the event → precise.
- record 5 (`id=33 opcode=1`): lookup key `(1,2)` misses everywhere, while
  descriptor id `(33,2)` resolves. The event is real, the lookup is wrong.
- record 6 (id 99): only `probeother` covers it → source coverage matters.

### `shellcore_collision.etl` — a wrong template can look perfect

Real bundled manifest, real collision. Event id `6206` arrives with header
`OpCode=2`. `dissect` looks up `(2, 0)` and gets
`AggregatePropertyProvider_GetValueStop` (`FMTID:GUID, PID:u32`, 20 bytes),
while the descriptor id `6206` is `Thumbnails_CacheLookupStop`
(`HRESULT:u32, LowQuality:u8`, 5 bytes).

With a 20-byte payload the wrong template consumes **exactly 20 bytes and
raises nothing**. With a 5-byte payload it raises `EOFError`. "No exception"
is therefore not evidence: the same wrong lookup flips between silent success
and a crash depending only on payload length.

### `pointer_width.etl` — per-record global ABI state

`parse_payload` mutates `module.c_parser.EtwPointer` on the **cached module**
for each record based on `header.is_64bit`. Consequences:

- parsing is order-dependent: a 32-bit record after a 64-bit record sees the
  previous record's width until the next mutation;
- the generated `EtwPointer.as_32bit` is missing `@classmethod`
  (`manifest.py:73`), so the 32-bit branch raises
  `TypeError: EtwPointer.as_32bit() missing 1 required positional argument`.
  The diagnostic reports this as `abi-error` before blaming a template.

### `broken_manifest.etl` — compile failures are not `ManifestNotFoundError`

352 of the 841 bundled manifests raise during `compile_xml` (`KeyError`,
`SyntaxError`, `ParserError`, `ParseError`). `lookup()` only converts `IOError`
into `ManifestNotFoundError`, and `parse_payload` only catches
`(ManifestNotFoundError, AttributeError)`. A broken bundled manifest therefore
escapes as `KeyError('Binary')` from `record.event`. Absence of a manifest and
a broken manifest are *different* failures and should be reported separately.

## Source call chain

Record construction (`dissect/etl/etl.py`):

```
ETL.__init__                       etl.py:52   first buffer, logfile header, pointer_size
Buffer.__iter__ -> read_record    etl.py:158  marker -> header type (utils.py:49-61)
EventRecord.event                 etl.py:206  lazy parse_payload(header)
parse_payload                     etl.py:295  manifest.lookup(header.provider_id)
                                             -> Event(header, mf)
Event.__init__                    etl.py:230  key = (header.opcode, header.version)
                                             EVENTS[key]; template(header.payload)
                                             KeyError -> _struct = None (silent)
manifest.lookup                   manifest.py:167
  1. CACHE[guid]                             process-global, first wins
  2. importlib.import_module("dissect.etl.manifests.{guid}")
  3. compile_xml(get_resource_string("manifests/xml/{guid}.xml"))
generate_from_xml                 manifest.py:211
  - templates -> cstruct struct per <template tid>
  - EVENTS key built from <event value, version>   manifest.py:269-275
  - Structure._calc_offsets patched globally       manifest.py:34
Event.event_values                etl.py:270  reads self._struct._values (cstruct 4.8: __values__)
```

Two independent identity spaces meet here:

- the **record descriptor** carries `id`, `version`, `channel`, `level`,
  `opcode`, `task`, `keywords` (`headers/event.py:50`);
- the **manifest entry** is indexed by `(event value, version)`, but
  `Event.__init__` looks it up by `(header.OpCode, header.Version)`.

They coincide for legacy kernel providers (`opcode == value`, e.g. ALPC) and
diverge for modern providers (`opcode="win:Stop"` with `value=6206`). Across
the bundled manifests, 17,971 templated events have no `opcode` attribute at
all, 8,760 use `win:*` symbolic opcodes that differ from `value`, and 426
events share a `(value, version)` key, so later entries silently overwrite
earlier ones in the generated dict.

## What can be decided precisely

Precise (single candidate, no caller input):

- the descriptor id resolves in exactly one candidate and its template
  consumes the payload exactly (`[precise]`);
- the same holds through the `(opcode, version)` key **and** agrees with the
  descriptor id;
- exactly one candidate defines a unique event id that others lack
  (`alpc_conflict.etl` record 6).

Needs the caller to choose a source:

- several candidates fit the descriptor id exactly (`manifest_v1_v2.etl`,
  `alpc_conflict.etl` records 1–2);
- only `(opcode, version)` entries exist and disagree with the descriptor id;
- no candidate consumes the payload exactly, but several are plausible
  (`[caller-or-source-required]`).

Unresolvable from the file alone:

- unknown GUID: no manifest anywhere (do **not** silently fall back to
  descriptor-only values as if they were manifest fields);
- broken bundled manifest: report the compile error, not "not found";
- two byte-identical layouts with different semantics: only a
  provider-symbol/version attestation from the exporter can decide.

## Implemented guidance (no template service required)

The diagnostic itself is the tool; the following are the changes it argues for
in `dissect.etl`. They are recommendations, not applied to library code here.

1. **Key by descriptor id, not header opcode.** Build a second index
   `EVENTS_BY_ID[(value, version)]` and try it first; keep the opcode key only
   as a fallback for legacy providers. Log which key matched.
2. **Make cache identity explicit.** Replace `CACHE[guid]` with a
   `ManifestRef(guid, source, sha256, width)` key or provide
   `lookup(guid, source=...)`; expose `cache_clear()`/`use_manifest()` so a
   caller can pin one source per investigation. Never let two files with the
   same GUID silently share a template.
3. **Check consumption.** After `template(payload)`, compare
   `len(payload) - stream.tell()`; expose it on `Event` and treat `> 0` as
   `TrailingPayload` rather than success. Report it per record.
4. **Never swallow the KeyError.** `except KeyError: _struct = None` hides a
   missing event and a wrong-key lookup identically; raise or attach
   `lookup_key`/`descriptor_id` to the event.
5. **Separate errors.** `lookup()` should wrap compile failures in
   `ManifestNotFoundError` (or a new `ManifestCompileError`) with the manifest
   location; `parse_payload` should not swallow them as "no manifest".
6. **Per-record pointer width.** Pass width into template parsing instead of
   mutating the cached module; add `@classmethod` to `EtwPointer.as_32bit`
   (`manifest.py:73`). The same applies to `UserSID_blob`.
7. **Exporter attestation (optional, caller-side).** When byte fit is
   ambiguous, require the caller to supply the expected provider
   symbol/version (e.g. from the export job config). Comparing
   `PROVIDER_SYMBOL` + manifest SHA-256 across the two machines decides the
   `manifest_v1_v2.etl` case precisely; the library cannot decide it from
   bytes alone.
