# Forensic inspection evidence

This directory contains two hand-crafted, deliberately malformed ZIP micro
samples and the scripts that demonstrate the read-only inspection added under
`Zip::Forensic` (`require 'zip/forensic'`).

The samples are rebuilt deterministically by `build_samples.rb`; nothing about
the inspection repairs, normalises or re-interprets them.

## Reproducing

```shell
# Build both samples into this directory (or pass another output directory):
ruby samples/forensic/build_samples.rb

# Build, hash before/after, and print the full offset-based report:
ruby -Ilib samples/forensic/run_demo.rb
```

Every reported value keeps its provenance: the parsed value, the source
structure, an absolute byte offset, its length and the raw bytes, for example
`0 [EOCD bytes @0x00e0..@0x00e2: 00 00]`. A reviewer can jump straight to any
offset with a hex viewer, for example:

```shell
xxd -g1 -s 0x00f2 -l 25 forensic_duplicate_names.zip
```

## Sample 1 — `forensic_duplicate_names.zip` (267 bytes)

Two central directory records carry identical raw name bytes `dup.txt`
(`64 75 70 2E 74 78 74`), pointing at two distinct local headers with
different payloads. Twenty-five bytes are appended after the EOCD.

Structural map (decimal / hex offsets):

| Structure | Offset | Evidence |
| --- | --- | --- |
| local header #1 `dup.txt` | 0 / `@0x0000` | data `@0x0025..@0x002f`, body `first body` |
| local header #2 `dup.txt` | 47 / `@0x002f` | data `@0x0054..@0x0072`, body `second body, different content` |
| central record #1 `dup.txt` | 114 / `@0x0072` | local-header-offset field `@0x009c..@0x00a0` = 0 |
| central record #2 `dup.txt` | 167 / `@0x00a7` | local-header-offset field `@0x00d1..@0x00d5` = 47 |
| EOCD | 220 / `@0x00dc` | central-directory offset `@0x00ec..@0x00f0` = 114 |
| trailing bytes | 242 / `@0x00f2` | 25 bytes, preview `53 55 53 50 49 43 49 4F 55 53 ...` (`SUSPICIOUS...`) |

Findings:

- `duplicate_entry_name` at central records `@0x0072` and `@0x00a7`. Both
  records are retained in on-disk order; a name-keyed `EntrySet` (the ordinary
  `Zip::File` path) keeps only the last one, so `Zip::File#size` is 1 while the
  forensic report shows 2.
- Unparsed region: `trailing @0x00f2..@0x010b (25 bytes)`. These bytes are not
  interpreted as an entry; the inspector does not guess what they mean.

## Sample 2 — `forensic_misaligned_offsets.zip` (338 bytes)

Three local headers and three central records, with deliberately broken links.

Structural map:

| Structure | Offset | Note |
| --- | --- | --- |
| local header `orphan.bin` | 0 / `@0x0000` | referenced by no central record |
| local header `a.txt` | 54 / `@0x0036` | referenced by no central record |
| local header `b.txt` | 98 / `@0x0062` | referenced by central records #1 and #2 |
| central record #1 `a.txt` | 159 / `@0x009f` | offset field says 98 — points at `b.txt` |
| central record #2 `b.txt` | 210 / `@0x00d2` | offset field says 98 — same target as #1 |
| central record #3 `ghost.txt` | 261 / `@0x0105` | offset field says 58 / `@0x003a`, inside data, no header there |
| EOCD | 316 / `@0x013c` | declares 3 entries |

Findings (each with the exact field and target offsets):

- `local_central_name_mismatch` — central name at `@0x00cd` (`a.txt`) vs local
  name at `@0x0080` (`b.txt`).
- `dangling_local_header_offset` — central field at `@0x012f` points to
  `@0x003a` where no local header signature exists; `ghost.txt` is left
  `dangling_offset` and no entry is synthesised for it.
- `orphan_local_header` — `orphan.bin` at `@0x0000` and `a.txt` at `@0x0036`.
- `overlapping_data_ranges` — records #1 and #2 both claim the data range
  `@0x0085..@0x009f`.

For contrast, the ordinary API reads `a.txt` and silently returns `b.txt`'s
payload (`payload B, a little longer`) because it trusts the offset; the
forensic API never treats that as a confirmed, recovered entry.

## Read-only guarantee

`run_demo.rb` records each file's SHA256 and mtime immediately before and
after `Zip::Forensic.inspect` and asserts both are identical, and that the
report's embedded SHA256 matches. The inspector only ever seeks/reads; it has
no write path. For an IO object the original position is restored.

## Unparsed regions

Regions are classified as `preamble` (bytes before the first structure),
`gap` (bytes between parsed structures) or `trailing` (bytes after the EOCD).
They carry an offset, length, a short hex preview and a note. They are never
turned into entries: their meaning stays unconfirmed by design.
