# Binary synthesis: products and provenance

`SmdaReport.synthesizeBinary()` rebuilds a **fictive** PE, ELF or Mach-O file from a recovered
CFG. The output exists so that similarity tooling (BSim-compatible analyses, MCRIT-style indexers)
and re-disassembly frontends (IDA, Ghidra, Binary Ninja) can load recovered code at its original
virtual addresses. **It is not a recovered original file**, and nothing in the pipeline treats it
as one: any byte the report cannot account for is newly generated structure, and the provenance
manifest below is what keeps the two kinds of bytes distinguishable downstream.

## Byte provenance

Every byte of a synthesized file has exactly one of these origins:

| origin | what it is | where it comes from |
|---|---|---|
| `recovered_block` | instruction bytes of one basic block | `report.xcfg` — byte-identical to what the disassembler read |
| `recovered_string` | bytes of a referenced string | `stringrefs` in the report, re-encoded (ascii/utf-8) |
| `import_slot` | an import thunk slot | the **address** is recovered from `xmetadata.imported_functions`; the **content** written into it is generated |
| `generated` | everything else | created by the synthesizer |

`generated` covers: file headers, section alignment padding, NOP fill between and around planted
blocks, the import descriptor/hint/name tables, IAT gap padding and terminator slots, and string
terminators. None of it is recovered, and none of it may be read as a fact about the original file.

## The special cases

- **Non-contiguous basic blocks.** Blocks of one function are planted per block, not per function
  extent, because they are not necessarily contiguous. The gap between two blocks of the same
  function is generated NOP fill — the manifest lists each block as its own region precisely so
  that nobody mistakes the gap for recovered code.
- **Same-address conflicts.** A well-formed report cannot contain overlapping blocks (the CFG
  model forbids it), but a hand-built one can. Planting happens in ascending function-offset, then
  ascending block-offset order, and the later planting wins. Every overlap is recorded in the
  manifest's `conflicts` list with the winning and the overwritten source.
- **Missing buffer (`STORE_BUFFER`).** Synthesis is deterministic from report content only. It
  never consults `report.buffer`, so a report analyzed with `STORE_BUFFER = False` (no stored
  buffer) synthesizes byte-identically to the same report with the buffer stored. The switch keeps
  its existing meaning — persist the analyzed buffer inside the report for carving — and has no
  effect on synthesis or on the manifest.
- **Import metadata.** `xmetadata.imported_functions` contributes slot addresses and (dll, name)
  pairs. The synthesizer builds a new import structure around them: thunk values, descriptors,
  hint/name blobs and DLL strings are all generated, IAT gaps up to a bound are padded with
  invented ordinal-0 thunks, and a slot that fits no data section is relocated into a synthetic
  IAT (recorded in the synthesizer's warnings). The manifest lists the *reported* slot addresses.

## Guarantees

- **The report is never modified.** Synthesis and manifest construction are pure functions of
  report content; `report.toDict()` is identical before and after either runs.
- **Deterministic.** Same report, same bytes, same manifest.
- **No layout fabrication.** A file layout the report cannot prove (original section contents,
  unrecovered data, headers beyond the stored `xheader`) is not reconstructed and passed off as
  recovered — it is generated, and the manifest's `default_origin: generated` says so.

## The provenance manifest

`SmdaReport.synthesisProvenance()` returns a JSON-serializable dict meant to be stored by a
backend next to the synthesized bytes:

```python
manifest = report.synthesisProvenance()
blob = report.synthesizeBinary()
```

```json
{
  "kind": "smda.synthesis.provenance",
  "format_version": 1,
  "architecture": "intel",
  "base_addr": 4096,
  "regions": [
    {"origin": "recovered_block", "va_start": 4096, "va_end": 4101, "size": 5,
     "sha256": "...", "function_offset": 4096, "block_offset": 4096}
  ],
  "conflicts": [],
  "default_origin": "generated",
  "generated_structures": ["file_headers", "section_alignment_padding", "nop_fill",
                           "import_tables", "iat_gap_padding", "iat_terminators",
                           "string_terminators"],
  "notes": ["..."]
}
```

- `regions` — every recovered range, with `sha256` of the expected content where content is
  recovered, so an independent reader (e.g. LIEF) can verify a synthesized file against the
  manifest without trusting the synthesizer. `import_slot` regions carry `content_origin:
  generated` because only their address is recovered.
- `conflicts` — same-address overlaps between recovered blocks (see above).
- `default_origin` — the origin of any byte not covered by `regions`.
- The manifest is format-agnostic: it describes the address space all three synthesizers plant
  into, not one file's layout. It accepts the same `function_offsets`, `with_imports` and
  `with_strings` filters as `synthesizeBinary()`.

## What the output is good for — and what it cannot prove

Suitable for:

- similarity and clustering tooling that consumes PE/ELF/Mach-O files (BSim-compatible pipelines),
- loading recovered code into an interactive disassembler at the original VAs,
- re-running SMDA or another disassembler over the recovered instruction stream.

Not evidence for:

- the original file's section layout, names or sizes beyond what the stored `xheader` records,
- any byte the analysis never recovered — data sections, unreferenced code, overlays, resources,
- the original import structure (IAT layout, hint values, ordinal-vs-name choices beyond the
  report's strings),
- timestamps, checksums, signatures, relocations, exception tables or any other header metadata —
  all generated,
- executability or provenance of the original sample. A synthesized file must never be presented
  or stored as a recovered original.
