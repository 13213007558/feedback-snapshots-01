# CIM capture consistency check (read-only)

`dissect.cim.consistency` inspects a captured `INDEX.BTR` + `OBJECTS.DATA` +
`MAPPING*.MAP` set and reports what the bytes prove versus what the material
cannot answer. It never writes to, repairs or rewrites the inputs.

```sh
python -m dissect.cim.consistency /path/to/capture        # text report
python -m dissect.cim.consistency /path/to/capture --json # machine readable
```

Any subset of `MAPPING*.MAP` is accepted; a missing file is reported as missing
material, not as evidence of tampering.

## Layout facts this check relies on

Each `MAPPINGn.MAP` holds **two** mapping tables back to back, not one:

| table | declared pages | entries | maps |
| --- | --- | --- | --- |
| object table | 3020 | 2853 | logical object page -> `OBJECTS.DATA` page |
| index table | 653 | 453 | logical index page -> `INDEX.BTR` page |

`CIM.__init__` opens one file and reads the object table then the index table
from it (`dissect/cim/cim.py:71`, `dissect/cim/cim.py:80`), and
`Store.page()` treats entry 0's `used_space` as the root logical page
(`dissect/cim/index.py:78`).

## What is checked

- **layout**: both tables present, same declared version, table version vs the
  other table.
- **capacity**: declared `physical_page_count` versus the real file size, split
  into *proven truncation* (a mapped page lies past EOF) and *insufficient*
  (nothing mapped is cut off).
- **generation**: header `first_id`/`second_id` versus the per-entry stamps.
- **page identity**: index pages must carry the `logical_id` their mapping entry
  assigns; object pages must have a TOC consistent with the entry's declared
  `free_space`. `page_crc` is never trusted — the library does not validate it,
  and CRC-32/CRC-32C do not reproduce it.
- **selection**: the file `find_current_mapping` picks (strict `>` on version,
  first file wins ties) versus the highest declared generation.
- **references**: the index B-tree is read through candidate *A*'s index table
  and every data reference is resolved through candidate *B*'s object table,
  for every *A* x *B* pair. Same-file pairs must resolve completely; cross-file
  pairs that dangle prove the two files are not from one capture state.

## Verdicts

- `trusted_with_caveats` — at least one complete mapping resolves all of its own
  references; cross-combination warnings and open questions are still listed.
- `untrusted` — every complete mapping has dangling self-references.
- `insufficient` — no complete mapping, or nothing traversable.

Never merge page tables from different generations to read more: the
cross-combination matrix exists precisely to show that such a view dangles.

## Worked example: the three shipped fixtures

Running the check on `tests/_data` (decompressed) yields:

```
verdict: trusted_with_caveats
recommended view: MAPPING2.MAP
```

- `MAPPING1`/`MAPPING2` share version `0x9ee6` but declare generations
  `0x1ac`/`0x1ad`; `MAPPING3` is older still (`0x9ec4`, `0x1ab`, clean flag 0).
- `find_current_mapping` picks `MAPPING1` because it compares with `>` and
  therefore keeps the first file on a version tie — not because it is newest.
- `MAPPING1` and `MAPPING3` map 8 object pages and 33 index pages differently
  (e.g. logical 2244 -> physical 2792 vs 18).
- Each file's index keys resolve 100% against its *own* object table
  (11949/11949, 11949/11949, 11951/11951), but cross-combining them dangles:
  22 refs for `MAPPING1` index x `MAPPING3` objects, 24 the other way.
- Undecidable: `page_crc` cannot be recomputed; the index table declares 653
  pages while `INDEX.BTR` holds 652 (highest mapped page 596, so nothing is
  truncated); no file carries an independent capture timestamp.

## Interpretation rules used

- A **proven** finding needs two independent byte-level observations that cannot
  both be true, e.g. index page `logical_id` versus the mapping entry, or a
  data reference that resolves in one table and dangles in another.
- A finding is **insufficient** when the bytes are *compatible* with several
  explanations, e.g. a cleared clean flag, an unreferenced size shortfall, or
  identical tables under two different generation stamps.
- Agreement between two mapping files is circumstantial: nothing in
  `INDEX.BTR`, `OBJECTS.DATA` or `MAPPING*.MAP` records an independent capture
  time, so "same window" can never be proven, only made unlikely.
