# Lazy-load access-order divergences

Divergences found by `tests/test_lazy_load_order.py` between the lazy
(`clr_lazy_load=True`) and eager (`clr_lazy_load=False`) metadata paths.
Each entry records the minimal access sequence and the sample patch that
reproduces it. All offsets are derived at runtime from an eager baseline
parse of `tests/data/hello-world/hello-world.exe`.

## D1: uncontrolled load-state error (RecursionError) on truncated rows

- Sample patch: truncate the file in the middle of the second TypeDef row,
  i.e. at `TypeDef.file_offset + TypeDef.row_size + TypeDef.row_size // 2`
  (`0x33e + 14 + 7 = 0x353` for the fixture).
- Minimal access sequence:
  ```python
  dn = dnfile.dnPE(patched, clr_lazy_load=True)
  dn.net.mdtables.TypeDef[1].Extends
  ```
- Before the fix: lazy path died with `RecursionError` (the dataless row
  stayed in the lazy-load state, so every attribute miss re-triggered the
  full loader). Eager path raised a controlled `AttributeError`.
- Fix: `ClrMetaDataTable._lazy_parse_row` (src/dnfile/base.py) now marks a
  row that can never receive data as loaded, so attribute access raises
  `AttributeError` and re-access is consistent.

## D2: rows past the truncation point missing (None) in lazy mode

- Sample patch: same truncation as D1.
- Minimal access sequence:
  ```python
  dn = dnfile.dnPE(patched, clr_lazy_load=True)
  dn.net.mdtables.MemberRef[1]  # table located after the cut
  ```
- Before the fix: lazy path returned `None` for every row of tables past
  the truncation point (their tables never received a lazy-load state),
  while the eager path returned dataless row objects. Row identity and the
  set of available fields therefore depended on parse mode.
- Fix: `MetaDataTables.parse` (src/dnfile/stream.py) now gives tables that
  never received data an empty lazy-load state, so their rows materialize
  (without data) on access, matching eager parsing.

## D3: corrupt rows reported fake `None` fields and spurious warnings

- Sample patch: same truncation as D1.
- Minimal access sequence:
  ```python
  dn = dnfile.dnPE(patched, clr_lazy_load=True)
  dn.net.mdtables.TypeDef[1].Flags  # row has no data
  ```
- Before the fix: lazy path returned `None` and emitted per-attribute
  warnings (e.g. "failed to fetch flag: no data"), presenting the truncated
  row as if it were valid but empty and masking the already-reported
  truncation. Eager path raised `AttributeError` without extra warnings.
- Fix: same change as D1; a dataless row no longer attempts per-attribute
  parsing.

## Allowed differences (not divergences)

- Warnings may be *delayed* until the first access that needs the data.
- Warnings may be *repeated* by the lazy path (e.g. "not enough data to
  parse row N" is emitted per accessed row, and a row parsed incrementally
  is parsed again during the full load).
- The invariant enforced by the tests: every warning produced by the eager
  parse must also appear on the lazy path (no masking), PE-level warnings
  (`dn.get_warnings()`) must be identical, and the public attribute view of
  every row must be identical once both parses are fully traversed.
