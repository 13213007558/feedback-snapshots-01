# Registry views and `Wow6432Node`

This note records what `dissect.regf` can and cannot answer for a "32-bit view"
option, and describes the opt-in API in `dissect/regf/views.py`.  The default
lookup behaviour of `RegistryHive` is unchanged.

## What the parser supports

`RegistryHive.open()` walks the stored key tree one path component at a time:

```python
def open(self, path: str) -> CellType:
    path = path.strip("\\")
    parts = path.split("\\") if path else []

    realpath = []
    node = self._root
    for part in parts:
        subkey = node.subkey(part)
        realpath.append(subkey.name)
        node = subkey
    return node
```

(source: `dissect/regf/regf.py:109`)

Consequences that matter for a view option:

- `Wow6432Node` is an ordinary subkey. Nothing in `regf.py` mentions it.
- `HKEY_LOCAL_MACHINE`, `HKLM`, drive paths and `\Registry\Machine` are not
  modelled. The hive is addressed relative to its own root key.
- Symbolic links are not dereferenced. `KEY.SYM_LINK` and `REG_LINK` exist as
  constants (`dissect/regf/c_regf.py:16`, `:154`) but are never read by
  `open()`. That is why this sample hive has `Select` but no physical
  `CurrentControlSet` key.
- Lookup depth is one hive. Cross-hive questions such as "is this value also in
  the SOFTWARE hive?" need another hive.
- Index lookup is mostly case-insensitive: `FastLeaf` and `HashLeaf` lower-case
  names, but `IndexLeaf.subkey()` compares with `==` (case-sensitive). The
  path helper in `views.py` falls back to a case-insensitive comparison, since
  Windows key names are case-insensitive.

`RegistryHive` also exposes metadata that is *not* trustworthy evidence on its
own:

- `RegistryHive.filename` comes from the hive base block (`regf.py:55`). It can
  be edited, so it does not prove which hive role a file really had. Use an
  external label (`hive_role`) instead.
- `RegistryHive.version` is the base block `Minor` field (`regf.py:49`), not the
  Windows build. It does not identify the OS version.
- `RegistryHive.dirty` is inverted in this checkout. The code sets
  `dirty = xor32_crc(...) == CheckSum` (`regf.py:57`) and warns when it is
  `True`, while the message claims the checksum *failed*. A hive whose checksum
  matches is reported as dirty. Do not use this flag as evidence until upstream
  is fixed; check the checksum yourself if it matters.

## What requires external evidence

The set of redirected and shared keys is not a property of the hive bytes. It
depends on:

| Question | Evidence needed |
| --- | --- |
| Is this process 32-bit or 64-bit? | Process bitness, not the hive |
| Is the OS 32-bit or 64-bit? | OS architecture (a 32-bit OS has no `Wow6432Node` split) |
| Which subtrees were redirected on this Windows build? | OS version / documented per-version rules |
| Was a key shared rather than redirected? | Ruleset for that build; the disk layout alone cannot show intent |
| Which control set is current? | `Select\Current` in the same SYSTEM hive, plus cross-hive checks |
| Is this hive really SOFTWARE/SYSTEM? | External provenance; the base-block filename is editable |

Two traps this API avoids:

- Do not blindly insert `Wow6432Node`. A key may exist only natively, only in
  `Wow6432Node`, or in both with different contents. All three are visible in
  the experiment hive.
- Do not treat "not found in the 32-bit view" as "the machine has no such
  configuration". Report the view miss together with whatever the other view
  contains.

## Interface

All types are in `dissect.regf.views` and re-exported from `dissect.regf`.

- `resolve_physical(hive, path) -> LookupResult`
  Default query. Exact, hive-relative, no rewriting. Status is `FOUND` or
  `NOT_FOUND`. A path that names a physical `Wow6432Node` subtree is reported
  with `mode=EXPLICIT_PHYSICAL` and is resolved literally, never rewritten a
  second time.
- `resolve_view(hive, path, view=..., policy=..., context=...) -> LookupResult`
  Logical query. `ViewKind.NATIVE` never rewrites. `ViewKind.WOW32` applies
  only the caller's `RedirectionPolicy`.
- `resolve_current_control_set(hive) -> ControlSetResolution`
  Resolves `Select\Current` inside the same hive and reports `NEEDS_CONTEXT`
  when the evidence is absent.
- `RedirectionRule` / `RedirectionPolicy` / `load_policy()`
  Rules are plain data (JSON-loadable). A rule can require `os_arch`,
  `process_bits`, `os_version`, or any explicit context field.
- `LookupContext`
  Optional `os_arch`, `process_bits`, `os_version`, `hive_role`,
  `control_set`, `source`. Missing required fields are reported, never filled
  with defaults.

Statuses are deliberately distinct:

- `FOUND` / `NOT_FOUND` — physical result.
- `NOT_FOUND_IN_VIEW` — the requested view has no such key; `alternatives`
  may contain the other view.
- `NEEDS_CONTEXT` — a rule could not be evaluated; `required_context` lists
  what to supply.
- `OUT_OF_SCOPE` — no rule covers the path, or the policy is for another hive
  role. `UnmatchedPolicy.PASSTHROUGH` is the explicit opt-in to fall back to
  the physical path.
- `RULE_CONFLICT` — the path already names `Wow6432Node` (explicit physical
  path), or two equally specific rules disagree.
- `INVALID_PATH` — the path is absolute (`HKLM\...`) or malformed.

## Experiment

`tests/hive_builder.py` builds a valid hive with both keys on disk:

```
Software\Classes\CLSID\{...}                 -> native-64
Software\Wow6432Node\Classes\CLSID\{...}     -> wow-32
Software\NativeOnly                          -> native-64
Software\Wow6432Node\WowOnly                 -> wow-32
```

Query results (see `tests/test_views.py`):

| Query | Mode | Status | Physical path |
| --- | --- | --- | --- |
| `Software\Classes\CLSID\{...}` | physical | `FOUND` | native path, `native-64` |
| `Software\Wow6432Node\Classes\CLSID\{...}` | explicit physical | `FOUND` | wow path, `wow-32` |
| same CLSID, view `wow32`, rule applies | logical | `FOUND` | wow path, `wow-32` |
| `Software\Classes`, view `wow32`, `Classes` shared | logical | `FOUND` | native `Software\Classes` |
| `Software\NativeOnly`, view `wow32` | logical | `NOT_FOUND_IN_VIEW` | `Software\Wow6432Node\NativeOnly` + native alternative |
| explicit `Wow6432Node` path, view `wow32` | logical | `RULE_CONFLICT` | — |
| `Select`, view `wow32`, no rule | logical | `OUT_OF_SCOPE` | — |
| version-gated rule, no `os_version` | logical | `NEEDS_CONTEXT` | `required_context=("os_version",)` |

On the repository `SYSTEM.gz`, `resolve_current_control_set()` returns
`ControlSet001` from `Select\Current`; `ControlSet001\Services\Tcpip` in a
32-bit view is `NOT_FOUND_IN_VIEW` while the native key is attached as an
alternative. The sample has no `Wow6432Node` keys at all, which is exactly why
the API refuses to infer machine-wide absence from a view miss.

## Not implemented

- Automatic per-Windows-version rule sets. Callers must supply and version
  their own policy; this keeps the parser honest about what the bytes prove.
- Symbolic link / `REG_LINK` dereferencing. `resolve_current_control_set()`
  uses `Select\Current` and reports a symlink key if present.
- Cross-hive lookups (SYSTEM + SOFTWARE + user hives). Compose results from
  multiple `RegistryHive` instances and keep provenance per hive.
