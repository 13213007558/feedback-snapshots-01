# Offline WMI/CIM recoverability review

Scope: `dissect.cim` at `862df8a`, sample repository under `tests/_data`.
Question: can an offline `OBJECTS.DATA` / `INDEX.BTR` / `MAPPING*.MAP` set
recover *all instance properties* of a class, including dynamic properties and
qualifiers?

Short answer: **no, not "all".** The schema, many qualifiers, and a subset of
instance values are on disk. Dynamic values and several object/array/state
cases are not fully represented, and some of the current code paths produce
plausible-looking but wrong values. A report must label every value with its
provenance rather than printing `""`/`False` for unknown data.

Evidence below is from the bundled sample: 92 namespaces, 6,672 unique class
definitions (12,563 namespace/class views), 2,511 unique instance records,
2,313 instances yielded by `Class.instances`.

## Capability table

| Surface | What is on disk | Current handling | Source | Recoverable offline? |
|---|---|---|---|---|
| Class name, superclass, property names/indexes/offsets | Yes, class definition | Works | `classes.py:224-251`, `cim.py:240-262` | Yes |
| Builtin qualifiers `DYNAMIC`, `PROVIDER`, `KEY`, `READ_ACCESS`, `TYPE` | Yes (qualifier references) | Mapped | `c_cim.py:120-126`, `classes.py:359-368` | Yes; IDs 4/5 are unmapped and collapse to `None` |
| Ordinary string qualifiers | Yes (`property_data` region) | Works when pointer is in owning region | `classes.py:359-368`, `391-410` | Yes |
| Array qualifiers (`ValueMap`, `Values`, `MappingStrings[]`) | Yes (array of uint32 string offsets) | Returns the offsets, not strings | `classes.py:412-418` | Yes from existing bytes; code needs a decoder. Non-string array qualifiers already decode as typed values. |
| Schema default values | Yes (class default block) | Works, but array-flag sizing is wrong for `0x60` | `classes.py:116-124`, `cim.py:370-405` | Yes, with caveat below |
| Instance scalar values (string/number/bool) | Yes, when state says initialized | Works for scalar non-object types | `classes.py:310-325`, `420-441` | Yes |
| Instance string arrays | Yes (array of offsets) | Returns `uint32` offsets where strings are expected | `classes.py:412-418`, `421-422` | Yes from existing bytes; code needs a decoder. Non-string array element types already decode as typed values (if present). |
| Instance `OBJECT` / `OBJECT[]` | Raw bytes/offset are present | No decoder; raises `ValueError` | `classes.py:443` | Partially; semantics need format work, not collection |
| Instance property-state semantics | 2 bits per property | `0b10` consistent with default; `0b11` unresolved and can look like `False` | `classes.py:100-107`, `211-221`, `310-325` | Needs format confirmation for `0b11` |
| Inherited key properties | Key qualifier lives on ancestor | `ClassDefinition.keys` scans only own props | `classes.py:253-260`, `327-332` | Yes; code must walk derivation |
| Dynprops metadata (DYNPROPS-qualified class) | State, count, 41-byte records, data region | Reads 8 bytes then misaligns `DataRegion` | `classes.py:287-296`, `371-388` | Metadata bytes yes; field mapping is unimplemented |
| Dynamic class values (`CLASS_QUALIFIER_DYNAMIC`) | Only schema; values live in provider | N/A | `c_cim.py:120-126` | **No**; requires live/provider collection |
| Runtime-only properties of dynamic classes | Not in repository | N/A | — | **No** |

Legend: *yes from existing bytes* means an implementation change is enough;
*requires collection* means the fact is absent from this evidence. Source paths
are relative to the repository root; full ranges are in `experiments/SOURCE_MAP.md`.

### How each state is represented

The probe never renders unknown data as a value. Each result carries one of
these statuses:

| Status | Meaning | Example rendered result |
|---|---|---|
| `stored` | Bytes in this instance/class record | `{"property": "MyKey", "status": "stored", "value": "SR"}` (the current parser yields `""` instead) |
| `default` | Schema default, not an instance value | `{"property": "DeliverSynchronously", "status": "default", "value": false}` |
| `uninitialized` | State bits say no value was written | `{"property": "RPGlobalInterval", "status": "uninitialized", "value": null}` |
| `unsupported` | Bytes exist; no decoder in this code | `{"property": "Connection", "status": "unsupported", "value": 15}` (TOC offset, not an object) |
| `unavailable` | Structure is unimplemented or not present | `{"property": "dynprop metadata", "status": "unavailable", "value": {...raw bounds...}}` |
| `conflict` | Two on-disk sources disagree; do not choose silently | `{"library_class_name": "\x08", "library_value": "", "status": "conflict"}` (correct bytes give `"SR"`) |

`null` above means "no value", never "empty string". An empty string is only
emitted when the bytes actually encode one (`status: stored`, `value: ""`).

## Where it goes wrong

### 1. Dynprops boundary is skipped by a fixed 8 bytes

`ClassInstance.__init__` calls `Dynprops(buf)` then `DataRegion(buf)`
(`dissect/cim/classes.py:295-296`). `Dynprops` consumes the state byte and,
for `HAS_DYNPROPS`, two uint32s (`classes.py:371-383`). It does not retain or
interpret them.

In the sample's only dynprops instance, `root\DEFAULT:SystemRestoreConfig`,
the self-consistent layout is (one sample; field names below are descriptive,
not yet proven):

- `+0` state `0x02`
- `+1` uint32 count `4`
- `+5 .. +5+4*41` four records, each beginning with its own uint32 size `41`
- `+169..+173` int32 data-region size `561` (`0x231`)
- `+173 ..` data region, ending exactly at the record end (0 trailing bytes)

The current code reads the first two dwords after the state as opaque (they
are the count `4` and the first record's own size `41`) and then treats the
next dword (`0x23` = 35) as a `DataRegion` size. The result:

- `ClassInstance.class_name` decodes as `'\x08'`
- `MyKey` decodes as `''`
- every other property stays uninitialized, so the record appears to contain only an empty `MyKey`

This is a **silent wrong answer**, not missing data. The same bytes at the
correct boundary give `MyKey == "SR"`, class name `SystemRestoreConfig`, and
the declared size exactly consumes the record.

The probe (`experiments/cim_recoverability_probe.py`) demonstrates both
results side by side under `--json` and prints the record metadata.

### 2. String arrays are offsets, not values

`DataRegion.get_array` returns `ctype[size](buf)` (`classes.py:412-418`).
For a STRING array the ctype is `uint32`, so the result is a list of string
offsets. This affects both qualifiers and instance values. A real `ValueMap`
in the sample:

- library: `[2568, 2577, 2592, 2606, 2615, 2633, 2648, 2656]`
- bytes: `['Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown']`

The integer list is non-empty and plausible, so downstream JSON/CSV output
will look like data. It is not the qualifier value. The same defect affects 6,126 property *array* qualifier references in the
sample (plus 788 class *array* qualifiers), but only the STRING ones are
mis-decoded: in the CIMV2 namespace, 839 `ValueMap` and 53 `Values` qualifiers
are STRING arrays, versus one INT32 array. Non-string arrays already produce
typed values.

### 3. Inherited keys collapse instances

`ClassDefinition.keys` scans `self.properties` only (`classes.py:253-260`).
`__Win32Provider` declares no key of its own; `__Provider.Name` carries the
key qualifier. Therefore `ClassDefinition.keys` is empty, `InstanceKey` becomes
`"default"`, and `Class.instances` deduplicates every record under that key
(`cim.py:288-300`).

Measured in the sample:

- `root\CIMV2:__Win32Provider`: 47 distinct records, 1 instance yielded
- `root\DEFAULT:__Win32Provider`: 9 records, 1 yielded
- `root\WMI:WDMClassesOfDriver`: 3,097 index refs but only 1,588 distinct
  records; this class has its own keys, so all 1,588 are yielded (the index
  lookup itself returns duplicate references)
- whole sample: 2,511 distinct records, 2,313 yielded; 117 records lost this
  way across 18 class groups (plus one class that aborts entirely)

All 47 provider `Name` values are distinct and decodable. This is an
implementation defect, not missing evidence.

### 4. Array flag `0x40` / `0x60` is not just `0x20`

`ARRAY_STATES` defines only `NOT_ARRAY = 0x0` and `ARRAY = 0x20`
(`c_cim.py:105-108`). The sample also contains:

- `0x40`: 3,095 property definitions in 1,200 unique classes. It appears on
  both inherited and locally declared scalar properties, so on its own it does
  **not** mean array.
- `0x60`: 99 property definitions in 45 unique classes, which *are* arrays
  (e.g. `CIM_Slot.ConnectorType`, `Win32_Trustee.SID`)

Code uses equality `== ARRAY_STATES.ARRAY` in four places
(`classes.py:39, 143, 421`; `cim.py:274`), so `0x60` is treated as scalar.
For default-block sizing this is demonstrably wrong: comparing predicted size
to the declared `default_values_metadata_size` for 6,016 class definitions,
treating `0x20` as a bit matches **6,016/6,016**; equality matches only
5,955/6,016. The 61 mismatches all contain a `0x60` property (111 properties
total). Any implementation should treat `flag & 0x20` as array and keep the
rest of the bits separate.

### 5. `CIM_TYPES.OBJECT` has no path

`DataRegion.get_value` raises `ValueError("Unknown value type")` for
`OBJECT` (`classes.py:443`). In the sample, 191 direct instance properties
carry `OBJECT` values: 81 scalars and 110 arrays. All 81 scalars are in
`MSFT_CliAlias`. That class fails at the first `OBJECT` and loses all 81
distinct records during enumeration.

The raw TOC values are present (e.g. offset 15 for `Connection`), but object
semantics — embedded object layout, target class, nested properties — are not
implemented. This is a format/decoder gap, not something the live machine must
supply. `REAL32`, `REAL64` and `CHAR16` hit the same `Unknown value type`
branch but have no directly stored instance values in this sample, so their
instance path is unverified.

### 6. `0b11` property state is unresolved, not a value

`ClassInstance.properties` treats the upper state bit as "use
`prop.default_value`" (`classes.py:316-321`). That part is consistent with the
sample: all 923 properties with state `0b10` have a schema default, and their
TOC word is always `0` (unused). Returning the default is defensible there.

The unresolved case is `0b11` (upper bit set, "not initialized"):

- 3,054 properties, **none** of which has a class default
- `ClassInstanceProperty.is_default_value` returns `False` for all of them
  because `is_initialized` is false (`classes.py:211-215`)
- `.value` raises `ValueError("Property is not initialized")`
  (`classes.py:217-221`), which is safe, but a consumer that catches the
  exception and reads `is_default_value` sees `False`, not "unknown"

So the failure mode here is representational: an unresolved/absent property
can be mistaken for an explicit `False`. The sample does not establish whether
`0b11` means "provider default unavailable", "NULL", or something else; that
needs WMIO documentation or a controlled capture. It should be reported as
`UNKNOWN_STATE`, never as `False` or `""`.

`0b01` (51 properties) has no default and is not initialized; the same
representation rule applies. `0b00` (9,179 properties) uses the TOC and is the
normal stored-value case (689 of them also have a schema default, but lower
bit clear means the stored value is authoritative).

### 7. Unmapped builtin IDs become `None`

`BUILTIN_QUALIFIERS` lacks IDs 4 and 5 (`c_cim.py:120-126`). The sample uses:

- ID 4 (`PROP_QUALIFIER_WRITE_ACCESS` in WMIO terms): 4,807 property-qualifier
  references across unique class definitions, e.g. `__Trustee.Domain`,
  `__ACE.AccessMask`
- ID 5: once, on `Win32_NTEventlogFile.OverWritePolicy`

`Qualifier.__init__` calls `BUILTIN_QUALIFIERS(qualref.key).name`
(`classes.py:364-368`), which evaluates to `None`; the qualifier is then stored
under the `None` key and disappears from normal keyed access. `BUILTIN_PROPERTIES`
similarly lacks ID 5 (`PROPAGATED`), which produces one `None` property name in
`MSFT_TaskSettings3`.

### 8. Dynamic classes have no instance records here

2,720 unique class definitions carry `CLASS_QUALIFIER_DYNAMIC`, but **none**
has a stored instance record in this repository. `CLASS_QUALIFIER_DYNAMIC`
means the provider computes the class at runtime; the repository stores the
schema, not values. A report can say "the class is dynamic and its values were
not captured"; it cannot derive process/service/etc. runtime values from these
files. That requires a live/provider-side collection (or a memory image with
provider state), which is outside this evidence.

### 9. DYNPROPS metadata is detectable but not mapped

The sample has exactly one `DYNPROPS`-qualified class
(`SystemRestoreConfig`). Its instance carries four dynprop records. The bytes
and embedded strings are present (`SystemRestoreConfig`, `DYNPROPS`,
`PropertyContext`, registry paths, `RegPropProv`), and the record size/count is
stable and parseable. But `DynpropQualifier` is an empty class
(`classes.py:386-388`), and `Dynprops.dynprops` is always `None`
(`classes.py:375`). Field names and the mapping from dynprop records to
instance properties are not established by the current code.

What is safe to report offline: that dynprops exist, their count, their
declared record size, the total data size, and the raw strings. What is not
safe: presenting a dynprop record as a named property value.

## What can be fixed with bytes already on disk

No new collection needed:

- Correct dynprops boundary (count + self-sized records before `DataRegion`).
- Decode STRING arrays in qualifiers and instance values from their offset
  arrays.
- Treat `array_state & 0x20` as array; keep `0x40`/`0x60` distinct.
- Walk the derivation chain for key qualifiers before deduplicating instances.
- Map builtin qualifier IDs 4/5 and property ID 5, or surface them as
  `UNMAPPED_*` rather than `None`.
- Decode or explicitly mark `OBJECT`/`OBJECT[]`; do not abort an entire class
  enumeration for one unsupported property.
- Report `UNINITIALIZED` / `UNKNOWN_STATE` / `UNSUPPORTED_TYPE` instead of
  `""`, `False`, or `0`.

## What must come from additional evidence

- Runtime values of `CLASS_QUALIFIER_DYNAMIC` classes (process, service,
  provider output, etc.). Only the schema is stored.
- The exact meaning of the `0b11` property-state combination (3,054 properties
  with no schema default). Confirm with WMIO docs and a controlled capture; the
  current code only exposes it as "uninitialized", which consumers can confuse
  with `False`.
- Dynprop field semantics and the authoritative mapping of dynprop records to
  properties. The bytes exist, but names/roles need a documented layout or a
  paired live capture; guessing would exceed the evidence.
- `OBJECT` semantics if the target object's class/layout cannot be inferred
  from the embedded bytes and schema. Encoded objects may be recoverable, but
  the interpretation requires one more format fact.

## Reproduce

```sh
.venv/bin/python experiments/cim_recoverability_probe.py --data tests/_data
.venv/bin/python experiments/cim_recoverability_probe.py --data tests/_data --json
.venv/bin/python -m pytest -q -o addopts= experiments/test_cim_recoverability_probe.py
```

The probe does not access a live WMI service. It reads the fixture bytes,
re-parses the instance tail itself, and labels every result as `stored`,
`default`, `uninitialized`, `unsupported`, `unavailable`, or `conflict`.
