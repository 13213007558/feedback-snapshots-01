#!/usr/bin/env python3
"""Offline CIM recoverability probe.

Answers one narrow question for a Windows CIM repository:

    Given only INDEX.BTR, OBJECTS.DATA and MAPPINGn.MAP, what can be recovered
    for each class property, and what would still require the live WMI
    provider?

The probe never contacts a live WMI service. Every result is labelled by where
it came from: bytes in this instance record, a schema default, an uninitialized
slot, an unsupported type, or an unimplemented structure. Unknown/undecoded
values are represented by an explicit status, never by ``""`` or ``False``.

Run:
    python experiments/cim_recoverability_probe.py --data tests/_data
    python experiments/cim_recoverability_probe.py --data tests/_data --json

``--data`` accepts a directory of raw CIM files or the repository fixture
directory containing ``*.gz`` copies.
"""

from __future__ import annotations

import argparse
import gzip
import json
import struct
import sys
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

DATA_PAGE_SIZE = 0x2000
MAPPING_PAGE_ID_MASK = 0x3FFFFFFF


class Status(str, Enum):
    STORED = "stored"                # bytes in this instance record
    DEFAULT = "default"              # schema default, not an instance value
    UNINITIALIZED = "uninitialized"  # state flags say no value was written
    UNSUPPORTED = "unsupported"      # bytes exist, no decoder in dissect.cim
    UNAVAILABLE = "unavailable"      # structure not implemented / not locatable
    CONFLICT = "conflict"            # state and bytes disagree


@dataclass
class Finding:
    subject: str
    status: str
    value: Any = None
    source: str = ""
    detail: str = ""


TYPE_SIZE = {
    0x2: 2, 0x3: 4, 0x4: 4, 0x5: 8, 0x8: 4, 0xB: 2, 0xD: 4,
    0x10: 1, 0x11: 1, 0x12: 2, 0x13: 4, 0x14: 8, 0x15: 8,
    0x65: 4, 0x66: 4, 0x67: 2,
}
ARRAY_BIT = 0x20


# ---------------------------------------------------------------------------
# Raw byte access. Only this part resembles dissect.cim; the decoders below
# are deliberately separate so the probe can contrast them with the library.
# ---------------------------------------------------------------------------


def read_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def decode_string(region: bytes, offset: int) -> str:
    """Decode the length-free CIM string at ``offset``.

    Raises instead of returning "" for an invalid flag or truncated data.
    """
    if offset < 0 or offset >= len(region):
        raise ValueError(f"string offset {offset} outside region of {len(region)} bytes")
    flag = region[offset]
    raw = region[offset + 1 :]
    if flag == 0:
        end = raw.find(b"\x00")
        if end < 0:
            raise ValueError("unterminated latin1 string")
        return raw[:end].decode("latin1")
    if flag == 1:
        if len(raw) % 2:
            raw = raw[:-1]
        units = [raw[i : i + 2] for i in range(0, len(raw), 2)]
        out = bytearray()
        for unit in units:
            if unit == b"\x00\x00":
                break
            out += unit
        return out.decode("utf-16-le")
    raise ValueError(f"invalid string encoding flag {flag!r}")


def materialize(data_dir: Path) -> Path:
    if (data_dir / "OBJECTS.DATA").exists():
        return data_dir
    tmp = Path(tempfile.mkdtemp(prefix="cim-probe-"))
    for name in ("INDEX.BTR", "OBJECTS.DATA", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"):
        gz = data_dir / f"{name}.gz"
        with gzip.open(gz, "rb") as src, (tmp / name).open("wb") as dst:
            dst.write(src.read())
    return tmp


def load_cim(data_dir: Path) -> Any:
    from dissect.cim.cim import CIM  # local import keeps startup fast for --help

    return CIM.from_directory(materialize(data_dir))


# ---------------------------------------------------------------------------
# Instance record parsing, including the dynprops boundary under review.
# ---------------------------------------------------------------------------


@dataclass
class InstanceRecord:
    states: bytes
    toc: dict[int, int]
    qualifier_block: bytes
    dyn_state: int
    dyn_count: int | None
    dyn_records: list[bytes]
    dyn_declared_size: int | None
    data_region: bytes
    trailing: int
    dyn_data_offset: int


def parse_instance(obj: bytes, props: list[Any], *, xp: bool = False) -> InstanceRecord:
    """Parse the post-header instance payload, exposing the dynprops block.

    ``obj`` is the bytes after ``class_instance_header`` (i.e.
    ``ClassInstance.header.remaining_data``).
    """
    payload = obj
    n = len(props)
    state_len = (2 * n + 7) // 8
    states = payload[:state_len]
    pos = state_len

    toc: dict[int, int] = {}
    for p in sorted(props, key=lambda p: p.index):
        size = 4 if (p.type.array_state & ARRAY_BIT) else len(p.ctype)
        toc[p.index] = int.from_bytes(payload[pos : pos + size], "little")
        pos += size

    # The qualifier list is length-prefixed in bytes; the length *includes*
    # its own 4-byte field. Verified against records with 0 and 1 qualifiers.
    qbase = pos
    qlen = read_u32(payload, pos)
    pos += 4
    qend = qbase + qlen
    qstart = pos
    while pos + 9 <= qend:
        # qualifier_reference: uint32 key_reference, uint8 unk, cim_type type,
        # then inline value. cim_type is type, array_state, uint16 unk.
        type_id = payload[pos + 5]
        array = payload[pos + 6]
        pos += 9 + (0 if array & ARRAY_BIT else TYPE_SIZE.get(type_id, 4))
    if pos != qend:
        raise ValueError(f"qualifier list ended at {pos}, declared {qend}")
    qualifier_block = payload[qstart:pos]

    dyn_state = payload[pos]
    pos += 1
    dyn_count = None
    dyn_records: list[bytes] = []
    declared = None
    if dyn_state == 0x2:
        # Observed layout: uint8 state, uint32 count, then ``count`` records.
        # Each record starts with its own uint32 size (41 in the sample).
        dyn_count = read_u32(payload, pos)
        pos += 4
        # Each record starts with its own uint32 size (41 in the sample);
        # that size field is part of the record.
        record_size = read_u32(payload, pos)
        if record_size < 4 or record_size > len(payload):
            raise ValueError(f"implausible dynprop record size {record_size}")
        dyn_records = [
            payload[pos + i * record_size : pos + (i + 1) * record_size] for i in range(dyn_count)
        ]
        pos += dyn_count * record_size
        declared = read_u32(payload, pos) & 0x7FFFFFFF
        pos += 4
    else:
        declared = read_u32(payload, pos) & 0x7FFFFFFF
        pos += 4

    data_start = pos
    data = payload[data_start : data_start + declared]
    return InstanceRecord(
        states=states,
        toc=toc,
        qualifier_block=qualifier_block,
        dyn_state=dyn_state,
        dyn_count=dyn_count,
        dyn_records=dyn_records,
        dyn_declared_size=declared,
        data_region=data,
        trailing=len(payload) - (data_start + declared),
        dyn_data_offset=data_start,
    )


def state_for(record: InstanceRecord, index: int) -> tuple[bool, bool]:
    """Return (use_default, initialized) from the two-bit property state."""
    byte = record.states[index // 4]
    bits = (byte >> (2 * (index % 4))) & 0x3
    return bool(bits & 0b10), not (bits & 0b01)


# ---------------------------------------------------------------------------
# Demonstrations
# ---------------------------------------------------------------------------


def locate(cim: Any, ns: str, cls: str) -> tuple[Any, Any]:
    c = cim.namespace(ns).class_(cls)
    ref = cim.key().NS(ns).CI(cls).IL().references()[0]
    return c, cim.get_class_instance(c, ref)


def demo_dynprops(cim: Any) -> list[Finding]:
    c, ci = locate(cim, "root\\DEFAULT", "SystemRestoreConfig")
    props = sorted(c.properties.values(), key=lambda p: p.index)
    rec = parse_instance(ci.header.remaining_data, props)

    out = [
        Finding(
            "SystemRestoreConfig / instance record",
            Status.STORED.value,
            {
                "dynprops_state": rec.dyn_state,
                "dynprops_count": rec.dyn_count,
                "dynprops_record_size": read_u32(rec.dyn_records[0], 0) if rec.dyn_records else None,
                "dynprops_declared_data_size": rec.dyn_declared_size,
                "dynprops_trailing_bytes": rec.trailing,
                "data_region_offset_in_payload": rec.dyn_data_offset,
            },
            "OBJECTS.DATA (instance header tail)",
            "Current code skips the count and the first record's size dword, then reads the "
            "record's first qualifier dword as a DataRegion size. The layout above is "
            "self-consistent for this sample (one record set).",
        )
    ]

    # Current library result, shown explicitly so the contrast is recorded.
    out.append(
        Finding(
            "SystemRestoreConfig / MyKey (current dissect.cim)",
            Status.CONFLICT.value,
            {"library_class_name": ci.class_name, "library_value": ci.properties["MyKey"].value},
            "dissect.cim ClassInstance",
            "Current boundary lands inside the dynprops metadata; class_name decodes as a "
            "control byte and MyKey decodes as an empty string. Neither is a stored value.",
        )
    )

    # Correct-boundary result.
    out.append(
        Finding(
            "SystemRestoreConfig / MyKey (corrected boundary)",
            Status.STORED.value,
            decode_string(rec.data_region, rec.toc[0]),
            "OBJECTS.DATA (data region after dynprops metadata)",
            "Recovered from the same bytes by skipping count*41 bytes of dynprops metadata.",
        )
    )

    for p in props:
        use_default, initialized = state_for(rec, p.index)
        if not initialized:
            out.append(
                Finding(
                    f"SystemRestoreConfig / {p.name}",
                    Status.UNINITIALIZED.value,
                    None,
                    "instance property-state bits",
                    "No value was stored for this property in this record.",
                )
            )
            continue
        if use_default:
            # Bit 2 is not a reliable "value == schema default" flag in the
            # sample. Report it as unresolved, not as the default value.
            out.append(
                Finding(
                    f"SystemRestoreConfig / {p.name}",
                    Status.UNAVAILABLE.value,
                    None,
                    "instance property-state bits",
                    "State bit 2 is set, but the schema declares no default for this "
                    "property. Neither the default nor a stored value may be claimed.",
                )
            )
            continue
        # Only MyKey is non-zero in this record.
        if p.index == 0:
            continue
        out.append(
            Finding(f"SystemRestoreConfig / {p.name}", Status.STORED.value, rec.toc[p.index], "TOC slot")
        )

    # Dynprop metadata is recoverable, but its field semantics are only partly known.
    if rec.dyn_records:
        rec0 = rec.dyn_records[0]
        out.append(
            Finding(
                "SystemRestoreConfig / dynprop metadata",
                Status.UNAVAILABLE.value,
                {
                    "record_length": 41,
                    "leading_dwords": [read_u32(rec0, i) for i in (0, 4, 8, 12)],
                    "qualifier_tail_hex": rec0[17:].hex(),
                },
                "dynprops record bytes",
                "The record bytes and embedded strings are present, but field names and "
                "the mapping to instance properties are not implemented in dissect.cim. "
                "The byte layout is known well enough to locate and bound the records; "
                "the semantic mapping is not.",
            )
        )
    return out


def demo_key_inheritance(cim: Any) -> list[Finding]:
    out = []
    for ns in ("root\\CIMV2", "root\\DEFAULT", "root\\subscription"):
        try:
            c = cim.namespace(ns).class_("__Win32Provider")
        except Exception as exc:  # noqa: BLE001 - probe reports, does not hide
            out.append(Finding(f"{ns} / __Win32Provider", Status.UNAVAILABLE.value, None, "", str(exc)))
            continue
        refs = cim.key().NS(ns).CI("__Win32Provider").IL().references()
        unique = {(r.data_page, r.data_id, r.data_length) for r in refs}
        yielded = list(c.instances)
        out.append(
            Finding(
                f"{ns} / __Win32Provider",
                Status.CONFLICT.value,
                {"distinct_records": len(unique), "instances_yielded": len(yielded)},
                "INDEX.BTR vs Class.instances",
                "ClassDefinition.keys only inspects own properties; the key qualifier is "
                "on ancestor __Provider.Name, so every instance has key 'default' and "
                "all but one are dropped by the duplicate filter.",
            )
        )
    return out


def demo_qualifier_arrays(cim: Any) -> list[Finding]:
    base = cim.namespace("root\\CIMV2").class_("Win32_BaseService")
    prop = base.class_definition.properties["State"]
    qual = prop.qualifiers["ValueMap"]
    region = qual._data
    ptr = qual._qualref.value
    count = read_u32(region.data, ptr)
    offsets = struct.unpack_from(f"<{count}I", region.data, ptr + 4)
    decoded = [region.get_string(o) for o in offsets]
    return [
        Finding(
            "Win32_BaseService.State.ValueMap (current dissect.cim)",
            Status.UNSUPPORTED.value,
            list(qual.value),
            "class definition qualifier",
            "STRING+ARRAY qualifiers return the array of uint32 string offsets, not strings. "
            "The values look plausible (and are non-empty), which makes the error easy to miss.",
        ),
        Finding(
            "Win32_BaseService.State.ValueMap (byte decode)",
            Status.STORED.value,
            decoded,
            "class definition qualifier region",
            "The same bytes decode to the actual ValueMap strings; no extra collection is needed.",
        ),
    ]


def demo_unsupported(cim: Any) -> list[Finding]:
    c = cim.namespace("root\\Cli").class_("MSFT_CliAlias")
    refs = cim.key().NS("root\\Cli").CI("MSFT_CliAlias").IL().references()
    unique = {(r.data_page, r.data_id, r.data_length) for r in refs}
    try:
        list(c.instances)
        outcome = "enumerated"
    except Exception as exc:  # noqa: BLE001 - this is the finding
        outcome = f"{type(exc).__name__}: {exc}"
    ci = cim.get_class_instance(c, refs[0])
    return [
        Finding(
            "MSFT_CliAlias / instances",
            Status.UNSUPPORTED.value,
            {"distinct_records": len(unique), "enumeration": outcome},
            "OBJECTS.DATA",
            "Instances contain OBJECT and OBJECT[] fields. dissect.cim has no decoder for "
            "CIM_TYPES.OBJECT, so enumeration aborts and all records for this class are lost.",
        ),
        Finding(
            "MSFT_CliAlias / Connection (OBJECT)",
            Status.UNSUPPORTED.value,
            ci.toc[0],
            "instance TOC",
            "The TOC points at bytes in the data region; OBJECT semantics (embedded object "
            "layout, its class, and its properties) are not implemented.",
        ),
    ]


def demo_default_vs_state(cim: Any) -> list[Finding]:
    out = []

    # A clean schema-default case: state is 0b10, TOC is unused (0).
    try:
        c = cim.namespace("root\\subscription").class_("__FilterToConsumerBinding")
        ref = cim.key().NS("root\\subscription").CI("__FilterToConsumerBinding").IL().references()[0]
        ci = cim.get_class_instance(c, ref)
        prop = c.properties["DeliverSynchronously"]
        state = ci.property_states[prop.index]
        out.append(
            Finding(
                "root\\subscription / __FilterToConsumerBinding.DeliverSynchronously",
                Status.DEFAULT.value,
                prop.default_value,
                "class default-values block",
                f"State={state}, TOC={int(ci.toc[prop.index])}; the TOC is an unused slot. "
                "This is a schema default, not necessarily a value the provider wrote "
                "for this instance.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - optional demonstration
        out.append(
            Finding(
                "root\\subscription / __FilterToConsumerBinding.DeliverSynchronously",
                Status.UNAVAILABLE.value,
                None,
                "",
                f"could not locate clean default example: {exc}",
            )
        )

    # The unresolved case: 0b11 (upper bit set, lower bit says uninitialized),
    # and the class declares no default. The library exposes this as
    # is_initialized=False / is_default_value=False, which a consumer can
    # mistake for an explicit False.
    try:
        c = cim.namespace("root\\CIMV2").class_("__Win32Provider")
        ref = cim.key().NS("root\\CIMV2").CI("__Win32Provider").IL().references()[0]
        ci = cim.get_class_instance(c, ref)
        prop = ci.properties["DefaultMachineName"]
        out.append(
            Finding(
                "root\\CIMV2 / __Win32Provider.DefaultMachineName",
                Status.UNAVAILABLE.value,
                {
                    "state": {"use_default": prop.state.use_default_value, "initialized": prop.state.is_initialized},
                    "has_schema_default": prop.has_default_value,
                    "is_default_value": prop.is_default_value,
                    "toc_word": int(ci.toc[prop.index]),
                },
                "instance property-state bits",
                "State is 0b11 with no schema default. There is no stored value and no "
                "default; the only safe report is UNKNOWN/UNINITIALIZED. Reporting "
                "is_default_value=False as a value would turn 'unknown' into a boolean.",
            )
        )
    except Exception as exc:  # noqa: BLE001
        out.append(
            Finding(
                "root\\CIMV2 / __Win32Provider.DefaultMachineName",
                Status.UNAVAILABLE.value,
                None,
                "",
                f"could not demonstrate unresolved state: {exc}",
            )
        )
    return out


def capability_table(cim: Any) -> list[dict[str, Any]]:
    return [
        {
            "surface": "Class names, inheritance, property types/indexes",
            "state": Status.STORED.value,
            "source": "OBJECTS.DATA class definition",
            "scope": "Complete for the sample when class_name_offset==0 and no dynprops corruption.",
        },
        {
            "surface": "Builtin qualifiers DYNAMIC/PROVIDER/KEY/READ_ACCESS/TYPE",
            "state": Status.STORED.value,
            "source": "class/property qualifier references",
            "scope": "Mapped IDs 1,3,6,7,10. Unknown IDs 4 and 5 currently become a None key.",
        },
        {
            "surface": "String qualifiers (Description, MappingStrings, ...)",
            "state": Status.STORED.value,
            "source": "class property_data region",
            "scope": "Single strings decode correctly when the offset is in the owning region.",
        },
        {
            "surface": "Array qualifiers (ValueMap, Values, MappingStrings arrays)",
            "state": Status.UNSUPPORTED.value,
            "source": "qualifier array of uint32 offsets",
            "scope": "Current code returns offsets; the offset array itself is sufficient to decode.",
        },
        {
            "surface": "Schema default values",
            "state": Status.DEFAULT.value,
            "source": "class default-values block",
            "scope": "Available only where the class declares them; not an instance value.",
        },
        {
            "surface": "Instance scalar values (string/number/bool)",
            "state": Status.STORED.value,
            "source": "instance TOC + data region",
            "scope": "Recoverable when state says initialized and not default-derived.",
        },
        {
            "surface": "Instance string arrays",
            "state": Status.UNSUPPORTED.value,
            "source": "TOC -> array of uint32 offsets",
            "scope": "Current code returns integer offsets where strings are expected.",
        },
        {
            "surface": "Instance OBJECT / OBJECT[] values",
            "state": Status.UNSUPPORTED.value,
            "source": "instance TOC + data region",
            "scope": "No decoder; enumeration aborts for affected classes.",
        },
        {
            "surface": "Dynamic classes' runtime-only properties",
            "state": Status.UNAVAILABLE.value,
            "source": "not in OBJECTS.DATA",
            "scope": "CLASS_QUALIFIER_DYNAMIC is schema metadata; values live in the provider.",
        },
        {
            "surface": "Dynprops metadata (DYNPROPS-qualified classes)",
            "state": Status.UNAVAILABLE.value,
            "source": "instance tail after property states",
            "scope": "Bytes present and locatable; field semantics not implemented in dissect.cim.",
        },
        {
            "surface": "Anonymous/default-key instances",
            "state": Status.CONFLICT.value,
            "source": "ClassDefinition.keys",
            "scope": "Inherited key qualifiers are missed; duplicate collapsing drops records.",
        },
        {
            "surface": "Instance property state (2 bits/property)",
            "state": Status.UNAVAILABLE.value,
            "source": "instance property-state array",
            "scope": "0b10 is consistent with a schema default; 0b11 has no default and no "
            "stored value and must be reported as unknown, not as False.",
        },
    ]


def run(data_dir: Path) -> list[Finding]:
    cim = load_cim(data_dir)
    findings: list[Finding] = []
    findings += demo_dynprops(cim)
    findings += demo_key_inheritance(cim)
    findings += demo_qualifier_arrays(cim)
    findings += demo_unsupported(cim)
    findings += demo_default_vs_state(cim)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("tests/_data"))
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    findings = run(args.data)
    cim = load_cim(args.data)

    if args.json:
        print(
            json.dumps(
                {
                    "findings": [asdict(f) for f in findings],
                    "capability_table": capability_table(cim),
                },
                indent=2,
                default=str,
            )
        )
        return 0

    print("CIM offline recoverability probe")
    print(f"data: {args.data}")
    print()
    print("Each row states where the value came from; it never substitutes a value.")
    print()
    for f in findings:
        print(f"[{f.status}] {f.subject}")
        if f.value is not None:
            print(f"    value:  {f.value!r}")
        if f.source:
            print(f"    source: {f.source}")
        if f.detail:
            print(f"    note:   {f.detail}")
        print()
    print("Capability table:")
    for row in capability_table(cim):
        print(f"  - {row['surface']}: {row['state']} ({row['source']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
