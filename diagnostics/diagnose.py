"""Offline manifest-conflict diagnosis for dissect.etl.

The tool never treats "parsing did not raise" as evidence that the right
template was chosen.  For every event record it reports four independent
facts:

1. manifest provenance: which module answered the GUID lookup (origin,
   location, content hash, provider name/symbol),
2. the event descriptor from the record header: id, version, channel, level,
   opcode, task, keywords -- not just the lookup key,
3. the layout of the selected template: static size, field names, types,
   offsets and pointer width, and
4. byte accounting: how many payload bytes the template consumed, how many it
   left, and which fields consumed them.

It also evaluates several candidate manifests for the same GUID in isolation,
so candidates never contaminate each other's cache or pointer state.

Usage (from the repository root):

    .venv/bin/python diagnostics/diagnose.py inspect diagnostics/fixtures/alpc_conflict.etl
    .venv/bin/python diagnostics/diagnose.py compare diagnostics/fixtures/alpc_conflict.etl \
        --candidate repo \
        --candidate b=diagnostics/manifests/exporter_b_24byte.xml \
        --candidate c=diagnostics/manifests/exporter_c_24byte.xml
    .venv/bin/python diagnostics/diagnose.py cache-order diagnostics/fixtures/alpc_conflict.etl \
        --candidate repo --candidate b=diagnostics/manifests/exporter_b_24byte.xml
    .venv/bin/python diagnostics/diagnose.py probe 30336ed4-e327-447c-9de0-51b652c86108 --candidate repo
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import types
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dissect.etl import manifest  # noqa: E402
from dissect.etl.etl import ETL  # noqa: E402
from dissect.etl.exceptions import ManifestNotFoundError  # noqa: E402

# Standard Windows event metadata encodings.  These are used only to check that
# a candidate manifest entry is *semantically* consistent with the descriptor;
# they are not used to select a provider source.
LEVEL_VALUES = {
    "win:LogAlways": 0,
    "win:Critical": 1,
    "win:Error": 2,
    "win:Warning": 3,
    "win:Informational": 4,
    "win:Verbose": 5,
}
OPCODE_VALUES = {
    "win:Info": 0,
    "win:Start": 1,
    "win:Stop": 2,
    "win:DCStart": 3,
    "win:DCEnd": 4,
    "win:Extension": 5,
    "win:Reply": 6,
    "win:Resume": 7,
    "win:Suspend": 8,
    "win:Send": 9,
    "win:Receive": 240,
}


# ---------------------------------------------------------------------------
# Candidates and provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """A manifest source that can be bound to a provider GUID."""

    name: str
    origin: str  # "file" | "resource"
    path: str | None = None

    def load(self, guid: UUID) -> tuple[types.ModuleType, ManifestIdentity]:
        module, identity = self._load(guid)
        declared = getattr(module, "PROVIDER_GUID", None)
        if declared is not None and str(declared).lower() != str(guid).lower():
            raise ValueError(f"manifest declares {declared}, expected {guid}")
        return module, identity

    def _load(self, guid: UUID) -> tuple[types.ModuleType, ManifestIdentity]:
        if self.origin == "resource":
            location = f"dissect.etl/manifests/xml/{{{guid}}}.xml"
            text = manifest.get_resource_string(f"manifests/xml/{{{guid}}}.xml")
        elif self.origin == "file":
            assert self.path is not None
            path = Path(self.path)
            location = str(path.resolve())
            text = path.read_text()
        else:
            raise ValueError(f"unsupported candidate origin: {self.origin}")
        module = manifest.compile_xml(guid, text)
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        return module, ManifestIdentity(self.name, self.origin, location, digest)

    @classmethod
    def from_spec(cls, spec: str) -> Candidate:
        """Accept ``name=path``, ``name=repo`` or a bare path."""
        if spec in ("repo", "bundled", "resource"):
            return cls("repo", "resource")
        if "=" not in spec:
            return cls(Path(spec).stem, "file", spec)
        name, value = spec.split("=", 1)
        if value in ("repo", "bundled", "resource"):
            return cls(name, "resource")
        return cls(name, "file", value)


@dataclass(frozen=True)
class ManifestIdentity:
    """Where a candidate came from and what bytes it contained."""

    label: str
    origin: str
    location: str
    sha256: str

    @property
    def digest(self) -> str:
        return self.sha256[:16]


@dataclass(frozen=True)
class LoadedManifest:
    identity: ManifestIdentity
    module: types.ModuleType

    @property
    def provider_name(self) -> str | None:
        return getattr(self.module, "PROVIDER_NAME", None)

    @property
    def provider_symbol(self) -> str | None:
        return getattr(self.module, "PROVIDER_SYMBOL", None)

    @property
    def events(self) -> dict[tuple[int, int], Any]:
        return getattr(self.module, "EVENTS", {})


def describe_module(module: types.ModuleType) -> dict[str, Any]:
    return {
        "module": getattr(module, "__name__", None),
        "provider_name": getattr(module, "PROVIDER_NAME", None),
        "provider_guid": str(getattr(module, "PROVIDER_GUID", None)),
        "provider_symbol": getattr(module, "PROVIDER_SYMBOL", None),
        "events": len(getattr(module, "EVENTS", {})),
    }


def lookup_identity(guid: UUID) -> dict[str, Any]:
    """Resolve a GUID exactly the way parse_payload does, then describe the winner."""
    cache_hit = guid in manifest.CACHE
    try:
        module = manifest.lookup(guid)
    except ManifestNotFoundError:
        return {"found": False, "guid": str(guid), "cache_hit": cache_hit}
    return {"found": True, "guid": str(guid), "cache_hit": cache_hit, **describe_module(module)}


def bundled_candidate(guid: UUID) -> Candidate | None:
    try:
        manifest.get_resource_string(f"manifests/xml/{{{guid}}}.xml")
    except OSError:
        return None
    return Candidate("repo", "resource")


def rank_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Stable order independent of CLI argument order."""
    return sorted(candidates, key=lambda c: (c.origin != "resource", c.name, c.path or ""))


# ---------------------------------------------------------------------------
# Layout and byte accounting
# ---------------------------------------------------------------------------


def _type_name(field_type: Any) -> str:
    return getattr(field_type, "__name__", repr(field_type))


def describe_layout(module: types.ModuleType, entry: Any) -> dict[str, Any]:
    template = entry.template
    fields = []
    for fname, fobj in getattr(template, "fields", {}).items():
        ftype = fobj.type
        fields.append(
            {
                "name": fname,
                "type": _type_name(ftype),
                "offset": fobj.offset,
                "static_size": getattr(ftype, "size", None),
                "dynamic": getattr(ftype, "dynamic", None),
            }
        )
    pointer = getattr(getattr(module, "c_parser", None), "EtwPointer", None)
    return {
        "structure": getattr(template, "__name__", repr(template)),
        "static_size": getattr(template, "size", None),
        "dynamic": getattr(template, "dynamic", None),
        "fields": fields,
        "pointer_width": getattr(pointer, "size", None) if pointer is not None else None,
    }


def apply_pointer_width(module: types.ModuleType, is_64_bit: bool) -> dict[str, Any]:
    """Mirror parse_payload's ABI setup for one record.

    dissect stores EtwPointer/UserSID_blob on the *cached module*, so this is
    process-global mutable state that depends on the last record parsed.
    """
    parser = getattr(module, "c_parser", None)
    pointer = getattr(parser, "EtwPointer", None)
    sid = getattr(parser, "UserSID_blob", None)
    before = {
        "EtwPointer": getattr(pointer, "size", None),
        "UserSID_blob": getattr(sid, "size", None),
    }
    error = None
    try:
        if pointer is not None:
            pointer.as_64bit() if is_64_bit else pointer.as_32bit()
        if sid is not None:
            sid.as_64bit() if is_64_bit else sid.as_32bit()
    except Exception as exc:  # noqa: BLE001 - the 32-bit path is broken by design
        error = f"{type(exc).__name__}: {exc}"
    after = {
        "EtwPointer": getattr(pointer, "size", None),
        "UserSID_blob": getattr(sid, "size", None),
    }
    return {"requested_is_64bit": is_64_bit, "before": before, "after": after, "error": error}


def parse_counted(template: Any, payload: bytes) -> dict[str, Any]:
    """Parse ``payload`` with a counted stream; report consumed/unconsumed bytes."""
    stream = io.BytesIO(payload)
    try:
        value = template(stream)
    except Exception as exc:  # noqa: BLE001 - every failure class is diagnostic data
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "consumed": stream.tell(),
            "unconsumed": len(payload) - stream.tell(),
            "values": None,
        }
    consumed = stream.tell()
    return {
        "ok": True,
        "error": None,
        "consumed": consumed,
        "unconsumed": len(payload) - consumed,
        "dynamic_sizes": dict(getattr(value, "__dynamic_sizes__", {})),
        # StructureValuesProxy is a Mapping, not a dict; convert explicitly so
        # callers can rely on plain Mapping semantics.
        "values": _jsonable(dict(getattr(value, "__values__", {}))),
    }


def _jsonable(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return repr(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"hex": raw.hex(), "len": len(raw)}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, depth + 1) for v in value]
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return repr(value)


# ---------------------------------------------------------------------------
# Event descriptor and semantic consistency
# ---------------------------------------------------------------------------


def describe_header(header: Any) -> dict[str, Any]:
    descriptor: dict[str, Any] = {}
    try:
        event_descriptor = header.descriptor
    except Exception:  # noqa: BLE001 - some header types have no descriptor
        event_descriptor = None
    if event_descriptor is not None:
        descriptor = {
            "id": event_descriptor.id,
            "version": event_descriptor.version,
            "channel": event_descriptor.channel,
            "level": event_descriptor.level,
            "opcode": event_descriptor.opcode,
            "task": event_descriptor.task,
            "keywords": event_descriptor.keywords,
        }
    return {
        "header_type": type(header).__name__,
        "marker": f"0x{header.marker:08x}",
        "size": header.size,
        "minimal_size": header.minimal_size,
        "is_64bit": header.is_64bit,
        "provider_id": str(header.provider_id) if header.provider_id else None,
        "descriptor": descriptor,
        "lookup_key": [getattr(header, "opcode", None), getattr(header, "version", None)],
        "payload_size": len(header.payload),
    }


def descriptor_checks(entry: Any, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Check a manifest entry against the header descriptor, field by field."""
    checks: dict[str, Any] = {
        "id_matches_value": False,
        "version_matches": False,
        "opcode_semantics": "not numeric",
        "level_semantics": "not numeric",
    }
    if not descriptor:
        return checks
    checks["id_matches_value"] = entry.value == descriptor.get("id")
    checks["version_matches"] = entry.version == descriptor.get("version")

    entry_opcode = entry.opcode
    if isinstance(entry_opcode, int):
        checks["opcode_semantics"] = "numeric=header" if entry_opcode == descriptor.get("opcode") else "numeric!=header"
    else:
        mapped = OPCODE_VALUES.get(entry_opcode)
        if mapped is not None:
            checks["opcode_semantics"] = "symbol=header" if mapped == descriptor.get("opcode") else "symbol!=header"

    entry_level = entry.level
    if isinstance(entry_level, int):
        checks["level_semantics"] = "numeric=header" if entry_level == descriptor.get("level") else "numeric!=header"
    else:
        mapped = LEVEL_VALUES.get(entry_level)
        if mapped is not None:
            checks["level_semantics"] = "symbol=header" if mapped == descriptor.get("level") else "symbol!=header"

    return checks


def verdict_for(entry: Any, layout: dict[str, Any], parse: dict[str, Any]) -> str:
    """Classify the byte-level fit of one candidate for one record."""
    if entry is None:
        return "no-entry"
    if not parse["ok"]:
        return "truncated"
    if parse["unconsumed"] == 0:
        return "exact"
    return "padded"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def iter_records(etl: ETL) -> list[tuple[int, Any]]:
    records = []
    index = 0
    for buffer in etl.buffers():
        for record in buffer:
            records.append((index, record))
            index += 1
    return records


def candidate_report(guid: UUID, candidate: Candidate, records: list[tuple[int, Any]]) -> dict[str, Any]:
    """Evaluate one candidate against every record, in isolation."""
    try:
        module, identity = candidate.load(guid)
    except Exception as exc:  # noqa: BLE001 - compile failures are part of the diagnosis
        return {
            "candidate": asdict(candidate),
            "load_error": f"{type(exc).__name__}: {exc}",
            "records": [],
        }

    report: dict[str, Any] = {
        "candidate": asdict(candidate),
        "identity": asdict(identity),
        "module": describe_module(module),
        "records": [],
    }
    events = getattr(module, "EVENTS", {})
    for index, record in records:
        if index == 0:
            continue  # logfile / SYSTEM record, not a manifest event
        info = describe_header(record.header)
        descriptor = info.get("descriptor") or {}
        lookup_key = tuple(info["lookup_key"])
        entry = events.get(lookup_key)
        id_key = (descriptor.get("id"), descriptor.get("version"))
        id_entry = events.get(id_key)

        row: dict[str, Any] = {
            "record": index,
            "header": info,
            "lookup_entry": _entry_summary(entry),
            "id_entry": _entry_summary(id_entry),
            "lookup_hit": entry is not None,
            "id_hit": id_entry is not None,
            "id_agrees_with_lookup": bool(
                entry is not None and id_entry is not None and entry.symbol == id_entry.symbol
            ),
        }
        if entry is not None:
            abi = apply_pointer_width(module, bool(info["is_64bit"]))
            row["descriptor_checks"] = descriptor_checks(entry, descriptor)
            row["abi"] = abi
            row["layout"] = describe_layout(module, entry)
            row["parse"] = parse_counted(entry.template, bytes(record.header.payload))
            row["verdict"] = verdict_for(entry, row["layout"], row["parse"])
            if abi["error"]:
                row["parse"] = {
                    "ok": False,
                    "error": f"ABI setup failed: {abi['error']}",
                    "consumed": 0,
                    "unconsumed": len(record.header.payload),
                    "values": None,
                }
                row["verdict"] = "abi-error"
        else:
            row["descriptor_checks"] = {}
            row["layout"] = None
            row["parse"] = None
            row["abi"] = None
            row["verdict"] = "no-entry"
        if id_entry is not None:
            apply_pointer_width(module, bool(info["is_64bit"]))
            id_parse = parse_counted(id_entry.template, bytes(record.header.payload))
            row["id_parse"] = {
                "symbol": id_entry.symbol,
                "layout": describe_layout(module, id_entry),
                "parse": id_parse,
                "verdict": verdict_for(id_entry, {}, id_parse),
                "descriptor_checks": descriptor_checks(id_entry, descriptor),
            }
        else:
            row["id_parse"] = None
        report["records"].append(row)
    return report


def _entry_summary(entry: Any) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "symbol": entry.symbol,
        "value": entry.value,
        "version": entry.version,
        "opcode": entry.opcode,
        "level": entry.level,
        "task": entry.task,
        "keywords": entry.keywords,
        "template": getattr(entry.template, "__name__", None),
    }


def record_table(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for report in reports:
        candidate_name = report["candidate"]["name"]
        if report.get("load_error"):
            rows.append(
                {"record": "-", "candidate": candidate_name, "symbol": "LOAD ERROR", "result": report["load_error"]}
            )
            continue
        for row in report["records"]:
            parse = row.get("parse") or {}
            entry = row.get("lookup_entry") or {}
            id_entry = row.get("id_entry") or {}
            rows.append(
                {
                    "record": row["record"],
                    "candidate": candidate_name,
                    "lookup": entry.get("symbol") or "-",
                    "id": id_entry.get("symbol") or "-",
                    "layout": _layout_signature(row.get("layout")),
                    "payload": row["header"]["payload_size"],
                    "used": parse.get("consumed", "-"),
                    "left": parse.get("unconsumed", "-"),
                    "verdict": row["verdict"],
                    "result": "ok" if parse.get("ok") else (parse.get("error") or "-"),
                }
            )
    return rows


def _layout_signature(layout: dict[str, Any] | None) -> str:
    if not layout:
        return "-"
    parts = []
    for item in layout["fields"]:
        size = item["static_size"] if item["static_size"] is not None else "dyn"
        parts.append(f"{item['name']}:{item['type']}@{item['offset']}+{size}")
    return f"{layout['static_size'] if layout['static_size'] is not None else 'dyn'}[{','.join(parts)}]"


def _print_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    widths = {key: max(len(title), *(len(str(row.get(key, ""))) for row in rows)) for key, title in columns}
    print("  ".join(title.ljust(widths[key]) for key, title in columns))
    print("  ".join("-" * widths[key] for key, _ in columns))
    for row in rows:
        print("  ".join(str(row.get(key, "")).ljust(widths[key]) for key, _ in columns))


def ambiguity_summary(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classify each record on two independent axes: lookup key and descriptor id.

    A candidate is only a *precise* answer when the entry reached through the
    descriptor id (event value) matches the descriptor metadata and consumes the
    payload exactly.  Byte-fit alone is never treated as provenance.
    """
    by_record: dict[int, list[tuple[str, dict[str, Any]]]] = {}
    for report in reports:
        if report.get("load_error"):
            continue
        name = report["candidate"]["name"]
        for row in report["records"]:
            by_record.setdefault(row["record"], []).append((name, row))

    summary = []
    for record, entries in sorted(by_record.items()):
        exact_lookup = [name for name, row in entries if row["verdict"] == "exact"]
        exact_id = [
            name
            for name, row in entries
            if row.get("id_parse") and row["id_parse"]["parse"]["ok"] and row["id_parse"]["parse"]["unconsumed"] == 0
        ]
        id_available = [name for name, row in entries if row.get("id_entry") is not None]
        lookup_only = [name for name, row in entries if row["lookup_entry"] is not None and row.get("id_entry") is None]
        key_space_conflict = [
            name
            for name, row in entries
            if row["lookup_entry"] is not None
            and row.get("id_entry") is not None
            and row["lookup_entry"]["symbol"] != row["id_entry"]["symbol"]
        ]
        lookup_miss_id_hit = [
            name for name, row in entries if row["lookup_entry"] is None and row.get("id_entry") is not None
        ]
        header = entries[0][1] if entries else None
        lookup_key = header["header"]["lookup_key"] if header else None
        descriptor_id = (header["header"]["descriptor"] or {}).get("id") if header else None
        key_fingerprint = (descriptor_id, (header["header"]["descriptor"] or {}).get("version") if header else None)

        if key_space_conflict:
            resolution = "key-space-conflict"
            detail = (
                f"descriptor id {descriptor_id} and (opcode, version) {tuple(lookup_key)} select different "
                f"entries in {', '.join(key_space_conflict)}"
            )
            if len(exact_id) == 1:
                conclusion = f"precise, but only through descriptor id {descriptor_id}: {exact_id[0]} ({detail})"
            elif len(exact_id) > 1:
                conclusion = f"ambiguous through descriptor id {descriptor_id} ({', '.join(exact_id)}); {detail}"
            else:
                conclusion = (
                    f"descriptor id {descriptor_id} resolves but nothing consumes the payload exactly; {detail}"
                )
        elif lookup_miss_id_hit:
            resolution = "lookup-miss-id-hit"
            if len(exact_id) == 1:
                conclusion = (
                    f"lookup (opcode, version) {tuple(lookup_key)} misses, but descriptor id "
                    f"{key_fingerprint} resolves uniquely to {exact_id[0]}"
                )
            elif len(exact_id) > 1:
                conclusion = (
                    f"lookup (opcode, version) {tuple(lookup_key)} misses; descriptor id {key_fingerprint} "
                    f"resolves in {', '.join(exact_id)} without a unique layout"
                )
            else:
                conclusion = (
                    f"lookup (opcode, version) {tuple(lookup_key)} misses; descriptor id {key_fingerprint} "
                    f"resolves in {', '.join(id_available)} but none consumes the payload exactly"
                )
        elif len(exact_id) == 1:
            resolution = "precise"
            conclusion = f"precisely disambiguated by descriptor id {descriptor_id}: {exact_id[0]}"
        elif len(exact_id) > 1:
            resolution = "caller-must-choose"
            conclusion = (
                f"ambiguous: {len(exact_id)} candidate manifests fit descriptor id {descriptor_id} "
                f"exactly ({', '.join(exact_id)})"
            )
        elif id_available:
            resolution = "caller-or-source-required"
            conclusion = "descriptor id resolves, but no candidate consumes the payload exactly"
        elif lookup_only:
            resolution = "caller-must-choose"
            conclusion = "only entries reached through (opcode, version) exist; descriptor id is not present"
        elif exact_lookup:
            resolution = "caller-must-choose"
            conclusion = f"lookup key finds {', '.join(exact_lookup)} but no descriptor id entry exists"
        else:
            resolution = "no-source"
            conclusion = "no candidate manifest covers this descriptor"

        summary.append(
            {
                "record": record,
                "descriptor_id": descriptor_id,
                "lookup_key": lookup_key,
                "exact_by_lookup": exact_lookup,
                "exact_by_id": exact_id,
                "id_available": id_available,
                "lookup_only": lookup_only,
                "key_space_conflict": key_space_conflict,
                "resolution": resolution,
                "conclusion": conclusion,
            }
        )
    return summary


def cmd_inspect(args: argparse.Namespace) -> int:
    path = Path(args.etl)
    etl = ETL(io.BytesIO(path.read_bytes()))
    records = iter_records(etl)
    print(f"file: {path}")
    print(f"pointer_size={etl.pointer_size} is_64bit={etl.is_64bit} buffers={etl.logfile_header.buffers_written}")
    print(f"cache_before: {list(map(str, manifest.CACHE))}")
    for index, record in records:
        header = record.header
        print(f"\nrecord {index}: {json.dumps(describe_header(header), default=str)}")
        if index == 0:
            print(f"  logfile logger={etl.logfile_header.logger_name!r} file={etl.logfile_header.log_filename!r}")
            continue
        print(f"  manifest: {json.dumps(lookup_identity(header.provider_id), default=str)}")
        try:
            event = record.event
        except Exception as exc:  # noqa: BLE001 - failures are the subject
            print(f"  record.event raised {type(exc).__name__}: {exc}")
            continue
        print(f"  provider_name={event.provider_name()!r} symbol={event.symbol()!r}")
        if event._event is not None and event._manifest is not None:
            print(f"  layout: {json.dumps(describe_layout(event._manifest, event._event), default=str)}")
            print(f"  parse: {json.dumps(parse_counted(event._event.template, bytes(header.payload)), default=str)}")
        try:
            print(f"  event_values: {json.dumps(_jsonable(event.event_values()), default=str)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  event_values raised {type(exc).__name__}: {exc}")
    print(f"\ncache_after: {list(map(str, manifest.CACHE))}")
    return 0


def _infer_guid(records: list[tuple[int, Any]], explicit: str | None) -> UUID:
    if explicit:
        return UUID(explicit)
    providers = {}
    for index, record in records:
        if index == 0:
            continue
        providers.setdefault(str(record.header.provider_id), record.header.provider_id)
    if len(providers) != 1:
        raise SystemExit(f"multiple providers in file, pass --guid: {list(providers)}")
    return next(iter(providers.values()))


def cmd_compare(args: argparse.Namespace) -> int:
    path = Path(args.etl)
    etl = ETL(io.BytesIO(path.read_bytes()))
    records = iter_records(etl)
    guid = _infer_guid(records, args.guid)

    print(f"file: {path}")
    print(f"provider: {guid}")
    print(f"pointer_size={etl.pointer_size} is_64bit={etl.is_64bit} records={len(records)}")

    candidates = [Candidate.from_spec(spec) for spec in args.candidate]
    if not candidates:
        auto = bundled_candidate(guid)
        if auto is None:
            print("no bundled manifest for this provider; supply --candidate", file=sys.stderr)
            return 2
        candidates = [auto]
    candidates = rank_candidates(candidates)

    reports = [candidate_report(guid, candidate, records) for candidate in candidates]
    _print_table(
        record_table(reports),
        [
            ("record", "rec"),
            ("candidate", "candidate"),
            ("lookup", "lookup(op,ver)"),
            ("id", "entry(id,ver)"),
            ("layout", "layout"),
            ("payload", "bytes"),
            ("used", "used"),
            ("left", "left"),
            ("verdict", "fit"),
            ("result", "parse result"),
        ],
    )

    print("\nmanifest provenance:")
    for report in reports:
        if report.get("load_error"):
            print(f"  {report['candidate']['name']}: LOAD ERROR {report['load_error']}")
            continue
        identity = report["identity"]
        module = report["module"]
        print(
            f"  {report['candidate']['name']}: origin={identity['origin']} "
            f"sha256={identity['sha256'][:16]} events={module['events']} "
            f"provider={module['provider_name']!r} symbol={module['provider_symbol']!r}"
        )
        print(f"    {identity['location']}")

    print("\nper-record conclusion (byte fit is not provenance):")
    summary = ambiguity_summary(reports)
    if not summary:
        print("  no candidate produced a usable event report")
        for report in reports:
            if report.get("load_error"):
                print(f"  {report['candidate']['name']}: load error {report['load_error']}")
    for item in summary:
        print(f"  record {item['record']}: [{item['resolution']}] {item['conclusion']}")
        if item["lookup_only"]:
            print(f"    lookup-key-only candidates: {', '.join(item['lookup_only'])}")

    if args.load_order:
        _print_load_order(guid, candidates, records)

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "file": str(path),
                    "provider": str(guid),
                    "pointer_size": etl.pointer_size,
                    "is_64bit": etl.is_64bit,
                    "candidates": reports,
                    "ambiguity": ambiguity_summary(reports),
                },
                indent=2,
                default=str,
            )
        )
        print(f"\nwrote {args.json}")
    return 0


def _print_load_order(guid: UUID, candidates: list[Candidate], records: list[tuple[int, Any]]) -> None:
    print("\nload order (cold cache, then each candidate in turn, exactly like opening files):")
    original_cache = dict(manifest.CACHE)
    try:
        for step, candidate in enumerate(candidates):
            seed_cache = {} if step == 0 else dict(manifest.CACHE)
            manifest.CACHE.clear()
            manifest.CACHE.update(seed_cache)
            module, identity = candidate.load(guid)
            manifest.CACHE.setdefault(guid, module)
            winner = lookup_identity(guid)
            first = step == 0
            print(
                f"  open {step}: candidate={candidate.name:<10} "
                f"cold={'yes' if first else 'no ':<3} "
                f"installed={winner.get('provider_symbol') or winner.get('provider_name')!r} "
                f"cache_hit={'no' if first else 'yes'}"
            )
        print("  first successful lookup wins for the lifetime of the process; later files")
        print("  for the same GUID silently reuse it (cache_hit=yes) regardless of their bytes.")
    finally:
        manifest.CACHE.clear()
        manifest.CACHE.update(original_cache)


def cmd_cache_order(args: argparse.Namespace) -> int:
    """Run the *real* record.event path with different cache seeds.

    This is deliberately not a simulation: it reproduces what a long-lived
    process sees when two exporters' files are opened in a chosen order.
    """
    path = Path(args.etl)
    data = path.read_bytes()
    etl = ETL(io.BytesIO(data))
    guid = _infer_guid(iter_records(etl), args.guid)
    candidates = rank_candidates([Candidate.from_spec(spec) for spec in args.candidate])
    if not candidates:
        auto = bundled_candidate(guid)
        if auto is None:
            print("no bundled manifest for this provider; supply --candidate", file=sys.stderr)
            return 2
        candidates = [auto]

    print(f"file: {path}")
    print(f"provider: {guid}")
    print(f"duration: {etl.end - etl.start} (logfile start/end)\n")
    rows = []
    original_cache = dict(manifest.CACHE)
    try:
        for seed in candidates:
            module, identity = seed.load(guid)
            # Fresh ETL per seed: EventRecord also memoises the parsed Event,
            # so reusing records would hide the effect we are measuring.
            manifest.CACHE.clear()
            manifest.CACHE[guid] = module
            seed_etl = ETL(io.BytesIO(data))
            for index, record in iter_records(seed_etl):
                if index == 0:
                    continue
                header = record.header
                info = describe_header(header)
                try:
                    event = record.event
                    if event._event is not None:
                        parse = parse_counted(event._event.template, bytes(header.payload))
                        values = parse.get("values")
                        rows.append(
                            {
                                "seed": seed.name,
                                "record": index,
                                "descriptor": _descriptor_signature(info),
                                "manifest_symbol": event.symbol(),
                                "template": getattr(event._event.template, "__name__", None),
                                "used": parse.get("consumed"),
                                "left": parse.get("unconsumed"),
                                "values": json.dumps(values, default=str)[:90],
                                "result": "ok" if parse["ok"] else parse["error"],
                            }
                        )
                    else:
                        rows.append(
                            {
                                "seed": seed.name,
                                "record": index,
                                "descriptor": _descriptor_signature(info),
                                "manifest_symbol": None,
                                "template": None,
                                "used": "-",
                                "left": "-",
                                "values": "-",
                                "result": "no lookup entry",
                            }
                        )
                except Exception as exc:  # noqa: BLE001 - cache-order failures are findings
                    rows.append(
                        {
                            "seed": seed.name,
                            "record": index,
                            "descriptor": _descriptor_signature(info),
                            "manifest_symbol": "<raised>",
                            "template": "-",
                            "used": "-",
                            "left": "-",
                            "values": "-",
                            "result": f"{type(exc).__name__}: {exc}",
                        }
                    )
    finally:
        manifest.CACHE.clear()
        manifest.CACHE.update(original_cache)

    _print_table(
        rows,
        [
            ("seed", "cache seed"),
            ("record", "rec"),
            ("descriptor", "descriptor"),
            ("manifest_symbol", "symbol"),
            ("template", "template"),
            ("used", "used"),
            ("left", "left"),
            ("values", "values"),
            ("result", "result"),
        ],
    )
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2, default=str))
        print(f"\nwrote {args.json}")
    return 0


def _descriptor_signature(info: dict[str, Any]) -> str:
    d = info.get("descriptor") or {}
    return (
        f"id={d.get('id')} op={d.get('opcode')} ver={d.get('version')} "
        f"lvl={d.get('level')} task={d.get('task')} kw=0x{(d.get('keywords') or 0):x}"
    )


def cmd_probe(args: argparse.Namespace) -> int:
    """List the two key spaces a manifest contains: event value and opcode."""
    guid = UUID(args.guid)
    for spec in args.candidate:
        candidate = Candidate.from_spec(spec)
        module, identity = candidate.load(guid)
        print(f"\ncandidate {candidate.name} sha256={identity.digest}")
        print(f"  {identity.location}")
        print(f"  provider={module.PROVIDER_NAME!r} symbol={module.PROVIDER_SYMBOL!r} events={len(module.EVENTS)}")
        for key in sorted(module.EVENTS):
            entry = module.EVENTS[key]
            if args.id is not None and entry.value != args.id:
                continue
            size = entry.template.size
            print(
                f"  EVENTS[{key}] value={entry.value} opcode={entry.opcode!r} version={entry.version} "
                f"symbol={entry.symbol!r} template={entry.template.__name__} "
                f"size={size if size is not None else 'dyn'}"
            )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="inspect one ETL through the real, process-wide cache")
    inspect.add_argument("etl")
    inspect.set_defaults(func=cmd_inspect)

    compare = sub.add_parser("compare", help="evaluate isolated candidate manifests against one ETL")
    compare.add_argument("etl")
    compare.add_argument("--guid", help="provider GUID (inferred when the file has one)")
    compare.add_argument("--candidate", action="append", default=[], metavar="NAME=PATH|repo")
    compare.add_argument("--load-order", action="store_true", help="show first-wins cache ordering")
    compare.add_argument("--json", metavar="PATH")
    compare.set_defaults(func=cmd_compare)

    cache_order = sub.add_parser("cache-order", help="run the real parse path under different cache seeds")
    cache_order.add_argument("etl")
    cache_order.add_argument("--guid")
    cache_order.add_argument("--candidate", action="append", default=[], metavar="NAME=PATH|repo")
    cache_order.add_argument("--json", metavar="PATH")
    cache_order.set_defaults(func=cmd_cache_order)

    probe = sub.add_parser("probe", help="list EVENTS keys (value vs opcode) for a provider GUID")
    probe.add_argument("guid")
    probe.add_argument("--candidate", action="append", default=[], metavar="NAME=PATH|repo")
    probe.add_argument("--id", type=int, help="filter to one descriptor id")
    probe.set_defaults(func=cmd_probe)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
