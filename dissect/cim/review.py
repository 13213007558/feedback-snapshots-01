"""Offline review packages for WMI permanent event subscriptions.

This module is a small prototype for handing *one* WMI permanent subscription
(filter + consumer + binding) to another investigator for offline review,
without distributing the whole ``OBJECTS.DATA``.

Evidence model
--------------
The package separates four roles of data:

``evidence-raw``
    Verbatim record bytes extracted from ``OBJECTS.DATA`` (the three instance
    records and every class-definition record needed to decode them,
    including the full inheritance chain so inherited default values can be
    resolved). These bytes must be preserved bit-exact; their SHA-256 is in
    the manifest.
``derived-view``
    Decoded JSON views of the raw records. These are *derived* data: the
    verifier re-parses the raw records and must reproduce them exactly. They
    exist for convenience, never as a substitute for the raw bytes.
``locator-metadata``
    Data that is only needed to *locate* the evidence in the original
    repository: index key strings, logical->physical mapping entries, TOC
    offsets, page hashes, source file hashes. Not evidence content itself.
``context-disclosure``
    Data about *other* objects that share a data page with the evidence.
    By default only TOC metadata (record id, offset, size, CRC) of
    co-located records is included -- never their content. Full page images
    are optional and explicitly flagged, because they disclose the content
    of unrelated objects.

What the package summary proves / does not prove
------------------------------------------------
The manifest and summary can prove, to a re-verifier:

* the shipped raw records are unmodified since packaging (SHA-256);
* the decoded views are faithful decodings of those exact bytes (the
  verifier re-parses them independently and compares);
* the reference graph is internally consistent: the object paths stored in
  the binding record resolve to the shipped filter/consumer records;
* the provenance metadata suffices to re-locate every record in the
  original ``OBJECTS.DATA`` and to match it against a copy of that file.

It can *not* prove:

* completeness -- other subscriptions/consumers may exist in the source
  repository; the package covers exactly one subscription;
* authenticity of the source ``OBJECTS.DATA`` -- source hashes only anchor
  the package to whatever file was hashed; chain of custody is external;
* that co-located objects are unrelated to the subscription;
* the meaning of repository-internal timestamps (they are reported, not
  validated).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cim.c_cim import DATA_PAGE_SIZE, SYSTEM_NAMESPACE_NAME
from dissect.cim.classes import ClassDefinition, ClassInstance, PropertyDefaultValues
from dissect.cim.cim import Property
from dissect.cim.exceptions import Error

if TYPE_CHECKING:
    from dissect.cim.cim import CIM, Namespace
    from dissect.cim.index import Key

FORMAT_VERSION = "dissect-cim-review/1"

ROLE_EVIDENCE_RAW = "evidence-raw"
ROLE_DERIVED = "derived-view"
ROLE_LOCATOR = "locator-metadata"
ROLE_CONTEXT = "context-disclosure"

PROOF_SCOPE = {
    "proves": [
        "Raw records in the package are byte-identical to what was extracted (SHA-256 in manifest).",
        "Decoded JSON views are faithful decodings of those exact bytes; the verifier re-parses "
        "the raw records offline and must reproduce identical key attributes.",
        "The reference graph is internally consistent: the object paths stored in the binding "
        "record resolve to the included filter and consumer records.",
        "Provenance metadata (index key, logical/physical page, record offset/size, mapping "
        "entry, page SHA-256) suffices to re-locate every record in the original OBJECTS.DATA "
        "and to match it against a copy of that file.",
    ],
    "does_not_prove": [
        "Completeness: other subscriptions, bindings or consumers may exist in the source "
        "repository; this package covers exactly one subscription.",
        "Authenticity of the source OBJECTS.DATA: source hashes only anchor the package to "
        "whatever file was hashed; chain of custody must come from outside the package.",
        "That co-located objects on the same pages are unrelated to the subscription; only "
        "their TOC metadata (or, if enabled, full page images) is disclosed.",
        "The meaning of repository-internal timestamps (ts1/ts2, class timestamps); they are "
        "reported as-is, not validated.",
    ],
    "additional_disclosures": [
        "Full 0x2000-byte page images of pages containing evidence records (only when "
        "include_pages=True): discloses the content of co-located, potentially unrelated "
        "objects (other subscriptions, command lines, SIDs, user names).",
        "Page SHA-256 hashes (always included): disclose no content, but allow confirmation "
        "of the records' page context against the original OBJECTS.DATA.",
        "TOC metadata of co-located records (record id, offset, size, CRC): discloses their "
        "existence and layout, not their content.",
        "Mapping entries and index key strings: disclose hashes (MD5/SHA-256 of uppercased "
        "UTF-16-LE names) of object names; enumerable for known names.",
        "Source file hashes of OBJECTS.DATA / INDEX.BTR / MAPPING*.MAP, when provided.",
    ],
}

_INSTANCE_REF_RE = re.compile(r"^(?P<class>[A-Za-z_][A-Za-z0-9_]*)\.(?P<keys>.+)$")
_KEY_PAIR_RE = re.compile(r"""([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^;]+)""")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return {"@datetime": value.isoformat()}
    if isinstance(value, bytes):
        return {"@bytes": value.hex()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, str):
        return str(value)
    return str(value)


def _normalize(view: dict[str, Any]) -> dict[str, Any]:
    """Reduce a view to JSON-native types so comparisons are encoding-stable."""
    return json.loads(json.dumps(view, ensure_ascii=False))


def _type_name(cim_type: Any) -> str:
    name = cim_type.type.name
    if cim_type.array_state.name == "ARRAY":
        name += "[]"
    return name


def _sanitize(item_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", item_id)


def parse_instance_reference(value: str) -> tuple[str, dict[str, str]]:
    """Parse a relative instance object path, e.g. ``__EventFilter.Name="X"``."""
    match = _INSTANCE_REF_RE.match(value.strip())
    if not match:
        raise ValueError(f"Not an instance reference: {value!r}")
    keys = {}
    for pair in _KEY_PAIR_RE.finditer(match.group("keys")):
        raw = pair.group(2)
        if raw.startswith(('"', "'")) and raw.endswith(('"', "'")):
            raw = raw[1:-1]
        keys[pair.group(1)] = raw
    return match.group("class"), keys


class OfflineClass:
    """A class layout rebuilt purely from preserved class-definition records.

    Mirrors the parts of :class:`dissect.cim.cim.Class` that are needed to
    decode instances and inherited default values, without a live repository.
    """

    def __init__(self, class_definition: ClassDefinition, parent: OfflineClass | None = None):
        self.class_definition = class_definition
        self.parent = parent

    @property
    def name(self) -> str:
        return self.class_definition.class_name

    @property
    def derivation(self) -> list[OfflineClass]:
        chain = []
        node: OfflineClass | None = self
        while node is not None:
            chain.append(node)
            node = node.parent
        chain.reverse()
        return chain

    @cached_property
    def properties(self) -> dict[str, Property]:
        props = {}
        for class_ in self.derivation:
            for prop in class_.class_definition.properties.values():
                props[prop.name] = Property(self, prop)
        return props

    @property
    def property_default_values(self) -> PropertyDefaultValues:
        props = sorted(self.properties.values(), key=lambda p: p.index)
        return PropertyDefaultValues(BytesIO(self.class_definition.default_values_data), props)


class _OfflineCim:
    """Minimal shim for :class:`ClassInstance`, which only needs ``type_xp``."""

    def __init__(self, type_xp: bool):
        self.type_xp = type_xp


def build_offline_classes(class_records: dict[str, bytes]) -> dict[str, OfflineClass]:
    """Rebuild the class hierarchy from raw class-definition records.

    Args:
        class_records: mapping of an arbitrary id to raw record bytes.

    Returns:
        Mapping of lowercased class name to :class:`OfflineClass`.
    """
    definitions = {}
    for item_id, raw in class_records.items():
        cd = ClassDefinition(None, BytesIO(raw))
        definitions[cd.class_name.lower()] = cd

    classes: dict[str, OfflineClass] = {}

    def resolve(name: str) -> OfflineClass:
        key = name.lower()
        if key in classes:
            return classes[key]
        if key not in definitions:
            raise Error(f"Missing class definition record for: {name}")
        cd = definitions[key]
        parent = resolve(cd.super_class_name) if cd.super_class_name else None
        classes[key] = OfflineClass(cd, parent)
        return classes[key]

    for name in definitions:
        resolve(name)
    return classes


def _class_view(offline_class: OfflineClass, namespace: str) -> dict[str, Any]:
    cd = offline_class.class_definition
    merged = offline_class.properties
    props = []
    for name, prop in cd.properties.items():
        merged_prop = merged[name]
        entry = {
            "name": name,
            "type": _type_name(prop.type),
            "index": prop.index,
            "offset": prop.offset,
            "level": prop.level,
            "qualifiers": {k: _json_value(q.value) for k, q in prop.qualifiers.items()},
            "has_default_value": merged_prop.has_default_value,
            "is_inherited": merged_prop.is_inherited,
        }
        if merged_prop.has_default_value:
            entry["default_value"] = _json_value(merged_prop.default_value)
        props.append(entry)
    return _normalize(
        {
            "class_name": cd.class_name,
            "super_class_name": cd.super_class_name,
            "namespace": namespace,
            "timestamp": cd.timestamp.isoformat(),
            "keys": cd.keys,
            "qualifiers": {k: _json_value(q.value) for k, q in cd.qualifiers.items()},
            "properties": props,
        }
    )


def _instance_view(class_name: str, namespace: str, ci: ClassInstance) -> dict[str, Any]:
    props = []
    for name, prop in ci.properties.items():
        entry = {
            "name": name,
            "type": _type_name(prop.type),
            "is_initialized": prop.is_initialized,
            "is_default_value": prop.is_default_value,
            "is_inherited": prop.is_inherited,
        }
        if prop.is_initialized:
            entry["value"] = _json_value(prop.value)
        if prop.has_default_value:
            entry["default_value"] = _json_value(prop.default_value)
        props.append(entry)
    return _normalize(
        {
            "class": class_name,
            "namespace": namespace,
            "key": {k: _json_value(v) for k, v in ci.key.items()},
            "key_string": str(ci.key),
            "ts1": ci.ts1.isoformat(),
            "ts2": ci.ts2.isoformat(),
            "properties": props,
        }
    )


def _parse_instance_record(offline_class: OfflineClass, raw: bytes, type_xp: bool) -> ClassInstance:
    return ClassInstance(_OfflineCim(type_xp), offline_class, BytesIO(raw))


@dataclass
class RecordExtraction:
    """Raw record bytes plus everything needed to re-locate them."""

    raw: bytes
    index_key: str
    logical_page: int
    physical_page: int
    record_id: int
    record_offset: int
    record_size: int
    toc_crc: int
    declared_length: int
    spanned_logical_pages: list[int]
    page_sha256: str
    mapping_entry: dict[str, Any]
    co_located: list[dict[str, Any]]

    def provenance(self) -> dict[str, Any]:
        return {
            "index_key": self.index_key,
            "logical_page": self.logical_page,
            "physical_page": self.physical_page,
            "record_id": self.record_id,
            "record_offset": self.record_offset,
            "record_size": self.record_size,
            "toc_crc": self.toc_crc,
            "declared_length": self.declared_length,
            "spanned_logical_pages": self.spanned_logical_pages,
            "page_sha256": self.page_sha256,
            "mapping_entry": self.mapping_entry,
        }


def extract_record(cim: CIM, ref: Key) -> RecordExtraction:
    """Extract a record's verbatim bytes and its locating metadata."""
    store = cim.objects.store
    page = store.page(ref.data_page)

    entry = next((e for e in page.toc.entries if e.record_id == ref.data_id), None)
    if entry is None:
        raise Error(f"Record id {ref.data_id} not found on logical page {ref.data_page}")

    raw = cim.objects.get(ref).read()

    spanned = []
    remaining = len(raw) - entry.size
    logical = ref.data_page + 1
    while remaining > 0:
        spanned.append(logical)
        remaining -= DATA_PAGE_SIZE
        logical += 1

    mapping_entry = store.map.get_entry(ref.data_page)
    page_bytes = store.physical_page(mapping_entry.page_number)

    co_located = [
        {"record_id": e.record_id, "offset": e.offset, "size": e.size, "crc": e.crc}
        for e in page.toc.entries
        if e.record_id != ref.data_id
    ]

    return RecordExtraction(
        raw=raw,
        index_key=str(ref),
        logical_page=ref.data_page,
        physical_page=mapping_entry.page_number,
        record_id=ref.data_id,
        record_offset=entry.offset,
        record_size=entry.size,
        toc_crc=entry.crc,
        declared_length=ref.data_length,
        spanned_logical_pages=spanned,
        page_sha256=_sha256(page_bytes),
        mapping_entry={
            "logical_page": ref.data_page,
            "physical_page": mapping_entry.page_number,
            "page_crc": mapping_entry.page_crc,
            "free_space": mapping_entry.free_space,
            "used_space": mapping_entry.used_space,
            "first_id": mapping_entry.first_id,
            "second_id": mapping_entry.second_id,
        },
        co_located=co_located,
    )


def _class_definition_ref(cim: CIM, namespace: str, class_name: str) -> tuple[str, Key]:
    """Resolve a class definition reference, falling back to the system namespace."""
    for ns_name in (namespace, SYSTEM_NAMESPACE_NAME):
        ref = cim.key().NS(ns_name).CD(class_name).reference()
        if ref is not None:
            return ns_name, ref
    raise Error(f"Cannot resolve class definition: {class_name}")


def _instance_refs(cim: CIM, ns: Namespace, class_name: str) -> list[tuple[Key, bytes]]:
    """Enumerate (index reference, raw record) pairs for all instances of a class."""
    refs = []
    q = cim.key().NS(ns.name).CI(class_name).IL()
    for ref in q.references():
        refs.append((ref, cim.objects.get(ref).read()))
    return refs


def _matches_instance(ci: ClassInstance, class_name: str, keys: dict[str, str]) -> bool:
    if ci.class_name.lower() != class_name.lower():
        return False
    instance_key = ci.key
    for prop, value in keys.items():
        for key_name, key_value in instance_key.items():
            if key_name.lower() == prop.lower() and str(key_value) == value:
                break
        else:
            return False
    return True


@dataclass
class _Item:
    id: str
    role: str
    kind: str
    raw: bytes | None = None
    view: dict[str, Any] | None = None
    provenance: RecordExtraction | None = None
    namespace: str | None = None
    class_name: str | None = None


def build_review_package(
    cim: CIM,
    namespace: str,
    out_dir: str | Path,
    binding_key: str | None = None,
    sources: dict[str, BinaryIO] | None = None,
    include_pages: bool = False,
) -> Path:
    """Build an offline review package for one permanent event subscription.

    Args:
        cim: the live repository, used only to *locate* records.
        namespace: namespace holding the ``__FilterToConsumerBinding`` instance.
        out_dir: output directory for the package.
        binding_key: optional string form of the binding instance key, required
            when the namespace holds more than one binding.
        sources: optional ``{name: file-like}`` of source repository files;
            their SHA-256 is recorded as locator metadata.
        include_pages: also ship full images of pages containing evidence
            records (discloses co-located objects' content; see module docs).
    """
    ns = cim.namespace(namespace)
    out = Path(out_dir)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    (out / "decoded").mkdir(parents=True, exist_ok=True)

    items: list[_Item] = []
    class_records: dict[str, bytes] = {}
    class_namespaces: dict[str, str] = {}

    def add_class_with_derivation(class_name: str) -> None:
        name = class_name
        while name:
            if name.lower() not in {k.lower() for k in class_records}:
                resolved_ns, ref = _class_definition_ref(cim, ns.name, name)
                extraction = extract_record(cim, ref)
                item_id = f"class/{resolved_ns}/{name}"
                items.append(
                    _Item(
                        id=item_id,
                        role=ROLE_EVIDENCE_RAW,
                        kind="class-definition",
                        raw=extraction.raw,
                        provenance=extraction,
                        namespace=resolved_ns,
                        class_name=name,
                    )
                )
                class_records[name] = extraction.raw
                class_namespaces[name.lower()] = resolved_ns
                cd = ClassDefinition(None, BytesIO(extraction.raw))
                name = cd.super_class_name
            else:
                cd = ClassDefinition(None, BytesIO(class_records[name]))
                name = cd.super_class_name

    def offline_class_for(class_name: str) -> OfflineClass:
        classes = build_offline_classes({name: raw for name, raw in class_records.items()})
        return classes[class_name.lower()]

    # 1. Locate and select the binding instance.
    binding_candidates = []
    for ref, raw in _instance_refs(cim, ns, "__FilterToConsumerBinding"):
        add_class_with_derivation("__FilterToConsumerBinding")
        ci = _parse_instance_record(offline_class_for("__FilterToConsumerBinding"), raw, cim.type_xp)
        if binding_key is None or str(ci.key) == binding_key:
            binding_candidates.append((ref, raw, ci))

    if not binding_candidates:
        raise Error(f"No matching __FilterToConsumerBinding instance in {ns.name}")
    if len(binding_candidates) > 1:
        raise Error("Multiple bindings match; pass binding_key to select one")
    binding_ref, binding_raw, binding_ci = binding_candidates[0]

    binding_extraction = extract_record(cim, binding_ref)
    items.append(
        _Item(
            id="instance/binding",
            role=ROLE_EVIDENCE_RAW,
            kind="instance",
            raw=binding_raw,
            provenance=binding_extraction,
            namespace=ns.name,
            class_name="__FilterToConsumerBinding",
        )
    )

    # 2. Resolve filter and consumer references from the binding record.
    binding_props = binding_ci.properties
    references = []
    endpoints = {}
    for prop_name, item_id in (("Filter", "instance/filter"), ("Consumer", "instance/consumer")):
        ref_value = binding_props[prop_name].value
        class_name, keys = parse_instance_reference(ref_value)
        add_class_with_derivation(class_name)
        offline_class = offline_class_for(class_name)

        match = None
        for ref, raw in _instance_refs(cim, ns, class_name):
            ci = _parse_instance_record(offline_class, raw, cim.type_xp)
            if _matches_instance(ci, class_name, keys):
                if match is not None:
                    raise Error(f"Ambiguous instance reference: {ref_value}")
                match = (ref, raw, ci)
        if match is None:
            raise Error(f"Cannot resolve instance reference: {ref_value}")

        ref, raw, ci = match
        extraction = extract_record(cim, ref)
        items.append(
            _Item(
                id=item_id,
                role=ROLE_EVIDENCE_RAW,
                kind="instance",
                raw=raw,
                provenance=extraction,
                namespace=ns.name,
                class_name=class_name,
            )
        )
        endpoints[prop_name.lower()] = ci
        references.append(
            {"from": "instance/binding", "property": prop_name, "raw_value": ref_value, "to": item_id}
        )

    # 3. Decoded views, derived exclusively from the preserved raw records.
    all_classes = build_offline_classes(class_records)
    for item in items:
        if item.kind == "class-definition":
            item.view = _class_view(all_classes[item.class_name.lower()], item.namespace)
        elif item.kind == "instance":
            oc = all_classes[item.class_name.lower()]
            ci = _parse_instance_record(oc, item.raw, cim.type_xp)
            item.view = _instance_view(item.class_name, item.namespace, ci)

    # 4. Locator metadata: mapping entries and source hashes.
    mapping_locators: dict[int, dict[str, Any]] = {}
    for item in items:
        prov = item.provenance
        for logical in [prov.logical_page, *prov.spanned_logical_pages]:
            if logical not in mapping_locators:
                entry = cim.objects.store.map.get_entry(logical)
                mapping_locators[logical] = {
                    "logical_page": logical,
                    "physical_page": entry.page_number,
                    "page_crc": entry.page_crc,
                    "free_space": entry.free_space,
                    "used_space": entry.used_space,
                    "first_id": entry.first_id,
                    "second_id": entry.second_id,
                }

    source_hashes = {}
    if sources:
        for name, fh in sources.items():
            pos = fh.tell()
            fh.seek(0)
            source_hashes[name] = _sha256(fh.read())
            fh.seek(pos)

    # 5. Context disclosure: co-located record metadata, optional page images.
    evidence_records = {(item.provenance.physical_page, item.provenance.record_id) for item in items}
    pages: dict[int, dict[str, Any]] = {}
    for item in items:
        prov = item.provenance
        page = pages.setdefault(
            prov.physical_page,
            {
                "physical_page": prov.physical_page,
                "page_sha256": prov.page_sha256,
                "evidence_items": [],
                "co_located_records": {},
            },
        )
        page["evidence_items"].append(item.id)
        for record in prov.co_located:
            if (prov.physical_page, record["record_id"]) in evidence_records:
                continue
            page["co_located_records"][record["record_id"]] = record
    for page in pages.values():
        page["co_located_records"] = sorted(page["co_located_records"].values(), key=lambda r: r["offset"])

    if include_pages:
        (out / "pages").mkdir(exist_ok=True)
        for physical_page, page in pages.items():
            page_bytes = cim.objects.store.physical_page(physical_page)
            page_file = f"pages/page_{physical_page:06d}.bin"
            (out / page_file).write_bytes(page_bytes)
            page["file"] = page_file
            page["file_sha256"] = _sha256(page_bytes)
            page["disclosure"] = (
                "Full page image: contains the content of co-located objects that are "
                "not part of this subscription."
            )

    # 6. Write raw records and decoded views.
    manifest_items = []
    for item in items:
        entry = {"id": item.id, "role": item.role, "kind": item.kind}
        raw_file = f"raw/{_sanitize(item.id)}.bin"
        (out / raw_file).write_bytes(item.raw)
        entry.update(
            {
                "file": raw_file,
                "sha256": _sha256(item.raw),
                "size": len(item.raw),
                "namespace": item.namespace,
                "class": item.class_name,
                "provenance": item.provenance.provenance(),
            }
        )
        decoded_file = f"decoded/{_sanitize(item.id)}.json"
        (out / decoded_file).write_text(json.dumps(item.view, indent=2, ensure_ascii=False))
        entry["decoded"] = decoded_file
        entry["decoded_role"] = ROLE_DERIVED
        manifest_items.append(entry)

    for logical, locator in sorted(mapping_locators.items()):
        manifest_items.append({"id": f"locator/mapping/{logical}", "role": ROLE_LOCATOR, **locator})
    for physical_page, page in sorted(pages.items()):
        manifest_items.append(
            {
                "id": f"context/page/{physical_page}",
                "role": ROLE_CONTEXT,
                **page,
                "justification": (
                    "Co-located records share a data page with evidence records; only their "
                    "TOC metadata is disclosed so the original page context can be re-located "
                    "and hashed, without exporting unrelated objects' content."
                ),
            }
        )

    manifest = {
        "format": FORMAT_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "subject": {
            "namespace": ns.name,
            "binding_key": str(binding_ci.key),
        },
        "source": {
            "type_xp": cim.type_xp,
            "file_sha256": source_hashes,
            "note": "Source hashes anchor this package to the hashed repository files; "
            "they say nothing about those files' own provenance.",
        },
        "items": manifest_items,
        "references": references,
        "proof_scope": PROOF_SCOPE,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    views = {item.id: item.view for item in items}
    (out / "SUMMARY.md").write_text(_render_summary(manifest, views))
    return out


def _prop_value(view: dict[str, Any], name: str) -> Any:
    for prop in view["properties"]:
        if prop["name"].lower() == name.lower():
            return prop.get("value")
    return None


def _render_summary(manifest: dict[str, Any], views: dict[str, Any]) -> str:
    lines = [
        "# WMI Permanent Subscription - Offline Review Package",
        "",
        f"- Format: `{manifest['format']}`",
        f"- Created (UTC): {manifest['created_utc']}",
        f"- Subject namespace: `{manifest['subject']['namespace']}`",
        f"- Binding key: `{manifest['subject']['binding_key']}`",
    ]
    source_hashes = manifest["source"].get("file_sha256") or {}
    if source_hashes:
        lines.append("- Source anchors (SHA-256):")
        for name, digest in sorted(source_hashes.items()):
            lines.append(f"  - `{name}`: `{digest}`")

    filter_view = views.get("instance/filter", {})
    consumer_view = views.get("instance/consumer", {})
    binding_view = views.get("instance/binding", {})

    lines += [
        "",
        "## Key attributes (decoded from the preserved raw records)",
        "",
        f"### Filter - {filter_view.get('class')} ({filter_view.get('key_string')})",
        "",
    ]
    for prop in ("Name", "Query", "QueryLanguage", "EventNamespace"):
        lines.append(f"- {prop}: `{_prop_value(filter_view, prop)}`")
    lines += [
        "",
        f"### Consumer - {consumer_view.get('class')} ({consumer_view.get('key_string')})",
        "",
    ]
    for prop in consumer_view.get("properties", []):
        if prop.get("is_initialized") and prop.get("value") not in (None, "", False, 0):
            lines.append(f"- {prop['name']}: `{prop.get('value')}`")
    lines += [
        "",
        f"### Binding - {binding_view.get('class')}",
        "",
        f"- ts1/ts2: `{binding_view.get('ts1')}` / `{binding_view.get('ts2')}`",
        "",
        "## Reference graph",
        "",
    ]
    for ref in manifest["references"]:
        lines.append(f"- `{ref['from']}` --{ref['property']}--> `{ref['to']}` (`{ref['raw_value']}`)")

    lines += ["", "## Evidence items and provenance", ""]
    for item in manifest["items"]:
        if item["role"] == ROLE_EVIDENCE_RAW:
            prov = item["provenance"]
            lines.append(
                f"- `{item['id']}`: sha256 `{item['sha256'][:16]}...`, "
                f"physical page {prov['physical_page']}, offset {prov['record_offset']}, "
                f"size {prov['record_size']}"
            )
        elif item["role"] == ROLE_CONTEXT:
            count = len(item["co_located_records"])
            lines.append(
                f"- `{item['id']}`: {count} co-located record(s), metadata only "
                f"(page sha256 `{item['page_sha256'][:16]}...`)"
            )

    lines += ["", "## What this package proves", ""]
    lines += [f"- {s}" for s in PROOF_SCOPE["proves"]]
    lines += ["", "## What this package does NOT prove", ""]
    lines += [f"- {s}" for s in PROOF_SCOPE["does_not_prove"]]
    lines += ["", "## Possible additional disclosures (to preserve page-level evidence)", ""]
    lines += [f"- {s}" for s in PROOF_SCOPE["additional_disclosures"]]
    lines.append("")
    return "\n".join(lines)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
    views: dict[str, Any] = field(default_factory=dict)
    references: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name, ok, detail))


def verify_review_package(pkg_dir: str | Path) -> VerifyReport:
    """Independently verify a review package and re-read it offline.

    Re-reads only the package contents: re-hashes raw records, re-parses them
    with the CIM decoders, regenerates the decoded views, and resolves the
    reference graph. Returns a report whose ``views`` hold the independently
    decoded key attributes.
    """
    pkg = Path(pkg_dir)
    report = VerifyReport()

    manifest = json.loads((pkg / "manifest.json").read_text())
    report.add(
        "manifest.format",
        manifest.get("format") == FORMAT_VERSION,
        manifest.get("format", "<missing>"),
    )
    type_xp = manifest["source"]["type_xp"]

    # 1. Integrity of every shipped byte string.
    raw_records: dict[str, bytes] = {}
    class_records: dict[str, bytes] = {}
    item_meta: dict[str, dict[str, Any]] = {}
    for item in manifest["items"]:
        item_meta[item["id"]] = item
        file_name = item.get("file")
        if not file_name:
            continue
        data = (pkg / file_name).read_bytes()
        digest = _sha256(data)
        ok = digest == item.get("sha256", item.get("file_sha256")) and (
            "size" not in item or len(data) == item["size"]
        )
        report.add(f"integrity.{item['id']}", ok, f"sha256={digest[:16]}...")
        if item.get("role") == ROLE_EVIDENCE_RAW:
            raw_records[item["id"]] = data
            if item["kind"] == "class-definition":
                class_records[item["id"]] = data

    # 2. Rebuild the class hierarchy and instances from the raw records only.
    try:
        classes = build_offline_classes(class_records)
        offline_by_item = {}
        for item_id, raw in class_records.items():
            cd = ClassDefinition(None, BytesIO(raw))
            offline_by_item[item_id] = classes[cd.class_name.lower()]
        report.add("classes.hierarchy", True, f"{len(classes)} classes rebuilt")
    except Exception as e:
        report.add("classes.hierarchy", False, str(e))
        return report

    # 3. Regenerate decoded views and compare with the shipped ones.
    for item in manifest["items"]:
        if item.get("role") != ROLE_EVIDENCE_RAW:
            continue
        item_id = item["id"]
        try:
            if item["kind"] == "class-definition":
                view = _class_view(offline_by_item[item_id], item["namespace"])
            else:
                oc = classes[item["class"].lower()]
                ci = _parse_instance_record(oc, raw_records[item_id], type_xp)
                report.add(
                    f"instance.class_name.{item_id}",
                    ci.class_name.lower() == item["class"].lower(),
                    f"record says {ci.class_name!r}",
                )
                view = _instance_view(item["class"], item["namespace"], ci)
        except Exception as e:
            report.add(f"decoded.matches_raw.{item_id}", False, f"re-parse failed: {e}")
            continue
        shipped = json.loads((pkg / item["decoded"]).read_text())
        report.add(
            f"decoded.matches_raw.{item_id}",
            shipped == view,
            "decoded view regenerated from raw record",
        )
        report.views[item_id] = view

    # 4. Resolve the reference graph against the included instances.
    instance_views = {
        item_id: view
        for item_id, view in report.views.items()
        if item_meta[item_id]["kind"] == "instance"
    }
    for edge in manifest.get("references", []):
        try:
            class_name, keys = parse_instance_reference(edge["raw_value"])
            resolved = None
            for item_id, view in instance_views.items():
                if view["class"].lower() != class_name.lower():
                    continue
                view_keys = {k.lower(): str(v) for k, v in view["key"].items()}
                if all(view_keys.get(p.lower()) == v for p, v in keys.items()):
                    resolved = item_id
            ok = resolved == edge["to"]
            detail = f"{edge['raw_value']} -> {resolved}"
        except Exception as e:
            ok, detail = False, str(e)
        report.add(f"reference.{edge['from']}.{edge['property']}", ok, detail)

        source_view = report.views.get(edge["from"])
        if source_view:
            stored = _prop_value(source_view, edge["property"])
            report.add(
                f"reference.value.{edge['from']}.{edge['property']}",
                stored == edge["raw_value"],
                f"stored value {stored!r}",
            )
    report.references = manifest.get("references", [])

    # 5. Provenance completeness: mapping locators and context disclosures.
    mapping_locators = {
        item["logical_page"]
        for item in manifest["items"]
        if item.get("role") == ROLE_LOCATOR and item["id"].startswith("locator/mapping/")
    }
    context_pages = {
        item["physical_page"]
        for item in manifest["items"]
        if item.get("role") == ROLE_CONTEXT
    }
    for item in manifest["items"]:
        if item.get("role") != ROLE_EVIDENCE_RAW:
            continue
        prov = item["provenance"]
        needed = {prov["logical_page"], *prov["spanned_logical_pages"]}
        report.add(
            f"locator.mapping.{item['id']}",
            needed <= mapping_locators,
            f"logical pages {sorted(needed)}",
        )
        report.add(
            f"context.disclosed.{item['id']}",
            prov["physical_page"] in context_pages,
            f"physical page {prov['physical_page']}",
        )

    return report
