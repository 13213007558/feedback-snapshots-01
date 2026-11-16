from __future__ import annotations

import json
from typing import TYPE_CHECKING, BinaryIO

from dissect.cim.cim import CIM
from dissect.cim.review import (
    ROLE_CONTEXT,
    ROLE_EVIDENCE_RAW,
    ROLE_LOCATOR,
    build_review_package,
    verify_review_package,
)

if TYPE_CHECKING:
    from pathlib import Path


def _build_package(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO], out: Path) -> Path:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    return build_review_package(
        repo,
        "root\\subscription",
        out,
        sources={"OBJECTS.DATA": objects_bin, "INDEX.BTR": index_bin},
    )


def test_review_package_roundtrip(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO], tmp_path: Path
) -> None:
    pkg = _build_package(index_bin, objects_bin, mappings_bin, tmp_path / "pkg")

    manifest = json.loads((pkg / "manifest.json").read_text())
    roles = {item["role"] for item in manifest["items"]}
    assert ROLE_EVIDENCE_RAW in roles
    assert ROLE_LOCATOR in roles
    assert ROLE_CONTEXT in roles

    raw_ids = {item["id"] for item in manifest["items"] if item["role"] == ROLE_EVIDENCE_RAW}
    assert {"instance/binding", "instance/filter", "instance/consumer"} <= raw_ids
    # Class definitions must cover the full inheritance chain for inherited defaults.
    class_ids = {item["class"].lower() for item in manifest["items"] if item.get("kind") == "class-definition"}
    assert {
        "__filtertoconsumerbinding",
        "__eventfilter",
        "nteventlogeventconsumer",
        "__eventconsumer",
        "__indicationrelated",
        "__systemclass",
    } <= class_ids

    # No page images by default: co-located objects are metadata-only.
    assert not (pkg / "pages").exists()

    report = verify_review_package(pkg)
    assert report.ok, [c for c in report.checks if not c.ok]

    # Independent offline read yields the same key attributes.
    filter_view = report.views["instance/filter"]
    assert filter_view["class"] == "__EventFilter"
    assert filter_view["key"] == {"Name": "SCM Event Log Filter"}
    props = {p["name"]: p.get("value") for p in filter_view["properties"]}
    assert props["Query"] == "select * from MSFT_SCMEventLogEvent"
    assert props["QueryLanguage"] == "WQL"
    assert props["EventNamespace"] == "root\\cimv2"

    consumer_view = report.views["instance/consumer"]
    assert consumer_view["class"] == "NTEventLogEventConsumer"
    consumer_props = {p["name"]: p.get("value") for p in consumer_view["properties"]}
    assert consumer_props["SourceName"] == "Service Control Manager"

    # Reference graph resolves binding -> filter/consumer.
    edges = {(e["from"], e["property"], e["to"]) for e in report.references}
    assert ("instance/binding", "Filter", "instance/filter") in edges
    assert ("instance/binding", "Consumer", "instance/consumer") in edges


def test_review_package_detects_tampering(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO], tmp_path: Path
) -> None:
    pkg = _build_package(index_bin, objects_bin, mappings_bin, tmp_path / "pkg")

    raw_file = pkg / "raw" / "instance_filter.bin"
    data = bytearray(raw_file.read_bytes())
    data[-1] ^= 0xFF
    raw_file.write_bytes(bytes(data))

    report = verify_review_package(pkg)
    assert not report.ok
    assert any(c.name == "integrity.instance/filter" and not c.ok for c in report.checks)


def test_review_package_detects_decoded_tampering(
    index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO], tmp_path: Path
) -> None:
    pkg = _build_package(index_bin, objects_bin, mappings_bin, tmp_path / "pkg")

    decoded_file = pkg / "decoded" / "instance_filter.json"
    view = json.loads(decoded_file.read_text())
    for prop in view["properties"]:
        if prop["name"] == "Query":
            prop["value"] = "select * from SomethingElse"
    decoded_file.write_text(json.dumps(view, indent=2))

    report = verify_review_package(pkg)
    assert not report.ok
    assert any(c.name == "decoded.matches_raw.instance/filter" and not c.ok for c in report.checks)
