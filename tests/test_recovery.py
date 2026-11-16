from __future__ import annotations

import base64
import hashlib
import struct
from io import BytesIO
from typing import BinaryIO

import pytest
from dissect.cim import FragmentReason, RecordClassification, RecordKind, Reliability, SchemaSource
from dissect.cim.cim import CIM
from dissect.cim.recovery import _parse_class_definition, _parse_class_instance

PAGE_SIZE = 0x2000


def _name_hash(name: str) -> str:
    return hashlib.sha256(name.upper().encode("utf-16-le")).hexdigest().upper()


def build_class_definition(name: str, super_name: str = "") -> bytes:
    """Build a minimal class definition record matching the real layout."""
    class_name_record = b"\x00" + name.encode() + b"\x00"
    property_data = b"\x00" + name.encode() + b"\x00"

    out = bytearray()
    out += struct.pack("<I", len(super_name)) + super_name.encode("utf-16-le")
    out += struct.pack("<Q", 132000000000000000)
    out += struct.pack("<I", 0) + b"\x00"
    out += struct.pack("<I", 0)  # class name offset in property data
    out += struct.pack("<I", 0)  # default values metadata size
    out += struct.pack("<I", 4 + len(class_name_record)) + class_name_record
    out += struct.pack("<I", 4)  # empty qualifier list includes its own length
    out += struct.pack("<I", 0)  # property count
    out += struct.pack("<I", len(property_data)) + property_data
    out += struct.pack("<I", 4)  # trailing empty section
    return bytes(out)


def build_class_instance(name: str, extra: bytes = b"", properties: int = 0) -> bytes:
    """Build a minimal class instance record matching the real layout."""
    name_hash = _name_hash(name)
    content = b"\x00" + name.encode() + b"\x00" + extra
    data_region = struct.pack("<I", len(content)) + content
    property_states = b"\x00" * ((2 * properties + 7) // 8)
    remaining = property_states + struct.pack("<I", 0) + b"\x01" + data_region
    data_size = 9 + len(remaining)

    data = name_hash.encode("utf-16-le")
    data += struct.pack("<QQII", 1, 1, data_size, 0)
    data += b"\x00" + remaining
    return data


def build_data_page(records: list[tuple[int, bytes]], start_offset: int | None = None) -> bytes:
    count = len(records)
    offset = start_offset if start_offset is not None else (count + 1) * 16

    toc = bytearray()
    for record_id, data in records:
        toc += struct.pack("<IIII", record_id, offset, len(data), 0)
        offset += len(data)
    toc += b"\x00" * 16

    body = b"".join(data for _, data in records)
    page = bytes(toc) + body
    assert len(page) <= PAGE_SIZE
    return page + b"\x00" * (PAGE_SIZE - len(page))


def build_index_page(keys: list[str]) -> bytes:
    keys = sorted(keys)
    count = len(keys)

    strings = b""
    offsets = []
    for key in keys:
        offsets.append(len(strings))
        strings += key.encode() + b"\x00"

    body = bytearray()
    body += struct.pack("<IIIII", 0xABCD, 0, 0, 0, count)
    body += struct.pack(f"<{count}I", *([0] * count))
    body += struct.pack(f"<{count + 1}I", *([0xFFFFFFFF] * (count + 1)))
    body += struct.pack(f"<{count}H", *[i * 2 for i in range(count)])

    string_definition_table = []
    for i in range(count):
        string_definition_table += [1, i]
    body += struct.pack("<H", len(string_definition_table))
    body += struct.pack(f"<{len(string_definition_table)}H", *string_definition_table)
    body += struct.pack("<H", count)
    body += struct.pack(f"<{count + 1}H", *[*offsets, 0])

    page = bytes(body) + strings
    return page + b"\x00" * (PAGE_SIZE - len(page))


def build_mapping(entries: dict[int, tuple[int, int]], count: int, version: int) -> bytes:
    """Build a normal (non-XP) mapping file. Entries are logical -> (physical, free space)."""
    out = bytearray()
    out += struct.pack("<IIIIII", 0xABCD, version, 3, 2, 64, count)
    for logical in range(count):
        if logical in entries:
            physical, free_space = entries[logical]
            out += struct.pack("<IIIIII", physical, 0, free_space, 0, 3, 2)
        else:
            out += struct.pack("<IIIIII", 0x3FFFFFFF, 0, 0, 0, 3, 2)
    out += struct.pack("<I", 0)
    return bytes(out)


def build_mapping_file(objects_mapping: bytes, index_mapping: bytes) -> bytes:
    return objects_mapping + struct.pack("<I", 0xDCBA) + index_mapping


def data_key(namespace: str, class_name: str, kind: str, page: int, record_id: int, length: int) -> str:
    ns_hash = hashlib.sha256(namespace.upper().encode("utf-16-le")).hexdigest().upper()
    class_hash = _name_hash(class_name)
    if kind == "CD":
        return f"NS_{ns_hash}/CD_{class_hash}.{page}.{record_id}.{length}"
    return f"NS_{ns_hash}/CI_{class_hash}/IL_{'A' * 64}.{page}.{record_id}.{length}"


@pytest.fixture
def synthetic_cim() -> tuple[CIM, dict[str, bytes]]:
    namespace = "root\\test"
    reachable_class = "TestConsumer"
    residual_class = "ResidualConsumer"
    missing_class = "MissingConsumer"

    reachable_cd = build_class_definition(reachable_class)
    reachable_inst = build_class_instance(reachable_class)
    residual_cd = build_class_definition(residual_class)
    residual_inst = build_class_instance(residual_class)
    missing_inst = build_class_instance(missing_class)

    text = b'ROOT\\subscription:CommandLineEventConsumer.Name="Evil";powershell -enc SECRET'

    # Page 0: reachable class definition and instance, plus plain text that must not be treated as an object.
    page0_records = [
        (1, reachable_cd),
        (2, reachable_inst),
        (3, text),
    ]
    page0 = build_data_page(page0_records)

    # Page 1: instance whose class definition is absent everywhere.
    page1 = build_data_page([(4, missing_inst)])

    # Page 2: residual class definition and instance. The class definition is unreferenced, but it still
    # provides a schema for the residual instance.
    page2 = build_data_page([(5, residual_cd), (6, residual_inst)])

    # Page 3 + 4: a record that spans a page boundary. The first page carries only its TOC and the first chunk.
    cross_inst = build_class_instance(reachable_class, extra=b"\x00" * 9000)
    first_chunk = cross_inst[: PAGE_SIZE - 32]
    continuation_data = cross_inst[PAGE_SIZE - 32 :]
    cross_page = struct.pack("<IIII", 7, 32, len(cross_inst), 0) + b"\x00" * 16 + first_chunk
    cross_page += b"\x00" * (PAGE_SIZE - len(cross_page))
    continuation_page = continuation_data + b"\x00" * (PAGE_SIZE - len(continuation_data))

    # Page 5: residual record left behind on a page that is also mapped by a stale mapping file.
    reused_inst = build_class_instance(reachable_class)
    page5 = build_data_page([(8, reused_inst)])

    # Page 6: two structurally valid records, but the second one lies in the page's reported free space.
    free_cd = build_class_definition("FreeConsumer")
    free_inst = build_class_instance("FreeConsumer")
    page6 = build_data_page([(9, free_cd), (10, free_inst)])
    free_space_page6 = PAGE_SIZE - (2 * 16 + len(free_cd))

    # Page 7: empty TOC but stale payload, as left behind after a page was reused.
    stale_payload = b'ROOT\\subscription:__EventFilter.Name="Stale"\x00' * 4
    page7 = b"\x00" * 16 + stale_payload + b"\x00" * (PAGE_SIZE - 16 - len(stale_payload))

    objects = b"".join([page0, page1, page2, cross_page, continuation_page, page5, page6, page7])

    page0_used = (len(page0_records) + 1) * 16 + sum(len(data) for _, data in page0_records)
    free_spaces = {
        0: PAGE_SIZE - page0_used,
        1: PAGE_SIZE - ((1 + 1) * 16 + len(missing_inst)),
        2: PAGE_SIZE - ((2 + 1) * 16 + len(residual_cd) + len(residual_inst)),
        3: 0,
        4: 0,
        5: PAGE_SIZE - ((1 + 1) * 16 + len(reused_inst)),
        6: free_space_page6,
        7: PAGE_SIZE - 16,
    }

    current_entries = {logical: (logical, free_spaces[logical]) for logical in free_spaces}
    current = build_mapping(current_entries, 8, version=2)

    # The stale mapping maps logical page 7 to physical page 5 as well, marking it as reused.
    stale_entries = {**{logical: (logical, 0) for logical in current_entries}, 7: (5, 0)}
    stale = build_mapping(stale_entries, 8, version=1)

    index_mapping = build_mapping({0: (0, 0)}, 1, version=2)

    keys = [
        data_key(namespace, reachable_class, "CD", 0, 1, len(reachable_cd)),
        data_key(namespace, reachable_class, "IL", 0, 2, len(reachable_inst)),
    ]
    index = build_index_page(keys)

    cim = CIM(
        BytesIO(index),
        BytesIO(objects),
        [BytesIO(build_mapping_file(stale, index_mapping)), BytesIO(build_mapping_file(current, index_mapping))],
    )

    expected = {
        "reachable_cd": reachable_cd,
        "reachable_inst": reachable_inst,
        "residual_cd": residual_cd,
        "residual_inst": residual_inst,
        "missing_inst": missing_inst,
        "text": text,
        "cross_inst": cross_inst,
        "reused_inst": reused_inst,
        "free_cd": free_cd,
        "free_inst": free_inst,
        "stale_payload": stale_payload,
    }
    return cim, expected


def test_scan_is_opt_in_and_does_not_change_enumeration(synthetic_cim: tuple[CIM, dict[str, bytes]]) -> None:
    cim, _ = synthetic_cim

    assert not hasattr(cim, "_recovery")
    before = [class_.name for class_ in cim.namespace("root\\test").classes]
    cim.scan_unreferenced()
    after = [class_.name for class_ in cim.namespace("root\\test").classes]

    assert before == after
    assert before == ["TestConsumer"]
    # Residual records are not enumerated as real instances.
    assert [
        instance.class_instance.class_name for instance in cim.namespace("root\\test").class_("TestConsumer").instances
    ] == ["TestConsumer"]


def test_scan_classification(synthetic_cim: tuple[CIM, dict[str, bytes]]) -> None:
    cim, expected = synthetic_cim
    result = cim.scan_unreferenced()

    by_id = {record.record_id: record for record in result.records}

    reachable_cd = by_id[1]
    assert reachable_cd.classification is RecordClassification.REACHABLE
    assert reachable_cd.kind is RecordKind.CLASS_DEFINITION
    assert reachable_cd.class_name == "TestConsumer"
    assert reachable_cd.schema_source is SchemaSource.RECORD
    assert reachable_cd.data == expected["reachable_cd"]

    reachable_inst = by_id[2]
    assert reachable_inst.classification is RecordClassification.REACHABLE
    assert reachable_inst.kind is RecordKind.CLASS_INSTANCE
    assert reachable_inst.data == expected["reachable_inst"]

    residual_cd = by_id[5]
    assert residual_cd.classification is RecordClassification.UNREFERENCED
    assert residual_cd.kind is RecordKind.CLASS_DEFINITION
    assert residual_cd.class_name == "ResidualConsumer"
    assert residual_cd.reliability is Reliability.MEDIUM
    assert residual_cd.data == expected["residual_cd"]

    residual_inst = by_id[6]
    assert residual_inst.classification is RecordClassification.UNREFERENCED
    assert residual_inst.kind is RecordKind.CLASS_INSTANCE
    assert residual_inst.class_name == "ResidualConsumer"
    assert residual_inst.schema_source is SchemaSource.RECOVERY
    assert residual_inst.reliability is Reliability.HIGH
    assert residual_inst.data == expected["residual_inst"]

    missing = by_id[4]
    assert missing.classification is RecordClassification.FRAGMENT
    assert missing.fragment_reason is FragmentReason.CLASS_DEFINITION_MISSING
    assert missing.class_name == "MissingConsumer"
    assert missing.data == expected["missing_inst"]

    text = by_id[3]
    assert text.classification is RecordClassification.FRAGMENT
    assert text.fragment_reason is FragmentReason.STRUCTURE_INVALID
    assert text.class_name is None
    assert text.data == expected["text"]

    # The text contains a consumer path, but it must not be surfaced as a deleted malicious subscription.
    assert b"CommandLineEventConsumer" in text.data
    assert text.class_name != "CommandLineEventConsumer"
    assert text.is_fragment


def test_scan_cross_page_and_page_reuse(synthetic_cim: tuple[CIM, dict[str, bytes]]) -> None:
    cim, expected = synthetic_cim
    result = cim.scan_unreferenced()

    by_id = {record.record_id: record for record in result.records}

    cross = by_id[7]
    assert cross.classification is RecordClassification.UNREFERENCED
    assert cross.cross_page is True
    assert cross.reliability is Reliability.MEDIUM
    assert cross.length == len(expected["cross_inst"])
    assert cross.data == expected["cross_inst"]

    reused = by_id[8]
    assert reused.classification is RecordClassification.FRAGMENT
    assert reused.fragment_reason is FragmentReason.PAGE_REUSED
    assert reused.page_reused is True
    assert reused.data == expected["reused_inst"]
    assert 5 in result.reused_physical_pages

    in_free = by_id[10]
    assert in_free.classification is RecordClassification.FRAGMENT
    assert in_free.fragment_reason is FragmentReason.RECORD_IN_FREE_SPACE
    assert in_free.in_free_space is True
    assert in_free.data == expected["free_inst"]


def test_scan_preserves_location_and_schema(synthetic_cim: tuple[CIM, dict[str, bytes]]) -> None:
    cim, expected = synthetic_cim
    result = cim.scan_unreferenced()

    record = next(record for record in result.records if record.record_id == 6)
    assert record.physical_page == 2
    assert record.logical_page == 2
    assert record.offset == 3 * 16 + len(expected["residual_cd"])
    assert record.length == len(expected["residual_inst"])
    assert record.class_hash == _name_hash("ResidualConsumer")
    assert record.schema_available is True
    assert record.location.toc_crc == 0


def test_scan_output_is_inert(synthetic_cim: tuple[CIM, dict[str, bytes]]) -> None:
    cim, expected = synthetic_cim
    result = cim.scan_unreferenced()

    text = next(record for record in result.records if record.record_id == 3)
    payload = result.to_dict()

    assert "data" not in payload["records"][0]
    assert payload["records"][0]["data_sha256"]

    with_data = text.to_dict(include_data=True)
    assert base64.b64decode(with_data["data"]) == expected["text"]

    assert "CommandLineEventConsumer" not in str(payload["summary"])
    assert result.summary()["reachable"] == 2
    assert result.summary()["unreferenced"] == 3
    assert result.summary()["fragment"] == 5
    assert result.summary()["residual_pages"] == 1

    residual = result.residual_pages[0]
    assert residual.physical_page == 7
    assert residual.logical_page == 7
    assert residual.offset == 16
    assert residual.length == PAGE_SIZE - 16
    assert (
        residual.data_sha256
        == hashlib.sha256(
            expected["stale_payload"] + b"\x00" * (PAGE_SIZE - 16 - len(expected["stale_payload"]))
        ).hexdigest()
    )
    assert "__EventFilter" not in str(residual.to_dict())


def test_record_parsers_reject_malformed_data() -> None:
    payload = build_class_instance("TestConsumer")
    corrupted = bytearray(payload)
    corrupted[-8:] = b"\xff" * 8

    with pytest.raises(ValueError):
        _parse_class_instance(bytes(corrupted), False)

    with pytest.raises(ValueError):
        _parse_class_definition(b"\xff" * 32)
    with pytest.raises(ValueError):
        _parse_class_definition(b"")


def _buffered(fh: BinaryIO) -> BytesIO:
    return BytesIO(fh.read())


@pytest.fixture
def real_cim(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> CIM:
    return CIM(_buffered(index_bin), _buffered(objects_bin), [_buffered(fh) for fh in mappings_bin])


@pytest.fixture
def real_scan(real_cim: CIM) -> tuple[CIM, object]:
    return real_cim, real_cim.scan_unreferenced()


def test_scan_reachable_matches_objects_api(real_scan: tuple[CIM, object]) -> None:
    cim, result = real_scan

    assert result.reachable
    reachable = next(
        record for record in result.reachable if record.index_keys and record.kind is RecordKind.CLASS_INSTANCE
    )

    reference = cim.key(*reachable.index_keys[0].split("/"))
    assert reference.is_data_reference
    expected = cim.objects.get(reference).getvalue()
    assert reachable.data == expected
    assert reachable.length == len(expected)


def _enumeration(cim: CIM) -> tuple[list[str], list[str]]:
    subscription = cim.root.namespace("subscription")
    classes = [class_.name for class_ in subscription.classes]
    instances = [str(instance.key) for instance in subscription.class_("__filtertoconsumerbinding").instances]
    return classes, instances


def test_scan_does_not_change_namespace_enumeration(real_cim: CIM) -> None:
    cim = real_cim

    before_classes, before_instances = _enumeration(cim)
    result = cim.scan_unreferenced()
    after_classes, after_instances = _enumeration(cim)

    assert before_classes == after_classes
    assert before_instances == after_instances
    assert result.unreferenced or result.fragments


def test_scan_real_sample_reports_reasons(real_scan: tuple[CIM, object]) -> None:
    cim, result = real_scan

    reasons = {record.fragment_reason for record in result.fragments}
    assert FragmentReason.STRUCTURE_INVALID in reasons

    for record in result.records:
        assert record.length > 0
        assert record.physical_page >= 0
        assert len(record.data) <= record.length
        assert record.classification in RecordClassification
