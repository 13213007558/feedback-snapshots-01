from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from dissect.cim.consistency import diagnose, diagnose_directory, parse_mapping

PAGE_SIZE = 0x2000


def index_page(logical_id: int, keys: list[list[str]], children: list[int] | None = None) -> bytes:
    """Build a minimal but structurally valid index page."""
    parts: list[str] = []
    for key in keys:
        for part in key:
            if part not in parts:
                parts.append(part)

    definitions: list[int] = []
    starts: list[int] = []
    for key in keys:
        starts.append(len(definitions))
        definitions.append(len(key))
        for part in key:
            definitions.append(parts.index(part))

    fixed = 20 + 4 * len(keys) + 4 * (len(keys) + 1) + 2 * len(keys) + 2 + 2 * len(definitions) + 2
    fixed += 2 * (len(parts) + 1)

    payload = bytearray()
    offsets: list[int] = []
    for part in parts:
        offsets.append(len(payload))
        payload += part.encode("utf8") + b"\x00"

    buf = bytearray(PAGE_SIZE)
    struct.pack_into("<5I", buf, 0, 0xACCC, logical_id, 0, 0, len(keys))

    offset = 20
    for _ in keys:
        struct.pack_into("<I", buf, offset, 0)
        offset += 4
    for child in children or [0] * (len(keys) + 1):
        struct.pack_into("<I", buf, offset, child)
        offset += 4
    for start in starts:
        struct.pack_into("<H", buf, offset, start)
        offset += 2
    struct.pack_into("<H", buf, offset, len(definitions))
    offset += 2
    for value in definitions:
        struct.pack_into("<H", buf, offset, value)
        offset += 2
    struct.pack_into("<H", buf, offset, len(parts))
    offset += 2
    for value in offsets:
        struct.pack_into("<H", buf, offset, value)
        offset += 2
    struct.pack_into("<H", buf, offset, 0)
    offset += 2

    assert offset == fixed, (offset, fixed)
    buf[fixed : fixed + len(payload)] = payload
    return bytes(buf)


def object_page(records: list[tuple[int, int]]) -> bytes:
    """Build an object page whose TOC lists ``(record_id, size)`` pairs."""
    buf = bytearray(PAGE_SIZE)
    payload_offset = 0x100
    offset = 0
    for record_id, size in records:
        struct.pack_into("<4I", buf, offset, record_id, payload_offset, size, 0)
        offset += 16
        buf[payload_offset : payload_offset + size] = bytes([record_id & 0xFF]) * size
        payload_offset += size
    return bytes(buf)


def mapping(
    object_entries: list[tuple[int, ...]],
    index_entries: list[tuple[int, ...]],
    *,
    version: int,
    first_id: int,
    second_id: int,
    object_pages: int,
    index_pages: int,
    trailing: int = 1,
) -> bytes:
    """Build a two-table mapping file (object table followed by index table)."""
    out = bytearray()
    for declared, entries in ((object_pages, object_entries), (index_pages, index_entries)):
        out += struct.pack("<6I", 0xABCD, version, first_id, second_id, declared, len(entries))
        for entry in entries:
            out += struct.pack("<6I", *entry)
        out += struct.pack("<I", 0) + struct.pack("<I", 0xDCBA)
    out += struct.pack("<I", trailing)
    return bytes(out)


def entry(page_number: int, generation: int, *, crc: int = 0, free: int = 0, used: int = 0) -> tuple[int, ...]:
    return (page_number, crc, free, used, generation, generation - 1)


UNMAPPED = (0x3FFFFFFF, 0, 0, 0, 0, 0)


def two_generation_fixture() -> tuple[bytes, bytes, bytes, bytes]:
    """Two mapping files that are each self-consistent but mutually incompatible.

    Generation 1 places logical object page 2 on physical page 2, holding record 11.
    Generation 2 moves the same logical page to physical page 6, holding record 12.
    Their index tables point at different physical copies of the tree.
    """
    objects = bytearray()
    objects += object_page([(11, 64)])
    objects += object_page([(21, 32)])
    objects += object_page([(11, 64)])
    objects += object_page([(31, 48)])
    objects += object_page([(41, 16)])
    objects += object_page([(51, 16)])
    objects += object_page([(12, 64)])
    objects += object_page([(61, 16)])

    key_old = ["NS_AAAA", "CI_BBBB", "IL_CCCC.2.11.64"]
    key_new = ["NS_AAAA", "CI_BBBB", "IL_CCCC.2.12.64"]

    index = bytearray()
    index += index_page(0, [key_old])
    index += index_page(1, [["NS_DDDD", "CD_EEEE"]])
    index += index_page(0, [key_new])
    index += index_page(1, [["NS_DDDD", "CD_EEEE"]])

    old_object = [entry(0, 1), entry(1, 1), entry(2, 1), entry(3, 1)] + [UNMAPPED] * 4
    old_index = [entry(0, 1), entry(1, 1)] + [UNMAPPED] * 2
    new_object = [entry(0, 2), entry(1, 2), entry(6, 2), entry(3, 2)] + [UNMAPPED] * 4
    new_index = [entry(2, 2), entry(1, 2)] + [UNMAPPED] * 2

    old = mapping(
        old_object, old_index, version=0x10, first_id=1, second_id=0, object_pages=8, index_pages=4
    )
    new = mapping(
        new_object, new_index, version=0x11, first_id=2, second_id=1, object_pages=8, index_pages=4
    )
    return bytes(index), bytes(objects), old, new


def test_two_generations_are_each_readable() -> None:
    index, objects, old, new = two_generation_fixture()

    for name, data in (("OLD.MAP", old), ("NEW.MAP", new)):
        report = diagnose(index, objects, [(name, data)])
        assert report.verdict == "trusted_with_caveats", report.to_text()
        assert report.recommended_source == name
        assert not [f for f in report.proven if f.code.startswith("reference")]
        assert [f for f in report.insufficient if f.code == "coverage.candidates"]


def test_cross_combination_proves_generation_mismatch() -> None:
    index, objects, old, new = two_generation_fixture()
    report = diagnose(index, objects, [("OLD.MAP", old), ("NEW.MAP", new)])

    assert report.verdict == "trusted_with_caveats"
    assert report.recommended_source == "NEW.MAP"

    cross = {(c.index_source, c.object_source): c for c in report.cross}
    assert cross[("OLD.MAP", "OLD.MAP")].dangling == 0
    assert cross[("NEW.MAP", "NEW.MAP")].dangling == 0
    assert cross[("OLD.MAP", "NEW.MAP")].dangling == 1
    assert cross[("NEW.MAP", "OLD.MAP")].dangling == 1
    assert cross[("OLD.MAP", "NEW.MAP")].breakdown["record_missing"] == 1

    codes = {f.code for f in report.proven}
    assert "reference.cross" in codes
    assert "mapping.objects.divergence" in codes
    assert "mapping.index.divergence" in codes


def test_identical_page_tables_with_different_generations_is_proven() -> None:
    index, objects, old, _ = two_generation_fixture()
    # Rebuild the same page tables, but claim a newer generation everywhere.
    clone = mapping(
        [entry(0, 2), entry(1, 2), entry(2, 2), entry(3, 2)] + [UNMAPPED] * 4,
        [entry(0, 2), entry(1, 2)] + [UNMAPPED] * 2,
        version=0x11,
        first_id=2,
        second_id=1,
        object_pages=8,
        index_pages=4,
    )

    report = diagnose(index, objects, [("OLD.MAP", old), ("CLONE.MAP", clone)])
    same_table = [f for f in report.insufficient if f.code == "mapping.objects.same_table"]
    assert same_table
    assert "cannot decide which" in same_table[0].detail
    assert "mapping.index.same_table" in {f.code for f in report.insufficient}


def test_missing_index_table_is_insufficient_not_tampering() -> None:
    index, objects, old, _ = two_generation_fixture()
    object_only = old[: len(old) // 2]

    report = diagnose(index, objects, [("PARTIAL.MAP", object_only)])
    assert report.verdict == "insufficient"
    assert [f.code for f in report.proven if f.code == "layout.tables"]
    detail = " ".join(f.detail for f in report.findings)
    assert "missing" in detail or "cannot serve both roles" in detail


def test_no_mapping_file_is_missing_material() -> None:
    index, objects, _, _ = two_generation_fixture()
    report = diagnose(index, objects, [])

    assert report.verdict == "insufficient"
    assert report.recommended_source is None
    assert any(f.code == "coverage.candidates" for f in report.insufficient)
    assert any("not evidence of tampering" in reason for reason in report.reasons)


def test_declared_capacity_without_truncation_is_insufficient() -> None:
    index, objects, old, _ = two_generation_fixture()
    # Claim one more index page than INDEX.BTR actually holds, but keep mapped pages inside the file.
    patched = bytearray(old)
    tables = parse_mapping(old, "OLD.MAP").tables
    struct.pack_into("<I", patched, tables[1].offset + 8, 5)
    report = diagnose(index, objects, [("OLD.MAP", bytes(patched))])

    capacity = [f for f in report.findings if f.code == "layout.capacity.index"]
    assert capacity and capacity[0].status == "insufficient"


def test_truncated_mapped_page_is_proven() -> None:
    index, objects, old, _ = two_generation_fixture()
    patched = bytearray(old)
    tables = parse_mapping(old, "OLD.MAP").tables
    struct.pack_into("<I", patched, tables[1].entry_offsets[0], 99)
    report = diagnose(index, objects, [("OLD.MAP", bytes(patched))])

    range_findings = [f for f in report.proven if f.code == "page.mapping.range"]
    assert range_findings


def test_diagnose_directory_is_read_only(tmp_path: Path) -> None:
    index, objects, old, new = two_generation_fixture()
    for name, data in (("INDEX.BTR", index), ("OBJECTS.DATA", objects), ("MAPPING1.MAP", old), ("MAPPING2.MAP", new)):
        tmp_path.joinpath(name).write_bytes(data)

    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.iterdir()}
    first = diagnose_directory(tmp_path)
    second = diagnose_directory(tmp_path)
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.iterdir()}

    assert after == before
    assert first.to_dict() == second.to_dict()
    assert first.verdict == "trusted_with_caveats"


def test_real_capture_selection_is_not_recency(tmp_path: Path) -> None:
    """The shipped capture mixes three generations; the parser still picks MAPPING1."""
    import gzip

    data = Path(__file__).parent / "_data"
    index = gzip.decompress(data.joinpath("INDEX.BTR.gz").read_bytes())
    objects = gzip.decompress(data.joinpath("OBJECTS.DATA.gz").read_bytes())
    mappings = [
        (f"MAPPING{i}.MAP", gzip.decompress(data.joinpath(f"MAPPING{i}.MAP.gz").read_bytes())) for i in range(1, 4)
    ]

    report = diagnose(index, objects, mappings)

    assert report.selection.library_pick == "MAPPING1.MAP"
    assert report.selection.newest_by_stamp == "MAPPING2.MAP"
    assert report.selection.order_dependent is True
    assert report.recommended_source == "MAPPING2.MAP"

    cross = {(c.index_source, c.object_source): c for c in report.cross}
    for source in ("MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"):
        assert cross[(source, source)].dangling == 0
    assert cross[("MAPPING1.MAP", "MAPPING3.MAP")].dangling == 22
    assert cross[("MAPPING3.MAP", "MAPPING2.MAP")].dangling == 24

    codes = {f.code for f in report.proven}
    assert {"selection.version_tie", "selection.newest", "reference.cross"} <= codes
    assert not [f for f in report.proven if f.code == "reference.self"]
