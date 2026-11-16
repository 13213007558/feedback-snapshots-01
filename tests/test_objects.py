from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.cim.c_cim import DATA_PAGE_SIZE, UNMAPPED_PAGE_VALUE
from dissect.cim.cim import CIM
from dissect.cim.exceptions import (
    DuplicateRecordIdError,
    MissingObjectDataError,
    ObjectLengthError,
    RecordNotFoundError,
    ShortReadError,
    UnmappedPageError,
)
from dissect.cim.index import Key

if TYPE_CHECKING:
    from collections.abc import Iterable

INDEX_PHYSICAL = 5
START_LOGICAL = 10
OBJECT_OFFSET = 0x100
TAIL_MARKER = b"<<<UNIQUE-OBJECT-TAIL-MARKER>>>"
AFTER_OBJECT = b"AFTER-OBJECT-DECOY"


@dataclass
class Repository:
    cim: CIM
    key: Key
    data: bytes


def mapping_file(entries: list[int], physical_page_count: int) -> BytesIO:
    """Build a mapping file with two consecutive mapping states, as Windows writes them."""
    entry_count = len(entries)
    header = struct.pack("<6I", 0xABCD, 0x1234, 2, 1, physical_page_count, entry_count)
    body = b"".join(struct.pack("<6I", page, 0, 0, 0, 2, 1) for page in entries)
    blob = header + body + struct.pack("<I", 0) + struct.pack("<I", 0xDCBA)

    return BytesIO(blob + blob + b"\x00\x00\x00\x00")


def index_file(physical_page_count: int) -> BytesIO:
    """Build an index file with one empty leaf page at logical page 0."""
    page = struct.pack("<6I3H", 1, 0, 0, 0, 0, 0xFFFFFFFF, 0, 0, 0)
    buf = bytearray(physical_page_count * DATA_PAGE_SIZE)
    buf[INDEX_PHYSICAL * DATA_PAGE_SIZE : INDEX_PHYSICAL * DATA_PAGE_SIZE + len(page)] = page

    return BytesIO(bytes(buf))


def object_key(cim: CIM, logical_page: int, record_id: int, length: int) -> Key:
    return Key(cim, f"TEST.{logical_page}.{record_id}.{length}")


def build_repository(
    *,
    data: bytes | None = None,
    offset: int = OBJECT_OFFSET,
    start_physical: int = 7,
    continuation_physicals: tuple[int, ...] = (2, 9, 4),
    toc_size: int | None = None,
    index_length: int | None = None,
    toc_record_id: int = 1,
    key_record_id: int = 1,
    duplicate_record_id: bool = False,
    unmapped: Iterable[int] = (),
    truncated_mapping: int | None = None,
    adjacent_decoy: bytes | None = None,
    truncate: int | None = None,
    physical_page_count: int = 16,
) -> Repository:
    if data is None:
        body_len = 2 * DATA_PAGE_SIZE + 291
        body = _pattern(body_len - len(TAIL_MARKER)) + TAIL_MARKER
        data = body
        # Fill the first fragment with data, so the object starts in the middle of the page.
        data = _pattern(DATA_PAGE_SIZE - offset) + data

    logical_pages: dict[int, bytes] = {}

    first_length = min(len(data), DATA_PAGE_SIZE - offset)
    first_page = bytearray(b"\x00" * DATA_PAGE_SIZE)

    toc_entries = struct.pack("<4I", toc_record_id, offset, toc_size if toc_size is not None else len(data), 0)
    if duplicate_record_id:
        toc_entries += struct.pack("<4I", toc_record_id, offset + 1, len(data), 0)
    toc_entries += struct.pack("<4I", 0, 0, 0, 0)
    first_page[: len(toc_entries)] = toc_entries
    first_page[offset : offset + first_length] = data[:first_length]
    logical_pages[START_LOGICAL] = bytes(first_page)

    chunks = [data[pos : pos + DATA_PAGE_SIZE] for pos in range(first_length, len(data), DATA_PAGE_SIZE)]
    if len(chunks) != len(continuation_physicals):
        raise AssertionError(f"Need {len(chunks)} continuation pages, got {len(continuation_physicals)}")

    chunk_lengths = [len(chunk) for chunk in chunks]
    for logical_offset, (chunk, _physical) in enumerate(zip(chunks, continuation_physicals, strict=True), start=1):
        if len(chunk) < DATA_PAGE_SIZE:
            chunk = chunk + AFTER_OBJECT * (DATA_PAGE_SIZE // len(AFTER_OBJECT))
            chunk = chunk[:DATA_PAGE_SIZE]

        logical_pages[START_LOGICAL + logical_offset] = chunk

    objects = bytearray(b"\xcc" * (physical_page_count * DATA_PAGE_SIZE))

    # Put a decoy right after the start page's physical location. Reading physical neighbours
    # instead of following the logical mapping would pick this up.
    if start_physical + 1 < physical_page_count:
        decoy = (b"WRONG-PHYSICAL-NEIGHBOUR:" * DATA_PAGE_SIZE)[:DATA_PAGE_SIZE]
        objects[(start_physical + 1) * DATA_PAGE_SIZE : (start_physical + 2) * DATA_PAGE_SIZE] = decoy

    for logical_offset, physical in enumerate([start_physical, *continuation_physicals]):
        chunk = logical_pages[START_LOGICAL + logical_offset]
        objects[physical * DATA_PAGE_SIZE : physical * DATA_PAGE_SIZE + len(chunk)] = chunk

    # Put decoy bytes immediately after the real object bytes on its final page, simulating the
    # next object sharing the page. A boundary bug would borrow these bytes.
    if adjacent_decoy is not None:
        final_physical = continuation_physicals[-1] if continuation_physicals else start_physical
        final_length = chunk_lengths[-1] if chunk_lengths else first_length
        decoy_start = final_physical * DATA_PAGE_SIZE + final_length
        objects[decoy_start : decoy_start + len(adjacent_decoy)] = adjacent_decoy

    if truncate is not None:
        objects = objects[:truncate]

    entry_count = max(START_LOGICAL + len(continuation_physicals) + 1, 32)
    entries = [UNMAPPED_PAGE_VALUE] * entry_count
    entries[0] = INDEX_PHYSICAL
    for logical_offset, physical in enumerate([start_physical, *continuation_physicals]):
        entries[START_LOGICAL + logical_offset] = physical
    for logical_page in unmapped:
        entries[logical_page] = UNMAPPED_PAGE_VALUE

    if truncated_mapping is not None:
        entries = entries[:truncated_mapping]

    mappings = [mapping_file(entries, physical_page_count)]
    cim = CIM(index_file(physical_page_count), BytesIO(bytes(objects)), mappings)
    key = object_key(cim, START_LOGICAL, key_record_id, index_length if index_length is not None else len(data))

    return Repository(cim, key, data)


def _pattern(length: int) -> bytes:
    return bytes((i * 37 + 11) & 0xFF for i in range(length))


def test_reassembles_object_across_shuffled_logical_pages() -> None:
    repo = build_repository()

    result = repo.cim.objects.get(repo.key).read()

    assert result == repo.data
    assert len(result) == repo.key.data_length
    assert result.endswith(TAIL_MARKER)
    assert AFTER_OBJECT not in result
    assert b"WRONG-PHYSICAL-NEIGHBOUR" not in result


def test_last_page_partial_use_is_truncated() -> None:
    repo = build_repository()

    result = repo.cim.objects.get(repo.key).read()

    # The last logical page contains 291 object bytes followed by decoy bytes.
    assert (len(repo.data) - (DATA_PAGE_SIZE - OBJECT_OFFSET)) % DATA_PAGE_SIZE == 291
    assert result[-len(TAIL_MARKER) :] == TAIL_MARKER
    assert AFTER_OBJECT not in result


def test_missing_middle_mapping_reports_logical_page() -> None:
    repo = build_repository(unmapped=[12])

    with pytest.raises(MissingObjectDataError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.missing_pages == (12,)
    assert error.missing_ranges == ((12, 12),)
    assert error.object_range == (10, 13)
    assert "logical page 12" in str(error)
    assert "logical pages 10-13" in str(error)


def test_missing_consecutive_mappings_report_logical_range() -> None:
    repo = build_repository(unmapped=[11, 12])

    with pytest.raises(MissingObjectDataError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.missing_pages == (11, 12)
    assert error.missing_ranges == ((11, 12),)
    assert "logical pages 11-12" in str(error)


def test_unmapped_start_page_reports_missing_start() -> None:
    repo = build_repository(unmapped=[START_LOGICAL])

    with pytest.raises(MissingObjectDataError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.missing_pages == (START_LOGICAL,)
    assert error.object_range == (START_LOGICAL, START_LOGICAL)


def test_unmapped_page_does_not_return_shortened_object() -> None:
    repo = build_repository(unmapped=[12])

    with pytest.raises(MissingObjectDataError):
        repo.cim.objects.get(repo.key)

    # There is deliberately no partially reconstructed result to fall back on.
    assert not hasattr(repo.cim.objects.get, "partial")


def test_short_read_of_continuation_page() -> None:
    # Truncate inside the physical page that holds the last logical continuation page.
    truncate = 12 * DATA_PAGE_SIZE + 100
    repo = build_repository(
        start_physical=1,
        continuation_physicals=(6, 3, 12),
        truncate=truncate,
    )

    with pytest.raises(ShortReadError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.page == 13
    assert error.expected == 291
    assert error.actual == 100
    assert error.missing_pages == (13,)


def test_short_read_of_start_page() -> None:
    data_length = 1000
    data = _pattern(data_length)
    truncate = 15 * DATA_PAGE_SIZE + OBJECT_OFFSET + 500

    repo = build_repository(
        data=data,
        start_physical=15,
        continuation_physicals=(),
        truncate=truncate,
    )

    with pytest.raises(ShortReadError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.page == START_LOGICAL
    assert error.expected == OBJECT_OFFSET + data_length
    assert error.actual == OBJECT_OFFSET + 500


def test_toc_size_smaller_than_index_length() -> None:
    repo = build_repository(toc_size=DATA_PAGE_SIZE)

    with pytest.raises(ObjectLengthError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.toc_size == DATA_PAGE_SIZE
    assert error.index_length == repo.key.data_length
    assert error.logical_page == START_LOGICAL


def test_toc_size_larger_than_index_length() -> None:
    repo = build_repository(toc_size=DATA_PAGE_SIZE * 10)

    with pytest.raises(ObjectLengthError):
        repo.cim.objects.get(repo.key)


def test_duplicate_toc_record_id_is_rejected() -> None:
    repo = build_repository(duplicate_record_id=True)

    with pytest.raises(DuplicateRecordIdError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.record_id == 1
    assert error.logical_page == START_LOGICAL
    assert error.count == 2


def test_missing_toc_record_id_is_rejected() -> None:
    repo = build_repository(key_record_id=999)

    with pytest.raises(RecordNotFoundError) as exc_info:
        repo.cim.objects.get(repo.key)

    assert exc_info.value.record_id == 999
    assert exc_info.value.logical_page == START_LOGICAL


def test_does_not_borrow_bytes_from_adjacent_object() -> None:
    decoy = b"NEXT-OBJECT-ON-SAME-PAGE"
    repo = build_repository(adjacent_decoy=decoy)

    result = repo.cim.objects.get(repo.key).read()

    assert result == repo.data
    assert not result.endswith(decoy)
    assert decoy not in result


def test_missing_multiple_disjoint_ranges() -> None:
    # Span logical pages 10-17 so gaps at 11, 12 and 15 are all inside the object range.
    length = (DATA_PAGE_SIZE - OBJECT_OFFSET) + 6 * DATA_PAGE_SIZE + 100
    data = _pattern(length - len(TAIL_MARKER)) + TAIL_MARKER
    repo = build_repository(
        data=data,
        continuation_physicals=(1, 2, 3, 4, 6, 9, 10),
        unmapped=[11, 12, 15],
    )

    with pytest.raises(MissingObjectDataError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.object_range == (10, 17)
    assert error.missing_pages == (11, 12, 15)
    assert error.missing_ranges == ((11, 12), (15, 15))
    assert "logical pages 11-12, 15" in str(error)


def test_pages_beyond_mapping_entry_count_are_missing() -> None:
    repo = build_repository(truncated_mapping=12)

    with pytest.raises(MissingObjectDataError) as exc_info:
        repo.cim.objects.get(repo.key)

    error = exc_info.value
    assert error.missing_pages == (12, 13)
    assert error.missing_ranges == ((12, 13),)


def test_non_data_key_is_rejected() -> None:
    repo = build_repository()

    with pytest.raises(ValueError, match="not a data reference"):
        repo.cim.objects.get(repo.cim.key("NS_TEST"))


def test_zero_length_object() -> None:
    repo = build_repository(data=b"", continuation_physicals=(), offset=OBJECT_OFFSET)

    assert repo.cim.objects.get(repo.key).read() == b""


def test_unmapped_page_error_is_object_data_error() -> None:
    repo = build_repository(unmapped=[12])

    with pytest.raises(UnmappedPageError):
        repo.cim.objects.get(repo.key)
