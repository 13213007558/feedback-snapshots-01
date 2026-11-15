from __future__ import annotations

import struct
import zlib
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ewf import ewf, metadata
from dissect.evidence.ewf.c_ewf import c_ewf
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Sequence

SEGMENT_HEADER_SIZE = len(c_ewf.SegmentHeader)
DESCRIPTOR_SIZE = len(c_ewf.SectionDescriptor)


def _section(section_type: str, payload: bytes) -> tuple[str, bytes]:
    return section_type, payload


def _header_section(section_type: str, payload: bytes) -> tuple[str, bytes]:
    return _section(section_type, zlib.compress(payload))


def _hash_section(md5_hex: str) -> tuple[str, bytes]:
    data = bytes.fromhex(md5_hex) + b"\x00" * 16 + struct.pack("<I", 0)
    return "hash", data


def _corrupt_section() -> tuple[str, bytes]:
    return "header2", b"this is not zlib compressed data"


def _done_section(offset: int) -> bytes:
    return struct.pack("<16sQQ40sI", b"done".ljust(16, b"\x00"), offset, 0, b"\x00" * 40, 0)


def _main_v3(values: dict[str, str], keys: Sequence[str] | None = None) -> bytes:
    """Build a header2 (format 3) main block; the payload is encoded as UTF-16-LE with a BOM."""
    keys = list(keys if keys is not None else values)
    key_line = "\t".join(keys)
    value_line = "\t".join(values.get(key, "") for key in keys)
    text = f"3\nmain\n{key_line}\n{value_line}\n\n"
    return b"\xff\xfe" + text.encode("utf-16-le")


def _main_v1(values: dict[str, str], keys: Sequence[str] | None = None) -> bytes:
    """Build a legacy header (format 1) main block using CRLF, UTF-8 by default."""
    keys = list(keys if keys is not None else values)
    lines = ["1", "main", "\t".join(keys), "\t".join(values.get(key, "") for key in keys), ""]
    return ("\r\n".join(lines)).encode()


def _build_ewf(sections: Sequence[tuple[str, bytes]]) -> BytesIO:
    """Assemble a minimal EWF segment with correct section chaining and a terminating done section."""
    descriptors: list[bytes] = []
    offset = SEGMENT_HEADER_SIZE
    for section_type, data in sections:
        next_offset = offset + DESCRIPTOR_SIZE + len(data)
        raw_type = section_type.encode().ljust(16, b"\x00")
        descriptors.append(
            struct.pack("<16sQQ40sI", raw_type, next_offset, DESCRIPTOR_SIZE + len(data), b"\x00" * 40, 0)
        )
        offset = next_offset

    out = BytesIO()
    out.write(b"EVF\x09\x0d\x0a\xff\x00" + b"\x01" + struct.pack("<HH", 1, 1))
    for descriptor, (_section_type, data) in zip(descriptors, sections, strict=True):
        out.write(descriptor)
        out.write(data)
    out.write(_done_section(offset))
    out.seek(0)
    return out


def _conflict_sample() -> BytesIO:
    """Two header2 sections disagree on the case number, one header misses fields and one is corrupt.

    The legacy header stores the acquisition time without a timezone, while the header2 sections
    store epoch seconds.
    """
    v3_keys = ["a", "c", "n", "e", "t", "md", "sn", "av", "ov", "m", "u", "p", "dc"]

    first = _main_v3(
        {
            "a": "laptop image",
            "c": "CASE-001",
            "n": "EVID-01",
            "e": "alice",
            "t": "initial acquisition",
            "av": "20140608",
            "ov": "Linux",
            "m": "1766585901",
            "u": "1766585901",
            "p": "0",
        },
        v3_keys,
    )
    second = _main_v3(
        {
            "a": "laptop image",
            "c": "CASE-001-REV2",
            "n": "EVID-01",
            "e": "bob",
            "av": "20140608",
            "ov": "Linux",
            "m": "1766585902",
            "u": "1766585902",
            "p": "0",
        },
        v3_keys,
    )
    legacy = _main_v1(
        {
            "c": "CASE-001",
            "n": "EVID-01",
            "a": "laptop image",
            "e": "alice",
            "t": "initial acquisition",
            "av": "20140608",
            "ov": "Linux",
            "m": "2025 12 24 15 18 21",
            "u": "2025 12 24 15 18 21",
            "p": "",
        }
    )
    sections = [
        _header_section("header2", first),
        _header_section("header2", second),
        _header_section("header", legacy),
        _corrupt_section(),
        _hash_section("9683f7575933eac7390416991cfc5b84"),
    ]
    return _build_ewf(sections)


def test_metadata_conflicting_case_number_and_naive_time() -> None:
    report = metadata.read_metadata(_conflict_sample())

    assert len(report.headers) == 4
    assert [header.healthy for header in report.headers] == [True, True, True, False]
    assert "zlib" in report.corrupt_headers[0].error

    case = report.explain("case_number")
    assert case.conflicting is True
    assert case.distinct_values == ("CASE-001", "CASE-001-REV2")
    # Two healthy headers claim CASE-001 (the two header2 copies), one claims the revision.
    assert case.selected.value == "CASE-001"
    assert case.selection_reason == "majority"
    assert [candidate.origin.section_type for candidate in case.candidates] == [
        "header2",
        "header2",
        "header",
    ]

    examiner = report.explain("examiner_name")
    assert examiner.conflicting is True
    # alice is claimed by the first header2 and the legacy header (two healthy sections),
    # bob only by the second header2, so the majority wins.
    assert examiner.selected.value == "alice"
    assert examiner.selection_reason == "majority"

    times = report.explain("acquisition_time")
    parsed = {candidate.value: metadata.parse_time(candidate.value) for candidate in times.candidates}
    epoch = parsed["1766585902"]
    naive = parsed["2025 12 24 15 18 21"]
    assert epoch.kind == "epoch_seconds"
    assert epoch.timezone_known is True
    assert naive.kind == "space_separated"
    assert naive.timezone_known is False
    assert naive.datetime.tzinfo is None

    brief = report.brief()
    assert brief["case_number"]["value"] == "CASE-001"
    assert brief["case_number"]["value_source"] == "verbatim"
    assert brief["case_number"]["inferred"]["field_name_mapped_from"] == "c"
    inferred_time = brief["acquisition_time"]["inferred"]["time"]
    assert inferred_time["timezone_known"] is False or inferred_time["kind"] == "epoch_seconds"


def test_corrupt_header_never_overrides_healthy_values() -> None:
    report = metadata.read_metadata(_conflict_sample())

    assert len(report.corrupt_headers) == 1
    corrupt = report.corrupt_headers[0]
    assert corrupt.candidates == []
    assert corrupt.raw == b"this is not zlib compressed data"

    # Every selected candidate originates from a healthy header.
    for field_report in report.fields.values():
        if field_report.selected is not None:
            assert field_report.selected.origin in {header.origin for header in report.healthy_headers}


def test_candidate_provenance_and_raw_bytes() -> None:
    report = metadata.read_metadata(_conflict_sample())
    candidate = report.explain("case_number").candidates[0]

    assert candidate.raw_key == "c"
    assert candidate.value == "CASE-001"
    assert candidate.block == "main"
    assert candidate.line_number == 4
    assert candidate.known_field is True
    assert candidate.origin.section_type == "header2"
    assert candidate.origin.encoding == "utf-16-le"
    # The stored raw bytes are the exact UTF-16-LE encoding of the verbatim value.
    assert candidate.raw_value == "CASE-001".encode("utf-16-le")
    assert (
        candidate.raw_value
        == report.headers[0].raw[candidate.byte_offset : candidate.byte_offset + len(candidate.raw_value)]
    )


def test_missing_fields_are_distinct_from_empty_and_absent() -> None:
    payload = _main_v3({"c": "ONLY-CASE", "e": ""}, keys=["a", "c", "e"])
    fh = _build_ewf([_header_section("header2", payload)])
    report = metadata.read_metadata(fh)

    # Absent keys ("a") and present-but-empty keys ("e") both produce no displayable field.
    assert "description" not in report.fields
    assert "examiner_name" not in report.fields
    with pytest.raises(KeyError):
        report.explain("examiner_name")
    assert report.explain("case_number").selected.value == "ONLY-CASE"


def test_tie_break_prefers_header2_then_segment_order() -> None:
    # One header and one header2 each claim a different case number: equal votes, header2 wins.
    legacy = _main_v1({"c": "FROM-HEADER"})
    modern = _main_v3({"c": "FROM-HEADER2"})
    fh = _build_ewf(
        [
            _header_section("header", legacy),
            _header_section("header2", modern),
        ]
    )
    report = metadata.read_metadata(fh)

    case = report.explain("case_number")
    assert case.conflicting is True
    assert case.selection_reason == "preferred_header"
    assert case.selected.value == "FROM-HEADER2"
    assert case.selected.origin.section_type == "header2"


def test_duplicate_keys_keep_every_candidate() -> None:
    payload = _main_v3(
        {"c": "DUP", "t": "first note", "e": "alice"},
        keys=["c", "t", "t", "e"],
    )
    fh = _build_ewf([_header_section("header2", payload)])
    report = metadata.read_metadata(fh)

    notes = report.explain("notes")
    assert len(notes.candidates) == 2
    assert [candidate.occurrence for candidate in notes.candidates] == [0, 1]
    assert [candidate.value for candidate in notes.candidates] == ["first note", "first note"]
    # A duplicated key inside one healthy header does not manufacture a conflict.
    assert notes.conflicting is False


def test_claimed_hash_is_never_marked_verified() -> None:
    report = metadata.read_metadata(_conflict_sample())

    assert len(report.hashes) == 1
    claimed = report.hashes[0]
    assert claimed.algorithm == "md5"
    assert claimed.digest == "9683f7575933eac7390416991cfc5b84"
    assert claimed.verified is False
    assert claimed.origin.section_type == "hash"
    assert "claimed, not verified" in metadata.render_report(report)


def test_encoding_differences_utf16_be_and_latin1_fallback() -> None:
    text = "3\nmain\nc\te\nCASE-BE\nzorro\n\n"
    utf16_be = b"\xfe\xff" + text.encode("utf-16-be")
    # A lone 0xe9 is not valid UTF-8 and forces the latin-1 fallback.
    latin1 = b"1\r\nmain\r\nc\te\r\ncaf\xe9\trenee\r\n"

    fh = _build_ewf(
        [
            _header_section("header2", utf16_be),
            _header_section("header", latin1),
        ]
    )
    report = metadata.read_metadata(fh)

    origins = {header.origin.encoding: header for header in report.healthy_headers}
    assert "utf-16-be" in origins
    be_candidate = report.explain("case_number").candidates[0]
    assert be_candidate.raw_value == "CASE-BE".encode("utf-16-be")

    fallback_header = next(header for header in report.healthy_headers if header.origin.encoding_fallback)
    assert fallback_header.origin.encoding == "latin-1"
    case = report.explain("case_number")
    latin1_candidate = next(candidate for candidate in case.candidates if candidate.origin.encoding == "latin-1")
    assert latin1_candidate.value == "caf\xe9"
    assert latin1_candidate.raw_value == b"caf\xe9"
    # Tie between the two encodings: header2 is preferred for display.
    assert case.conflicting is True
    assert case.selected.value == "CASE-BE"


def test_all_headers_corrupt_yields_empty_fields() -> None:
    fh = _build_ewf([_section("header", b"broken payload")])
    report = metadata.read_metadata(fh)

    assert report.fields == {}
    assert len(report.corrupt_headers) == 1
    assert report.brief() == {}


def test_read_headers_accepts_ewf_instance_and_handles() -> None:
    fh = _conflict_sample()
    from_handle = metadata.read_headers(fh)

    fh.seek(0)
    from_list = metadata.read_headers([fh])

    assert [header.origin.descriptor_offset for header in from_handle] == [
        header.origin.descriptor_offset for header in from_list
    ]


def test_read_headers_accepts_ewf_instance(ewf_single: BinaryIO) -> None:
    ewf_image = ewf.EWF(ewf_single)
    from_instance = metadata.read_headers(ewf_image)
    assert from_instance and all(header.healthy for header in from_instance)


def test_real_image_headers_and_rendered_report() -> None:
    path: Path = absolute_path("_data/ewf/single/image.E01")
    report = metadata.read_metadata(path)

    assert all(header.healthy for header in report.headers)
    assert report.explain("case_number").selected.value == "case_number"
    rendered = metadata.render_report(report)
    assert "[verbatim]" in rendered
    assert "[parser-inferred]" in rendered
    assert "timezone unknown" in rendered or "UTC" in rendered
    assert "claimed, not verified" in rendered


def test_segmented_image_collects_headers_across_segments() -> None:
    paths = [absolute_path(f"_data/ewf/segmented/image.E0{i}") for i in range(1, 6)]
    report = metadata.read_metadata(paths)

    assert report.headers
    assert all(header.origin.segment_index == 0 for header in report.headers)
    assert report.hashes[0].origin.segment_index == 4


def test_locked_adcrypt_container_is_reported_not_trusted() -> None:
    # A still-encrypted ADCRYPT segment cannot be enumerated; it must surface as a segment error
    # rather than crash or produce fabricated header values.
    report = metadata.read_metadata(absolute_path("_data/ewf/encrypted-passphrase/encrypted.E01"))

    assert report.headers == []
    assert report.hashes == []
    assert 0 in report.segment_errors
    assert "section enumeration failed" in report.segment_errors[0]
    assert "Unreadable segments" in metadata.render_report(report)


def test_render_report_lists_conflict_evidence() -> None:
    rendered = metadata.render_report(metadata.read_metadata(_conflict_sample()))

    assert "CASE-001" in rendered and "CASE-001-REV2" in rendered
    assert "Corrupt headers" in rendered
    assert "Conflicting claims" in rendered


def test_parse_time_variants() -> None:
    epoch = metadata.parse_time("1766585901")
    assert epoch.kind == "epoch_seconds"
    assert epoch.timezone_known is True

    naive = metadata.parse_time("2025 12 24 15 18 21")
    assert naive.kind == "space_separated"
    assert naive.timezone_known is False

    iso = metadata.parse_time("2025-12-24T15:18:21+02:00")
    assert iso.kind == "iso8601"
    assert iso.timezone_known is True

    unparsed = metadata.parse_time("not a date")
    assert unparsed.kind == "unparsed"
    assert unparsed.datetime is None
    assert unparsed.raw == "not a date"


@pytest.mark.parametrize("fixture_name", ["ewf_single"])
def test_fixture_loading(fixture_name: str, request: pytest.FixtureRequest) -> None:
    fh: BinaryIO = request.getfixturevalue(fixture_name)
    report = metadata.read_metadata(fh)
    assert report.healthy_headers
