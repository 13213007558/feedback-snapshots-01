from __future__ import annotations

import hashlib
import json
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.ewf import EWF, EWFMetadata
from dissect.evidence.ewf.metadata import (
    HEADER_KIND_PRIORITY,
    SELECTION_STRATEGY,
    _decode_header,
    _decode_unmarked_utf16,
    parse_time,
)
from tests._tools.ewf.builder import (
    HeaderSpec,
    build_image,
    build_metadata_conflict_image,
    build_segmented_image,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def _open(data: bytes) -> EWF:
    return EWF(BytesIO(data))


def _simple_header(case: str = "CASE-1", time: str = "2026-02-03 04:05:06") -> str:
    return "\n".join(
        [
            "3",
            "main",
            "a\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc",
            f"Description\t{case}\tE-1\tAlice Example\t\t\t\tAcqTool 1.2\tLinux\t{time}\t{time}\t0\t",
            "",
        ]
    )


@pytest.fixture
def conflict_image() -> EWF:
    return _open(build_metadata_conflict_image().data)


def test_existing_image_metadata(ewf_single: BytesIO) -> None:
    metadata = EWF(ewf_single).metadata

    assert isinstance(metadata, EWFMetadata)
    assert metadata["case_number"].value == "case_number"
    assert metadata["examiner_name"].value == "examiner_name"
    assert metadata["acquisition_time"].value == "1766585901"
    assert metadata["acquisition_time"].conflict
    assert len(metadata.headers) == 3


def test_metadata_is_cached_and_requires_unlock(ewf_encrypted_passphrase: BytesIO) -> None:
    e = EWF(ewf_encrypted_passphrase)

    assert e.is_locked()
    with pytest.raises(ValueError, match="locked by ADCRYPT"):
        _ = e.metadata

    e.unlock(passphrase="password")
    # This image declares only blank case and examiner fields
    assert e.metadata["case_number"].status == "missing"
    assert e.metadata["description"].value == "untitled"
    assert e.metadata is e.metadata


def test_conflict_sample_brief_and_details(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    brief = metadata.brief()

    assert brief == {
        "case_number": "CASE-2026-001",
        "evidence_number": "E-1",
        "description": "Primary description",
        "examiner_name": "Alice Example",
        "acquisition_time": "2026-02-03 04:05:06",
    }

    details = metadata.details()
    case = details["fields"]["case_number"]

    assert case["status"] == "conflict"
    assert case["value"] == "CASE-2026-001"
    assert case["value_origin"] == "header declaration"
    assert case["verbatim"] is True
    assert case["conflict"] is True

    values = [candidate["value"] for candidate in case["candidates"]]
    assert values == ["CASE-2026-CORRUPT", "CASE-2026-001", "CASE-2026-777", "CASE-2026-999"]

    selected = [candidate for candidate in case["candidates"] if candidate["selected"]]
    assert len(selected) == 1
    assert selected[0]["value"] == "CASE-2026-001"
    assert selected[0]["source"]["kind"] == "header2"
    assert selected[0]["source"]["section_offset"] == 258


def test_conflict_candidates_keep_provenance(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    case = metadata["case_number"]

    for candidate in case.candidates:
        field = candidate.field
        source = field.source

        assert field.payload_offset is not None
        assert field.payload_size is not None
        assert field.raw_value is not None
        assert field.raw_value == candidate.field.value.encode(source.encoding)

        # The recorded offset points at the same bytes inside the decompressed header payload
        payload = next(header.payload for header in metadata.headers if header.source is source)
        assert payload[field.payload_offset : field.payload_offset + field.payload_size] == field.raw_value

        assert source.segment_index == 0
        assert source.section_offset >= 0
        assert source.kind in ("header", "header2")


def test_corrupt_header_never_overrides_healthy_header(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    corrupt = metadata.headers[0]

    assert corrupt.source.kind == "header2"
    assert corrupt.source.section_offset == 13
    assert not corrupt.source.usable
    assert corrupt.source.descriptor_checksum_valid is False
    assert "section descriptor checksum mismatch" in corrupt.source.problems

    # The corrupt header is earlier, but cannot win: a healthy header2 is selected instead
    assert metadata["case_number"].value != "CASE-2026-CORRUPT"
    assert metadata["examiner_name"].value != "Mallory Example"
    assert metadata["acquisition_time"].value != "2026-02-03 00:00:00"

    corrupt_candidate = metadata["case_number"].candidates[0]
    assert corrupt_candidate.selected is False
    assert corrupt_candidate.rejected_reason == "source header failed integrity or structure checks"


def test_corrupt_zlib_payload_is_unusable() -> None:
    image = build_image([HeaderSpec("header2", _simple_header()), HeaderSpec("header2", _simple_header())]).data
    # Break the first header payload so zlib cannot decompress it
    broken = bytearray(image)
    broken[0x0D + 0x4C + 10 : 0x0D + 0x4C + 20] = b"\x00" * 10

    e = _open(bytes(broken))
    metadata = e.metadata

    assert not metadata.headers[0].source.usable
    assert any("zlib" in problem for problem in metadata.headers[0].source.problems)
    assert metadata["case_number"].value == "CASE-1"


def test_empty_healthy_header_beats_non_empty_corrupt_header() -> None:
    empty = "3\nmain\nc\tn\te\n\tE-1\t\n"
    data = build_image(
        [
            HeaderSpec("header2", _simple_header(case="CASE-CORRUPT"), corrupt_descriptor_checksum=True),
            HeaderSpec("header2", empty),
        ]
    ).data
    metadata = _open(data).metadata

    # The damaged header cannot donate its value, and the healthy empty declaration is not
    # promoted to a value either: the field is reported missing, without inventing text.
    assert metadata["case_number"].status == "missing"
    assert metadata["case_number"].value is None

    reasons = {candidate.field.value: candidate.rejected_reason for candidate in metadata["case_number"].candidates}
    assert reasons["CASE-CORRUPT"] == "source header failed integrity or structure checks"
    assert reasons[""] == "empty declaration; no usable non-empty declaration exists"


def test_single_header_kind_priority() -> None:
    data = build_image(
        [
            HeaderSpec("header", _simple_header(case="CASE-LEGACY")),
            HeaderSpec("header2", _simple_header(case="CASE-NEW")),
        ]
    ).data
    metadata = _open(data).metadata

    assert HEADER_KIND_PRIORITY["header2"] > HEADER_KIND_PRIORITY["header"]
    assert metadata["case_number"].value == "CASE-NEW"
    assert metadata["case_number"].status == "conflict"
    assert [candidate.field.value for candidate in metadata["case_number"].candidates] == [
        "CASE-LEGACY",
        "CASE-NEW",
    ]


def test_earliest_segment_wins() -> None:
    segments = build_segmented_image(
        [HeaderSpec("header2", _simple_header(case="CASE-SEGMENT-1"))],
        [HeaderSpec("header2", _simple_header(case="CASE-SEGMENT-2"))],
    )
    metadata = EWF([BytesIO(segment) for segment in segments]).metadata

    assert [header.source.segment_index for header in metadata.headers] == [0, 1]
    assert metadata["case_number"].value == "CASE-SEGMENT-1"
    assert metadata["case_number"].status == "conflict"

    candidates = metadata["case_number"].candidates
    assert [(candidate.field.value, candidate.field.source.segment_index) for candidate in candidates] == [
        ("CASE-SEGMENT-1", 0),
        ("CASE-SEGMENT-2", 1),
    ]


def test_duplicate_keys_are_all_retained() -> None:
    text = "3\nmain\nc\tn\tc\nCASE-FIRST\tE-1\tCASE-SECOND\n"
    metadata = _open(build_image([HeaderSpec("header2", text)]).data).metadata

    case = metadata["case_number"]
    assert case.value == "CASE-FIRST"
    assert case.status == "conflict"
    assert [candidate.field.value for candidate in case.candidates] == ["CASE-FIRST", "CASE-SECOND"]
    assert "duplicate key 'c' at column 2" in metadata.headers[0].issues


def test_missing_fields_are_reported_not_invented() -> None:
    text = "2\nmain\nc\te\nCASE-1\n"
    metadata = _open(build_image([HeaderSpec("header", text)]).data).metadata

    assert metadata["examiner_name"].status == "missing"
    assert metadata["examiner_name"].value is None
    assert "missing value for key 'e' at column 1" in metadata.headers[0].issues

    candidate = metadata["examiner_name"].candidates[0]
    assert candidate.field.missing is True
    assert candidate.as_dict()["missing_value_cell"] is True
    assert candidate.field.raw_value is None


def test_missing_key_row_is_not_usable() -> None:
    text = "3\nmain\n\nDescription\n"
    metadata = _open(build_image([HeaderSpec("header2", text), HeaderSpec("header2", _simple_header())]).data).metadata

    assert not metadata.headers[0].source.usable
    assert "no main metadata block with key and value rows" in metadata.headers[0].source.problems
    assert metadata["case_number"].value == "CASE-1"


def test_empty_declaration_does_not_beat_non_empty() -> None:
    empty = "3\nmain\nc\tn\te\n\tE-1\t\n"
    data = build_image([HeaderSpec("header2", empty), HeaderSpec("header2", _simple_header(case="CASE-REAL"))]).data
    metadata = _open(data).metadata

    assert metadata["case_number"].value == "CASE-REAL"
    assert metadata["case_number"].status == "consistent"

    reasons = [candidate.rejected_reason for candidate in metadata["case_number"].candidates if not candidate.selected]
    assert reasons == ["empty declaration; a non-empty declaration exists"]


def test_time_without_timezone_is_explicit() -> None:
    metadata = _open(build_metadata_conflict_image().data).metadata
    resolution = metadata["acquisition_time"]

    assert resolution.value == "2026-02-03 04:05:06"
    assert resolution.parsed is not None
    assert resolution.parsed.timezone_known is False
    assert resolution.parsed.timezone is None
    assert resolution.parsed.inferred is True
    assert resolution.parsed.as_dict()["parser_inferred"] is True
    assert resolution.parsed.as_dict()["raw"] == "2026-02-03 04:05:06"

    summary = metadata.summary()["fields"]["acquisition_time"]
    assert summary["parsed"]["timezone_known"] is False
    assert summary["parsed"]["parser_inferred"] is True


def test_time_with_timezone_and_epoch() -> None:
    zoned = parse_time("2026-02-03T04:05:06+02:00")
    assert zoned.timezone_known is True
    assert zoned.datetime is not None
    assert zoned.datetime.utcoffset() is not None
    assert zoned.inferred is True

    epoch = parse_time("1766585901")
    assert epoch.timezone_known is True
    assert epoch.datetime is not None
    assert epoch.datetime.isoformat() == "2025-12-24T14:18:21+00:00"
    assert epoch.inferred is True


def test_declared_digest_is_not_verified(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    assert len(metadata.digests) == 1

    digest = metadata.digests[0]
    assert digest.algorithm == "md5"
    assert digest.value == hashlib.md5(conflict_image.open().read()).hexdigest()
    assert digest.verified is False
    assert digest.verification_status == "not_verified"
    assert digest.section_checksum_valid is True

    payload = digest.as_dict()
    assert payload["verified"] is False
    assert payload["verification_status"] == "not_verified"
    assert payload["source"]["raw_value"] == digest.value

    # Even a correct declaration remains a declaration, never a completed verification
    assert payload["value"] == hashlib.md5(conflict_image.open().read()).hexdigest()
    assert payload["verified"] is False


def test_summary_and_details_mark_derived_values(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    summary = metadata.summary()
    details = metadata.details()

    assert summary["selection_strategy"] == list(SELECTION_STRATEGY)
    assert details["selection_strategy"] == list(SELECTION_STRATEGY)
    assert summary["image"]["parser_inferred"] is True
    assert "candidates" not in summary["fields"]["case_number"]
    assert "candidates" in details["fields"]["case_number"]

    # Everything in the summary is JSON serialisable so a receiving page can render it as-is
    json.dumps(summary)
    json.dumps(details)


def test_metadata_survives_broken_section_link() -> None:
    built = build_image([HeaderSpec("header2", _simple_header()), HeaderSpec("header2", _simple_header(case="CASE-2"))])

    stream = BytesIO(built.data)
    e = EWF(stream)

    # Break the next pointer of the first header after the container was opened. The metadata
    # scan must recover the following header from the section sizes instead of stopping.
    first = built.header_offsets[0]
    stream.seek(first + 16)
    stream.write((0xDEADBEEF).to_bytes(8, "little"))

    # The metadata scan recovers the following header from the section sizes instead of
    # stopping, but the broken header itself is untrustworthy and cannot be selected.
    metadata = e.metadata
    assert len(metadata.headers) == 2
    assert metadata.errors
    assert metadata["case_number"].value == "CASE-2"


def test_unmarked_utf16_decoding() -> None:
    text = "3\nmain\nc\nCASE-1\n"
    assert _decode_unmarked_utf16(text.encode("utf-16-le")) == (text, "utf-16-le", True)
    assert _decode_unmarked_utf16(text.encode("utf-16-be")) == (text, "utf-16-be", True)
    assert _decode_unmarked_utf16(text.encode("utf-8")) is None

    decoded, encoding, inferred = _decode_header(text.encode("utf-16-le"))
    assert decoded == text
    assert encoding == "utf-16-le"
    assert inferred is True


def test_marked_utf16_is_not_inferred() -> None:
    text = "3\nmain\nc\nCASE-1\n"
    assert _decode_header(b"\xff\xfe" + text.encode("utf-16-le")) == (text, "utf-16-le", False)
    assert _decode_header(b"\xfe\xff" + text.encode("utf-16-be")) == (text, "utf-16-be", False)


def test_encoding_differences_are_preserved(conflict_image: EWF) -> None:
    metadata = conflict_image.metadata
    kinds = {header.source.kind: header.source for header in metadata.headers}

    assert kinds["header2"].encoding == "utf-16-le"
    assert kinds["header2"].encoding_inferred is False
    assert kinds["header"].encoding == "cp1252"
    assert kinds["header"].encoding_inferred is True

    legacy = metadata["examiner_name"].candidates[-1]
    assert legacy.field.value == "José Example"
    assert legacy.field.source.encoding == "cp1252"


def test_loaded_sample_file_is_stable() -> None:
    sample: Path = absolute_path("_data/ewf/metadata-conflicts/image.E01")
    metadata = EWF(sample).metadata

    assert metadata["case_number"].value == "CASE-2026-001"
    assert metadata["case_number"].status == "conflict"
    assert metadata["acquisition_time"].parsed is not None
    assert metadata["acquisition_time"].parsed.timezone_known is False
    assert len(metadata.conflicts()) >= 3
