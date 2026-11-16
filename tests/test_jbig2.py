"""Regression tests for JBIG2 segment headers and segment dependencies.

Exported JBIG2 files must be reconstructable by independent readers, so the
expected header bytes and reference relations are verified with a small
standalone parser (and hand-laid-out byte strings) instead of the pdfminer
reader/writer under test.
"""

import io

import pytest

from pdfminer.jbig2 import JBIG2StreamReader, JBIG2StreamWriter
from pdfminer.pdfexceptions import PDFValueError

# Segment types, as assigned by the JBIG2 spec (ITU T.88)
SEG_TYPE_SYMBOL_DICTIONARY = 0
SEG_TYPE_IMMEDIATE_GENERIC_REGION = 38
SEG_TYPE_PAGE_INFORMATION = 48
SEG_TYPE_END_OF_PAGE = 49
SEG_TYPE_END_OF_FILE = 51

JBIG2_FILE_HEADER_ID = b"\x97\x4a\x42\x32\x0d\x0a\x1a\x0a"


def make_segment(
    number,
    *,
    seg_type=SEG_TYPE_SYMBOL_DICTIONARY,
    page_assoc=0,
    refs=(),
    retain=None,
    raw_data=b"\x00",
):
    """Build a segment dict for the writer with consistent ref counts"""
    if retain is None:
        retain = [True] * (len(refs) + 1)
    return {
        "number": number,
        "flags": {
            "deferred": False,
            "page_assoc_long": page_assoc > 255,
            "type": seg_type,
        },
        "retention_flags": {
            "ref_count": len(refs),
            "retain_segments": list(retain),
            "ref_segments": list(refs),
        },
        "page_assoc": page_assoc,
        "data_length": len(raw_data),
        "raw_data": raw_data,
    }


def write_segments(segments, **kwargs):
    stream = io.BytesIO()
    JBIG2StreamWriter(stream).write_segments(segments, **kwargs)
    return stream.getvalue()


# --- Independent parser: written from the spec, shares no code with the ---
# --- reader/writer under test.                                         ---


def parse_segment_header(data, offset):
    """Parse one segment header and its data, spec ITU T.88 section 7.2"""
    start = offset
    number = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4

    flags = data[offset]
    offset += 1
    deferred = bool(flags & 0b10000000)
    page_assoc_long = bool(flags & 0b01000000)
    seg_type = flags & 0b00111111

    first_retention_byte = data[offset]
    offset += 1
    short_count = first_retention_byte >> 5
    if short_count < 0b111:
        ref_count = short_count
        retain = [bool(first_retention_byte & (1 << bit)) for bit in range(5)]
    else:
        count_dword = (first_retention_byte << 24) | int.from_bytes(
            data[offset : offset + 3],
            "big",
        )
        offset += 3
        ref_count = count_dword & 0x1FFFFFFF
        retention_byte_count = (ref_count + 1 + 7) // 8
        retain = []
        for _ in range(retention_byte_count):
            retain_byte = data[offset]
            offset += 1
            retain.extend(bool(retain_byte & (1 << bit)) for bit in range(8))

    if number <= 256:
        ref_width = 1
    elif number <= 65536:
        ref_width = 2
    else:
        ref_width = 4
    ref_bytes = data[offset : offset + ref_width * ref_count]
    refs = []
    for ref_index in range(ref_count):
        ref_start = offset + ref_index * ref_width
        refs.append(int.from_bytes(data[ref_start : ref_start + ref_width], "big"))
    offset += ref_width * ref_count

    if page_assoc_long:
        page_assoc = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
    else:
        page_assoc = data[offset]
        offset += 1

    data_length = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    raw_data = data[offset : offset + data_length]
    offset += data_length

    segment = {
        "number": number,
        "deferred": deferred,
        "page_assoc_long": page_assoc_long,
        "type": seg_type,
        "ref_count": ref_count,
        "retain_segments": retain,
        "ref_segments": refs,
        "ref_width": ref_width,
        "ref_bytes": ref_bytes,
        "page_assoc": page_assoc,
        "data_length": data_length,
        "raw_data": raw_data,
        "header_offset": start,
    }
    return segment, offset


def parse_segments(data, offset=0):
    segments = []
    while offset < len(data):
        segment, offset = parse_segment_header(data, offset)
        segments.append(segment)
    return segments


def parse_file(data):
    """Parse a standalone JBIG2 file including the 13-byte file header"""
    assert data[:8] == JBIG2_FILE_HEADER_ID
    organisation = data[8]
    offset = 9
    number_of_pages = None
    if not organisation & 0b00000010:
        number_of_pages = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
    segments = parse_segments(data, offset)
    return {
        "sequential": bool(organisation & 0b00000001),
        "number_of_pages": number_of_pages,
        "segments": segments,
    }


# --- Reference width at the 256/65536 segment number boundaries ---


@pytest.mark.parametrize(
    ("number", "expected_width"),
    [(256, 1), (257, 2), (65536, 2), (65537, 4)],
)
def test_referred_segment_number_width_boundaries(number, expected_width):
    """Referred segment numbers widen at segment 257 and 65537"""
    target = make_segment(1)
    segment = make_segment(
        number,
        seg_type=SEG_TYPE_IMMEDIATE_GENERIC_REGION,
        page_assoc=1,
        refs=(1,),
    )
    data = write_segments([target, segment], fix_last_page=False)

    parsed = parse_segments(data)
    assert len(parsed) == 2
    assert parsed[1]["number"] == number
    assert parsed[1]["ref_width"] == expected_width
    assert parsed[1]["ref_segments"] == [1]
    assert parsed[1]["ref_bytes"] == (1).to_bytes(expected_width, "big")


def test_segment_header_bytes_hand_laid():
    """Byte-exact header layout for a 1-byte and a 2-byte reference"""
    segments = [
        make_segment(1),
        make_segment(
            257,
            seg_type=SEG_TYPE_IMMEDIATE_GENERIC_REGION,
            page_assoc=1,
            refs=(1,),
            retain=[True, False],
            raw_data=b"\xab",
        ),
    ]
    data = write_segments(segments, fix_last_page=False)

    expected = bytes.fromhex(
        # segment 1: no references, global, 1 byte of data
        "00000001"
        "00"
        "01"
        "00"
        "00000001"
        "00"
        # segment 257: type 38, ref count 1, 2-byte reference to segment 1
        "00000101"
        "26"
        "21"
        "0001"
        "01"
        "00000001"
        "ab",
    )
    assert data == expected

    # the pdfminer reader must decode the hand-laid bytes identically,
    # pinning its referred-segment-number width against the spec layout
    read_back = JBIG2StreamReader(io.BytesIO(expected)).get_segments()
    assert [segment["number"] for segment in read_back] == [1, 257]
    assert read_back[1]["retention_flags"]["ref_segments"] == [1]
    assert read_back[1]["retention_flags"]["retain_segments"][:2] == [True, False]
    assert read_back[1]["raw_data"] == b"\xab"


# --- Retention flags beyond the short count range ---


def make_long_form_segments(retain):
    refs = tuple(range(1, 9))
    segments = [make_segment(number) for number in refs]
    segments.append(make_segment(9, refs=refs, retain=retain))
    return segments


def test_long_form_retention_flags_layout():
    """ref_count 8 needs the long form: 4-byte count plus retention bytes"""
    retain = [False] * 7 + [True, False]
    data = write_segments(make_long_form_segments(retain), fix_last_page=False)

    parsed = parse_segments(data)
    segment = parsed[8]
    assert segment["number"] == 9
    assert segment["ref_count"] == 8
    assert segment["ref_segments"] == list(range(1, 9))
    assert segment["retain_segments"][:9] == retain

    header = data[segment["header_offset"] :]
    expected_header = bytes.fromhex(
        # segment 9, type 0
        "00000009"
        "00"
        # long form marker 0b111, referred-to count 8
        "e0000008"
        # retention bits: only the eighth bit of the first byte set
        "8000"
        # eight 1-byte references to segments 1..8
        "0102030405060708"
        # global segment, 1 byte of data
        "00"
        "00000001"
        "00",
    )
    assert header == expected_header

    # the pdfminer reader must decode its own export identically
    read_back = JBIG2StreamReader(io.BytesIO(data)).get_segments()
    assert read_back[8]["retention_flags"]["ref_count"] == 8
    assert read_back[8]["retention_flags"]["retain_segments"][:9] == retain
    assert read_back[8]["retention_flags"]["ref_segments"] == list(range(1, 9))


def test_eighth_retention_bit_counterexample():
    """Counterexample: streams differ only in the eighth retention bit.

    The difference must be attributed to exactly that bit of exactly that
    segment, proving the tests can locate a single-bit header corruption.
    """
    retain_set = [False] * 7 + [True, False]
    retain_unset = [False] * 9
    data_set = write_segments(make_long_form_segments(retain_set), fix_last_page=False)
    data_unset = write_segments(
        make_long_form_segments(retain_unset),
        fix_last_page=False,
    )

    differing_offsets = [
        offset
        for offset, (byte_set, byte_unset) in enumerate(
            zip(data_set, data_unset, strict=True),
        )
        if byte_set != byte_unset
    ]
    assert len(differing_offsets) == 1

    parsed_set = parse_segments(data_set)
    parsed_unset = parse_segments(data_unset)
    for segment_set, segment_unset in zip(parsed_set, parsed_unset, strict=True):
        if segment_set["number"] == 9:
            assert segment_set["retain_segments"][7] is True
            assert segment_unset["retain_segments"][7] is False
            assert segment_set["header_offset"] < differing_offsets[0]
        else:
            assert segment_set == segment_unset

    read_set = JBIG2StreamReader(io.BytesIO(data_set)).get_segments()
    read_unset = JBIG2StreamReader(io.BytesIO(data_unset)).get_segments()
    assert read_set[8]["retention_flags"]["retain_segments"][7] is True
    assert read_unset[8]["retention_flags"]["retain_segments"][7] is False


# --- Export mixing global and page segments ---


def test_global_and_page_segments_export():
    """Global segments and page segments must both survive a file export"""
    segments = [
        make_segment(0, raw_data=b"\x01\x02"),
        make_segment(1, seg_type=SEG_TYPE_PAGE_INFORMATION, page_assoc=1),
        make_segment(
            2,
            seg_type=SEG_TYPE_IMMEDIATE_GENERIC_REGION,
            page_assoc=1,
            refs=(0,),
            raw_data=b"\x03\x04",
        ),
    ]
    stream = io.BytesIO()
    JBIG2StreamWriter(stream).write_file(segments)

    parsed = parse_file(stream.getvalue())
    assert parsed["sequential"] is True
    assert parsed["number_of_pages"] == 1

    exported = parsed["segments"]
    assert [segment["number"] for segment in exported] == [0, 1, 2, 3, 4]
    assert [segment["type"] for segment in exported] == [
        SEG_TYPE_SYMBOL_DICTIONARY,
        SEG_TYPE_PAGE_INFORMATION,
        SEG_TYPE_IMMEDIATE_GENERIC_REGION,
        SEG_TYPE_END_OF_PAGE,
        SEG_TYPE_END_OF_FILE,
    ]
    assert [segment["page_assoc"] for segment in exported] == [0, 1, 1, 1, 0]

    global_segment = exported[0]
    page_segment = exported[2]
    assert global_segment["page_assoc"] == 0
    assert page_segment["ref_segments"] == [global_segment["number"]]
    assert page_segment["raw_data"] == b"\x03\x04"

    # the export must also round-trip through the pdfminer reader
    read_back = JBIG2StreamReader(io.BytesIO(stream.getvalue()[13:])).get_segments()
    assert [segment["number"] for segment in read_back] == [0, 1, 2, 3, 4]
    assert read_back[2]["retention_flags"]["ref_segments"] == [0]
    assert read_back[2]["raw_data"] == b"\x03\x04"


# --- Diagnostics for broken headers and dependencies ---


def test_truncated_reference_table_raises():
    """A segment announcing two references but carrying one must not pass"""
    data = bytes.fromhex(
        # segment 7, type 0, ref count 2, then only a single 1-byte reference
        "00000007" "00" "40" "01",
    )
    with pytest.raises(PDFValueError, match="segment 7"):
        JBIG2StreamReader(io.BytesIO(data)).get_segments()


def test_truncated_segment_header_raises():
    data = bytes.fromhex("00000007" "00")
    with pytest.raises(PDFValueError, match="segment 7"):
        JBIG2StreamReader(io.BytesIO(data)).get_segments()


def test_wrong_reference_width_counterexample():
    """Counterexample: segment 300 needs 2-byte references, one was written.

    The desynchronised stream must be reported against segment 300 instead
    of being silently dropped.
    """
    data = bytes.fromhex(
        # valid segment 1
        "00000001"
        "00"
        "01"
        "00"
        "00000001"
        "00"
        # segment 300 with an illegally narrow 1-byte reference field
        "0000012c"
        "00"
        "21"
        "01"
        "01"
        "00000001"
        "00",
    )
    with pytest.raises(PDFValueError, match="segment 300"):
        JBIG2StreamReader(io.BytesIO(data)).get_segments()


def test_duplicate_segment_numbers_raise():
    segment = bytes.fromhex("00000003" "00" "01" "00" "00000001" "00")
    with pytest.raises(PDFValueError, match="Duplicate.*3"):
        JBIG2StreamReader(io.BytesIO(segment * 2)).get_segments()

    with pytest.raises(PDFValueError, match="Duplicate.*3"):
        write_segments([make_segment(3), make_segment(3)], fix_last_page=False)


def test_missing_dependency_raises():
    """A dangling reference must abort the export, not drop the segment"""
    segments = [make_segment(2, refs=(99,))]
    with pytest.raises(PDFValueError, match="segment 2 refers to missing segment 99"):
        write_segments(segments, fix_last_page=False)


def test_valid_dependencies_pass():
    segments = [
        make_segment(0),
        make_segment(1, page_assoc=1, refs=(0,)),
    ]
    data = write_segments(segments, fix_last_page=False)
    parsed = parse_segments(data)
    assert parsed[1]["ref_segments"] == [0]
