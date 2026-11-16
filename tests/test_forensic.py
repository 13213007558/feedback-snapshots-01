#!/usr/bin/env python3

"""Forensic character-mapping tests.

The hand-built PDF deliberately exercises the cases a forensic report must
distinguish:

* two simple fonts that map the *same* operand bytes to different text,
* a ToUnicode multi-code-point mapping (one glyph -> several code points),
* an encoding-based ligature (one compatibility code point),
* a CID font with two-byte code spaces and an unmapped glyph, and
* text shown through both ``Tj`` and the multi-operand ``TJ`` operator.
"""

from io import BytesIO

import pytest

from pdfminer.converter import ForensicLayoutAnalyzer
from pdfminer.forensic import (
    SOURCE_ENCODING,
    SOURCE_NONE,
    SOURCE_TOUNICODE,
    STATUS_LIGATURE,
    STATUS_MISSING,
    STATUS_MULTICODEPOINT,
    STATUS_REPLACEMENT,
    STATUS_SINGLE,
    CharMappingRecord,
    ForensicTrace,
    GlyphMapping,
    cid_placeholder,
    is_ligature_text,
)
from pdfminer.high_level import extract_char_mappings, extract_text
from pdfminer.layout import LAParams
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage


def _stream_object(payload: bytes) -> bytes:
    # /Length counts only the payload; the single LF between the payload and
    # "endstream" is excluded so parser stream positioning stays exact.
    head = b"<< /Length " + str(len(payload)).encode() + b" >>\nstream\n"
    return head + payload + b"\nendstream"


TOUNICODE_F1 = b"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
1 begincodespacerange
<00> <FF>
endcodespacerange
2 beginbfchar
<2A> <00660069>
<2B> <0042>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end"""

TOUNICODE_F3 = b"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
2 beginbfchar
<0041> <0058>
<0042> <0059005A>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end"""

# Byte 0x2A is shown under both F1 and F2 but resolves to different text.
CONTENT = (
    b"BT\n"
    b"/F1 12 Tf\n"
    b"50 760 Td\n"
    b"<2A2B2C2D2E> Tj\n"
    b"1 0 0 1 0 -20 Tm\n"
    b"[<2A> 250 <2B>] TJ\n"
    b"/F2 12 Tf\n"
    b"1 0 0 1 0 -40 Tm\n"
    b"<2A2B2C2E> Tj\n"
    b"/F3 12 Tf\n"
    b"1 0 0 1 0 -60 Tm\n"
    b"<004100420099> Tj\n"
    b"ET\n"
)


def build_forensic_pdf() -> bytes:
    objects: dict[int, bytes] = {}

    def add(num: int, body: bytes) -> None:
        objects[num] = body

    add(
        5,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding "
        b"/Differences [42 /fi 43 /X 46 /Z ] >> "
        b"/ToUnicode 6 0 R >>",
    )
    add(6, _stream_object(TOUNICODE_F1))
    add(
        7,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding "
        b"/Differences [42 /fi 43 /X 46 /Z ] >> >>",
    )
    add(
        8,
        b"<< /Type /Font /Subtype /Type0 /BaseFont /F3 "
        b"/Encoding /Identity-H /ToUnicode 9 0 R "
        b"/DescendantFonts [10 0 R] >>",
    )
    add(9, _stream_object(TOUNICODE_F3))
    add(
        10,
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /F3 "
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) "
        b"/Supplement 0 >> /FontDescriptor 11 0 R /DW 1000 >>",
    )
    add(
        11,
        b"<< /Type /FontDescriptor /FontName /F3 /Flags 4 "
        b"/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 "
        b"/CapHeight 700 /StemV 80 >>",
    )
    add(4, _stream_object(CONTENT))
    add(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R /F2 7 0 R /F3 8 0 R >> >> "
        b"/Contents 4 0 R >>",
    )
    add(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {0: 0}
    for num in range(1, 12):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 12\n"
    out += b"0000000000 65535 f \n"
    for num in range(1, 12):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += (
        b"trailer\n<< /Size 12 /Root 1 0 R >>\nstartxref\n"
        + str(xref_pos).encode()
        + b"\n%%EOF\n"
    )
    return bytes(out)


@pytest.fixture(scope="module")
def trace() -> ForensicTrace:
    return extract_char_mappings(BytesIO(build_forensic_pdf()))


def test_pdf_text_extraction_still_works() -> None:
    # The replacement placeholder must remain visible in normal extraction.
    text = extract_text(BytesIO(build_forensic_pdf()))
    assert "(cid:153)" in text


def test_one_record_per_decoded_glyph(trace: ForensicTrace) -> None:
    # 5 (Tj F1) + 2 (TJ F1) + 4 (Tj F2) + 3 (Tj F3) = 14 glyphs.
    assert len(trace) == 14
    assert all(isinstance(record, CharMappingRecord) for record in trace)


def test_same_bytes_map_to_different_text_across_fonts(
    trace: ForensicTrace,
) -> None:
    f1 = trace.for_operand("obj-5", 0)[0]
    f2 = trace.for_operand("obj-7", 0)[0]
    # The exact same operand byte 0x2A ...
    assert f1.raw_bytes == f2.raw_bytes == b"\x2a"
    # ... resolves through different sources to different text.
    assert f1.source == SOURCE_TOUNICODE
    assert f1.text == "fi"
    assert f2.source == SOURCE_ENCODING
    assert f2.text == "ﬁ"
    # The fonts are distinguished by stable object ids, not names.
    assert f1.font_id != f2.font_id


def test_multicodepoint_mapping_records_every_codepoint(
    trace: ForensicTrace,
) -> None:
    record = trace.for_operand("obj-5", 0)[0]
    assert record.status == STATUS_MULTICODEPOINT
    assert record.is_multicodepoint
    assert record.codepoints == (0x66, 0x69)
    assert record.codepoint_hex() == ["U+0066", "U+0069"]


def test_ligature_is_distinct_from_multicodepoint(
    trace: ForensicTrace,
) -> None:
    record = trace.for_operand("obj-7", 0)[0]
    assert record.status == STATUS_LIGATURE
    assert record.is_ligature
    # A named ligature is one compatibility code point that NFKC expands.
    assert record.codepoints == (0xFB01,)
    assert is_ligature_text(record.text)


def test_missing_mapping_and_replacement_are_separate(
    trace: ForensicTrace,
) -> None:
    missing = trace.for_operand("obj-8", 0)[-1]
    assert missing.raw_bytes == b"\x00\x99"
    assert missing.cid == 153
    assert missing.source == SOURCE_NONE
    assert missing.status == STATUS_REPLACEMENT
    assert missing.is_replacement
    assert missing.text == cid_placeholder(153)
    # The placeholder must never be presented as original document text in
    # the search-oriented normalization.
    assert "(cid:153)" not in trace.search_text
    assert missing.text in trace.document_text


def test_multibyte_byte_ranges(trace: ForensicTrace) -> None:
    cid_records = trace.for_operand("obj-8", 0)
    assert [record.byte_range for record in cid_records] == [
        (0, 2),
        (2, 4),
        (4, 6),
    ]
    assert [record.raw_bytes.hex() for record in cid_records] == [
        "0041",
        "0042",
        "0099",
    ]
    # The second CID glyph expands to two code points.
    assert cid_records[1].status == STATUS_MULTICODEPOINT
    assert cid_records[1].text == "YZ"


def test_operand_index_distinguishes_tj_operands(trace: ForensicTrace) -> None:
    tj_records = [r for r in trace if r.operator == "TJ"]
    # [<2A> 250 <2B>] contributes two byte-string operands.
    assert [r.operand_index for r in tj_records] == [0, 1]
    assert [r.byte_range for r in tj_records] == [(0, 1), (0, 1)]


def test_raw_bytes_are_preserved_verbatim(trace: ForensicTrace) -> None:
    for record in trace:
        assert record.raw_bytes
        assert record.byte_length == len(record.raw_bytes)
        start, end = record.byte_range
        assert end > start


def test_search_text_normalizes_ligature(trace: ForensicTrace) -> None:
    # The U+FB01 ligature is decomposed for search, while the genuine
    # multi-code-point mapping stays as plain characters.
    assert "ﬁ" not in trace.search_text
    assert "fi" in trace.search_text
    # No replacement placeholder leaks into searchable text.
    assert "(cid:" not in trace.search_text


def test_records_locate_operand_without_font_names(
    trace: ForensicTrace,
) -> None:
    # Locate purely by font object id, operand index and byte range.
    located = trace.for_operand("obj-8", 0, byte_range=(2, 4))
    assert len(located) == 1
    assert located[0].raw_bytes == b"\x00\x42"
    assert located[0].cid == 66


def test_forensic_analyzer_tracks_page_number() -> None:
    rsrcmgr = PDFResourceManager()
    device = ForensicLayoutAnalyzer(rsrcmgr, laparams=LAParams())
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    with BytesIO(build_forensic_pdf()) as fp:
        for page in PDFPage.get_pages(fp):
            interpreter.process_page(page)
    page_trace = device.get_trace()
    assert {record.page for record in page_trace} == {0}


def test_glyph_mapping_helpers() -> None:
    single = GlyphMapping(
        cid=1, text="B", source=SOURCE_TOUNICODE,
        status=STATUS_SINGLE, codepoints=(0x42,),
    )
    assert not single.is_missing and not single.is_replacement
    missing = GlyphMapping(
        cid=9, text="", source=SOURCE_NONE, status=STATUS_MISSING,
    )
    assert missing.is_missing and not missing.is_replacement
    assert missing.codepoints == ()


def test_decode_spans_track_multibyte_ranges() -> None:
    from pdfminer.cmapdb import FileCMap, IdentityCMap

    trie = FileCMap()
    trie.add_code2cid("AB", 99)
    # Two-byte code space matched as one span; unmatched byte kept visible.
    assert list(trie.decode_spans(b"AB\x43")) == [
        (0, 2, 99),
        (2, 1, None),
    ]
    # Identity CMap consumes two bytes per CID and flags odd trailing bytes.
    assert list(IdentityCMap().decode_spans(b"\x00\x41\x2c")) == [
        (0, 2, 65),
        (2, 1, None),
    ]


def test_ligature_detection_helper() -> None:
    assert is_ligature_text("ﬁ")  # U+FB01 decomposes to "fi" under NFKC
    assert not is_ligature_text("f")
    assert not is_ligature_text("fi")
