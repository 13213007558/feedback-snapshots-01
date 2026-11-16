"""Regression tests for inline image (BI/ID/EI) boundary detection.

An inline image's data may legitimately contain the bytes ``EI`` (and even
``EI`` followed by whitespace), so the end of the image cannot be located by
simply taking the first or last ``EI`` match.  These tests build tiny PDFs in
memory and assert that only the real page text is ever exposed as content
operators, regardless of the read buffer size used by the tokenizer.
"""

import base64
import logging
import zlib
from io import BytesIO

import pytest

from pdfminer.high_level import extract_text
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import InlineImageData, PDFContentParser
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfpage import PDFPage
from pdfminer.pdftypes import PDFStream
from pdfminer.psparser import LIT, PSBaseParser, PSLiteral


def _build_pdf(content: bytes) -> bytes:
    """Build a minimal single-page PDF whose content stream is ``content``."""
    out = BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def write_obj(num: int, body: bytes) -> None:
        offsets[num] = out.tell()
        out.write(f"{num} 0 obj\n".encode() + body + b"\nendobj\n")

    write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    write_obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    write_obj(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    )
    write_obj(4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    write_obj(
        5,
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    )
    xref_pos = out.tell()
    out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for num in range(1, 6):
        out.write(f"{offsets[num]:010d} 00000 n \n".encode())
    out.write(
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % xref_pos
    )
    return out.getvalue()


def _tokens(pdf: bytes) -> list[object]:
    doc = PDFDocument(PDFParser(BytesIO(pdf)))
    page = next(PDFPage.create_pages(doc))
    parser = PDFContentParser(page.contents)
    result: list[object] = []
    while True:
        try:
            _, obj = parser.nextobject()
        except Exception:
            break
        result.append(obj)
    return result


def _inline_streams(pdf: bytes) -> list[PDFStream]:
    return [obj for obj in _tokens(pdf) if isinstance(obj, PDFStream)]


# A 1x1 RGB image occupies exactly three bytes.  Choosing "EI " makes the
# image data itself contain an EI operator followed by whitespace, which the
# naive first-match scanner mistakes for the end of the image.
UNFILTERED_CONTENT = (
    b"q\n"
    b"BI /W 1 /H 1 /CS /RGB /BPC 8 ID EI \nEI\n"
    b"Q\n"
    b"BT /F1 12 Tf 72 700 Td (REAL PAGE TEXT) Tj ET\n"
)

# A six-byte image whose inner "EI " is followed by bytes that look like the
# text-showing operator Tj, exercising the "image bytes as operators" hazard.
UNFILTERED_TJ_CONTENT = (
    b"q\n"
    b"BI /W 1 /H 2 /CS /RGB /BPC 8 ID EI TjX\nEI\n"
    b"Q\n"
    b"BT /F1 12 Tf 72 700 Td (REAL) Tj ET\n"
)


def test_unfiltered_image_with_inner_ei_is_bounded_by_length() -> None:
    pdf = _build_pdf(UNFILTERED_CONTENT)
    (image,) = _inline_streams(pdf)
    # The whole three-byte image must be retained, not cut at the inner EI.
    assert image.rawdata == b"EI "
    assert extract_text(BytesIO(pdf)).strip() == "REAL PAGE TEXT"


def test_unfiltered_image_never_leaks_tj_operator() -> None:
    pdf = _build_pdf(UNFILTERED_TJ_CONTENT)
    (image,) = _inline_streams(pdf)
    assert image.rawdata == b"EI TjX"
    # No token that originated inside the image may survive as an operator.
    names = [
        getattr(obj, "name", None)
        for obj in _tokens(pdf)
        if not isinstance(obj, PDFStream)
    ]
    assert b"TjX" not in names
    assert extract_text(BytesIO(pdf)).strip() == "REAL"


@pytest.mark.parametrize("bufsiz", [1, 2, 3, 5, 16, 64, 256, 4096])
def test_unfiltered_boundary_is_stable_across_buffer_sizes(bufsiz: int) -> None:
    original = PSBaseParser.BUFSIZ
    PSBaseParser.BUFSIZ = bufsiz
    try:
        pdf = _build_pdf(UNFILTERED_TJ_CONTENT)
        (image,) = _inline_streams(pdf)
        assert image.rawdata == b"EI TjX"
        assert extract_text(BytesIO(pdf)).strip() == "REAL"
    finally:
        PSBaseParser.BUFSIZ = original


def test_terminator_split_across_buffer_boundary() -> None:
    # Force the two-byte EI terminator to straddle every possible alignment.
    for pad in range(0, 8):
        content = (
            b"q\n"
            + b" " * pad
            + b"BI /W 1 /H 1 /CS /RGB /BPC 8 ID EI \nEI\nQ\n"
            b"BT /F1 12 Tf 72 700 Td (SPLIT) Tj ET\n"
        )
        for bufsiz in (2, 3, 4):
            original = PSBaseParser.BUFSIZ
            PSBaseParser.BUFSIZ = bufsiz
            try:
                pdf = _build_pdf(content)
                (image,) = _inline_streams(pdf)
                assert image.rawdata == b"EI "
                assert extract_text(BytesIO(pdf)).strip() == "SPLIT"
            finally:
                PSBaseParser.BUFSIZ = original


def test_ascii85_uses_its_own_end_of_data_marker() -> None:
    # The block 00 00 28 55 ASCII85-encodes to b'!!"EI', so the encoded image
    # contains literal "EI" bytes that must not terminate the image.
    raw = b"\x00\x00(U" * 64
    encoded = base64.a85encode(raw)
    assert b"EI" in encoded
    content = (
        b"q\n"
        b"BI /W 64 /H 1 /CS /RGB /BPC 8 /F /ASCII85Decode ID "
        + encoded
        + b"~>\nEI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (A85 REAL TEXT) Tj ET\n"
    )
    pdf = _build_pdf(content)
    (image,) = _inline_streams(pdf)
    # The ~> marker is retained for the decoder; the inner EI is harmless.
    assert image.rawdata.endswith(b"~>")
    assert image.get_data() == raw
    assert extract_text(BytesIO(pdf)).strip() == "A85 REAL TEXT"


def test_asciihex_uses_greater_than_marker() -> None:
    content = (
        b"q\nBI /W 6 /H 1 /CS /G /BPC 8 /F /AHx ID 454920414243> EI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (AHX REAL TEXT) Tj ET\n"
    )
    pdf = _build_pdf(content)
    (image,) = _inline_streams(pdf)
    assert image.get_data() == b"EI ABC"
    assert extract_text(BytesIO(pdf)).strip() == "AHX REAL TEXT"


def _flate_stream_with_inner_ei() -> tuple[bytes, bytes]:
    """Return (raw image, flate-encoded image) containing an inner EI+space."""
    import random

    rng = random.Random(1)
    for _ in range(200_000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randint(20, 300)))
        encoded = zlib.compress(raw, 9)
        if b"EI " in encoded:
            return raw, encoded
    raise RuntimeError("could not synthesise a flate stream containing EI ")


def test_flate_decoy_ei_rejected_by_strict_validation() -> None:
    raw, encoded = _flate_stream_with_inner_ei()
    decoy = encoded.find(b"EI ")
    assert decoy != -1
    # The cut at the inner EI is not a valid zlib stream, but the full one is.
    parser = PDFContentParser.__new__(PDFContentParser)
    assert parser._decodes_cleanly(encoded[:decoy], [LIT("Fl")]) is False
    assert parser._decodes_cleanly(encoded, [LIT("Fl")]) is True

    content = (
        b"q\nBI /W %d /H 1 /CS /G /BPC 8 /F /Fl ID " % len(raw)
        + encoded
        + b"\nEI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (FL REAL) Tj ET\n"
    )
    pdf = _build_pdf(content)
    (image,) = _inline_streams(pdf)
    # The whole encoded stream is retained rather than cut at the decoy;
    # only the separating whitespace before EI may be appended.
    assert image.rawdata.startswith(encoded)
    assert image.get_data() == raw
    assert extract_text(BytesIO(pdf)).strip() == "FL REAL"


def test_ambiguous_filtered_image_is_reported_and_source_kept(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Two run-length cuts decode without error, so the true end is ambiguous.
    # The parser must log the ambiguity instead of silently picking an EI,
    # while the genuine text that follows remains readable.
    encoded = bytes([2]) + b"ABC" + bytes([128])
    encoded += b"EI Tj"
    encoded += bytes([2]) + b"XYZ" + bytes([128])
    content = (
        b"q\nBI /W 6 /H 1 /CS /G /BPC 8 /F /RL ID "
        + encoded
        + b" EI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (RL REAL TEXT) Tj ET\n"
    )
    pdf = _build_pdf(content)
    with caplog.at_level(logging.WARNING):
        text = extract_text(BytesIO(pdf))
    assert "ambiguous" in caplog.text.lower()
    assert text.strip() == "RL REAL TEXT"


def test_missing_ei_reports_and_keeps_remainder(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Declared three-byte image but the stream is truncated before EI.  The
    # boundary cannot be confirmed, so no PDFStream is produced and the
    # parser position is restored, leaving the bytes in their original
    # source instead of silently swallowing them as image data.
    content = b"q\nBI /W 1 /H 1 /CS /RGB /BPC 8 ID AB"
    pdf = _build_pdf(content)
    with caplog.at_level(logging.WARNING):
        tokens = _tokens(pdf)
    assert "could not confirm" in caplog.text
    assert not [obj for obj in tokens if isinstance(obj, PDFStream)]


def test_ambiguous_then_real_text_still_tokenizes() -> None:
    # End-to-end check that after an unresolved boundary the following text
    # operators are still parsed from their original source.
    encoded = bytes([2]) + b"ABC" + bytes([128]) + b"EI Tj"
    encoded += bytes([2]) + b"XYZ" + bytes([128])
    content = (
        b"q\nBI /W 6 /H 1 /CS /G /BPC 8 /F /RL ID "
        + encoded
        + b" EI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (KEPT) Tj ET\n"
    )
    pdf = _build_pdf(content)
    token_values = [
        obj for obj in _tokens(pdf) if isinstance(obj, (bytes, PSLiteral))
    ]
    assert b"KEPT" in token_values


def test_inline_image_data_container() -> None:
    data = InlineImageData(data=b"abc", eod=b"EI", end=10)
    assert data.data == b"abc"
    assert data.eod == b"EI"
    assert data.end == 10
    assert repr(data) == "<InlineImageData: len=3, eod=b'EI'>"


def test_sub_byte_samples_are_packed_with_ceiling() -> None:
    # Six 1-bit grayscale samples occupy a single packed byte, and the
    # following EI must still be recognised as the image terminator.
    content = (
        b"q\nBI /W 2 /H 3 /CS /G /BPC 1 ID \xff\nEI\nQ\n"
        b"BT /F1 12 Tf 72 700 Td (PACKED) Tj ET\n"
    )
    pdf = _build_pdf(content)
    (image,) = _inline_streams(pdf)
    assert image.rawdata == b"\xff"
    assert extract_text(BytesIO(pdf)).strip() == "PACKED"


def test_expected_length_uses_colour_space_components() -> None:
    length = PDFContentParser._expected_image_length
    assert length({"W": 1, "H": 1, "CS": LIT("RGB"), "BPC": 8}) == 3
    assert length({"W": 1, "H": 2, "CS": LIT("RGB"), "BPC": 8}) == 6
    assert length({"W": 2, "H": 3, "CS": LIT("G"), "BPC": 1}) == 1
    assert length({"W": 4, "H": 1, "CS": LIT("I"), "BPC": 8}) == 4
    # Missing dimensions or an unresolvable colour space yield no length.
    assert length({"CS": LIT("G")}) is None
    assert length({"W": 4, "H": 1, "CS": ["Indexed"], "BPC": 8}) is None
