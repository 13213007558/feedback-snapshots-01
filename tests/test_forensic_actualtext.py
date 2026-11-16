"""Tests for ActualText-aware forensic extraction.

The fixtures below are hand-built PDFs (no third-party writer) covering nested
marked content, property dictionaries referenced by name through
/Properties, Form XObjects with independent resources, and unclosed
marked-content diagnostics.
"""

from __future__ import annotations

import io
import json
import logging

from pdfminer.forensic import (
    extract_actualtext,
    extract_actualtext_report,
    forensic_report_json,
)

# --------------------------------------------------------------------------
# Minimal PDF writer (sufficient for these fixtures; not part of the library)
# --------------------------------------------------------------------------


def _pdf_string(text: str) -> bytes:
    if all(ord(ch) < 128 for ch in text):
        escaped = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        return f"({escaped})".encode("latin-1")
    return b"(\xfe\xff" + text.encode("utf-16-be") + b")"


def _dict(mapping, stream=None):
    body = bytearray(b"<<")
    for key, value in mapping.items():
        body.extend(b" /" + key.encode() + b" " + value)
    if stream is not None:
        body.extend(b" >>\nstream\n" + stream + b"\nendstream")
    else:
        body.extend(b" >>")
    return bytes(body)


class _Pdf:
    def __init__(self):
        self._bodies = []

    def add(self, body):
        self._bodies.append(body)
        return len(self._bodies)

    def build(self):
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(self._bodies, start=1):
            offsets.append(len(out))
            out.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
        xref = len(out)
        size = len(self._bodies) + 1
        out.extend(f"xref\n0 {size}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            out.extend(f"{offset:010d} 00000 n \n".encode())
        out.extend(
            f"trailer\n<< /Size {size} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n".encode()
        )
        return bytes(out)


def _text(x, y, font, size, text):
    return (
        b"BT /"
        + font.encode()
        + b" "
        + str(size).encode()
        + b" Tf "
        + str(x).encode()
        + b" "
        + str(y).encode()
        + b" Td "
        + _pdf_string(text)
        + b" Tj ET"
    )


def _make_pdf(page_streams, page_resources=None, form_specs=None):
    """Build a one-or-more page PDF.

    page_streams: list of content-stream byte strings.
    form_specs: optional list of (name, stream_bytes, resources_bytes, bbox).
    Returns the serialised PDF bytes.
    """
    pdf = _Pdf()
    catalog = pdf.add(b"")
    pages = pdf.add(b"")
    font = pdf.add(
        _dict(
            {
                "Type": b"/Font",
                "Subtype": b"/Type1",
                "BaseFont": b"/Helvetica",
            }
        )
    )
    base_resources = {
        "Font": _dict({"F1": f"{font} 0 R".encode()}),
    }

    form_refs = {}
    if form_specs:
        for name, stream, resources, bbox in form_specs:
            xobj = pdf.add(
                _dict(
                    {
                        "Type": b"/XObject",
                        "Subtype": b"/Form",
                        "BBox": bbox,
                        "Resources": resources,
                        "Length": str(len(stream)).encode(),
                    },
                    stream=stream,
                )
            )
            form_refs[name] = xobj
        base_resources["XObject"] = _dict(
            {name: f"{ref} 0 R".encode() for name, ref in form_refs.items()}
        )

    if page_resources:
        base_resources.update(page_resources)

    page_numbers = []
    for stream_bytes in page_streams:
        contents = pdf.add(
            _dict(
                {
                    "Length": str(len(stream_bytes)).encode(),
                },
                stream=stream_bytes,
            )
        )
        page = pdf.add(
            _dict(
                {
                    "Type": b"/Page",
                    "Parent": f"{pages} 0 R".encode(),
                    "MediaBox": b"[ 0 0 612 792 ]",
                    "Resources": _dict(base_resources),
                    "Contents": f"{contents} 0 R".encode(),
                }
            )
        )
        page_numbers.append(page)

    kids = b"[ " + b" ".join(f"{n} 0 R".encode() for n in page_numbers) + b" ]"
    pdf._bodies[catalog - 1] = _dict(
        {
            "Type": b"/Catalog",
            "Pages": f"{pages} 0 R".encode(),
        }
    )
    pdf._bodies[pages - 1] = _dict(
        {
            "Type": b"/Pages",
            "Kids": kids,
            "Count": str(len(page_numbers)).encode(),
        }
    )
    return pdf.build()


def _report(pdf_bytes):
    return extract_actualtext_report(io.BytesIO(pdf_bytes))


# --------------------------------------------------------------------------
# Reading order vs drawn evidence
# --------------------------------------------------------------------------


class TestActualTextChannels:
    def test_actualtext_replaces_two_drawn_runs_without_duplication(self):
        stream = b"\n".join(
            [
                _text(72, 720, "F1", 12, "PLAIN"),
                b"/P << /ActualText " + _pdf_string("ALT") + b" /MCID 1 >> BDC",
                _text(72, 700, "F1", 12, "AAA"),
                _text(72, 680, "F1", 12, "BBB"),
                b"EMC",
                _text(72, 660, "F1", 12, "TAIL"),
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]

        # Reading channel: replacement once, replaced glyphs suppressed.
        assert page.reading_text == "PLAINALTTAIL"
        # Drawn channel: every painted glyph retained, no replacement text.
        assert page.drawn_text == "PLAINAAABBBTAIL"
        # The replacement appears exactly once in reading order.
        assert page.reading_text.count("ALT") == 1
        assert "AAA" not in page.reading_text

    def test_nested_mark_inner_actualtext_respected(self):
        stream = b"\n".join(
            [
                b"/Outer << /ActualText " + _pdf_string("OUTER") + b" >> BDC",
                _text(72, 700, "F1", 12, "OUT-1"),
                b"/Inner << /ActualText " + _pdf_string("INNER") + b" >> BDC",
                _text(72, 680, "F1", 12, "IN-GLYPH"),
                b"EMC",
                _text(72, 660, "F1", 12, "OUT-2"),
                b"EMC",
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        outer = page.root.children[0]

        # The outer replacement wins: nested content is fully suppressed.
        assert outer.reading_text() == "OUTER"
        assert page.reading_text == "OUTER"
        # Drawn evidence keeps the full nested glyph order.
        assert outer.drawn_text() == "OUT-1IN-GLYPHOUT-2"
        inner = outer.children[0]
        assert inner.tag == "Inner"
        assert inner.actual_text == "INNER"
        assert inner.drawn_text() == "IN-GLYPH"

    def test_nested_mark_without_outer_actualtext_reads_inner(self):
        stream = b"\n".join(
            [
                b"/Outer BMC",
                _text(72, 700, "F1", 12, "BEFORE"),
                b"/Inner << /ActualText " + _pdf_string("IX") + b" >> BDC",
                _text(72, 680, "F1", 12, "HIDDEN"),
                b"EMC",
                _text(72, 660, "F1", 12, "AFTER"),
                b"EMC",
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        assert page.reading_text == "BEFOREIXAFTER"
        assert page.drawn_text == "BEFOREHIDDENAFTER"

    def test_empty_actualtext_suppresses_decorative_glyphs(self):
        stream = b"\n".join(
            [
                b"/Artifact << /ActualText () >> BDC",
                _text(72, 700, "F1", 12, "DECOR"),
                b"EMC",
                _text(72, 680, "F1", 12, "KEPT"),
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        assert page.reading_text == "KEPT"
        assert page.drawn_text == "DECORKEPT"

    def test_interspersed_glyphs_and_marks_keep_document_order(self):
        stream = b"\n".join(
            [
                b"/S BMC",
                _text(72, 700, "F1", 12, "ONE"),
                b"/I << /ActualText " + _pdf_string("X") + b" >> BDC",
                _text(72, 680, "F1", 12, "TWO"),
                b"EMC",
                _text(72, 660, "F1", 12, "THREE"),
                b"EMC",
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        assert page.drawn_text == "ONETWOTHREE"
        assert page.reading_text == "ONEXTHREE"


class TestPropertyResolution:
    def test_named_property_dictionary_via_resources(self):
        stream = b"\n".join(
            [
                b"/Span /P1 BDC",
                _text(72, 700, "F1", 12, "GLYPH"),
                b"EMC",
            ]
        )

        pdf = _Pdf()
        catalog = pdf.add(b"")
        pages = pdf.add(b"")
        font = pdf.add(
            _dict(
                {
                    "Type": b"/Font",
                    "Subtype": b"/Type1",
                    "BaseFont": b"/Helvetica",
                }
            )
        )
        named = pdf.add(
            _dict(
                {
                    "ActualText": _pdf_string("NAMED-ALT"),
                    "MCID": b"5",
                }
            )
        )
        resources = _dict(
            {
                "Font": _dict({"F1": f"{font} 0 R".encode()}),
                "Properties": _dict({"P1": f"{named} 0 R".encode()}),
            }
        )
        contents = pdf.add(
            _dict(
                {
                    "Length": str(len(stream)).encode(),
                },
                stream=stream,
            )
        )
        page = pdf.add(
            _dict(
                {
                    "Type": b"/Page",
                    "Parent": f"{pages} 0 R".encode(),
                    "MediaBox": b"[ 0 0 612 792 ]",
                    "Resources": resources,
                    "Contents": f"{contents} 0 R".encode(),
                }
            )
        )
        pdf._bodies[catalog - 1] = _dict(
            {
                "Type": b"/Catalog",
                "Pages": f"{pages} 0 R".encode(),
            }
        )
        pdf._bodies[pages - 1] = _dict(
            {
                "Type": b"/Pages",
                "Kids": b"[ " + f"{page} 0 R".encode() + b" ]",
                "Count": b"1",
            }
        )

        report = _report(pdf.build())
        mark = report.pages[0].root.children[0]
        assert mark.actual_text == "NAMED-ALT"
        assert mark.mcid == 5
        assert report.pages[0].reading_text == "NAMED-ALT"
        assert report.pages[0].drawn_text == "GLYPH"

    def test_missing_named_property_is_diagnosed(self, caplog):
        stream = b"\n".join(
            [
                b"/Span /MISSING BDC",
                _text(72, 700, "F1", 12, "GLYPH"),
                b"EMC",
            ]
        )
        with caplog.at_level(logging.WARNING):
            page = _report(_make_pdf([stream])).pages[0]
        mark = page.root.children[0]
        assert mark.actual_text is None
        assert page.reading_text == "GLYPH"
        assert any("Properties" in rec.message for rec in caplog.records)


class TestFormXObject:
    def test_form_uses_independent_resources_and_context(self):
        form_stream = b"\n".join(
            [
                b"/Span << /ActualText " + _pdf_string("FORM-ALT") + b" >> BDC",
                _text(0, 0, "F1", 10, "FORM-GLYPH"),
                b"EMC",
            ]
        )
        form_resources = _dict(
            {
                "Font": _dict({"F1": b"7 0 R"}),
            }
        )
        page_stream = b"\n".join(
            [
                _text(72, 720, "F1", 12, "PAGE-GLYPH"),
                b"q 1 0 0 1 72 600 cm /Fm1 Do Q",
            ]
        )
        specs = [("Fm1", form_stream, form_resources, b"[ 0 0 300 40 ]")]
        report = _report(_make_pdf([page_stream], form_specs=specs))
        page = report.pages[0]

        form_mark = next(m for m in page.root.iter_marks() if m.tag == "Span")
        assert form_mark.location.form_xobject == "Fm1"
        assert form_mark.location.page == 1
        assert form_mark.actual_text == "FORM-ALT"
        assert form_mark.drawn_text() == "FORM-GLYPH"
        # Both channels combine page and form content.
        assert page.drawn_text == "PAGE-GLYPHFORM-GLYPH"
        assert page.reading_text == "PAGE-GLYPHFORM-ALT"

    def test_unclosed_mark_inside_form_is_diagnosed(self):
        form_stream = b"\n".join(
            [
                b"/Span << /MCID 2 >> BDC",
                _text(0, 0, "F1", 10, "TRAPPED"),
                # no EMC
            ]
        )
        form_resources = _dict({"Font": _dict({"F1": b"7 0 R"})})
        page_stream = b"q 1 0 0 1 72 600 cm /Fm1 Do Q"
        specs = [("Fm1", form_stream, form_resources, b"[ 0 0 300 40 ]")]
        report = _report(_make_pdf([page_stream], form_specs=specs))
        diagnostics = report.pages[0].diagnostics
        assert any("Unclosed" in d and "Span" in d and "Fm1" in d for d in diagnostics)
        # Glyphs inside the unclosed form mark remain visible as drawn evidence.
        assert "TRAPPED" in report.pages[0].drawn_text


class TestDiagnostics:
    def test_unclosed_mark_on_page_reports_location(self):
        stream = b"\n".join(
            [
                _text(72, 720, "F1", 12, "A"),
                b"/Span << /MCID 9 >> BDC",
                _text(72, 700, "F1", 12, "B"),
            ]
        )
        report = _report(_make_pdf([stream, _text(72, 720, "F1", 12, "SECOND")]))
        diag = report.pages[0].diagnostics
        assert any("page 1" in d and "Span" in d and "MCID 9" in d for d in diag)
        # Second page is independent and healthy.
        assert report.pages[1].diagnostics == []
        assert report.pages[1].reading_text == "SECOND"

    def test_emc_without_open_tag_is_diagnosed(self):
        stream = b"EMC"
        report = _report(_make_pdf([stream]))
        assert any("EMC" in d for d in report.pages[0].diagnostics)


class TestMarkedContentPoints:
    def test_dp_point_captures_actualtext_without_glyph_suppression(self):
        stream = b"\n".join(
            [
                b"/Note << /ActualText "
                + _pdf_string("POINT-ALT")
                + b" /MCID 11 >> DP",
                _text(72, 720, "F1", 12, "VISIBLE"),
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        assert len(page.points) == 1
        point = page.points[0]
        assert point.tag == "Note"
        assert point.mcid == 11
        assert point.actual_text == "POINT-ALT"
        # A point wraps no glyphs, so painted text is read and drawn normally.
        assert page.reading_text == "VISIBLE"
        assert page.drawn_text == "VISIBLE"
        # But the point's ActualText is still listed as an evidence span.
        assert [span.tag for span in page.actual_text_spans()] == ["Note"]

    def test_mp_point_without_properties(self):
        stream = b"\n".join(
            [
                b"/Marker MP",
                _text(72, 720, "F1", 12, "TEXT"),
            ]
        )
        page = _report(_make_pdf([stream])).pages[0]
        assert len(page.points) == 1
        assert page.points[0].tag == "Marker"
        assert page.points[0].actual_text is None
        assert page.reading_text == "TEXT"


class TestMismatchSummary:
    def test_mismatch_points_to_specific_mark_and_page(self):
        stream = b"\n".join(
            [
                b"/P << /ActualText " + _pdf_string("ALT") + b" /MCID 4 >> BDC",
                _text(72, 700, "F1", 12, "VISUAL"),
                b"EMC",
            ]
        )
        report = _report(_make_pdf([stream]))
        mismatches = report.mismatches()
        assert len(mismatches) == 1
        mismatch = mismatches[0]
        assert mismatch["tag"] == "P"
        assert mismatch["page"] == 1
        assert mismatch["mcid"] == 4
        assert mismatch["actual_text"] == "ALT"
        assert mismatch["drawn_text"] == "VISUAL"

    def test_matching_actualtext_is_not_a_mismatch(self):
        stream = b"\n".join(
            [
                b"/P << /ActualText " + _pdf_string("SAME") + b" >> BDC",
                _text(72, 700, "F1", 12, "SAME"),
                b"EMC",
            ]
        )
        report = _report(_make_pdf([stream]))
        assert report.mismatches() == []


class TestPublicApi:
    def test_dict_and_json_output_are_equivalent(self):
        stream = b"\n".join(
            [
                b"/P << /ActualText " + _pdf_string("ALT") + b" >> BDC",
                _text(72, 700, "F1", 12, "GLYPH"),
                b"EMC",
            ]
        )
        data = pdf_bytes = _make_pdf([stream])
        as_dict = extract_actualtext(io.BytesIO(pdf_bytes))
        as_json = json.loads(forensic_report_json(io.BytesIO(data)))
        assert as_dict["reading_text"] == as_json["reading_text"] == "ALT"
        assert as_dict["drawn_text"] == as_json["drawn_text"] == "GLYPH"
        assert as_dict["pages"][0]["marks"][1]["actual_text"] == "ALT"

    def test_page_numbers_filter(self):
        report = extract_actualtext_report(
            io.BytesIO(
                _make_pdf(
                    [
                        _text(72, 720, "F1", 12, "ONE"),
                        _text(72, 720, "F1", 12, "TWO"),
                    ]
                )
            ),
            page_numbers=[1],
        )
        assert len(report.pages) == 1
        assert report.pages[0].page_number == 2
