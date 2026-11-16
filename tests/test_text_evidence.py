"""Tests for traceable text evidence extraction."""

import json
from io import BytesIO

from pdfminer.high_level import extract_text, extract_text_evidence
from pdfminer.text_evidence import FormReference
from pdfminer.utils import apply_matrix_pt


def build_pdf(objects: list[bytes]) -> bytes:
    """Build a minimal PDF with a classic cross-reference table."""
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for objid, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{objid} 0 obj\n".encode()
        out += body
        if not body.endswith(b"\n"):
            out += b"\n"
        out += b"endobj\n"
    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(out)


def stream(data: bytes, extra: bytes = b"") -> bytes:
    return (
        b"<< /Length " + str(len(data)).encode() + extra + b" >>\nstream\n"
        + data
        + b"\nendstream\n"
    )


HELVETICA = (
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
    b"/Encoding /WinAnsiEncoding >>\n"
)

FORM_CONTENT = (
    b"BT /F1 12 Tf 10 50 Td (FormVisible) Tj ET\n"
    b"BT /F1 12 Tf 10 50 Td 3 Tr (FormHidden) Tj ET\n"
)

PAGE_CONTENT = (
    b"BT /F1 24 Tf 72 720 Td (Visible) Tj ET\n"
    b"BT /F1 24 Tf 72 720 Td 3 Tr (Hidden) Tj ET\n"
    b"BT /F1 16 Tf 72 640 Td (BeforeForm) Tj ET\n"
    b"q 1 0 0 1 72 400 cm /Fm0 Do Q\n"
)


def make_pdf(
    page_content: bytes = PAGE_CONTENT,
    resources: bytes | None = None,
) -> bytes:
    if resources is None:
        resources = (
            b"<< /Font << /F1 5 0 R >> /XObject << /Fm0 6 0 R >> >>"
        )
    return build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>\n",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources " + resources + b" /Contents 4 0 R >>\n"
            ),
            stream(page_content),
            HELVETICA,
            stream(
                FORM_CONTENT,
                b" /Type /XObject /Subtype /Form /BBox [0 0 300 100] "
                b"/Resources << /Font << /F1 5 0 R >> >>",
            ),
        ],
    )


def get_runs(pdf: bytes):
    pages = extract_text_evidence(BytesIO(pdf))
    assert len(pages) == 1
    return pages[0], pages[0].runs


class TestTextEvidenceSources:
    def test_visible_and_hidden_text_are_separate_runs(self):
        _page, runs = get_runs(make_pdf())

        assert [run.text for run in runs] == [
            "Visible",
            "Hidden",
            "BeforeForm",
            "FormVisible",
            "FormHidden",
        ]
        visible, hidden = runs[0], runs[1]
        assert visible.visibility == "visible"
        assert hidden.visibility == "invisible"
        assert hidden.render_mode == 3
        assert hidden.paint_mode == "none"

        # Both were drawn at the same text position and page origin.
        assert visible.glyphs[0].text_position == hidden.glyphs[0].text_position
        assert visible.glyphs[0].page_origin == hidden.glyphs[0].page_origin
        assert apply_matrix_pt(
            visible.glyphs[0].matrix,
            (0, 0),
        ) == apply_matrix_pt(hidden.glyphs[0].matrix, (0, 0))

    def test_source_stream_and_operator_offsets(self):
        _page, runs = get_runs(make_pdf())

        visible = runs[0]
        assert visible.source.page_index == 0
        assert visible.source.page_objid == 3
        assert visible.source.content_stream_objid == 4
        assert visible.source.content_stream_index == 0
        assert visible.source.form_path == ()
        expected_offset = PAGE_CONTENT.index(
            b"Tj",
            PAGE_CONTENT.index(b"(Visible)"),
        )
        assert visible.source.operator_offset == expected_offset

    def test_form_xobject_source_is_preserved(self):
        _page, runs = get_runs(make_pdf())

        form_visible, form_hidden = runs[3], runs[4]
        for run in (form_visible, form_hidden):
            assert run.source.form_path == (FormReference("Fm0", 6),)
            assert run.source.content_stream_objid == 6
            assert run.source.content_stream_index == 0
            assert run.source.page_index == 0

        assert form_visible.visibility == "visible"
        assert form_hidden.visibility == "invisible"
        assert form_hidden.render_mode == 3
        assert form_visible.glyphs[0].text_position == (
            form_hidden.glyphs[0].text_position
        )

    def test_evidence_is_json_serialisable(self):
        page, _runs = get_runs(make_pdf())
        payload = json.loads(json.dumps(page.to_dict()))
        assert payload["runs"][0]["text"] == "Visible"
        assert payload["runs"][1]["visibility"] == "invisible"
        assert payload["runs"][3]["source"]["form_path"] == [
            {"name": "Fm0", "objid": 6},
        ]

    def test_default_extract_text_is_unchanged(self):
        # The default API still flattens the content into ordinary text.
        text = extract_text(BytesIO(make_pdf()))
        assert "Visible" in text
        assert "Hidden" in text


class TestUncertainVisibility:
    def test_clipping_is_unknown(self):
        content = (
            b"q 0 0 300 300 re W n\n"
            b"BT /F1 24 Tf 72 720 Td (Clipped) Tj ET\nQ\n"
        )
        _page, runs = get_runs(make_pdf(content))
        assert len(runs) == 1
        assert runs[0].visibility == "unknown"
        assert runs[0].clipping_active is True
        assert any("clip" in reason for reason in runs[0].visibility_reasons)

    def test_transparency_is_unknown(self):
        content = b"/GS1 gs BT /F1 24 Tf 72 720 Td (Faded) Tj ET\n"
        resources = (
            b"<< /Font << /F1 5 0 R >> "
            b"/ExtGState << /GS1 << /ca 0.4 >> >> >>"
        )
        _page, runs = get_runs(make_pdf(content, resources))
        assert len(runs) == 1
        assert runs[0].visibility == "unknown"
        assert runs[0].transparency_uncertain is True
        assert any("transparency" in reason for reason in runs[0].visibility_reasons)

    def test_later_overpaint_is_unknown(self):
        content = (
            b"BT /F1 24 Tf 72 720 Td (Covered) Tj ET\n"
            b"0 0 0 rg 0 700 300 60 re f\n"
        )
        _page, runs = get_runs(make_pdf(content))
        assert len(runs) == 1
        assert runs[0].visibility == "unknown"
        assert runs[0].occlusion == "possible"

    def test_hidden_text_does_not_hide_visible_text(self):
        content = (
            b"BT /F1 24 Tf 72 720 Td (Visible) Tj ET\n"
            b"BT /F1 24 Tf 72 720 Td 3 Tr (Hidden) Tj ET\n"
        )
        _page, runs = get_runs(make_pdf(content))
        assert runs[0].visibility == "visible"
        assert runs[1].visibility == "invisible"

    def test_soft_mask_is_unknown(self):
        content = b"/GS1 gs BT /F1 24 Tf 72 720 Td (Masked) Tj ET\n"
        resources = (
            b"<< /Font << /F1 5 0 R >> "
            b"/ExtGState << /GS1 << /SMask << /S /Alpha >> >> >> >>"
        )
        _page, runs = get_runs(make_pdf(content, resources))
        assert len(runs) == 1
        assert runs[0].visibility == "unknown"
        assert runs[0].transparency_uncertain is True

    def test_glyph_outside_page_is_unknown(self):
        content = b"BT /F1 24 Tf 700 900 Td (Outside) Tj ET\n"
        _page, runs = get_runs(make_pdf(content))
        assert len(runs) == 1
        assert runs[0].visibility == "unknown"
        assert any("page" in reason for reason in runs[0].visibility_reasons)


class TestCliEvidence:
    def test_pdf2txt_evidence_output(self, tmp_path):
        pdf_path = tmp_path / "evidence.pdf"
        pdf_path.write_bytes(make_pdf())
        out_path = tmp_path / "evidence.json"

        from tools import pdf2txt

        pdf2txt.main(["-t", "evidence", "-o", str(out_path), str(pdf_path)])

        payload = json.loads(out_path.read_text(encoding="utf-8"))
        runs = payload["pages"][0]["runs"]
        assert [run["text"] for run in runs] == [
            "Visible",
            "Hidden",
            "BeforeForm",
            "FormVisible",
            "FormHidden",
        ]
        assert runs[1]["visibility"] == "invisible"
        assert runs[4]["source"]["form_path"] == [{"name": "Fm0", "objid": 6}]

    def test_content_stream_array_indices(self):
        pdf = build_pdf(
            [
                b"<< /Type /Catalog /Pages 2 0 R >>\n",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n",
                (
                    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    b"/Resources << /Font << /F1 5 0 R >> >> "
                    b"/Contents [4 0 R 6 0 R] >>\n"
                ),
                stream(b"BT /F1 24 Tf 72 720 Td (First) Tj ET\n"),
                HELVETICA,
                stream(b"BT /F1 24 Tf 72 600 Td (Second) Tj ET\n"),
            ],
        )
        _page, runs = get_runs(pdf)
        assert [(run.text, run.source.content_stream_index) for run in runs] == [
            ("First", 0),
            ("Second", 1),
        ]
        assert runs[1].source.content_stream_objid == 6
