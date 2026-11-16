import io
from html.parser import HTMLParser
from tempfile import TemporaryFile

from pdfminer.converter import (
    PDFConverter,
    PDFLayoutAnalyzer,
    _escape_css_font_name,
)
from pdfminer.high_level import extract_pages, extract_text_to_fp
from pdfminer.layout import LTChar, LTContainer, LTCurve, LTLine, LTRect
from pdfminer.pdfinterp import PDFGraphicState
from tests.helpers import absolute_sample_path


class TestPaintPath:
    def test_paint_path(self):
        path = [("m", 6, 7), ("l", 7, 7)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item._objs) == 1

    def test_paint_path_mlllh(self):
        path = [("m", 6, 7), ("l", 7, 7), ("l", 7, 91), ("l", 6, 91), ("h",)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item) == 1

    def test_paint_path_multiple_mlllh(self):
        """Path from samples/contrib/issue-00369-excel.pdf"""
        path = [
            ("m", 6, 7),
            ("l", 7, 7),
            ("l", 7, 91),
            ("l", 6, 91),
            ("h",),
            ("m", 4, 7),
            ("l", 6, 7),
            ("l", 6, 91),
            ("l", 4, 91),
            ("h",),
            ("m", 67, 2),
            ("l", 68, 2),
            ("l", 68, 3),
            ("l", 67, 3),
            ("h",),
        ]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item._objs) == 3

    def test_paint_path_quadrilaterals(self):
        """Via https://github.com/pdfminer/pdfminer.six/issues/473"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        def get_types(path):
            return list(map(type, parse(path)))

        # Standard rect
        assert get_types(
            [
                ("m", 10, 90),
                ("l", 90, 90),
                ("l", 90, 10),
                ("l", 10, 10),
                ("h",),
            ],
        ) == [LTRect]

        # Same but mllll variation
        assert get_types(
            [
                ("m", 10, 90),
                ("l", 90, 90),
                ("l", 90, 10),
                ("l", 10, 10),
                ("l", 10, 90),
            ],
        ) == [LTRect]

        # Same but mllllh variation
        assert get_types(
            [
                ("m", 10, 90),
                ("l", 90, 90),
                ("l", 90, 10),
                ("l", 10, 10),
                ("l", 10, 90),
                ("h",),
            ],
        ) == [LTRect]

        # Bowtie shape
        assert get_types(
            [
                ("m", 110, 90),
                ("l", 190, 10),
                ("l", 190, 90),
                ("l", 110, 10),
                ("h",),
            ],
        ) == [LTCurve]

        # Quadrilateral with one slanted side
        assert get_types(
            [
                ("m", 210, 90),
                ("l", 290, 60),
                ("l", 290, 10),
                ("l", 210, 10),
                ("h",),
            ],
        ) == [LTCurve]

        # Path with two rect subpaths
        assert get_types(
            [
                ("m", 310, 90),
                ("l", 350, 90),
                ("l", 350, 10),
                ("l", 310, 10),
                ("h",),
                ("m", 350, 90),
                ("l", 390, 90),
                ("l", 390, 10),
                ("l", 350, 10),
                ("h",),
            ],
        ) == [LTRect, LTRect]

        # Path with one rect subpath and one pentagon
        assert get_types(
            [
                ("m", 410, 90),
                ("l", 445, 90),
                ("l", 445, 10),
                ("l", 410, 10),
                ("h",),
                ("m", 455, 70),
                ("l", 475, 90),
                ("l", 490, 70),
                ("l", 490, 10),
                ("l", 455, 10),
                ("h",),
            ],
        ) == [LTRect, LTCurve]

        # Three types of simple lines
        assert get_types(
            [
                # Vertical line
                ("m", 10, 30),
                ("l", 10, 40),
                ("h",),
                # Horizontal line
                ("m", 10, 50),
                ("l", 70, 50),
                ("h",),
                # Diagonal line
                ("m", 10, 10),
                ("l", 30, 30),
                ("h",),
            ],
        ) == [LTLine, LTLine, LTLine]

        # Same as above, but 'ml' variation
        assert get_types(
            [
                # Vertical line
                ("m", 10, 30),
                ("l", 10, 40),
                # Horizontal line
                ("m", 10, 50),
                ("l", 70, 50),
                # Diagonal line
                ("m", 10, 10),
                ("l", 30, 30),
            ],
        ) == [LTLine, LTLine, LTLine]

        # There are six lines in this one-page PDF;
        # they all have shape 'ml' not 'mlh'
        ml_pdf = extract_pages("samples/contrib/pr-00530-ml-lines.pdf")
        ml_pdf_page = next(iter(ml_pdf))
        assert sum(type(item) is LTLine for item in ml_pdf_page) == 6

    def _get_analyzer(self):
        analyzer = PDFLayoutAnalyzer(None)
        analyzer.set_ctm([1, 0, 0, 1, 0, 0])
        return analyzer

    def test_paint_path_beziers(self):
        """See section 4.4, table 4.9 of the PDF reference manual"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        # "c" operator
        assert parse(
            [
                ("m", 72.41, 433.89),
                ("c", 72.41, 434.45, 71.96, 434.89, 71.41, 434.89),
            ],
        )[0].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]

        # "v" operator
        assert parse([("m", 72.41, 433.89), ("v", 71.96, 434.89, 71.41, 434.89)])[
            0
        ].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]

        # "y" operator
        assert parse([("m", 72.41, 433.89), ("y", 72.41, 434.45, 71.41, 434.89)])[
            0
        ].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]

    def test_paint_path_beziers_check_raw(self):
        """See section 4.4, table 4.9 of the PDF reference manual"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        # "c" operator
        assert parse(
            [
                ("m", 72.41, 433.89),
                ("c", 72.41, 434.45, 71.96, 434.89, 71.41, 434.89),
            ],
        )[0].original_path == [
            ("m", (72.41, 433.89)),
            ("c", (72.41, 434.45), (71.96, 434.89), (71.41, 434.89)),
        ]

    def test_paint_path_dashed(self):
        """See section 4.4, table 4.9 of the PDF reference manual"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            graphicstate = PDFGraphicState()
            graphicstate.dash = ([1, 1], 0)
            analyzer.paint_path(graphicstate, False, False, False, path)
            return analyzer.cur_item._objs

        # "c" operator
        assert parse(
            [
                ("m", 72.41, 433.89),
                ("c", 72.41, 434.45, 71.96, 434.89, 71.41, 434.89),
            ],
        )[0].dashing_style == ([1, 1], 0)

    def test_paint_path_without_starting_m(self):
        gs = PDFGraphicState()
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        paths = [[("h",)], [("l", 72.41, 433.89), ("l", 82.41, 433.89), ("h",)]]
        for path in paths:
            analyzer.paint_path(gs, False, False, False, path)
        assert len(analyzer.cur_item._objs) == 0

    def test_linewidth(self):
        ml_pdf = extract_pages("samples/contrib/issue_1165_linewidth.pdf")
        ml_pdf_page = next(iter(ml_pdf))
        lines = sorted(
            [item for item in ml_pdf_page if type(item) is LTLine],
            key=lambda line: line.linewidth,
        )
        assert len(lines) == 2
        assert lines[0].linewidth == 2.83465
        assert lines[1].linewidth == 2 * 2.83465


def get_chars(el):
    if isinstance(el, LTContainer):
        for item in el:
            yield from get_chars(item)
    elif isinstance(el, LTChar):
        yield el
    else:
        pass


class TestColorSpace:
    def test_do_rg(self):
        path = absolute_sample_path("contrib/issue-00352-hash-twos-complement.pdf")
        for page in extract_pages(path):
            for char in get_chars(page):
                cs = char.ncs.name
                color = char.graphicstate.ncolor
                if cs == "DeviceGray":
                    assert isinstance(color, (float, int))
                elif cs == "DeviceRGB":
                    assert len(color) == 3
                elif cs == "DeviceCMYK":
                    assert len(color) == 4
                elif cs == "Pattern":
                    # Pattern colors should be stored as strings (pattern names)
                    assert isinstance(color, str)
                    assert color.startswith("P")  # Pattern names typically start with P

    def test_pattern_colors(self):
        """Test that Pattern color spaces are properly handled.

        Pattern colors use pattern names (like 'P1444') instead of numeric values.
        Colored patterns (PaintType=1): stored as string (pattern name)
        Uncolored patterns (PaintType=2): stored as tuple (base_color, pattern name)
        """
        path = absolute_sample_path("test_pattern_colors.pdf")

        for page in extract_pages(path):
            # Check for any objects with pattern colors
            for item in page:
                if isinstance(item, LTCurve):
                    # LTCurve objects have stroking_color and non_stroking_color
                    if item.stroking_color is not None:
                        # Colored pattern: stored as string
                        if isinstance(item.stroking_color, str):
                            assert item.stroking_color.startswith("P")
                        # Uncolored pattern: stored as tuple (base_color, pattern_name)
                        elif (
                            isinstance(item.stroking_color, tuple)
                            and len(item.stroking_color) == 2
                        ):
                            _base_color, pattern_name = item.stroking_color
                            assert isinstance(pattern_name, str)
                            assert pattern_name.startswith("P")
                    if item.non_stroking_color is not None:
                        # Colored pattern: stored as string
                        if isinstance(item.non_stroking_color, str):
                            assert item.non_stroking_color.startswith("P")
                        # Uncolored pattern: stored as tuple (base_color, pattern_name)
                        elif (
                            isinstance(item.non_stroking_color, tuple)
                            and len(item.non_stroking_color) == 2
                        ):
                            _base_color, pattern_name = item.non_stroking_color
                            assert isinstance(pattern_name, str)
                            assert pattern_name.startswith("P")

    def test_pattern_operators(self, caplog):
        """Test SCN/scn operators with all pattern combinations.

        Tests:
        - Colored patterns (1 operand: pattern name)
        - Uncolored patterns with gray (2 operands: gray + pattern name)
        - Uncolored patterns with RGB (4 operands: r,g,b + pattern name)
        - Uncolored patterns with CMYK (5 operands: c,m,y,k + pattern name)
        - Invalid patterns (non-PSLiteral operands) trigger warnings
        """
        from pdfminer.converter import PDFPageAggregator
        from pdfminer.layout import LAParams
        from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
        from pdfminer.psparser import PSLiteral

        # Create minimal PDF with Pattern color space
        # We'll test the interpreter methods directly
        rsrcmgr = PDFResourceManager()
        laparams = LAParams()
        device = PDFPageAggregator(rsrcmgr, laparams=laparams)
        interpreter = PDFPageInterpreter(rsrcmgr, device)

        # Initialize the interpreter state (creates graphicstate)
        interpreter.init_resources({})
        interpreter.init_state((1, 0, 0, 1, 0, 0))  # Identity matrix

        # Test 1: Colored pattern (stroking)
        interpreter.graphicstate.scs.name = "Pattern"
        interpreter.graphicstate.scs.ncomponents = 1
        interpreter.push(PSLiteral("P1444"))
        interpreter.do_SCN()
        assert interpreter.graphicstate.scolor == "P1444"

        # Test 2: Colored pattern (non-stroking)
        interpreter.graphicstate.ncs.name = "Pattern"
        interpreter.graphicstate.ncs.ncomponents = 1
        interpreter.push(PSLiteral("P1445"))
        interpreter.do_scn()
        assert interpreter.graphicstate.ncolor == "P1445"

        # Test 3: Uncolored pattern with gray
        interpreter.graphicstate.scs.ncomponents = 2
        interpreter.push(0.5)  # gray value
        interpreter.push(PSLiteral("P2000"))
        interpreter.do_SCN()
        assert isinstance(interpreter.graphicstate.scolor, tuple)
        assert len(interpreter.graphicstate.scolor) == 2
        base_color, pattern_name = interpreter.graphicstate.scolor
        assert base_color == 0.5
        assert pattern_name == "P2000"

        # Test 4: Uncolored pattern with RGB
        interpreter.graphicstate.ncs.ncomponents = 4
        interpreter.push(0.77)  # R
        interpreter.push(0.2)  # G
        interpreter.push(0.0)  # B
        interpreter.push(PSLiteral("P3000"))
        interpreter.do_scn()
        assert isinstance(interpreter.graphicstate.ncolor, tuple)
        assert len(interpreter.graphicstate.ncolor) == 2
        base_color, pattern_name = interpreter.graphicstate.ncolor
        assert base_color == (0.77, 0.2, 0.0)
        assert pattern_name == "P3000"

        # Test 5: Uncolored pattern with CMYK
        interpreter.graphicstate.scs.ncomponents = 5
        interpreter.push(0.1)  # C
        interpreter.push(0.2)  # M
        interpreter.push(0.3)  # Y
        interpreter.push(0.4)  # K
        interpreter.push(PSLiteral("P4000"))
        interpreter.do_SCN()
        assert isinstance(interpreter.graphicstate.scolor, tuple)
        assert len(interpreter.graphicstate.scolor) == 2
        base_color, pattern_name = interpreter.graphicstate.scolor
        assert base_color == (0.1, 0.2, 0.3, 0.4)
        assert pattern_name == "P4000"

        # Test 6: Invalid pattern (non-PSLiteral) - should trigger warning
        interpreter.graphicstate.ncs.ncomponents = 1
        interpreter.push(0.5)  # Invalid: should be PSLiteral, not float
        caplog.clear()
        with caplog.at_level("WARNING"):
            interpreter.do_scn()
        assert "Pattern color space requires name object (PSLiteral)" in caplog.text
        assert "got float: 0.5" in caplog.text
        assert "ISO 32000 8.7.3.2" in caplog.text

        # Test 7: Invalid uncolored pattern (non-PSLiteral for pattern name)
        interpreter.graphicstate.scs.ncomponents = 2
        interpreter.push(0.5)  # gray
        interpreter.push(999)  # Invalid: should be PSLiteral, not int
        caplog.clear()
        with caplog.at_level("WARNING"):
            interpreter.do_SCN()
        assert "Pattern color space requires name object (PSLiteral)" in caplog.text
        assert "got int: 999" in caplog.text
        assert "ISO 32000 8.7.3.3" in caplog.text


class TestBinaryDetector:
    def test_stringio(self):
        assert not PDFConverter._is_binary_stream(io.StringIO())

    def test_bytesio(self):
        assert PDFConverter._is_binary_stream(io.BytesIO())

    def test_tmpfile(self):
        with TemporaryFile(mode="w") as f:
            assert not PDFConverter._is_binary_stream(f)

    def test_binary_tmpfile(self):
        with TemporaryFile(mode="wb") as f:
            assert PDFConverter._is_binary_stream(f)

    def test_non_file_like_object_defaults_to_binary(self):
        assert PDFConverter._is_binary_stream(object())

    def test_textiowrapper(self):
        assert not PDFConverter._is_binary_stream(io.TextIOBase())


class _HTMLAuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list = []
        self.text: list = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


class TestHTMLConverterOutputEscaping:
    """HTMLConverter must treat font names, text and image names from the
    PDF as untrusted: they must not inject tags, event handlers or extra
    CSS declarations into the generated report."""

    EVIL_FONT_NAME = 'EVIL+Font";}</style><script>alert(1)</script>{x:expression('
    EVIL_IMAGE_NAME = 'Im"><img src=x onerror=alert(2)>'

    ALLOWED_CSS_PROPERTIES = {
        "position",
        "border",
        "color",
        "left",
        "top",
        "width",
        "height",
        "font-size",
        "font-family",
        "writing-mode",
    }

    @staticmethod
    def _pdf_name(raw: str) -> str:
        # Encode as a PDF name object, escaping every non-alphanumeric byte.
        return "".join(
            chr(byte) if chr(byte).isalnum() and byte < 0x80 else f"#{byte:02X}"
            for byte in raw.encode("utf-8")
        )

    def _build_malicious_pdf(self) -> bytes:
        evil_font = self._pdf_name(self.EVIL_FONT_NAME)
        evil_image = self._pdf_name(self.EVIL_IMAGE_NAME)
        content = (
            b"BT /F1 12 Tf 100 700 Td "
            b'(Body <script>alert\\(1\\)</script> "quoted" & <b>bold</b>) Tj ET\n'
            b"BT /F2 14 Tf 100 650 Td (Caf\\351 na\\357ve) Tj ET\n"
            + f"q 50 0 0 50 100 400 cm /{evil_image} Do Q\n".encode()
        )
        image_data = b"\xff\xd8\xff\xd9"  # only stored, never decoded
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> "
                + f"/XObject << /{evil_image} 7 0 R >>".encode()
                + b" >> /Contents 6 0 R >>"
            ),
            (
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{evil_font} "
                "/Encoding /WinAnsiEncoding "
                "/FontDescriptor << /Type /FontDescriptor "
                f"/FontName /{evil_font} /Flags 4 "
                "/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 "
                "/Descent -200 /CapHeight 700 /StemV 80 >> >>"
            ).encode(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>",
            b"<< /Length "
            + str(len(content)).encode()
            + b" >>\nstream\n"
            + content
            + b"endstream",
            (
                b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 "
                b"/ColorSpace /DeviceRGB /BitsPerComponent 8 "
                b"/Filter /DCTDecode /Length "
                + str(len(image_data)).encode()
                + b" >>\nstream\n"
                + image_data
                + b"\nendstream"
            ),
        ]
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n")
        offsets = []
        for obj_id, body in enumerate(objects, start=1):
            offsets.append(out.tell())
            out.write(f"{obj_id} 0 obj\n".encode() + body + b"\nendobj\n")
        xref = out.tell()
        out.write(f"xref\n0 {len(objects) + 1}\n".encode())
        out.write(b"0000000000 65535 f \n")
        for offset in offsets:
            out.write(f"{offset:010d} 00000 n \n".encode())
        out.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n".encode()
        )
        return out.getvalue()

    def _convert_to_html(self, pdf_bytes: bytes, output_dir: str) -> str:
        outfp = io.BytesIO()
        with io.BytesIO(pdf_bytes) as inf:
            extract_text_to_fp(
                inf,
                outfp,
                output_type="html",
                codec="utf-8",
                output_dir=output_dir,
            )
        return outfp.getvalue().decode("utf-8")

    def test_escape_css_font_name(self):
        assert _escape_css_font_name("Helvetica") == "Helvetica"
        assert _escape_css_font_name("Times New Roman") == "Times New Roman"
        # Non-ASCII font names stay readable.
        assert _escape_css_font_name("微软雅黑") == "微软雅黑"
        escaped = _escape_css_font_name(
            'x";}</style><script>alert(1)</script>{background:url(evil)'
        )
        for char in "\"'<>&;:{}()":
            assert char not in escaped
        # A leading digit would invalidate the CSS identifier.
        assert _escape_css_font_name("9lives").startswith("\\39 ")

    def test_no_injection_via_font_text_or_image(self, tmp_path):
        html = self._convert_to_html(self._build_malicious_pdf(), str(tmp_path))

        parser = _HTMLAuditParser()
        parser.feed(html)
        tags = [tag for tag, _ in parser.tags]

        # No injected tags; the only img is the legitimate exported image.
        assert "script" not in tags
        assert "style" not in tags
        assert tags.count("img") == 1
        assert "<script" not in html
        assert "</style>" not in html

        # No event-handler attributes anywhere.
        for _, attrs in parser.tags:
            for attr_name in attrs:
                assert not attr_name.lower().startswith("on")

        # Every style attribute only contains expected declarations; the
        # hostile font name cannot smuggle in extra ones.
        font_families = []
        for _, attrs in parser.tags:
            style = attrs.get("style")
            if style is None:
                continue
            for declaration in style.split(";"):
                declaration = declaration.strip()
                if not declaration:
                    continue
                prop, _, value = declaration.partition(":")
                prop = prop.strip()
                assert prop in self.ALLOWED_CSS_PROPERTIES
                if prop == "font-family":
                    font_families.append(value.strip())

        # The normal font survives untouched; the hostile name is kept as
        # data but neutralized into a single inert CSS identifier.
        assert "Helvetica" in font_families
        evil_families = [f for f in font_families if f.startswith("Font")]
        assert len(evil_families) == 1
        for char in "\"'<>&;:{}()":
            assert char not in evil_families[0]

        # The hostile image name is an inert attribute value, not markup.
        img_attrs = next(attrs for tag, attrs in parser.tags if tag == "img")
        assert img_attrs["src"] == self.EVIL_IMAGE_NAME + ".jpg"

        # Body text is escaped, not dropped: markup degrades to inert text
        # and non-ASCII content is preserved.
        assert "&lt;script&gt;" in html
        text = "".join(parser.text)
        assert "alert(1)" in text
        assert "Café naïve" in text
