"""Tests for the per-document stream decoding budget.

The budget protects PDF parsing from "decompression bomb" streams whose
small encoded payload expands to a huge decoded output. These tests cover
the individual bounded decoders, the filter-chain wiring inside
:class:`~pdfminer.pdftypes.PDFStream` (including predictors), and the
end-to-end behavior on multi-stream documents.
"""

import zlib
from base64 import a85encode
from io import BytesIO

import pytest

from pdfminer.ascii85 import ascii85decode, asciihexdecode
from pdfminer.ccitt import CCITTFaxDecoder
from pdfminer.decodebudget import DecodeBudget, PDFDecodeBudgetExceeded
from pdfminer.high_level import extract_text
from pdfminer.lzw import lzwdecode
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import PDFContentParser
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFStream
from pdfminer.psexceptions import PSEOF
from pdfminer.psparser import LIT
from pdfminer.runlength import rldecode
from pdfminer.utils import apply_png_predictor, apply_tiff_predictor

LZW_SAMPLE = b"\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01"
LZW_DECODED = b"-----A---B"


def make_pdf(stream_objects: dict[int, bytes]) -> bytes:
    """Build a minimal valid PDF from a mapping of objid -> object body."""
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [] /Count 0 >>",
    }
    objects.update(stream_objects)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for objid in sorted(objects):
        offsets[objid] = len(out)
        out += f"{objid} 0 obj\n".encode()
        out += objects[objid]
        out += b"\nendobj\n"
    xref_pos = len(out)
    maxid = max(objects)
    out += f"xref\n0 {maxid + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for objid in range(1, maxid + 1):
        out += f"{offsets[objid]:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {maxid + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def flate_stream(objid: int, payload: bytes) -> tuple[int, bytes]:
    compressed = zlib.compress(payload)
    body = (
        f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode()
        + compressed
        + b"\nendstream"
    )
    return objid, body


def make_page_pdf(content_payload: bytes) -> bytes:
    """Build a one-page PDF whose page content stream is Flate encoded."""
    compressed = zlib.compress(content_payload)
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        4: (
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode()
            + compressed
            + b"\nendstream"
        ),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for objid in sorted(objects):
        offsets[objid] = len(out)
        out += f"{objid} 0 obj\n".encode()
        out += objects[objid]
        out += b"\nendobj\n"
    xref_pos = len(out)
    maxid = max(objects)
    out += f"xref\n0 {maxid + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for objid in range(1, maxid + 1):
        out += f"{offsets[objid]:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {maxid + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


class TestDecodeBudgetLimits:
    def test_rejects_negative_limits(self):
        with pytest.raises(ValueError):
            DecodeBudget(total_limit=-1)
        with pytest.raises(ValueError):
            DecodeBudget(step_limit=-1)

    def test_remaining_tracks_consumption(self):
        budget = DecodeBudget(total_limit=10)
        budget.begin_step("layer")
        budget.charge("layer", 4)
        assert budget.total_consumed == 4
        assert budget.remaining() == 6

    def test_none_limits_are_unbounded(self):
        budget = DecodeBudget()
        budget.begin_step("layer")
        budget.charge("layer", 10**9)
        assert budget.remaining() is None

    def test_total_limit_message_names_layer(self):
        budget = DecodeBudget(total_limit=5)
        budget.begin_step("FlateDecode")
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            budget.charge("FlateDecode", 6)
        assert "FlateDecode" in str(exc_info.value)

    def test_step_limit_accumulates_chunks_within_one_step(self):
        budget = DecodeBudget(total_limit=1000, step_limit=10)
        budget.begin_step("layer")
        budget.charge("layer", 6)
        with pytest.raises(PDFDecodeBudgetExceeded):
            budget.charge("layer", 5)
        # A new step resets the per-step counter but not the total.
        budget.begin_step("next")
        budget.charge("next", 4)
        assert budget.total_consumed == 10


class TestBoundedDecoders:
    def test_flate_stream_decodes_with_sufficient_budget(self):
        plain = b"hello world " * 100
        budget = DecodeBudget(total_limit=10_000, step_limit=10_000)
        stream = PDFStream(
            {"Filter": LIT("FlateDecode")},
            zlib.compress(plain),
            budget=budget,
        )
        assert stream.get_data() == plain
        assert budget.total_consumed == len(plain)

    def test_flate_stops_before_full_allocation(self):
        plain = b"boom " * 10_000
        budget = DecodeBudget(total_limit=100, step_limit=10_000)
        stream = PDFStream(
            {"Filter": LIT("FlateDecode")},
            zlib.compress(plain),
            budget=budget,
        )
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            stream.get_data()
        assert "FlateDecode" in str(exc_info.value)
        # A failed decode must not leave a cached partial result behind.
        assert stream.data is None

    def test_flate_bomb_does_not_allocate_full_output(self):
        import tracemalloc

        encoded_bomb = zlib.compress(b"\x00" * (1024 * 1024), level=9)
        assert len(encoded_bomb) < 2048
        budget = DecodeBudget(total_limit=4096, step_limit=4096)
        stream = PDFStream(
            {"Filter": LIT("FlateDecode")},
            encoded_bomb,
            budget=budget,
        )
        tracemalloc.start()
        try:
            with pytest.raises(PDFDecodeBudgetExceeded):
                stream.get_data()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # The full one-megabyte output must never be allocated.
        assert peak < 100 * 1024
        assert stream.data is None

    def test_lzw_decode_charges_incrementally(self):
        budget = DecodeBudget(total_limit=100, step_limit=100)
        assert lzwdecode(LZW_SAMPLE, budget=budget) == LZW_DECODED
        assert budget.total_consumed == len(LZW_DECODED)

    def test_lzw_stops_inside_decoder(self):
        budget = DecodeBudget(total_limit=3, step_limit=100)
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            lzwdecode(LZW_SAMPLE, budget=budget)
        assert "LZWDecode" in str(exc_info.value)

    def test_runlength_budget(self):
        encoded = b"\x05123456\xfa7\x04abcde\x80junk"
        budget = DecodeBudget(total_limit=100, step_limit=100)
        assert rldecode(encoded, budget=budget) == b"1234567777777abcde"
        tight = DecodeBudget(total_limit=5, step_limit=100)
        with pytest.raises(PDFDecodeBudgetExceeded):
            rldecode(encoded, budget=tight)

    def test_ascii85_budget_matches_unbounded_output(self):
        encoded = a85encode(b"Man is distinguished")
        budget = DecodeBudget(total_limit=100, step_limit=100)
        assert ascii85decode(encoded, budget=budget) == b"Man is distinguished"
        assert budget.total_consumed == len(b"Man is distinguished")

    def test_ascii85_z_abbreviation_charges_four_bytes(self):
        budget = DecodeBudget(total_limit=4, step_limit=100)
        assert ascii85decode(b"z", budget=budget) == b"\x00\x00\x00\x00"
        exhausted = DecodeBudget(total_limit=3, step_limit=100)
        with pytest.raises(PDFDecodeBudgetExceeded):
            ascii85decode(b"z", budget=exhausted)

    def test_ascii85_partial_groups_match_stdlib(self):
        from base64 import a85decode as std_a85decode

        budget = DecodeBudget(total_limit=1000, step_limit=1000)
        for payload in (b"a", b"ab", b"abc", b"abcd", b"x" * 57):
            encoded = a85encode(payload)
            assert ascii85decode(encoded, budget=budget) == std_a85decode(encoded)
        # A 'z' at a boundary emits four zero bytes and resets the group.
        assert ascii85decode(b"9jqo^z", budget=budget) == std_a85decode(b"9jqo^z")

    def test_asciihex_budget_uses_exact_output_size(self):
        budget = DecodeBudget(total_limit=3, step_limit=100)
        assert asciihexdecode(b"61 62 63", budget=budget) == b"abc"
        assert budget.total_consumed == 3
        with pytest.raises(PDFDecodeBudgetExceeded):
            asciihexdecode(b"61 62 63", budget=DecodeBudget(total_limit=2))

    def test_png_predictor_budget(self):
        encoded = bytes([0, 1, 2, 0, 3, 4])
        budget = DecodeBudget(total_limit=100, step_limit=100)
        result = apply_png_predictor(
            12, 1, 2, 8, encoded, budget=budget, layer="PNG predictor"
        )
        assert result == b"\x01\x02\x03\x04"
        assert budget.total_consumed == 4

    def test_tiff_predictor_budget(self):
        encoded = b"\x01\x02\x03\x04"
        budget = DecodeBudget(total_limit=100, step_limit=100)
        result = apply_tiff_predictor(
            1, 2, 8, encoded, budget=budget, layer="TIFF predictor"
        )
        assert result == b"\x01\x03\x03\x07"
        assert budget.total_consumed == 4

    def test_ccitt_charges_each_scanline(self):
        budget = DecodeBudget(total_limit=1, step_limit=100)
        decoder = CCITTFaxDecoder(5, budget=budget)
        decoder.output_line(0, b"00000")  # five bits -> one byte
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            decoder.output_line(1, b"00000")
        assert "CCITTFaxDecode" in str(exc_info.value)

    def test_ccitt_step_limit_covers_whole_line(self):
        budget = DecodeBudget(total_limit=100, step_limit=1)
        decoder = CCITTFaxDecoder(16, budget=budget)
        with pytest.raises(PDFDecodeBudgetExceeded):
            decoder.output_line(0, [0] * 16)  # sixteen bits -> two bytes


class TestStreamFilterChains:
    def _ascii85_flate_stream(self, plain: bytes, budget: DecodeBudget) -> PDFStream:
        encoded = a85encode(zlib.compress(plain))
        return PDFStream(
            {"Filter": [LIT("ASCII85Decode"), LIT("FlateDecode")]},
            encoded,
            budget=budget,
        )

    def test_chain_decodes_when_budget_covers_every_step(self):
        plain = b"chain " * 50
        budget = DecodeBudget(total_limit=100_000, step_limit=100_000)
        stream = self._ascii85_flate_stream(plain, budget)
        assert stream.get_data() == plain

    def test_chain_checks_every_step_not_only_final_size(self):
        plain = b"chain " * 50
        flate_payload = zlib.compress(plain)
        # Enough for the ASCII85 step (its output is the flate payload)
        # but not for the following Flate expansion.
        budget = DecodeBudget(total_limit=len(flate_payload), step_limit=100_000)
        stream = self._ascii85_flate_stream(plain, budget)
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            stream.get_data()
        assert "filter 1" in str(exc_info.value)
        assert "FlateDecode" in str(exc_info.value)

    def test_step_limit_stops_at_first_filter(self):
        plain = b"chain " * 50
        budget = DecodeBudget(total_limit=100_000, step_limit=4)
        stream = self._ascii85_flate_stream(plain, budget)
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            stream.get_data()
        assert "filter 0" in str(exc_info.value)
        assert "ASCII85Decode" in str(exc_info.value)

    def test_lzw_then_flate_combination(self):
        # Encode LZW payload and wrap it in Flate; decoding runs Flate
        # first (filter index 0) and LZW second (filter index 1).
        encoded = zlib.compress(LZW_SAMPLE)
        budget = DecodeBudget(total_limit=100, step_limit=100)
        stream = PDFStream(
            {"Filter": [LIT("FlateDecode"), LIT("LZWDecode")]},
            encoded,
            budget=budget,
        )
        assert stream.get_data() == LZW_DECODED

    def test_predictor_is_its_own_budget_layer(self):
        encoded = bytes([0, 1, 2, 0, 3, 4])
        params = {
            "Predictor": 12,
            "Columns": 2,
            "Colors": 1,
            "BitsPerComponent": 8,
        }
        # Flate output is six bytes; leave no room for the predictor
        # output which is four bytes.
        budget = DecodeBudget(total_limit=6, step_limit=1000)
        stream = PDFStream(
            {"Filter": LIT("FlateDecode"), "DecodeParms": params},
            zlib.compress(encoded),
            budget=budget,
        )
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            stream.get_data()
        assert "predictor" in str(exc_info.value)


class TestInlineImageBudget:
    def _parse_inline_streams(
        self, content: bytes, budget: DecodeBudget
    ) -> list[PDFStream]:
        # The outer content stream carries the document budget; the
        # PDFContentParser must propagate it to inline image streams.
        outer = PDFStream({}, content, budget=budget)
        parser = PDFContentParser([outer], budget=budget)
        inline_streams = []
        while True:
            try:
                _, obj = parser.nextobject()
            except PSEOF:
                break
            if isinstance(obj, PDFStream):
                inline_streams.append(obj)
        return inline_streams

    def test_inline_flate_image_uses_document_budget(self):
        image = bytes([10, 20, 30, 40])
        content = (
            b"q 100 0 0 100 0 0 cm BI /W 4 /H 1 /CS /G /BPC 8 "
            b"/F /FlateDecode ID " + zlib.compress(image) + b" EI Q"
        )
        budget = DecodeBudget(total_limit=1000, step_limit=1000)
        (inline,) = self._parse_inline_streams(content, budget)
        assert inline.budget is budget
        assert inline.get_data() == image
        assert budget.total_consumed == len(image)

    def test_inline_flate_image_respects_tight_budget(self):
        image = bytes([10, 20, 30, 40])
        content = (
            b"q 100 0 0 100 0 0 cm BI /W 4 /H 1 /CS /G /BPC 8 "
            b"/F /FlateDecode ID " + zlib.compress(image) + b" EI Q"
        )
        budget = DecodeBudget(total_limit=2, step_limit=1000)
        (inline,) = self._parse_inline_streams(content, budget)
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            inline.get_data()
        assert "FlateDecode" in str(exc_info.value)


class TestDocumentBudget:
    def test_budget_accumulates_across_streams(self):
        first = b"A" * 50
        second = b"B" * 70
        pdf = make_pdf(dict([flate_stream(3, first), flate_stream(4, second)]))
        parser = PDFParser(BytesIO(pdf))
        budget = DecodeBudget(total_limit=10_000, step_limit=10_000)
        doc = PDFDocument(parser, decode_budget=budget)
        assert doc.getobj(3).get_data() == first
        assert doc.getobj(4).get_data() == second
        assert budget.total_consumed == 120

    def test_budget_exhausted_between_streams_names_layer(self):
        first = b"A" * 50
        second = b"B" * 70
        pdf = make_pdf(dict([flate_stream(3, first), flate_stream(4, second)]))
        parser = PDFParser(BytesIO(pdf))
        budget = DecodeBudget(total_limit=60, step_limit=10_000)
        doc = PDFDocument(parser, decode_budget=budget)
        assert doc.getobj(3).get_data() == first
        with pytest.raises(PDFDecodeBudgetExceeded) as exc_info:
            doc.getobj(4).get_data()
        assert "FlateDecode" in str(exc_info.value)

    def test_cached_read_is_not_charged_twice(self):
        pdf = make_pdf(dict([flate_stream(3, b"cached " * 10)]))
        parser = PDFParser(BytesIO(pdf))
        budget = DecodeBudget(total_limit=10_000, step_limit=10_000)
        doc = PDFDocument(parser, decode_budget=budget)
        stream = doc.getobj(3)
        first = stream.get_data()
        consumed = budget.total_consumed
        second = stream.get_data()
        assert first is second
        assert budget.total_consumed == consumed

    def test_reread_after_exhaustion_cannot_bypass_limit(self):
        pdf = make_pdf(dict([flate_stream(3, b"x" * 100)]))
        parser = PDFParser(BytesIO(pdf))
        budget = DecodeBudget(total_limit=10, step_limit=10_000)
        doc = PDFDocument(parser, decode_budget=budget)
        stream = doc.getobj(3)
        for _ in range(2):
            with pytest.raises(PDFDecodeBudgetExceeded):
                stream.get_data()
        assert stream.data is None

    def test_high_compression_remains_readable_with_adequate_budget(self):
        # A highly compressible payload: tiny input, large output.
        payload = b"Z" * 5000
        pdf = make_pdf(dict([flate_stream(3, payload)]))
        budget = DecodeBudget(total_limit=10_000, step_limit=10_000)
        parser = PDFParser(BytesIO(pdf))
        doc = PDFDocument(parser, decode_budget=budget)
        assert doc.getobj(3).get_data() == payload

    def test_high_level_api_forwards_budget(self):
        content = b"BT /F1 12 Tf 100 700 Td (Hello) Tj ET" * 50
        pdf = make_page_pdf(content)
        tight = DecodeBudget(total_limit=10, step_limit=10_000)
        with pytest.raises(PDFDecodeBudgetExceeded):
            extract_text(BytesIO(pdf), decode_budget=tight)
        # A generous budget still parses the same document.
        generous = DecodeBudget(total_limit=100_000, step_limit=100_000)
        extract_text(BytesIO(pdf), decode_budget=generous)

    def test_extract_text_accepts_budget(self):
        # Simply ensure the keyword is wired through the public entry point.
        pdf = make_page_pdf(b"BT /F1 12 Tf 100 700 Td (Hello) Tj ET")
        budget = DecodeBudget(total_limit=100_000, step_limit=100_000)
        extract_text(BytesIO(pdf), decode_budget=budget)

    def test_document_without_budget_keeps_legacy_behavior(self):
        payload = b"legacy " * 100
        pdf = make_pdf(dict([flate_stream(3, payload)]))
        parser = PDFParser(BytesIO(pdf))
        doc = PDFDocument(parser)
        assert doc.decode_budget is None
        assert doc.getobj(3).get_data() == payload
