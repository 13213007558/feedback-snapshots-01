import io
import itertools

import pytest

from pdfminer.pdfdocument import PDFDocument, PDFNoPageLabels
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser, PDFSyntaxError
from pdfminer.pdftypes import dict_value, int_value, stream_value
from tests.helpers import absolute_sample_path


class TestPdfDocument:
    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open(absolute_sample_path("simple1.pdf"), "rb") as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            with pytest.raises(PDFObjectNotFound):
                doc.getobj(0)

    def test_encrypted_no_id(self):
        # Some documents may be encrypted but not have an /ID key in
        # their trailer. Tests
        # https://github.com/pdfminer/pdfminer.six/issues/594
        path = absolute_sample_path("encryption/encrypted_doc_no_id.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            assert doc.info == [{"Producer": b"European Patent Office"}]

    def test_page_labels(self):
        path = absolute_sample_path("contrib/pagelabels.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            total_pages = int_value(dict_value(doc.catalog["Pages"])["Count"])
            assert list(itertools.islice(doc.get_page_labels(), total_pages)) == [
                "iii",
                "iv",
                "1",
                "2",
                "1",
            ]

    def test_no_page_labels(self):
        path = absolute_sample_path("simple1.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)

            with pytest.raises(PDFNoPageLabels):
                doc.get_page_labels()

    def test_annotations(self):
        path = absolute_sample_path("contrib/issue-1082-annotations.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for _i, page in enumerate(PDFPage.create_pages(doc)):
                print(page)


class _ObjStmPdfBuilder:
    """Build a minimal PDF with two text objects in one object stream.

    Objects 10 and 11 hold the strings "(AAAA)" and "(BBBB)". ``body_order``
    controls their physical order, ``header`` controls the (objid, body
    index, offset) triples written to the object stream header, and
    ``compressed`` controls the xref ``(stream objid, index)`` pairs.
    """

    BODY_A = b"(AAAA)"
    BODY_B = b"(BBBB)"

    def __init__(
        self,
        *,
        body_order: tuple[bytes, bytes] = (BODY_A, BODY_B),
        header: list[tuple[int, int, int | None]] | None = None,
        header_gap: bytes = b"",
        compressed: list[tuple[int, int]] | None = None,
        omit_first: bool = False,
    ) -> None:
        self.body_order = body_order
        self.header_gap = header_gap
        self.omit_first = omit_first
        self.header = header or [(10, 0, None), (11, 1, None)]
        self.compressed = compressed or [(5, 0), (5, 1)]

    def build(self) -> bytes:
        out = bytearray(b"%PDF-1.7\n")
        offsets: dict[int, int] = {}

        def add(objid: int, content: bytes) -> None:
            offsets[objid] = len(out)
            out.extend(f"{objid} 0 obj\n".encode())
            out.extend(content)
            out.extend(b"\nendobj\n")

        add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
        add(2, b"<< /Type /Pages /Kids [] /Count 0 >>")

        # Offsets of the two bodies relative to First, in physical order.
        body_starts: list[int] = []
        position = 0
        for body in self.body_order:
            body_starts.append(position)
            position += len(body) + 1  # separating space
        bodies = b" ".join(self.body_order)

        header_text = b""
        for header_objid, body_index, offset in self.header:
            if offset is None:
                offset = body_starts[body_index]
            header_text += f"{header_objid} {offset} ".encode()
        first = len(header_text) + len(self.header_gap)
        data = header_text + self.header_gap + bodies
        first_entry = "" if self.omit_first else f" /First {first}"
        add(
            5,
            f"<< /Type /ObjStm /N {len(self.header)}{first_entry} "
            f"/Length {len(data)} >>\nstream\n".encode()
            + data
            + b"\nendstream",
        )

        xref_offset = len(out)
        entries = [bytes([0]) + (0).to_bytes(2, "big") + bytes([0])]
        for oid in (1, 2):
            entries.append(bytes([1]) + offsets[oid].to_bytes(2, "big") + bytes([0]))
        entries.append(bytes([1]) + offsets[5].to_bytes(2, "big") + bytes([0]))
        entries.append(bytes([1]) + xref_offset.to_bytes(2, "big") + bytes([0]))
        for strmid, index in self.compressed:
            entries.append(bytes([2]) + strmid.to_bytes(2, "big") + bytes([index]))
        xref_data = b"".join(entries)
        add(
            6,
            b"<< /Type /XRef /Size 12 /W [1 2 1] /Index [0 3 5 2 10 2] "
            b"/Root 1 0 R /Length %d >>\nstream\n"
            % len(xref_data)
            + xref_data
            + b"\nendstream",
        )
        out.extend(f"startxref\n{xref_offset}\n%%EOF\n".encode())
        return bytes(out)


def _open_objstm_document(data: bytes, caching: bool = True) -> PDFDocument:
    return PDFDocument(PDFParser(io.BytesIO(data)), caching=caching)


class TestObjStm:
    def test_objects_are_located_by_header_objid(self):
        doc = _open_objstm_document(_ObjStmPdfBuilder().build())
        assert doc.getobj(10) == b"AAAA"
        assert doc.getobj(11) == b"BBBB"

    def test_xref_index_controls_which_header_entry_is_used(self):
        # Swapping the two xref indices makes objid 10 resolve through the
        # header entry for objid 11 and must not return "(BBBB)".
        data = _ObjStmPdfBuilder(compressed=[(5, 1), (5, 0)]).build()
        for caching in (True, False):
            doc = _open_objstm_document(data, caching=caching)
            with pytest.raises(PDFObjectNotFound, match=r"10"):
                doc.getobj(10)
            with pytest.raises(PDFObjectNotFound, match=r"11"):
                doc.getobj(11)

    def test_offset_pointing_at_another_object_is_rejected(self):
        # Objid 10's header offset points at the body of objid 11.
        data = _ObjStmPdfBuilder(header=[(10, 0, 7), (11, 1, 0)]).build()
        for caching in (True, False):
            doc = _open_objstm_document(data, caching=caching)
            with pytest.raises(PDFObjectNotFound, match=r"points to another object"):
                doc.getobj(10)

    def test_offset_into_header_is_rejected(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, None), (11, 1, 1)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"object stream offset"):
            doc.getobj(11)

    def test_offset_beyond_stream_is_rejected(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, None), (11, 1, 99)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"object stream offset"):
            doc.getobj(11)

    def test_negative_offset_is_rejected(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, None), (11, 1, -1)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"negative offset"):
            doc.getobj(11)

    def test_first_inside_header_is_rejected(self):
        data = _ObjStmPdfBuilder().build()
        # Move First backwards so that it points into the header. The
        # substitution is length-preserving, leaving all xref offsets valid.
        old = b"/First 10"
        assert old in data
        broken = data.replace(old, b"/First 5  ", 1)
        doc = _open_objstm_document(broken)
        with pytest.raises(PDFObjectNotFound, match=r"overlaps body"):
            doc.getobj(10)

    def test_negative_index_is_rejected(self):
        doc = _open_objstm_document(_ObjStmPdfBuilder().build())
        stream = stream_value(doc.getobj(5))
        with pytest.raises(PDFSyntaxError, match=r"negative index"):
            doc._getobj_objstm(stream, -1, 10)

    def test_duplicate_header_objid_is_rejected(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, None), (10, 1, None)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"duplicate objid"):
            doc.getobj(10)

    def test_duplicate_header_offset_is_rejected(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, None), (11, 0, None)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"duplicate offset"):
            doc.getobj(11)

    def test_cache_does_not_change_resolution(self):
        data = _ObjStmPdfBuilder().build()
        cached = _open_objstm_document(data, caching=True)
        uncached = _open_objstm_document(data, caching=False)
        for objid in (10, 11):
            assert cached.getobj(objid) == uncached.getobj(objid)

    def test_legal_whitespace_and_body_order_are_supported(self):
        # Object 11 is stored before object 10, with extra header whitespace.
        data = _ObjStmPdfBuilder(
            body_order=(_ObjStmPdfBuilder.BODY_B, _ObjStmPdfBuilder.BODY_A),
            header=[(11, 0, None), (10, 1, None)],
            header_gap=b"\n  \t ",
            compressed=[(5, 1), (5, 0)],
        ).build()
        doc = _open_objstm_document(data)
        assert doc.getobj(10) == b"AAAA"
        assert doc.getobj(11) == b"BBBB"

    def test_error_reports_objid_and_stream_location(self):
        data = _ObjStmPdfBuilder(header=[(10, 0, 7), (11, 1, 0)]).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound) as excinfo:
            doc.getobj(10)
        message = str(excinfo.value)
        assert "objid=10" in message
        assert "stream=5" in message

    def test_missing_first_is_rejected(self):
        data = _ObjStmPdfBuilder(omit_first=True).build()
        doc = _open_objstm_document(data)
        with pytest.raises(PDFObjectNotFound, match=r"First is not defined"):
            doc.getobj(10)
