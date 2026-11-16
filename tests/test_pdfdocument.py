import itertools

import pytest

from pdfminer.pdfdocument import (
    PDFDocument,
    PDFNoPageLabels,
    PDFStandardSecurityHandlerV5,
)
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import dict_value, int_value
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

    def test_password_role_user_and_owner(self):
        path = absolute_sample_path("encryption/aes-256-r6.pdf")
        for password, role in (("usersecret", "user"), ("ownersecret", "owner")):
            with open(path, "rb") as fp:
                doc = PDFDocument(PDFParser(fp), password=password)
            assert doc.password_role == role
            assert doc.permissions == 0xFFFFFFFC

    def test_perms_entry_validates_declared_bits(self):
        path = absolute_sample_path("encryption/aes-256.pdf")
        with open(path, "rb") as fp:
            doc = PDFDocument(PDFParser(fp), password="foo")
        docid, param = doc.encryption
        assert doc.perms_verified is True

        tampered = dict(param, P=-17)
        handler = PDFStandardSecurityHandlerV5(docid, tampered, "foo")
        assert handler.perms_verified is False
        assert handler.is_extractable() is False

    def test_unencrypted_document_has_no_declaration(self):
        with open(absolute_sample_path("simple1.pdf"), "rb") as fp:
            doc = PDFDocument(PDFParser(fp))
        assert doc.encryption is None
        assert doc.permissions is None
        assert doc.password_role is None
        assert doc.perms_verified is None

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
