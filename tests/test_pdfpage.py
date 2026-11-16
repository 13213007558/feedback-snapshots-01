import hashlib
import io

import pytest

from pdfminer.high_level import extract_pages, extract_text, extract_text_to_fp
from pdfminer.layout import LTTextContainer
from pdfminer.pdfdocument import PDFDocument, PDFTextExtractionNotAllowed
from pdfminer.pdfexceptions import PDFValueError
from pdfminer.pdfpage import ExtractionPolicy, PDFPage
from pdfminer.pdfparser import PDFParser
from tests.helpers import absolute_sample_path


class TestPdfPage:
    def test_page_labels(self):
        path = absolute_sample_path("contrib/pagelabels.pdf")
        expected_labels = ["iii", "iv", "1", "2", "1"]

        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for i, page in enumerate(PDFPage.create_pages(doc)):
                assert page.label == expected_labels[i]


def _sample_text(
    path: str,
    check_extractable: bool = False,
    extraction_policy: ExtractionPolicy | None = None,
) -> str:
    return "".join(
        element.get_text()
        for page in extract_pages(
            path,
            check_extractable=check_extractable,
            extraction_policy=extraction_policy,
        )
        for element in page
        if isinstance(element, LTTextContainer)
    )


def _sha256(path: str) -> str:
    with open(path, "rb") as fp:
        return hashlib.sha256(fp.read()).hexdigest()


@pytest.fixture
def restricted_path() -> str:
    return absolute_sample_path("contrib/issue-00352-asw-oct96-p41.pdf")


class TestExtractionPermission:
    def test_default_warns_and_extracts(self, restricted_path, caplog):
        text = _sample_text(restricted_path)
        assert text.strip()
        assert "should not allow text extraction" in caplog.text

    def test_check_extractable_raises_in_every_high_level_entry(
        self,
        restricted_path,
    ):
        with pytest.raises(PDFTextExtractionNotAllowed):
            extract_text(restricted_path, check_extractable=True)
        with pytest.raises(PDFTextExtractionNotAllowed):
            list(extract_pages(restricted_path, check_extractable=True))
        with (
            open(restricted_path, "rb") as fp,
            pytest.raises(PDFTextExtractionNotAllowed),
        ):
            extract_text_to_fp(fp, io.BytesIO(), check_extractable=True)

    def test_unknown_keywords_are_not_silently_ignored(self, restricted_path):
        with open(restricted_path, "rb") as fp, pytest.raises(PDFValueError):
            extract_text_to_fp(fp, io.BytesIO(), check_extractabl=True)

    def test_policy_denies_by_default(self, restricted_path):
        policy = ExtractionPolicy()
        with pytest.raises(PDFTextExtractionNotAllowed):
            _sample_text(restricted_path, extraction_policy=policy)

    def test_grant_is_scoped_to_named_document(self, restricted_path, caplog):
        allowed = ExtractionPolicy(
            [_sha256(restricted_path)],
            granted=True,
            grant_reason="case 2026-11-17 forensic review",
        )
        assert _sample_text(restricted_path, extraction_policy=allowed).strip()
        assert "application grant was supplied" in caplog.text

        other = absolute_sample_path("simple1.pdf")
        # A grant naming the restricted document must not authorize another
        # document, even though that other document allows extraction anyway.
        with open(restricted_path, "rb") as first, open(other, "rb") as second:
            first_doc = PDFDocument(PDFParser(first))
            second_doc = PDFDocument(PDFParser(second))
            assert allowed.bind(first_doc, _sha256(restricted_path)).granted
            assert not allowed.bind(second_doc, _sha256(other)).granted

    def test_grant_requires_digest_and_reason(self):
        with pytest.raises(PDFValueError):
            ExtractionPolicy(granted=True, grant_reason="no documents named")
        with pytest.raises(PDFValueError):
            ExtractionPolicy(["0" * 64], granted=True)

    def test_audit_record_marks_decision_layer(self, restricted_path):
        digest = _sha256(restricted_path)
        policy = ExtractionPolicy([digest], granted=True, grant_reason="warrant 42")
        with open(restricted_path, "rb") as fp:
            document = PDFDocument(PDFParser(fp))
            record = policy.bind(document, digest).audit_record()
        assert record["decided_by"] == "application_grant"
        assert record["application_grant"] is True
        assert record["grant_reason"] == "warrant 42"
        assert record["permission_bits"] == 4294965956
        assert record["password_role"] == "user"
        assert record["document_sha256"] == digest

    def test_denied_path_produces_no_text(self, restricted_path):
        policy = ExtractionPolicy()
        with pytest.raises(PDFTextExtractionNotAllowed):
            _sample_text(restricted_path, extraction_policy=policy)
