import hashlib
import itertools
import logging
from collections.abc import Collection, Container, Iterator
from typing import Any, BinaryIO, ClassVar

from pdfminer import settings
from pdfminer.pdfdocument import (
    PDFDocument,
    PDFNoPageLabels,
    PDFTextExtractionNotAllowed,
)
from pdfminer.pdfexceptions import PDFObjectNotFound, PDFValueError
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import dict_value, int_value, list_value, resolve1
from pdfminer.psparser import LIT
from pdfminer.utils import Rect, parse_rect

log = logging.getLogger(__name__)

# some predefined literals and keywords.
LITERAL_PAGE = LIT("Page")
LITERAL_PAGES = LIT("Pages")


def _document_digest(fp: BinaryIO) -> str:
    """Return the SHA-256 of the whole PDF, restoring the stream position."""
    position = fp.tell()
    digest = hashlib.sha256()
    try:
        fp.seek(0)
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    finally:
        fp.seek(position)
    return digest.hexdigest()


class ExtractionPolicy:
    """Application-level extraction authorization for named documents.

    A grant names the exact documents it applies to, by SHA-256 of the PDF
    bytes. It is therefore impossible for one grant to authorize a different
    file, and no module-level or process-wide switch is involved. A grant
    without ``doc_digests`` is rejected: the caller must say which documents
    the authorization covers.

    Decryption and authorization are deliberately separate. A correct user or
    owner password only proves access to the cipher; it never implies that the
    application is allowed to extract text. ``granted`` is the application's
    explicit authorization to ignore the document's ``/P`` bits, and the reason
    is carried into the audit record.

    :param doc_digests: SHA-256 hex digests of the documents this policy may
        authorize for extraction.
    :param granted: Whether the application grants extraction for these
        documents despite their ``/P`` bits.
    :param grant_reason: Human-readable justification, required when
        ``granted`` is true.
    """

    def __init__(
        self,
        doc_digests: Collection[str] = (),
        granted: bool = False,
        grant_reason: str | None = None,
    ) -> None:
        if granted and not doc_digests:
            error_msg = "An extraction grant must name the document digests it covers"
            raise PDFValueError(error_msg)
        if granted and not grant_reason:
            error_msg = "An extraction grant requires a non-empty reason for audit"
            raise PDFValueError(error_msg)
        self.doc_digests = frozenset(doc_digests)
        self.granted = granted
        self.grant_reason = grant_reason

    def bind(self, document: PDFDocument, doc_digest: str) -> "ExtractionDecision":
        return ExtractionDecision(document, self, doc_digest)


class ExtractionDecision:
    """The result of applying one :class:`ExtractionPolicy` to one document."""

    def __init__(
        self,
        document: PDFDocument,
        policy: ExtractionPolicy,
        doc_digest: str,
    ) -> None:
        self.document = document
        self.policy = policy
        self.doc_digest = doc_digest

    @property
    def allowed_by_pdf(self) -> bool:
        """Whether the document's declared permission bits allow extraction."""
        return self.document.is_extractable

    @property
    def granted(self) -> bool:
        """Whether this specific document is covered by the application grant."""
        return (
            self.policy.granted
            and self.doc_digest in self.policy.doc_digests
            and self.document.encryption is not None
        )

    @property
    def decided_by(self) -> str:
        """Which layer produced the current decision.

        ``pdf_permission`` means the document declaration was followed,
        ``application_grant`` means an explicit grant allowed extraction, and
        ``unencrypted`` means there was no declaration to honor.
        """
        if self.document.encryption is None:
            return "unencrypted"
        if not self.allowed_by_pdf and self.granted:
            return "application_grant"
        return "pdf_permission"

    @property
    def allowed(self) -> bool:
        if self.document.encryption is None:
            return True
        return self.allowed_by_pdf or self.granted

    def audit_record(self, action: str = "extract_text") -> dict[str, Any]:
        """Return a JSON-serializable record of this decision."""
        return {
            "action": action,
            "document_sha256": self.doc_digest,
            "document_encrypted": self.document.encryption is not None,
            "pdf_permission_extract": self.allowed_by_pdf,
            "permission_bits": self.document.permissions,
            "password_role": self.document.password_role,
            "perms_verified": self.document.perms_verified,
            "application_grant": self.granted,
            "grant_reason": self.policy.grant_reason if self.granted else None,
            "decided_by": self.decided_by,
            "allowed": self.allowed,
        }

    def check(self, source: object = None) -> None:
        """Raise when extraction is not allowed under this decision."""
        if not self.allowed:
            error_msg = (
                f"Text extraction is not allowed: {source!r} "
                f"(permission_bits={self.document.permissions!r})"
            )
            raise PDFTextExtractionNotAllowed(error_msg)
        if not self.allowed_by_pdf and self.granted:
            log.warning(
                "Extracting text from %r despite the document's permission "
                "bits because an application grant was supplied: %s",
                source,
                self.policy.grant_reason,
            )


class PDFPage:
    """An object that holds the information about a page.

    A PDFPage object is merely a convenience class that has a set
    of keys and values, which describe the properties of a page
    and point to its contents.

    Attributes
    ----------
      doc: a PDFDocument object.
      pageid: any Python object that can uniquely identify the page.
      attrs: a dictionary of page attributes.
      contents: a list of PDFStream objects that represents the page content.
      lastmod: the last modified time of the page.
      resources: a dictionary of resources used by the page.
      mediabox: the physical size of the page.
      cropbox: the crop rectangle of the page.
      rotate: the page rotation (in degree).
      annots: the page annotations.
      beads: a chain that represents natural reading order.
      label: the page's label (typically, the logical page number).

    """

    def __init__(
        self,
        doc: PDFDocument,
        pageid: object,
        attrs: object,
        label: str | None,
    ) -> None:
        """Initialize a page object.

        doc: a PDFDocument object.
        pageid: any Python object that can uniquely identify the page.
        attrs: a dictionary of page attributes.
        label: page label string.
        """
        self.doc = doc
        self.pageid = pageid
        self.attrs = dict_value(attrs)
        self.label = label
        self.lastmod = resolve1(self.attrs.get("LastModified"))
        self.resources: dict[object, object] = resolve1(
            self.attrs.get("Resources", {}),
        )

        self.mediabox = self._parse_mediabox(self.attrs.get("MediaBox"))
        self.cropbox = self._parse_cropbox(self.attrs.get("CropBox"), self.mediabox)
        self.contents = self._parse_contents(self.attrs.get("Contents"))

        self.rotate = (int_value(self.attrs.get("Rotate", 0)) + 360) % 360
        self.annots = self.attrs.get("Annots")
        self.beads = self.attrs.get("B")

    def __repr__(self) -> str:
        return f"<PDFPage: Resources={self.resources!r}, MediaBox={self.mediabox!r}>"

    INHERITABLE_ATTRS: ClassVar[set[str]] = {
        "Resources",
        "MediaBox",
        "CropBox",
        "Rotate",
    }

    @classmethod
    def create_pages(cls, document: PDFDocument) -> Iterator["PDFPage"]:
        def depth_first_search(
            obj: Any,
            parent: dict[str, Any],
            visited: set[Any] | None = None,
        ) -> Iterator[tuple[int, dict[Any, dict[Any, Any]]]]:
            if isinstance(obj, int):
                object_id = obj
                object_properties = dict_value(document.getobj(object_id)).copy()
            else:
                # This looks broken. obj.objid means obj could be either
                # PDFObjRef or PDFStream, but neither is valid for dict_value.
                object_id = obj.objid  # type: ignore[attr-defined]
                object_properties = dict_value(obj).copy()

            # Avoid recursion errors by keeping track of visited nodes
            if visited is None:
                visited = set()
            if object_id in visited:
                return
            visited.add(object_id)

            for k, v in parent.items():
                if k in cls.INHERITABLE_ATTRS and k not in object_properties:
                    object_properties[k] = v

            object_type = object_properties.get("Type")
            if object_type is None and not settings.STRICT:  # See #64
                object_type = object_properties.get("type")

            if object_type is LITERAL_PAGES and "Kids" in object_properties:
                log.debug("Pages: Kids=%r", object_properties["Kids"])
                for child in list_value(object_properties["Kids"]):
                    yield from depth_first_search(child, object_properties, visited)

            elif object_type is LITERAL_PAGE:
                log.debug("Page: %r", object_properties)
                yield (object_id, object_properties)

        try:
            page_labels: Iterator[str | None] = document.get_page_labels()
        except PDFNoPageLabels:
            page_labels = itertools.repeat(None)

        pages = False
        if "Pages" in document.catalog:
            objects = depth_first_search(document.catalog["Pages"], document.catalog)
            for objid, tree in objects:
                yield cls(document, objid, tree, next(page_labels))
                pages = True
        if not pages:
            # fallback when /Pages is missing.
            for xref in document.xrefs:
                for objid in xref.get_objids():
                    try:
                        obj = document.getobj(objid)
                        if isinstance(obj, dict) and obj.get("Type") is LITERAL_PAGE:
                            yield cls(document, objid, obj, next(page_labels))
                    except PDFObjectNotFound:
                        pass

    @classmethod
    def get_pages(
        cls,
        fp: BinaryIO,
        pagenos: Container[int] | None = None,
        maxpages: int = 0,
        password: str = "",
        caching: bool = True,
        check_extractable: bool = False,
        extraction_policy: ExtractionPolicy | None = None,
    ) -> Iterator["PDFPage"]:
        # Create a PDF parser object associated with the file object.
        parser = PDFParser(fp)
        # Create a PDF document object that stores the document structure.
        doc = PDFDocument(parser, password=password, caching=caching)
        if extraction_policy is not None:
            extraction_policy.bind(doc, _document_digest(fp)).check(fp)
        # Check if the document allows text extraction.
        # If not, warn the user and proceed.
        elif not doc.is_extractable:
            if check_extractable:
                error_msg = f"Text extraction is not allowed: {fp!r}"
                raise PDFTextExtractionNotAllowed(error_msg)
            else:
                warning_msg = (
                    f"The PDF {fp!r} contains a metadata field "
                    "indicating that it should not allow "
                    "text extraction. Ignoring this field "
                    "and proceeding. Use the check_extractable "
                    "if you want to raise an error in this case"
                )
                log.warning(warning_msg)
        # Process each page contained in the document.
        for pageno, page in enumerate(cls.create_pages(doc)):
            if pagenos and (pageno not in pagenos):
                continue
            yield page
            if maxpages and maxpages <= pageno + 1:
                break

    def _parse_mediabox(self, value: Any) -> Rect:
        us_letter = (0.0, 0.0, 612.0, 792.0)

        if value is None:
            log.warning(
                "MediaBox missing from /Page (and not inherited), "
                "defaulting to US Letter"
            )
            return us_letter

        try:
            return parse_rect(resolve1(val) for val in resolve1(value))

        except PDFValueError:
            log.warning("Invalid MediaBox in /Page, defaulting to US Letter")
            return us_letter

    def _parse_cropbox(self, value: Any, mediabox: Rect) -> Rect:
        if value is None:
            # CropBox is optional, and MediaBox is used if not specified.
            return mediabox

        try:
            return parse_rect(resolve1(val) for val in resolve1(value))

        except PDFValueError:
            log.warning("Invalid CropBox in /Page, defaulting to MediaBox")
            return mediabox

    def _parse_contents(self, value: Any) -> list[Any]:
        contents: list[Any] = []
        if value is not None:
            contents = resolve1(value)
            if not isinstance(contents, list):
                contents = [contents]
        return contents
