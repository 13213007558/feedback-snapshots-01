"""ActualText-aware forensic extraction.

The PDF accessibility model lets a marked-content sequence carry an
``/ActualText`` property that assistive technology must read *in place of*
whatever glyphs are painted inside that sequence (PDF 1.7, §14.9.4). The
painted glyphs and the replacement text are two distinct pieces of evidence:
a document may, deliberately or through corruption, display one string while
exposing a different one to screen readers.

This module keeps those two channels separate instead of concatenating them:

* the **reading** channel is what an accessible reader announces, honouring
  every ``/ActualText`` replacement (and suppressing the glyphs it replaces);
* the **drawn** channel is the Unicode recovered from the glyphs that are
  actually painted, regardless of any replacement.

It handles nested marked-content sequences, property dictionaries referenced
by name through the ``Properties`` resource dictionary, and the independent
resource dictionaries of Form XObjects. Marked-content sequences that are not
closed before their content stream ends are reported as locatable diagnostics.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Container
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO, Optional, cast

from pdfminer.pdfdevice import PDFDevice, PDFTextSeq
from pdfminer.pdffont import PDFFont, PDFUnicodeNotDefined
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from pdfminer.psparser import PSLiteral, literal_name
from pdfminer.utils import FileOrName, Matrix, Rect, make_compat_str, open_filename

if TYPE_CHECKING:
    from pdfminer.pdfinterp import (
        PDFGraphicState,
        PDFResourceManager,
        PDFStackT,
        PDFTextState,
        TagLocation,
    )

log = logging.getLogger(__name__)

ACTUAL_TEXT_KEY = "ActualText"
LANG_KEY = "Lang"
MCID_KEY = "MCID"


def _decode_drawn(textstate: PDFTextState, seq: PDFTextSeq) -> str:
    """Recover the Unicode of the glyphs that are actually painted."""
    font = textstate.font
    assert font is not None
    pieces: list[str] = []
    for obj in seq:
        if isinstance(obj, str):
            obj = obj.encode("latin-1", "ignore")
        if not isinstance(obj, bytes):
            # Numeric entries are kerning/position adjustments, not glyphs.
            continue
        for cid in font.decode(obj):
            try:
                pieces.append(font.to_unichr(cid))
            except PDFUnicodeNotDefined:
                pieces.append(_replacement_glyph(font, cid))
    return "".join(pieces)


def _replacement_glyph(font: PDFFont, cid: int) -> str:
    fontname = getattr(font, "fontname", None) or font.__class__.__name__
    return f"\\u{cid:04x}({fontname})"


@dataclass
class MarkedContent:
    """A single marked-content sequence (``BMC``/``BDC`` ... ``EMC``).

    The sequence body is kept in :attr:`content` in strict document order:
    a ``str`` is glyph evidence painted directly into the sequence, while a
    nested :class:`MarkedContent` represents an inner marked-content span.
    Keeping both kinds of entry in one list preserves the relative order of
    painted text and nested marks, which separate lists would scramble.
    """

    tag: str
    location: TagLocation
    mcid: int | None = None
    actual_text: str | None = None
    lang: str | None = None
    properties: dict[str, object] = field(default_factory=dict)
    content: list[str | MarkedContent] = field(default_factory=list)
    parent: Optional[MarkedContent] = field(default=None, repr=False)
    closed: bool = False

    @property
    def is_point(self) -> bool:
        """Marked-content points (``MP``/``DP``) never wrap glyphs."""
        return False

    @property
    def children(self) -> list[MarkedContent]:
        """Nested marked-content sequences, in document order."""
        return [item for item in self.content if isinstance(item, MarkedContent)]

    def add_text(self, text: str) -> None:
        self.content.append(text)

    def add_child(self, child: MarkedContent) -> None:
        self.content.append(child)

    def iter_marks(self) -> list[MarkedContent]:
        """This mark followed by every descendant, in document order."""
        result = [self]
        for child in self.children:
            result.extend(child.iter_marks())
        return result

    def drawn_text(self) -> str:
        """All glyph evidence painted inside this sequence, in document order."""
        pieces: list[str] = []
        for item in self.content:
            if isinstance(item, MarkedContent):
                pieces.append(item.drawn_text())
            else:
                pieces.append(item)
        return "".join(pieces)

    def reading_text(self) -> str:
        """Accessible reading order rooted at this sequence.

        A sequence carrying ``/ActualText`` announces that text verbatim and
        suppresses every glyph nested beneath it, including glyphs belonging
        to nested marks. Otherwise the contents are read in document order.
        """
        if self.actual_text is not None:
            return self.actual_text
        return self._reading_contents()

    def _reading_contents(self) -> str:
        pieces: list[str] = []
        for item in self.content:
            if isinstance(item, MarkedContent):
                pieces.append(item.reading_text())
            else:
                pieces.append(item)
        return "".join(pieces)


@dataclass
class MarkedContentPoint:
    """A marked-content point (``MP``/``DP``) that wraps no content."""

    tag: str
    location: TagLocation
    mcid: int | None = None
    actual_text: str | None = None
    lang: str | None = None
    properties: dict[str, object] = field(default_factory=dict)

    @property
    def is_point(self) -> bool:
        return True

    def iter_marks(self) -> list[Mark]:
        return [self]

    def drawn_text(self) -> str:
        return ""

    def reading_text(self) -> str:
        return self.actual_text if self.actual_text is not None else ""


# Either a wrapping marked-content sequence or a content-free point.
Mark = MarkedContent | MarkedContentPoint


@dataclass
class ForensicPage:
    """The two evidence channels and structure for one interpreted page."""

    page_number: int
    root: MarkedContent
    points: list[MarkedContentPoint] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def reading_text(self) -> str:
        return self.root.reading_text()

    @property
    def drawn_text(self) -> str:
        return self.root.drawn_text()

    def actual_text_spans(self) -> list[Mark]:
        spans: list[Mark] = []
        for mark in self.root.iter_marks():
            if mark.actual_text is not None:
                spans.append(mark)
        for point in self.points:
            if point.actual_text is not None:
                spans.append(point)
        return spans

    def mismatches(self) -> list[dict[str, object]]:
        """Every ActualText span whose reading text differs from its glyphs."""
        result: list[dict[str, object]] = []
        for mark in self.actual_text_spans():
            drawn = mark.drawn_text()
            reading = mark.reading_text()
            if reading != drawn:
                result.append(
                    {
                        "tag": mark.tag,
                        "location": mark.location.describe(),
                        "page": mark.location.page,
                        "form_xobject": mark.location.form_xobject,
                        "mcid": mark.mcid,
                        "actual_text": reading,
                        "drawn_text": drawn,
                    }
                )
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "page": self.page_number,
            "reading_text": self.reading_text,
            "drawn_text": self.drawn_text,
            "marks": [_mark_to_dict(mark) for mark in self.root.iter_marks()],
            "points": [_point_to_dict(point) for point in self.points],
            "mismatches": self.mismatches(),
            "diagnostics": list(self.diagnostics),
        }


def _mark_to_dict(mark: MarkedContent) -> dict[str, object]:
    return {
        "tag": mark.tag,
        "location": mark.location.describe(),
        "page": mark.location.page,
        "form_xobject": mark.location.form_xobject,
        "mcid": mark.mcid,
        "actual_text": mark.actual_text,
        "lang": mark.lang,
        "drawn_text": mark.drawn_text(),
        "reading_text": mark.reading_text(),
        "closed": mark.closed,
        "children": [_mark_to_dict(child) for child in mark.children],
    }


def _point_to_dict(point: MarkedContentPoint) -> dict[str, object]:
    return {
        "tag": point.tag,
        "location": point.location.describe(),
        "page": point.location.page,
        "form_xobject": point.location.form_xobject,
        "mcid": point.mcid,
        "actual_text": point.actual_text,
        "lang": point.lang,
    }


class ActualTextDevice(PDFDevice):
    """Collect reading-order and drawn-glyph evidence with ActualText spans.

    The device maintains a stack of open marked-content sequences. Glyphs are
    always appended to the innermost sequence so the *drawn* evidence is
    complete, while the *reading* output substitutes ``/ActualText`` and
    therefore never duplicates the replaced glyphs.
    """

    def __init__(self, rsrcmgr: PDFResourceManager) -> None:
        super().__init__(rsrcmgr)
        self.pages: list[ForensicPage] = []
        self._page: ForensicPage | None = None
        self._stack: list[MarkedContent] = []
        # Depth of the marked stack at each open Form XObject figure.
        self._figure_depth: list[int] = []
        # Marks already reported as unclosed, to avoid duplicate diagnostics.
        self._diagnosed: set[int] = set()
        # Zero-based document index of the next page to be interpreted.
        self._next_page_index = 0

    def set_page_index(self, index: int) -> None:
        """Set the zero-based document index of the page about to be parsed."""
        self._next_page_index = index

    # -- page / figure lifecycle -------------------------------------------

    def begin_page(self, page: PDFPage, ctm: Matrix) -> None:
        from pdfminer.pdfinterp import TagLocation

        root_location = TagLocation(page=self._next_page_index + 1)
        root = MarkedContent(tag="__page__", location=root_location)
        root.closed = True
        self._page = ForensicPage(
            page_number=root_location.page,
            root=root,
        )
        self._stack = [root]
        self._figure_depth = []
        self._diagnosed = set()
        self.pages.append(self._page)

    def end_page(self, page: PDFPage) -> None:
        assert self._page is not None
        if len(self._stack) > 1:
            for mark in self._stack[1:]:
                self._diagnose_unclosed(mark)
        self._stack = []
        self._page = None
        self._next_page_index += 1

    def begin_figure(self, name: str, bbox: Rect, matrix: Matrix) -> None:
        self._figure_depth.append(len(self._stack))

    def end_figure(self, name: str) -> None:
        assert self._page is not None
        base = self._figure_depth.pop() if self._figure_depth else 0
        while len(self._stack) > base:
            mark = self._stack.pop()
            self._diagnose_unclosed(mark)

    # -- marked content -----------------------------------------------------

    def begin_tag(
        self,
        tag: PSLiteral,
        props: Optional[PDFStackT] = None,
        location: Optional[TagLocation] = None,
    ) -> None:
        assert self._page is not None
        location = location or self._location()
        mark = MarkedContent(
            tag=literal_name(tag),
            location=location,
        )
        _apply_props(mark, props)
        mark.parent = self._stack[-1]
        self._stack[-1].add_child(mark)
        self._stack.append(mark)

    def end_tag(self, location: Optional[TagLocation] = None) -> None:
        if len(self._stack) <= 1:
            assert self._page is not None
            self._page.diagnostics.append(
                "EMC without a matching BMC/BDC at "
                f"{(location or self._location()).describe()}"
            )
            log.warning("EMC with no open marked-content sequence")
            return
        mark = self._stack.pop()
        mark.closed = True

    def do_tag(
        self,
        tag: PSLiteral,
        props: Optional[PDFStackT] = None,
        location: Optional[TagLocation] = None,
    ) -> None:
        assert self._page is not None
        location = location or self._location()
        point = MarkedContentPoint(
            tag=literal_name(tag),
            location=location,
        )
        _apply_point_props(point, props)
        self._page.points.append(point)

    # -- text ---------------------------------------------------------------

    def render_string(
        self,
        textstate: PDFTextState,
        seq: PDFTextSeq,
        ncs: object,
        graphicstate: PDFGraphicState,
    ) -> None:
        assert self._page is not None
        drawn = _decode_drawn(textstate, seq)
        if drawn:
            self._stack[-1].add_text(drawn)

    # -- report helpers -----------------------------------------------------

    def get_result(self) -> ForensicReport:
        return ForensicReport(pages=list(self.pages))

    def _location(self) -> TagLocation:
        from pdfminer.pdfinterp import TagLocation

        page_number = self._page.page_number if self._page is not None else 1
        return TagLocation(page=page_number)

    def _diagnose_unclosed(self, mark: MarkedContent) -> None:
        assert self._page is not None
        if not mark.closed and id(mark) not in self._diagnosed:
            message = (
                f"Unclosed marked-content sequence <{mark.tag}> opened at "
                f"{mark.location.describe()} never received a matching EMC"
            )
            if mark.mcid is not None:
                message += f" (MCID {mark.mcid})"
            self._page.diagnostics.append(message)
            self._diagnosed.add(id(mark))
            log.warning(message)


@dataclass
class ForensicReport:
    """Collected forensic evidence across every interpreted page."""

    pages: list[ForensicPage] = field(default_factory=list)

    @property
    def reading_text(self) -> str:
        return "\n".join(page.reading_text for page in self.pages)

    @property
    def drawn_text(self) -> str:
        return "\n".join(page.drawn_text for page in self.pages)

    @property
    def diagnostics(self) -> list[str]:
        return [message for page in self.pages for message in page.diagnostics]

    def mismatches(self) -> list[dict[str, object]]:
        return [mismatch for page in self.pages for mismatch in page.mismatches()]

    def to_dict(self) -> dict[str, object]:
        return {
            "pages": [page.to_dict() for page in self.pages],
            "reading_text": self.reading_text,
            "drawn_text": self.drawn_text,
            "mismatches": self.mismatches(),
            "diagnostics": self.diagnostics,
        }


def _normalise_props(props: Optional[PDFStackT]) -> dict[str, object]:
    if not isinstance(props, dict):
        return {}
    return {make_compat_str(key): value for key, value in props.items()}


def _apply_props(mark: MarkedContent, props: Optional[PDFStackT]) -> None:
    if not isinstance(props, dict):
        return
    if ACTUAL_TEXT_KEY in props:
        mark.actual_text = make_compat_str(props[ACTUAL_TEXT_KEY])
    if LANG_KEY in props:
        mark.lang = make_compat_str(props[LANG_KEY])
    if MCID_KEY in props:
        mark.mcid = _as_int(props[MCID_KEY])
    mark.properties = _normalise_props(props)


def _apply_point_props(point: MarkedContentPoint, props: Optional[PDFStackT]) -> None:
    if not isinstance(props, dict):
        return
    if ACTUAL_TEXT_KEY in props:
        point.actual_text = make_compat_str(props[ACTUAL_TEXT_KEY])
    if LANG_KEY in props:
        point.lang = make_compat_str(props[LANG_KEY])
    if MCID_KEY in props:
        point.mcid = _as_int(props[MCID_KEY])
    point.properties = _normalise_props(props)


def _as_int(value: object) -> int | None:
    try:
        return int(cast(int, value))
    except (TypeError, ValueError):
        return None


def extract_actualtext_report(
    pdf_file: FileOrName,
    password: str = "",
    page_numbers: Optional[Container[int]] = None,
    maxpages: int = 0,
    caching: bool = True,
) -> ForensicReport:
    """Interpret a PDF and return the ActualText-aware forensic report.

    :param pdf_file: path or binary file object of the PDF to interpret.
    :param password: password for encrypted documents.
    :param page_numbers: optional zero-based page indices to include.
    :param maxpages: stop after this many pages when positive.
    :param caching: whether the resource manager should cache resources.
    """
    with open_filename(pdf_file, "rb") as fp:
        fp = cast(BinaryIO, fp)
        rsrcmgr = PDFResourceManager(caching=caching)
        device = ActualTextDevice(rsrcmgr)
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        # Map each page object id to its zero-based document index so that a
        # page_numbers/maxpages subset still reports the original page number.
        all_pages = list(PDFPage.get_pages(fp, password=password, caching=caching))
        index_by_objid = {page.pageid: idx for idx, page in enumerate(all_pages)}
        for page in PDFPage.get_pages(
            fp,
            page_numbers,
            maxpages=maxpages,
            password=password,
            caching=caching,
        ):
            document_index = index_by_objid.get(page.pageid, len(device.pages))
            device.set_page_index(document_index)
            interpreter.pageno = document_index
            interpreter.process_page(page)
        return device.get_result()


def extract_actualtext(
    pdf_file: FileOrName,
    password: str = "",
    page_numbers: Optional[Container[int]] = None,
    maxpages: int = 0,
    caching: bool = True,
    **kwargs: Any,
) -> dict[str, object]:
    """Convenience wrapper returning the forensic report as plain dictionaries."""
    report = extract_actualtext_report(
        pdf_file,
        password=password,
        page_numbers=page_numbers,
        maxpages=maxpages,
        caching=caching,
    )
    return report.to_dict()


def forensic_report_json(
    pdf_file: FileOrName,
    password: str = "",
    page_numbers: Optional[Container[int]] = None,
    maxpages: int = 0,
    caching: bool = True,
    indent: int = 2,
) -> str:
    """Serialise the forensic report to a JSON string."""
    report = extract_actualtext_report(
        pdf_file,
        password=password,
        page_numbers=page_numbers,
        maxpages=maxpages,
        caching=caching,
    )
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)
