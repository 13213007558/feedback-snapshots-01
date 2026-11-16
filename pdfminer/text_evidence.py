"""Traceable text evidence for PDF content streams.

The regular extraction APIs intentionally return a flattened text string.  For
forensic review that is not enough: a character can come from a visible fill,
from invisible text (``Tr 3``), from a Form XObject, or from content that is
clipped or covered by something else.  This module keeps each text-showing
operator as a separate evidence record, including its content stream and byte
offset, glyph coordinates and a conservative visibility assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pdfminer.pdfcolor import PDFColorSpace
from pdfminer.pdfdevice import PDFTextDevice, PDFTextSeq
from pdfminer.pdffont import PDFFont, PDFUnicodeNotDefined
from pdfminer.pdfpage import PDFPage
from pdfminer.pdftypes import PDFStream
from pdfminer.utils import (
    Matrix,
    PathSegment,
    Point,
    Rect,
    apply_matrix_pt,
    apply_matrix_rect,
    mult_matrix,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pdfminer.pdfinterp import (
        PDFGraphicState,
        PDFResourceManager,
        PDFTextState,
    )


Visibility = Literal["visible", "invisible", "unknown"]
PaintMode = Literal["none", "fill", "stroke", "fill_and_stroke"]


@dataclass(frozen=True)
class GlyphEvidence:
    """A single glyph as produced by a text-showing operator.

    ``text_position`` is the glyph origin in text-line coordinates (the
    coordinates the content stream's ``Tm``/``Td`` operators work in).
    ``matrix`` maps glyph space to page space; ``bbox`` is the page-space
    bounding box and is only used as a location hint, never as proof of
    visibility.
    """

    cid: int
    char: str | None
    fontname: str
    fontsize: float
    advance: float
    text_position: Point
    matrix: Matrix
    bbox: Rect

    @property
    def page_origin(self) -> Point:
        """Glyph origin in page coordinates."""
        return apply_matrix_pt(self.matrix, (0.0, 0.0))


@dataclass(frozen=True)
class FormReference:
    """A Form XObject on the path that produced a text run."""

    name: str
    objid: int | None


@dataclass(frozen=True)
class TextSource:
    """Where in the PDF a text run was found.

    ``content_stream_index`` is the index in the page ``/Contents`` array.
    ``operator_offset`` is the byte offset of the text-showing operator inside
    the decoded content stream (not a file offset).
    """

    page_index: int
    page_objid: int | None
    content_stream_objid: int | None
    content_stream_generation: int | None
    content_stream_index: int | None
    operator_offset: int | None
    form_path: tuple[FormReference, ...] = ()

    @property
    def in_form(self) -> bool:
        return bool(self.form_path)


@dataclass(frozen=True)
class TextEvidence:
    """Text from one text-showing operator.

    A ``TextEvidence`` is never merged with another operator's text, even when
    both paint at the same coordinates.  ``visibility`` is one of:

    ``visible``
        The rendering mode paints glyphs and no active clip, transparency or
        detected later overpaint makes the result uncertain.
    ``invisible``
        The rendering mode paints neither fill nor stroke (``Tr 3`` or
        ``Tr 7``).  This is a property of the content stream, not a guess about
        the final image.
    ``unknown``
        A clip is active, transparency/blend mode is active, the glyph leaves
        the page or Form BBox, or a later painted object overlaps it.  pdfminer
        does not evaluate these cases completely.
    """

    text: str
    source: TextSource
    render_mode: int
    paint_mode: PaintMode
    visibility: Visibility
    visibility_reasons: tuple[str, ...]
    clipping_active: bool
    transparency_uncertain: bool
    occlusion: Literal["not_analyzed", "none_detected", "possible"]
    glyphs: tuple[GlyphEvidence, ...]
    bbox: Rect

    @property
    def invisible(self) -> bool:
        return self.visibility == "invisible"

    @property
    def hidden(self) -> bool:
        """Alias for ``invisible``; the text may still be searchable."""
        return self.visibility == "invisible"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "text": self.text,
            "visibility": self.visibility,
            "visibility_reasons": list(self.visibility_reasons),
            "render_mode": self.render_mode,
            "paint_mode": self.paint_mode,
            "clipping_active": self.clipping_active,
            "transparency_uncertain": self.transparency_uncertain,
            "occlusion": self.occlusion,
            "source": {
                "page_index": self.source.page_index,
                "page_objid": self.source.page_objid,
                "content_stream_objid": self.source.content_stream_objid,
                "content_stream_generation": self.source.content_stream_generation,
                "content_stream_index": self.source.content_stream_index,
                "operator_offset": self.source.operator_offset,
                "form_path": [
                    {"name": form.name, "objid": form.objid}
                    for form in self.source.form_path
                ],
            },
            "bbox": list(self.bbox),
            "glyph_count": len(self.glyphs),
            "glyphs": [
                {
                    "cid": glyph.cid,
                    "char": glyph.char,
                    "fontname": glyph.fontname,
                    "fontsize": glyph.fontsize,
                    "advance": glyph.advance,
                    "text_position": list(glyph.text_position),
                    "page_origin": list(glyph.page_origin),
                    "matrix": list(glyph.matrix),
                    "bbox": list(glyph.bbox),
                }
                for glyph in self.glyphs
            ],
        }


@dataclass(frozen=True)
class PageTextEvidence:
    """All text evidence for one page, in content-stream order."""

    page_index: int
    page_objid: int | None
    mediabox: Rect
    cropbox: Rect
    runs: tuple[TextEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "page_index": self.page_index,
            "page_objid": self.page_objid,
            "mediabox": list(self.mediabox),
            "cropbox": list(self.cropbox),
            "runs": [run.to_dict() for run in self.runs],
        }


@dataclass
class _PaintEvent:
    order: int
    bbox: Rect
    run_index: int | None


def _paint_mode(render_mode: int) -> PaintMode:
    """Map a text rendering mode to the painting it performs."""
    if render_mode in (1, 5):
        return "stroke"
    if render_mode in (2, 6):
        return "fill_and_stroke"
    if render_mode in (0, 4):
        return "fill"
    return "none"


def _intersects(one: Rect, other: Rect) -> bool:
    return not (
        one[2] <= other[0]
        or other[2] <= one[0]
        or one[3] <= other[1]
        or other[3] <= one[1]
    )


def _contains(outer: Rect, inner: Rect) -> bool:
    return (
        outer[0] <= inner[0]
        and outer[1] <= inner[1]
        and inner[2] <= outer[2]
        and inner[3] <= outer[3]
    )


def _normalise_rect(rect: Rect) -> Rect:
    x0, y0, x1, y1 = rect
    return min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)


class TextEvidenceDevice(PDFTextDevice):
    """A :class:`PDFDevice` that records traceable text evidence.

    Use it like any other device::

        rsrcmgr = PDFResourceManager()
        device = TextEvidenceDevice(rsrcmgr)
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        for page in PDFPage.get_pages(fp):
            interpreter.process_page(page)
        pages = device.pages
    """

    def __init__(self, rsrcmgr: PDFResourceManager) -> None:
        super().__init__(rsrcmgr)
        self.pages: list[PageTextEvidence] = []
        self._page_index = -1
        self._page_objid: int | None = None
        self._mediabox: Rect = (0.0, 0.0, 0.0, 0.0)
        self._cropbox: Rect = (0.0, 0.0, 0.0, 0.0)
        self._page_bbox: Rect = (0.0, 0.0, 0.0, 0.0)
        self._runs: list[TextEvidence] = []
        self._events: list[_PaintEvent] = []
        self._event_order = 0
        self._form_stack: list[tuple[str, Rect]] = []
        self._glyphs: list[GlyphEvidence] = []
        self._textstate: PDFTextState | None = None
        self._graphicstate: PDFGraphicState | None = None

    # -- pages and forms --------------------------------------------------
    def begin_page(self, page: PDFPage, ctm: Matrix) -> None:
        self._page_index += 1
        self._page_objid = page.pageid if isinstance(page.pageid, int) else None
        self._mediabox = _normalise_rect(apply_matrix_rect(ctm, page.mediabox))
        self._cropbox = _normalise_rect(apply_matrix_rect(ctm, page.cropbox))
        self._page_bbox = self._cropbox
        self._runs = []
        self._events = []
        self._event_order = 0
        self._form_stack = []
        self._glyphs = []

    def end_page(self, page: PDFPage) -> None:
        runs = self._apply_occlusion()
        self.pages.append(
            PageTextEvidence(
                page_index=self._page_index,
                page_objid=self._page_objid,
                mediabox=self._mediabox,
                cropbox=self._cropbox,
                runs=tuple(runs),
            ),
        )
        self._runs = []
        self._events = []

    def begin_figure(self, name: str, bbox: Rect, matrix: Matrix) -> None:
        assert self.ctm is not None
        form_ctm = mult_matrix(matrix, self.ctm)
        form_bbox = _normalise_rect(apply_matrix_rect(form_ctm, bbox))
        self._form_stack.append((name, form_bbox))

    def end_figure(self, name: str) -> None:
        if self._form_stack:
            self._form_stack.pop()

    # -- non-text painting ------------------------------------------------
    def paint_path(
        self,
        graphicstate: PDFGraphicState,
        stroke: bool,
        fill: bool,
        evenodd: bool,
        path: Sequence[PathSegment],
    ) -> None:
        if not (stroke or fill):
            return
        assert self.ctm is not None
        points: list[Point] = []
        for segment in path:
            if segment[0] == "h":
                continue
            coords = segment[1:]
            for index in range(0, len(coords) - 1, 2):
                points.append(
                    apply_matrix_pt(
                        self.ctm,
                        (float(coords[index]), float(coords[index + 1])),
                    ),
                )
        if points:
            xs = [point[0] for point in points]
            ys = [point[1] for point in points]
            self._add_paint_event((min(xs), min(ys), max(xs), max(ys)))

    def render_image(self, name: str, stream: PDFStream) -> None:
        # An image XObject paints the unit square in the current user space.
        assert self.ctm is not None
        self._add_paint_event(
            _normalise_rect(apply_matrix_rect(self.ctm, (0.0, 0.0, 1.0, 1.0))),
        )

    def _add_paint_event(self, rect: Rect, run_index: int | None = None) -> None:
        self._event_order += 1
        self._events.append(
            _PaintEvent(order=self._event_order, bbox=rect, run_index=run_index),
        )

    # -- text -------------------------------------------------------------
    def render_string(
        self,
        textstate: PDFTextState,
        seq: PDFTextSeq,
        ncs: PDFColorSpace,
        graphicstate: PDFGraphicState,
    ) -> None:
        self._glyphs = []
        self._textstate = textstate
        self._graphicstate = graphicstate
        try:
            super().render_string(textstate, seq, ncs, graphicstate)
        finally:
            self._finish_run()
            self._glyphs = []
            self._textstate = None
            self._graphicstate = None

    def render_char(
        self,
        matrix: Matrix,
        font: PDFFont,
        fontsize: float,
        scaling: float,
        rise: float,
        cid: int,
        ncs: PDFColorSpace,
        graphicstate: PDFGraphicState,
    ) -> float:
        try:
            char: str | None = font.to_unichr(cid)
        except PDFUnicodeNotDefined:
            char = None
        advance = font.char_width(cid) * fontsize * scaling
        if font.is_vertical():
            textdisp = font.char_disp(cid)
            assert isinstance(textdisp, tuple)
            (vx, vy) = textdisp
            vx = fontsize * 0.5 if vx is None else vx * fontsize * 0.001
            vy = (1000 - vy) * fontsize * 0.001
            glyph_bbox = (-vx, vy + rise + advance, -vx + fontsize, vy + rise)
        else:
            descent = font.get_descent() * fontsize
            glyph_bbox = (0, descent + rise, advance, descent + rise + fontsize)
        self._glyphs.append(
            GlyphEvidence(
                cid=cid,
                char=char,
                fontname=font.fontname,
                fontsize=fontsize,
                advance=advance,
                text_position=self._text_position or (0.0, 0.0),
                matrix=matrix,
                bbox=_normalise_rect(apply_matrix_rect(matrix, glyph_bbox)),
            ),
        )
        return advance

    def _finish_run(self) -> None:
        """Store one evidence record for the current text-showing operator."""
        textstate = self._textstate
        graphicstate = self._graphicstate
        if not self._glyphs or textstate is None or graphicstate is None:
            return

        glyphs = tuple(self._glyphs)
        bbox = (
            min(glyph.bbox[0] for glyph in glyphs),
            min(glyph.bbox[1] for glyph in glyphs),
            max(glyph.bbox[2] for glyph in glyphs),
            max(glyph.bbox[3] for glyph in glyphs),
        )
        render_mode = textstate.render
        paint_mode = _paint_mode(render_mode)
        visibility, reasons = self._assess_visibility(
            render_mode,
            paint_mode,
            bbox,
            graphicstate,
        )
        source = TextSource(
            page_index=self._page_index,
            page_objid=self._page_objid,
            content_stream_objid=textstate.source_stream_objid,
            content_stream_generation=textstate.source_stream_generation,
            content_stream_index=textstate.source_stream_index,
            operator_offset=textstate.source_position,
            form_path=tuple(
                FormReference(name=name, objid=objid)
                for name, objid in textstate.source_form_path
            ),
        )
        run = TextEvidence(
            text="".join(glyph.char for glyph in glyphs if glyph.char is not None),
            source=source,
            render_mode=render_mode,
            paint_mode=paint_mode,
            visibility=visibility,
            visibility_reasons=reasons,
            clipping_active=graphicstate.clipping,
            transparency_uncertain=graphicstate.transparency_uncertain,
            occlusion="not_analyzed",
            glyphs=glyphs,
            bbox=bbox,
        )
        self._runs.append(run)
        if paint_mode != "none" and render_mode < 4:
            # Modes 4-6 also update the clip, but their fill/stroke result is
            # not recorded as an opaque object that can hide earlier text.
            self._add_paint_event(bbox, run_index=len(self._runs) - 1)

    def _assess_visibility(
        self,
        render_mode: int,
        paint_mode: PaintMode,
        bbox: Rect,
        graphicstate: PDFGraphicState,
    ) -> tuple[Visibility, tuple[str, ...]]:
        if render_mode in (3, 7):
            return "invisible", (
                f"text rendering mode {render_mode} does not paint glyphs",
            )
        if paint_mode == "none":
            return "unknown", (
                f"unrecognised text rendering mode {render_mode!r}",
            )

        reasons: list[str] = []
        unknown = False
        if graphicstate.clipping:
            unknown = True
            reasons.append(
                "a clipping path is active; pdfminer.six does not evaluate "
                "clip geometry",
            )
        if graphicstate.transparency_uncertain:
            unknown = True
            reasons.append(
                "transparency or a non-Normal blend mode is active; "
                "compositing is not evaluated",
            )
        if not _contains(self._page_bbox, bbox):
            unknown = True
            reasons.append(
                "glyph bounds are not fully inside the page; page clipping "
                "is not evaluated",
            )
        for _name, form_bbox in self._form_stack:
            if not _contains(form_bbox, bbox):
                unknown = True
                reasons.append(
                    "glyph bounds are not fully inside an enclosing Form "
                    "XObject BBox",
                )
                break
        if unknown:
            return "unknown", tuple(reasons)
        return "visible", (
            f"text rendering mode {render_mode} paints glyphs and no active "
            "clip, transparency or later overpaint was detected",
        )

    def _apply_occlusion(self) -> list[TextEvidence]:
        """Downgrade runs covered by later painted objects to ``unknown``."""
        if not self._events:
            return list(self._runs)

        run_order: dict[int, int] = {}
        for event in self._events:
            if event.run_index is not None:
                run_order[event.run_index] = event.order

        result: list[TextEvidence] = []
        for index, run in enumerate(self._runs):
            order = run_order.get(index)
            if order is None:
                result.append(run)
                continue
            occluded = any(
                event.order > order
                and event.run_index != index
                and _intersects(event.bbox, run.bbox)
                for event in self._events
            )
            if occluded and run.visibility != "unknown":
                result.append(
                    TextEvidence(
                        text=run.text,
                        source=run.source,
                        render_mode=run.render_mode,
                        paint_mode=run.paint_mode,
                        visibility="unknown",
                        visibility_reasons=(
                            *run.visibility_reasons,
                            "a later painted object overlaps the glyph bounds; "
                            "occlusion is not fully evaluated",
                        ),
                        clipping_active=run.clipping_active,
                        transparency_uncertain=run.transparency_uncertain,
                        occlusion="possible",
                        glyphs=run.glyphs,
                        bbox=run.bbox,
                    ),
                )
            else:
                result.append(
                    TextEvidence(
                        text=run.text,
                        source=run.source,
                        render_mode=run.render_mode,
                        paint_mode=run.paint_mode,
                        visibility=run.visibility,
                        visibility_reasons=run.visibility_reasons,
                        clipping_active=run.clipping_active,
                        transparency_uncertain=run.transparency_uncertain,
                        occlusion="possible" if occluded else "none_detected",
                        glyphs=run.glyphs,
                        bbox=run.bbox,
                    ),
                )
        return result
