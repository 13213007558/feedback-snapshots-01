import logging
import zlib
from collections.abc import Iterator, Mapping, Sequence
from io import BytesIO
from typing import Union, cast

from pdfminer import settings
from pdfminer.ascii85 import ascii85decode, asciihexdecode
from pdfminer.casting import safe_cmyk, safe_float, safe_int, safe_matrix, safe_rgb
from pdfminer.ccitt import ccittfaxdecode
from pdfminer.cmapdb import CMap, CMapBase, CMapDB
from pdfminer.lzw import lzwdecode
from pdfminer.pdfcolor import PREDEFINED_COLORSPACE, PDFColorSpace
from pdfminer.pdfdevice import PDFDevice, PDFTextSeq
from pdfminer.pdfexceptions import PDFException, PDFValueError
from pdfminer.pdffont import (
    PDFCIDFont,
    PDFFont,
    PDFFontError,
    PDFTrueTypeFont,
    PDFType1Font,
    PDFType3Font,
)
from pdfminer.pdfpage import PDFPage
from pdfminer.pdftypes import (
    LITERALS_ASCII85_DECODE,
    LITERALS_ASCIIHEX_DECODE,
    LITERALS_CCITTFAX_DECODE,
    LITERALS_FLATE_DECODE,
    LITERALS_LZW_DECODE,
    LITERALS_RUNLENGTH_DECODE,
    PDFObjRef,
    PDFStream,
    dict_value,
    int_value,
    list_value,
    resolve1,
    stream_value,
)
from pdfminer.psexceptions import PSEOF, PSTypeError
from pdfminer.psparser import (
    KWD,
    LIT,
    PSKeyword,
    PSLiteral,
    PSStackParser,
    PSStackType,
    keyword_name,
    literal_name,
)
from pdfminer.runlength import rldecode
from pdfminer.utils import (
    MATRIX_IDENTITY,
    Matrix,
    PathSegment,
    Point,
    Rect,
    choplist,
    mult_matrix,
)

log = logging.getLogger(__name__)


class PDFResourceError(PDFException):
    pass


class PDFInterpreterError(PDFException):
    pass


LITERAL_PDF = LIT("PDF")
LITERAL_TEXT = LIT("Text")
LITERAL_FONT = LIT("Font")
LITERAL_FORM = LIT("Form")
LITERAL_IMAGE = LIT("Image")


class PDFTextState:
    matrix: Matrix
    linematrix: Point

    def __init__(self) -> None:
        self.font: PDFFont | None = None
        self.fontsize: float = 0
        self.charspace: float = 0
        self.wordspace: float = 0
        self.scaling: float = 100
        self.leading: float = 0
        self.render: int = 0
        self.rise: float = 0
        self.reset()
        # self.matrix is set
        # self.linematrix is set

    def __repr__(self) -> str:
        return (
            f"<PDFTextState: font={self.font!r}, "
            f"fontsize={self.fontsize!r}, "
            f"charspace={self.charspace!r}, "
            f"wordspace={self.wordspace!r}, "
            f"scaling={self.scaling!r}, "
            f"leading={self.leading!r}, "
            f"render={self.render!r}, "
            f"rise={self.rise!r}, "
            f"matrix={self.matrix!r}, "
            f"linematrix={self.linematrix!r}>"
        )

    def copy(self) -> "PDFTextState":
        obj = PDFTextState()
        obj.font = self.font
        obj.fontsize = self.fontsize
        obj.charspace = self.charspace
        obj.wordspace = self.wordspace
        obj.scaling = self.scaling
        obj.leading = self.leading
        obj.render = self.render
        obj.rise = self.rise
        obj.matrix = self.matrix
        obj.linematrix = self.linematrix
        return obj

    def reset(self) -> None:
        self.matrix = MATRIX_IDENTITY
        self.linematrix = (0, 0)


# Standard color types (used standalone or as base for uncolored patterns)
StandardColor = Union[
    float,  # Greyscale
    tuple[float, float, float],  # R, G, B
    tuple[float, float, float, float],  # C, M, Y, K
]

# Complete color type including patterns
Color = Union[
    StandardColor,  # Standard colors (gray, RGB, CMYK)
    str,  # Pattern name (colored pattern, PaintType=1)
    tuple[
        StandardColor, str
    ],  # (base_color, pattern_name) (uncolored pattern, PaintType=2)
]


class PDFGraphicState:
    def __init__(self) -> None:
        self.linewidth: float = 0
        self.linecap: object | None = None
        self.linejoin: object | None = None
        self.miterlimit: object | None = None
        self.dash: tuple[object, object] | None = None
        self.intent: object | None = None
        self.flatness: object | None = None

        # stroking color
        self.scolor: Color = 0
        self.scs: PDFColorSpace = PREDEFINED_COLORSPACE["DeviceGray"]

        # non stroking color
        self.ncolor: Color = 0
        self.ncs: PDFColorSpace = PREDEFINED_COLORSPACE["DeviceGray"]

    def copy(self) -> "PDFGraphicState":
        obj = PDFGraphicState()
        obj.linewidth = self.linewidth
        obj.linecap = self.linecap
        obj.linejoin = self.linejoin
        obj.miterlimit = self.miterlimit
        obj.dash = self.dash
        obj.intent = self.intent
        obj.flatness = self.flatness
        obj.scolor = self.scolor
        obj.scs = self.scs
        obj.ncolor = self.ncolor
        obj.ncs = self.ncs
        return obj

    def __repr__(self) -> str:
        return (
            f"<PDFGraphicState: "
            f"linewidth={self.linewidth!r}, "
            f"linecap={self.linecap!r}, "
            f"linejoin={self.linejoin!r}, "
            f"miterlimit={self.miterlimit!r}, "
            f"dash={self.dash!r}, "
            f"intent={self.intent!r}, "
            f"flatness={self.flatness!r}, "
            f"stroking color={self.scolor!r}, "
            f"non stroking color={self.ncolor!r}>"
        )


class PDFResourceManager:
    """Repository of shared resources.

    ResourceManager facilitates reuse of shared resources
    such as fonts and images so that large objects are not
    allocated multiple times.
    """

    def __init__(self, caching: bool = True) -> None:
        self.caching = caching
        self._cached_fonts: dict[object, PDFFont] = {}

    def get_procset(self, procs: Sequence[object]) -> None:
        for proc in procs:
            if proc is LITERAL_PDF or proc is LITERAL_TEXT:
                pass
            else:
                pass

    def get_cmap(self, cmapname: str, strict: bool = False) -> CMapBase:
        try:
            return CMapDB.get_cmap(cmapname)
        except CMapDB.CMapNotFound:
            if strict:
                raise
            return CMap()

    def get_font(self, objid: object, spec: Mapping[str, object]) -> PDFFont:
        if objid and objid in self._cached_fonts:
            font = self._cached_fonts[objid]
        else:
            log.debug("get_font: create: objid=%r, spec=%r", objid, spec)
            if settings.STRICT and spec["Type"] is not LITERAL_FONT:
                raise PDFFontError("Type is not /Font")
            # Create a Font object.
            if "Subtype" in spec:
                subtype = literal_name(spec["Subtype"])
            else:
                if settings.STRICT:
                    raise PDFFontError("Font Subtype is not specified.")
                subtype = "Type1"
            if subtype in ("Type1", "MMType1"):
                # Type1 Font
                font = PDFType1Font(self, spec)
            elif subtype == "TrueType":
                # TrueType Font
                font = PDFTrueTypeFont(self, spec)
            elif subtype == "Type3":
                # Type3 Font
                font = PDFType3Font(self, spec)
            elif subtype in ("CIDFontType0", "CIDFontType2"):
                # CID Font
                font = PDFCIDFont(self, spec)
            elif subtype == "Type0":
                # Type0 Font
                dfonts = list_value(spec["DescendantFonts"])
                assert dfonts
                subspec = dict_value(dfonts[0]).copy()
                for k in ("Encoding", "ToUnicode"):
                    if k in spec:
                        subspec[k] = resolve1(spec[k])
                font = self.get_font(None, subspec)
            else:
                if settings.STRICT:
                    raise PDFFontError(f"Invalid Font spec: {spec!r}")
                font = PDFType1Font(self, spec)  # this is so wrong!
            if objid and self.caching:
                self._cached_fonts[objid] = font
        return font


class InlineImageData:
    """The raw bytes of an inline image and how its boundary was found.

    ``data`` is the image content (excluding the ``ID`` whitespace and the
    terminating operator), ``eod`` is the end-of-data marker that bounded
    it (``EI``, or a filter marker such as ``~>``) and ``end`` is the
    absolute content-stream position of that marker.
    """

    __slots__ = ("data", "eod", "end")

    def __init__(self, data: bytes, eod: bytes, end: int) -> None:
        self.data = data
        self.eod = eod
        self.end = end

    def __repr__(self) -> str:
        return f"<InlineImageData: len={len(self.data)}, eod={self.eod!r}>"


class PDFContentParser(PSStackParser[Union[PSKeyword, PDFStream]]):
    def __init__(self, streams: Sequence[object]) -> None:
        self.streams = streams
        self.istream = 0
        # PSStackParser.__init__(fp=None) is safe only because we've overloaded
        # all the methods that would attempt to access self.fp without first
        # calling self.fillfp().
        PSStackParser.__init__(self, None)  # type: ignore[arg-type]

    def fillfp(self) -> bool:
        if not self.fp:
            if self.istream < len(self.streams):
                strm = stream_value(self.streams[self.istream])
                self.istream += 1
            else:
                raise PSEOF("Unexpected EOF, file truncated?")
            self.fp = BytesIO(strm.get_data())
            return True
        return False

    def seek(self, pos: int) -> None:
        self.fillfp()
        PSStackParser.seek(self, pos)

    def _current_stream_index(self) -> int:
        """Index of the content stream backing the current file object.

        ``fillfp`` advances ``istream`` past the active stream, so the
        backing stream is always ``istream - 1`` once ``fp`` is open.
        """
        assert self.fp is not None
        return self.istream - 1

    def _reposition(self, stream_index: int, pos: int) -> None:
        """Move to per-stream offset ``pos`` within ``stream_index``.

        Unlike :meth:`seek`, this works even after a scan has consumed the
        current stream (which sets ``fp`` to ``None`` and advances
        ``istream``): the target stream is reloaded on demand.  Inline
        images never span streams, so ``stream_index`` always names a
        stream that is current or already consumed.
        """
        if self.istream != stream_index + 1 or not self.fp:
            self.istream = stream_index + 1
            self.fp = BytesIO(stream_value(self.streams[stream_index]).get_data())
        PSStackParser.seek(self, pos)

    def fillbuf(self) -> bool:
        if self.charpos < len(self.buf):
            return False
        new_stream = False
        while 1:
            new_stream = self.fillfp()
            self.bufpos = self.fp.tell()
            self.buf = self.fp.read(self.BUFSIZ)
            if self.buf:
                break
            self.fp = None  # type: ignore[assignment]
        self.charpos = 0
        return new_stream

    # Whitespace defined in PDF Reference, table 1 (section 3.1.1).
    _WHITESPACE = frozenset(b"\x00\t\n\x0c\r ")
    # End-of-data markers of the filters that carry their own one
    # (PDF Reference, section 4.8.6, table 4.42).  Every other filter, and
    # the unfiltered case, is terminated by the ``EI`` operator.
    _FILTER_EOD: Mapping[object, bytes] = {
        LIT("ASCII85Decode"): b"~>",
        LIT("A85"): b"~>",
        LIT("ASCIIHexDecode"): b">",
        LIT("AHx"): b">",
    }

    def _next_byte(self) -> int:
        """Return the byte at the current position and advance past it.

        The fixed-size read buffer (``BUFSIZ``) is refilled transparently,
        so a terminator split over a buffer boundary is still recognised.
        Raises :class:`PSEOF` when no more data is available.
        """
        self.fillbuf()
        ci = self.buf[self.charpos]
        self.charpos += 1
        return ci

    def _iter_stream_bytes(self, stream_index: int) -> Iterator[int]:
        """Yield the remaining bytes of content stream ``stream_index`` only.

        An inline image is always contained in a single content stream, so
        this iterator stops at that stream's end instead of silently
        continuing into the next stream (which would mix two separate
        per-stream offset spaces).  The read buffer is refilled as needed,
        which is what lets a multi-byte terminator straddle a buffer.
        """
        active = stream_index + 1
        while True:
            if self.istream != active or not self.fp:
                return
            if self.charpos < len(self.buf):
                ci = self.buf[self.charpos]
                self.charpos += 1
                yield ci
                continue
            # Refill without consuming into the next stream: detect the
            # boundary by remembering the file object before the refill.
            current_fp = self.fp
            try:
                self.fillbuf()
            except PSEOF:
                return
            if self.fp is not current_fp or self.istream != active:
                return

    def _peek_byte(self, stream_index: int) -> int | None:
        """Return the byte at the current position without consuming it."""
        if self.istream != stream_index + 1 or not self.fp:
            return None
        try:
            self.fillbuf()
        except PSEOF:
            return None
        if self.istream != stream_index + 1:
            return None
        return self.buf[self.charpos]

    def _read_bytes(self, stream_index: int, length: int) -> bytes:
        """Consume and return the next ``length`` bytes from the stream.

        The read transparently crosses the fixed-size buffer boundary but
        never leaves content stream ``stream_index``.  Fewer than
        ``length`` bytes are returned only when the end of the stream is
        reached.
        """
        chunks: list[bytes] = []
        remaining = length
        active = stream_index + 1
        while remaining > 0 and self.istream == active and self.fp:
            if self.charpos >= len(self.buf):
                current_fp = self.fp
                try:
                    self.fillbuf()
                except PSEOF:
                    break
                if self.fp is not current_fp or self.istream != active:
                    break
            chunk = self.buf[self.charpos : self.charpos + remaining]
            if not chunk:
                break
            chunks.append(chunk)
            self.charpos += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _expected_image_length(attrs: Mapping[str, object]) -> int | None:
        """Number of bytes an unfiltered inline image must occupy.

        PDF Reference, section 4.8.6: for an image without a filter the
        amount of image data is determined entirely by ``W``, ``H``,
        ``BPC`` and the number of colour components, so the terminator is
        located by length rather than by searching for ``EI`` bytes that
        may legitimately occur inside the image data.
        """
        try:
            width = int(attrs["W"])
            height = int(attrs["H"])
        except (KeyError, TypeError, ValueError):
            return None
        if width <= 0 or height <= 0:
            return None
        # The default bits-per-component is 1 (PDF Reference, table 4.41).
        try:
            bpc = int(attrs.get("BPC", 1))
        except (TypeError, ValueError):
            return None
        if bpc <= 0:
            return None
        cs = attrs.get("CS", LIT("DeviceGray"))
        if isinstance(cs, PSLiteral):
            name = cs.name
            if not isinstance(name, str):
                return None
            ncomponents = {
                "G": 1,
                "DeviceGray": 1,
                "CalGray": 1,
                "RGB": 3,
                "DeviceRGB": 3,
                "CalRGB": 3,
                "Lab": 3,
                "CMYK": 4,
                "DeviceCMYK": 4,
            }.get(name)
            if ncomponents is None:
                # Indexed, Separation, DeviceN, Pattern, ... always use a
                # single component per sample (section 4.8.6).
                ncomponents = 1
        else:
            # An array-based colour space (e.g. [/Indexed ...]); the number
            # of components cannot be resolved here, so the length is unknown.
            return None
        total_bits = width * height * ncomponents * bpc
        # Sub-byte samples are packed, rounding up to a whole byte.
        return (total_bits + 7) // 8

    def _consume_leading_whitespace(self, stream_index: int) -> None:
        """Skip the single whitespace that terminates the ``ID`` operator."""
        first = self._peek_byte(stream_index)
        if first is not None and first in self._WHITESPACE:
            self._next_byte()

    def _find_ei_boundary(
        self, stream_index: int, data_length: int
    ) -> tuple[int, bytes] | None:
        """Confirm the ``EI`` operator that ends an unfiltered image.

        The image must occupy exactly ``data_length`` bytes (derived from
        ``W``, ``H``, ``BPC`` and the colour space).  After reading that
        many bytes, verify that an ``EI`` operator follows, separated from
        the data only by whitespace / a line ending.  Returns the
        (per-stream) position of ``EI`` and the image data, or ``None``.
        """
        data = self._read_bytes(stream_index, data_length)
        if len(data) != data_length:
            return None
        while True:
            following = self._peek_byte(stream_index)
            if following is None:
                return None
            if following in self._WHITESPACE:
                self._next_byte()
                continue
            break
        ei_pos = self._match_at_cursor(stream_index, b"EI")
        if ei_pos is None:
            return None
        return ei_pos, bytes(data)

    def _match_at_cursor(
        self, stream_index: int, marker: bytes
    ) -> int | None:
        """Check whether ``marker`` begins at the current cursor position.

        The bytes are inspected through the stream-bounded iterator so a
        marker that straddles a read buffer is detected.  On a match the
        cursor is repositioned at the first byte of the marker and its
        (per-stream) position is returned; otherwise the cursor is restored
        to where the check started.
        """
        start = self.bufpos + self.charpos
        matched = bytearray()
        for ci in self._iter_stream_bytes(stream_index):
            matched.append(ci)
            if bytes(matched) != marker[: len(matched)]:
                self._reposition(stream_index, start)
                return None
            if bytes(matched) == marker:
                self._reposition(stream_index, start)
                return start
        self._reposition(stream_index, start)
        return None

    def _find_filtered_boundary(
        self, stream_index: int, filters: Sequence[object]
    ) -> "InlineImageData | None":
        """Locate the end of a filtered inline image.

        Filters with an explicit end-of-data marker (ASCII85 and
        ASCIIHex) are bounded by that marker.  Otherwise every candidate
        ``EI`` operator (an ``EI`` followed by whitespace or the end of
        the content) is tried and the boundary is accepted only when the
        data up to it decodes without error.  Returns an
        :class:`InlineImageData`, or ``None`` when no boundary can be
        established with sufficient evidence; in that case the parser
        position is restored to the start of the image data.
        """
        start = self.bufpos + self.charpos
        eod = self._FILTER_EOD.get(filters[0])
        if eod is not None:
            data = bytearray()
            # Accumulate bytes until the end-of-data marker is matched,
            # scanning only the current stream so a split marker works.
            matched = 0
            for ci in self._iter_stream_bytes(stream_index):
                if ci == eod[matched]:
                    matched += 1
                    if matched == len(eod):
                        end = self.bufpos + self.charpos
                        # The marker belongs to the encoded data and is
                        # required by the decoder; the EI operator remains
                        # in the stream and is tokenised normally.
                        image = bytes(data) + eod
                        return InlineImageData(data=image, eod=eod, end=end)
                else:
                    if matched:
                        data.extend(eod[:matched])
                    data.append(ci)
                    matched = 1 if ci == eod[0] else 0
            self._reposition(stream_index, start)
            return None

        candidates = self._collect_ei_candidates(stream_index)
        validated: list[tuple[int, bytes]] = []
        for ei_pos, data in candidates:
            if self._decodes_cleanly(data, filters):
                validated.append((ei_pos, data))
        if len(validated) == 1:
            (ei_pos, data) = validated[0]
            self._reposition(stream_index, ei_pos)
            return InlineImageData(data=data, eod=b"EI", end=ei_pos)
        if not validated:
            log.warning(
                "Inline image: no decodable EI boundary found among %d "
                "candidate(s); leaving the remainder of the content stream "
                "untouched",
                len(candidates),
            )
        else:
            log.warning(
                "Inline image: %d EI boundaries decode successfully; the "
                "end of the image is ambiguous, leaving the remainder of "
                "the content stream untouched",
                len(validated),
            )
        self._reposition(stream_index, start)
        return None

    def _collect_ei_candidates(
        self, stream_index: int
    ) -> list[tuple[int, bytes]]:
        """Scan forward and record every plausible ``EI`` operator.

        A candidate is an ``EI`` byte sequence followed by PDF whitespace
        or the end of the content, which is what distinguishes the
        operator from the same bytes occurring inside binary image data.
        Each entry pairs the (per-stream) position of the ``EI`` with the
        complete image data that would result from cutting there.  The
        parser position is restored to where the scan began.
        """
        start = self.bufpos + self.charpos
        data = bytearray()
        candidates: list[tuple[int, bytes]] = []
        saw_e = False
        for ci in self._iter_stream_bytes(stream_index):
            if saw_e and ci == ord("I"):
                ei_pos = self.bufpos + self.charpos - 2
                following = self._peek_byte(stream_index)
                if following is None or following in self._WHITESPACE:
                    # data currently ends with the leading "E"; drop it so
                    # the cut excludes the whole "EI" operator.
                    candidates.append((ei_pos, bytes(data[:-1])))
            data.append(ci)
            saw_e = ci == ord("E")
        self._reposition(stream_index, start)
        return candidates

    def _decodes_cleanly(
        self, data: bytes, filters: Sequence[object]
    ) -> bool:
        """Return whether ``data`` survives the whole filter chain.

        The check is deliberately strict: the normal non-STRICT decoding
        path tolerates truncated Flate streams (it falls back to
        ``decompress_corrupted``), which would make every premature EI cut
        look valid.  A boundary is only accepted when each filter decodes
        without error, which is what distinguishes the real end of the
        image from an ``EI`` that merely happens to occur earlier.
        """
        current = data
        try:
            for filt in filters:
                current = self._strict_decode(filt, current)
        except Exception:  # noqa: BLE001 - any failure rejects the cut
            return False
        return True

    @staticmethod
    def _strict_decode(filt: object, data: bytes) -> bytes:
        """Apply one filter, raising on any invalid or truncated input."""
        if filt in LITERALS_FLATE_DECODE:
            return zlib.decompress(data)
        if filt in LITERALS_LZW_DECODE:
            return lzwdecode(data)
        if filt in LITERALS_ASCII85_DECODE:
            return ascii85decode(data)
        if filt in LITERALS_ASCIIHEX_DECODE:
            return asciihexdecode(data)
        if filt in LITERALS_RUNLENGTH_DECODE:
            return rldecode(data)
        if filt in LITERALS_CCITTFAX_DECODE:
            return ccittfaxdecode(data, {})
        # DCT/JPEG, JBIG2 and JPX are passed through untouched, so any cut
        # is structurally acceptable for them and must be disambiguated by
        # other means (the whitespace-delimited EI candidate ordering).
        return data

    def get_inline_data(
        self,
        pos: int,
        attrs: Mapping[str, object],
        filters: Sequence[object] | None,
    ) -> "InlineImageData | None":
        """Extract the data of an inline image.

        ``pos`` points just past the ``ID`` operator and its mandatory
        single whitespace.  ``attrs`` are the inline image dictionary
        entries and ``filters`` is its (possibly empty) filter chain.

        Returns an :class:`InlineImageData` whose ``data`` holds the image
        bytes and ``eod`` records how the boundary was found, or ``None``
        when the boundary cannot be determined reliably.  In the latter
        case the parser position is restored to ``pos`` so the following
        content (e.g. text shown with ``BT``/``Tj``) keeps its original
        source instead of being swallowed as image data.
        """
        self.seek(pos)
        stream_index = self._current_stream_index()
        self._consume_leading_whitespace(stream_index)

        if filters is not None:
            return self._find_filtered_boundary(stream_index, filters)

        expected = self._expected_image_length(attrs)
        if expected is not None:
            found = self._find_ei_boundary(stream_index, expected)
            if found is None:
                log.warning(
                    "Inline image: expected the EI operator %d byte(s) "
                    "after the start of the data but could not confirm it; "
                    "leaving the remainder of the content stream untouched",
                    expected,
                )
                self._reposition(stream_index, pos)
                return None
            ei_pos, data = found
            return InlineImageData(data=data, eod=b"EI", end=ei_pos)

        # No dimensional information to locate the boundary: fall back to
        # the first whitespace-delimited EI operator rather than guessing.
        candidates = self._collect_ei_candidates(stream_index)
        if not candidates:
            self._reposition(stream_index, pos)
            return None
        ei_pos, data = candidates[0]
        self._reposition(stream_index, ei_pos)
        return InlineImageData(data=data, eod=b"EI", end=ei_pos)

    def flush(self) -> None:
        self.add_results(*self.popall())

    KEYWORD_BI = KWD(b"BI")
    KEYWORD_ID = KWD(b"ID")
    KEYWORD_EI = KWD(b"EI")

    def do_keyword(self, pos: int, token: PSKeyword) -> None:
        if token is self.KEYWORD_BI:
            # inline image within a content stream
            self.start_type(pos, "inline")
        elif token is self.KEYWORD_ID:
            try:
                (_, objs) = self.end_type("inline")
                if len(objs) % 2 != 0:
                    error_msg = f"Invalid dictionary construct: {objs!r}"
                    raise PSTypeError(error_msg)
                d = {literal_name(k): resolve1(v) for (k, v) in choplist(2, objs)}
                filters = d.get("F")
                if isinstance(filters, PSLiteral):
                    filters = [filters]
                image = self.get_inline_data(
                    pos + len(b"ID "), d, filters
                )
                if image is None:
                    # The end of the image could not be located reliably.
                    # Leave the raw bytes in the content stream so that any
                    # real operators that follow are still parsed from
                    # their original source instead of being swallowed.
                    if settings.STRICT:
                        raise PSTypeError(
                            "Could not determine the end of the inline image"
                        )
                    return
                obj = PDFStream(d, image.data)
                self.push((pos, obj))
                if image.eod == b"EI":
                    self.push((pos, self.KEYWORD_EI))
            except PSTypeError:
                if settings.STRICT:
                    raise
        else:
            self.push((pos, token))


# Types that may appear on the PDF argument stack.
PDFStackT = PSStackType[PDFStream]


class PDFPageInterpreter:
    """Processor for the content of a PDF page

    Reference: PDF Reference, Appendix A, Operator Summary
    """

    def __init__(self, rsrcmgr: PDFResourceManager, device: PDFDevice) -> None:
        self.rsrcmgr = rsrcmgr
        self.device = device
        # Track stream IDs currently being executed to detect circular references
        self.stream_ids: set[int] = set()
        # Track stream IDs from parent interpreters in the call stack
        self.parent_stream_ids: set[int] = set()

    def dup(self) -> "PDFPageInterpreter":
        return self.__class__(self.rsrcmgr, self.device)

    def subinterp(self) -> "PDFPageInterpreter":
        """Create a sub-interpreter for processing nested content streams.

        This is used when invoking Form XObjects to prevent circular references.
        Unlike dup(), this method propagates the stream ID tracking from the
        parent interpreter, allowing detection of circular references across
        nested XObject invocations.
        """
        interp = self.dup()
        interp.parent_stream_ids.update(self.parent_stream_ids)
        interp.parent_stream_ids.update(self.stream_ids)
        return interp

    def init_resources(self, resources: dict[object, object]) -> None:
        """Prepare the fonts and XObjects listed in the Resource attribute."""
        self.resources = resources
        self.fontmap: dict[object, PDFFont] = {}
        self.xobjmap = {}
        self.csmap: dict[str, PDFColorSpace] = PREDEFINED_COLORSPACE.copy()
        if not resources:
            return

        def get_colorspace(spec: object) -> PDFColorSpace | None:
            if isinstance(spec, list):
                name = literal_name(spec[0])
            else:
                name = literal_name(spec)
            if name == "ICCBased" and isinstance(spec, list) and len(spec) >= 2:
                return PDFColorSpace(name, int_value(stream_value(spec[1])["N"]))
            elif name == "DeviceN" and isinstance(spec, list) and len(spec) >= 2:
                return PDFColorSpace(name, len(list_value(spec[1])))
            else:
                return PREDEFINED_COLORSPACE.get(name)

        for k, v in dict_value(resources).items():
            log.debug("Resource: %r: %r", k, v)
            if k == "Font":
                for fontid, spec in dict_value(v).items():
                    objid = None
                    if isinstance(spec, PDFObjRef):
                        objid = spec.objid
                    spec = dict_value(spec)
                    self.fontmap[fontid] = self.rsrcmgr.get_font(objid, spec)
            elif k == "ColorSpace":
                for csid, spec in dict_value(v).items():
                    colorspace = get_colorspace(resolve1(spec))
                    if colorspace is not None:
                        self.csmap[csid] = colorspace
            elif k == "ProcSet":
                self.rsrcmgr.get_procset(list_value(v))
            elif k == "XObject":
                for xobjid, xobjstrm in dict_value(v).items():
                    self.xobjmap[xobjid] = xobjstrm

    def init_state(self, ctm: Matrix) -> None:
        """Initialize the text and graphic states for rendering a page."""
        # gstack: stack for graphical states.
        self.gstack: list[tuple[Matrix, PDFTextState, PDFGraphicState]] = []
        self.ctm = ctm
        self.device.set_ctm(self.ctm)
        self.textstate = PDFTextState()
        self.graphicstate = PDFGraphicState()
        self.curpath: list[PathSegment] = []
        # argstack: stack for command arguments.
        self.argstack: list[PDFStackT] = []

    def push(self, obj: PDFStackT) -> None:
        self.argstack.append(obj)

    def pop(self, n: int) -> list[PDFStackT]:
        if n == 0:
            return []
        x = self.argstack[-n:]
        self.argstack = self.argstack[:-n]
        return x

    def get_current_state(self) -> tuple[Matrix, PDFTextState, PDFGraphicState]:
        return (self.ctm, self.textstate.copy(), self.graphicstate.copy())

    def set_current_state(
        self,
        state: tuple[Matrix, PDFTextState, PDFGraphicState],
    ) -> None:
        (self.ctm, self.textstate, self.graphicstate) = state
        self.device.set_ctm(self.ctm)

    def do_q(self) -> None:
        """Save graphics state"""
        self.gstack.append(self.get_current_state())

    def do_Q(self) -> None:
        """Restore graphics state"""
        if self.gstack:
            self.set_current_state(self.gstack.pop())

    def do_cm(
        self,
        a1: PDFStackT,
        b1: PDFStackT,
        c1: PDFStackT,
        d1: PDFStackT,
        e1: PDFStackT,
        f1: PDFStackT,
    ) -> None:
        """Concatenate matrix to current transformation matrix"""
        matrix = safe_matrix(a1, b1, c1, d1, e1, f1)

        if matrix is None:
            log.warning(
                "Cannot concatenate matrix to current transformation matrix "
                "because not all values in %r can be parsed as floats",
                (a1, b1, c1, d1, e1, f1),
            )
        else:
            self.ctm = mult_matrix(matrix, self.ctm)
            self.device.set_ctm(self.ctm)

    def do_w(self, linewidth: PDFStackT) -> None:
        """Set line width"""
        linewidth_f = safe_float(linewidth)
        if linewidth_f is None:
            log.warning(
                "Cannot set line width because %r is an invalid float value",
                linewidth,
            )
        else:
            scale = (self.ctm[0] ** 2 + self.ctm[1] ** 2) ** 0.5
            self.graphicstate.linewidth = linewidth_f * scale

    def do_J(self, linecap: PDFStackT) -> None:
        """Set line cap style"""
        self.graphicstate.linecap = linecap

    def do_j(self, linejoin: PDFStackT) -> None:
        """Set line join style"""
        self.graphicstate.linejoin = linejoin

    def do_M(self, miterlimit: PDFStackT) -> None:
        """Set miter limit"""
        self.graphicstate.miterlimit = miterlimit

    def do_d(self, dash: PDFStackT, phase: PDFStackT) -> None:
        """Set line dash pattern"""
        self.graphicstate.dash = (dash, phase)

    def do_ri(self, intent: PDFStackT) -> None:
        """Set color rendering intent"""
        self.graphicstate.intent = intent

    def do_i(self, flatness: PDFStackT) -> None:
        """Set flatness tolerance"""
        self.graphicstate.flatness = flatness

    def do_gs(self, name: PDFStackT) -> None:
        """Set parameters from graphics state parameter dictionary"""
        # TODO

    def do_m(self, x: PDFStackT, y: PDFStackT) -> None:
        """Begin new subpath"""
        x_f = safe_float(x)
        y_f = safe_float(y)

        if x_f is None or y_f is None:
            point = ("m", x, y)
            log.warning(
                "Cannot start new subpath because not all values "
                "in %r can be parsed as floats",
                point,
            )
        else:
            point = ("m", x_f, y_f)
            self.curpath.append(point)

    def do_l(self, x: PDFStackT, y: PDFStackT) -> None:
        """Append straight line segment to path"""
        x_f = safe_float(x)
        y_f = safe_float(y)
        if x_f is None or y_f is None:
            point = ("l", x, y)
            log.warning(
                "Cannot append straight line segment to path "
                "because not all values in %r can be parsed as floats",
                point,
            )
        else:
            point = ("l", x_f, y_f)
            self.curpath.append(point)

    def do_c(
        self,
        x1: PDFStackT,
        y1: PDFStackT,
        x2: PDFStackT,
        y2: PDFStackT,
        x3: PDFStackT,
        y3: PDFStackT,
    ) -> None:
        """Append curved segment to path (three control points)"""
        x1_f = safe_float(x1)
        y1_f = safe_float(y1)
        x2_f = safe_float(x2)
        y2_f = safe_float(y2)
        x3_f = safe_float(x3)
        y3_f = safe_float(y3)
        if (
            x1_f is None
            or y1_f is None
            or x2_f is None
            or y2_f is None
            or x3_f is None
            or y3_f is None
        ):
            point = ("c", x1, y1, x2, y2, x3, y3)
            log.warning(
                "Cannot append curved segment to path "
                "because not all values in %r can be parsed as floats",
                point,
            )
        else:
            point = ("c", x1_f, y1_f, x2_f, y2_f, x3_f, y3_f)
            self.curpath.append(point)

    def do_v(self, x2: PDFStackT, y2: PDFStackT, x3: PDFStackT, y3: PDFStackT) -> None:
        """Append curved segment to path (initial point replicated)"""
        x2_f = safe_float(x2)
        y2_f = safe_float(y2)
        x3_f = safe_float(x3)
        y3_f = safe_float(y3)
        if x2_f is None or y2_f is None or x3_f is None or y3_f is None:
            point = ("v", x2, y2, x3, y3)
            log.warning(
                "Cannot append curved segment to path "
                "because not all values in %r can be parsed as floats",
                point,
            )
        else:
            point = ("v", x2_f, y2_f, x3_f, y3_f)
            self.curpath.append(point)

    def do_y(self, x1: PDFStackT, y1: PDFStackT, x3: PDFStackT, y3: PDFStackT) -> None:
        """Append curved segment to path (final point replicated)"""
        x1_f = safe_float(x1)
        y1_f = safe_float(y1)
        x3_f = safe_float(x3)
        y3_f = safe_float(y3)
        if x1_f is None or y1_f is None or x3_f is None or y3_f is None:
            point = ("y", x1, y1, x3, y3)
            log.warning(
                "Cannot append curved segment to path "
                "because not all values in %r can be parsed as floats",
                point,
            )
        else:
            point = ("y", x1_f, y1_f, x3_f, y3_f)
            self.curpath.append(point)

    def do_h(self) -> None:
        """Close subpath"""
        self.curpath.append(("h",))

    def do_re(self, x: PDFStackT, y: PDFStackT, w: PDFStackT, h: PDFStackT) -> None:
        """Append rectangle to path"""
        x_f = safe_float(x)
        y_f = safe_float(y)
        w_f = safe_float(w)
        h_f = safe_float(h)

        if x_f is None or y_f is None or w_f is None or h_f is None:
            values = (x, y, w, h)
            log.warning(
                "Cannot append rectangle to path "
                "because not all values in %r can be parsed as floats",
                values,
            )
        else:
            self.curpath.append(("m", x_f, y_f))
            self.curpath.append(("l", x_f + w_f, y_f))
            self.curpath.append(("l", x_f + w_f, y_f + h_f))
            self.curpath.append(("l", x_f, y_f + h_f))
            self.curpath.append(("h",))

    def do_S(self) -> None:
        """Stroke path"""
        self.device.paint_path(self.graphicstate, True, False, False, self.curpath)
        self.curpath = []

    def do_s(self) -> None:
        """Close and stroke path"""
        self.do_h()
        self.do_S()

    def do_f(self) -> None:
        """Fill path using nonzero winding number rule"""
        self.device.paint_path(self.graphicstate, False, True, False, self.curpath)
        self.curpath = []

    def do_F(self) -> None:
        """Fill path using nonzero winding number rule (obsolete)"""

    def do_f_a(self) -> None:
        """Fill path using even-odd rule"""
        self.device.paint_path(self.graphicstate, False, True, True, self.curpath)
        self.curpath = []

    def do_B(self) -> None:
        """Fill and stroke path using nonzero winding number rule"""
        self.device.paint_path(self.graphicstate, True, True, False, self.curpath)
        self.curpath = []

    def do_B_a(self) -> None:
        """Fill and stroke path using even-odd rule"""
        self.device.paint_path(self.graphicstate, True, True, True, self.curpath)
        self.curpath = []

    def do_b(self) -> None:
        """Close, fill, and stroke path using nonzero winding number rule"""
        self.do_h()
        self.do_B()

    def do_b_a(self) -> None:
        """Close, fill, and stroke path using even-odd rule"""
        self.do_h()
        self.do_B_a()

    def do_n(self) -> None:
        """End path without filling or stroking"""
        self.curpath = []

    def do_W(self) -> None:
        """Set clipping path using nonzero winding number rule"""

    def do_W_a(self) -> None:
        """Set clipping path using even-odd rule"""

    def do_CS(self, name: PDFStackT) -> None:
        """Set color space for stroking operations

        Introduced in PDF 1.1
        """
        try:
            self.graphicstate.scs = self.csmap[literal_name(name)]
        except KeyError as err:
            if settings.STRICT:
                raise PDFInterpreterError(f"Undefined ColorSpace: {name!r}") from err

    def do_cs(self, name: PDFStackT) -> None:
        """Set color space for nonstroking operations"""
        try:
            self.graphicstate.ncs = self.csmap[literal_name(name)]
        except KeyError as err:
            if settings.STRICT:
                raise PDFInterpreterError(f"Undefined ColorSpace: {name!r}") from err

    def do_G(self, gray: PDFStackT) -> None:
        """Set gray level for stroking operations"""
        gray_f = safe_float(gray)

        if gray_f is None:
            log.warning(
                "Cannot set gray level because %r is an invalid float value",
                gray,
            )
        else:
            self.graphicstate.scolor = gray_f
            self.graphicstate.scs = self.csmap["DeviceGray"]

    def do_g(self, gray: PDFStackT) -> None:
        """Set gray level for nonstroking operations"""
        gray_f = safe_float(gray)

        if gray_f is None:
            log.warning(
                "Cannot set gray level because %r is an invalid float value",
                gray,
            )
        else:
            self.graphicstate.ncolor = gray_f
            self.graphicstate.ncs = self.csmap["DeviceGray"]

    def do_RG(self, r: PDFStackT, g: PDFStackT, b: PDFStackT) -> None:
        """Set RGB color for stroking operations"""
        rgb = safe_rgb(r, g, b)

        if rgb is None:
            log.warning(
                "Cannot set RGB stroke color "
                "because not all values in %r can be parsed as floats",
                (r, g, b),
            )
        else:
            self.graphicstate.scolor = rgb
            self.graphicstate.scs = self.csmap["DeviceRGB"]

    def do_rg(self, r: PDFStackT, g: PDFStackT, b: PDFStackT) -> None:
        """Set RGB color for nonstroking operations"""
        rgb = safe_rgb(r, g, b)

        if rgb is None:
            log.warning(
                "Cannot set RGB non-stroke color "
                "because not all values in %r can be parsed as floats",
                (r, g, b),
            )
        else:
            self.graphicstate.ncolor = rgb
            self.graphicstate.ncs = self.csmap["DeviceRGB"]

    def do_K(self, c: PDFStackT, m: PDFStackT, y: PDFStackT, k: PDFStackT) -> None:
        """Set CMYK color for stroking operations"""
        cmyk = safe_cmyk(c, m, y, k)

        if cmyk is None:
            log.warning(
                "Cannot set CMYK stroke color "
                "because not all values in %r can be parsed as floats",
                (c, m, y, k),
            )
        else:
            self.graphicstate.scolor = cmyk
            self.graphicstate.scs = self.csmap["DeviceCMYK"]

    def do_k(self, c: PDFStackT, m: PDFStackT, y: PDFStackT, k: PDFStackT) -> None:
        """Set CMYK color for nonstroking operations"""
        cmyk = safe_cmyk(c, m, y, k)

        if cmyk is None:
            log.warning(
                "Cannot set CMYK non-stroke color "
                "because not all values in %r can be parsed as floats",
                (c, m, y, k),
            )
        else:
            self.graphicstate.ncolor = cmyk
            self.graphicstate.ncs = self.csmap["DeviceCMYK"]

    def _parse_color_components(
        self, components: list[PDFStackT], context: str
    ) -> StandardColor | None:
        """Parse color components into StandardColor (gray, RGB, or CMYK).

        Args:
            components: List of 1, 3, or 4 numeric color components
            context: Description for error messages (e.g., "stroke", "non-stroke")

        Returns:
            Parsed color (float for gray, tuple for RGB/CMYK) or None if invalid
        """
        if len(components) == 1:
            gray = safe_float(components[0])
            if gray is None:
                log.warning(
                    "Cannot set %s color: %r is an invalid float value",
                    context,
                    components[0],
                )
            return gray

        elif len(components) == 3:
            rgb = safe_rgb(*components)
            if rgb is None:
                log.warning(
                    "Cannot set %s color: components %r cannot be parsed as RGB",
                    context,
                    components,
                )
            return rgb

        elif len(components) == 4:
            cmyk = safe_cmyk(*components)
            if cmyk is None:
                log.warning(
                    "Cannot set %s color: components %r cannot be parsed as CMYK",
                    context,
                    components,
                )
            return cmyk

        else:
            log.warning(
                "Cannot set %s color: %d components specified, "
                "but only 1 (grayscale), 3 (RGB), and 4 (CMYK) are supported",
                context,
                len(components),
            )
            return None

    def do_SCN(self) -> None:
        """Set color for stroking operations.

        Handles Pattern color spaces per ISO 32000-1:2008 4.5.5 (PDF 1.7)
        and ISO 32000-2:2020 8.7.3 (PDF 2.0):
        - Colored patterns (PaintType=1): single operand (pattern name)
        - Uncolored patterns (PaintType=2): n+1 operands (colors + pattern name)
        """
        n = self.graphicstate.scs.ncomponents

        components = self.pop(n)
        if len(components) != n:
            log.warning(
                "Cannot set stroke color because expected %d components but got %r",
                n,
                components,
            )

        elif self.graphicstate.scs.name != "Pattern":
            # Standard colors (gray, RGB, CMYK) - common case
            color = self._parse_color_components(components, "stroke")
            if color is not None:
                self.graphicstate.scolor = color

        elif len(components) >= 1:
            # Pattern color space (ISO 32000 8.7.3.2-3)
            # Last component is always the pattern name
            pattern_component = components[-1]

            # Per spec: pattern name must be a name object (PSLiteral)
            if not isinstance(pattern_component, PSLiteral):
                log.warning(
                    "Pattern color space requires name object (PSLiteral), "
                    "got %s: %r. "
                    "Per ISO 32000 8.7.3.2, colored patterns use syntax '/name SCN'. "
                    "Per ISO 32000 8.7.3.3, uncolored patterns use "
                    "syntax 'c1...cn /name SCN'.",
                    type(pattern_component).__name__,
                    pattern_component,
                )
                return

            pattern_name = literal_name(pattern_component)

            if len(components) == 1:
                # Colored tiling pattern (PaintType=1): just pattern name
                self.graphicstate.scolor = pattern_name
                log.debug("Set stroke pattern (colored): %s", pattern_name)
            else:
                # Uncolored tiling pattern (PaintType=2):
                # color components + pattern name
                base_color_components = components[:-1]

                # Parse base color using shared logic
                base_color = self._parse_color_components(
                    base_color_components, "stroke (uncolored pattern)"
                )
                if base_color is None:
                    return

                # Store as tuple: (base_color, pattern_name)
                self.graphicstate.scolor = (base_color, pattern_name)
                log.debug(
                    "Set stroke pattern (uncolored): %s + %s", base_color, pattern_name
                )

    def do_scn(self) -> None:
        """Set color for nonstroking operations.

        Handles Pattern color spaces per ISO 32000-1:2008 4.5.5 (PDF 1.7)
        and ISO 32000-2:2020 §8.7.3 (PDF 2.0):
        - Colored patterns (PaintType=1): single operand (pattern name)
        - Uncolored patterns (PaintType=2): n+1 operands (colors + pattern name)
        """
        n = self.graphicstate.ncs.ncomponents

        components = self.pop(n)
        if len(components) != n:
            log.warning(
                "Cannot set non-stroke color because expected %d components but got %r",
                n,
                components,
            )

        elif self.graphicstate.ncs.name != "Pattern":
            # Standard colors (gray, RGB, CMYK) - common case
            color = self._parse_color_components(components, "non-stroke")
            if color is not None:
                self.graphicstate.ncolor = color

        elif len(components) >= 1:
            # Pattern color space (ISO 32000 8.7.3.2-3)
            # Last component is always the pattern name
            pattern_component = components[-1]

            # Per spec: pattern name must be a name object (PSLiteral)
            if not isinstance(pattern_component, PSLiteral):
                log.warning(
                    "Pattern color space requires name object (PSLiteral), "
                    "got %s: %r. "
                    "Per ISO 32000 8.7.3.2, colored patterns use syntax '/name scn'. "
                    "Per ISO 32000 8.7.3.3, uncolored patterns use "
                    "syntax 'c1...cn /name scn'.",
                    type(pattern_component).__name__,
                    pattern_component,
                )
                return

            pattern_name = literal_name(pattern_component)

            if len(components) == 1:
                # Colored tiling pattern (PaintType=1): just pattern name
                self.graphicstate.ncolor = pattern_name
                log.debug("Set non-stroke pattern (colored): %s", pattern_name)
            else:
                # Uncolored tiling pattern (PaintType=2):
                # color components + pattern name
                base_color_components = components[:-1]

                # Parse base color using shared logic
                base_color = self._parse_color_components(
                    base_color_components, "non-stroke (uncolored pattern)"
                )
                if base_color is None:
                    return

                # Store as tuple: (base_color, pattern_name)
                self.graphicstate.ncolor = (base_color, pattern_name)
                log.debug(
                    "Set non-stroke pattern (uncolored): %s + %s",
                    base_color,
                    pattern_name,
                )

    def do_SC(self) -> None:
        """Set color for stroking operations"""
        self.do_SCN()

    def do_sc(self) -> None:
        """Set color for nonstroking operations"""
        self.do_scn()

    def do_sh(self, name: object) -> None:
        """Paint area defined by shading pattern"""

    def do_BT(self) -> None:
        """Begin text object

        Initializing the text matrix, Tm, and the text line matrix, Tlm, to
        the identity matrix. Text objects cannot be nested; a second BT cannot
        appear before an ET.
        """
        self.textstate.reset()

    def do_ET(self) -> None:
        """End a text object"""

    def do_BX(self) -> None:
        """Begin compatibility section"""

    def do_EX(self) -> None:
        """End compatibility section"""

    def do_MP(self, tag: PDFStackT) -> None:
        """Define marked-content point"""
        if isinstance(tag, PSLiteral):
            self.device.do_tag(tag)
        else:
            log.warning(
                "Cannot define marked-content point because %r is not a PSLiteral",
                tag,
            )

    def do_DP(self, tag: PDFStackT, props: PDFStackT) -> None:
        """Define marked-content point with property list"""
        if isinstance(tag, PSLiteral):
            self.device.do_tag(tag, props)
        else:
            log.warning(
                "Cannot define marked-content point with property list "
                "because %r is not a PSLiteral",
                tag,
            )

    def do_BMC(self, tag: PDFStackT) -> None:
        """Begin marked-content sequence"""
        if isinstance(tag, PSLiteral):
            self.device.begin_tag(tag)
        else:
            log.warning(
                "Cannot begin marked-content sequence because %r is not a PSLiteral",
                tag,
            )

    def do_BDC(self, tag: PDFStackT, props: PDFStackT) -> None:
        """Begin marked-content sequence with property list"""
        if isinstance(tag, PSLiteral):
            self.device.begin_tag(tag, props)
        else:
            log.warning(
                "Cannot begin marked-content sequence with property list "
                "because %r is not a PSLiteral",
                tag,
            )

    def do_EMC(self) -> None:
        """End marked-content sequence"""
        self.device.end_tag()

    def do_Tc(self, space: PDFStackT) -> None:
        """Set character spacing.

        Character spacing is used by the Tj, TJ, and ' operators.

        :param space: a number expressed in unscaled text space units.
        """
        charspace = safe_float(space)
        if charspace is None:
            log.warning(
                "Could not set character spacing because %r is an invalid float value",
                space,
            )
        else:
            self.textstate.charspace = charspace

    def do_Tw(self, space: PDFStackT) -> None:
        """Set the word spacing.

        Word spacing is used by the Tj, TJ, and ' operators.

        :param space: a number expressed in unscaled text space units
        """
        wordspace = safe_float(space)
        if wordspace is None:
            log.warning(
                "Could not set word spacing because %r is an invalid float value",
                space,
            )
        else:
            self.textstate.wordspace = wordspace

    def do_Tz(self, scale: PDFStackT) -> None:
        """Set the horizontal scaling.

        :param scale: is a number specifying the percentage of the normal width
        """
        scale_f = safe_float(scale)

        if scale_f is None:
            log.warning(
                "Could not set horizontal scaling because %r is an invalid float value",
                scale,
            )
        else:
            self.textstate.scaling = scale_f

    def do_TL(self, leading: PDFStackT) -> None:
        """Set the text leading.

        Text leading is used only by the T*, ', and " operators.

        :param leading: a number expressed in unscaled text space units
        """
        leading_f = safe_float(leading)
        if leading_f is None:
            log.warning(
                "Could not set text leading because %r is an invalid float value",
                leading,
            )
        else:
            self.textstate.leading = -leading_f

    def do_Tf(self, fontid: PDFStackT, fontsize: PDFStackT) -> None:
        """Set the text font

        :param fontid: the name of a font resource in the Font subdictionary
            of the current resource dictionary
        :param fontsize: size is a number representing a scale factor.
        """
        try:
            self.textstate.font = self.fontmap[literal_name(fontid)]
        except KeyError as err:
            if settings.STRICT:
                raise PDFInterpreterError(f"Undefined Font id: {fontid!r}") from err
            self.textstate.font = self.rsrcmgr.get_font(None, {})

        fontsize_f = safe_float(fontsize)
        if fontsize_f is None:
            log.warning(
                "Could not set text font because %r is an invalid float value",
                fontsize,
            )
        else:
            self.textstate.fontsize = fontsize_f

    def do_Tr(self, render: PDFStackT) -> None:
        """Set the text rendering mode"""
        render_i = safe_int(render)

        if render_i is None:
            log.warning(
                "Could not set text rendering mode because %r is an invalid int value",
                render,
            )
        else:
            self.textstate.render = render_i

    def do_Ts(self, rise: PDFStackT) -> None:
        """Set the text rise

        :param rise: a number expressed in unscaled text space units
        """
        rise_f = safe_float(rise)

        if rise_f is None:
            log.warning(
                "Could not set text rise because %r is an invalid float value",
                rise,
            )
        else:
            self.textstate.rise = rise_f

    def do_Td(self, tx: PDFStackT, ty: PDFStackT) -> None:
        """Move to the start of the next line

        Offset from the start of the current line by (tx , ty).
        """
        tx_ = safe_float(tx)
        ty_ = safe_float(ty)
        if tx_ is not None and ty_ is not None:
            (a, b, c, d, e, f) = self.textstate.matrix
            e_new = tx_ * a + ty_ * c + e
            f_new = tx_ * b + ty_ * d + f
            self.textstate.matrix = (a, b, c, d, e_new, f_new)

        elif settings.STRICT:
            raise PDFValueError(f"Invalid offset ({tx!r}, {ty!r}) for Td")

        self.textstate.linematrix = (0, 0)

    def do_TD(self, tx: PDFStackT, ty: PDFStackT) -> None:
        """Move to the start of the next line.

        offset from the start of the current line by (tx , ty). As a side effect, this
        operator sets the leading parameter in the text state.
        """
        tx_ = safe_float(tx)
        ty_ = safe_float(ty)

        if tx_ is not None and ty_ is not None:
            (a, b, c, d, e, f) = self.textstate.matrix
            e_new = tx_ * a + ty_ * c + e
            f_new = tx_ * b + ty_ * d + f
            self.textstate.matrix = (a, b, c, d, e_new, f_new)

        elif settings.STRICT:
            raise PDFValueError("Invalid offset ({tx}, {ty}) for TD")

        if ty_ is not None:
            self.textstate.leading = ty_

        self.textstate.linematrix = (0, 0)

    def do_Tm(
        self,
        a: PDFStackT,
        b: PDFStackT,
        c: PDFStackT,
        d: PDFStackT,
        e: PDFStackT,
        f: PDFStackT,
    ) -> None:
        """Set text matrix and text line matrix"""
        values = (a, b, c, d, e, f)
        matrix = safe_matrix(*values)

        if matrix is None:
            log.warning(
                "Could not set text matrix because "
                "not all values in %r can be parsed as floats",
                values,
            )
        else:
            self.textstate.matrix = matrix
            self.textstate.linematrix = (0, 0)

    def do_T_a(self) -> None:
        """Move to start of next text line"""
        (a, b, c, d, e, f) = self.textstate.matrix
        self.textstate.matrix = (
            a,
            b,
            c,
            d,
            self.textstate.leading * c + e,
            self.textstate.leading * d + f,
        )
        self.textstate.linematrix = (0, 0)

    def do_TJ(self, seq: PDFStackT) -> None:
        """Show text, allowing individual glyph positioning"""
        if self.textstate.font is None:
            if settings.STRICT:
                raise PDFInterpreterError("No font specified!")
            return
        self.device.render_string(
            self.textstate,
            cast(PDFTextSeq, seq),
            self.graphicstate.ncs,
            self.graphicstate.copy(),
        )

    def do_Tj(self, s: PDFStackT) -> None:
        """Show text"""
        self.do_TJ([s])

    def do__q(self, s: PDFStackT) -> None:
        """Move to next line and show text

        The ' (single quote) operator.
        """
        self.do_T_a()
        self.do_TJ([s])

    def do__w(self, aw: PDFStackT, ac: PDFStackT, s: PDFStackT) -> None:
        """Set word and character spacing, move to next line, and show text

        The " (double quote) operator.
        """
        self.do_Tw(aw)
        self.do_Tc(ac)
        self.do_TJ([s])

    def do_BI(self) -> None:
        """Begin inline image object"""

    def do_ID(self) -> None:
        """Begin inline image data"""

    def do_EI(self, obj: PDFStackT) -> None:
        """End inline image object"""
        if isinstance(obj, PDFStream) and "W" in obj and "H" in obj:
            iobjid = str(id(obj))
            self.device.begin_figure(iobjid, (0, 0, 1, 1), MATRIX_IDENTITY)
            self.device.render_image(iobjid, obj)
            self.device.end_figure(iobjid)

    def do_Do(self, xobjid_arg: PDFStackT) -> None:
        """Invoke named XObject"""
        xobjid = literal_name(xobjid_arg)
        try:
            xobj = stream_value(self.xobjmap[xobjid])
        except KeyError as err:
            if settings.STRICT:
                raise PDFInterpreterError(f"Undefined xobject id: {xobjid!r}") from err
            return
        log.debug("Processing xobj: %r", xobj)
        subtype = xobj.get("Subtype")
        if subtype is LITERAL_FORM and "BBox" in xobj:
            interpreter = self.subinterp()
            bbox = cast(Rect, list_value(xobj["BBox"]))
            matrix = cast(Matrix, list_value(xobj.get("Matrix", MATRIX_IDENTITY)))
            # According to PDF reference 1.7 section 4.9.1, XObjects in
            # earlier PDFs (prior to v1.2) use the page's Resources entry
            # instead of having their own Resources entry.
            xobjres = xobj.get("Resources")
            resources = dict_value(xobjres) if xobjres else self.resources.copy()
            self.device.begin_figure(xobjid, bbox, matrix)
            interpreter.render_contents(
                resources,
                [xobj],
                ctm=mult_matrix(matrix, self.ctm),
            )
            self.device.end_figure(xobjid)
        elif subtype is LITERAL_IMAGE and "Width" in xobj and "Height" in xobj:
            self.device.begin_figure(xobjid, (0, 0, 1, 1), MATRIX_IDENTITY)
            self.device.render_image(xobjid, xobj)
            self.device.end_figure(xobjid)
        else:
            # unsupported xobject type.
            pass

    def process_page(self, page: PDFPage) -> None:
        log.debug("Processing page: %r", page)
        (x0, y0, x1, y1) = page.mediabox
        if page.rotate == 90:
            ctm = (0, -1, 1, 0, -y0, x1)
        elif page.rotate == 180:
            ctm = (-1, 0, 0, -1, x1, y1)
        elif page.rotate == 270:
            ctm = (0, 1, -1, 0, y1, -x0)
        else:
            ctm = (1, 0, 0, 1, -x0, -y0)
        self.device.begin_page(page, ctm)
        self.render_contents(page.resources, page.contents, ctm=ctm)
        self.device.end_page(page)

    def render_contents(
        self,
        resources: dict[object, object],
        streams: Sequence[object],
        ctm: Matrix = MATRIX_IDENTITY,
    ) -> None:
        """Render the content streams.

        This method may be called recursively.
        """
        log.debug(
            "render_contents: resources=%r, streams=%r, ctm=%r",
            resources,
            streams,
            ctm,
        )
        self.init_resources(resources)
        self.init_state(ctm)
        self.execute(list_value(streams))

    def execute(self, streams: Sequence[object]) -> None:
        # Detect and prevent circular references in content streams
        # (including Form XObjects).
        # We track stream IDs being executed in the current interpreter and
        # all parent interpreters. If a stream is already being processed
        # in the call stack, we skip
        # it to prevent infinite recursion (CWE-835 vulnerability).
        valid_streams: list[PDFStream] = []
        self.stream_ids.clear()
        for obj in streams:
            stream = stream_value(obj)
            if stream.objid is None:
                # Inline streams without object IDs can't be tracked for circular refs
                log.warning(
                    "Execute called on non-indirect object (inline image?) %r", stream
                )
                continue
            if stream.objid in self.parent_stream_ids:
                log.warning(
                    "Refusing to execute circular reference to content stream %d",
                    stream.objid,
                )
            else:
                valid_streams.append(stream)
                self.stream_ids.add(stream.objid)
        try:
            parser = PDFContentParser(valid_streams)
        except PSEOF:
            # empty page
            return
        while True:
            try:
                (_, obj) = parser.nextobject()
            except PSEOF:
                break
            if isinstance(obj, PSKeyword):
                name = keyword_name(obj)
                method = "do_{}".format(
                    name.replace("*", "_a")
                    .replace('"', "_w")
                    .replace(
                        "'",
                        "_q",
                    )
                )
                if hasattr(self, method):
                    func = getattr(self, method)
                    nargs = func.__code__.co_argcount - 1
                    if nargs:
                        args = self.pop(nargs)
                        log.debug("exec: %s %r", name, args)
                        if len(args) == nargs:
                            func(*args)
                    else:
                        log.debug("exec: %s", name)
                        func()
                elif settings.STRICT:
                    error_msg = f"Unknown operator: {name!r}"
                    raise PDFInterpreterError(error_msg)
            else:
                self.push(obj)
