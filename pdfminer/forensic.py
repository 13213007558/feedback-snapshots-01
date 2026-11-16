"""Forensic character-mapping records.

The text shown by a PDF is the result of a chain of mappings: the raw
bytes of a text-showing operand (``Tj`` / ``TJ`` / ``'`` / ``"``) are decoded
into character identifiers (CIDs) by the active font's CMap, and each CID is
then translated into one or more Unicode code points.  A single glyph may map
to several code points (for example a ligature), may have no usable mapping at
all, or may be replaced by a synthetic placeholder.

This module records every step of that chain so that a report can always be
traced back to the exact operand bytes, without guessing from font names.
The original bytes and the emitted text are kept separate from the
normalized text used for searching; replacement placeholders are never
presented as document text.
"""

import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

# Mapping sources, ordered by precedence in the decoding chain.
# A font's ToUnicode CMap takes precedence over the font encoding and over
# the bundled Adobe CMaps shipped with pdfminer.
SOURCE_TOUNICODE = "tounicode"
SOURCE_ENCODING = "encoding"
SOURCE_BUILTIN_CMAP = "builtin-cmap"
SOURCE_IDENTITY = "identity"
SOURCE_TRUETYPE_CMAP = "truetype-cmap"
SOURCE_NONE = "none"

# Result categories for a single decoded glyph.
STATUS_SINGLE = "single"
STATUS_MULTICODEPOINT = "multicodepoint"
STATUS_LIGATURE = "ligature"
STATUS_MISSING = "missing"
STATUS_REPLACEMENT = "replacement"

# Synthetic placeholder emitted when no Unicode mapping exists.  This mirrors
# the long-standing ``(cid:N)`` convention used by the layout analyzer.
CID_PLACEHOLDER_PREFIX = "(cid:"
CID_PLACEHOLDER_SUFFIX = ")"


def is_ligature_text(text: str) -> bool:
    """Return True for a single code point that NFKC-decomposes.

    Compatibility ligatures such as U+FB01 (``fi``) are represented as one
    code point but expand to several characters under NFKC normalization.
    """
    return len(text) == 1 and len(unicodedata.normalize("NFKC", text)) > 1


@dataclass(frozen=True)
class GlyphMapping:
    """Outcome of resolving one CID through a font.

    :param cid: the character identifier decoded from the operand bytes, or
        ``None`` when the bytes could not be decoded to any CID.
    :param text: the Unicode text emitted for the glyph. When ``status`` is
        :data:`STATUS_MISSING` this is an empty string; when it is
        :data:`STATUS_REPLACEMENT` it is a synthetic placeholder.
    :param source: which mapping produced the text, one of the ``SOURCE_*``
        constants.
    :param status: one of the ``STATUS_*`` constants.
    :param codepoints: the Unicode code points emitted for the glyph.
    """

    cid: int | None
    text: str
    source: str
    status: str
    codepoints: tuple[int, ...] = field(default_factory=tuple)

    @property
    def is_missing(self) -> bool:
        return self.status == STATUS_MISSING

    @property
    def is_replacement(self) -> bool:
        return self.status == STATUS_REPLACEMENT

    @property
    def is_multicodepoint(self) -> bool:
        return len(self.codepoints) > 1


@dataclass(frozen=True)
class CharMappingRecord:
    """Forensic record linking one emitted glyph back to its operand.

    The record identifies the font by the stable ``font_id`` assigned by the
    resource manager rather than by its (possibly duplicated or misleading)
    font name, and points at the exact byte range inside a specific
    text-showing operand.

    :param page: zero-indexed page on which the glyph was shown.
    :param operand_index: index of the text operand among the operands of the
        text-showing operator (``Tj`` always has a single operand, ``TJ`` may
        have several byte strings interleaved with positioning numbers).
    :param byte_offset: offset of the glyph's bytes within the operand.
    :param byte_length: number of operand bytes consumed by the glyph.
    :param raw_bytes: the original operand bytes for the glyph, verbatim.
    :param cid: decoded character identifier, or ``None`` if undecodable.
    :param source: mapping source that produced the output.
    :param status: result category.
    :param text: the text actually emitted, including a synthetic placeholder
        when the glyph was substituted. Never treated as original document
        text when ``is_replacement`` is true.
    :param codepoints: emitted Unicode code points.
    :param font_id: stable identifier of the font resource in use.
    :param fontname: font name, retained for display only; localization must
        not rely on it.
    :param operator: the text-showing operator (``Tj``, ``TJ``, ``'`` or
        ``"``).
    """

    page: int
    operand_index: int
    byte_offset: int
    byte_length: int
    raw_bytes: bytes
    cid: int | None
    source: str
    status: str
    text: str
    codepoints: tuple[int, ...]
    font_id: str
    fontname: str
    operator: str

    @property
    def is_missing(self) -> bool:
        return self.status == STATUS_MISSING

    @property
    def is_replacement(self) -> bool:
        return self.status == STATUS_REPLACEMENT

    @property
    def is_ligature(self) -> bool:
        return self.status == STATUS_LIGATURE

    @property
    def is_multicodepoint(self) -> bool:
        return self.status == STATUS_MULTICODEPOINT

    @property
    def byte_range(self) -> tuple[int, int]:
        """Half-open byte range ``(offset, offset + length)`` in the operand."""
        return self.byte_offset, self.byte_offset + self.byte_length

    def codepoint_hex(self) -> list[str]:
        return [f"U+{cp:04X}" for cp in self.codepoints]


def cid_placeholder(cid: int | None) -> str:
    """Build the synthetic placeholder used for an unmapped glyph."""
    identifier = cid if cid is not None else "?"
    return f"{CID_PLACEHOLDER_PREFIX}{identifier}{CID_PLACEHOLDER_SUFFIX}"


class ForensicTrace:
    """Collection of :class:`CharMappingRecord` objects for a document.

    The trace keeps the emitted text and a separate search-oriented
    normalization apart.  Replacement placeholders and missing glyphs never
    enter either text representation as if they were document content;
    ligatures are decomposed by NFKC in :attr:`search_text` so that a search
    for the decomposed spelling still matches.
    """

    def __init__(self, records: Sequence[CharMappingRecord] | None = None) -> None:
        self._records: list[CharMappingRecord] = list(records or [])

    def add(self, record: CharMappingRecord) -> None:
        self._records.append(record)

    def __iter__(self) -> Iterator[CharMappingRecord]:
        return iter(self._records)

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> list[CharMappingRecord]:
        return list(self._records)

    @property
    def document_text(self) -> str:
        """Text as emitted, with placeholders shown explicitly.

        Replacement placeholders are kept verbatim and therefore remain
        distinguishable from genuine document characters.
        """
        return "".join(record.text for record in self._records)

    @property
    def search_text(self) -> str:
        """NFKC-normalized text for searching, without substitutes.

        Ligatures are decomposed (``U+FB01`` becomes ``fi``), multi-code-point
        mappings are preserved as their characters, and missing or replaced
        glyphs contribute nothing so that a placeholder can never match a
        search against the original document.
        """
        parts: list[str] = []
        for record in self._records:
            if record.is_missing or record.is_replacement:
                continue
            parts.append(unicodedata.normalize("NFKC", record.text))
        return "".join(parts)

    def for_operand(
        self,
        font_id: str,
        operand_index: int,
        byte_range: tuple[int, int] | None = None,
    ) -> list[CharMappingRecord]:
        """Return records located without relying on font names.

        Matching is done on the stable font identifier, the operand index and,
        optionally, the half-open byte range within that operand.
        """
        results = []
        for record in self._records:
            if record.font_id != font_id or record.operand_index != operand_index:
                continue
            if byte_range is not None and record.byte_range != byte_range:
                continue
            results.append(record)
        return results
