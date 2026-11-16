from __future__ import annotations

import codecs
from dataclasses import dataclass
from enum import Enum
from typing import Final

UTF16LE: Final[str] = "utf-16-le"
# latin-1 maps every byte 0x00-0xFF bijectively to U+0000-U+00FF. It is used
# only as a lossless, locale-independent view of ANSI bytes that have no
# trustworthy code page. It is never claimed to be the field's real encoding.
LATIN1: Final[str] = "latin-1"


class TextKind(str, Enum):
    """How the boundaries of a textual field are determined."""

    UTF16 = "utf-16le"
    ANSI = "ansi"


class DecodeStatus(str, Enum):
    """The confidence with which the raw bytes were interpreted."""

    DECODED = "decoded"
    DECODED_WITH_ESCAPES = "decoded_with_escapes"
    PENDING = "pending"


class EncodingSource(str, Enum):
    """Why a particular codec was (or was not) applied to a field."""

    # MS-SHLLINK explicitly defines the field as a Unicode (UTF-16LE) string.
    SPEC_UNICODE = "spec-unicode"
    # The field encoding was selected by the LinkFlags.is_unicode control bit.
    LINK_FLAG_IS_UNICODE = "link-flag-is_unicode"
    # The codec was supplied out of band by the caller, with stated provenance.
    CALLER = "caller"
    # The codec came from a ConsoleFEDataBlock CodePage, explicitly applied by
    # the caller. ConsoleFE pages are never applied automatically.
    CONSOLE_FE_HINT = "console-fe-hint"
    # An ANSI field whose "system default code page" is not recorded in the LNK.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AnsiCodec:
    """A code page for ANSI fields, bundled with its provenance.

    The parser itself never guesses an ANSI code page. Instances must be handed
    in by a caller that obtained the information out of band (host inventory,
    incident notes, an explicit ConsoleFE declaration, ...). ``origin`` records
    the kind of source and ``provenance`` records the exact justification, so
    every decoded field stays individually explainable.

    Args:
        codec: A Python codec name, e.g. ``"cp932"`` or ``"cp1252"``.
        provenance: Free-form justification carried onto every decoded field.
        origin: Classification of where the codec came from.
        note: Optional extra context carried onto every decoded field.
    """

    codec: str
    provenance: str = "caller-supplied"
    origin: EncodingSource = EncodingSource.CALLER
    note: str | None = None

    def __post_init__(self) -> None:
        # Fail fast on an unknown codec instead of silently producing pending data.
        codecs.lookup(self.codec)

    @classmethod
    def from_console_fe(cls, code_page: int, note: str | None = None) -> AnsiCodec:
        """Build a codec from an explicit, caller-confirmed ConsoleFE code page.

        The ConsoleFEDataBlock documents the console code page of the creating
        host, but MS-SHLLINK does not bind it to the ANSI string fields. This
        factory exists so a caller can deliberately apply it; the parser never
        calls it on its own.
        """
        codec = code_page_to_codec(code_page)
        return cls(
            codec=codec,
            provenance=f"console-fe-codepage:{code_page}",
            origin=EncodingSource.CONSOLE_FE_HINT,
            note=note,
        )


def code_page_to_codec(code_page: int) -> str:
    """Resolve a Windows code page identifier to a Python codec name."""
    # Windows code page numbers and Python "cpNNNN" codecs align for the ANSI
    # and OEM pages the LNK format is actually produced with.
    return f"cp{code_page}"


def coerce_ansi_codec(ansi_codec: AnsiCodec | str | None) -> AnsiCodec | None:
    """Normalize the accepted ``ansi_codec`` argument forms.

    Args:
        ansi_codec: ``None``, a plain Python codec name, or a ready
            :class:`AnsiCodec` carrying provenance.

    Returns:
        An :class:`AnsiCodec` instance or ``None`` when nothing was supplied.
    """
    if ansi_codec is None or isinstance(ansi_codec, AnsiCodec):
        return ansi_codec
    return AnsiCodec(codec=ansi_codec)


@dataclass(frozen=True)
class EncodedText:
    """A single textual LNK field with a fully documented decoding decision.

    The raw bytes are always retained, so two distinct byte sequences can never
    collapse into one display value. ANSI fields without a trustworthy code page
    stay :attr:`DecodeStatus.PENDING` instead of being decoded against the host
    locale or an assumed code page.

    Args:
        name: Dotted field path, e.g. ``stringdata.working_dir``.
        kind: Whether the field is UTF-16LE or ANSI.
        raw: The exact bytes stored in the LNK (null terminator removed where
            the structure defines one).
        value: The decoded string, or ``None`` when the field is pending.
        codec: The codec used for decoding, or ``None`` when pending.
        source: Why this codec was applied.
        status: Outcome of the decoding decision.
        note: Optional human-readable provenance detail.
    """

    name: str
    kind: TextKind
    raw: bytes
    value: str | None
    codec: str | None
    source: EncodingSource
    status: DecodeStatus
    note: str | None = None

    @property
    def is_pending(self) -> bool:
        """Whether the field could not be interpreted without external input."""
        return self.status == DecodeStatus.PENDING

    @property
    def text(self) -> str:
        """A locale-independent, lossless readable representation.

        Decoded fields return their value. Pending fields fall back to a latin-1
        view of the raw bytes: the mapping is bijective and uses no host locale,
        so distinct byte sequences always remain distinguishable. It does not
        claim latin-1 is the field's real code page.
        """
        if self.value is not None:
            return self.value
        return self.raw.decode(LATIN1)

    def explain(self) -> str:
        """One-line, per-field explanation of the decoding basis."""
        if self.status == DecodeStatus.PENDING:
            return f"{self.name}: ANSI field, code page not recorded in the LNK; left undecoded (raw={self.raw.hex()})"
        detail = f"{self.name}: {self.kind.value} decoded with {self.codec} (source={self.source.value}"
        if self.note:
            detail += f", note={self.note}"
        detail += f", status={self.status.value})"
        return detail

    def decode(self, codec: str = LATIN1, errors: str = "strict") -> str:
        """Byte-compatible helper for callers that used to call ``bytes.decode``.

        Pending fields are decoded on demand with the supplied codec (latin-1 by
        default, which is lossless and never raises). Already decoded fields
        ignore the arguments and return their stored value.
        """
        if self.value is not None:
            return self.value
        return self.raw.decode(codec, errors)

    def __str__(self) -> str:
        return self.text

    def __len__(self) -> int:
        return len(self.text)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EncodedText):
            return (self.kind, self.raw) == (other.kind, other.raw)
        if isinstance(other, bytes | bytearray | memoryview):
            return self.raw == bytes(other)
        if isinstance(other, str):
            return self.text == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.kind, self.raw))


def _decode_with_fallback(raw: bytes, codec: str) -> tuple[str, DecodeStatus]:
    try:
        return raw.decode(codec), DecodeStatus.DECODED
    except UnicodeDecodeError:
        # surrogateescape keeps every unmappable byte as a lone surrogate, so the
        # transformation stays reversible and can never merge distinct inputs.
        return raw.decode(codec, errors="surrogateescape"), DecodeStatus.DECODED_WITH_ESCAPES


def decode_utf16le(
    name: str,
    raw: bytes,
    source: EncodingSource = EncodingSource.SPEC_UNICODE,
    note: str | None = None,
) -> EncodedText:
    """Decode an explicitly UTF-16LE field without consulting the host locale.

    A truncated trailing byte is padded instead of raising, mirroring how
    Windows tolerates padded buffers.
    """
    padded = raw
    if len(padded) % 2:
        padded = padded + b"\x00"
        padding_note = "odd byte length padded with 0x00"
        note = f"{note}; {padding_note}" if note else padding_note
    value, status = _decode_with_fallback(padded, UTF16LE)
    return EncodedText(
        name=name,
        kind=TextKind.UTF16,
        raw=raw,
        value=value,
        codec=UTF16LE,
        source=source,
        status=status,
        note=note,
    )


def decode_ansi(name: str, raw: bytes, ansi_codec: AnsiCodec | None) -> EncodedText:
    """Interpret an ANSI field, or leave it pending when no codec is trusted.

    The LNK format only says these bytes use the creating host's "system default
    code page", which is not stored anywhere. Without caller-supplied provenance
    the bytes are retained untouched and marked pending.
    """
    if ansi_codec is None:
        return EncodedText(
            name=name,
            kind=TextKind.ANSI,
            raw=raw,
            value=None,
            codec=None,
            source=EncodingSource.UNKNOWN,
            status=DecodeStatus.PENDING,
            note="system default code page not recorded in the LNK",
        )

    value, status = _decode_with_fallback(raw, ansi_codec.codec)
    note = ansi_codec.note or ansi_codec.provenance
    if ansi_codec.note and ansi_codec.provenance:
        note = f"{ansi_codec.note} ({ansi_codec.provenance})"
    return EncodedText(
        name=name,
        kind=TextKind.ANSI,
        raw=raw,
        value=value,
        codec=ansi_codec.codec,
        source=ansi_codec.origin,
        status=status,
        note=note,
    )
