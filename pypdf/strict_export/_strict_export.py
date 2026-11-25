"""Implementation of the strict export decision helpers.

The whole module is built around byte-level guarantees. A token is considered
present only if its encoded bytes occur in the file, because that is exactly
what an outsider can recover with ``grep`` or by carving the raw stream,
regardless of whether any object still points at it.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

if TYPE_CHECKING:
    from pypdf.generic import IndirectObject

PathOrBytes = Path | str | bytes

StreamFactory = Callable[[], "IO[Any]"]
"""A zero-argument callable returning a fresh binary writable stream.

``BytesIO`` itself satisfies this type, so callers normally pass ``BytesIO``.
"""


class StrictExportError(RuntimeError):
    """Base class for strict-export failures."""


class SecretRemainsError(StrictExportError):
    """Raised when a sensitive token is still present in exported bytes."""

    def __init__(self, token: bytes, occurrences: int, mode: str) -> None:
        self.token = token
        self.occurrences = occurrences
        self.mode = mode
        preview = token if len(token) <= 32 else token[:32] + b"..."
        super().__init__(
            f"Sensitive token {preview!r} still occurs {occurrences} time(s) "
            f"in the bytes written in {mode!r} mode. An incremental save keeps "
            "the original revision; use a full rewrite to remove it."
        )


@dataclass(frozen=True)
class ExportDecision:
    """Whether two requirements can be satisfied together.

    Attributes:
        want_incremental: The caller asked for incremental saving.
        token_in_source: The sensitive token occurs in the source bytes.
        token_in_live_objects: The token occurs in an object reachable from the
            current trailer (an object the page tree still references), as
            opposed to living only in the history of an incremental file.
        incremental_is_safe: The two requirements are compatible in
            incremental mode. This is only true when the source bytes already
            contain no trace of the token.
        required_mode: The write mode the caller must use to obtain a clean
            artifact: ``"incremental"`` or ``"full"``.
        reason: Human-readable explanation of the decision.
    """

    want_incremental: bool
    token_in_source: bool
    token_in_live_objects: bool
    incremental_is_safe: bool
    required_mode: str
    reason: str

    @property
    def requirements_compatible(self) -> bool:
        """True when incremental saving and full removal can both be met."""
        if not self.want_incremental:
            return True
        return self.incremental_is_safe


def _as_bytes(data: PathOrBytes) -> bytes:
    if isinstance(data, bytes):
        return data
    return Path(data).read_bytes()


def _encode_token(token: str | bytes) -> bytes:
    if isinstance(token, str):
        return token.encode("utf-8")
    return token


def byte_ranges_for_token(data: bytes, token: str | bytes) -> list[tuple[int, int]]:
    """Return every ``(start, end)`` range where ``token`` occurs in ``data``.

    The scan is done on the raw bytes, so it also finds material that only
    survives in a superseded revision and is no longer referenced by any
    object.
    """
    needle = _encode_token(token)
    if not needle:
        raise ValueError("token must not be empty")
    ranges: list[tuple[int, int]] = []
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return ranges
        ranges.append((index, index + len(needle)))
        start = index + len(needle)


def source_contains_token(source: PathOrBytes, token: str | bytes) -> bool:
    """Return whether the source document bytes contain ``token``."""
    return bool(byte_ranges_for_token(_as_bytes(source), token))


def _stream_bytes(obj: object) -> bytes:
    get_data = getattr(obj, "get_data", None)
    if get_data is None:
        return b""
    try:
        data = get_data()
    except Exception:  # pragma: no cover - defensive: unreadable stream
        return b""
    return data if isinstance(data, bytes) else bytes(data)


def _token_in_live_objects(writer: PdfWriter, needle: bytes) -> bool:
    """Check objects reachable from the trailer, not the whole history."""
    reachable = writer._find_reachable_objects()
    for idnum in reachable:
        obj = writer._objects[idnum - 1]
        if obj is None:
            continue
        if needle in _stream_bytes(obj):
            return True
        if needle in repr(obj).encode("utf-8", "backslashreplace"):
            return True
    return False


def evaluate_export(
    source: PathOrBytes,
    token: str | bytes,
    *,
    want_incremental: bool,
) -> ExportDecision:
    """Decide which write mode can guarantee removal of ``token``.

    Args:
        source: The document that will be loaded into a writer, as bytes or a
            path.
        token: The sensitive material to eliminate, as ``str`` (UTF-8 encoded)
            or raw ``bytes``.
        want_incremental: Whether the business workflow needs incremental
            saving.

    Returns:
        An :class:`ExportDecision` stating whether the incremental-save and
        full-removal requirements are compatible and which mode must be used.
    """
    needle = _encode_token(token)
    source_bytes = _as_bytes(source)
    in_source = bool(byte_ranges_for_token(source_bytes, needle))

    reader = PdfReader(BytesIO(source_bytes))
    probe = PdfWriter(clone_from=reader)
    in_live = _token_in_live_objects(probe, needle)

    incremental_safe = not in_source
    if not want_incremental:
        required_mode = "full"
        reason = (
            "Incremental saving was not requested. Use a full rewrite with "
            "unreferenced-object cleanup so that only reachable objects are "
            "emitted."
        )
    elif incremental_safe:
        required_mode = "incremental"
        reason = (
            "The source bytes contain no trace of the token, so an "
            "incremental save cannot reintroduce it; both requirements are "
            "met together."
        )
    else:
        required_mode = "full"
        reason = (
            "The token is present in the source bytes. An incremental save "
            "copies the original revision verbatim and cannot remove it, even "
            "if the object is detached from the page. Use a full rewrite "
            "with unreferenced-object cleanup instead."
        )

    return ExportDecision(
        want_incremental=want_incremental,
        token_in_source=in_source,
        token_in_live_objects=in_live,
        incremental_is_safe=incremental_safe,
        required_mode=required_mode,
        reason=reason,
    )


def _replace_page_contents(writer: PdfWriter, page_index: int, data: bytes) -> None:
    page = writer.pages[page_index]
    stream = DecodedStreamObject()
    stream.set_data(data)
    reference: IndirectObject = writer._add_object(stream)
    page[NameObject("/Contents")] = reference


def export_strict(
    source: PathOrBytes,
    token: str | bytes,
    *,
    replace_page_contents: Sequence[tuple[int, bytes]] | None = None,
    want_incremental: bool = False,
    stream_factory: StreamFactory = BytesIO,
) -> tuple[IO[Any], ExportDecision]:
    """Produce bytes that are guaranteed not to contain ``token``.

    The function first runs :func:`evaluate_export`. When incremental saving
    is requested but incompatible with full removal it raises
    :class:`StrictExportError` rather than silently emitting a file whose
    history still leaks the material. After writing, every produced byte is
    scanned as a final guarantee.

    Args:
        source: The input document as bytes or a path.
        token: The sensitive material to eliminate.
        replace_page_contents: Optional ``(page_index, new_content_stream)``
            pairs that detach the old content stream, mirroring the
            "edit the page" workflow.
        want_incremental: Whether the caller wants an incremental save.
        stream_factory: Callable returning a fresh binary stream for output.

    Returns:
        A ``(output_stream, decision)`` tuple. The stream is positioned at the
        end; call ``.getvalue()`` on a ``BytesIO`` to read the artifact.

    Raises:
        StrictExportError: If incremental saving is requested but cannot
            guarantee removal.
        SecretRemainsError: If, despite the chosen mode, the token is found in
            the produced bytes.
    """
    needle = _encode_token(token)
    source_bytes = _as_bytes(source)
    decision = evaluate_export(
        source_bytes, needle, want_incremental=want_incremental
    )

    if want_incremental and not decision.requirements_compatible:
        raise StrictExportError(decision.reason)

    if want_incremental:
        reader = PdfReader(BytesIO(source_bytes))
        writer = PdfWriter(reader, incremental=True)
        for page_index, data in replace_page_contents or ():
            _replace_page_contents(writer, page_index, data)
    else:
        reader = PdfReader(BytesIO(source_bytes))
        writer = PdfWriter(clone_from=reader)
        for page_index, data in replace_page_contents or ():
            _replace_page_contents(writer, page_index, data)
        # Drop detached objects (e.g. the old content stream) so a full write
        # cannot emit them.
        writer.compress_identical_objects(
            remove_duplicates=False, remove_unreferenced=True
        )

    output = stream_factory()
    writer.write(output)

    produced = output.getvalue()  # type: ignore[attr-defined]
    occurrences = len(byte_ranges_for_token(produced, needle))
    if occurrences:
        mode = "incremental" if want_incremental else "full"
        raise SecretRemainsError(needle, occurrences, mode)

    return output, decision
