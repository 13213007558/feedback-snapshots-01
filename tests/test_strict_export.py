"""Acceptance tests for strict, byte-level secret removal.

The fixtures build small PDF documents by hand so that the tests never depend
on external sample files. Every claim about removal is checked twice:

1. logically, by re-reading the artifact with ``PdfReader``; and
2. physically, by scanning the serialized bytes for the sensitive marker.
"""

import io

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject
from pypdf.strict_export import (
    SecretRemainsError,
    StrictExportError,
    byte_ranges_for_token,
    evaluate_export,
    export_strict,
    source_contains_token,
)

SECRET_TEXT = "TOPSECRET-MARKER-42"
SECRET = SECRET_TEXT.encode("utf-8")
PUBLIC_TEXT = "PUBLIC HELLO"
REPLACEMENT_CONTENT = b"BT /F1 12 Tf 72 700 Td (PUBLIC HELLO) Tj ET"


def build_pdf_bytes(
    content: bytes,
    *,
    object_count: int = 5,
    root: int = 1,
    pages: int = 2,
    page: int = 3,
    font: int = 4,
    contents: int = 5,
) -> bytes:
    """Build a minimal one-page PDF whose content stream embeds ``content``."""
    out = io.BytesIO()

    def write(data: bytes | str) -> None:
        out.write(data if isinstance(data, bytes) else data.encode())

    write("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def put(number: int, body: bytes) -> None:
        offsets[number] = out.tell()
        write(f"{number} 0 obj\n".encode())
        write(body)
        write(b"\nendobj\n")

    put(root, b"<< /Type /Catalog /Pages 2 0 R >>")
    put(pages, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    put(
        contents,
        b"<< /Length %d >>\nstream\n" % len(content)
        + content
        + b"\nendstream",
    )
    put(font, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    put(
        page,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    )

    xref_position = out.tell()
    write(f"xref\n0 {object_count + 1}\n")
    write(b"0000000000 65535 f \n")
    for number in range(1, object_count + 1):
        write(("%010d 00000 n \n" % offsets[number]).encode())
    write(
        (
            "trailer\n<< /Size %d /Root %d 0 R >>\n"
            "startxref\n%d\n%%%%EOF\n"
            % (object_count + 1, root, xref_position)
        ).encode()
    )
    return out.getvalue()


@pytest.fixture
def contaminated_pdf() -> bytes:
    content = (
        b"BT /F1 12 Tf 72 700 Td (PUBLIC HELLO) Tj T* ("
        + SECRET
        + b") Tj ET"
    )
    return build_pdf_bytes(content)


@pytest.fixture
def clean_pdf() -> bytes:
    return build_pdf_bytes(REPLACEMENT_CONTENT)


def read_text(data: bytes) -> str:
    return PdfReader(io.BytesIO(data)).pages[0].extract_text()


def test_handmade_fixture_starts_with_live_secret(contaminated_pdf: bytes) -> None:
    assert source_contains_token(contaminated_pdf, SECRET)
    assert SECRET_TEXT in read_text(contaminated_pdf)
    assert len(byte_ranges_for_token(contaminated_pdf, SECRET)) == 1


def test_incremental_edit_leaves_secret_in_history(
    contaminated_pdf: bytes,
) -> None:
    """Editing the page incrementally removes it visually but not physically."""
    writer = PdfWriter(
        PdfReader(io.BytesIO(contaminated_pdf)), incremental=True
    )
    stream = DecodedStreamObject()
    stream.set_data(REPLACEMENT_CONTENT)
    writer.pages[0][NameObject("/Contents")] = writer._add_object(stream)

    output = io.BytesIO()
    writer.write(output)
    artifact = output.getvalue()

    # The visible page no longer contains the secret ...
    assert SECRET_TEXT not in read_text(artifact)
    assert PUBLIC_TEXT in read_text(artifact)
    # ... but the original revision keeps the raw bytes, and there are
    # multiple revisions in the file.
    assert SECRET in artifact
    assert artifact.count(b"%%EOF") == 2


def test_evaluate_export_flags_incompatible_incremental(
    contaminated_pdf: bytes,
) -> None:
    decision = evaluate_export(
        contaminated_pdf, SECRET, want_incremental=True
    )
    assert decision.token_in_source is True
    assert decision.token_in_live_objects is True
    assert decision.incremental_is_safe is False
    assert decision.requirements_compatible is False
    assert decision.required_mode == "full"


def test_evaluate_export_allows_incremental_when_source_clean(
    clean_pdf: bytes,
) -> None:
    decision = evaluate_export(clean_pdf, SECRET, want_incremental=True)
    assert decision.token_in_source is False
    assert decision.token_in_live_objects is False
    assert decision.incremental_is_safe is True
    assert decision.requirements_compatible is True
    assert decision.required_mode == "incremental"


def test_export_strict_refuses_incremental_when_secret_present(
    contaminated_pdf: bytes,
) -> None:
    with pytest.raises(StrictExportError, match="full rewrite"):
        export_strict(
            contaminated_pdf,
            SECRET,
            replace_page_contents=[(0, REPLACEMENT_CONTENT)],
            want_incremental=True,
        )


def test_full_rewrite_removes_secret_at_byte_and_reader_level(
    contaminated_pdf: bytes,
) -> None:
    output, decision = export_strict(
        contaminated_pdf,
        SECRET,
        replace_page_contents=[(0, REPLACEMENT_CONTENT)],
        want_incremental=False,
    )
    artifact = output.getvalue()

    assert decision.required_mode == "full"

    # Physical proof: no marker anywhere in the serialized artifact.
    assert byte_ranges_for_token(artifact, SECRET) == []
    assert SECRET not in artifact
    # Logical proof: the re-read document still shows the public content.
    text = read_text(artifact)
    assert PUBLIC_TEXT in text
    assert SECRET_TEXT not in text
    # A full rewrite is a single revision, so no superseded history remains.
    assert artifact.count(b"%%EOF") == 1


def test_full_rewrite_without_edit_also_purges_detached_secret(
    contaminated_pdf: bytes,
) -> None:
    """Detach the old content stream first, then rely on strict cleanup."""
    reader = PdfReader(io.BytesIO(contaminated_pdf))
    writer = PdfWriter(clone_from=reader)
    replacement = DecodedStreamObject()
    replacement.set_data(REPLACEMENT_CONTENT)
    writer.pages[0][NameObject("/Contents")] = writer._add_object(
        replacement
    )

    output = io.BytesIO()
    writer.compress_identical_objects(
        remove_duplicates=False, remove_unreferenced=True
    )
    writer.write(output)

    artifact = output.getvalue()
    assert SECRET not in artifact
    assert SECRET_TEXT not in read_text(artifact)


def test_export_strict_raises_if_token_survives(
    contaminated_pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The final byte scan must catch a leak instead of returning quietly."""
    from pypdf.strict_export import _strict_export

    def broken_cleanup(self: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        PdfWriter,
        "compress_identical_objects",
        broken_cleanup,
    )
    with pytest.raises(SecretRemainsError):
        _strict_export.export_strict(
            contaminated_pdf,
            SECRET,
            replace_page_contents=[(0, REPLACEMENT_CONTENT)],
        )


def test_incremental_on_clean_source_passes(clean_pdf: bytes) -> None:
    output, decision = export_strict(
        clean_pdf, SECRET, want_incremental=True
    )
    artifact = output.getvalue()
    assert SECRET not in artifact
    assert decision.requirements_compatible is True
    assert PUBLIC_TEXT in read_text(artifact)
