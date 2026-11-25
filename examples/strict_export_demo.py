"""End-to-end demonstration of strict secret removal.

Run with::

    python examples/strict_export_demo.py

The script builds a small PDF containing a public line and a secret line, then
shows the three outcomes an exporter can hit:

1. An incremental save keeps the secret in the file's history bytes.
2. The strict decision helper explains that the two requirements cannot be
   satisfied together and refuses the incremental export.
3. A full rewrite with unreferenced-object cleanup produces an artifact whose
   bytes and re-read content both prove the secret is gone.
"""

import io
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject
from pypdf.strict_export import (
    StrictExportError,
    byte_ranges_for_token,
    evaluate_export,
    export_strict,
)

SECRET = "TOPSECRET-MARKER-42".encode()
PUBLIC_LINE = "PUBLIC HELLO"
NEW_CONTENT = b"BT /F1 12 Tf 72 700 Td (PUBLIC HELLO) Tj ET"


def build_pdf() -> bytes:
    """Build a one-page PDF embedding both public and secret text."""
    content = (
        b"BT /F1 12 Tf 72 700 Td (PUBLIC HELLO) Tj T* ("
        + SECRET
        + b") Tj ET"
    )
    out = io.BytesIO()

    def write(data: bytes) -> None:
        out.write(data)

    write(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def put(number: int, body: bytes) -> None:
        offsets[number] = out.tell()
        write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    put(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    put(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    put(
        5,
        b"<< /Length %d >>\nstream\n" % len(content)
        + content
        + b"\nendstream",
    )
    put(4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    put(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    )
    xref = out.tell()
    write(b"xref\n0 6\n0000000000 65535 f \n")
    for number in range(1, 6):
        write(("%010d 00000 n \n" % offsets[number]).encode())
    write(
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode()
        + b"\n%%EOF\n"
    )
    return out.getvalue()


def text_of(data: bytes) -> str:
    return PdfReader(io.BytesIO(data)).pages[0].extract_text()


def main() -> None:
    source = build_pdf()
    print(f"source bytes contain secret: {SECRET in source}")
    print(f"source visible text:         {text_of(source)!r}\n")

    # 1. Incremental save: visually clean, but the history still leaks.
    inc_writer = PdfWriter(
        PdfReader(io.BytesIO(source)), incremental=True
    )
    stream = DecodedStreamObject()
    stream.set_data(NEW_CONTENT)
    inc_writer.pages[0][NameObject("/Contents")] = inc_writer._add_object(
        stream
    )
    inc_out = io.BytesIO()
    inc_writer.write(inc_out)
    incremental = inc_out.getvalue()
    print("[incremental] visible text:", repr(text_of(incremental)))
    print("[incremental] secret still in raw bytes:", SECRET in incremental)
    print("[incremental] revisions (%%EOF count):", incremental.count(b"%%EOF"), "\n")

    # 2. Ask the strict helper whether both requirements can coexist.
    decision = evaluate_export(source, SECRET, want_incremental=True)
    print("[decision] compatible:", decision.requirements_compatible)
    print("[decision] required mode:", decision.required_mode)
    print("[decision] reason:", decision.reason, "\n")

    try:
        export_strict(
            source,
            SECRET,
            replace_page_contents=[(0, NEW_CONTENT)],
            want_incremental=True,
        )
    except StrictExportError as exc:
        print("[strict] refused incremental export:", exc, "\n")

    # 3. Full rewrite gives an artifact that is provably clean.
    output, final_decision = export_strict(
        source,
        SECRET,
        replace_page_contents=[(0, NEW_CONTENT)],
        want_incremental=False,
    )
    artifact = output.getvalue()
    target = Path("strict_artifact.pdf")
    target.write_bytes(artifact)

    print("[full] mode used:", final_decision.required_mode)
    print("[full] byte-scan hits:", byte_ranges_for_token(artifact, SECRET))
    print("[full] secret in raw bytes:", SECRET in artifact)
    print("[full] re-read visible text:", repr(text_of(artifact)))
    print("[full] revisions (%%EOF count):", artifact.count(b"%%EOF"))
    print(f"[full] artifact written to {target}")


if __name__ == "__main__":
    main()
