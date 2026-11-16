"""A tiny dependency-free PDF writer for ActualText forensic fixtures.

It supports just enough of PDF 1.7 to exercise marked-content sequences:
standard Helvetica text, Form XObjects with independent resource
dictionaries, and a Properties resource dictionary referenced by name.
Nothing here is required by pdfminer itself; it only builds the binary
documents consumed by the tests and the demonstration sample.
"""

from __future__ import annotations


def pdf_string(text: str) -> bytes:
    """Encode text as a PDF text-string literal (UTF-16BE when needed)."""
    if all(ord(ch) < 128 for ch in text):
        escaped = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        return f"({escaped})".encode("latin-1")
    payload = b"\xfe\xff" + text.encode("utf-16-be")
    return (
        b"("
        + payload.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        + b")"
    )


def pdf_name(name: str) -> bytes:
    return b"/" + name.encode("latin-1")


class PdfBuilder:
    def __init__(self) -> None:
        # Each object is a function returning its serialised body bytes.
        self._objects: list[bytes] = []
        self.page_object_numbers: list[int] = []

    def add(self, body: bytes) -> int:
        self._objects.append(body)
        return len(self._objects)  # object numbers are 1-based

    def build(self) -> bytes:
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(self._objects, start=1):
            offsets.append(len(out))
            out.extend(f"{number} 0 obj\n".encode("latin-1"))
            out.extend(body)
            out.extend(b"\nendobj\n")
        xref_start = len(out)
        count = len(self._objects) + 1
        out.extend(f"xref\n0 {count}\n".encode("latin-1"))
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            out.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
        out.extend(
            f"trailer\n<< /Size {count} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n".encode("latin-1")
        )
        return bytes(out)


def dict_body(mapping: dict[str, bytes], stream: bytes | None = None) -> bytes:
    body = bytearray(b"<<")
    for key, value in mapping.items():
        body.extend(b" /" + key.encode("latin-1") + b" " + value)
    if stream is not None:
        body.extend(b" >>\nstream\n")
        body.extend(stream)
        body.extend(b"\nendstream")
    else:
        body.extend(b" >>")
    return bytes(body)


def array_body(items: list[bytes]) -> bytes:
    return b"[ " + b" ".join(items) + b" ]"
