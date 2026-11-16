"""Generate three minimal one-page PDFs (no third-party deps).

Each PDF is hand-assembled: catalog -> pages -> page -> font + content stream.
The content streams are crafted so that the *drawing order* in the file
differs from the *visual* reading order, which is exactly the situation a
forensic examiner has to disentangle.

Samples
-------
sample1_twocol.pdf   Two columns. The RIGHT column is drawn first in the
                     content stream; the LEFT column is drawn second.
sample2_rotated.pdf  One horizontal line, one 90-degree rotated string
                     (Tm matrix), one horizontal line. Drawn top, rotated,
                     bottom.
sample3_overlap.pdf  Two overlapping runs ("AAAA" then "BB" on the same
                     baseline, overlapping x-range) plus a gap pair "Q"/"P"
                     drawn right-glyph-first that merges or splits depending
                     on char_margin.
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent


def build_pdf(content: bytes, path: Path) -> None:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode()
        + b" >>\nstream\n" + content + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for num, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += (
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, xref)
    )
    path.write_bytes(bytes(out))


def text_op(x: float, y: float, text: str, size: int = 12) -> bytes:
    return b"BT /F1 %d Tf 1 0 0 1 %g %g Tm (%s) Tj ET" % (
        size, x, y, text.encode(),
    )


def main() -> None:
    # Sample 1: right column drawn BEFORE left column.
    s1 = b"\n".join([
        text_op(320, 710, "R1-gamma"),
        text_op(320, 690, "R2-delta"),
        text_op(50, 700, "L1-alpha"),
        text_op(50, 680, "L2-beta"),
    ])
    build_pdf(s1, HERE / "sample1_twocol.pdf")

    # Sample 2: horizontal, then 90-degree rotated (text climbs upward
    # from (400,300)), then horizontal.
    s2 = b"\n".join([
        text_op(50, 750, "TOP"),
        b"BT /F1 12 Tf 0 1 -1 0 400 300 Tm (VERT) Tj ET",
        text_op(50, 100, "END"),
    ])
    build_pdf(s2, HERE / "sample2_rotated.pdf")

    # Sample 3: overlapping runs + gap pair drawn right-glyph-first.
    # "AAAA" spans x=100..126.7; "BB" starts at x=112 (inside AAAA's range).
    # "Q" at x=430 drawn BEFORE "P" at x=400; gap ~22pt so the pair merges
    # into one line only when char_margin is raised (2.0 -> split, 3.0 -> merge).
    s3 = b"\n".join([
        text_op(100, 700, "AAAA"),
        text_op(112, 700, "BB"),
        text_op(430, 650, "Q"),
        text_op(400, 650, "P"),
    ])
    build_pdf(s3, HERE / "sample3_overlap.pdf")

    for name in ("sample1_twocol.pdf", "sample2_rotated.pdf", "sample3_overlap.pdf"):
        print("wrote", HERE / name)


if __name__ == "__main__":
    main()
