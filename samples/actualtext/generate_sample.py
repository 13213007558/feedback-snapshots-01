"""Generate the ActualText forensic demonstration document.

Run with the repository's Python environment::

    python samples/actualtext/generate_sample.py

The produced PDF, ``actualtext-forensic.pdf`` next to this script, contains:

* page 1 - an outer marked-content sequence whose /ActualText replaces *two*
  painted text runs, with a second, nested marked-content sequence inside it;
  one property dictionary is referenced by name through /Properties and a
  Form XObject contributes text through its own resource dictionary;
* page 2 - a deliberately unclosed marked-content sequence used to prove the
  locatable diagnostic output.
"""

from __future__ import annotations

import os

from pdfbuilder import PdfBuilder, array_body, dict_body, pdf_string

HERE = os.path.dirname(os.path.abspath(__file__))


def text_line(x: float, y: float, font: str, size: int, text: str) -> bytes:
    return (
        b"BT /"
        + font.encode()
        + b" "
        + str(size).encode()
        + b" Tf "
        + str(x).encode()
        + b" "
        + str(y).encode()
        + b" Td "
        + pdf_string(text)
        + b" Tj ET"
    )


def build() -> bytes:
    pdf = PdfBuilder()

    # --- shared objects -------------------------------------------------
    catalog = pdf.add(b"")  # 1, backfilled
    pages = pdf.add(b"")  # 2, backfilled

    # Standard Helvetica fonts, distinct resource names so a Form can prove
    # that it resolves fonts from its own resource dictionary.
    page_font = pdf.add(
        dict_body(
            {
                "Type": b"/Font",
                "Subtype": b"/Type1",
                "BaseFont": b"/Helvetica",
            }
        )
    )
    form_font = pdf.add(
        dict_body(
            {
                "Type": b"/Font",
                "Subtype": b"/Type1",
                "BaseFont": b"/Helvetica-Bold",
            }
        )
    )

    # Property dictionary referenced *by name* through /Properties.
    named_props = pdf.add(
        dict_body(
            {
                "Type": b"/Metadata",
                "ActualText": pdf_string("inner replacement"),
                "MCID": b"7",
            }
        )
    )

    # --- Form XObject with an independent resource dictionary -----------
    form_stream = b"\n".join(
        [
            b"/F1 10 Tf 1 0 0 1 0 0 Tm",
            # Nested ActualText entirely local to the Form's content stream.
            b"/Span << /ActualText " + pdf_string("form replacement") + b" >> BDC",
            text_line(0, 0, "F1", 10, "FORM-DRAWN"),
            b"EMC",
        ]
    )
    form_resources = dict_body(
        {
            "Font": dict_body({"F1": f"{form_font} 0 R".encode()}),
        }
    )
    form_xobj = pdf.add(
        dict_body(
            {
                "Type": b"/XObject",
                "Subtype": b"/Form",
                "BBox": b"[ 0 0 300 40 ]",
                "Resources": form_resources,
                "Length": str(len(form_stream)).encode(),
            },
            stream=form_stream,
        )
    )

    page_resources = dict_body(
        {
            "Font": dict_body({"F1": f"{page_font} 0 R".encode()}),
            "XObject": dict_body({"Fm1": f"{form_xobj} 0 R".encode()}),
            "Properties": dict_body({"P1": f"{named_props} 0 R".encode()}),
        }
    )

    # --- page 1 content --------------------------------------------------
    # Outer /ActualText covers TWO drawn text runs and wraps an inner mark.
    page1_stream = b"\n".join(
        [
            # Plain text outside any replacement scope.
            text_line(72, 720, "F1", 12, "PLAIN-START"),
            # Outer replacement span covering two painted runs plus a nested mark.
            b"/P << /ActualText "
            + pdf_string("outer replacement text")
            + b" /MCID 3 >> BDC",
            text_line(72, 700, "F1", 12, "DRAWN-ONE"),
            # Inner mark whose property dict is referenced by name via Properties.
            b"/Span /P1 BDC",
            text_line(72, 680, "F1", 12, "DRAWN-TWO"),
            b"EMC",
            text_line(72, 660, "F1", 12, "DRAWN-THREE"),
            b"EMC",
            # Text after the replacement scope is still read normally.
            text_line(72, 640, "F1", 12, "PLAIN-END"),
            # Form XObject drawn near the bottom, using its own resources.
            b"q 1 0 0 1 72 560 cm /Fm1 Do Q",
        ]
    )
    page1_contents = pdf.add(
        dict_body(
            {
                "Length": str(len(page1_stream)).encode(),
            },
            stream=page1_stream,
        )
    )
    page1 = pdf.add(
        dict_body(
            {
                "Type": b"/Page",
                "Parent": f"{pages} 0 R".encode(),
                "MediaBox": b"[ 0 0 612 792 ]",
                "Resources": page_resources,
                "Contents": f"{page1_contents} 0 R".encode(),
            }
        )
    )

    # --- page 2: deliberately unclosed marked-content sequence ----------
    page2_stream = b"\n".join(
        [
            text_line(72, 720, "F1", 12, "PAGE-TWO"),
            b"/Span << /MCID 9 >> BDC",
            text_line(72, 700, "F1", 12, "NEVER-CLOSED"),
            # No matching EMC: the sequence stays open until the stream ends.
        ]
    )
    page2_resources = dict_body(
        {
            "Font": dict_body({"F1": f"{page_font} 0 R".encode()}),
        }
    )
    page2_contents = pdf.add(
        dict_body(
            {
                "Length": str(len(page2_stream)).encode(),
            },
            stream=page2_stream,
        )
    )
    page2 = pdf.add(
        dict_body(
            {
                "Type": b"/Page",
                "Parent": f"{pages} 0 R".encode(),
                "MediaBox": b"[ 0 0 612 792 ]",
                "Resources": page2_resources,
                "Contents": f"{page2_contents} 0 R".encode(),
            }
        )
    )

    pdf.page_object_numbers[:] = [page1, page2]

    # Backfill the catalog and the page tree.
    pdf._objects[catalog - 1] = dict_body(
        {
            "Type": b"/Catalog",
            "Pages": f"{pages} 0 R".encode(),
        }
    )
    pdf._objects[pages - 1] = dict_body(
        {
            "Type": b"/Pages",
            "Kids": array_body([f"{page1} 0 R".encode(), f"{page2} 0 R".encode()]),
            "Count": b"2",
        }
    )
    return pdf.build()


def main() -> None:
    target = os.path.join(HERE, "actualtext-forensic.pdf")
    with open(target, "wb") as fp:
        fp.write(build())
    print(f"Wrote {target} ({os.path.getsize(target)} bytes)")


if __name__ == "__main__":
    main()
