"""Tests for the per-reader decoded-object resource budget."""

from io import BytesIO

import pytest

from pypdf import PdfReader, apply_configuration
from pypdf._resource_budget import ResourceBudget
from pypdf.errors import (
    LimitReachedError,
    PdfReadError,
    ResourceBudgetExceededError,
)

from . import RESOURCE_ROOT


def _build_multi_page_pdf(
    *,
    num_pages: int = 5,
    shared_font: bool = True,
    font_padding: int = 0,
) -> bytes:
    """
    Build a small uncompressed multi-page PDF entirely from synthetic data.

    The document contains a catalog, a page tree, one page dictionary and one
    content stream per page, and a font dictionary. When ``shared_font`` is
    set, every page references the same font object; otherwise each page gets
    its own font. ``font_padding`` adds inert string bytes to the font object
    so that the byte budget can be triggered deterministically.
    """
    page_ids = list(range(3, 3 + num_pages))
    next_id = 3 + num_pages
    if shared_font:
        font_id = next_id
        next_id += 1
        font_ids = None
    else:
        font_id = None
        font_ids = list(range(next_id, next_id + num_pages))
        next_id += num_pages
    content_ids = list(range(next_id, next_id + num_pages))

    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: (
            "<< /Type /Pages /Kids ["
            + " ".join(f"{page_id} 0 R" for page_id in page_ids)
            + f"] /Count {num_pages} >>"
        ).encode(),
    }
    for index, page_id in enumerate(page_ids):
        font_ref = font_id if shared_font else font_ids[index]
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_ref} 0 R >> >> "
            f"/Contents {content_ids[index]} 0 R >>"
        ).encode()

    padding = b" " * font_padding
    if shared_font:
        objects[font_id] = (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica"
            + (b" /Pad (" + padding + b")" if padding else b"")
            + b" >>"
        )
    else:
        for index, font_identifier in enumerate(font_ids):
            objects[font_identifier] = (
                f"<< /Type /Font /Subtype /Type1 /BaseFont /Font{index} >>".encode()
            )
    for index, content_id in enumerate(content_ids):
        stream = b"BT /F1 12 Tf 72 700 Td (Page %d) Tj ET" % (index + 1)
        objects[content_id] = (
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )

    output = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for object_id in sorted(objects):
        offsets[object_id] = len(output)
        output += f"{object_id} 0 obj\n".encode()
        output += objects[object_id]
        output += b"\nendobj\n"

    xref_offset = len(output)
    size = max(objects) + 1
    output += f"xref\n0 {size}\n".encode()
    output += b"0000000000 65535 f \n"
    for object_id in range(1, size):
        output += b"%010d 00000 n \n" % offsets[object_id]
    output += (
        b"trailer\n<< /Size " + str(size).encode() + b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n%%EOF\n"
    )
    return bytes(output)


def _decode_everything(reader: PdfReader) -> list[str]:
    """Force the reader to decode every reachable object of the document."""
    return [page.extract_text() for page in reader.pages]


def test_resource_budget__charges_each_distinct_object_once() -> None:
    data = _build_multi_page_pdf(num_pages=5)
    reader = PdfReader(BytesIO(data))

    assert reader.resource_budget.decoded_object_count == 0
    _decode_everything(reader)

    # catalog + page tree + 5 pages + 1 shared font + 5 content streams
    assert reader.resource_budget.decoded_object_count == 13
    assert reader.resource_budget.decoded_object_count == len(reader.resolved_objects)
    assert reader.resource_budget.decoded_byte_count > 0

    # Re-resolving the same objects must not charge anything again.
    object_count = reader.resource_budget.decoded_object_count
    byte_count = reader.resource_budget.decoded_byte_count
    _decode_everything(reader)
    reader.get_object(1)
    assert reader.resource_budget.decoded_object_count == object_count
    assert reader.resource_budget.decoded_byte_count == byte_count


def test_resource_budget__record_a_sequential_distinct_objects_stop() -> None:
    """Record A: decoding several different objects one after another stops at the cap."""
    data = _build_multi_page_pdf(num_pages=5)
    reader = PdfReader(BytesIO(data), decoded_object_limit=4)

    with pytest.raises(
        ResourceBudgetExceededError,
        match=r"^Decoded object budget exceeded: 5 > 4\.$",
    ):
        _decode_everything(reader)

    # The budget recorded the stop and did not count the rejected object.
    assert reader.resource_budget.decoded_object_count == 4


def test_resource_budget__record_b_shared_content_still_opens() -> None:
    """Record B: frequent reuse of the same shared object stays within the budget."""
    data = _build_multi_page_pdf(num_pages=5, shared_font=True)
    # Only 13 distinct objects exist; every page reuses the same font.
    reader = PdfReader(BytesIO(data), decoded_object_limit=13, decoded_byte_limit=10_000)

    pages = _decode_everything(reader)

    assert pages == ["Page 1", "Page 2", "Page 3", "Page 4", "Page 5"]
    assert reader.resource_budget.decoded_object_count == 13
    assert reader.resource_budget.decoded_byte_count <= 10_000


def test_resource_budget__distinct_fonts_consume_budget_separately() -> None:
    shared_data = _build_multi_page_pdf(num_pages=5, shared_font=True)
    distinct_data = _build_multi_page_pdf(num_pages=5, shared_font=False)

    shared_reader = PdfReader(BytesIO(shared_data))
    _decode_everything(shared_reader)
    distinct_reader = PdfReader(BytesIO(distinct_data))
    _decode_everything(distinct_reader)

    # Five distinct fonts replace the single shared font.
    assert distinct_reader.resource_budget.decoded_object_count == (
        shared_reader.resource_budget.decoded_object_count + 4
    )


def test_resource_budget__byte_limit_stops_decoding() -> None:
    data = _build_multi_page_pdf(num_pages=5, font_padding=200)
    reader = PdfReader(BytesIO(data), decoded_byte_limit=100)

    with pytest.raises(
        ResourceBudgetExceededError,
        match=r"^Decoded byte budget exceeded: \d+ > 100\.$",
    ):
        _decode_everything(reader)
    assert reader.resource_budget.decoded_byte_count <= 100


def test_resource_budget__metadata_and_pages_share_one_budget() -> None:
    data = _build_multi_page_pdf(num_pages=5)
    reader = PdfReader(BytesIO(data), decoded_object_limit=6)

    # Metadata access first, page iteration afterwards uses the same counters.
    _ = reader.metadata
    metadata_count = reader.resource_budget.decoded_object_count
    assert metadata_count <= 6

    with pytest.raises(ResourceBudgetExceededError):
        _decode_everything(reader)


def test_resource_budget__disabled_limits_never_stop() -> None:
    data = _build_multi_page_pdf(num_pages=5)
    reader = PdfReader(
        BytesIO(data),
        decoded_object_limit=None,
        decoded_byte_limit=None,
    )

    pages = _decode_everything(reader)
    assert pages == ["Page 1", "Page 2", "Page 3", "Page 4", "Page 5"]
    assert reader.resource_budget.maximum_object_count is None
    assert reader.resource_budget.maximum_byte_count is None


def test_resource_budget__configuration_defaults_apply() -> None:
    data = _build_multi_page_pdf(num_pages=3)
    with apply_configuration(
        reader_maximum_decoded_object_count=2,
        reader_maximum_decoded_byte_count=10_000,
    ):
        reader = PdfReader(BytesIO(data))
        with pytest.raises(ResourceBudgetExceededError):
            _decode_everything(reader)

    # Explicit constructor values win over the global configuration.
    with apply_configuration(reader_maximum_decoded_object_count=1):
        reader = PdfReader(BytesIO(data), decoded_object_limit=None)
        _decode_everything(reader)
        assert reader.resource_budget.maximum_object_count is None


def test_resource_budget__corruption_is_not_reported_as_budget_stop() -> None:
    data = _build_multi_page_pdf(num_pages=2)
    # Damage a referenced object so that parsing itself fails.
    corrupted = data.replace(b"3 0 obj\n<<", b"3 0 obj\n@@", 1)

    with pytest.raises(PdfReadError):
        reader = PdfReader(BytesIO(corrupted), strict=True)
        _decode_everything(reader)

    # The same healthy document still reports a budget stop separately.
    with pytest.raises(ResourceBudgetExceededError):
        reader = PdfReader(BytesIO(data), decoded_object_limit=1)
        _decode_everything(reader)


def test_resource_budget__unit() -> None:
    budget = ResourceBudget(maximum_object_count=2, maximum_byte_count=10)
    budget.charge(0, 1, 5)
    assert budget.decoded_object_count == 1
    assert budget.decoded_byte_count == 5

    # Repeated references to the same decoded object are free.
    budget.charge(0, 1, 5)
    assert budget.decoded_object_count == 1
    assert budget.decoded_byte_count == 5

    budget.charge(0, 2, 4)
    assert budget.decoded_object_count == 2
    assert budget.decoded_byte_count == 9

    with pytest.raises(ResourceBudgetExceededError, match="object budget"):
        budget.charge(0, 3, 0)
    with pytest.raises(ResourceBudgetExceededError, match="byte budget"):
        ResourceBudget(maximum_object_count=None, maximum_byte_count=3).charge(0, 9, 4)

    # Disabled limits accept arbitrary charges.
    unlimited = ResourceBudget(maximum_object_count=None, maximum_byte_count=None)
    unlimited.charge(0, 1, 10**9)
    assert unlimited.decoded_object_count == 1


def test_resource_budget__exception_hierarchy_distinguishes_corruption() -> None:
    # A budget stop is a security limit, not a malformed-file error.
    assert issubclass(ResourceBudgetExceededError, LimitReachedError)
    assert not issubclass(ResourceBudgetExceededError, PdfReadError)


def test_resource_budget__object_stream_pdf_stops_with_budget_error() -> None:
    # crazyones.pdf stores objects inside cross-reference/object streams.
    data = (RESOURCE_ROOT / "crazyones.pdf").read_bytes()
    reader = PdfReader(BytesIO(data))
    assert reader.xref_objStm

    with pytest.raises(ResourceBudgetExceededError, match="object budget"):
        tight_reader = PdfReader(BytesIO(data), decoded_object_limit=1)
        _ = list(tight_reader.pages)

    # A byte limit reached while reading the xref stream must keep its type
    # instead of being relabeled as a corrupted-trailer PdfReadError.
    with pytest.raises(ResourceBudgetExceededError, match="byte budget"):
        PdfReader(BytesIO(data), decoded_byte_limit=5)


def test_resource_budget__object_stream_objects_counted_once() -> None:
    reader = PdfReader(RESOURCE_ROOT / "crazyones.pdf")
    object_stream_ids = list(reader.xref_objStm.keys())

    reader.get_object(object_stream_ids[0])
    counted = reader.resource_budget.decoded_object_count

    # Resolving every sibling afterwards never recharges a cached object.
    for object_id in object_stream_ids:
        reader.get_object(object_id)
    assert reader.resource_budget.decoded_object_count == counted
    assert reader.resource_budget.decoded_object_count <= len(reader.resolved_objects)
