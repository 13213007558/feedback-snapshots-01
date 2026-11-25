"""Tests for scope-aware page composition."""

from io import BytesIO

import pytest

from pypdf import (
    ComposeLayer,
    CompositionResult,
    PdfReader,
    PdfWriter,
    ScopeConflictError,
    check_page_resource_references,
    compose_page,
    reachable_object_numbers,
)
from pypdf.constants import PageAttributes, Resources
from pypdf import PageObject
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    StreamObject,
    TextStringObject,
)


def _font(base_font: str) -> DictionaryObject:
    return DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject(base_font),
        }
    )


def _stream(writer: PdfWriter, data: bytes) -> IndirectObject:
    stream = StreamObject()
    stream.set_data(data)
    return writer._add_object(stream)


def _template(
    writer: PdfWriter,
    text: str,
    font: DictionaryObject | IndirectObject,
    *,
    font_name: str = "/F1",
    size: tuple[float, float] = (200, 200),
) -> PageObject:
    page = writer.add_blank_page(*size)
    page[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {
            NameObject(Resources.FONT): DictionaryObject({NameObject(font_name): font}),
        }
    )
    content = ContentStream(None, writer)
    content.operations = [
        ([NameObject(font_name), NumberObject(12)], b"Tf"),
        ([TextStringObject(text)], b"Tj"),
    ]
    page[NameObject(PageAttributes.CONTENTS)] = writer._add_object(content)
    return page


def _round_trip(writer: PdfWriter) -> PdfReader:
    buffer = BytesIO()
    writer.write(buffer)
    buffer.seek(0)
    return PdfReader(buffer)


def _used_font_names(page: PageObject) -> list[tuple[str, str]]:
    content = page.get_contents()
    assert content is not None
    resolved = []
    fonts = page[PageAttributes.RESOURCES][NameObject(Resources.FONT)].get_object()
    for operands, operator in content.operations:
        if operator != b"Tf":
            continue
        name = str(operands[0])
        font = fonts[NameObject(name)].get_object()
        resolved.append((name, str(font["/BaseFont"])))
    return resolved


def test_colliding_names_keep_layer_fonts_separate() -> None:
    """The same resource name with different objects is renamed per layer."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    layer_a = _template(writer, "Alpha", _font("/Helvetica"))
    layer_b = _template(writer, "Beta", _font("/Times-Roman"))

    result = writer.compose_page(
        destination, [ComposeLayer(layer_a, "A"), ComposeLayer(layer_b, "B")]
    )

    assert result.ok
    assert result.page is destination
    fonts = destination[PageAttributes.RESOURCES][NameObject(Resources.FONT)].get_object()
    assert str(fonts[NameObject("/F1")].get_object()["/BaseFont"]) == "/Helvetica"
    assert str(fonts[NameObject("/F1-0")].get_object()["/BaseFont"]) == "/Times-Roman"


def test_destination_direct_font_stays_shared_under_its_name() -> None:
    """A font stored directly in the destination resources stays usable."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    destination[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {NameObject(Resources.FONT): DictionaryObject({NameObject("/F1"): _font("/Courier")})}
    )
    existing = ContentStream(None, writer)
    existing.operations = [
        ([NameObject("/F1"), NumberObject(10)], b"Tf"),
        ([TextStringObject("Base")], b"Tj"),
    ]
    destination[NameObject(PageAttributes.CONTENTS)] = writer._add_object(existing)
    layer = _template(writer, "Alpha", _font("/Helvetica"))

    result = writer.compose_page(destination, [ComposeLayer(layer, "A")])

    assert result.ok
    fonts = destination[PageAttributes.RESOURCES][NameObject(Resources.FONT)].get_object()
    assert set(fonts) == {"/F1", "/F1-0"}
    assert isinstance(fonts[NameObject("/F1")], IndirectObject)

    output = _round_trip(writer).pages[0]
    assert output.extract_text() == "BaseAlpha"
    assert dict(_used_font_names(output)) == {
        "/F1": "/Courier",
        "/F1-0": "/Helvetica",
    }


def test_round_trip_resolves_each_name_and_shows_both_layers() -> None:
    """Reopening the output resolves every content-stream name to its approved object."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    destination[NameObject(PageAttributes.CONTENTS)] = writer._add_object(
        ContentStream(None, writer)
    )
    layer_a = _template(writer, "Alpha", _font("/Helvetica"))
    layer_b = _template(writer, "Beta", _font("/Times-Roman"))
    writer.compose_page(
        destination, [ComposeLayer(layer_a, "A"), ComposeLayer(layer_b, "B")]
    )

    reader = _round_trip(writer)
    page = reader.pages[0]

    assert page.extract_text() == "AlphaBeta"
    used = dict(_used_font_names(page))
    assert used == {"/F1": "/Helvetica", "/F1-0": "/Times-Roman"}
    assert check_page_resource_references(page) == []


def test_shared_object_is_published_once_and_reused() -> None:
    """One object shared by both layers keeps a single published name."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    shared_font = writer._add_object(_font("/Helvetica"))
    layer_a = _template(writer, "Alpha", shared_font)
    layer_b = _template(writer, "Beta", shared_font)

    result = writer.compose_page(
        destination, [ComposeLayer(layer_a, "A"), ComposeLayer(layer_b, "B")]
    )

    assert result.ok
    published_a, published_b = result.reports
    assert [(item.name, item.source_name) for item in published_a.published] == [
        ("/F1", "/F1")
    ]
    assert published_b.published == ()
    assert [(item.name, item.source_name) for item in published_b.reused] == [
        ("/F1", "/F1")
    ]
    fonts = destination[PageAttributes.RESOURCES][NameObject(Resources.FONT)].get_object()
    assert list(fonts) == ["/F1"]

    reader = _round_trip(writer)
    page = reader.pages[0]
    assert page.extract_text() == "AlphaBeta"
    assert dict(_used_font_names(page)) == {"/F1": "/Helvetica"}


def test_document_extension_objects_are_not_published_by_default() -> None:
    """A /PieceInfo marker introduced for a file-level extension stays internal."""
    source_writer = PdfWriter()
    layer_a = _template(source_writer, "Alpha", _font("/Helvetica"))
    marker = _stream(source_writer, b"approved provenance marker")
    layer_a[NameObject(PageAttributes.PIECE_INFO)] = source_writer._add_object(
        DictionaryObject(
            {
                NameObject("/pypdf.composition"): DictionaryObject(
                    {NameObject("/Private"): marker}
                )
            }
        )
    )
    _template(source_writer, "Beta", _font("/Times-Roman"))
    source = _round_trip(source_writer)

    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    bound_a = writer.clone_page_for_composition(source.pages[0])
    bound_b = writer.clone_page_for_composition(source.pages[1])

    result = writer.compose_page(
        destination, [ComposeLayer(bound_a, "A"), ComposeLayer(bound_b, "B")]
    )

    assert result.ok
    assert PageAttributes.PIECE_INFO in result.reports[0].excluded_extension_keys
    assert PageAttributes.PIECE_INFO not in destination

    output = _round_trip(writer).pages[0]
    assert PageAttributes.PIECE_INFO not in output
    assert output.extract_text() == "AlphaBeta"
    assert check_page_resource_references(output) == []
    # The marker object exists only in the source template, not in the output.
    assert marker.idnum not in reachable_object_numbers(writer)


def test_document_extension_can_be_selected_explicitly() -> None:
    """The exporter can opt in to one document-level extension."""
    source_writer = PdfWriter()
    layer = _template(source_writer, "Alpha", _font("/Helvetica"))
    marker = _stream(source_writer, b"selected provenance marker")
    layer[NameObject(PageAttributes.PIECE_INFO)] = source_writer._add_object(
        DictionaryObject(
            {
                NameObject("/pypdf.composition"): DictionaryObject(
                    {NameObject("/Private"): marker}
                )
            }
        )
    )
    source = _round_trip(source_writer)

    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    bound = writer.clone_page_for_composition(source.pages[0])

    result = writer.compose_page(
        destination,
        [ComposeLayer(bound, "A", include_document_extensions=(PageAttributes.PIECE_INFO,))],
    )

    assert result.ok
    assert result.reports[0].published_extension_keys == (PageAttributes.PIECE_INFO,)
    assert PageAttributes.PIECE_INFO in destination

    output = _round_trip(writer).pages[0]
    assert PageAttributes.PIECE_INFO in output
    copied = output[PageAttributes.PIECE_INFO][NameObject("/pypdf.composition")]
    copied = copied.get_object()[NameObject("/Private")].get_object()
    assert copied.get_data() == b"selected provenance marker"


def test_reader_layers_are_bound_to_the_writer() -> None:
    """Layers cloned from a reader keep their own approved objects."""
    source_writer = PdfWriter()
    _template(source_writer, "Alpha", _font("/Helvetica"))
    _template(source_writer, "Beta", _font("/Times-Roman"))
    reader = _round_trip(source_writer)

    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    layer_a = writer.clone_page_for_composition(reader.pages[0])
    layer_b = writer.clone_page_for_composition(reader.pages[1])

    result = writer.compose_page(
        destination, [ComposeLayer(layer_a, "A"), ComposeLayer(layer_b, "B")]
    )

    assert result.ok
    output = _round_trip(writer).pages[0]
    assert output.extract_text() == "AlphaBeta"
    assert dict(_used_font_names(output)) == {
        "/F1": "/Helvetica",
        "/F1-0": "/Times-Roman",
    }


def test_destination_keeps_its_own_content_on_success() -> None:
    """Composing over a page keeps the destination's existing content."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    destination_font = writer._add_object(_font("/Courier"))
    destination[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {
            NameObject(Resources.FONT): DictionaryObject(
                {NameObject("/F1"): destination_font}
            )
        }
    )
    existing = ContentStream(None, writer)
    existing.operations = [
        ([NameObject("/F1"), NumberObject(10)], b"Tf"),
        ([TextStringObject("Base")], b"Tj"),
    ]
    destination[NameObject(PageAttributes.CONTENTS)] = writer._add_object(existing)
    layer = _template(writer, "Alpha", _font("/Helvetica"))

    result = writer.compose_page(destination, [ComposeLayer(layer, "A")])

    assert result.ok
    output = _round_trip(writer).pages[0]
    assert output.extract_text() == "BaseAlpha"
    assert dict(_used_font_names(output)) == {
        "/F1": "/Courier",
        "/F1-0": "/Helvetica",
    }


def test_conflict_is_reported_and_destination_can_still_write() -> None:
    """A rejected layer leaves the destination unchanged and still writable."""
    writer = PdfWriter()
    destination = writer.add_blank_page(300, 300)
    destination_font = writer._add_object(_font("/Courier"))
    destination[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {
            NameObject(Resources.FONT): DictionaryObject(
                {NameObject("/F1"): destination_font}
            )
        }
    )
    existing = ContentStream(None, writer)
    existing.operations = [
        ([NameObject("/F1"), NumberObject(10)], b"Tf"),
        ([TextStringObject("Base")], b"Tj"),
    ]
    destination[NameObject(PageAttributes.CONTENTS)] = writer._add_object(existing)

    broken = writer.add_blank_page(100, 100)
    broken[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {NameObject(Resources.FONT): DictionaryObject()}
    )
    broken_content = ContentStream(None, writer)
    broken_content.set_data(b"/F9 12 Tf (Rejected) Tj")
    broken[NameObject(PageAttributes.CONTENTS)] = writer._add_object(broken_content)
    writer.remove_page(broken.indirect_reference)

    result = writer.compose_page(destination, [ComposeLayer(broken, "broken")])

    assert not result.ok
    assert result.page is None
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert (conflict.layer, conflict.scope, conflict.name) == (
        "broken",
        "content-reference",
        "/F9",
    )
    assert "not define" in conflict.reason
    assert dict(_used_font_names(destination)) == {"/F1": "/Courier"}

    output = _round_trip(writer).pages[0]
    assert output.extract_text() == "Base"
    assert check_page_resource_references(output) == []


def test_strict_conflict_raises_and_does_not_publish() -> None:
    """``strict=True`` raises for the same conflict without modifying the page."""
    writer = PdfWriter()
    destination = writer.add_blank_page(100, 100)
    broken = writer.add_blank_page(100, 100)
    broken[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {NameObject(Resources.FONT): DictionaryObject()}
    )
    broken_content = ContentStream(None, writer)
    broken_content.set_data(b"/F9 12 Tf (Rejected) Tj")
    broken[NameObject(PageAttributes.CONTENTS)] = writer._add_object(broken_content)
    writer.remove_page(broken.indirect_reference)
    original_resources = destination.get(PageAttributes.RESOURCES)

    with pytest.raises(ScopeConflictError, match="content-reference"):
        writer.compose_page(destination, [ComposeLayer(broken, "broken")], strict=True)

    assert destination.get(PageAttributes.RESOURCES) == original_resources
    assert PageAttributes.CONTENTS not in destination


def test_conflicts_are_checked_before_publication() -> None:
    """A conflict in the second layer does not publish the first layer's objects."""
    writer = PdfWriter()
    destination = writer.add_blank_page(100, 100)
    approved = _template(writer, "Alpha", _font("/Helvetica"))
    broken = writer.add_blank_page(100, 100)
    broken[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
        {NameObject(Resources.FONT): DictionaryObject()}
    )
    broken_content = ContentStream(None, writer)
    broken_content.set_data(b"/F9 12 Tf (Rejected) Tj")
    broken[NameObject(PageAttributes.CONTENTS)] = writer._add_object(broken_content)
    writer.remove_page(broken.indirect_reference)
    object_count = len(writer._objects)

    result = writer.compose_page(
        destination, [ComposeLayer(approved, "A"), ComposeLayer(broken, "B")]
    )

    assert not result.ok
    assert len(writer._objects) == object_count
    assert result.reports[0].published == ()


def test_compose_page_function_matches_writer_method() -> None:
    """The module function accepts the same tuples as the writer method."""
    writer = PdfWriter()
    destination = writer.add_blank_page(100, 100)
    layer_a = _template(writer, "Alpha", _font("/Helvetica"))
    layer_b = _template(writer, "Beta", _font("/Times-Roman"))

    result = compose_page(writer, 0, [("A", layer_a), ("B", layer_b)])

    assert isinstance(result, CompositionResult)
    assert result.ok
    assert result.page is destination
    assert [report.layer for report in result.reports] == ["A", "B"]


def test_two_graphics_objects_with_the_same_name_stay_separate() -> None:
    """XObject graphics resources are renamed and resolved independently."""
    writer = PdfWriter()
    destination = writer.add_blank_page(200, 200)

    def add_graphics(data: bytes) -> PageObject:
        page = writer.add_blank_page(100, 100)
        form = StreamObject()
        form[NameObject("/Type")] = NameObject("/XObject")
        form[NameObject("/Subtype")] = NameObject("/Form")
        form[NameObject("/BBox")] = ArrayObject(
            [NumberObject(0), NumberObject(0), NumberObject(10), NumberObject(10)]
        )
        form.set_data(data)
        form_ref = writer._add_object(form)
        page[NameObject(PageAttributes.RESOURCES)] = DictionaryObject(
            {NameObject(Resources.XOBJECT): DictionaryObject({NameObject("/Gs"): form_ref})}
        )
        content = ContentStream(None, writer)
        content.operations = [([NameObject("/Gs")], b"Do")]
        page[NameObject(PageAttributes.CONTENTS)] = writer._add_object(content)
        return page

    layer_a = add_graphics(b"0 0 10 10 re")
    layer_b = add_graphics(b"0 0 20 20 re")

    result = writer.compose_page(
        destination, [ComposeLayer(layer_a, "A"), ComposeLayer(layer_b, "B")]
    )

    assert result.ok
    xobjects = destination[PageAttributes.RESOURCES][NameObject(Resources.XOBJECT)].get_object()
    assert set(xobjects) == {"/Gs", "/Gs-0"}
    first = xobjects[NameObject("/Gs")].get_object()
    second = xobjects[NameObject("/Gs-0")].get_object()
    assert first.get_data() == b"0 0 10 10 re"
    assert second.get_data() == b"0 0 20 20 re"

    reader = _round_trip(writer)
    page = reader.pages[0]
    content = page.get_contents()
    assert content is not None
    used = [
        str(operands[0])
        for operands, operator in content.operations
        if operator == b"Do"
    ]
    assert used == ["/Gs", "/Gs-0"]
    assert check_page_resource_references(page) == []
