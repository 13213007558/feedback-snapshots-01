"""Scope-aware composition of approved page layers.

Overlay composition draws several approved template pages onto one destination
page. Templates frequently use the same resource name for different fonts and
graphics, so every layer's resources have to stay tied to the content stream
that references them.

Only resources that participate in page rendering are published. Objects that
are introduced solely by a document-level extension, such as ``/PieceInfo`` or
``/AF``, are never copied unless the exporter explicitly selects them for that
layer.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from ._configuration import get_configuration
from ._page import PageObject
from .constants import PageAttributes, Resources
from .errors import PyPdfError
from .generic import (
    ArrayObject,
    ContentStream,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NameObject,
    NullObject,
    PdfObject,
    StreamObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    from ._writer import PdfWriter

#: Resource categories that participate in page rendering.
RENDERING_RESOURCE_CATEGORIES: tuple[str, ...] = (
    Resources.EXT_G_STATE,
    Resources.COLOR_SPACE,
    Resources.PATTERN,
    Resources.SHADING,
    Resources.XOBJECT,
    Resources.FONT,
    Resources.PROPERTIES,
)

#: Page entries that carry document-level extensions rather than page rendering.
DOCUMENT_EXTENSION_KEYS: tuple[str, ...] = (
    PageAttributes.AF,
    PageAttributes.D_PART,
    PageAttributes.METADATA,
    PageAttributes.OUTPUT_INTENTS,
    PageAttributes.PIECE_INFO,
    PageAttributes.STRUCT_PARENTS,
    PageAttributes.VP,
)

#: Color space names that the PDF specification defines without a page resource.
_DEVICE_COLOR_SPACES: frozenset[str] = frozenset(
    ("/DeviceGray", "/DeviceRGB", "/DeviceCMYK", "/Pattern")
)

#: Operators whose first operand names a resource of a specific category.
_RESOURCE_OPERATORS: dict[bytes, str] = {
    b"Tf": Resources.FONT,
    b"Do": Resources.XOBJECT,
    b"gs": Resources.EXT_G_STATE,
    b"sh": Resources.SHADING,
}

#: Operators whose name operand is a resource of a specific category.
_NAME_OPERATORS: dict[bytes, str] = {
    b"CS": Resources.COLOR_SPACE,
    b"cs": Resources.COLOR_SPACE,
    b"BDC": Resources.PROPERTIES,
}


class ScopeConflictError(PyPdfError):
    """Raised for scope conflicts when composition runs with ``strict=True``."""

    def __init__(self, conflicts: Sequence["ScopeConflict"]) -> None:
        self.conflicts = tuple(conflicts)
        super().__init__("; ".join(conflict.message for conflict in self.conflicts))


@dataclass(frozen=True)
class ScopeConflict:
    """A conflict that prevented a layer from being published."""

    layer: str
    scope: str
    name: str
    reason: str

    @property
    def message(self) -> str:
        """Human-readable description of the conflict."""
        return f"[{self.layer}] {self.scope} {self.name}: {self.reason}"


@dataclass(frozen=True)
class ComposeLayer:
    """One approved template layer drawn onto the destination page."""

    page: PageObject
    """Source page of the approved template."""

    name: str
    """Name identifying the layer in reports and conflicts."""

    include_document_extensions: tuple[str, ...] = ()
    """Document-level extension keys the exporter explicitly selects."""


@dataclass(frozen=True)
class PublishedResource:
    """One resource name resolved in the composed page."""

    category: str
    layer: str
    source_name: str
    name: str
    indirect_reference: IndirectObject | None = None
    reused: bool = False


@dataclass(frozen=True)
class ResourceScopeReport:
    """Resource scope outcome for one layer."""

    layer: str
    published: tuple[PublishedResource, ...] = ()
    reused: tuple[PublishedResource, ...] = ()
    excluded_extension_keys: tuple[str, ...] = ()
    published_extension_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompositionResult:
    """Result of a scoped overlay composition.

    ``ok`` is true only if the destination page was composed. On a scope
    conflict the destination page is left untouched, ``page`` is ``None`` and
    ``conflicts`` explains what was rejected.
    """

    page: PageObject | None = None
    reports: tuple[ResourceScopeReport, ...] = ()
    conflicts: tuple[ScopeConflict, ...] = ()

    @property
    def ok(self) -> bool:
        """Whether the destination page was composed."""
        return self.page is not None and not self.conflicts


class _LayerPlan:
    """One layer's publication plan, built before the writer is modified."""

    def __init__(self, layer: ComposeLayer, content: ContentStream | None) -> None:
        self.layer = layer
        self.content = content
        self.rename: dict[str, dict[str, str]] = {
            category: {} for category in RENDERING_RESOURCE_CATEGORIES
        }
        self.published: list[PublishedResource] = []
        self.reused: list[PublishedResource] = []
        self.pending: list[tuple[str, str, Any]] = []
        self.planned: list[PublishedResource] = []
        self.excluded_extensions: list[str] = []
        self.published_extensions: list[str] = []


@dataclass
class _Snapshot:
    """Writer and page state captured before composition."""

    objects: list[Any]
    translated: dict[int, dict[Any, Any]]
    page_items: dict[Any, Any]
    resources_items: list[tuple[Any, Any]] | None


def _resolve(value: Any) -> Any:
    if isinstance(value, IndirectObject):
        try:
            return value.get_object()
        except Exception:  # noqa: BLE001 - a broken reference counts as missing
            return NullObject()
    return value


def _resource_dictionary(container: DictionaryObject, category: str) -> DictionaryObject:
    value = _resolve(container.get(category, None))
    return value if isinstance(value, DictionaryObject) else DictionaryObject()


def _effective_resources(page: PageObject) -> DictionaryObject:
    resources = page.get_inherited(key=PageAttributes.RESOURCES, default=DictionaryObject())
    return resources if isinstance(resources, DictionaryObject) else DictionaryObject()


def _fingerprint(value: Any, seen: set[int] | None = None) -> str:
    """Fingerprint an object by content, independent of its object number."""
    seen = set() if seen is None else seen
    if isinstance(value, IndirectObject):
        return _fingerprint(_resolve(value), seen)
    if isinstance(value, StreamObject):
        if id(value) in seen:
            return "cycle"
        seen.add(id(value))
        digest = hashlib.sha256(b"stream")
        for key in sorted(str(name) for name in value.keys()):
            if key == "/Length":
                continue
            digest.update(key.encode())
            digest.update(_fingerprint(value.raw_get(key), seen).encode())
        digest.update(value._data)  # noqa: SLF001 - avoid decoding the stream
        return digest.hexdigest()
    if isinstance(value, DictionaryObject):
        if id(value) in seen:
            return "cycle"
        seen.add(id(value))
        digest = hashlib.sha256(b"dict")
        for key in sorted(str(name) for name in value.keys()):
            digest.update(key.encode())
            digest.update(_fingerprint(value.raw_get(key), seen).encode())
        return digest.hexdigest()
    if isinstance(value, ArrayObject):
        if id(value) in seen:
            return "cycle"
        seen.add(id(value))
        digest = hashlib.sha256(b"array")
        for item in value:
            digest.update(_fingerprint(item, seen).encode())
        return digest.hexdigest()
    return f"{type(value).__name__}:{value!r}"


def _published_name(base: str, taken: set[str]) -> str:
    if base not in taken:
        return base
    index = 0
    while f"{base}-{index}" in taken:
        index += 1
    return f"{base}-{index}"


def _content_for_page(page: PageObject, pdf: Any) -> ContentStream | None:
    contents = page.get(PageAttributes.CONTENTS, None)
    if contents is None or is_null_or_none(contents):
        return None
    resolved = _resolve(contents)
    if not isinstance(resolved, (StreamObject, ArrayObject)):
        return None
    return ContentStream(resolved, pdf)


def _resource_uses(content: ContentStream) -> Iterable[tuple[str, str, bytes]]:
    """Yield ``(category, name, operator)`` for resource names in a content stream."""
    for operands, operator in content.operations:
        if operator == b"INLINE IMAGE":
            if isinstance(operands, dict):
                settings = operands.get("settings")
                if isinstance(settings, DictionaryObject):
                    for key in ("/CS", "/ColorSpace"):
                        value = settings.get(key)
                        if isinstance(value, NameObject) and value not in _DEVICE_COLOR_SPACES:
                            yield Resources.COLOR_SPACE, str(value), operator
            continue
        if not isinstance(operands, list):
            continue
        category = _RESOURCE_OPERATORS.get(operator)
        if category is not None:
            if operands and isinstance(operands[0], NameObject):
                yield category, str(operands[0]), operator
        elif operator in _NAME_OPERATORS:
            index = 1 if operator == b"BDC" else 0
            category = _NAME_OPERATORS[operator]
            if index >= len(operands) or not isinstance(operands[index], NameObject):
                continue
            if category == Resources.COLOR_SPACE and operands[index] in _DEVICE_COLOR_SPACES:
                continue
            yield category, str(operands[index]), operator
        elif operator in (b"scn", b"SCN"):
            for operand in operands:
                if isinstance(operand, NameObject):
                    yield Resources.PATTERN, str(operand), operator


def _rename_operands(operands: Any, operator: bytes, rename: Mapping[str, Mapping[str, str]]) -> None:
    if operator == b"INLINE IMAGE":
        if isinstance(operands, dict):
            settings = operands.get("settings")
            if isinstance(settings, DictionaryObject):
                color_rename = rename.get(Resources.COLOR_SPACE, {})
                for key in ("/CS", "/ColorSpace"):
                    value = settings.get(key)
                    if isinstance(value, NameObject) and value in color_rename:
                        settings[NameObject(key)] = NameObject(color_rename[value])
        return
    if not isinstance(operands, list) or not operands:
        return
    category = _RESOURCE_OPERATORS.get(operator)
    if category is not None:
        if isinstance(operands[0], NameObject):
            operands[0] = NameObject(rename[category].get(operands[0], operands[0]))
        return
    category = _NAME_OPERATORS.get(operator)
    if category is not None:
        index = 1 if operator == b"BDC" else 0
        if index < len(operands) and isinstance(operands[index], NameObject):
            current = operands[index]
            if category != Resources.COLOR_SPACE or current not in _DEVICE_COLOR_SPACES:
                operands[index] = NameObject(rename[category].get(current, current))
        return
    if operator in (b"scn", b"SCN"):
        pattern_rename = rename[Resources.PATTERN]
        for index, operand in enumerate(operands):
            if isinstance(operand, NameObject) and operand in pattern_rename:
                operands[index] = NameObject(pattern_rename[operand])


def _rename_content(content: ContentStream, rename: Mapping[str, Mapping[str, str]]) -> None:
    for operands, operator in content.operations:
        _rename_operands(operands, operator, rename)


def _clone_into_writer(
    value: Any, writer: PdfWriter, *, force_duplicate: bool = False
) -> IndirectObject:
    if isinstance(value, IndirectObject):
        reference_clone = value.clone(writer, force_duplicate=force_duplicate)
        if isinstance(reference_clone, IndirectObject):
            return reference_clone
        return writer._add_object(cast(PdfObject, reference_clone))
    resolved = _resolve(value)
    cloned: Any = (
        resolved.clone(writer)
        if isinstance(resolved, PdfObject)
        else resolved
    )
    if isinstance(cloned, IndirectObject):
        return cloned
    reference = getattr(cloned, "indirect_reference", None)
    if isinstance(reference, IndirectObject) and reference.pdf is writer:
        return reference
    return writer._add_object(cast(PdfObject, cloned))


def _normalize_layers(
    layers: Iterable[ComposeLayer | PageObject | tuple[str, PageObject]],
) -> list[ComposeLayer]:
    normalized: list[ComposeLayer] = []
    for index, layer in enumerate(layers):
        if isinstance(layer, ComposeLayer):
            normalized.append(layer)
        elif isinstance(layer, PageObject):
            normalized.append(ComposeLayer(page=layer, name=f"layer-{index + 1}"))
        else:
            name, page = layer
            normalized.append(ComposeLayer(page=page, name=str(name)))
    return normalized


def _plan_layer(
    layer: ComposeLayer,
    writer: PdfWriter,
    categories: dict[str, DictionaryObject],
    taken: dict[str, set[str]],
    published: dict[tuple[str, str], tuple[str, IndirectObject | None]],
    destination: dict[tuple[str, str], str],
    direct_destination: Mapping[tuple[str, str], str],
) -> tuple[_LayerPlan, list[ScopeConflict]]:
    """
    Plan one layer without modifying the writer.

    Resource objects are cloned only by :func:`_publish_plan`, after every
    layer has been checked. Until then ``categories`` holds the references the
    layer would publish, so naming and reuse decisions already account for
    earlier layers.
    """
    conflicts: list[ScopeConflict] = []
    try:
        content = _content_for_page(layer.page, writer)
        if content is not None:
            content.operations  # noqa: B018 - parse now, so a conflict can be reported
    except Exception as exception:  # noqa: BLE001
        content = None
        conflicts.append(
            ScopeConflict(
                layer.name,
                "content-stream",
                "/Contents",
                f"the layer content stream cannot be read: {exception}",
            )
        )
    plan = _LayerPlan(layer, content)
    resources = _effective_resources(layer.page)

    for category in RENDERING_RESOURCE_CATEGORIES:
        entries = _resource_dictionary(resources, category)
        for raw_name in entries:
            source_name = str(raw_name)
            raw = entries.raw_get(raw_name)
            key = (category, _fingerprint(raw))
            if key in published:
                name, shared = published[key]
                plan.reused.append(
                    PublishedResource(category, layer.name, source_name, name, shared, True)
                )
                plan.rename[category][source_name] = name
                continue
            if key in destination:
                name = destination[key]
                entry = categories[category][NameObject(name)]
                if isinstance(entry, IndirectObject) and key not in direct_destination:
                    plan.reused.append(
                        PublishedResource(
                            category, layer.name, source_name, name, entry, True
                        )
                    )
                else:
                    # The destination page uses a direct object under this name,
                    # for example one of its fonts. Keep the name, because the
                    # destination's own content already refers to it, and publish
                    # it as an indirect object so both contents share one object.
                    plan.pending.append((category, name, entry))
                    plan.planned.append(
                        PublishedResource(category, layer.name, source_name, name)
                    )
                plan.rename[category][source_name] = name
                continue
            name = _published_name(source_name, taken[category])
            taken[category].add(name)
            plan.pending.append((category, name, raw))
            plan.planned.append(
                PublishedResource(category, layer.name, source_name, name)
            )
            published[key] = (name, None)
            plan.rename[category][source_name] = name

    if content is not None:
        for category, name, operator in _resource_uses(content):
            if NameObject(name) not in _resource_dictionary(resources, category):
                conflicts.append(
                    ScopeConflict(
                        layer.name,
                        "content-reference",
                        name,
                        f"operator {operator!r} references {category} {name}, "
                        "which the layer does not define",
                    )
                )
        _rename_content(content, plan.rename)

    for extension_key in DOCUMENT_EXTENSION_KEYS:
        if extension_key not in layer.page:
            continue
        if extension_key in layer.include_document_extensions:
            plan.published_extensions.append(extension_key)
        else:
            plan.excluded_extensions.append(extension_key)
    return plan, conflicts


def _publish_plan(
    plan: _LayerPlan, writer: PdfWriter, categories: dict[str, DictionaryObject]
) -> list[ScopeConflict]:
    """Clone the planned objects into the writer and bind them to their names."""
    conflicts: list[ScopeConflict] = []
    published: list[PublishedResource] = []
    for (category, name, raw), planned in zip(plan.pending, plan.planned):
        reference = _clone_into_writer(raw, writer, force_duplicate=True)
        categories[category][NameObject(name)] = reference
        published.append(
            PublishedResource(
                category, planned.layer, planned.source_name, name, reference
            )
        )
    plan.published = published

    reused: list[PublishedResource] = []
    for resource in plan.reused:
        entry = categories[resource.category].get(NameObject(resource.name), None)
        if not isinstance(entry, IndirectObject):
            # An earlier layer planned this object; it is cloned by its own plan.
            if resource.indirect_reference is not None:
                reused.append(resource)
                continue
            conflicts.append(
                ScopeConflict(
                    plan.layer.name,
                    "published-resource",
                    resource.name,
                    f"{resource.category} {resource.name} is not an indirect object",
                )
            )
            continue
        reused.append(
            PublishedResource(
                resource.category,
                resource.layer,
                resource.source_name,
                resource.name,
                entry,
                True,
            )
        )
    plan.reused = reused
    return conflicts


def _snapshot(writer: PdfWriter, page: PageObject) -> _Snapshot:
    own_resources = page.get(PageAttributes.RESOURCES, None)
    resources_items: list[tuple[Any, Any]] | None = None
    if own_resources is not None and not is_null_or_none(own_resources):
        resolved = _resolve(own_resources)
        if isinstance(resolved, DictionaryObject) and resolved is not page:
            resources_items = list(resolved.items())
    return _Snapshot(
        objects=list(writer._objects),
        translated={source: dict(table) for source, table in writer._id_translated.items()},
        page_items=dict(page.items()),
        resources_items=resources_items,
    )


def _restore(writer: PdfWriter, page: PageObject, snapshot: _Snapshot) -> None:
    writer._objects = list(snapshot.objects)
    writer._id_translated = {
        source: dict(table) for source, table in snapshot.translated.items()
    }
    page.clear()
    page.update(snapshot.page_items)
    page._content_stream_images = None  # noqa: SLF001
    if snapshot.resources_items is not None:
        own_resources = page.get(PageAttributes.RESOURCES, None)
        resolved = _resolve(own_resources)
        if isinstance(resolved, DictionaryObject):
            resolved.clear()
            resolved.update(dict(snapshot.resources_items))


def _apply_resources(
    writer: PdfWriter,
    page: PageObject,
    effective: DictionaryObject,
    categories: dict[str, DictionaryObject],
) -> None:
    merged = DictionaryObject()
    for key, value in effective.items():
        if str(key) not in RENDERING_RESOURCE_CATEGORIES:
            merged[key] = value
    for category, entries in categories.items():
        if len(entries) == 0 and category not in {str(key) for key in effective}:
            continue
        merged[NameObject(category)] = entries

    own_resources = page.get(PageAttributes.RESOURCES, None)
    if own_resources is None or is_null_or_none(own_resources):
        page[NameObject(PageAttributes.RESOURCES)] = writer._add_object(merged)
        return
    resolved = _resolve(own_resources)
    if isinstance(resolved, DictionaryObject):
        resolved.clear()
        resolved.update(merged)
        if isinstance(own_resources, IndirectObject) and own_resources.pdf is not writer:
            page[NameObject(PageAttributes.RESOURCES)] = writer._add_object(resolved)
        return
    page[NameObject(PageAttributes.RESOURCES)] = writer._add_object(merged)


def _collect_old_content_references(contents: Any) -> list[IndirectObject]:
    references: list[IndirectObject] = []
    if isinstance(contents, IndirectObject):
        references.append(contents)
        resolved = _resolve(contents)
        if isinstance(resolved, ArrayObject):
            references.extend(
                entry for entry in resolved if isinstance(entry, IndirectObject)
            )
    return references


def _apply_contents(
    writer: PdfWriter,
    page: PageObject,
    streams: list[ContentStream],
) -> None:
    old_contents = page.get(PageAttributes.CONTENTS, None)
    old_references = _collect_old_content_references(old_contents)
    new_array = ArrayObject(writer._add_object(stream) for stream in streams)
    page[NameObject(PageAttributes.CONTENTS)] = writer._add_object(new_array)
    for reference in old_references:
        if reference.pdf is writer and 0 < reference.idnum <= len(writer._objects):
            writer._replace_object(reference, NullObject())
    page._content_stream_images = None  # noqa: SLF001


def _verify(
    page: PageObject,
    plans: list[_LayerPlan],
    writer: PdfWriter,
) -> list[ScopeConflict]:
    conflicts: list[ScopeConflict] = []
    final_resources = _effective_resources(page)
    for plan in plans:
        for resource in (*plan.published, *plan.reused):
            entry = final_resources.get(NameObject(resource.category), None)
            dictionary = _resolve(entry)
            if not isinstance(dictionary, DictionaryObject):
                conflicts.append(
                    ScopeConflict(
                        plan.layer.name,
                        "published-resource",
                        resource.name,
                        f"{resource.category} is missing from the composed resources",
                    )
                )
                continue
            value = dictionary.get(NameObject(resource.name), None)
            if value is None:
                conflicts.append(
                    ScopeConflict(
                        plan.layer.name,
                        "published-resource",
                        resource.name,
                        f"{resource.category} {resource.name} is not published",
                    )
                )
                continue
            if resource.indirect_reference is not None:
                references = {reference.idnum: reference for reference in (value, _resolve(value)) if isinstance(reference, IndirectObject)}
                if (
                    resource.indirect_reference.idnum not in references
                    or resource.indirect_reference.pdf is not writer
                ):
                    conflicts.append(
                        ScopeConflict(
                            plan.layer.name,
                            "published-resource",
                            resource.name,
                            f"{resource.category} {resource.name} does not resolve to "
                            "the published object",
                        )
                    )
        if plan.content is None:
            continue
        for category, name, operator in _resource_uses(plan.content):
            dictionary = _resolve(final_resources.get(NameObject(category), None))
            if not isinstance(dictionary, DictionaryObject) or NameObject(name) not in dictionary:
                conflicts.append(
                    ScopeConflict(
                        plan.layer.name,
                        "content-reference",
                        name,
                        f"operator {operator!r} no longer resolves after renaming",
                    )
                )
    return conflicts


def _reports(plans: list[_LayerPlan]) -> tuple[ResourceScopeReport, ...]:
    return tuple(
        ResourceScopeReport(
            layer=plan.layer.name,
            published=tuple(plan.published),
            reused=tuple(plan.reused),
            excluded_extension_keys=tuple(plan.excluded_extensions),
            published_extension_keys=tuple(plan.published_extensions),
        )
        for plan in plans
    )


def compose_page(
    writer: PdfWriter,
    page: PageObject | int,
    layers: Iterable[ComposeLayer | PageObject | tuple[str, PageObject]],
    *,
    strict: bool = False,
) -> CompositionResult:
    """
    Draw approved template pages onto one destination page with scoped resources.

    Every layer keeps its own resource definitions. If two layers use the same
    resource name for different objects, the later layer is renamed and its
    content stream is rewritten. An object shared by several layers, or already
    published on the destination page, is reused under a single name.

    Only rendering resources are copied. Document-level extension keys stay
    internal unless the exporter selects them through
    :attr:`ComposeLayer.include_document_extensions`. Publication and reference
    consistency are verified before the result is accepted; a rejected
    composition leaves the destination page and the writer untouched.

    Args:
        writer: The writer that owns the destination page.
        page: Destination page, or its index in the writer.
        layers: Layers drawn over the destination page. A layer may be a
            :class:`ComposeLayer`, a page (named automatically), or a
            ``(name, page)`` tuple.
        strict: Raise :class:`ScopeConflictError` instead of returning a result
            with ``conflicts``.

    Returns:
        The :class:`CompositionResult`.

    Raises:
        PyPdfError: The writer is incremental or the page belongs to another
            document.
    """
    if writer.incremental:
        raise PyPdfError("Scope-aware composition is not supported for incremental writers.")
    destination = writer.pages[page] if isinstance(page, int) else page
    reference = destination.indirect_reference
    if reference is not None and reference.pdf is not writer:
        raise PyPdfError("The destination page does not belong to this writer.")
    if reference is None and destination.pdf is not None and destination.pdf is not writer:
        raise PyPdfError("The destination page does not belong to this writer.")

    normalized = _normalize_layers(layers)
    effective = _effective_resources(destination)
    categories: dict[str, DictionaryObject] = {}
    taken: dict[str, set[str]] = {}
    destination_names: dict[tuple[str, str], str] = {}
    direct_destination: dict[tuple[str, str], str] = {}
    for category in RENDERING_RESOURCE_CATEGORIES:
        entries = DictionaryObject(dict(_resource_dictionary(effective, category).items()))
        categories[category] = entries
        taken[category] = {str(name) for name in entries}
        for name, raw in entries.items():
            resource_key = (category, _fingerprint(raw))
            destination_names[resource_key] = str(name)
            if not isinstance(raw, IndirectObject):
                direct_destination[resource_key] = str(name)

    snapshot = _snapshot(writer, destination)
    published: dict[tuple[str, str], tuple[str, IndirectObject | None]] = {}
    conflicts: list[ScopeConflict] = []
    plans: list[_LayerPlan] = []

    try:
        for layer in normalized:
            plan, layer_conflicts = _plan_layer(
                layer,
                writer,
                categories,
                taken,
                published,
                destination_names,
                direct_destination,
            )
            plans.append(plan)
            conflicts.extend(layer_conflicts)

        if not conflicts:
            for plan in plans:
                for key in plan.published_extensions:
                    if key in destination:
                        conflicts.append(
                            ScopeConflict(
                                plan.layer.name,
                                "document-extension",
                                key,
                                "the destination page already defines this extension key",
                            )
                        )
            if not conflicts:
                for plan in plans:
                    conflicts.extend(_publish_plan(plan, writer, categories))
                if not conflicts:
                    for plan in plans:
                        for key in plan.published_extensions:
                            destination[NameObject(key)] = _clone_into_writer(
                                plan.layer.page.raw_get(key),
                                writer,
                                force_duplicate=True,
                            )

        if not conflicts:
            streams: list[ContentStream] = []
            existing = destination.get(PageAttributes.CONTENTS, None)
            if existing is not None and not is_null_or_none(existing):
                existing_content = ContentStream(_resolve(existing), writer)
                existing_content.isolate_graphics_state()
                streams.append(existing_content)
            configuration = get_configuration()
            for plan in plans:
                content = plan.content
                if content is None:
                    continue
                rect = getattr(plan.layer.page, configuration.page_merge_box)
                clip = ArrayObject(
                    (
                        FloatObject(rect.left),
                        FloatObject(rect.bottom),
                        FloatObject(rect.width),
                        FloatObject(rect.height),
                    )
                )
                content.operations.insert(0, (clip, b"re"))
                content.operations.insert(1, ([], b"W"))
                content.operations.insert(2, ([], b"n"))
                content.isolate_graphics_state()
                streams.append(content)
            if streams:
                _apply_contents(writer, destination, streams)
                _apply_resources(writer, destination, effective, categories)
                conflicts.extend(_verify(destination, plans, writer))
    except Exception:
        _restore(writer, destination, snapshot)
        raise

    if conflicts:
        _restore(writer, destination, snapshot)
        if strict:
            raise ScopeConflictError(conflicts)
        return CompositionResult(reports=_reports(plans), conflicts=tuple(conflicts))
    return CompositionResult(page=destination, reports=_reports(plans))


def reachable_object_numbers(pdf: Any) -> set[int]:
    """
    Return the object numbers reachable from a document's trailer.

    Works for :class:`PdfReader` and :class:`PdfWriter`. Objects that are no
    longer reachable, for example a document-level extension that was not
    published, are not part of the result. Reading a document is not the same
    as retaining it: an object is only reported if the document graph still
    leads to it.
    """
    roots: list[Any] = [pdf.root_object]
    for extra in (
        getattr(pdf, "_info", None),
        getattr(pdf, "_ID", None),
        getattr(pdf, "_encrypt_entry", None),
    ):
        if extra is not None:
            roots.append(extra)
    reachable: set[int] = set()
    stack = list(roots)
    objects = getattr(pdf, "_objects", None)
    while stack:
        current = stack.pop()
        if isinstance(current, IndirectObject):
            if current.pdf is not pdf or current.idnum in reachable:
                continue
            reachable.add(current.idnum)
            try:
                if objects is not None:
                    if not 0 < current.idnum <= len(objects):
                        continue
                    target = objects[current.idnum - 1]
                else:
                    target = pdf.get_object(current.idnum)
            except Exception:  # noqa: BLE001 - a missing object ends this branch
                continue
            if target is not None:
                stack.append(target)
            continue
        if isinstance(current, DictionaryObject):
            stack.extend(current.values())
        elif isinstance(current, ArrayObject):
            stack.extend(current)
    return reachable


def check_page_resource_references(page: PageObject) -> list[str]:
    """
    Verify that every resource name used by the page's content stream resolves.

    Returns a list of human-readable problems; an empty list means all
    references resolve in the page's (possibly inherited) resources.
    """
    problems: list[str] = []
    content = _content_for_page(page, page.pdf)
    if content is None:
        return problems
    resources = _effective_resources(page)
    for category, name, operator in _resource_uses(content):
        if NameObject(name) not in _resource_dictionary(resources, category):
            problems.append(f"{operator!r} references {category} {name}, which is not defined")
    return problems
