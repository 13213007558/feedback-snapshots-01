# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""
Render internal and partner views of the same BOM.

Restricted components must not disclose their name, repository, evidence paths,
or other identifying details. The partner view replaces each of them with a
stable placeholder and rewrites dependency and vulnerability references, so the
remaining consumers can still see that a risk originates from a restricted
dependency.

Both views are verified by re-parsing their JSON and XML renderings and by
comparing the reconstructed relationship graphs with the intended ones.
"""

__all__ = [
    'RESTRICTED_COMPONENT_PROPERTY',
    'BomRelationshipReport',
    'BomView',
    'BomViewPair',
    'BomViewRedactor',
    'collect_relationship_report',
    'is_restricted_component',
    'make_bom_views',
]

import copy
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from io import StringIO
from json import loads as json_loads
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Union
from uuid import UUID

from packageurl import PackageURL
from sortedcontainers import SortedSet

from ...exception.model import BomIdentityLeakException, BomReferenceIntegrityException
from ...model import Property, XsUri
from ...model.bom import Bom
from ...model.bom_ref import BomRef
from ...model.component import Component
from ...model.service import Service
from ...schema import OutputFormat, SchemaVersion

RESTRICTED_COMPONENT_PROPERTY = 'urn:cdx:restricted:component'
"""
Property name used to mark a component as restricted.

A component carrying this property with a truthy value is treated as restricted
by :func:`is_restricted_component`. The marker is deliberately retained on
partner placeholders, so consumers can see that a dependency was redacted.
"""


_FALSE_VALUES = frozenset(('', '0', 'false', 'no', 'off'))
_GENERIC_PARTNER_TOKEN = '[restricted]'
_GENERIC_TERMS = frozenset((
    # Schema-defined literals and common placeholders that cannot identify one component.
    'true', 'false', 'yes', 'no', 'none', 'null', 'unknown', 'other', 'required', 'optional',
    'cyclonedx', 'restricted', 'redacted', 'withheld',
))


def is_restricted_component(component: Component) -> bool:
    """
    Check whether a component is marked as restricted via :data:`RESTRICTED_COMPONENT_PROPERTY`.
    """
    return any(
        prop.name == RESTRICTED_COMPONENT_PROPERTY
        and (prop.value or '').strip().lower() not in _FALSE_VALUES
        for prop in component.properties
    )


@dataclass(frozen=True)
class BomRelationshipReport:
    """
    Snapshot of the relationships encoded in a BOM.

    The report only covers identity and edges, not descriptive fields, which
    makes it suitable for verifying a redacted view against its source.
    """

    component_refs: FrozenSet[str]
    service_refs: FrozenSet[str]
    dependency_edges: FrozenSet[Tuple[str, str]]
    vulnerability_targets: FrozenSet[Tuple[str, FrozenSet[str]]]
    unresolved_refs: FrozenSet[str]
    duplicate_refs: FrozenSet[str]

    @property
    def is_complete(self) -> bool:
        """Whether every relationship points at a known component or service and all refs are unique."""
        return not self.unresolved_refs and not self.duplicate_refs


@dataclass(frozen=True)
class BomView:
    """A rendered view of a BOM, including both supported output formats."""

    bom: Bom
    json: str
    xml: str
    relationship_report: BomRelationshipReport

    def as_string(self, output_format: OutputFormat) -> str:
        """Return the rendering for the requested format."""
        if output_format is OutputFormat.JSON:
            return self.json
        if output_format is OutputFormat.XML:
            return self.xml
        raise ValueError(f'Unsupported output format: {output_format!r}')


@dataclass(frozen=True)
class BomViewPair:
    """The internal and partner views of the same BOM."""

    internal: BomView
    partner: BomView
    # Map of original restricted `bom-ref` values to partner placeholders. Keep this internal.
    restricted_bom_refs: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'restricted_bom_refs', MappingProxyType(dict(self.restricted_bom_refs)))


class BomViewRedactor:
    """
    Render internal and partner views of a single BOM.

    Restrict components either by marking them with
    :data:`RESTRICTED_COMPONENT_PROPERTY`, by supplying a predicate, or by
    supplying ``bom-ref`` values. A restricted component also restricts the
    components nested inside it, because assemblies are part of its identity.

    Restricted components are replaced by placeholder components with stable
    references and a public marker property. Dependencies, nested assemblies,
    and vulnerability targets are rewritten to the placeholders, so the partner
    view still shows that a risk originates from a restricted dependency.

    All textual fields of the partner view are scrubbed for values collected
    from restricted components (names, purls, repository URLs, evidence paths,
    contacts, property values, hashes) and for any additional
    ``sensitive_strings``. The internal view retains the original values.

    The source BOM is never modified.

    :raises ValueError: if no component matches the restriction criteria.
    :raises cyclonedx.exception.model.BomReferenceIntegrityException: if the source BOM or a rendered view has
        dangling references or duplicate ``bom-ref`` values, or if a re-parsed view does not reproduce the
        relationship graph.
    :raises cyclonedx.exception.model.BomIdentityLeakException: if the internal view lost restricted details or the
        partner view still contains restricted identity material.
    """

    def __init__(
        self,
        bom: Bom,
        *,
        restricted: Optional[Union[Callable[[Component], bool], Iterable[str]]] = None,
        placeholder_prefix: str = 'restricted-component',
        sensitive_strings: Optional[Iterable[str]] = None,
        label: str = 'restricted component',
    ) -> None:
        self._source = _normalized_copy(bom)
        self._placeholder_prefix = placeholder_prefix or 'restricted-component'
        self._label = label
        self._sensitive_strings = tuple(sorted({s for s in (sensitive_strings or ()) if s}))
        selector = _make_selector(restricted)
        matched = sorted(
            (component for component in _iter_inventory_components(self._source) if selector(component)),
            key=_component_sort_key,
        )
        if not matched:
            raise ValueError('No restricted components matched the supplied criteria')
        restricted_components: Dict[str, Component] = {}
        for component in matched:
            for nested in component.iter_all_nested_components(include_self=True):
                if nested.bom_ref.value:
                    restricted_components.setdefault(nested.bom_ref.value, nested)
        self._restricted_components: Tuple[Component, ...] = tuple(
            restricted_components[ref] for ref in sorted(restricted_components)
        )
        self._placeholder_map = self._make_placeholder_map()
        restricted_ids = {id(component) for component in self._restricted_components}
        public_values = _public_values(
            component
            for component in _iter_inventory_components(self._source)
            if id(component) not in restricted_ids
        )
        self._scrub_terms = _component_scrub_terms(self._restricted_components, public_values)
        self._scrub_terms.update({term: _GENERIC_PARTNER_TOKEN for term in self._sensitive_strings})
        self._partner_cache: Optional[Tuple[Bom, Dict[str, str]]] = None

    @property
    def restricted_components(self) -> Tuple[Component, ...]:
        """The components that are replaced in the partner view, in placeholder order."""
        return self._restricted_components

    @property
    def placeholder_map(self) -> Mapping[str, str]:
        """Map of original restricted ``bom-ref`` values to the placeholders used in the partner view."""
        return MappingProxyType(dict(self._placeholder_map))

    def internal_view(self, *, schema_version: SchemaVersion = SchemaVersion.V1_7) -> BomView:
        """Render the internal view, which retains all restricted component details."""
        _check_schema_version(schema_version)
        bom = copy.deepcopy(self._source)
        _verify_relationships(bom, 'internal')
        _prepare_for_output(bom)
        report = _verify_relationships(bom, 'internal')
        json_str, xml_str = _render(bom, schema_version)
        parsed = _verify_roundtrip(bom, report, json_str, xml_str, 'internal')
        _verify_internal_view(parsed, self._restricted_components)
        return BomView(bom=bom, json=json_str, xml=xml_str, relationship_report=report)

    def partner_view(self, *, schema_version: SchemaVersion = SchemaVersion.V1_7) -> BomView:
        """Render the partner view, with restricted components replaced by placeholders."""
        _check_schema_version(schema_version)
        partner, _ = self._partner_bom_and_map()
        partner = copy.deepcopy(partner)
        _verify_relationships(partner, 'partner')
        _prepare_for_output(partner)
        report = _verify_relationships(partner, 'partner')
        json_str, xml_str = _render(partner, schema_version)
        parsed = _verify_roundtrip(partner, report, json_str, xml_str, 'partner')
        _verify_partner_view(parsed, self._scrub_terms, self._restricted_components)
        return BomView(bom=partner, json=json_str, xml=xml_str, relationship_report=report)

    def export(self, *, schema_version: SchemaVersion = SchemaVersion.V1_7) -> BomViewPair:
        """Render both views of the same BOM."""
        return BomViewPair(
            internal=self.internal_view(schema_version=schema_version),
            partner=self.partner_view(schema_version=schema_version),
            restricted_bom_refs=self._placeholder_map,
        )

    # region partner preparation

    def _make_placeholder_map(self) -> Dict[str, str]:
        used_refs = {ref.value for ref in _iter_bom_refs(self._source) if ref.value}
        ref_map: Dict[str, str] = {}
        index = 0
        for source in self._restricted_components:
            placeholder = ''
            while not placeholder or placeholder in used_refs:
                index += 1
                placeholder = f'{self._placeholder_prefix}-{index}'
            used_refs.add(placeholder)
            if source.bom_ref.value:
                ref_map[source.bom_ref.value] = placeholder
        return ref_map

    def _partner_bom_and_map(self) -> Tuple[Bom, Dict[str, str]]:
        if self._partner_cache is None:
            self._partner_cache = self._build_partner_bom()
        return self._partner_cache

    def _build_partner_bom(self) -> Tuple[Bom, Dict[str, str]]:
        memo: Dict[int, Any] = {}
        partner = copy.deepcopy(self._source, memo)
        ref_map = dict(self._placeholder_map)
        for source in self._restricted_components:
            placeholder = ref_map.get(source.bom_ref.value or '')
            if placeholder is None:  # pragma: no cover - all components are normalized to have a ref
                raise ValueError(f'Restricted component without a bom-ref: {source!r}')
            target = memo[id(source)]
            target.bom_ref.value = placeholder
            _restrict_component(target, placeholder, self._label)

        # A restricted assembly loses its children; keep those children in the partner BOM so that dependency and
        # vulnerability references to them do not dangle.
        reachable = _reachable_nested_component_ids(partner)
        top_level = {id(component) for component in partner.components}
        for source in self._restricted_components:
            target = memo[id(source)]
            if target is partner.metadata.component:
                continue
            if id(target) in top_level or id(target) in reachable:
                continue
            partner.components.add(target)

        # Rewrite references first, then scrub text. Scrubbing runs second so that a restricted value never survives
        # by being embedded in a reference string.
        scrubber = _make_scrubber(self._scrub_terms)

        def transform(value: str) -> str:
            value = ref_map.get(value, value)
            return scrubber(value) if scrubber is not None else value

        _transform_strings(
            partner, transform,
            uri_transform=lambda uri: 'https://redacted.invalid/' if transform(uri) != uri else uri,
        )
        _rehash(partner)
        return partner, ref_map

    # endregion partner preparation


def make_bom_views(
    bom: Bom,
    *,
    restricted: Optional[Union[Callable[[Component], bool], Iterable[str]]] = None,
    schema_version: SchemaVersion = SchemaVersion.V1_7,
    placeholder_prefix: str = 'restricted-component',
    sensitive_strings: Optional[Iterable[str]] = None,
    label: str = 'restricted component',
) -> BomViewPair:
    """Convenience wrapper around :class:`BomViewRedactor`."""
    return BomViewRedactor(
        bom,
        restricted=restricted,
        placeholder_prefix=placeholder_prefix,
        sensitive_strings=sensitive_strings,
        label=label,
    ).export(schema_version=schema_version)


# region model normalization and traversal

_LEAF_TYPES = (str, bytes, int, float, bool, complex, type(None), Enum, UUID, datetime, Decimal, type)


def _make_selector(
    restricted: Optional[Union[Callable[[Component], bool], Iterable[str]]]
) -> Callable[[Component], bool]:
    if callable(restricted):
        return restricted
    if restricted is None:
        return is_restricted_component
    refs = frozenset((restricted,)) if isinstance(restricted, str) else frozenset(restricted)
    return lambda component: component.bom_ref.value in refs


def _check_schema_version(schema_version: SchemaVersion) -> None:
    if schema_version < SchemaVersion.V1_4:
        raise ValueError(
            'Restricted BOM views need CycloneDX schema version 1.4 or later, '
            f'got {schema_version.to_version()}'
        )


def _normalized_copy(bom: Bom) -> Bom:
    """Copy a BOM and give every component/service a unique, non-empty ``bom-ref``."""
    source = copy.deepcopy(bom)
    if source.metadata.component is not None:
        root = source.metadata.component
        # The metadata component is the BOM's subject. When it is also listed as a root component it must not be
        # serialized twice, because that would duplicate its `bom-ref`.
        source.components = tuple(component for component in source.components if component is not root)
    used = {ref.value for ref in _iter_bom_refs(source) if ref.value}
    for prefix, items in (
        ('component', sorted(_iter_components(source), key=_component_sort_key)),
        ('service', sorted(_iter_services(source), key=_service_sort_key)),
    ):
        for item in items:
            if item.bom_ref.value:
                continue
            index = 0
            while True:
                index += 1
                candidate = f'{prefix}-{index}'
                if candidate not in used:
                    used.add(candidate)
                    item.bom_ref.value = candidate
                    break
    _rehash(source)
    return source


def _reachable_nested_component_ids(bom: Bom) -> Set[int]:
    ids: Set[int] = set()

    def walk(component: Component) -> None:
        for nested in component.components:
            ids.add(id(nested))
            walk(nested)

    if bom.metadata.component is not None:
        walk(bom.metadata.component)
    for component in bom.components:
        walk(component)
    return ids


def _prepare_for_output(bom: Bom) -> None:
    """Complete the default dependency entries before rendering and verifying."""
    bom.validate()
    _rehash(bom)


def _iter_components(bom: Bom) -> Iterator[Component]:
    yield from _unique_instances(_walk(bom), Component)


def _iter_inventory_components(bom: Bom) -> Iterator[Component]:
    """Components that make up the inventory: the metadata component, its assemblies, and the root components."""
    seen: Set[int] = set()

    def emit(component: Component) -> Iterator[Component]:
        for nested in component.iter_all_nested_components(include_self=True):
            if id(nested) not in seen:
                seen.add(id(nested))
                yield nested

    if bom.metadata.component is not None:
        yield from emit(bom.metadata.component)
    for component in bom.components:
        yield from emit(component)


def _iter_services(bom: Bom) -> Iterator[Service]:
    yield from _unique_instances(_walk(bom), Service)


def _iter_bom_refs(obj: Any) -> Iterator[BomRef]:
    yield from _unique_instances(_walk(obj), BomRef)


def _unique_instances(values: Iterable[Any], cls: type) -> Iterator[Any]:
    seen: Set[int] = set()
    for value in values:
        if isinstance(value, cls) and id(value) not in seen:
            seen.add(id(value))
            yield value


def _walk(obj: Any) -> Iterator[Any]:
    """Yield every mutable model object reachable from ``obj``."""
    seen: Set[int] = set()

    def walk(value: Any) -> Iterator[Any]:
        if isinstance(value, _LEAF_TYPES) or isinstance(value, PackageURL):
            return
        value_id = id(value)
        if value_id in seen:
            return
        seen.add(value_id)
        yield value
        if isinstance(value, Mapping):
            for item in value.values():
                yield from walk(item)
        elif isinstance(value, (list, tuple, set, frozenset, SortedSet)):
            for item in value:
                yield from walk(item)
        elif hasattr(value, '__dict__'):
            for item in vars(value).values():
                yield from walk(item)

    yield from walk(obj)


def _transform_strings(
    obj: Any,
    transform: Callable[[str], str],
    *,
    uri_transform: Optional[Callable[[str], str]] = None,
) -> Any:
    """
    Apply ``transform`` to every string reachable from ``obj``.

    ``SortedSet`` items are rebuilt, because their sort/hash keys may have changed. URI values can be handled
    separately via ``uri_transform`` so that redaction still yields a syntactically valid URI.
    """
    seen: Set[int] = set()

    def visit(value: Any) -> Any:
        # Enum cases frequently subclass `str`; they must remain enum instances for serialization.
        if isinstance(value, Enum):
            return value
        if isinstance(value, str):
            return transform(value)
        if isinstance(value, XsUri):
            if uri_transform is not None and id(value) not in seen:
                seen.add(id(value))
                value._uri = uri_transform(value._uri)  # noqa: SLF001
            return value
        if isinstance(value, _LEAF_TYPES) or isinstance(value, PackageURL):
            return value
        value_id = id(value)
        if value_id in seen:
            return value
        seen.add(value_id)
        if isinstance(value, dict):
            for key, item in list(value.items()):
                value[key] = visit(item)
            return value
        if isinstance(value, list):
            for index, item in enumerate(value):
                value[index] = visit(item)
            return value
        if isinstance(value, tuple):
            return tuple(visit(item) for item in value)
        if isinstance(value, (set, frozenset, SortedSet)):
            items = [visit(item) for item in value]
            if isinstance(value, (set, SortedSet)):
                value.clear()
                value.update(items)
                return value
            return frozenset(items)
        if hasattr(value, '__dict__'):
            for name, item in list(vars(value).items()):
                setattr(value, name, visit(item))
            return value
        return value

    return visit(obj)


def _rehash(obj: Any) -> None:
    """
    Re-add items to every ``SortedSet`` after their sort/hash keys changed.

    Children are processed before their containers, so parent ordering sees the
    final hash of each child.
    """
    done: Set[int] = set()
    active: Set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, _LEAF_TYPES) or isinstance(value, PackageURL):
            return
        value_id = id(value)
        if value_id in done or value_id in active:
            return
        active.add(value_id)
        if isinstance(value, SortedSet):
            items = list(value)
            for item in items:
                visit(item)
            value.clear()
            value.update(items)
        elif isinstance(value, Mapping):
            for item in value.values():
                visit(item)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                visit(item)
        elif hasattr(value, '__dict__'):
            for item in vars(value).values():
                visit(item)
        active.discard(value_id)
        done.add(value_id)

    visit(obj)


def _component_sort_key(component: Component) -> Tuple[str, str, str, str, str]:
    return (
        component.bom_ref.value or '',
        component.group or '',
        component.name,
        component.version or '',
        str(component.purl) if component.purl else '',
    )


def _service_sort_key(service: Service) -> Tuple[str, str, str, str]:
    return (
        service.bom_ref.value or '',
        service.group or '',
        service.name,
        service.version or '',
    )


def _restrict_component(component: Component, placeholder: str, label: str) -> None:
    """Remove identifying and evidentiary content from a restricted component in place."""
    component.name = placeholder
    component.group = None
    component.version = None
    component.description = f'{label} ({placeholder}); details withheld'
    component.purl = None
    component.cpe = None
    component.supplier = None
    component.manufacturer = None
    component.authors = ()
    component.publisher = None
    component.hashes = ()
    component.licenses = ()
    component.copyright = None
    component.omnibor_ids = ()
    component.swhids = ()
    component.swid = None
    component.pedigree = None
    component.external_references = ()
    component.properties = (Property(name=RESTRICTED_COMPONENT_PROPERTY, value='true'),)
    component.components = ()
    component.evidence = None
    component.release_notes = None
    component.crypto_properties = None
    component.tags = ()
    component.author = None
    component.modified = False


# endregion model normalization and traversal


# region sensitive terms

def _public_values(components: Iterable[Component]) -> Tuple[str, ...]:
    values: Set[str] = set()
    for component in components:
        values.update(_raw_sensitive_terms(component))
    return tuple(values)


def _component_scrub_terms(components: Iterable[Component], public_values: Iterable[str]) -> Dict[str, str]:
    """
    All values that may be replaced in the partner view, mapped to a replacement token.

    Values that are already disclosed by a non-restricted component are left alone: redacting them would corrupt
    public data without protecting anything.
    """
    public = tuple(public_values)
    terms: Dict[str, str] = {}
    for component in components:
        for term in _raw_sensitive_terms(component):
            if any(term == value or term in value for value in public):
                continue
            terms.setdefault(term, _GENERIC_PARTNER_TOKEN)
    return terms


def _raw_sensitive_terms(component: Component) -> Iterator[str]:
    def emit(value: Optional[Any], *, short_ok: bool = False) -> Iterator[str]:
        if value is None:
            return
        text = str(value).strip()
        if not text or text.lower() in _GENERIC_TERMS:
            return
        if len(text) < (2 if short_ok else 3):
            return
        yield text

    yield from emit(component.bom_ref.value, short_ok=True)
    yield from emit(component.name, short_ok=True)
    yield from emit(component.group)
    yield from emit(component.purl)
    yield from emit(component.cpe)
    yield from emit(component.publisher)
    yield from emit(component.author)
    yield from emit(component.description)
    yield from emit(component.copyright)
    for entity in (component.supplier, component.manufacturer):
        if entity is None:
            continue
        yield from emit(entity.name)
        yield from emit(entity.bom_ref.value)
        for url in entity.urls:
            yield from emit(url)
        if entity.address is not None:
            yield from emit(entity.address.street_address)
            yield from emit(entity.address.locality)
            yield from emit(entity.address.postal_code)
        for contact in entity.contacts:
            yield from emit(contact.name)
            yield from emit(contact.email)
            yield from emit(contact.phone)
    for contact in component.authors:
        yield from emit(contact.name)
        yield from emit(contact.email)
        yield from emit(contact.phone)
    for reference in component.external_references:
        yield from emit(reference.url)
        yield from emit(reference.comment)
    for prop in component.properties:
        if prop.name != RESTRICTED_COMPONENT_PROPERTY:
            yield from emit(prop.value)
    if component.swid is not None:
        yield from emit(component.swid.tag_id)
        yield from emit(component.swid.name)
    for hash_type in component.hashes:
        yield from emit(hash_type.content)
    if component.evidence is not None:
        for occurrence in component.evidence.occurrences:
            yield from emit(occurrence.location)
            yield from emit(occurrence.symbol)
            yield from emit(occurrence.additional_context)
        if component.evidence.callstack is not None:
            for frame in component.evidence.callstack.frames:
                yield from emit(frame.package)
                yield from emit(frame.module)
                yield from emit(frame.function)
                yield from emit(frame.full_filename)
        for identity in component.evidence.identity:
            yield from emit(identity.concluded_value)


def _make_scrubber(terms: Mapping[str, str]) -> Optional[Callable[[str], str]]:
    if not terms:
        return None
    ordered = sorted(terms, key=len, reverse=True)
    lowered = {term.lower(): token for term, token in terms.items()}
    pattern = re.compile('|'.join(_term_pattern(term) for term in ordered), re.IGNORECASE)

    def scrub(value: str) -> str:
        return pattern.sub(lambda match: lowered.get(match.group(0).lower(), _GENERIC_PARTNER_TOKEN), value)

    return scrub


def _term_pattern(term: str) -> str:
    if re.search(r'[/\\@:]', term) or ' ' in term:
        return re.escape(term)
    return r'(?<![A-Za-z0-9_.-])' + re.escape(term) + r'(?![A-Za-z0-9_.-])'


def _find_term(text: str, term: str) -> bool:
    return re.search(_term_pattern(term), text, re.IGNORECASE) is not None

# endregion sensitive terms


# region rendering and verification

def _render(bom: Bom, schema_version: SchemaVersion) -> Tuple[str, str]:
    from ...output import make_outputter
    json_str = make_outputter(bom, OutputFormat.JSON, schema_version).output_as_string(indent=2)
    xml_str = make_outputter(bom, OutputFormat.XML, schema_version).output_as_string(indent=2)
    return json_str, xml_str


def collect_relationship_report(bom: Bom) -> BomRelationshipReport:
    """
    Collect the component/service references and the edges that point at them.

    Unresolved references and duplicate ``bom-ref`` values are reported rather
    than raised, so callers can inspect a BOM before deciding what to do.
    """
    components = tuple(_iter_components(bom))
    services = tuple(_iter_services(bom))
    component_ref_values = [c.bom_ref.value for c in components if c.bom_ref.value]
    service_ref_values = [s.bom_ref.value for s in services if s.bom_ref.value]
    component_refs = frozenset(component_ref_values)
    service_refs = frozenset(service_ref_values)
    known = component_refs | service_refs

    all_refs = component_ref_values + service_ref_values
    duplicates = frozenset(ref for ref in set(all_refs) if all_refs.count(ref) > 1)

    unresolved: Set[str] = set()
    edges: Set[Tuple[str, str]] = set()
    seen_dependencies: Set[int] = set()
    todo = list(bom.dependencies)
    while todo:
        dependency = todo.pop()
        if id(dependency) in seen_dependencies:
            continue
        seen_dependencies.add(id(dependency))
        source = dependency.ref.value or ''
        if source and source not in known:
            unresolved.add(source)
        for nested in dependency.dependencies:
            target = nested.ref.value or ''
            if target and target not in known:
                unresolved.add(target)
            edges.add((source, target))
            todo.append(nested)

    vulnerability_targets: Set[Tuple[str, FrozenSet[str]]] = set()
    for vulnerability in bom.vulnerabilities:
        key = vulnerability.id or vulnerability.bom_ref.value or ''
        targets: Set[str] = set()
        for target in vulnerability.affects:
            targets.add(target.ref)
            if target.ref not in known:
                unresolved.add(target.ref)
        vulnerability_targets.add((key, frozenset(targets)))

    return BomRelationshipReport(
        component_refs=component_refs,
        service_refs=service_refs,
        dependency_edges=frozenset(edges),
        vulnerability_targets=frozenset(vulnerability_targets),
        unresolved_refs=frozenset(unresolved),
        duplicate_refs=duplicates,
    )


def _verify_relationships(bom: Bom, view_name: str) -> BomRelationshipReport:
    report = collect_relationship_report(bom)
    problems: List[str] = []
    if report.unresolved_refs:
        problems.append('unresolved refs: ' + ', '.join(sorted(report.unresolved_refs)))
    if report.duplicate_refs:
        problems.append('duplicate refs: ' + ', '.join(sorted(report.duplicate_refs)))
    if problems:
        raise BomReferenceIntegrityException(f'{view_name} BOM is inconsistent: ' + '; '.join(problems))
    return report


def _verify_roundtrip(
    bom: Bom,
    expected: BomRelationshipReport,
    json_str: str,
    xml_str: str,
    view_name: str,
) -> Tuple[Bom, Bom]:
    parsed_json = Bom.from_json(json_loads(json_str))
    parsed_xml = Bom.from_xml(StringIO(xml_str))
    if parsed_json is None or parsed_xml is None:
        raise BomReferenceIntegrityException(f'{view_name} view could not be re-parsed')

    for fmt, parsed in (('JSON', parsed_json), ('XML', parsed_xml)):
        actual = collect_relationship_report(parsed)
        problems: List[str] = []
        if actual.unresolved_refs:
            problems.append('unresolved refs: ' + ', '.join(sorted(actual.unresolved_refs)))
        if actual.duplicate_refs:
            problems.append('duplicate refs: ' + ', '.join(sorted(actual.duplicate_refs)))
        if actual.component_refs != expected.component_refs:
            problems.append('component refs differ')
        if actual.service_refs != expected.service_refs:
            problems.append('service refs differ')
        if actual.dependency_edges != expected.dependency_edges:
            problems.append('dependency edges differ')
        if actual.vulnerability_targets != expected.vulnerability_targets:
            problems.append('vulnerability targets differ')
        if problems:
            raise BomReferenceIntegrityException(
                f'{view_name} view failed {fmt} round-trip verification: ' + '; '.join(problems)
            )
    return parsed_json, parsed_xml


def _verify_internal_view(
    parsed_views: Tuple[Bom, Bom],
    restricted: Iterable[Component],
) -> None:
    problems: List[str] = []
    for component in restricted:
        original = component.bom_ref.value
        if not original:
            continue
        for fmt, parsed in (('JSON', parsed_views[0]), ('XML', parsed_views[1])):
            by_ref = {c.bom_ref.value: c for c in _iter_components(parsed) if c.bom_ref.value}
            restored = by_ref.get(original)
            if restored is None:
                problems.append(f'{fmt}: component {original!r} missing')
                continue
            if restored.name != component.name:
                problems.append(f'{fmt}: name of {original!r} changed')
            if str(restored.purl or '') != str(component.purl or ''):
                problems.append(f'{fmt}: purl of {original!r} changed')
            expected_terms = _raw_sensitive_terms(component)
            parsed_texts = tuple(_model_texts(restored))
            for term in expected_terms:
                if not any(_find_term(text, term) for text in parsed_texts):
                    problems.append(f'{fmt}: {term!r} missing from {original!r}')
    if problems:
        raise BomIdentityLeakException(
            'The internal view does not retain restricted component details: ' + '; '.join(sorted(set(problems)))
        )


def _verify_partner_view(
    parsed_views: Tuple[Bom, Bom],
    scrub_terms: Mapping[str, str],
    restricted: Iterable[Component],
) -> None:
    original_refs = {component.bom_ref.value for component in restricted if component.bom_ref.value}
    for fmt, parsed in (('JSON', parsed_views[0]), ('XML', parsed_views[1])):
        # Check the parsed model, not the raw document: fixed format literals such as `bomFormat: CycloneDX` are not
        # component data and must not be mistaken for leaked identity.
        leaked = sorted(
            term
            for term in scrub_terms
            if any(_find_term(value, term) for value in _model_texts(parsed))
        )
        if leaked:
            raise BomIdentityLeakException(
                f'The partner view ({fmt}) still contains restricted identity material: ' + ', '.join(leaked)
            )
        component_refs = {c.bom_ref.value for c in _iter_components(parsed) if c.bom_ref.value}
        still_present = original_refs & component_refs
        if still_present:
            raise BomIdentityLeakException(
                f'The partner view ({fmt}) still uses original restricted references: '
                + ', '.join(sorted(still_present))
            )
        if not any(is_restricted_component(c) for c in _iter_components(parsed)):
            raise BomIdentityLeakException(f'The partner view ({fmt}) has no restricted component placeholders')


def _model_texts(obj: Any) -> Iterator[str]:
    """Every user-provided string value in a model, excluding enum literals and type names."""
    for value in _walk(obj):
        if isinstance(value, Enum):
            continue
        if isinstance(value, PackageURL):
            yield str(value)
            continue
        if isinstance(value, BomRef):
            if value.value:
                yield value.value
            continue
        if not hasattr(value, '__dict__'):
            continue
        for item in vars(value).values():
            if isinstance(item, PackageURL):
                yield str(item)
            elif isinstance(item, str) and not isinstance(item, Enum):
                yield item
            elif isinstance(item, (list, tuple, set, frozenset)) and all(isinstance(v, str) for v in item):
                yield from (v for v in item if v)

# endregion rendering and verification
