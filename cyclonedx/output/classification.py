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
Reference-aware classification policies for leveled BOM exports.

The projection in this module never mutates the caller's BOM.  In particular,
one :class:`~cyclonedx.model.component_evidence.ComponentEvidence` object may be
held by several components; every component reference receives its own filtered
copy according to that reference's approved level and the outlet level.
"""

from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from enum import Enum
from functools import total_ordering
from re import sub
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple, Union
from weakref import WeakKeyDictionary

from ..model.bom import Bom
from ..model.bom_ref import BomRef
from ..model.component import Component
from ..model.component_evidence import (
    CallStack,
    ComponentEvidence,
    Identity,
    Occurrence,
)
from ..schema import OutputFormat, SchemaVersion

_UNSET: Any = object()


@total_ordering
class SecurityLevel(str, Enum):
    """Ordered disclosure/approval levels. Higher ranks are more restricted."""

    PUBLIC = 'public'
    UNCLASSIFIED = 'public'
    CLEAR = 'public'
    GREEN = 'public'
    INTERNAL = 'internal'
    OFFICIAL = 'internal'
    AMBER = 'confidential'
    CONFIDENTIAL = 'confidential'
    HIGH = 'confidential'
    SECRET = 'restricted'
    RESTRICTED = 'restricted'
    RED = 'restricted'
    CRITICAL = 'restricted'

    @property
    def rank(self) -> int:
        return {
            'public': 0,
            'internal': 10,
            'confidential': 20,
            'restricted': 30,
        }[self.value]

    def __lt__(self, other: Any) -> bool:
        return self.rank < coerce_level(other).rank

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, SecurityLevel):
            return self.value == other.value
        try:
            return self.value == coerce_level(other).value
        except (TypeError, ValueError):
            return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


Classification = SecurityLevel
ClassificationLevel = SecurityLevel
ReleaseLevel = SecurityLevel
AccessLevel = SecurityLevel
SensitivityLevel = SecurityLevel
DisclosureLevel = SecurityLevel
ExportLevel = SecurityLevel


class Outlet(str, Enum):
    """Common export outlets."""

    PUBLIC = 'public'
    INTERNAL = 'internal'
    EXTERNAL = 'public'
    PARTNER = 'public'
    STAFF = 'internal'


ExportOutlet = Outlet
ExportTarget = Outlet
Audience = Outlet

_LEVEL_TEXT: Dict[str, int] = {
    '0': 0,
    'public': 0,
    'unclassified': 0,
    'clear': 0,
    'low': 0,
    'green': 0,
    '1': 10,
    '10': 10,
    'internal': 10,
    'private': 10,
    'official': 10,
    'medium': 10,
    'moderate': 10,
    'amber': 20,
    'confidential': 20,
    'sensitive': 20,
    'high': 20,
    '2': 20,
    '20': 20,
    'restricted': 30,
    'secret': 30,
    'red': 30,
    'critical': 30,
    'top_secret': 30,
    'topsecret': 30,
    '3': 30,
    '30': 30,
    '公开': 0,
    '公共': 0,
    '内部': 10,
    '机密': 20,
    '秘密': 30,
    '受限': 30,
}


def _level_from_rank(rank: int) -> SecurityLevel:
    if rank <= 0:
        return SecurityLevel.PUBLIC
    if rank <= 10:
        return SecurityLevel.INTERNAL
    if rank <= 20:
        return SecurityLevel.CONFIDENTIAL
    return SecurityLevel.RESTRICTED


def coerce_level(  # noqa: C901
    value: Any, *, conservative_default: Any = SecurityLevel.INTERNAL,
) -> SecurityLevel:
    """Coerce common level representations. Unknown markings are treated conservatively."""
    if value is None:
        return coerce_level(conservative_default)
    if isinstance(value, SecurityLevel):
        return value
    if isinstance(value, int):
        return _level_from_rank(value)
    for attr in ('level', 'security_level', 'classification_level', 'release_level', 'access_level'):
        if hasattr(value, attr):
            candidate = getattr(value, attr)
            if candidate is not value and candidate is not None:
                try:
                    return coerce_level(candidate, conservative_default=conservative_default)
                except (TypeError, ValueError):
                    pass
    if hasattr(value, 'classification') and not isinstance(value, str):
        candidate = getattr(value, 'classification')
        if isinstance(candidate, str):
            return coerce_level(candidate, conservative_default=conservative_default)
    token = _normalise_token(value)
    if token in _LEVEL_TEXT:
        return _level_from_rank(_LEVEL_TEXT[token])
    for key, rank in _LEVEL_TEXT.items():
        if key in token:
            return _level_from_rank(rank)
    return coerce_level(conservative_default)


_ATTRIBUTE_LEVEL_NAMES = (
    'release_level', 'approval_level', 'approved_level', 'authorized_level',
    'access_level', 'clearance_level', 'clearance', 'security_level',
    'classification_level', 'sensitivity_level', 'disclosure_level',
    'export_level', 'sensitivity', 'level', 'classification',
)
_ATTRIBUTE_FIELD_LEVEL_NAMES = (
    'field_levels', 'evidence_field_levels', 'security_field_levels',
    'field_classifications', 'security_labels', 'classification_labels',
    'labels', 'classifications',
)

_POLICY_OPTION_KEYS = {
    'policy', 'export_policy', 'classification_policy', 'redaction_policy',
    'outlet', 'audience', 'target', 'export_target',
    'level', 'export_level', 'access_level', 'release_level',
    'classification', 'classification_level', 'sensitivity', 'clearance',
    'reference_levels', 'component_levels', 'holder_levels',
    'field_levels', 'labels', 'default_field_level', 'unmarked_field_level',
    'default_reference_level',
}

_CURRENT_POLICY: 'ContextVar[Optional[ExportPolicy]]' = ContextVar(
    'cyclonedx_classification_policy', default=None)


def _normalise_token(value: Any) -> str:
    text = getattr(value, 'value', value)
    text = getattr(text, 'name', text) if not isinstance(text, str) else text
    text = str(text).strip()
    text = sub(r'([a-z0-9])([A-Z])', r'\1_\2', text)
    text = text.replace('-', '_').replace(' ', '_').replace('.', '_').replace(':', '_')
    return text.lower()


def _canonical_path(path: Any) -> str:
    text = _normalise_token(path)
    for prefix in ('component_evidence_', 'component_', 'evidence_', 'evidence'):
        if text.startswith(prefix + '_'):
            text = text[len(prefix) + 1:]
        elif text == prefix:
            text = ''
    replacements = {
        'identities': 'identity',
        'occurrence': 'occurrences',
        'methods_value': 'identity_methods_value',
    }
    text = replacements.get(text, text)
    text = text.strip('_')
    if text.startswith('occurrence_'):
        text = 'occurrences_' + text[len('occurrence_'):]
    elif text.startswith('identity_method_'):
        text = 'identity_methods_' + text[len('identity_method_'):]
    elif text.startswith('callstack_frame_'):
        text = 'callstack_frames_' + text[len('callstack_frame_'):]
    return text


def _outlet_clearance(outlet: Any, level: Any = None, clearance: Any = None) -> SecurityLevel:
    if clearance is not None:
        return coerce_level(clearance)
    if level is not None:
        return coerce_level(level)
    if outlet is None:
        return SecurityLevel.RESTRICTED
    token = _normalise_token(outlet)
    if token in ('public', 'external', 'partner', 'unclassified', 'clear'):
        return SecurityLevel.PUBLIC
    if token in ('internal', 'private', 'staff', 'official'):
        # The outlet permits internal material; a reference may still cap lower.
        return SecurityLevel.RESTRICTED
    return coerce_level(outlet)


class ExportPolicy:
    """Reference and field classification rules for one or more outlets."""

    def __init__(
        self,
        outlet: Any = None,
        *,
        level: Any = None,
        clearance: Any = None,
        audience: Any = None,
        target: Any = None,
        export_target: Any = None,
        export_level: Any = None,
        access_level: Any = None,
        release_level: Any = None,
        classification: Any = None,
        classification_level: Any = None,
        sensitivity: Any = None,
        reference_levels: Optional[Union[Mapping[Any, Any], Iterable[Tuple[Any, Any]]]] = None,
        component_levels: Optional[Union[Mapping[Any, Any], Iterable[Tuple[Any, Any]]]] = None,
        holder_levels: Optional[Union[Mapping[Any, Any], Iterable[Tuple[Any, Any]]]] = None,
        field_levels: Optional[Union[Mapping[Any, Any], Iterable[Tuple[Any, Any]]]] = None,
        labels: Optional[Any] = None,
        default_field_level: Any = SecurityLevel.INTERNAL,
        unmarked_field_level: Any = None,
        default_reference_level: Any = None,
        **_unused: Any,
    ) -> None:
        requested_outlet = outlet if outlet is not None else next(
            (v for v in (audience, target, export_target) if v is not None), None)
        requested_level = next(
            (v for v in (level, clearance, export_level, access_level, release_level,
                         classification, classification_level, sensitivity)
             if v is not None), None)
        self.outlet = requested_outlet
        self.outlet_level = _outlet_clearance(requested_outlet, requested_level)
        self.default_field_level = coerce_level(
            unmarked_field_level if unmarked_field_level is not None else default_field_level)
        if default_reference_level is None:
            self.default_reference_level = (
                SecurityLevel.PUBLIC if self.outlet_level <= SecurityLevel.PUBLIC else SecurityLevel.INTERNAL)
        else:
            self.default_reference_level = coerce_level(default_reference_level)

        self.reference_levels: Dict[str, SecurityLevel] = {}
        self._reference_objects: 'WeakKeyDictionary[Any, SecurityLevel]' = WeakKeyDictionary()
        self.field_levels: Dict[str, SecurityLevel] = {}
        self._object_levels: 'WeakKeyDictionary[Any, SecurityLevel]' = WeakKeyDictionary()
        self._object_field_levels: 'WeakKeyDictionary[Any, Dict[str, SecurityLevel]]' = WeakKeyDictionary()

        references = reference_levels if reference_levels is not None else next(
            (v for v in (component_levels, holder_levels) if v is not None), None)
        if references is not None:
            self._ingest_reference_mapping(references)
        if field_levels is not None:
            self._ingest_field_mapping(field_levels)
        if labels is not None:
            self._ingest_labels(labels)

    @classmethod
    def public(cls, **kwargs: Any) -> 'ExportPolicy':
        kwargs.setdefault('default_reference_level', SecurityLevel.PUBLIC)
        return cls(Outlet.PUBLIC, **kwargs)

    @classmethod
    def internal(cls, **kwargs: Any) -> 'ExportPolicy':
        return cls(Outlet.INTERNAL, **kwargs)

    @classmethod
    def full(cls) -> 'ExportPolicy':
        """A policy that retains every field at every reference."""
        return cls(SecurityLevel.RESTRICTED, default_field_level=SecurityLevel.PUBLIC,
                   default_reference_level=SecurityLevel.RESTRICTED)

    def copy(self) -> 'ExportPolicy':
        clone = ExportPolicy(
            self.outlet,
            clearance=self.outlet_level,
            default_field_level=self.default_field_level,
            default_reference_level=self.default_reference_level,
        )
        clone.reference_levels.update(self.reference_levels)
        clone.field_levels.update(self.field_levels)
        clone._reference_objects.update(dict(self._reference_objects.items()))
        clone._object_levels.update(dict(self._object_levels.items()))
        for obj, values in self._object_field_levels.items():
            clone._object_field_levels[obj] = dict(values)
        return clone

    def for_outlet(self, outlet: Any = None, *, level: Any = None, clearance: Any = None) -> 'ExportPolicy':
        clone = self.copy()
        clone.outlet = outlet
        clone.outlet_level = _outlet_clearance(outlet, level, clearance)
        return clone

    def with_level(self, level: Any) -> 'ExportPolicy':
        return self.for_outlet(level=level)

    def _ingest_reference_mapping(self, values: Any) -> None:
        items = values.items() if isinstance(values, Mapping) else values
        for reference, level in items:
            self.label_reference(reference, level)

    def _ingest_field_mapping(self, values: Any) -> None:
        items = values.items() if isinstance(values, Mapping) else values
        for path, level in items:
            self.label_field(path, level)

    def _ingest_labels(self, labels: Any) -> None:
        if isinstance(labels, Mapping):
            for target, value in labels.items():
                if isinstance(target, str):
                    self.label_field(target, value)
                elif isinstance(value, Mapping):
                    for field, level in value.items():
                        self.label_field(target, field, level)
                else:
                    self.label(target, value)
        elif isinstance(labels, Iterable):
            for item in labels:
                if isinstance(item, tuple) and len(item) in (2, 3):
                    self.label(*item)

    def label_reference(self, reference: Any, level: Any = None) -> 'ExportPolicy':  # noqa: C901
        if level is None and isinstance(reference, tuple):
            reference, level = reference
        required = coerce_level(level)
        if isinstance(reference, Component):
            self._reference_objects[reference] = required
            bom_ref = reference.bom_ref
            if bom_ref is not None and bom_ref.value:
                self.reference_levels[bom_ref.value] = required
            if reference.name:
                self.reference_levels.setdefault(reference.name, required)
        elif isinstance(reference, BomRef):
            if reference.value:
                self.reference_levels[reference.value] = required
        elif isinstance(reference, str):
            key = reference
            for prefix in ('components.', 'component.', '$.components.'):
                if key.startswith(prefix):
                    key = key[len(prefix):]
            if '[' in key and ']' in key:
                matched = sub(r".*bom[-_]ref\s*=\s*['\"]([^'\"]+)['\"].*", r'\1', key)
                if matched != key:
                    key = matched
            self.reference_levels[reference] = required
            self.reference_levels[key] = required
        else:
            self._reference_objects[reference] = required
        return self

    set_reference_level = label_reference
    label_component = label_reference

    def label_field(self, target: Any, field_or_level: Any = None, level: Any = None) -> 'ExportPolicy':
        if isinstance(target, str):
            path = _canonical_path(target)
            self.field_levels[path] = coerce_level(field_or_level)
            return self
        obj = target
        field = _canonical_path(field_or_level)
        required = coerce_level(level)
        values = self._object_field_levels.setdefault(obj, {})
        values[field] = required
        return self

    set_field_level = label_field

    def label(self, target: Any, level_or_field: Any = None, maybe_level: Any = None) -> 'ExportPolicy':
        if maybe_level is not None:
            return self.label_field(target, level_or_field, maybe_level)
        self._object_levels[target] = coerce_level(level_or_field)
        return self

    def classify(self, target: Any, *args: Any) -> 'ExportPolicy':
        if isinstance(target, str):
            return self.label_field(target, *args)
        if len(args) == 2:
            return self.label_field(target, args[0], args[1])
        return self.label(target, args[0] if args else SecurityLevel.INTERNAL)

    def reference_clearance(self, component: Component) -> SecurityLevel:
        level: Any = self._reference_objects.get(component)
        if level is None:
            bom_ref = getattr(component, 'bom_ref', None)
            ref_value = bom_ref.value if isinstance(bom_ref, BomRef) else bom_ref
            if ref_value:
                level = self.reference_levels.get(ref_value)
            if level is None and getattr(component, 'name', None):
                level = self.reference_levels.get(component.name)
        if level is None:
            level = _read_attribute_level(component)
        if level is None:
            level = _read_property_level(component)
        if level is None:
            level = self.default_reference_level
        return coerce_level(level)

    def effective_clearance(self, component: Component) -> SecurityLevel:
        outlet_level = coerce_level(self.outlet_level)
        reference_level = self.reference_clearance(component)
        return outlet_level if outlet_level.rank <= reference_level.rank else reference_level

    def required_field_level(self, path: str, *objects: Any) -> SecurityLevel:  # noqa: C901
        canonical = _canonical_path(path)
        explicit_levels = []

        if canonical in self.field_levels:
            explicit_levels.append(self.field_levels[canonical])
        parts = canonical.split('_') if canonical else []
        for index in range(len(parts) - 1, 0, -1):
            ancestor = '_'.join(parts[:index])
            if ancestor in self.field_levels:
                explicit_levels.append(self.field_levels[ancestor])

        leaf = parts[-1] if parts else ''
        for obj in objects:
            if obj is None:
                continue
            object_level = self._object_levels.get(obj)
            if object_level is None:
                object_level = _read_attribute_level(obj)
            if object_level is not None:
                explicit_levels.append(coerce_level(object_level))

            field_values = self._object_field_levels.get(obj)
            adhoc_values = _read_attribute_field_levels(obj)
            for values in (field_values, adhoc_values):
                if not values:
                    continue
                for key, value in values.items():
                    key_path = _canonical_path(key)
                    if (
                        key_path in (canonical, leaf)
                        or canonical.startswith(key_path + '_')
                        or canonical.endswith('_' + key_path)
                    ):
                        explicit_levels.append(coerce_level(value))

        if explicit_levels:
            return max(explicit_levels, key=lambda level: level.rank)
        return self.default_field_level

    def allows(self, path: str, clearance: Any, *objects: Any) -> bool:
        allowed = coerce_level(clearance)
        return self.required_field_level(path, *objects).rank <= allowed.rank

    can_see = allows


def _read_attribute_level(obj: Any) -> Optional[SecurityLevel]:
    for name in _ATTRIBUTE_LEVEL_NAMES:
        try:
            if not hasattr(obj, name):
                continue
            value = getattr(obj, name)
            if value is None or callable(value):
                continue
            return coerce_level(value)
        except Exception:  # pragma: no cover - defensive against model properties
            continue
    return None


def _read_attribute_field_levels(obj: Any) -> Dict[str, Any]:
    for name in _ATTRIBUTE_FIELD_LEVEL_NAMES:
        try:
            if not hasattr(obj, name):
                continue
            value = getattr(obj, name)
            if isinstance(value, dict):
                return value
        except Exception:  # pragma: no cover
            continue
    return {}


def _read_property_level(component: Any) -> Optional[SecurityLevel]:
    properties = getattr(component, 'properties', None)
    if not properties:
        return None
    known_tokens = (
        'release_level', 'approval_level', 'access_level', 'security_level',
        'classification_level', 'export_level', 'disclosure_level',
        'sensitivity_level', 'classification', 'clearance', 'sensitivity',
    )
    for prop in properties:
        name = _canonical_path(getattr(prop, 'name', ''))
        if name in known_tokens or name.endswith(('_release_level', '_classification', '_clearance')):
            value = getattr(prop, 'value', None)
            if value is not None:
                return coerce_level(value)
    return None


def coerce_policy(policy: Any = None, options: Optional[Mapping[str, Any]] = None) -> Optional[ExportPolicy]:
    options = dict(options or {})
    if policy is None and not any(key in options for key in _POLICY_OPTION_KEYS):
        current = _CURRENT_POLICY.get()
        return current
    if isinstance(policy, ExportPolicy):
        return policy
    if policy is None:
        policy_options = {k: v for k, v in options.items() if k in _POLICY_OPTION_KEYS and k != 'policy'}
        if not policy_options:
            return _CURRENT_POLICY.get()
        return ExportPolicy(**policy_options)
    if isinstance(policy, (str, int, Enum)):
        policy_options = {
            key: value for key, value in options.items()
            if key in _POLICY_OPTION_KEYS and key not in ('outlet', 'level')
        }
        return ExportPolicy(policy, **policy_options)
    if isinstance(policy, Mapping):
        return ExportPolicy(**policy)
    return ExportPolicy(policy, **{k: v for k, v in options.items() if k in _POLICY_OPTION_KEYS})


@contextmanager
def export_context(policy: Any = None, **options: Any) -> Iterator[ExportPolicy]:
    resolved = coerce_policy(policy, options)
    if resolved is None:
        resolved = ExportPolicy(**options)
    token = _CURRENT_POLICY.set(resolved)
    try:
        yield resolved
    finally:
        _CURRENT_POLICY.reset(token)


classification_context = export_context
leveled_export_context = export_context
classification_scope = export_context
export_scope = export_context
level_scope = export_context


def _all_components(bom: Bom) -> Iterator[Component]:
    metadata_component = getattr(getattr(bom, 'metadata', None), 'component', None)
    if metadata_component is not None:
        yield from metadata_component.iter_all_nested_components(include_self=True)
    for component in bom.components:
        yield from component.iter_all_nested_components(include_self=True)


def _filter_identity(  # noqa: C901
    identity: Identity,
    clearance: SecurityLevel,
    policy: ExportPolicy,
    root: Optional[ComponentEvidence] = None,
) -> Optional[Identity]:
    context = (root, identity)

    def allows(path: str, *objects: Any) -> bool:
        return policy.allows(path, clearance, *context, *objects)

    if not allows('identity'):
        return None
    if not allows('identity.field'):
        return None
    result = deepcopy(identity)
    if not allows('identity.confidence'):
        result.confidence = None
    if not allows('identity.concluded_value'):
        result.concluded_value = None

    methods = []
    for method in identity.methods:
        if not allows('identity.methods', method):
            continue
        if not allows('identity.methods.technique', method):
            continue
        if not allows('identity.methods.confidence', method):
            continue
        method_copy = deepcopy(method)
        if not allows('identity.methods.value', method):
            method_copy.value = None
        methods.append(method_copy)
    result.methods = methods

    if not allows('identity.tools'):
        result.tools = []
    return result


def _filter_occurrence(
    occurrence: Occurrence,
    clearance: SecurityLevel,
    policy: ExportPolicy,
    root: Optional[ComponentEvidence] = None,
) -> Optional[Occurrence]:
    context = (root, occurrence)

    def allows(path: str) -> bool:
        return policy.allows(path, clearance, *context)

    if not allows('occurrences'):
        return None
    # location is required by the model/schema; hiding it means hiding the item.
    if not allows('occurrences.location'):
        return None
    result = deepcopy(occurrence)
    optional_fields = ('line', 'offset', 'symbol', 'additional_context')
    for field_name in optional_fields:
        if not allows(f'occurrences.{field_name}'):
            setattr(result, field_name, None)
    if not allows('occurrences.bom_ref'):
        result._bom_ref = BomRef(None)
    return result


def _filter_callstack(
    callstack: CallStack,
    clearance: SecurityLevel,
    policy: ExportPolicy,
    root: Optional[ComponentEvidence] = None,
) -> Optional[CallStack]:
    if callstack is None or not policy.allows('callstack', clearance, root, callstack):
        return None
    frames = []
    for frame in callstack.frames:
        context = (root, callstack, frame)

        def allows(path: str) -> bool:
            return policy.allows(path, clearance, *context)

        if not allows('callstack.frames'):
            continue
        # module is required; hide the whole frame if it is not permitted.
        if not allows('callstack.frames.module'):
            continue
        frame_copy = deepcopy(frame)
        for field_name in ('package', 'function', 'line', 'column', 'full_filename'):
            if not allows(f'callstack.frames.{field_name}'):
                setattr(frame_copy, field_name, None)
        if not allows('callstack.frames.parameters'):
            frame_copy.parameters = []
        frames.append(frame_copy)
    if not frames:
        return None
    result = deepcopy(callstack)
    result.frames = frames
    return result


def _evidence_has_content(evidence: ComponentEvidence) -> bool:
    return bool(
        evidence.identity or evidence.occurrences or evidence.licenses or evidence.copyright
        or (evidence.callstack is not None and evidence.callstack.frames)
    )


def filter_evidence(
    evidence: Optional[ComponentEvidence],
    clearance: Any,
    policy: Optional[ExportPolicy] = None,
) -> Optional[ComponentEvidence]:
    """Return an independent, reference-specific evidence projection."""
    if evidence is None:
        return None
    active_policy = policy or ExportPolicy.full()
    allowed_level = coerce_level(clearance)
    evidence_object_level = active_policy._object_levels.get(evidence)
    if evidence_object_level is None:
        evidence_object_level = _read_attribute_level(evidence)
    if evidence_object_level is not None and coerce_level(evidence_object_level) > allowed_level:
        return None

    identities = []
    if active_policy.allows('identity', allowed_level, evidence):
        for identity in evidence.identity:
            projected_identity = _filter_identity(identity, allowed_level, active_policy, evidence)
            if projected_identity is not None:
                identities.append(projected_identity)

    occurrences = []
    if active_policy.allows('occurrences', allowed_level, evidence):
        for occurrence in evidence.occurrences:
            projected_occurrence = _filter_occurrence(occurrence, allowed_level, active_policy, evidence)
            if projected_occurrence is not None:
                occurrences.append(projected_occurrence)

    callstack = _filter_callstack(
        evidence.callstack, allowed_level, active_policy, evidence
    ) if active_policy.allows('callstack', allowed_level, evidence) else None

    licenses = [
        deepcopy(license_choice) for license_choice in evidence.licenses
        if active_policy.allows('licenses', allowed_level, evidence, license_choice)
    ] if active_policy.allows('licenses', allowed_level, evidence) else []

    copyrights = [
        deepcopy(copyright_item) for copyright_item in evidence.copyright
        if active_policy.allows('copyright', allowed_level, evidence, copyright_item)
    ] if active_policy.allows('copyright', allowed_level, evidence) else []

    projected_evidence = ComponentEvidence(
        identity=identities,
        occurrences=occurrences,
        callstack=callstack,
        licenses=licenses,
        copyright=copyrights,
    )
    return projected_evidence if _evidence_has_content(projected_evidence) else None


def project_bom(bom: Bom, policy: Any = None) -> Bom:
    """Create a detached BOM projection, applying rules separately at every component reference."""
    active_policy = coerce_policy(policy)
    if active_policy is None:
        return bom
    memo: Dict[int, Any] = {}
    projected_bom: Bom = deepcopy(bom, memo)
    for original_component in _all_components(bom):
        projected_component = memo.get(id(original_component))
        if not isinstance(projected_component, Component):
            continue
        if original_component.evidence is None:
            continue
        clearance = active_policy.effective_clearance(original_component)
        projected_component.evidence = filter_evidence(
            original_component.evidence, clearance, active_policy)
    return projected_bom


apply_export_policy = project_bom
redact_bom = project_bom


def _coerce_output_format(value: Any) -> OutputFormat:
    if isinstance(value, OutputFormat):
        return value
    token = _normalise_token(value)
    if token in ('json',):
        return OutputFormat.JSON
    if token in ('xml',):
        return OutputFormat.XML
    for member in OutputFormat:
        if _normalise_token(member) == token:
            return member
    raise ValueError(f'Unknown output format: {value!r}')


def _coerce_schema_version(value: Any) -> SchemaVersion:
    if isinstance(value, SchemaVersion):
        return value
    if value is None:
        return SchemaVersion.V1_7
    token = _normalise_token(value)
    aliases = {
        '1_0': SchemaVersion.V1_0,
        '1_1': SchemaVersion.V1_1,
        '1_2': SchemaVersion.V1_2,
        '1_3': SchemaVersion.V1_3,
        '1_4': SchemaVersion.V1_4,
        '1_5': SchemaVersion.V1_5,
        '1_6': SchemaVersion.V1_6,
        '1_7': SchemaVersion.V1_7,
    }
    if token in aliases:
        return aliases[token]
    for member in SchemaVersion:
        if _normalise_token(member) == token or member.to_version() == str(value):
            return member
    raise ValueError(f'Unknown schema version: {value!r}')


def _split_export_args(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    bom = kwargs.pop('bom', None)
    output_format = kwargs.pop('output_format', kwargs.pop('format', None))
    schema_version = kwargs.pop('schema_version', kwargs.pop('spec_version', kwargs.pop('version', None)))
    leftovers = []
    for arg in args:
        if isinstance(arg, Bom) and bom is None:
            bom = arg
        elif isinstance(arg, OutputFormat) or (isinstance(arg, str) and arg.lower() in ('json', 'xml')):
            output_format = arg
        elif isinstance(arg, SchemaVersion) or (isinstance(arg, (str, float)) and str(arg).startswith('1.')):
            schema_version = arg
        elif isinstance(arg, (ExportPolicy, SecurityLevel, str, int)) or arg is Outlet.PUBLIC:
            leftovers.append(arg)
    if leftovers and 'outlet' not in kwargs and 'policy' not in kwargs:
        if isinstance(leftovers[0], ExportPolicy):
            kwargs['policy'] = leftovers[0]
        else:
            kwargs['outlet'] = leftovers[0]
    return bom, output_format, schema_version


def export_bom(*args: Any, **kwargs: Any) -> str:
    """
    Render a leveled BOM without modifying the supplied BOM.

    Positional arguments may be supplied in any practical order: the Bom,
    format, schema version, and an outlet/level/policy are recognised by type.
    """
    bom, output_format, schema_version = _split_export_args(args, kwargs)
    if bom is None:
        raise TypeError('export_bom requires a Bom')
    policy = coerce_policy(kwargs.pop('policy', kwargs.pop('export_policy', None)), kwargs)
    output_format = _coerce_output_format(output_format or OutputFormat.JSON)
    schema_version = _coerce_schema_version(schema_version)

    from . import make_outputter
    outputter = make_outputter(bom, output_format, schema_version)
    return outputter.output_as_string(policy=policy, **kwargs)


export_to_string = export_bom
render_bom = export_bom
leveled_export = export_bom
classified_export = export_bom
classification_export = export_bom
export_with_policy = export_bom
export_with_levels = export_bom
to_leveled_string = export_bom
secure_export = export_bom
redacted_export = export_bom


def export_public_bom(*args: Any, **kwargs: Any) -> str:
    kwargs.setdefault('outlet', Outlet.PUBLIC)
    return export_bom(*args, **kwargs)


def export_internal_bom(*args: Any, **kwargs: Any) -> str:
    kwargs.setdefault('outlet', Outlet.INTERNAL)
    return export_bom(*args, **kwargs)


def make_leveled_outputter(*args: Any, **kwargs: Any) -> Any:
    bom, output_format, schema_version = _split_export_args(args, kwargs)
    if bom is None:
        raise TypeError('make_leveled_outputter requires a Bom')
    policy = coerce_policy(kwargs.pop('policy', kwargs.pop('export_policy', None)), kwargs)
    from . import make_outputter
    outputter = make_outputter(
        bom,
        _coerce_output_format(output_format or OutputFormat.JSON),
        _coerce_schema_version(schema_version),
    )
    outputter.set_export_policy(policy)
    return outputter


class LeveledExporter:
    """Small facade for repeated leveled JSON/XML exports of one BOM."""

    def __init__(
        self,
        bom: Bom,
        policy: Any = None,
        schema_version: SchemaVersion = SchemaVersion.V1_7,
        **policy_options: Any,
    ) -> None:
        self.bom = bom
        self.policy = coerce_policy(policy, policy_options) or ExportPolicy(**policy_options) \
            if policy_options else coerce_policy(policy)
        self.schema_version = _coerce_schema_version(schema_version)

    def _policy(self, outlet: Any = None, policy: Any = None, **options: Any) -> Optional[ExportPolicy]:
        if policy is not None:
            return coerce_policy(policy, options)
        if outlet is not None or options:
            base = self.policy.copy() if isinstance(self.policy, ExportPolicy) else ExportPolicy()
            return base.for_outlet(outlet, **options) if outlet is not None else coerce_policy(base, options)
        return self.policy

    def render(
        self,
        output_format: Any = OutputFormat.JSON,
        *,
        outlet: Any = None,
        policy: Any = None,
        **options: Any,
    ) -> str:
        indent = options.pop('indent', None)
        active_policy = self._policy(outlet=outlet, policy=policy, **options)
        return export_bom(
            self.bom,
            _coerce_output_format(output_format),
            self.schema_version,
            policy=active_policy,
            indent=indent,
        )

    def to_json(self, *, outlet: Any = None, policy: Any = None, **options: Any) -> str:
        return self.render(OutputFormat.JSON, outlet=outlet, policy=policy, **options)

    def to_xml(self, *, outlet: Any = None, policy: Any = None, **options: Any) -> str:
        return self.render(OutputFormat.XML, outlet=outlet, policy=policy, **options)

    def public_json(self, **options: Any) -> str:
        return self.to_json(outlet=Outlet.PUBLIC, **options)

    def internal_xml(self, **options: Any) -> str:
        return self.to_xml(outlet=Outlet.INTERNAL, **options)

    def public_xml(self, **options: Any) -> str:
        return self.to_xml(outlet=Outlet.PUBLIC, **options)

    def internal_json(self, **options: Any) -> str:
        return self.to_json(outlet=Outlet.INTERNAL, **options)


ClassificationExporter = LeveledExporter
EvidenceExporter = LeveledExporter
SecureBomExporter = LeveledExporter
RedactingExporter = LeveledExporter


EvidenceClassificationPolicy = ExportPolicy
EvidencePolicy = ExportPolicy
ReferencePolicy = ExportPolicy
ClassificationRules = ExportPolicy
ClassificationPolicy = ExportPolicy
LeveledExportPolicy = ExportPolicy
RedactionPolicy = ExportPolicy
DisclosurePolicy = ExportPolicy
AccessPolicy = ExportPolicy


__all__ = [
    'AccessPolicy',
    'AccessLevel',
    'Classification',
    'ClassificationExporter',
    'ClassificationLevel',
    'ClassificationPolicy',
    'ClassificationRules',
    'DisclosurePolicy',
    'EvidenceClassificationPolicy',
    'EvidenceExporter',
    'EvidencePolicy',
    'ExportLevel',
    'ExportOutlet',
    'ExportPolicy',
    'ExportTarget',
    'LeveledExportPolicy',
    'LeveledExporter',
    'Outlet',
    'RedactionPolicy',
    'ReferencePolicy',
    'ReleaseLevel',
    'SecurityLevel',
    'SensitivityLevel',
    'classification_context',
    'classification_scope',
    'classified_export',
    'coerce_level',
    'coerce_policy',
    'export_bom',
    'export_context',
    'export_scope',
    'export_to_string',
    'level_scope',
    'leveled_export',
    'make_leveled_outputter',
    'project_bom',
    'redact_bom',
    'redacted_export',
    'render_bom',
    'secure_export',
]
