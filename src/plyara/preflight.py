# Copyright 2025 plyara Maintainers
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
"""Offline namespace link preflight for YARA rule packages.

The preflight parses caller-supplied texts, never files referenced by
``include`` directives, and never downloads anything.  Rule identity is the
pair ``(namespace, rule name)``.  An unqualified dependency is resolved only
inside the namespace of the text that contains it.  A qualified dependency
such as ``other_namespace.rule_name`` is resolved only inside the named
namespace.

All report collections are sorted before they are returned.  Consequently,
swapping the order in which source packages are supplied produces an equal
report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable, Mapping

from plyara.core import Parser, Plyara

_EXTERNAL_TYPE_ALIASES = {
    'bool': 'boolean',
    'boolean': 'boolean',
    'double': 'float',
    'float': 'float',
    'int': 'integer',
    'integer': 'integer',
    'str': 'string',
    'string': 'string',
    'text': 'string',
}

_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_QUALIFIED_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$')
_NUMBER = re.compile(r'^(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[KMG]B)?)$')

# Tokens that cannot be a rule dependency on their own.
_PUNCTUATION = {
    '(', ')', '[', ']', '{', '}', ',', ':', '.', '..', ';', '?',
    '+', '-', '*', '/', '%', '&', '|', '^', '~', '<<', '>>',
    '==', '!=', '>', '<', '>=', '<=', '=', '!', '&&', '||',
}

_BUILTIN_CONDITION_NAMES = Parser.KEYWORDS | {'defined', 'for', 'of', 'in', 'at'}


def _digest(text: str) -> str:
    """Return the SHA-256 digest of UTF-8 text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _normalize_external_type(value: Any) -> str:
    """Normalize a caller-provided external variable type."""
    if value is None:
        return 'unknown'
    if not isinstance(value, str):
        raise TypeError('external variable type must be a string or None')
    normalized = _EXTERNAL_TYPE_ALIASES.get(value.strip().lower())
    if normalized is None:
        raise ValueError(
            'unsupported external variable type {!r}; expected one of '
            'integer, float, boolean, string'.format(value)
        )
    return normalized


@dataclass(frozen=True)
class SourceText:
    """A YARA text supplied by the caller together with its namespace.

    Args:
        namespace: Identity of the rule space containing this text.
        text: YARA source text.  It is parsed but never treated as a path.
        origin: Optional stable label for the source.  When omitted, a label
            derived from the namespace and the text digest is used.
        externals: External variables expected by this package, mapping name
            to one of ``integer``, ``float``, ``boolean``, or ``string``.
    """
    namespace: str
    text: str
    origin: str | None = None
    externals: Mapping[str, str] | tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self):
        """Validate the source and normalize optional fields."""
        if not isinstance(self.namespace, str) or not self.namespace:
            raise ValueError('namespace must be a non-empty string')
        if any(character.isspace() or character == '.' for character in self.namespace):
            raise ValueError('namespace must not contain whitespace or dots')
        if not isinstance(self.text, str):
            raise TypeError('text must be a string')

        items = self.externals.items() if isinstance(self.externals, Mapping) else self.externals
        normalized = set()
        for name, value_type in items:
            if not isinstance(name, str) or not _IDENTIFIER.match(name):
                raise ValueError('external variable name {!r} is not an identifier'.format(name))
            normalized.add((name, _normalize_external_type(value_type)))

        origin = self.origin
        if origin is None:
            origin = '{}@{}'.format(self.namespace, _digest(self.text)[:12])
        if not isinstance(origin, str) or not origin:
            raise ValueError('origin must be a non-empty string when provided')

        object.__setattr__(self, 'origin', origin)
        object.__setattr__(self, 'externals', tuple(sorted(normalized)))


@dataclass(frozen=True)
class SourceLocation:
    """A concrete location inside a caller-supplied text."""
    namespace: str
    origin: str
    source_sha256: str
    start_line: int | None = None
    stop_line: int | None = None


@dataclass(frozen=True)
class SourceRecord:
    """Summary of one parsed source text."""
    namespace: str
    origin: str
    source_sha256: str
    rule_count: int
    external_count: int
    include_count: int


@dataclass(frozen=True)
class RuleDefinition:
    """A rule definition bound to its namespace and source text."""
    namespace: str
    name: str
    is_private: bool
    is_global: bool
    location: SourceLocation
    condition: str
    condition_terms: tuple[str, ...]
    tags: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResolvedReference:
    """A dependency that resolved to exactly one definition or external."""
    namespace: str
    rule: str
    term: str
    term_index: int
    source: SourceLocation
    condition: str
    target_kind: str
    target_namespace: str | None
    target_name: str
    target_sources: tuple[SourceLocation, ...]
    target_conditions: tuple[str, ...] = ()


@dataclass(frozen=True)
class DuplicateDefinition:
    """The same rule name defined more than once inside one namespace."""
    namespace: str
    name: str
    definitions: tuple[RuleDefinition, ...]


@dataclass(frozen=True)
class MissingReference:
    """A dependency that has no definition in its binding namespace."""
    namespace: str
    rule: str
    term: str
    term_index: int
    expected_namespace: str
    source: SourceLocation
    condition: str
    definitions_elsewhere: tuple[RuleDefinition, ...] = ()


@dataclass(frozen=True)
class AmbiguousReference:
    """A dependency whose name has multiple definitions in its namespace."""
    namespace: str
    rule: str
    term: str
    term_index: int
    expected_namespace: str
    source: SourceLocation
    condition: str
    candidates: tuple[RuleDefinition, ...]


@dataclass(frozen=True)
class GatedRule:
    """A rule gated by a global rule in the same namespace."""
    name: str
    location: SourceLocation


@dataclass(frozen=True)
class GlobalGating:
    """A global rule and the rules it implicitly gates."""
    namespace: str
    global_rule: str
    source: SourceLocation
    gated_rules: tuple[GatedRule, ...]


@dataclass(frozen=True)
class ExternalDeclaration:
    """An external variable declaration supplied by one package."""
    name: str
    value_type: str
    location: SourceLocation


@dataclass(frozen=True)
class ExternalConflict:
    """A release-level conflict caused by an external variable."""
    kind: str
    name: str
    namespace: str | None
    declarations: tuple[ExternalDeclaration, ...]
    rules: tuple[RuleDefinition, ...] = ()
    message: str = ''


@dataclass(frozen=True)
class IncludeDirective:
    """An include directive that was recorded but deliberately not opened."""
    namespace: str
    origin: str
    target: str


@dataclass(frozen=True)
class ParseFailure:
    """A source text that Plyara could not parse."""
    namespace: str
    origin: str
    error_type: str
    message: str


def _rule_sort_key(rule: RuleDefinition):
    """Return the deterministic ordering key for a rule definition."""
    return (
        rule.namespace,
        rule.name,
        rule.location.origin,
        rule.location.start_line if rule.location.start_line is not None else -1,
        rule.location.stop_line if rule.location.stop_line is not None else -1,
        rule.condition,
    )


def _location_sort_key(location: SourceLocation):
    """Return the deterministic ordering key for a source location."""
    return (
        location.namespace,
        location.origin,
        location.start_line if location.start_line is not None else -1,
        location.stop_line if location.stop_line is not None else -1,
        location.source_sha256,
    )


def _coerce_source(value: Any) -> SourceText:
    """Accept SourceText, mappings, or short tuples as source input."""
    if isinstance(value, SourceText):
        return value
    if isinstance(value, Mapping):
        return SourceText(
            namespace=value['namespace'],
            text=value['text'],
            origin=value.get('origin'),
            externals=value.get('externals', ()),
        )
    if isinstance(value, (tuple, list)):
        if len(value) < 2:
            raise TypeError('source tuples need at least (namespace, text)')
        if len(value) > 4:
            raise TypeError('source tuples accept at most (namespace, text, origin, externals)')
        return SourceText(
            namespace=value[0],
            text=value[1],
            origin=value[2] if len(value) > 2 else None,
            externals=value[3] if len(value) > 3 else (),
        )
    raise TypeError('unsupported source value: {!r}'.format(type(value).__name__))


def _normalize_sources(sources: Iterable[Any] | Mapping[str, Any]) -> list[SourceText]:
    """Normalize supported source inputs into sorted SourceText objects."""
    if isinstance(sources, Mapping):
        raw_sources = list()
        for namespace, value in sources.items():
            if isinstance(value, str):
                raw_sources.append(SourceText(namespace=namespace, text=value, origin=namespace))
            elif isinstance(value, Mapping):
                specification = dict(value)
                specification.setdefault('namespace', namespace)
                raw_sources.append(_coerce_source(specification))
            else:
                raise TypeError(
                    'mapping sources must be text or source mappings, not {!r}'.format(
                        type(value).__name__
                    )
                )
    else:
        raw_sources = [_coerce_source(source) for source in sources]

    return sorted(
        raw_sources,
        key=lambda source: (
            source.namespace,
            source.origin,
            _digest(source.text),
            source.text,
        ),
    )


def _loop_variable_scopes(terms: tuple[str, ...] | list[str]):
    """Return for-loop variable declarations and the body spans they cover.

    Returns:
        tuple: ``(declarations, shadows)`` where ``declarations`` is a mapping
        of token index to variable name and ``shadows`` is a tuple of
        ``(start, end, name)`` body spans.
    """
    declarations = dict()
    shadows = list()
    for index, term in enumerate(terms):
        if term != 'for':
            continue

        depth = 0
        colon = None
        for cursor in range(index + 1, len(terms)):
            token = terms[cursor]
            if token == '(':
                depth += 1
            elif token == ')':
                if depth == 0:
                    break
                depth -= 1
            elif token == ':' and depth == 0:
                colon = cursor
                break

        if colon is None:
            continue

        variable = None
        depth = 0
        for cursor in range(index + 1, colon):
            token = terms[cursor]
            if token == '(':
                depth += 1
            elif token == ')':
                depth -= 1
            elif token == 'in' and depth == 0:
                candidate = terms[cursor - 1]
                if _IDENTIFIER.match(candidate) and candidate not in _BUILTIN_CONDITION_NAMES:
                    variable = candidate
                    declarations[cursor - 1] = candidate
                break

        if variable is None or colon + 1 >= len(terms) or terms[colon + 1] != '(':
            continue

        depth = 0
        for cursor in range(colon + 1, len(terms)):
            token = terms[cursor]
            if token == '(':
                depth += 1
            elif token == ')':
                depth -= 1
                if depth == 0:
                    shadows.append((colon + 1, cursor, variable))
                    break

    return declarations, tuple(shadows)


def _identifier_candidates(terms, known_namespaces, known_modules):
    """Yield dependency candidates from condition terms.

    Each candidate is a dict with the written term, its token index, the
    binding namespace, and the bare rule name.  Keywords, string identifiers,
    literals, function calls, module attributes, and for-loop variables are
    filtered out.
    """
    declarations, shadows = _loop_variable_scopes(terms)

    def shadowed(index, name):
        """Return whether a token is shadowed by a surrounding loop variable."""
        return any(start <= index <= end and name == variable for start, end, variable in shadows)

    for index, term in enumerate(terms):
        if not isinstance(term, str):
            continue
        if index in declarations:
            continue
        if index > 0 and terms[index - 1] == '.':
            # A member name after a dot is part of a module or attribute
            # expression such as ``pe.sections[0].name``.
            continue
        if term in _PUNCTUATION or term in _BUILTIN_CONDITION_NAMES:
            continue
        if term.startswith(('$', '#', '@', '!')):
            continue
        if term.startswith(('"', "'", '/')):
            continue
        if _NUMBER.match(term):
            continue

        next_term = terms[index + 1] if index + 1 < len(terms) else None
        if next_term == '(':
            # A bare or qualified identifier followed by an argument list is
            # a function or a built-in, never a rule dependency.
            continue

        if _QUALIFIED_IDENTIFIER.match(term):
            parts = term.split('.')
            if len(parts) != 2:
                # Nested attribute access such as ``pe.sections[0].name`` is
                # a module expression, not a rule namespace reference.
                continue
            prefix, name = parts
            if prefix in known_modules and prefix not in known_namespaces:
                # A module (``pe``, ``math``, ...) is not a rule space.
                continue
            if shadowed(index, name):
                continue
            yield {
                'term': term,
                'term_index': index,
                'target_namespace': prefix,
                'name': name,
                'qualified': True,
            }
            continue

        if not _IDENTIFIER.match(term):
            continue
        if shadowed(index, term):
            continue
        yield {
            'term': term,
            'term_index': index,
            'target_namespace': None,
            'name': term,
            'qualified': False,
        }


def _external_declarations_for(source: SourceText, source_location: SourceLocation):
    """Convert a package's external declarations into report records."""
    declarations = list()
    for name, value_type in source.externals:
        declarations.append(ExternalDeclaration(
            name=name,
            value_type=value_type,
            location=SourceLocation(
                namespace=source_location.namespace,
                origin=source_location.origin,
                source_sha256=source_location.source_sha256,
            ),
        ))
    return declarations


def _build_duplicates(rules_by_key):
    """Build duplicate-definition findings for every namespace."""
    duplicates = list()
    for (namespace, name), definitions in rules_by_key.items():
        if len(definitions) > 1:
            ordered = tuple(sorted(definitions, key=_rule_sort_key))
            duplicates.append(DuplicateDefinition(
                namespace=namespace,
                name=name,
                definitions=ordered,
            ))
    return tuple(sorted(duplicates, key=lambda item: (item.namespace, item.name)))


def _build_global_gating(rules):
    """Build namespace-local global gating findings."""
    by_namespace = defaultdict(list)
    for rule in rules:
        by_namespace[rule.namespace].append(rule)

    records = list()
    for namespace in sorted(by_namespace):
        namespace_rules = sorted(by_namespace[namespace], key=_rule_sort_key)
        for index, global_rule in enumerate(namespace_rules):
            if not global_rule.is_global:
                continue
            gated = tuple(
                GatedRule(name=other.name, location=other.location)
                for other_index, other in enumerate(namespace_rules)
                if other_index != index
            )
            records.append(GlobalGating(
                namespace=namespace,
                global_rule=global_rule.name,
                source=global_rule.location,
                gated_rules=gated,
            ))

    return tuple(sorted(
        records,
        key=lambda item: (
            item.namespace,
            item.global_rule,
            _location_sort_key(item.source),
            tuple((gated.name, _location_sort_key(gated.location)) for gated in item.gated_rules),
        ),
    ))


def _build_external_conflicts(external_declarations, rules_by_key):
    """Build external type conflicts and rule-name collisions."""
    by_name = defaultdict(list)
    for declaration in external_declarations:
        by_name[declaration.name].append(declaration)

    conflicts = list()
    known_namespaces = sorted({namespace for namespace, _ in rules_by_key})

    for name in sorted(by_name):
        declarations = tuple(sorted(
            by_name[name],
            key=lambda item: (item.name, item.value_type, _location_sort_key(item.location)),
        ))
        known_types = sorted({item.value_type for item in declarations if item.value_type != 'unknown'})
        if len(known_types) > 1:
            conflicts.append(ExternalConflict(
                kind='type_mismatch',
                name=name,
                namespace=None,
                declarations=declarations,
                message='external variable {!r} is declared with conflicting types: {}'.format(
                    name, ', '.join(known_types)
                ),
            ))

        for namespace in known_namespaces:
            definitions = rules_by_key.get((namespace, name), ())
            if not definitions:
                continue
            ordered_rules = tuple(sorted(definitions, key=_rule_sort_key))
            conflicts.append(ExternalConflict(
                kind='rule_name_shadow',
                name=name,
                namespace=namespace,
                declarations=declarations,
                rules=ordered_rules,
                message=(
                    'external variable {!r} has the same name as rule definitions '
                    'in namespace {!r}'.format(name, namespace)
                ),
            ))

    return tuple(sorted(
        conflicts,
        key=lambda item: (
            item.kind,
            item.name,
            item.namespace or '',
            tuple((declaration.value_type, _location_sort_key(declaration.location))
                  for declaration in item.declarations),
            tuple(_rule_sort_key(rule) for rule in item.rules),
        ),
    ))


def preflight(sources, externals: Mapping[str, str] | None = None) -> 'PreflightReport':
    """Run an offline namespace link preflight over caller-supplied texts.

    Args:
        sources: Iterable of ``SourceText`` objects, mappings with
            ``namespace`` and ``text`` keys, ``(namespace, text[, origin[,
            externals]])`` tuples, or a mapping of namespace to text.
        externals: Optional release-wide external declarations.  Prefer
            declaring externals on each ``SourceText`` so every declaration
            has a concrete source text.

    Returns:
        PreflightReport: Deterministically ordered findings.

    Raises:
        TypeError: If a source has an unsupported shape.
        ValueError: If a namespace, external name, or external type is invalid.
    """
    normalized_sources = _normalize_sources(sources)

    source_records = list()
    all_rules = list()
    external_declarations = list()
    include_directives = list()
    parse_failures = list()
    seen_includes = set()

    for source in normalized_sources:
        source_digest = _digest(source.text)
        source_location = SourceLocation(
            namespace=source.namespace,
            origin=source.origin,
            source_sha256=source_digest,
        )

        parser = Plyara()
        try:
            parsed_rules = parser.parse_string(source.text)
        except Exception as error:  # noqa: BLE001 - a bad package must not stop the preflight
            parse_failures.append(ParseFailure(
                namespace=source.namespace,
                origin=source.origin,
                error_type=type(error).__name__,
                message=str(error),
            ))
            parsed_rules = []

        for include_target in parser.includes:
            include_key = (source.namespace, source.origin, include_target)
            if include_key in seen_includes:
                continue
            seen_includes.add(include_key)
            include_directives.append(IncludeDirective(
                namespace=source.namespace,
                origin=source.origin,
                target=include_target,
            ))

        for parsed_rule in parsed_rules:
            scopes = set(parsed_rule.get('scopes', ()))
            definition = RuleDefinition(
                namespace=source.namespace,
                name=parsed_rule['rule_name'],
                is_private='private' in scopes,
                is_global='global' in scopes,
                location=SourceLocation(
                    namespace=source.namespace,
                    origin=source.origin,
                    source_sha256=source_digest,
                    start_line=parsed_rule.get('start_line'),
                    stop_line=parsed_rule.get('stop_line'),
                ),
                condition=str(parsed_rule.get('raw_condition', '')).strip(),
                condition_terms=tuple(parsed_rule.get('condition_terms', ())),
                tags=tuple(sorted(parsed_rule.get('tags', ()))),
                imports=tuple(sorted(set(parsed_rule.get('imports', ())))),
            )
            all_rules.append(definition)

        external_declarations.extend(
            _external_declarations_for(source, source_location)
        )

        source_records.append(SourceRecord(
            namespace=source.namespace,
            origin=source.origin,
            source_sha256=source_digest,
            rule_count=len(parsed_rules),
            external_count=len(source.externals),
            include_count=sum(
                1 for include in include_directives
                if include.namespace == source.namespace and include.origin == source.origin
            ),
        ))

    if externals:
        for name, value_type in sorted(externals.items()):
            if not isinstance(name, str) or not _IDENTIFIER.match(name):
                raise ValueError('external variable name {!r} is not an identifier'.format(name))
            external_declarations.append(ExternalDeclaration(
                name=name,
                value_type=_normalize_external_type(value_type),
                location=SourceLocation(
                    namespace='<caller>',
                    origin='<caller>',
                    source_sha256='',
                ),
            ))

    all_rules = sorted(all_rules, key=_rule_sort_key)
    rules_by_key = defaultdict(list)
    for rule in all_rules:
        rules_by_key[(rule.namespace, rule.name)].append(rule)
    rules_by_key = dict(rules_by_key)

    external_by_name = defaultdict(list)
    for declaration in external_declarations:
        external_by_name[declaration.name].append(declaration)

    known_namespaces = {source.namespace for source in normalized_sources}
    known_modules = set(Parser.IMPORT_OPTIONS)
    for rule in all_rules:
        known_modules.update(rule.imports)

    references = list()
    missing_references = list()
    ambiguous_references = list()

    for rule in all_rules:
        for candidate in _identifier_candidates(rule.condition_terms, known_namespaces, known_modules):
            expected_namespace = candidate['target_namespace'] or rule.namespace
            definitions = rules_by_key.get((expected_namespace, candidate['name']), [])

            if len(definitions) == 1:
                target = definitions[0]
                references.append(ResolvedReference(
                    namespace=rule.namespace,
                    rule=rule.name,
                    term=candidate['term'],
                    term_index=candidate['term_index'],
                    source=rule.location,
                    condition=rule.condition,
                    target_kind='rule',
                    target_namespace=target.namespace,
                    target_name=target.name,
                    target_sources=(target.location,),
                    target_conditions=(target.condition,),
                ))
                continue

            if len(definitions) > 1:
                ambiguous_references.append(AmbiguousReference(
                    namespace=rule.namespace,
                    rule=rule.name,
                    term=candidate['term'],
                    term_index=candidate['term_index'],
                    expected_namespace=expected_namespace,
                    source=rule.location,
                    condition=rule.condition,
                    candidates=tuple(sorted(definitions, key=_rule_sort_key)),
                ))
                continue

            # Externals are release-wide in YARA.  A bare name may bind to one
            # only when no rule definition owns that name in this namespace.
            if not candidate['qualified'] and candidate['name'] in external_by_name:
                declarations = tuple(sorted(
                    external_by_name[candidate['name']],
                    key=lambda item: (item.name, item.value_type, _location_sort_key(item.location)),
                ))
                references.append(ResolvedReference(
                    namespace=rule.namespace,
                    rule=rule.name,
                    term=candidate['term'],
                    term_index=candidate['term_index'],
                    source=rule.location,
                    condition=rule.condition,
                    target_kind='external',
                    target_namespace=None,
                    target_name=candidate['name'],
                    target_sources=tuple(item.location for item in declarations),
                    target_conditions=(),
                ))
                continue

            elsewhere = tuple(sorted(
                (
                    definition
                    for definition in all_rules
                    if definition.name == candidate['name'] and definition.namespace != expected_namespace
                ),
                key=_rule_sort_key,
            ))
            missing_references.append(MissingReference(
                namespace=rule.namespace,
                rule=rule.name,
                term=candidate['term'],
                term_index=candidate['term_index'],
                expected_namespace=expected_namespace,
                source=rule.location,
                condition=rule.condition,
                definitions_elsewhere=elsewhere,
            ))

    references = tuple(sorted(
        references,
        key=lambda item: (
            item.namespace,
            item.rule,
            item.term_index,
            item.term,
            item.target_kind,
            item.target_namespace or '',
            item.target_name,
            _location_sort_key(item.source),
        ),
    ))
    missing_references = tuple(sorted(
        missing_references,
        key=lambda item: (
            item.namespace,
            item.rule,
            item.term_index,
            item.term,
            item.expected_namespace,
            _location_sort_key(item.source),
            tuple(_rule_sort_key(definition) for definition in item.definitions_elsewhere),
        ),
    ))
    ambiguous_references = tuple(sorted(
        ambiguous_references,
        key=lambda item: (
            item.namespace,
            item.rule,
            item.term_index,
            item.term,
            item.expected_namespace,
            _location_sort_key(item.source),
            tuple(_rule_sort_key(definition) for definition in item.candidates),
        ),
    ))

    duplicate_definitions = _build_duplicates(rules_by_key)
    global_gating = _build_global_gating(all_rules)
    external_conflicts = _build_external_conflicts(external_declarations, rules_by_key)

    return PreflightReport(
        sources=tuple(sorted(
            source_records,
            key=lambda item: (item.namespace, item.origin, item.source_sha256),
        )),
        rules=tuple(all_rules),
        references=references,
        duplicate_definitions=duplicate_definitions,
        missing_references=missing_references,
        ambiguous_references=ambiguous_references,
        global_gating=global_gating,
        external_declarations=tuple(sorted(
            external_declarations,
            key=lambda item: (item.name, item.value_type, _location_sort_key(item.location)),
        )),
        external_conflicts=external_conflicts,
        includes=tuple(sorted(
            include_directives,
            key=lambda item: (item.namespace, item.origin, item.target),
        )),
        parse_failures=tuple(sorted(
            parse_failures,
            key=lambda item: (item.namespace, item.origin, item.error_type, item.message),
        )),
    )


def _json_ready(value):
    """Convert dataclasses and tuples into JSON-friendly values."""
    if is_dataclass(value):
        return {key: _json_ready(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    return value


@dataclass(frozen=True)
class PreflightReport:
    """Deterministic result of an offline namespace link preflight."""
    sources: tuple[SourceRecord, ...]
    rules: tuple[RuleDefinition, ...]
    references: tuple[ResolvedReference, ...]
    duplicate_definitions: tuple[DuplicateDefinition, ...]
    missing_references: tuple[MissingReference, ...]
    ambiguous_references: tuple[AmbiguousReference, ...]
    global_gating: tuple[GlobalGating, ...]
    external_declarations: tuple[ExternalDeclaration, ...]
    external_conflicts: tuple[ExternalConflict, ...]
    includes: tuple[IncludeDirective, ...]
    parse_failures: tuple[ParseFailure, ...]

    @property
    def duplicates(self):
        """Alias for duplicate_definitions."""
        return self.duplicate_definitions

    @property
    def missing(self):
        """Alias for missing_references."""
        return self.missing_references

    @property
    def ambiguous(self):
        """Alias for ambiguous_references."""
        return self.ambiguous_references

    @property
    def ok(self):
        """Report whether the release has no link, duplicate, parse, or external errors."""
        return not (
            self.duplicate_definitions
            or self.missing_references
            or self.ambiguous_references
            or self.external_conflicts
            or self.parse_failures
        )

    def summary(self):
        """Return a compact count summary."""
        return {
            'rules': len(self.rules),
            'references': len(self.references),
            'duplicate_definition_groups': len(self.duplicate_definitions),
            'missing_references': len(self.missing_references),
            'ambiguous_references': len(self.ambiguous_references),
            'global_gating_records': len(self.global_gating),
            'external_conflicts': len(self.external_conflicts),
            'includes_not_opened': len(self.includes),
            'parse_failures': len(self.parse_failures),
        }

    def to_dict(self):
        """Return a deterministic, JSON-friendly dictionary."""
        return {
            'schema_version': 1,
            'ok': self.ok,
            'summary': self.summary(),
            'sources': _json_ready(self.sources),
            'rules': _json_ready(self.rules),
            'references': _json_ready(self.references),
            'duplicate_definitions': _json_ready(self.duplicate_definitions),
            'missing_references': _json_ready(self.missing_references),
            'ambiguous_references': _json_ready(self.ambiguous_references),
            'global_gating': _json_ready(self.global_gating),
            'external_declarations': _json_ready(self.external_declarations),
            'external_conflicts': _json_ready(self.external_conflicts),
            'includes': _json_ready(self.includes),
            'parse_failures': _json_ready(self.parse_failures),
        }

    def to_json(self):
        """Return the report as sorted, indented JSON."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, ensure_ascii=False)


def _sources_from_payload(payload):
    """Extract source specifications from a CLI manifest."""
    if isinstance(payload, Mapping):
        if 'sources' in payload:
            payload = payload['sources']
        elif 'packages' in payload:
            payload = payload['packages']
        else:
            raise ValueError("manifest must contain a 'sources' or 'packages' list")
    if not isinstance(payload, list):
        raise ValueError('manifest sources must be a list')
    return [_coerce_source(entry) for entry in payload]


def main(argv=None):
    """Run the offline preflight command line interface."""
    parser = argparse.ArgumentParser(
        prog='plyara-preflight',
        description='Offline namespace link preflight for YARA rule packages.',
    )
    parser.add_argument(
        'manifest',
        nargs='?',
        default='-',
        help="JSON manifest path, or '-' to read standard input (default: -).",
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Exit with status 1 when the preflight reports errors.',
    )
    args = parser.parse_args(argv)

    try:
        if args.manifest == '-':
            raw_manifest = sys.stdin.read()
        else:
            raw_manifest = pathlib.Path(args.manifest).read_text(encoding='utf-8')
        payload = json.loads(raw_manifest)
        sources = _sources_from_payload(payload)
        report = preflight(sources)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        parser.error(str(error))

    print(report.to_json())
    return 1 if args.check and not report.ok else 0


if __name__ == '__main__':
    sys.exit(main())
