"""
Data classification for validated instances.

JSON Schema validates instances, but it has no notion of a
:dfn:`data classification` -- the sensitivity level which an audit or
compliance process attaches to an individual field.  This module adds a
small, explicit collection layer on top of validation:

* any subschema may carry a classification keyword, for example
  ``{"x-classification": "confidential"}``;
* only branches which actually take effect for the instance contribute
  levels (the successful side of ``if``/``then``/``else``, the matching
  ``anyOf``/``oneOf`` alternatives, resolved references, and so on);
* when several effective definitions disagree, the strictest one wins;
* a field with no effective definition is reported explicitly as
  ``"unknown"`` rather than being silently omitted.

The result is a JSON-serializable document intended to be consumed by a
downstream compliance system.  If the instance is invalid, no official
classification is produced at all -- the classification view is
``"withheld"`` and any observations which might otherwise have applied
are confined to a diagnostic section, clearly marked as unapproved.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import referencing
import referencing.exceptions
import referencing.jsonschema
from attrs import define, field, frozen

from jsonschema import _utils, exceptions, validators

__all__ = [
    "DEFAULT_KEYWORDS",
    "DEFAULT_LEVELS",
    "UNKNOWN",
    "ClassificationConfigurationError",
    "ClassificationConflict",
    "ClassificationEntry",
    "ClassificationPolicy",
    "ClassificationResult",
    "ClassificationSource",
    "UnknownLevelError",
    "classify",
]

#: The format identifier for the emitted compliance document.
FORMAT = "jsonschema-classification/v1"

#: The level name used when a field has no effective classification.
UNKNOWN = "unknown"

#: Levels understood by default, ordered from least to most sensitive.
DEFAULT_LEVELS = ("public", "internal", "confidential", "restricted")

#: Classification keywords recognized by default.
DEFAULT_KEYWORDS = (
    "x-classification",
    "x-dataClassification",
    "x-data-classification",
)


class ClassificationConfigurationError(ValueError):
    """A schema's classification configuration is not usable."""

    def __init__(self, message: str, *, path: str | None = None):
        super().__init__(message)
        self.message = message
        self.path = path

    def __str__(self) -> str:
        if self.path is None:
            return self.message
        return f"{self.message} (at {self.path})"


class UnknownLevelError(ClassificationConfigurationError):
    """A configured classification level is not part of the policy."""

    def __init__(self, message: str, *, path: str | None = None, level=None):
        super().__init__(message, path=path)
        self.level = level


def _pointer(path: Iterable[str | int]) -> str:
    """Render a JSON Pointer for a sequence of path components."""
    return "".join(
        "/" + str(part).replace("~", "~0").replace("/", "~1") for part in path
    )


def _json_path(path: Iterable[str | int]) -> str:
    """Render a JSONPath-like expression for a sequence of components."""
    json_path = "$"
    for part in path:
        if isinstance(part, int):
            json_path += f"[{part}]"
        elif part.isidentifier():
            json_path += f".{part}"
        else:
            escaped = str(part).replace("\\", "\\\\").replace("'", r"\'")
            json_path += f"['{escaped}']"
    return json_path


@frozen
class ClassificationPolicy:
    """
    The ordered levels and keywords used while collecting classifications.

    Arguments:

        levels:

            Level names ordered from least to most sensitive.  The last
            level is the strictest.  A mapping of level name to rank is
            also accepted.

        keywords:

            Classification keyword names to recognize.  If more than one
            is provided, any of them may be used in a schema.

        unknown:

            The name used to explicitly represent an unconfigured field.
    """

    levels: tuple[str, ...] = DEFAULT_LEVELS
    keywords: tuple[str, ...] = DEFAULT_KEYWORDS
    unknown: str = UNKNOWN

    def __attrs_post_init__(self):
        levels = self.levels
        if isinstance(levels, Mapping):
            levels = tuple(
                sorted(levels, key=lambda each: (levels[each], each)),
            )
        levels = tuple(levels)
        if not levels:
            raise ClassificationConfigurationError(
                "At least one classification level is required.",
            )
        if len(set(levels)) != len(levels):
            raise ClassificationConfigurationError(
                f"Duplicate classification levels: {levels!r}",
            )
        if self.unknown in levels:
            raise ClassificationConfigurationError(
                f"{self.unknown!r} cannot be used as a configured level.",
            )

        keywords = self.keywords
        if isinstance(keywords, str):
            keywords = (keywords,)
        keywords = tuple(keywords)
        if not keywords or not all(keywords):
            raise ClassificationConfigurationError(
                "At least one classification keyword is required.",
            )

        object.__setattr__(self, "levels", levels)
        object.__setattr__(self, "keywords", keywords)

    def rank(self, level: str) -> int:
        """Return the strictness rank of ``level``."""
        try:
            return self.levels.index(level)
        except ValueError:
            raise UnknownLevelError(
                f"Unknown classification level {level!r}; configured "
                f"levels are {list(self.levels)!r}.",
            ) from None

    def strictest(self, levels: Iterable[str]) -> str:
        """Return the strictest of the given known ``levels``."""
        return max(levels, key=self.rank)


@frozen
class ClassificationSource:
    """One effective (or explicitly rejected) definition of a level."""

    level: str | None
    keyword: str | None
    schema_path: str
    path: tuple[str | int, ...] = ()
    ref: str | None = None
    resolved_uri: str | None = None
    schema_uri: str | None = None
    effective: bool = True
    reason: str | None = None

    @property
    def configured(self) -> bool:
        return self.level is not None

    @property
    def instance_path(self) -> str:
        return _pointer(self.path)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "instance_path": self.instance_path,
            "json_path": _json_path(self.path),
            "level": self.level,
            "configured": self.configured,
            "effective": self.effective,
        }
        if self.keyword is not None:
            result["keyword"] = self.keyword
        if self.schema_path:
            result["schema_path"] = self.schema_path
        if self.schema_uri is not None:
            result["schema_uri"] = self.schema_uri
        if self.ref is not None:
            result["ref"] = self.ref
        if self.resolved_uri is not None:
            result["resolved_uri"] = self.resolved_uri
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@frozen
class ClassificationEntry:
    """The approved classification of one instance location."""

    path: tuple[str | int, ...]
    level: str
    known: bool
    sources: tuple[ClassificationSource, ...]

    @property
    def instance_path(self) -> str:
        return _pointer(self.path)

    @property
    def json_path(self) -> str:
        return _json_path(self.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_path": self.instance_path,
            "json_path": self.json_path,
            "level": self.level,
            "known": self.known,
            "status": "classified" if self.known else "unconfigured",
            "sources": [source.to_dict() for source in self.sources],
        }


@frozen
class ClassificationConflict:
    """Several effective definitions gave one location different levels."""

    path: tuple[str | int, ...]
    levels: tuple[str, ...]
    selected: str
    sources: tuple[ClassificationSource, ...]

    @property
    def instance_path(self) -> str:
        return _pointer(self.path)

    @property
    def json_path(self) -> str:
        return _json_path(self.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_path": self.instance_path,
            "json_path": self.json_path,
            "levels": list(self.levels),
            "selected": self.selected,
            "resolution": "strictest",
            "sources": [source.to_dict() for source in self.sources],
        }


@frozen
class ClassificationResult:
    """The combined validation and classification outcome."""

    valid: bool
    status: str
    errors: tuple[exceptions.ValidationError, ...]
    entries: tuple[ClassificationEntry, ...]
    conflicts: tuple[ClassificationConflict, ...]
    rejected: tuple[ClassificationSource, ...]
    policy: ClassificationPolicy
    schema_id: str | None = None
    reason: str | None = None

    @property
    def approved(self) -> tuple[ClassificationEntry, ...]:
        """The approved entries, or an empty tuple when withheld."""
        return self.entries if self.status == "approved" else ()

    @staticmethod
    def _error_dict(error: exceptions.ValidationError) -> dict[str, Any]:
        return {
            "instance_path": _pointer(error.absolute_path),
            "json_path": error.json_path,
            "message": error.message,
            "validator": error.validator,
            "schema_path": _pointer(error.absolute_schema_path),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable compliance document."""
        approved = self.status == "approved"
        known = [entry for entry in self.approved if entry.known]
        groups = OrderedDict()
        for entry in known:
            if entry.path:
                top = entry.path[0]
                current = groups.get(top)
                if current is None or self.policy.rank(
                    entry.level,
                ) > self.policy.rank(current):
                    groups[top] = entry.level
        by_top_level = {str(top): level for top, level in groups.items()}
        if self.approved:
            highest = (
                self.policy.strictest(entry.level for entry in known)
                if known
                else self.policy.unknown
            )
        else:
            highest = None
        classification: dict[str, Any] = {
            "status": self.status,
            "approved": approved,
            "policy": {
                "keywords": list(self.policy.keywords),
                "levels": list(self.policy.levels),
                "unknown": self.policy.unknown,
            },
            "fields": [entry.to_dict() for entry in self.approved],
            "conflicts": (
                [conflict.to_dict() for conflict in self.conflicts]
                if approved
                else []
            ),
            "summary": {
                "field_count": len(self.approved),
                "classified_count": len(known) if approved else 0,
                "unknown_count": (
                    len(self.approved) - len(known) if approved else 0
                ),
                "conflict_count": len(self.conflicts) if approved else 0,
                "highest_level": highest,
                "highest_level_by_root": by_top_level,
            },
        }
        if self.reason is not None:
            classification["reason"] = self.reason

        diagnostics: dict[str, Any] = {"branch_count": len(self.rejected)}
        if approved:
            diagnostics["rejected_branches"] = [
                source.to_dict() for source in self.rejected
            ]
        else:
            diagnostics["unapproved_observations"] = [
                source.to_dict() for source in self.rejected
            ]

        return {
            "format": FORMAT,
            "schema_id": self.schema_id,
            "valid": self.valid,
            "validation": {
                "valid": self.valid,
                "errors": [self._error_dict(error) for error in self.errors],
            },
            "classification": classification,
            "diagnostics": diagnostics,
        }


@define
class _Definition:
    level: str
    keyword: str
    schema_path: str
    ref: str | None
    resolved_uri: str | None
    schema_uri: str | None


@define
class _Node:
    path: tuple[str | int, ...]
    definitions: list[_Definition] = field(factory=list)


_SPECIFICATIONS: dict[type, referencing.jsonschema.Specification] = {}


def _specification(validator):
    signature = type(validator)
    specification = _SPECIFICATIONS.get(signature)
    if specification is None:
        specification = referencing.jsonschema.specification_with(
            dialect_id=validator.ID_OF(validator.META_SCHEMA),
            default=referencing.Specification.OPAQUE,
        )
        _SPECIFICATIONS[signature] = specification
    return specification


def _applicable(validator, schema) -> list[tuple[str, Any]]:
    """The keywords applicable to ``schema`` for this validator's draft."""
    return list(type(validator)._APPLICABLE_VALIDATORS(schema))


def _extract_level(
    value: Any, policy: ClassificationPolicy, where: str
) -> str:
    if isinstance(value, Mapping):
        value = value.get("level")
    if not isinstance(value, str):
        raise ClassificationConfigurationError(
            f"Classification at {where} must be a level name, got {value!r}.",
        )
    policy.rank(value)
    return value


def _matches(pattern, name) -> bool:
    import re

    return re.search(pattern, name) is not None


def _value_at(instance, path):
    value = instance
    for part in path:
        try:
            value = value[part]
        except (KeyError, IndexError, TypeError):
            return _MISSING
    return value


_MISSING = object()


def _is_container(value) -> bool:
    return isinstance(value, (Mapping, list, tuple))


class _Collector:
    def __init__(self, validator, policy: ClassificationPolicy, instance):
        self.validator = validator
        self.policy = policy
        self.instance = instance
        self.nodes: OrderedDict[tuple, _Node] = OrderedDict()
        self.rejected: list[ClassificationSource] = []
        self._visited: set[tuple] = set()
        self._scanned: set[tuple] = set()
        self._rejected_seen: set[tuple] = set()
        self._specification = _specification(validator)

    def _lookup(self, validator, ref):
        try:
            return validator._resolver.lookup(ref)
        except referencing.exceptions.Unresolvable:
            return None

    def _evolve(self, validator, schema, resolver=None):
        if resolver is None:
            resolver = validator._resolver.in_subresource(
                self._specification.create_resource(schema),
            )
        return validator.evolve(schema=schema, _resolver=resolver)

    # -- bookkeeping -----------------------------------------------------

    @staticmethod
    def _uri(validator) -> str | None:
        try:
            return validator._resolver._base_uri or None
        except AttributeError:  # pragma: no cover - defensive
            return None

    @staticmethod
    def _identity(schema) -> int:
        return id(schema)

    def _schema_uri(self, validator, pointer: str) -> str | None:
        base = self._uri(validator)
        if base is None:
            return None
        return f"{base.split('#', 1)[0]}#{pointer}"

    def _record(
        self,
        path,
        level,
        keyword,
        schema_path,
        ref,
        validator,
    ) -> None:
        node = self.nodes.setdefault(path, _Node(path=path))
        node.definitions.append(
            _Definition(
                level=level,
                keyword=keyword,
                schema_path=schema_path,
                ref=ref,
                resolved_uri=self._uri(validator),
                schema_uri=self._schema_uri(validator, schema_path),
            ),
        )

    def _reject(
        self,
        path,
        level,
        keyword,
        schema_path,
        ref,
        validator,
        reason,
    ) -> None:
        key = (path, level, keyword, schema_path, ref, reason)
        if key in self._rejected_seen:
            return
        self._rejected_seen.add(key)
        self.rejected.append(
            ClassificationSource(
                level=level,
                keyword=keyword,
                schema_path=schema_path,
                path=path,
                ref=ref,
                resolved_uri=self._uri(validator),
                schema_uri=self._schema_uri(validator, schema_path),
                effective=False,
                reason=reason,
            ),
        )

    def _classification(
        self,
        schema: Mapping[str, Any],
        applicable: Sequence[tuple[str, Any]],
        spath,
    ) -> list[tuple[str, str]]:
        """Return every ``(keyword, level)`` configured on this schema."""
        found = []
        for keyword, value in applicable:
            if keyword in self.policy.keywords:
                where = _pointer((*spath, keyword))
                found.append(
                    (keyword, _extract_level(value, self.policy, where))
                )
        return found

    # -- effective traversal --------------------------------------------

    def visit(
        self,
        instance,
        schema,
        parent,
        ipath: tuple[str | int, ...],
        spath: tuple[str | int, ...],
        ref: str | None,
        resolver=None,
    ) -> None:
        if schema is True or schema is False:
            return

        evolved = self._evolve(parent, schema, resolver)
        key = (
            self._uri(evolved) or "",
            self._identity(schema),
            _pointer(spath),
            ipath,
        )
        if key in self._visited:
            return
        self._visited.add(key)

        applicable = _applicable(evolved, schema)
        configured = self._classification(schema, applicable, spath)
        for keyword, level in configured:
            self._record(
                ipath,
                level,
                keyword,
                _pointer((*spath, keyword)),
                ref,
                evolved,
            )

        for keyword, value in applicable:
            if keyword in self.policy.keywords:
                continue
            if keyword in {"$ref", "$dynamicRef", "$recursiveRef"}:
                resolved = self._lookup(evolved, value)
                if resolved is not None:
                    self.visit(
                        instance,
                        resolved.contents,
                        evolved,
                        ipath,
                        _pointer_parts(value),
                        value,
                        resolver=resolved.resolver,
                    )
            else:
                self._keyword(
                    keyword,
                    value,
                    instance,
                    schema,
                    evolved,
                    ipath,
                    spath,
                    ref,
                )

    def _keyword(
        self,
        keyword,
        value,
        instance,
        schema,
        validator,
        ipath,
        spath,
        ref,
    ):
        def child(item, subschema, name, location, keyword_name=None):
            self.visit(
                item,
                subschema,
                validator,
                (*ipath, name),
                (*spath, keyword_name or keyword, location),
                ref,
            )

        if keyword == "properties":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                for name, subschema in value.items():
                    if name in instance:
                        child(
                            instance[name],
                            subschema,
                            name,
                            name,
                            "properties",
                        )
        elif keyword == "patternProperties":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                for pattern, subschema in value.items():
                    for name, item in instance.items():
                        if _matches(pattern, name):
                            child(
                                item,
                                subschema,
                                name,
                                pattern,
                                "patternProperties",
                            )
        elif keyword == "additionalProperties":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                for name, item in _extras(instance, schema):
                    child(
                        item,
                        value,
                        name,
                        "",
                        "additionalProperties",
                    )
        elif keyword == "unevaluatedProperties":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                evaluated = set(
                    _utils.find_evaluated_property_keys_by_schema(
                        validator,
                        instance,
                        schema,
                    ),
                )
                for name, item in instance.items():
                    if name not in evaluated:
                        child(
                            item,
                            value,
                            name,
                            "",
                            "unevaluatedProperties",
                        )
        elif keyword == "dependentSchemas":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                for name, subschema in value.items():
                    if name in instance:
                        self.visit(
                            instance,
                            subschema,
                            validator,
                            ipath,
                            (*spath, "dependentSchemas", name),
                            ref,
                        )
        elif keyword == "dependencies":
            if isinstance(instance, Mapping) and isinstance(value, Mapping):
                for name, dependency in value.items():
                    if name in instance and isinstance(dependency, Mapping):
                        self.visit(
                            instance,
                            dependency,
                            validator,
                            ipath,
                            (*spath, "dependencies", name),
                            ref,
                        )
        elif keyword == "prefixItems":
            if _is_array(instance):
                for index, (item, subschema) in enumerate(
                    zip(instance, value),
                ):
                    child(item, subschema, index, index, "prefixItems")
        elif keyword == "items":
            self._items(instance, value, schema, validator, ipath, spath, ref)
        elif keyword == "additionalItems":
            if _is_array(instance) and isinstance(value, Mapping):
                start = len(schema.get("items", ()))
                for index in range(start, len(instance)):
                    child(
                        instance[index],
                        value,
                        index,
                        "",
                        "additionalItems",
                    )
        elif keyword == "contains":
            if _is_array(instance) and isinstance(value, Mapping):
                for index, item in enumerate(instance):
                    if validator.evolve(schema=value).is_valid(item):
                        child(item, value, index, "", "contains")
                    else:
                        self._scan(
                            item,
                            value,
                            validator,
                            (*ipath, index),
                            (*spath, "contains"),
                            ref,
                            "contains_item_failed",
                        )
        elif keyword == "unevaluatedItems":
            if _is_array(instance) and isinstance(value, Mapping):
                evaluated = set(
                    _utils.find_evaluated_item_indexes_by_schema(
                        validator,
                        instance,
                        schema,
                    ),
                )
                for index, item in enumerate(instance):
                    if index not in evaluated:
                        child(
                            item,
                            value,
                            index,
                            "",
                            "unevaluatedItems",
                        )
        elif keyword == "allOf":
            for index, subschema in enumerate(value):
                self.visit(
                    instance,
                    subschema,
                    validator,
                    ipath,
                    (*spath, "allOf", index),
                    ref,
                )
        elif keyword == "anyOf":
            self._any_of(instance, value, validator, ipath, spath, ref)
        elif keyword == "oneOf":
            self._one_of(instance, value, validator, ipath, spath, ref)
        elif keyword == "not":
            self._scan(
                instance,
                value,
                validator,
                ipath,
                (*spath, "not"),
                ref,
                "not_subschema",
            )
        elif keyword == "if":
            self._if(instance, value, schema, validator, ipath, spath, ref)

    def _items(self, instance, items, schema, validator, ipath, spath, ref):
        if not _is_array(instance):
            return
        if isinstance(items, Sequence) and not isinstance(items, str):
            for index, (item, subschema) in enumerate(zip(instance, items)):
                self.visit(
                    item,
                    subschema,
                    validator,
                    (*ipath, index),
                    (*spath, "items", index),
                    ref,
                )
        elif isinstance(items, Mapping):
            start = len(schema.get("prefixItems", ()))
            for index in range(start, len(instance)):
                self.visit(
                    instance[index],
                    items,
                    validator,
                    (*ipath, index),
                    (*spath, "items"),
                    ref,
                )

    def _any_of(self, instance, subschemas, validator, ipath, spath, ref):
        for index, subschema in enumerate(subschemas):
            location = (*spath, "anyOf", index)
            if validator.evolve(schema=subschema).is_valid(instance):
                self.visit(
                    instance, subschema, validator, ipath, location, ref
                )
            else:
                self._scan(
                    instance,
                    subschema,
                    validator,
                    ipath,
                    location,
                    ref,
                    "anyOf_branch_failed",
                )

    def _one_of(self, instance, subschemas, validator, ipath, spath, ref):
        valid = {
            index
            for index, subschema in enumerate(subschemas)
            if validator.evolve(schema=subschema).is_valid(instance)
        }
        for index, subschema in enumerate(subschemas):
            location = (*spath, "oneOf", index)
            if index in valid:
                self.visit(
                    instance, subschema, validator, ipath, location, ref
                )
            else:
                self._scan(
                    instance,
                    subschema,
                    validator,
                    ipath,
                    location,
                    ref,
                    "oneOf_branch_failed",
                )

    def _if(self, instance, condition, schema, validator, ipath, spath, ref):
        matched = validator.evolve(schema=condition).is_valid(instance)
        if matched:
            self.visit(
                instance,
                condition,
                validator,
                ipath,
                (*spath, "if"),
                ref,
            )
            if "then" in schema:
                self.visit(
                    instance,
                    schema["then"],
                    validator,
                    ipath,
                    (*spath, "then"),
                    ref,
                )
            if "else" in schema:
                self._scan(
                    instance,
                    schema["else"],
                    validator,
                    ipath,
                    (*spath, "else"),
                    ref,
                    "else_branch_not_taken",
                )
        else:
            self._scan(
                instance,
                condition,
                validator,
                ipath,
                (*spath, "if"),
                ref,
                "if_condition_failed",
            )
            if "then" in schema:
                self._scan(
                    instance,
                    schema["then"],
                    validator,
                    ipath,
                    (*spath, "then"),
                    ref,
                    "then_branch_not_taken",
                )
            if "else" in schema:
                self.visit(
                    instance,
                    schema["else"],
                    validator,
                    ipath,
                    (*spath, "else"),
                    ref,
                )

    # -- diagnostic traversal of rejected branches ----------------------

    def _scan(
        self,
        instance,
        schema,
        parent,
        ipath,
        spath,
        ref,
        reason,
        resolver=None,
        depth: int = 0,
    ) -> None:
        """Record classifications the instance did not actually reach."""
        if schema is True or schema is False or depth > 64:
            return
        evolved = self._evolve(parent, schema, resolver)
        key = (
            self._uri(evolved) or "",
            self._identity(schema),
            _pointer(spath),
            ipath,
        )
        if key in self._scanned:
            return
        self._scanned.add(key)

        applicable = _applicable(evolved, schema)
        for keyword, value in applicable:
            if keyword in self.policy.keywords:
                where = _pointer((*spath, keyword))
                level = _extract_level(value, self.policy, where)
                self._reject(
                    ipath,
                    level,
                    keyword,
                    where,
                    ref,
                    evolved,
                    reason,
                )

        for keyword, value in applicable:
            if keyword in self.policy.keywords:
                continue
            if keyword in {"$ref", "$dynamicRef", "$recursiveRef"}:
                resolved = self._lookup(evolved, value)
                if resolved is not None:
                    self._scan(
                        instance,
                        resolved.contents,
                        evolved,
                        ipath,
                        _pointer_parts(value),
                        value,
                        reason,
                        resolver=resolved.resolver,
                        depth=depth + 1,
                    )
            elif keyword == "properties":
                if isinstance(instance, Mapping) and isinstance(
                    value, Mapping
                ):
                    for name, subschema in value.items():
                        if name in instance:
                            self._scan(
                                instance[name],
                                subschema,
                                evolved,
                                (*ipath, name),
                                (*spath, "properties", name),
                                ref,
                                reason,
                                depth=depth + 1,
                            )
            elif keyword == "patternProperties":
                if isinstance(instance, Mapping) and isinstance(
                    value, Mapping
                ):
                    for pattern, subschema in value.items():
                        for name, item in instance.items():
                            if _matches(pattern, name):
                                self._scan(
                                    item,
                                    subschema,
                                    evolved,
                                    (*ipath, name),
                                    (*spath, "patternProperties", pattern),
                                    ref,
                                    reason,
                                    depth=depth + 1,
                                )
            elif keyword == "additionalProperties":
                if isinstance(instance, Mapping) and isinstance(
                    value, Mapping
                ):
                    for name, item in _extras(instance, schema):
                        self._scan(
                            item,
                            value,
                            evolved,
                            (*ipath, name),
                            (*spath, "additionalProperties"),
                            ref,
                            reason,
                            depth=depth + 1,
                        )
            elif keyword == "dependentSchemas":
                if isinstance(instance, Mapping) and isinstance(
                    value, Mapping
                ):
                    for name, subschema in value.items():
                        if name in instance:
                            self._scan(
                                instance,
                                subschema,
                                evolved,
                                ipath,
                                (*spath, "dependentSchemas", name),
                                ref,
                                reason,
                                depth=depth + 1,
                            )
            elif keyword == "prefixItems":
                if _is_array(instance):
                    for index, (item, subschema) in enumerate(
                        zip(instance, value),
                    ):
                        self._scan(
                            item,
                            subschema,
                            evolved,
                            (*ipath, index),
                            (*spath, "prefixItems", index),
                            ref,
                            reason,
                            depth=depth + 1,
                        )
            elif keyword == "items":
                self._scan_items(
                    instance,
                    value,
                    schema,
                    evolved,
                    ipath,
                    spath,
                    ref,
                    reason,
                    depth,
                )
            elif keyword == "contains":
                if _is_array(instance) and isinstance(value, Mapping):
                    for index, item in enumerate(instance):
                        self._scan(
                            item,
                            value,
                            evolved,
                            (*ipath, index),
                            (*spath, "contains"),
                            ref,
                            reason,
                            depth=depth + 1,
                        )
            elif keyword in {"allOf", "anyOf", "oneOf"}:
                for index, subschema in enumerate(value):
                    self._scan(
                        instance,
                        subschema,
                        evolved,
                        ipath,
                        (*spath, keyword, index),
                        ref,
                        reason,
                        depth=depth + 1,
                    )
            elif keyword == "not":
                self._scan(
                    instance,
                    value,
                    evolved,
                    ipath,
                    (*spath, "not"),
                    ref,
                    reason,
                    depth=depth + 1,
                )
            elif keyword == "if" and isinstance(schema, Mapping):
                self._scan(
                    instance,
                    value,
                    evolved,
                    ipath,
                    (*spath, "if"),
                    ref,
                    reason,
                    depth=depth + 1,
                )
                for branch in ("then", "else"):
                    if branch in schema:
                        self._scan(
                            instance,
                            schema[branch],
                            evolved,
                            ipath,
                            (*spath, branch),
                            ref,
                            reason,
                            depth=depth + 1,
                        )

    def _scan_items(
        self,
        instance,
        items,
        schema,
        validator,
        ipath,
        spath,
        ref,
        reason,
        depth,
    ):
        if not _is_array(instance):
            return
        if isinstance(items, Sequence) and not isinstance(items, str):
            for index, (item, subschema) in enumerate(zip(instance, items)):
                self._scan(
                    item,
                    subschema,
                    validator,
                    (*ipath, index),
                    (*spath, "items", index),
                    ref,
                    reason,
                    depth=depth + 1,
                )
        elif isinstance(items, Mapping):
            start = len(schema.get("prefixItems", ()))
            for index in range(start, len(instance)):
                self._scan(
                    instance[index],
                    items,
                    validator,
                    (*ipath, index),
                    (*spath, "items"),
                    ref,
                    reason,
                    depth=depth + 1,
                )

    def withhold(self) -> None:
        """Keep only diagnostic observations of the failed branches."""
        observed = []
        for node in self.nodes.values():
            for definition in node.definitions:
                observed.append(
                    ClassificationSource(
                        level=definition.level,
                        keyword=definition.keyword,
                        schema_path=definition.schema_path,
                        path=node.path,
                        ref=definition.ref,
                        resolved_uri=definition.resolved_uri,
                        schema_uri=definition.schema_uri,
                        effective=False,
                        reason="instance_invalid",
                    ),
                )
        self.rejected = [*self.rejected, *observed]
        self.nodes.clear()

    # -- result assembly -------------------------------------------------

    def result(self, valid: bool, errors, schema_id) -> ClassificationResult:
        entries = []
        conflicts = []
        missing = [
            path
            for path in _leaf_paths(self.instance)
            if path not in self.nodes
        ]
        for path in missing:
            self.nodes[path] = _Node(path=path)
        for path, node in self.nodes.items():
            value = _value_at(self.instance, path)
            configured = node.definitions
            if not configured:
                if value is _MISSING or _is_container(value):
                    continue
                entries.append(
                    ClassificationEntry(
                        path=path,
                        level=self.policy.unknown,
                        known=False,
                        sources=(
                            ClassificationSource(
                                level=None,
                                keyword=None,
                                schema_path="",
                                path=path,
                                reason="no_effective_definition",
                            ),
                        ),
                    ),
                )
                continue

            levels = {definition.level for definition in configured}
            selected = self.policy.strictest(levels)
            sources = tuple(
                ClassificationSource(
                    level=definition.level,
                    keyword=definition.keyword,
                    schema_path=definition.schema_path,
                    path=path,
                    ref=definition.ref,
                    resolved_uri=definition.resolved_uri,
                    schema_uri=definition.schema_uri,
                )
                for definition in node.definitions
            )
            entries.append(
                ClassificationEntry(
                    path=path,
                    level=selected,
                    known=True,
                    sources=sources,
                ),
            )
            if len(levels) > 1:
                conflicts.append(
                    ClassificationConflict(
                        path=path,
                        levels=tuple(sorted(levels, key=self.policy.rank)),
                        selected=selected,
                        sources=sources,
                    ),
                )

        if valid:
            status = "approved"
            reason = None
        else:
            status = "withheld"
            reason = "instance_invalid"
            entries = []
            conflicts = []

        return ClassificationResult(
            valid=valid,
            status=status,
            errors=tuple(errors),
            entries=tuple(entries),
            conflicts=tuple(conflicts),
            rejected=tuple(self.rejected),
            policy=self.policy,
            schema_id=schema_id,
            reason=reason,
        )


def _pointer_parts(ref) -> tuple[str | int, ...]:
    """The path components of a reference's JSON pointer, if it has one."""
    if not isinstance(ref, str) or "#" not in ref:
        return ()
    fragment = ref.split("#", 1)[1]
    if not fragment.startswith("/"):
        return ()
    parts = []
    for raw in fragment.lstrip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        parts.append(int(part) if part.isdigit() else part)
    return tuple(parts)


def _is_array(value) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str)


def _leaf_paths(instance, path=()):
    """Yield the paths of all scalar leaves in ``instance``."""
    if isinstance(instance, Mapping):
        for name, value in instance.items():
            yield from _leaf_paths(value, (*path, name))
    elif _is_array(instance):
        for index, value in enumerate(instance):
            yield from _leaf_paths(value, (*path, index))
    else:
        yield path


def _extras(instance, schema):
    properties = schema.get("properties", {})
    patterns = list(schema.get("patternProperties", ()))
    for name, value in instance.items():
        if name in properties or any(
            _matches(pattern, name) for pattern in patterns
        ):
            continue
        yield name, value


def classify(
    instance: Any,
    schema: Any,
    *,
    validator_cls=None,
    policy: ClassificationPolicy | None = None,
    registry=None,
) -> ClassificationResult:
    """
    Validate ``instance`` and collect its effective data classifications.

    Arguments:

        instance:

            The JSON instance (usually a decoded ``dict``/``list``).

        schema:

            The JSON Schema to validate with.  Classification keywords
            may appear anywhere a subschema does.

        validator_cls:

            An optional validator class.  If unprovided, one is chosen
            from the schema's :kw:`$schema` keyword.

        policy:

            A `ClassificationPolicy` controlling recognized keywords and
            the strictness order of levels.

        registry:

            An optional `referencing.Registry` used to resolve external
            references, as with validator classes themselves.

    Returns:

        ClassificationResult:

            A result whose `to_dict` method produces the compliance
            document.  Invalid instances produce a ``"withheld"``
            classification with no approved fields.
    """
    policy = policy or ClassificationPolicy()
    if not isinstance(schema, (Mapping, bool)):
        raise ClassificationConfigurationError(
            f"A schema must be an object or boolean, got {schema!r}.",
        )
    if validator_cls is None:
        validator_cls = validators.validator_for(schema)

    if registry is None:
        validator = validator_cls(schema)
    else:
        validator = validator_cls(schema, registry=registry)
    errors = list(validator.iter_errors(instance))
    valid = not errors

    collector = _Collector(validator, policy, instance)
    root_resolver = validator._resolver
    collector.visit(
        instance,
        schema,
        validator,
        (),
        (),
        None,
        resolver=root_resolver,
    )
    if not valid:
        collector.withhold()

    schema_id = schema.get("$id") if isinstance(schema, Mapping) else None
    return collector.result(valid=valid, errors=errors, schema_id=schema_id)
