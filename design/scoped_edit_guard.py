"""Prototype guard for schema-scoped configuration edits.

The guard answers one question: given a schema, a baseline document, a
proposed document and a set of writable instance paths, may the edit be
handled locally, or must it be escalated for review?

It is deliberately conservative.  It never claims that a cross-path
permission change is impossible; it only auto-approves when its evidence
says no such change was observed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

_MISSING = object()

Path = tuple[Any, ...]


# ---------------------------------------------------------------- documents


def diff(old: Any, new: Any, prefix: Path = ()) -> dict[Path, tuple[str, Any, Any]]:
    """Return leaf-level changes.

    Object members are compared individually.  A change to an array's length
    is reported as a replacement of the array itself, which is intentionally
    coarse: an operator allowed to edit ``items/3`` is not thereby allowed to
    grow or shrink the array.
    """
    if isinstance(old, Mapping) and isinstance(new, Mapping):
        changes: dict[Path, tuple[str, Any, Any]] = {}
        keys = list(old) + [key for key in new if key not in old]
        for key in keys:
            changes.update(
                diff(old.get(key, _MISSING), new.get(key, _MISSING), prefix + (key,)),
            )
        return changes

    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return {prefix: ("replace", old, new)}
        changes = {}
        for index, (left, right) in enumerate(zip(old, new)):
            changes.update(diff(left, right, prefix + (index,)))
        return changes

    if old is _MISSING or new is _MISSING:
        kind = "add" if old is _MISSING else "remove"
        return {prefix: (kind, None if old is _MISSING else old, new)}

    if old != new:
        return {prefix: ("replace", old, new)}
    return {}


def get_path(document: Any, path: Path) -> Any:
    node = document
    for part in path:
        node = node[part]
    return node


def set_path(document: Any, path: Path, value: Any) -> None:
    node = document
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def delete_path(document: Any, path: Path) -> bool:
    try:
        node = document
        for part in path[:-1]:
            node = node[part]
        del node[path[-1]]
    except (KeyError, IndexError, TypeError):
        return False
    return True


def within(path: Path, writable: set[Path]) -> bool:
    return any(path[: len(prefix)] == prefix for prefix in writable)


def has_path(document: Any, path: Path) -> bool:
    node = document
    for part in path:
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and isinstance(part, int) and -len(node) <= part < len(node):
            node = node[part]
        else:
            return False
    return True


# ------------------------------------------------------------- schema crawling


def _resolve_local(root: Any, ref: str) -> Any:
    """Resolve a same-document JSON pointer, or return None."""
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        return None
    node = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, Mapping):
            if token not in node:
                return None
            node = node[token]
        elif isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


@dataclass
class SchemaFacts:
    dynamic_refs: list[str] = field(default_factory=list)
    nonlocal_refs: list[str] = field(default_factory=list)
    recursive_refs: list[Path] = field(default_factory=list)
    unevaluated_scopes: set[Path] = field(default_factory=set)
    dependent_keys: dict[tuple[Path, str], str] = field(default_factory=dict)
    mentioned_paths: set[Path] = field(default_factory=set)
    candidate_values: list[Any] = field(default_factory=list)

    def add_value(self, value: Any) -> None:
        if isinstance(value, (bool, int, float, str)) and value not in self.candidate_values:
            self.candidate_values.append(value)


_NUMERIC_BOUNDS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
)


def analyze_schema(schema: Mapping) -> SchemaFacts:
    facts = SchemaFacts()
    _scan_schema(schema, schema, (), (), facts, frozenset(), 0)
    return facts


def _scan_schema(
    root: Any,
    node: Any,
    scope: Path,
    spath: Path,
    facts: SchemaFacts,
    seen: frozenset[tuple[int, Path]],
    depth: int,
) -> None:
    if depth > 64:
        return
    if node is True or node is False or not isinstance(node, Mapping):
        return

    marker = (id(node), scope)
    if marker in seen:
        facts.recursive_refs.append(spath)
        return
    seen = seen | {marker}

    if "$dynamicRef" in node:
        facts.dynamic_refs.append(str(node["$dynamicRef"]))
    if "$ref" in node:
        ref = node["$ref"]
        target = _resolve_local(root, ref)
        if target is None:
            facts.nonlocal_refs.append(str(ref))
        else:
            _scan_schema(
                root,
                target,
                scope,
                spath + ("$ref", ref),
                facts,
                seen,
                depth + 1,
            )

    for keyword in _NUMERIC_BOUNDS:
        value = node.get(keyword)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            facts.add_value(value)
            facts.add_value(value - 1)
            facts.add_value(value + 1)

    if "const" in node:
        facts.add_value(node["const"])
    for value in node.get("enum", []) if isinstance(node.get("enum"), list) else []:
        facts.add_value(value)

    for keyword in ("minLength", "maxLength"):
        value = node.get(keyword)
        if isinstance(value, int) and not isinstance(value, bool):
            for length in {0, max(0, value - 1), value, value + 1}:
                facts.add_value("x" * length)
    if node.get("type") == "boolean":
        facts.add_value(True)
        facts.add_value(False)

    if "unevaluatedProperties" in node or "unevaluatedItems" in node:
        facts.unevaluated_scopes.add(scope)

    for key in ("dependentSchemas", "dependentRequired"):
        dependencies = node.get(key)
        if isinstance(dependencies, Mapping):
            for trigger in dependencies:
                facts.dependent_keys[(scope, trigger)] = key
                if key == "dependentSchemas":
                    _scan_schema(
                        root,
                        dependencies[trigger],
                        scope,
                        spath + (key, trigger),
                        facts,
                        seen,
                        depth + 1,
                    )

    properties = node.get("properties")
    if isinstance(properties, Mapping):
        for key, subschema in properties.items():
            facts.mentioned_paths.add(scope + (key,))
            _scan_schema(
                root,
                subschema,
                scope + (key,),
                spath + ("properties", key),
                facts,
                seen,
                depth + 1,
            )

    patterns = node.get("patternProperties")
    if isinstance(patterns, Mapping):
        for pattern, subschema in patterns.items():
            _scan_schema(
                root,
                subschema,
                scope,
                spath + ("patternProperties", pattern),
                facts,
                seen,
                depth + 1,
            )

    if isinstance(node.get("additionalProperties"), Mapping):
        _scan_schema(
            root,
            node["additionalProperties"],
            scope,
            spath + ("additionalProperties",),
            facts,
            seen,
            depth + 1,
        )

    items = node.get("items")
    if isinstance(items, Mapping):
        _scan_schema(root, items, scope, spath + ("items",), facts, seen, depth + 1)
    for index, subschema in enumerate(node.get("prefixItems", [])):
        _scan_schema(
            root,
            subschema,
            scope + (index,),
            spath + ("prefixItems", index),
            facts,
            seen,
            depth + 1,
        )
    if isinstance(node.get("contains"), Mapping):
        _scan_schema(
            root,
            node["contains"],
            scope,
            spath + ("contains",),
            facts,
            seen,
            depth + 1,
        )

    for keyword in ("allOf", "anyOf", "oneOf"):
        for index, subschema in enumerate(node.get(keyword, [])):
            _scan_schema(
                root,
                subschema,
                scope,
                spath + (keyword, index),
                facts,
                seen,
                depth + 1,
            )
    for keyword in ("if", "then", "else", "not"):
        if keyword in node:
            _scan_schema(
                root,
                node[keyword],
                scope,
                spath + (keyword,),
                facts,
                seen,
                depth + 1,
            )


# -------------------------------------------------------------- branch state


def _valid_under(
    validator: Draft202012Validator,
    subschema: Any,
    instance: Any,
    counter: list[int],
) -> bool:
    """Validate ``instance`` against ``subschema`` with the root resolver.

    ``evolve`` deliberately keeps the original resolver, so a subschema that
    contains ``$ref`` into the document's ``$defs`` still resolves.  This is
    the public-API counterpart to ``descend``.
    """
    counter[0] += 1
    return validator.evolve(schema=subschema).is_valid(instance)


def branch_state(
    validator: Draft202012Validator,
    schema: Mapping,
    instance: Any,
) -> tuple[dict[tuple, tuple[Path, Any]], set[str], list[int]]:
    """Record every runtime branch decision that validation makes.

    The state includes ``if``/``then``/``else`` selection, which
    ``dependentSchemas`` triggers fired, and which ``oneOf``/``anyOf``
    branches validated.  Comparing the state for the old and new document
    is how a branch flip is detected even when both documents are valid.
    """
    state: dict[tuple, tuple[Path, Any]] = {}
    flags: set[str] = set()
    counter = [0]

    def walk(
        node: Any,
        current: Any,
        scope: Path,
        spath: Path,
        seen: frozenset[tuple[int, Path]],
        depth: int,
    ) -> None:
        if depth > 64:
            flags.add("depth_limit")
            return
        if node is True or node is False or not isinstance(node, Mapping):
            return

        marker = (id(node), scope)
        if marker in seen:
            flags.add("recursive_ref")
            return
        seen = seen | {marker}

        if "$dynamicRef" in node:
            flags.add("dynamic_ref")
        if "$ref" in node:
            ref = node["$ref"]
            target = _resolve_local(schema, ref)
            if target is None:
                flags.add("nonlocal_ref")
            else:
                walk(
                    target,
                    current,
                    scope,
                    spath + ("$ref", ref),
                    seen,
                    depth + 1,
                )
            node = {k: v for k, v in node.items() if k != "$ref"}
            if not node:
                return

        if "if" in node:
            outcome = _valid_under(validator, node["if"], current, counter)
            state[(spath, "if")] = (scope, outcome)
            branch = "then" if outcome else "else"
            if branch in node:
                state[(spath, "if", "selected")] = (scope, branch)
                walk(
                    node[branch],
                    current,
                    scope,
                    spath + (branch,),
                    seen,
                    depth + 1,
                )

        for keyword in ("oneOf", "anyOf"):
            subschemas = node.get(keyword)
            if isinstance(subschemas, list):
                outcomes = tuple(
                    _valid_under(validator, subschema, current, counter)
                    for subschema in subschemas
                )
                state[(spath, keyword)] = (scope, outcomes)
                for index, outcome in enumerate(outcomes):
                    if outcome:
                        walk(
                            subschemas[index],
                            current,
                            scope,
                            spath + (keyword, index),
                            seen,
                            depth + 1,
                        )

        for subschema in node.get("allOf", []) if isinstance(node.get("allOf"), list) else []:
            walk(subschema, current, scope, spath + ("allOf",), seen, depth + 1)

        if "not" in node:
            state[(spath, "not")] = (
                scope,
                _valid_under(validator, node["not"], current, counter),
            )

        dependencies = node.get("dependentSchemas")
        if isinstance(dependencies, Mapping) and isinstance(current, Mapping):
            triggered = tuple(key for key in dependencies if key in current)
            state[(spath, "dependentSchemas")] = (scope, triggered)
            for key in triggered:
                walk(
                    dependencies[key],
                    current,
                    scope,
                    spath + ("dependentSchemas", key),
                    seen,
                    depth + 1,
                )

        requires = node.get("dependentRequired")
        if isinstance(requires, Mapping) and isinstance(current, Mapping):
            for key, needed in requires.items():
                if key in current:
                    missing = tuple(item for item in needed if item not in current)
                    state[(spath, "dependentRequired", key)] = (scope, missing)

        properties = node.get("properties")
        if isinstance(properties, Mapping) and isinstance(current, Mapping):
            for key, subschema in properties.items():
                if key in current:
                    walk(
                        subschema,
                        current[key],
                        scope + (key,),
                        spath + ("properties", key),
                        seen,
                        depth + 1,
                    )

        patterns = node.get("patternProperties")
        matched: set[str] = set()
        if isinstance(patterns, Mapping) and isinstance(current, Mapping):
            for pattern, subschema in patterns.items():
                for key in current:
                    if isinstance(key, str) and re.search(pattern, key):
                        matched.add(key)
                        walk(
                            subschema,
                            current[key],
                            scope + (key,),
                            spath + ("patternProperties", pattern),
                            seen,
                            depth + 1,
                        )

        additional = node.get("additionalProperties")
        if isinstance(additional, Mapping) and isinstance(current, Mapping):
            known = set(properties) if isinstance(properties, Mapping) else set()
            for key, value in current.items():
                if key not in known and key not in matched:
                    walk(
                        additional,
                        value,
                        scope + (key,),
                        spath + ("additionalProperties",),
                        seen,
                        depth + 1,
                    )

        items = node.get("items")
        if isinstance(items, Mapping) and isinstance(current, list):
            for index, value in enumerate(current):
                walk(
                    items,
                    value,
                    scope + (index,),
                    spath + ("items",),
                    seen,
                    depth + 1,
                )

        prefix = node.get("prefixItems")
        if isinstance(prefix, list) and isinstance(current, list):
            for index, subschema in enumerate(prefix[: len(current)]):
                walk(
                    subschema,
                    current[index],
                    scope + (index,),
                    spath + ("prefixItems", index),
                    seen,
                    depth + 1,
                )

        contains = node.get("contains")
        if isinstance(contains, Mapping) and isinstance(current, list):
            state[(spath, "contains")] = (
                scope,
                tuple(
                    _valid_under(validator, contains, value, counter)
                    for value in current
                ),
            )

    walk(schema, instance, (), (), frozenset(), 0)
    return state, flags, counter


# --------------------------------------------------------------- local check


def local_subschemas(root: Any, path: Path) -> list[Any]:
    """Return the unconditional subschemas that apply at ``path``.

    Only ``properties``/``patternProperties``/``additionalProperties``,
    ``items``/``prefixItems`` and ``allOf``/``$ref`` are followed.  Anything
    conditional or annotation-driven is deliberately absent: the local
    check is a necessary condition, never the whole proof.
    """
    found: list[Any] = []

    def collect(node: Any, remaining: Path, seen: frozenset[int]) -> None:
        if node is True or node is False or not isinstance(node, Mapping):
            if not remaining:
                found.append(node)
            return
        if id(node) in seen:
            return
        seen = seen | {id(node)}

        if "$ref" in node:
            target = _resolve_local(root, node["$ref"])
            if target is not None:
                collect(target, remaining, seen)

        for subschema in node.get("allOf", []) if isinstance(node.get("allOf"), list) else []:
            collect(subschema, remaining, seen)

        if not remaining:
            found.append(node)
            return

        head, rest = remaining[0], remaining[1:]
        if isinstance(head, str):
            matched = False
            properties = node.get("properties")
            if isinstance(properties, Mapping) and head in properties:
                collect(properties[head], rest, seen)
                matched = True
            for pattern, subschema in (node.get("patternProperties") or {}).items():
                if re.search(pattern, head):
                    collect(subschema, rest, seen)
                    matched = True
            additional = node.get("additionalProperties")
            if not matched and isinstance(additional, Mapping):
                collect(additional, rest, seen)
        elif isinstance(head, int):
            prefix = node.get("prefixItems")
            if isinstance(prefix, list) and head < len(prefix):
                collect(prefix[head], rest, seen)
            elif isinstance(node.get("items"), Mapping):
                collect(node["items"], rest, seen)

    collect(root, path, frozenset())
    return found


# ------------------------------------------------------------------ witnesses


def _is_near(path: Path, mentioned: set[Path]) -> bool:
    for candidate in mentioned:
        if path[: len(candidate)] == candidate:
            return True
        if candidate[: len(path)] == path:
            return True
    return False


def _document_paths(document: Any, prefix: Path = ()) -> set[Path]:
    paths: set[Path] = set()
    if isinstance(document, Mapping):
        for key, value in document.items():
            paths.add(prefix + (key,))
            paths.update(_document_paths(value, prefix + (key,)))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            paths.add(prefix + (index,))
            paths.update(_document_paths(value, prefix + (index,)))
    return paths


def find_witnesses(
    validator: Draft202012Validator,
    old: Any,
    new: Any,
    changed: set[Path],
    facts: SchemaFacts,
    counter: list[int],
    *,
    max_paths: int = 24,
    max_values: int = 48,
    max_witnesses: int = 5,
) -> tuple[list[dict[str, Any]], int]:
    """Search for a value at an untouched path whose acceptance flipped.

    A witness is the human-readable form of an escalation: ``path`` accepted
    ``value`` in one document but not the other.  Absence of a witness is not
    proof of safety -- the fingerprint/static checks carry that weight.
    """
    candidates = {
        path
        for path in (_document_paths(old) | _document_paths(new))
        if path not in changed
        and not any(path[: len(item)] == item or item[: len(path)] == path for item in changed)
        and _is_near(path, facts.mentioned_paths)
    }
    values = facts.candidate_values[:max_values]
    found: list[dict[str, Any]] = []
    inspected = 0

    for path in sorted(candidates, key=repr)[:max_paths]:
        for value in values:
            inspected += 1
            old_copy = copy.deepcopy(old)
            new_copy = copy.deepcopy(new)
            if not has_path(new, path):
                continue
            if not delete_path(old_copy, path) or not delete_path(new_copy, path):
                continue
            set_path(old_copy, path, copy.deepcopy(value))
            set_path(new_copy, path, copy.deepcopy(value))
            counter[0] += 2
            old_valid = validator.is_valid(old_copy)
            new_valid = validator.is_valid(new_copy)
            if old_valid != new_valid:
                found.append(
                    {
                        "path": path,
                        "value": value,
                        "old_valid": old_valid,
                        "new_valid": new_valid,
                    },
                )
                break
        if len(found) >= max_witnesses:
            break
    return found, inspected


# -------------------------------------------------------------------- verdict


@dataclass
class Decision:
    verdict: str
    reasons: list[str] = field(default_factory=list)
    witnesses: list[dict[str, Any]] = field(default_factory=list)
    branch_changes: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


def guard(
    schema: Mapping,
    old: Any,
    new: Any,
    writable: set[Path],
) -> Decision:
    try:
        validator = Draft202012Validator(schema)
        validator.check_schema(schema)
    except SchemaError as error:
        return Decision("reject", [f"schema_invalid: {error.message}"])

    changes = diff(old, new)
    facts = analyze_schema(schema)
    metrics: dict[str, Any] = {
        "changed_paths": len(changes),
        "mentioned_paths": len(facts.mentioned_paths),
        "candidate_values": len(facts.candidate_values),
    }

    metrics["full_validations"] = 1
    if not validator.is_valid(old):
        return Decision(
            "reject",
            ["baseline_invalid: the stored document does not validate"],
            metrics=metrics,
        )

    violations = [path for path in changes if not within(path, writable)]
    if violations:
        return Decision(
            "reject",
            [f"acl_violation: {path!r} is outside the writable paths" for path in violations],
            metrics=metrics,
        )

    metrics["full_validations"] += 1
    full_errors = list(validator.iter_errors(new))
    if full_errors:
        details = [
            f"{error.json_path} [{error.validator}] {error.message}"
            for error in full_errors[:5]
        ]
        return Decision(
            "reject",
            ["full_validation_failed: " + "; ".join(details)],
            metrics=metrics,
        )

    if not changes:
        return Decision("auto-approve", ["no changes"], metrics=metrics)

    reasons: list[str] = []

    for path, (kind, _old_value, new_value) in changes.items():
        if kind == "remove":
            continue
        subschemas = local_subschemas(schema, path)
        if not subschemas:
            reasons.append(f"local_subschema_unavailable: {path!r}")
            continue
        for subschema in subschemas:
            errors = list(validator.evolve(schema=subschema).iter_errors(new_value))
            metrics["local_validations"] = metrics.get("local_validations", 0) + 1
            for error in errors:
                reasons.append(
                    f"local_invalid: {path!r} [{error.validator}] {error.message}",
                )

    for path, (kind, _old_value, _new_value) in changes.items():
        if kind not in {"add", "remove"}:
            continue
        parent, key = path[:-1], path[-1]
        dependency = facts.dependent_keys.get((parent, key))
        if dependency is not None:
            reasons.append(
                f"presence_dependency: {kind} of {path!r} triggers {dependency}",
            )

    for path in changes:
        if path[:-1] in facts.unevaluated_scopes:
            reasons.append(
                f"unevaluated_scope: {path[:-1]!r} uses unevaluatedProperties/Items",
            )

    if facts.dynamic_refs:
        reasons.append(
            "dynamic_ref: " + ", ".join(sorted(set(facts.dynamic_refs))),
        )
    if facts.nonlocal_refs:
        reasons.append(
            "nonlocal_ref: " + ", ".join(sorted(set(facts.nonlocal_refs))),
        )
    if facts.recursive_refs:
        reasons.append("recursive_ref: schema reaches itself; locality unbounded")

    old_state, old_flags, old_calls = branch_state(validator, schema, old)
    new_state, new_flags, new_calls = branch_state(validator, schema, new)
    metrics["branch_decisions"] = len(old_state)
    metrics["branch_validations"] = old_calls[0] + new_calls[0]

    branch_changes: list[dict[str, Any]] = []
    for key in sorted(set(old_state) | set(new_state), key=repr):
        before = old_state.get(key)
        after = new_state.get(key)
        if before == after:
            continue
        scope = (before or after or ((), None))[0]
        branch_changes.append(
            {
                "schema_path": list(key[0]) if isinstance(key, tuple) else [],
                "keyword": key[-1] if isinstance(key, tuple) else key,
                "scope": list(scope),
                "old": None if before is None else before[1],
                "new": None if after is None else after[1],
            },
        )
    for change in branch_changes:
        reasons.append(
            "branch_flip: "
            f"at {change['scope']!r} keyword={change['keyword']!r} "
            f"{change['old']!r} -> {change['new']!r}",
        )
    for flag in (old_flags | new_flags):
        reasons.append(f"branch_flag: {flag}")

    witnesses, inspected = find_witnesses(
        validator,
        old,
        new,
        set(changes),
        facts,
        [0],
    )
    metrics["witness_candidates"] = inspected
    metrics["witness_validations"] = 2 * inspected
    for witness in witnesses:
        reasons.append(
            "permission_witness: "
            f"{witness['path']!r}={witness['value']!r} "
            f"old_valid={witness['old_valid']} new_valid={witness['new_valid']}",
        )

    verdict = "escalate" if reasons else "auto-approve"
    return Decision(
        verdict,
        reasons,
        witnesses=witnesses,
        branch_changes=branch_changes,
        metrics=metrics,
    )

# --------------------------------------------------------- change fingerprints


def change_fingerprint(
    schema: Mapping,
    old: Any,
    new: Any,
    changed: Iterable[Path],
) -> dict[str, Any]:
    """A stable hash of the change *plus* the effective constraint sources.

    The fingerprint is what an approver records.  A later edit that produces a
    different fingerprint is a different change even if the diff text looks
    similar, because it may bind to a different `$defs` node or a different
    conditional branch.
    """
    old_paths = _document_paths(old)
    new_paths = _document_paths(new)
    parts = []
    for path in sorted(changed, key=repr):
        parts.append(
            {
                "path": list(path),
                "old": get_path(old, path) if path in old_paths else None,
                "new": get_path(new, path) if path in new_paths else None,
                "local_schemas": [
                    _canonical(item) for item in local_subschemas(schema, path)
                ],
            },
        )
    blob = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return {
        "sha256": hashlib.sha256(blob.encode()).hexdigest(),
        "changes": parts,
    }


def _canonical(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, default=str))
    except TypeError:
        return str(value)


# ---------------------------------------------------------------- review flow


@dataclass
class Justification:
    """The recorded human reason for accepting an escalated change.

    A justification can waive *semantic* escalations (branch flips, witnesses,
    reference hazards).  It can never waive an ACL violation, an invalid
    schema, or an invalid resulting document -- those are structural and must
    be fixed, not argued away.
    """

    reason: str
    approver: str
    acknowledged: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("justification reason must be non-empty")
        if not self.approver.strip():
            raise ValueError("approver must be non-empty")


_STRUCTURAL = (
    "acl_violation:",
    "full_validation_failed:",
    "schema_invalid:",
    "baseline_invalid:",
    "local_invalid:",
)


def review(
    schema: Mapping,
    old: Any,
    new: Any,
    writable: set[Path],
    justification: Justification | None = None,
) -> Decision:
    """Run the guard, then optionally apply a recorded justification."""
    decision = guard(schema, old, new, writable)
    if decision.verdict != "escalate" or justification is None:
        return decision

    if any(reason.startswith(_STRUCTURAL) for reason in decision.reasons):
        return decision

    unacknowledged = [
        reason
        for reason in decision.reasons
        if reason.split(":", 1)[0] not in justification.acknowledged
    ]
    if unacknowledged:
        decision.reasons.append(
            "justification_incomplete: unacknowledged "
            + ", ".join(sorted({reason.split(":", 1)[0] for reason in unacknowledged})),
        )
        return decision

    decision.verdict = "approved-with-justification"
    decision.reasons.append(
        f"justification: {justification.approver} -- {justification.reason}",
    )
    return decision
