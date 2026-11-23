"""Executable examples for design/README.md.

Run with ``.venv/bin/python -m pytest design/test_scoped_edit_guard.py -q``.
"""

from __future__ import annotations

import copy

import pytest

from scoped_edit_guard import (
    Justification,
    change_fingerprint,
    guard,
    local_subschemas,
    review,
)

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "mode": {"enum": ["live", "readonly"]},
        "limits": {
            "type": "object",
            "properties": {
                "retries": {"type": "integer", "minimum": 0, "maximum": 3},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
            },
            "required": ["retries", "timeoutSeconds"],
            "additionalProperties": False,
        },
        "publish": {"type": "boolean"},
    },
    "required": ["mode", "limits", "publish"],
    "if": {"properties": {"mode": {"const": "live"}}},
    "then": {
        "properties": {
            "limits": {"properties": {"timeoutSeconds": {"maximum": 30}}},
            "publish": {"const": True},
        },
    },
    "else": {
        "properties": {
            "limits": {"properties": {"timeoutSeconds": {"maximum": 300}}},
            "publish": {"const": False},
        },
    },
}

BASE = {
    "mode": "live",
    "limits": {"retries": 1, "timeoutSeconds": 20},
    "publish": True,
}


def _edit(**changes):
    document = copy.deepcopy(BASE)
    for path, value in changes.items():
        node = document
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return document


def test_independent_edit_is_local():
    """Example A: editing only limits.retries leaves every other permit fixed."""
    edited = _edit(**{"limits.retries": 2})
    decision = guard(SCHEMA, BASE, edited, writable={("limits", "retries")})
    assert decision.verdict == "auto-approve", decision.reasons

    # The effective schema at limits.timeoutSeconds is unaffected too.
    before = local_subschemas(SCHEMA, ("limits", "timeoutSeconds"))
    assert before, "schema should constrain timeoutSeconds"


def test_branch_flip_escalates_even_when_both_documents_valid():
    """Example B: switching mode from live to readonly widens timeout to 300."""
    edited = _edit(**{"mode": "readonly", "publish": False})
    decision = guard(
        SCHEMA,
        BASE,
        edited,
        writable={("mode",), ("publish",)},
    )
    assert decision.verdict == "escalate"
    joined = " ".join(decision.reasons)
    # The flip is visible both as a branch decision change ...
    assert "branch_flip" in joined
    assert "'then' -> 'else'" in joined or "'else' -> 'then'" in joined


def test_witness_finds_other_path_permit_change():
    """A witness is a concrete value at an untouched path that flips."""
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "integer"},
            "b": {"type": "integer"},
        },
        "dependentSchemas": {"a": {"properties": {"b": {"maximum": 5}}}},
    }
    base = {"a": 1, "b": 3}
    edited = {"a": 1, "b": 9}  # invalid while ``a`` exists, so a plain reject
    assert guard(schema, base, edited, {("b",)}).verdict == "reject"

    removed = {"b": 3}
    decision = guard(schema, base, removed, {("a",)})
    assert decision.verdict == "escalate"
    assert any("presence_dependency" in reason for reason in decision.reasons)


def test_dependent_schema_permission_witness():
    """The witness names the widened field, not just the branch that moved."""
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "integer"},
            "b": {"type": "integer"},
        },
        "dependentSchemas": {"a": {"properties": {"b": {"maximum": 5}}}},
    }
    base = {"a": 1, "b": 3}
    edited = {"b": 3}
    decision = guard(schema, base, edited, {("a",)})
    witnesses = {tuple(w["path"]): w for w in decision.witnesses}
    assert ("b",) in witnesses
    assert witnesses[("b",)]["old_valid"] is False
    assert witnesses[("b",)]["new_valid"] is True

    # The branch flip in SCHEMA produces a witness at the widened leaf too.
    flipped = guard(
        SCHEMA,
        BASE,
        _edit(**{"mode": "readonly", "publish": False}),
        {("mode",), ("publish",)},
    )
    by_path = {tuple(w["path"]): w for w in flipped.witnesses}
    assert by_path[("limits", "timeoutSeconds")]["new_valid"] is True
    assert by_path[("limits", "timeoutSeconds")]["value"] == 31


def test_acl_rejects_before_semantics():
    edited = _edit(**{"limits.retries": 2, "publish": False})
    decision = guard(SCHEMA, BASE, edited, {("limits", "retries")})
    assert decision.verdict == "reject"
    assert any("acl_violation" in reason for reason in decision.reasons)


def test_full_validation_still_applied():
    edited = _edit(**{"limits.retries": 99})
    decision = guard(SCHEMA, BASE, edited, {("limits", "retries")})
    assert decision.verdict == "reject"
    assert any("full_validation_failed" in reason for reason in decision.reasons)


def test_static_hazards_escalate():
    schema = {
        "type": "object",
        "properties": {"x": {"type": "integer"}, "y": {"$dynamicRef": "#meta"}},
    }
    decision = guard(schema, {"x": 1}, {"x": 2}, {("x",)})
    assert decision.verdict == "escalate"
    assert any("dynamic_ref" in reason for reason in decision.reasons)


def test_justification_records_reason_but_cannot_bypass_structure():
    edited = _edit(**{"mode": "readonly", "publish": False})
    justification = Justification(
        "Scheduled maintenance window; readonly mode is intended.",
        "oncall@example.test",
        acknowledged=frozenset({"branch_flip", "permission_witness"}),
    )
    decision = review(
        SCHEMA,
        BASE,
        edited,
        writable={("mode",), ("publish",)},
        justification=justification,
    )
    assert decision.verdict == "approved-with-justification"
    assert any("Scheduled maintenance" in reason for reason in decision.reasons)

    structural = review(
        SCHEMA,
        BASE,
        edited,
        writable={("limits", "retries")},
        justification=justification,
    )
    assert structural.verdict == "reject"


def test_change_fingerprint_is_stable_and_content_sensitive():
    edited = _edit(**{"limits.retries": 2})
    first = change_fingerprint(SCHEMA, BASE, edited, {("limits", "retries")})
    second = change_fingerprint(SCHEMA, BASE, edited, {("limits", "retries")})
    assert first["sha256"] == second["sha256"]

    other = change_fingerprint(SCHEMA, BASE, _edit(**{"limits.retries": 3}), {("limits", "retries")})
    assert other["sha256"] != first["sha256"]

def test_local_only_check_would_have_approved_the_branch_flip():
    """The whole point: every changed path passes locally, yet meaning moved.

    This test is the counter-example to a naive "validate just the touched
    leaves" policy.  It must stay failing-safe: the guard escalates.
    """
    from jsonschema import Draft202012Validator

    edited = _edit(**{"mode": "readonly", "publish": False})
    validator = Draft202012Validator(SCHEMA)

    # 1. Every changed leaf is valid under its own unconditional subschema.
    for path, value in [(("mode",), "readonly"), (("publish",), False)]:
        subschemas = local_subschemas(SCHEMA, path)
        assert subschemas
        for subschema in subschemas:
            assert validator.evolve(schema=subschema).is_valid(value), (path, subschema)

    # 2. Even the full new document is valid.
    assert validator.is_valid(edited)

    # 3. But an untouched path gained permission, so a local-only policy is
    #    wrong and the guard must not auto-approve.
    decision = guard(SCHEMA, BASE, edited, {("mode",), ("publish",)})
    assert decision.verdict == "escalate"


def test_naive_local_policy_is_demonstrably_unsafe():
    """Quantify the gap: 31 is rejected before and accepted after."""
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(SCHEMA)
    before = _edit(**{"limits.timeoutSeconds": 31})
    after = copy.deepcopy(before)
    after["mode"] = "readonly"
    after["publish"] = False
    assert validator.is_valid(before) is False
    assert validator.is_valid(after) is True
