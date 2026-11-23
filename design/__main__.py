"""Print the two worked examples from design/README.md.

Usage::

    .venv/bin/python -m design

The output is stable and can be compared against the tables in the README.
"""

from __future__ import annotations

import copy
import json
import sys

from .scoped_edit_guard import Justification, guard, review

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


def show(title, decision):
    print("=" * 60)
    print(title)
    print("verdict:", decision.verdict)
    for reason in decision.reasons:
        print(" -", reason)
    print("metrics:", json.dumps(decision.metrics, sort_keys=True))
    if decision.witnesses:
        print("witnesses:", json.dumps(decision.witnesses, sort_keys=True))


def main() -> int:
    independent = copy.deepcopy(BASE)
    independent["limits"]["retries"] = 2
    show(
        "A. independent edit: limits.retries 1 -> 2",
        guard(SCHEMA, BASE, independent, writable={("limits", "retries")}),
    )

    flipped = copy.deepcopy(BASE)
    flipped["mode"] = "readonly"
    flipped["publish"] = False
    show(
        "B. branch flip: mode live -> readonly",
        guard(
            SCHEMA,
            BASE,
            flipped,
            writable={("mode",), ("publish",)},
        ),
    )

    show(
        "B'. same change with a signed justification",
        review(
            SCHEMA,
            BASE,
            flipped,
            writable={("mode",), ("publish",)},
            justification=Justification(
                "Scheduled maintenance window; readonly mode is intended.",
                "oncall@example.test",
                acknowledged=frozenset({"branch_flip", "permission_witness"}),
            ),
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
