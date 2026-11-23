"""
Produce the compliance-facing classification reports for the sample orders.

Run from the repository root with::

    python examples/classification/report.py
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema.classification import classify

HERE = Path(__file__).parent
CASES = (
    ("retail-order", "schema.json", "retail-order.json"),
    ("wholesale-order", "schema.json", "wholesale-order.json"),
    ("conflict-order", "conflict-schema.json", "conflict-order.json"),
    ("invalid-order", "schema.json", "invalid-order.json"),
)


def load(name):
    return json.loads((HERE / name).read_text())


def main():
    reports = HERE / "reports"
    reports.mkdir(exist_ok=True)
    for name, schema_name, instance_name in CASES:
        result = classify(load(instance_name), load(schema_name))
        document = result.to_dict()
        destination = reports / f"{name}.json"
        destination.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        )
        summary = document["classification"]["summary"]
        print(
            f"{name}: valid={document['valid']} "
            f"status={document['classification']['status']} "
            f"fields={summary['field_count']} "
            f"conflicts={summary['conflict_count']} "
            f"highest={summary['highest_level']}",
        )


if __name__ == "__main__":
    main()
