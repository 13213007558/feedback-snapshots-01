"""Machine-local persistence for restricted review data.

The internal record contains config values, normalized-only coordinates and the
raw exception text. It is written to a local file and is intentionally separate
from the public report, which never carries this data.
"""
import json
from typing import Any
from typing import Dict

from .models import ReviewResult


def write_internal_record(result: ReviewResult, path: str) -> str:
    """Persist the full internal record as JSON. Returns the path written."""
    record = result.internal_record()
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write('\n')
    return path


def read_internal_record(path: str) -> Dict[str, Any]:
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)
