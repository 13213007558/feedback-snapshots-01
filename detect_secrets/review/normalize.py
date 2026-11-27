"""Structured parsing and normalization with faithful source mapping.

The normalized shape is deliberately easy to audit: every scalar leaf becomes
one ``path = value`` row, sorted by path, with same-name fields merged. Because
sorting and merging move rows relative to the input, each normalized entry keeps
the original line/column of every occurrence it was derived from.
"""
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Tuple

import yaml

from .models import NormalizedEntry
from .models import Representation
from .models import SourceLocation


@dataclass(frozen=True)
class RawField:
    """One scalar leaf as located in the original input."""

    logical_path: Tuple[str, ...]
    value: str
    line: int
    column: int


def parse_structured(text: str) -> List[NormalizedEntry]:
    """Parse YAML/JSON text into normalized, source-mapped entries.

    :raises: yaml.YAMLError when the input cannot be structured-parsed.
    """
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    raw_fields = _collect_fields(root, prefix=())
    return _normalize(raw_fields)


def _collect_fields(
    node: yaml.nodes.Node,
    prefix: Tuple[str, ...],
) -> List[RawField]:
    if isinstance(node, yaml.ScalarNode):
        return [
            RawField(
                logical_path=prefix,
                value=str(node.value),
                line=node.start_mark.line + 1,
                column=node.start_mark.column + 1,
            ),
        ]

    if isinstance(node, yaml.SequenceNode):
        output: List[RawField] = []
        for index, child in enumerate(node.value):
            output.extend(_collect_fields(child, prefix + (f'[{index}]',)))
        return output

    if isinstance(node, yaml.MappingNode):
        output = []
        # Iterating node.value (rather than a dict) preserves duplicate keys:
        # same-name pairs are kept here and merged later in _normalize.
        for key_node, value_node in node.value:
            key = str(key_node.value)
            output.extend(_collect_fields(value_node, prefix + (key,)))
        return output

    return []


def _normalize(raw_fields: List[RawField]) -> List[NormalizedEntry]:
    grouped: Dict[Tuple[str, ...], List[RawField]] = {}
    for field in raw_fields:
        grouped.setdefault(field.logical_path, []).append(field)

    entries: List[NormalizedEntry] = []
    for normalized_line, logical_path in enumerate(sorted(grouped), start=1):
        occurrences = grouped[logical_path]
        original_locations = tuple(
            SourceLocation(
                line=occurrence.line,
                column=occurrence.column,
                representation=Representation.ORIGINAL,
                path=occurrence.logical_path,
            )
            for occurrence in occurrences
        )
        entries.append(
            NormalizedEntry(
                logical_path=logical_path,
                value=occurrences[-1].value,
                normalized_line=normalized_line,
                original_locations=original_locations,
                occurrence_count=len(occurrences),
                occurrence_values=tuple(occurrence.value for occurrence in occurrences),
            ),
        )

    return entries


def render_normalized(entries: List[NormalizedEntry]) -> List[str]:
    """Render normalized entries, one row per entry (row number == normalized line)."""
    return [entry.render() for entry in entries]
