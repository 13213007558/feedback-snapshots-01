from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.identity.compare import Relation, RelationKind, SnapshotComparison

if TYPE_CHECKING:
    from dissect.database.ese.ntds.identity.model import DisplayPath, ObjectIdentity, ObjectState


_RELATION_HEADERS = {
    RelationKind.SAME: "Identical objects (same GUID, same path)",
    RelationKind.RENAMED: "Renamed objects (same GUID, new RDN)",
    RelationKind.MOVED: "Moved objects (same GUID, new parent)",
    RelationKind.RENAMED_AND_MOVED: "Renamed and moved objects (same GUID)",
    RelationKind.STATE_CHANGED: "Objects with a lifecycle state change",
    RelationKind.DNT_REUSED: "Reused DNT slots (different GUID, not the same object)",
    RelationKind.POSITION_ONLY: "Position-only matches (different GUID, same display path)",
    RelationKind.DISAPPEARED: "Objects only in the old snapshot",
    RelationKind.APPEARED: "Objects only in the new snapshot",
}

# Presentation order tells the correlation story before the weaker position-only evidence.
_RELATION_ORDER = (
    RelationKind.RENAMED,
    RelationKind.MOVED,
    RelationKind.RENAMED_AND_MOVED,
    RelationKind.STATE_CHANGED,
    RelationKind.DNT_REUSED,
    RelationKind.POSITION_ONLY,
    RelationKind.SAME,
    RelationKind.DISAPPEARED,
    RelationKind.APPEARED,
)


def render_comparison(comparison: SnapshotComparison) -> str:
    """Render a human-readable report that keeps identity and display paths separate.

    Each finding shows the GUID-based correlation (or explicit lack of it) and both display
    paths with their completion status, so a reader can retrace every path to its records.

    Args:
        comparison: The result of :func:`compare_snapshots`.

    Returns:
        A formatted, newline-separated report.
    """
    lines = [f"Comparison: {comparison.old_label} -> {comparison.new_label}"]

    for kind in _RELATION_ORDER:
        relations = comparison.of_kind(kind)
        if not relations:
            continue
        lines.extend(("", f"== {_RELATION_HEADERS[kind]} ({len(relations)}) =="))
        for relation in relations:
            lines.extend(_render_relation(relation))

    return "\n".join(lines)


def _render_relation(relation: Relation) -> list[str]:
    lines = [f"- {relation.detail}"]
    if relation.old is not None:
        lines.append(f"    old: {_describe(relation.old, relation.old_path)}")
    if relation.new is not None:
        lines.append(f"    new: {_describe(relation.new, relation.new_path)}")
    return lines


def _describe(identity: ObjectIdentity, path: DisplayPath) -> str:
    status = "complete" if path.is_complete else f"incomplete ({len(path.issues)} issue(s))"
    chain = " -> ".join(f"DNT{dnt}" for dnt in path.dnts)
    return (
        f"guid={identity.guid} state={_flags(identity.state)} dnt={identity.dnt} "
        f"dn={path.dn!r} [{status}] chain={chain}"
    )


def _flags(state: ObjectState) -> str:
    return "|".join(flag.name for flag in type(state) if flag and flag in state) or "LIVE"
