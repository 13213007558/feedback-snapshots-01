from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, auto
from typing import TYPE_CHECKING

from dissect.database.ese.ntds.identity.model import ObjectState

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.identity.model import DisplayPath, ObjectIdentity
    from dissect.database.ese.ntds.identity.snapshot import Snapshot


class RelationKind(IntEnum):
    """Outcome of trying to relate a record in the old snapshot to one in the new snapshot."""

    SAME = auto()
    """Same GUID, same DNT and unchanged display path."""

    RENAMED = auto()
    """Same GUID; the RDN (name or RDN type) changed."""

    MOVED = auto()
    """Same GUID; the parent chain changed while the RDN stayed the same."""

    RENAMED_AND_MOVED = auto()
    """Same GUID; both the RDN and the parent chain changed."""

    DNT_REUSED = auto()
    """Same DNT in both snapshots but a different GUID: the row slot was reclaimed."""

    STATE_CHANGED = auto()
    """Same GUID but the lifecycle state changed (for example live to deleted)."""

    DISAPPEARED = auto()
    """GUID present in the old snapshot has no counterpart in the new one."""

    APPEARED = auto()
    """GUID in the new snapshot has no counterpart in the old one."""

    POSITION_ONLY = auto()
    """Different objects (no GUID link) that currently sit at the same display path."""


@dataclass(frozen=True)
class Relation:
    """A single finding from a two-snapshot comparison.

    Display paths are carried as full :class:`DisplayPath` objects on both sides so every
    finding can be retraced through the original parent chains rather than trusted as strings.
    """

    kind: RelationKind
    old: ObjectIdentity | None
    new: ObjectIdentity | None
    old_path: DisplayPath | None
    new_path: DisplayPath | None
    detail: str

    def __str__(self) -> str:
        left = f"DNT{self.old.dnt}" if self.old else "<absent>"
        right = f"DNT{self.new.dnt}" if self.new else "<absent>"
        return f"[{self.kind.name}] {left} -> {right}: {self.detail}"


@dataclass(frozen=True)
class SnapshotComparison:
    """The full result set of comparing an old snapshot against a new one."""

    old_label: str
    new_label: str
    relations: tuple[Relation, ...]

    def of_kind(self, kind: RelationKind) -> tuple[Relation, ...]:
        """Return only the findings of a given kind."""
        return tuple(relation for relation in self.relations if relation.kind == kind)

    def __iter__(self) -> Iterator[Relation]:
        return iter(self.relations)


def _classify_guid_pair(
    old: ObjectIdentity,
    new: ObjectIdentity,
    old_path: DisplayPath,
    new_path: DisplayPath,
) -> RelationKind:
    if old.state != new.state:
        return RelationKind.STATE_CHANGED

    # Rename is defined purely on the object's own RDN. A rename also changes the rendered DN
    # string, so the move check must look at the stored parent link instead of the full path.
    renamed = (old.rdn_type, old.all_rdn_values) != (new.rdn_type, new.all_rdn_values)
    moved = old.pdnt != new.pdnt

    if renamed and moved:
        return RelationKind.RENAMED_AND_MOVED
    if renamed:
        return RelationKind.RENAMED
    if moved:
        return RelationKind.MOVED
    return RelationKind.SAME


def compare_snapshots(old: Snapshot, new: Snapshot) -> SnapshotComparison:
    """Compare two small snapshots using GUID identity, never DNT identity.

    Rules:

    - Records sharing a GUID are the same logical object even when their DNT, name or parent
      changed. The finding is classified accordingly.
    - A DNT that points to different GUIDs on each side is reported as :attr:`DNT_REUSED`;
      the two objects are not related.
    - Deleted and phantom records keep their state and are never treated as normal live
      objects; a live/deleted transition is a state change, not a rename.
    - Objects with no GUID-based link that merely share a display path are reported separately
      as :attr:`POSITION_ONLY`.

    Args:
        old: The earlier snapshot.
        new: The later snapshot.

    Returns:
        A :class:`SnapshotComparison` covering every record on both sides.
    """
    relations: list[Relation] = []

    old_guid_index = old.by_guid()
    new_guid_index = new.by_guid()

    # Rows with a real identity link (GUID pair or proven DNT reuse). These are excluded from
    # weaker position-only matching; rows only claimed by appear/disappear remain candidates.
    paired_old: set[int] = set()
    paired_new: set[int] = set()

    # Pass 1: DNT slot analysis. A DNT shared across snapshots that holds two different GUIDs
    # is a reused row slot. These rows are claimed first so they are not also reported as an
    # appear/disappear pair of unrelated objects.
    reused_pairs: list[tuple[ObjectIdentity, ObjectIdentity]] = []
    for old_identity in old.identities():
        new_identity = new.get(old_identity.dnt)
        if (
            new_identity is not None
            and old_identity.guid is not None
            and new_identity.guid is not None
            and old_identity.guid != new_identity.guid
        ):
            reused_pairs.append((old_identity, new_identity))
            paired_old.add(old_identity.dnt)
            paired_new.add(new_identity.dnt)

    # Pass 2: GUID correlation for every GUID visible on either side.
    all_guids = set(old_guid_index) | set(new_guid_index)
    for guid in sorted(all_guids, key=str):
        old_records = old_guid_index.get(guid, [])
        new_records = new_guid_index.get(guid, [])
        for index in range(max(len(old_records), len(new_records))):
            old_identity = old_records[index] if index < len(old_records) else None
            new_identity = new_records[index] if index < len(new_records) else None
            if (old_identity and old_identity.dnt in paired_old) or (new_identity and new_identity.dnt in paired_new):
                continue
            old_path = old.path(old_identity.dnt) if old_identity else None
            new_path = new.path(new_identity.dnt) if new_identity else None

            if old_identity and new_identity:
                paired_old.add(old_identity.dnt)
                paired_new.add(new_identity.dnt)
                kind = _classify_guid_pair(old_identity, new_identity, old_path, new_path)
                detail = _guid_detail(kind, old_identity, new_identity, old_path, new_path)
            elif old_identity:
                kind = RelationKind.DISAPPEARED
                detail = f"GUID {guid} has no object in {new.label}"
            else:
                kind = RelationKind.APPEARED
                detail = f"GUID {guid} has no object in {old.label}"

            relations.append(Relation(kind, old_identity, new_identity, old_path, new_path, detail))

    # Pass 3: emit the reused-slot findings with their retraced display paths.
    for old_identity, new_identity in reused_pairs:
        relations.append(
            Relation(
                RelationKind.DNT_REUSED,
                old_identity,
                new_identity,
                old.path(old_identity.dnt),
                new.path(new_identity.dnt),
                (
                    f"DNT {old_identity.dnt} held GUID {old_identity.guid} in {old.label} "
                    f"but GUID {new_identity.guid} in {new.label}"
                ),
            )
        )

    _add_position_only(old, new, paired_old, paired_new, relations)

    return SnapshotComparison(old.label, new.label, tuple(relations))


def _add_position_only(
    old: Snapshot,
    new: Snapshot,
    claimed_old: set[int],
    claimed_new: set[int],
    relations: list[Relation],
) -> None:
    new_by_path: dict[str, list[ObjectIdentity]] = {}
    for identity in new.identities():
        if identity.dnt in claimed_new or not identity.is_live or identity.guid is None:
            continue
        path = new.path(identity.dnt)
        if path.is_complete:
            new_by_path.setdefault(path.dn, []).append(identity)

    for old_identity in old.identities():
        if old_identity.dnt in claimed_old or not old_identity.is_live or old_identity.guid is None:
            continue
        old_path = old.path(old_identity.dnt)
        if not old_path.is_complete:
            continue
        relations.extend(
            Relation(
                RelationKind.POSITION_ONLY,
                old_identity,
                new_identity,
                old_path,
                new.path(new_identity.dnt),
                (
                    f"unrelated objects share display path {old_path.dn!r}; "
                    f"GUIDs {old_identity.guid} and {new_identity.guid} do not match"
                ),
            )
            for new_identity in new_by_path.get(old_path.dn, [])
        )


def _guid_detail(
    kind: RelationKind,
    old: ObjectIdentity,
    new: ObjectIdentity,
    old_path: DisplayPath,
    new_path: DisplayPath,
) -> str:
    if kind == RelationKind.STATE_CHANGED:
        return f"state changed {_state_name(old.state)} -> {_state_name(new.state)} (same GUID {old.guid})"
    if kind == RelationKind.SAME:
        return f"same object at DNT {old.dnt}, path unchanged"
    changes: list[str] = []
    if kind in (RelationKind.RENAMED, RelationKind.RENAMED_AND_MOVED):
        changes.append(f"RDN {old.rdn_type}={old.name!r} -> {new.rdn_type}={new.name!r}")
    if kind in (RelationKind.MOVED, RelationKind.RENAMED_AND_MOVED):
        changes.append(f"parent DNT {old.pdnt} -> {new.pdnt}")
    changes.append(f"DNT {old.dnt} -> {new.dnt}" if old.dnt != new.dnt else f"DNT {old.dnt} retained")
    return "; ".join(changes) + f" (same GUID {old.guid})"


def _state_name(state: ObjectState) -> str:
    return "|".join(flag.name for flag in ObjectState if flag and flag in state) or "LIVE"
