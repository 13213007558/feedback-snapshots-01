"""Object identity and path representation for NTDS databases.

Offline investigation results often use the Distinguished Name (DN) as a unique key for directory objects.
That key is unstable: objects get renamed or moved, tombstoned objects linger in ``CN=Deleted Objects`` and
Directory Number Tags (DNT) get reused by new objects. This module gives callers an explicit split between
two things that are easily conflated:

- **In-database location**: the :class:`ObjectIdentity`, keyed by DNT, preserving the raw record, GUID,
  name(s) and parent reference (PDNT) of exactly one record in exactly one database.
- **Displayable directory path**: the :class:`ObjectPath`, a rendered DN-like string that retains the raw
  parent chain it was built from, so every rendered path can be traced back to the original records.

Phantom (cross-domain) and deleted (tombstone) objects are preserved as-is and flagged; they are never
"completed" into normal live objects by fabricating missing names or parent references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping
    from uuid import UUID

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.record import Record

__all__ = [
    "Change",
    "Correlation",
    "LocationCollision",
    "ObjectIdentity",
    "ObjectPath",
    "PathIssue",
    "Snapshot",
    "SnapshotDiff",
    "build_path",
    "escape_rdn",
]

#: DNT values that terminate a parent chain (the database root and the hidden root object)
ROOT_DNTS = (0, 2)


class PathIssue(IntFlag):
    """Diagnostics collected while constructing an :class:`ObjectPath`."""

    NONE = 0
    #: A parent DNT in the chain could not be resolved; the path is partial
    MISSING_PARENT = auto()
    #: The parent chain contains a cycle; traversal was stopped instead of recursing forever
    CYCLE = auto()
    #: An object in the chain has no name or no RDN type
    MISSING_NAME = auto()
    #: An object in the chain is a phantom (cross-domain reference), not a local live object
    PHANTOM = auto()
    #: An object in the chain is deleted (tombstoned)
    DELETED = auto()


class Change(IntFlag):
    """What changed between two correlated identities of the same object."""

    NONE = 0
    #: The (RDN) name changed
    RENAMED = auto()
    #: The parent reference (PDNT) changed
    MOVED = auto()


# Characters that must be escaped in a DN value (RFC 4514 section 2.4)
_RDN_SPECIAL = frozenset(',+"\\<>;=')


def escape_rdn(value: str) -> str:
    """Escape a single RDN value according to RFC 4514.

    Escapes the special characters ``, + " \\ < > ; =``, a leading ``#`` or space, a trailing space
    and any NUL characters.

    Args:
        value: The unescaped RDN value.

    Returns:
        The escaped RDN value, safe to embed in a distinguished name.
    """
    if not value:
        return value

    result = []
    for i, char in enumerate(value):
        if (
            char in _RDN_SPECIAL
            or char == "\x00"
            or (i == 0 and char in (" ", "#"))
            or (i == len(value) - 1 and char == " ")
        ):
            result.append("\\")
        result.append(char)
    return "".join(result)


@dataclass(slots=True)
class ObjectIdentity:
    """The identity of a single object within a single database or snapshot.

    This is the *in-database location* of an object. All fields are preserved separately and reflect the
    raw record; nothing is inferred or fabricated. Phantom and deleted objects keep their flags instead of
    being treated as normal live objects.
    """

    dnt: int
    """Directory Number Tag: the physical location of the record in the database. Reused after deletion."""

    pdnt: int | None
    """Parent DNT: the raw parent reference, kept as-is even if the parent is missing."""

    guid: UUID | None
    """The objectGUID, the only attribute that is stable across renames and moves. May be absent."""

    name: str | None
    """The primary (first) value of the ``name`` attribute, if any."""

    names: tuple[str, ...] = ()
    """All values of the ``name`` attribute, preserving multi-valued information."""

    rdn_type: str | None = None
    """The RDN attribute type (e.g. ``CN``, ``OU``, ``DC``), if known."""

    is_phantom: bool = False
    """Whether the object is a phantom (cross-domain reference)."""

    is_deleted: bool = False
    """Whether the object is deleted (tombstoned)."""

    record: Record | None = None
    """The raw record this identity was derived from, kept for traceability."""

    @classmethod
    def from_object(cls, obj: Object) -> ObjectIdentity:
        """Capture the identity of an :class:`Object`, preserving the raw record, GUID, name(s) and parent reference.

        Args:
            obj: The object to capture the identity of.
        """
        # Use the raw value so multi-valued ``name`` attributes keep all their values
        raw_name = obj.get("name", raw=True)
        if isinstance(raw_name, list):
            names = tuple(str(value) for value in raw_name)
        elif raw_name is None:
            names = ()
        else:
            names = (str(raw_name),)

        try:
            rdn_type = obj.get("RdnType")
        except ValueError:
            # The RDN type references an attribute that is not in the schema; keep nothing rather than guess
            rdn_type = None

        return cls(
            dnt=obj.dnt,
            pdnt=obj.pdnt,
            guid=obj.guid,
            name=names[0] if names else None,
            names=names,
            rdn_type=rdn_type if isinstance(rdn_type, str) else None,
            is_phantom=obj.is_phantom,
            is_deleted=obj.is_deleted,
            record=obj.record,
        )

    def same_object_as(self, other: ObjectIdentity) -> bool:
        """Return whether both identities refer to the same object, based on their GUID."""
        return self.guid is not None and self.guid == other.guid

    def same_location_as(self, other: ObjectIdentity) -> bool:
        """Return whether both identities occupy the same in-database location (DNT).

        Note that this says nothing about object identity: DNTs are reused after deletion.
        """
        return self.dnt == other.dnt


@dataclass(slots=True)
class ObjectPath:
    """A displayable directory path for an object, retaining the raw parent chain it was built from.

    The path is *not* an identity: it is a rendering of the parent references as they exist in one
    database or snapshot. Use :attr:`chain` to trace every rendered segment back to the raw
    :class:`ObjectIdentity` (and through it, the raw record) it came from.
    """

    chain: tuple[ObjectIdentity, ...]
    """The traversed parent chain, leaf first. Every rendered segment maps to one entry here."""

    issues: PathIssue = PathIssue.NONE
    """Diagnostics collected while constructing the path."""

    unresolved_dnt: int | None = None
    """The DNT that could not be resolved (missing parent or cycle entry point), if any."""

    @property
    def identity(self) -> ObjectIdentity | None:
        """Return the identity of the object this path is for (the leaf of the chain)."""
        return self.chain[0] if self.chain else None

    @property
    def complete(self) -> bool:
        """Return whether the path was fully resolved up to the database root without structural issues."""
        return not self.issues & (PathIssue.MISSING_PARENT | PathIssue.CYCLE | PathIssue.MISSING_NAME)

    @property
    def dn(self) -> str:
        """Return the rendered distinguished name.

        Segments with missing names are rendered as ``<?DNT=n>``. Unresolvable tails of the chain are
        rendered as ``<missing:DNT=n>`` or ``<cycle:DNT=n>`` so a partial path is always visibly partial.
        """
        segments = []
        for identity in self.chain:
            if identity.name is None or not identity.rdn_type:
                segments.append(f"<?DNT={identity.dnt}>")
            else:
                segments.append(f"{identity.rdn_type}={escape_rdn(identity.name)}")

        if self.unresolved_dnt is not None:
            if self.issues & PathIssue.CYCLE:
                segments.append(f"<cycle:DNT={self.unresolved_dnt}>")
            elif self.issues & PathIssue.MISSING_PARENT:
                segments.append(f"<missing:DNT={self.unresolved_dnt}>")

        return ",".join(segments)

    def __str__(self) -> str:
        return self.dn


def build_path(
    identities: Mapping[int, ObjectIdentity],
    dnt: int,
    *,
    root_dnts: Iterable[int] = ROOT_DNTS,
) -> ObjectPath:
    """Build an :class:`ObjectPath` for a DNT by iteratively walking parent references.

    The walk is iterative and keeps a visited set: a cyclic parent chain yields an :class:`ObjectPath`
    with :attr:`PathIssue.CYCLE` set instead of exhausting the recursion limit, and a parent DNT that is
    absent from ``identities`` yields :attr:`PathIssue.MISSING_PARENT` with a partial path.

    Args:
        identities: Mapping of DNT to :class:`ObjectIdentity`.
        dnt: The DNT to build the path for.
        root_dnts: DNT values that terminate the walk (the database root objects).
    """
    roots = frozenset(root_dnts)
    chain = []
    issues = PathIssue.NONE
    unresolved_dnt = None
    seen = set()

    current = dnt
    while current not in roots:
        if current in seen:
            issues |= PathIssue.CYCLE
            unresolved_dnt = current
            break
        seen.add(current)

        if (identity := identities.get(current)) is None:
            issues |= PathIssue.MISSING_PARENT
            unresolved_dnt = current
            break

        chain.append(identity)
        if identity.is_phantom:
            issues |= PathIssue.PHANTOM
        if identity.is_deleted:
            issues |= PathIssue.DELETED
        if identity.name is None or not identity.rdn_type:
            issues |= PathIssue.MISSING_NAME

        current = identity.pdnt if identity.pdnt is not None else 0

    return ObjectPath(chain=tuple(chain), issues=issues, unresolved_dnt=unresolved_dnt)


@dataclass(slots=True)
class Correlation:
    """Two identities in different snapshots that refer to the same object (matched by GUID)."""

    old: ObjectIdentity
    new: ObjectIdentity
    changes: Change = Change.NONE

    @property
    def renamed(self) -> bool:
        """Whether the object was renamed between the snapshots."""
        return bool(self.changes & Change.RENAMED)

    @property
    def moved(self) -> bool:
        """Whether the object's parent reference changed between the snapshots."""
        return bool(self.changes & Change.MOVED)

    @property
    def unchanged(self) -> bool:
        """Whether the object's name and parent reference are identical in both snapshots."""
        return self.changes == Change.NONE


@dataclass(slots=True)
class LocationCollision:
    """Two identities that share a DNT but are *different* objects (the DNT was reused).

    This is only a shared in-database location; the identities must not be correlated.
    """

    old: ObjectIdentity
    new: ObjectIdentity


@dataclass(slots=True)
class SnapshotDiff:
    """The result of comparing two :class:`Snapshot` instances."""

    old: Snapshot
    new: Snapshot
    #: Identity pairs matched by GUID; these are the same object in both snapshots
    correlated: list[Correlation] = field(default_factory=list)
    #: Identity pairs sharing a DNT but not a GUID; same location, different object
    collisions: list[LocationCollision] = field(default_factory=list)
    #: Identities only present in the new snapshot
    added: list[ObjectIdentity] = field(default_factory=list)
    #: Identities only present in the old snapshot
    removed: list[ObjectIdentity] = field(default_factory=list)


@dataclass(slots=True)
class Snapshot:
    """An offline snapshot of object identities from one NTDS database.

    A snapshot maps DNTs to :class:`ObjectIdentity` instances. Displayable paths can be derived with
    :meth:`path`, and two snapshots can be correlated with :meth:`compare`.
    """

    identities: dict[int, ObjectIdentity] = field(default_factory=dict)
    label: str = ""

    @classmethod
    def from_identities(cls, identities: Iterable[ObjectIdentity], *, label: str = "") -> Snapshot:
        """Build a snapshot from an iterable of identities."""
        return cls(identities={identity.dnt: identity for identity in identities}, label=label)

    @classmethod
    def from_database(cls, db: Database, *, label: str = "") -> Snapshot:
        """Capture a snapshot of all objects in a database, including phantom and deleted objects.

        Args:
            db: The database to snapshot.
            label: An optional label to identify the snapshot.
        """
        return cls.from_identities((ObjectIdentity.from_object(obj) for obj in db.data.iter()), label=label)

    def __len__(self) -> int:
        return len(self.identities)

    def __contains__(self, dnt: int) -> bool:
        return dnt in self.identities

    def __iter__(self) -> Iterator[ObjectIdentity]:
        return iter(self.identities.values())

    def identity(self, dnt: int) -> ObjectIdentity | None:
        """Return the identity for a DNT, if present in this snapshot."""
        return self.identities.get(dnt)

    def path(self, dnt: int) -> ObjectPath:
        """Build the displayable path for a DNT, with diagnostics for incomplete or cyclic parent chains."""
        return build_path(self.identities, dnt)

    def compare(self, other: Snapshot) -> SnapshotDiff:
        """Compare this snapshot (old) with another snapshot (new).

        Correlation is by GUID only: a shared GUID means the same object, and differences in name or
        parent reference are reported as renames and moves. A shared DNT with a *different* GUID means
        the DNT was reused; those pairs are reported as location collisions, never as correlations.
        Identities without a GUID cannot be correlated and end up in ``added``/``removed``.

        Args:
            other: The newer snapshot to compare against.
        """
        old_by_guid = {identity.guid: identity for identity in self.identities.values() if identity.guid is not None}
        new_by_guid = {identity.guid: identity for identity in other.identities.values() if identity.guid is not None}

        correlated = []
        matched_old: set[int] = set()
        matched_new: set[int] = set()
        for guid, old_identity in old_by_guid.items():
            if (new_identity := new_by_guid.get(guid)) is None:
                continue

            changes = Change.NONE
            if old_identity.name != new_identity.name:
                changes |= Change.RENAMED
            if old_identity.pdnt != new_identity.pdnt:
                changes |= Change.MOVED

            correlated.append(Correlation(old=old_identity, new=new_identity, changes=changes))
            matched_old.add(old_identity.dnt)
            matched_new.add(new_identity.dnt)

        removed = sorted(
            (identity for identity in self.identities.values() if identity.dnt not in matched_old),
            key=lambda identity: identity.dnt,
        )
        added = sorted(
            (identity for identity in other.identities.values() if identity.dnt not in matched_new),
            key=lambda identity: identity.dnt,
        )

        added_by_dnt = {identity.dnt: identity for identity in added}
        collisions = [
            LocationCollision(old=old_identity, new=added_by_dnt[old_identity.dnt])
            for old_identity in removed
            if old_identity.dnt in added_by_dnt
        ]

        return SnapshotDiff(
            old=self,
            new=other,
            correlated=sorted(correlated, key=lambda correlation: correlation.old.dnt),
            collisions=collisions,
            added=added,
            removed=removed,
        )
