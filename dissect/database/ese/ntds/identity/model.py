from __future__ import annotations

from enum import Flag, auto
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.database.ese.ntds.identity.escaping import render_rdn
from dissect.database.ese.ntds.identity.exceptions import PathIssue, PathIssueKind

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import EllipsisType


class ObjectState(Flag):
    """Lifecycle state of an object record within a single snapshot."""

    LIVE = 0
    """A normal, present object."""

    DELETED = auto()
    """A tombstone or recycled object (``isDeleted``)."""

    PHANTOM = auto()
    """A phantom record representing an object that lives in another naming context."""


class ObjectIdentity:
    """Stable, per-record view of an object's identity fields.

    Every field is kept separately so callers can distinguish the in-database locator
    (:attr:`dnt`), the cross-snapshot stable identifier (:attr:`guid`), the mutable naming
    information (:attr:`name` / :attr:`rdn_type`) and the parent reference (:attr:`pdnt`).
    Nothing here is reconstructed or "filled in": a missing value stays :class:`None`.

    Args:
        dnt: Directory Number Tag, the primary key of the row in this specific database.
        pdnt: Parent Directory Number Tag as stored; may reference a missing row.
        guid: The ``objectGUID`` as a :class:`UUID`, if present.
        name: The raw RDN value (``name`` attribute), if present.
        rdn_type: The RDN attribute type (for example ``cn`` or ``dc``), if present.
        state: The lifecycle state of the record.
        ncdnt: The naming context head DNT, if recorded.
        rdn_values: Additional RDN values when the RDN is multi-valued; ``name`` is always
            treated as the primary value.
        raw: The underlying record or fixture object for traceability.
    """

    __slots__ = ("dnt", "guid", "name", "ncdnt", "pdnt", "raw", "rdn_type", "rdn_values", "state")

    def __init__(
        self,
        dnt: int,
        pdnt: int | None,
        guid: UUID | None,
        name: str | None,
        rdn_type: str | None,
        state: ObjectState,
        ncdnt: int | None = None,
        rdn_values: Sequence[str] | None = None,
        raw: Any | None = None,
    ):
        self.dnt = dnt
        self.pdnt = pdnt
        self.guid = guid
        self.name = name
        self.rdn_type = rdn_type
        self.state = state
        self.ncdnt = ncdnt
        self.rdn_values = list(rdn_values or [])
        self.raw = raw

    @property
    def is_live(self) -> bool:
        """Return whether this is a normal, present object (not deleted and not phantom)."""
        return self.state == ObjectState.LIVE

    @property
    def all_rdn_values(self) -> list[str]:
        """Return all RDN values, the primary ``name`` first."""
        if self.name is None:
            return list(self.rdn_values)
        return [self.name, *self.rdn_values]

    @property
    def has_rdn(self) -> bool:
        """Return whether the record carries enough information to render an RDN."""
        return bool(self.rdn_type) and bool(self.all_rdn_values)

    def __repr__(self) -> str:
        flags = "|".join(flag.name for flag in ObjectState if flag and flag in self.state) or "LIVE"
        return (
            f"ObjectIdentity(dnt={self.dnt}, pdnt={self.pdnt}, guid={self.guid}, "
            f"rdn={self.rdn_type}={self.name!r}, state={flags})"
        )


class PathSegment:
    """One resolved hop of a parent chain.

    Args:
        dnt: The DNT of the object at this hop.
        rdn: The rendered (escaped) RDN string, or :class:`None` when the object has no RDN.
        identity: The full identity record of the object.
    """

    __slots__ = ("dnt", "identity", "rdn")

    def __init__(self, dnt: int, rdn: str | None, identity: ObjectIdentity):
        self.dnt = dnt
        self.rdn = rdn
        self.identity = identity

    def __repr__(self) -> str:
        return f"PathSegment(dnt={self.dnt}, rdn={self.rdn!r})"


class DisplayPath:
    """A displayable directory path together with everything needed to retrace it.

    The path is a presentation artifact, never an identity key. :attr:`segments` preserves the
    exact parent chain (each segment references its :class:`ObjectIdentity`, which retains the
    raw record), so every displayed path can be walked back to its original records.

    Args:
        target_dnt: The DNT the path was requested for.
        segments: Resolved hops, ordered from the target up to the highest reachable ancestor.
        issues: Diagnostics collected while walking the chain.
    """

    __slots__ = ("issues", "segments", "target_dnt")

    def __init__(self, target_dnt: int, segments: Sequence[PathSegment], issues: Sequence[PathIssue]):
        self.target_dnt = target_dnt
        self.segments = list(segments)
        self.issues = list(issues)

    @property
    def is_complete(self) -> bool:
        """Return whether the full chain was resolved without a structural problem.

        A :attr:`PathIssueKind.ROOT_REACHED` marker is informational: ending at the database
        root is the normal terminus, not an incomplete chain.
        """
        return not any(
            issue.kind
            in (
                PathIssueKind.MISSING_PARENT,
                PathIssueKind.MISSING_RDN,
                PathIssueKind.CYCLE,
            )
            for issue in self.issues
        )

    @property
    def has_cycle(self) -> bool:
        """Return whether a parent-chain cycle was detected."""
        return any(issue.kind == PathIssueKind.CYCLE for issue in self.issues)

    @property
    def dnts(self) -> list[int]:
        """Return the DNTs of the resolved chain from target to highest ancestor."""
        return [segment.dnt for segment in self.segments]

    @property
    def distinguished_name(self) -> str:
        """Render the DN string from the resolved segments.

        Segments without an RDN (for example the database root object) are skipped rather than
        producing an empty ``=`` component. The string follows the Active Directory convention
        of target RDN first, then ancestors; :attr:`segments` still stores the full parent
        chain independently so the path can be retraced. When the chain is incomplete the
        returned string still contains every segment that *could* be resolved; callers must
        check :attr:`is_complete` before treating it as a full DN.
        """
        return ",".join(segment.rdn for segment in self.segments if segment.rdn)

    @property
    def dn(self) -> str:
        """Alias for :attr:`distinguished_name`."""
        return self.distinguished_name

    def retraces(self) -> bool:
        """Verify the stored segments actually reproduce the stored parent links.

        Each non-root segment's ``pdnt`` must equal the DNT of the segment above it. This is
        the guarantee that a displayed path can always be checked against the original parent
        chain instead of being trusted as an opaque string.
        """
        for lower, upper in zip(self.segments, self.segments[1:], strict=False):
            if lower.identity.pdnt != upper.dnt:
                return False
        return True

    def __str__(self) -> str:
        return self.distinguished_name

    def __repr__(self) -> str:
        status = "complete" if self.is_complete else "incomplete"
        return f"DisplayPath(dnt={self.target_dnt}, {status}, dn={self.distinguished_name!r})"


def render_identity_rdn(identity: ObjectIdentity) -> tuple[str | None, PathIssue | None]:
    """Render the RDN of an identity record, recording a diagnostic on missing information.

    Args:
        identity: The identity record to render.

    Returns:
        A tuple of the rendered RDN (or :class:`None`) and an optional :class:`PathIssue`.
    """
    if not identity.has_rdn:
        return None, PathIssue(
            PathIssueKind.MISSING_RDN,
            identity.dnt,
            f"object has no usable RDN (rdn_type={identity.rdn_type!r}, name={identity.name!r})",
        )

    rdn = render_rdn(identity.rdn_type, identity.all_rdn_values)
    issue = (
        PathIssue(
            PathIssueKind.MULTI_VALUED_RDN,
            identity.dnt,
            f"RDN contains {len(identity.all_rdn_values)} attribute value assertions",
        )
        if len(identity.all_rdn_values) > 1
        else None
    )
    return rdn, issue


def identity_from_mapping(
    record: Mapping[str, Any],
    *,
    default_state: ObjectState | EllipsisType = ...,
) -> ObjectIdentity:
    """Build an :class:`ObjectIdentity` from a plain mapping (fixtures or generic record views).

    Recognized keys mirror the logical attribute names used by the NTDS object layer. The
    mapping is read defensively so partial fixtures do not require every key.

    Args:
        record: A mapping with any of ``dnt``, ``pdnt``, ``guid``, ``name``, ``rdn_type``,
            ``ncdnt``, ``state``, ``rdn_values`` and ``raw`` keys.
        default_state: Explicit state to assign. When omitted the state is derived from the
            ``is_deleted`` and ``is_phantom`` boolean keys, defaulting to live.

    Returns:
        The constructed identity record.
    """
    guid = record.get("guid")
    if isinstance(guid, str):
        guid = UUID(guid)

    if default_state is not ...:
        state = default_state
    else:
        state = ObjectState.LIVE
        if record.get("is_deleted"):
            state |= ObjectState.DELETED
        if record.get("is_phantom"):
            state |= ObjectState.PHANTOM

    return ObjectIdentity(
        dnt=record["dnt"],
        pdnt=record.get("pdnt"),
        guid=guid,
        name=record.get("name"),
        rdn_type=record.get("rdn_type"),
        state=state,
        ncdnt=record.get("ncdnt"),
        rdn_values=record.get("rdn_values"),
        raw=record.get("raw", record),
    )
