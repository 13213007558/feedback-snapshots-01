"""Offline group membership tracing for NTDS databases.

This module follows explicit ``member`` links and ``primaryGroupID`` relations without contacting a domain
controller. Paths are annotated with the evidence that proves each step, while unresolved edges, cycles,
foreign security principals and cross-domain boundaries are preserved for explanation.

A recorded membership path is not proof of live effective access: accounts may be disabled, deleted, filtered by
domain trust settings, or constrained by other controls that are not part of the offline NTDS database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.util import sid_domain, sid_for_rid, sid_rid

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.ntds import NTDS
    from dissect.database.ese.ntds.objects import Object

OFFLINE_WARNING = (
    "Membership is derived from offline NTDS link data only. It does not prove that an account currently exists, "
    "is enabled, or has effective permissions in a live domain."
)

OFFLINE_DISCLAIMER = OFFLINE_WARNING

_LOOKUP_ERRORS = (AttributeError, KeyError, KeyNotFoundError, TypeError, ValueError)

__all__ = [
    "OFFLINE_DISCLAIMER",
    "OFFLINE_WARNING",
    "MembershipEdge",
    "MembershipPath",
    "MembershipRelation",
    "MembershipTrace",
    "MembershipTracer",
    "resolve_membership",
    "trace_group_members",
    "trace_memberships",
]


class MembershipRelation(Enum):
    """The kind of evidence that establishes a membership relation."""

    MEMBER = "member"
    """An explicit ``member`` link between a group and a member."""

    PRIMARY_GROUP = "primaryGroupID"
    """A relation inferred from the member's ``primaryGroupID`` and SID scope."""

    FOREIGN_SECURITY_PRINCIPAL = "foreignSecurityPrincipal"
    """A foreign security principal whose external identity cannot be expanded offline."""


@dataclass(frozen=True)
class MembershipEdge:
    """A single, independently provable step in a membership path.

    ``resolved`` means that the relation itself was found in the offline database and both endpoints exist.
    ``expandable`` means that traversal can continue past the target. Foreign security principals, phantom
    (cross-domain) objects and missing link targets are not expandable.
    """

    relation: MembershipRelation
    member: Object | None
    group: Object | None
    member_dnt: int | None = None
    group_dnt: int | None = None
    member_sid: str | None = None
    group_sid: str | None = None
    observed: str = ""
    resolved: bool = True
    expandable: bool = True
    reason: str | None = None

    @property
    def attribute(self) -> str:
        """Return the canonical attribute that defines this relation."""
        return self.relation.value

    @property
    def source(self) -> str:
        """Return the attribute that was observed while tracing this edge."""
        return self.observed or self.attribute

    @property
    def from_object(self) -> Object | None:
        """Return the object at the source end of this edge."""
        return self.member

    @property
    def to_object(self) -> Object | None:
        """Return the object at the target end of this edge."""
        return self.group

    @property
    def target(self) -> Object | None:
        """Return the target object of this relation (the group for upward traces)."""
        return self.group

    @property
    def evidence(self) -> str:
        """Return the attribute that proves this edge."""
        return self.source

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this edge."""
        return {
            "relation": self.relation.value,
            "observed": self.source,
            "resolved": self.resolved,
            "expandable": self.expandable,
            "reason": self.reason,
            "member": _object_ref(self.member, sid=self.member_sid, dnt=self.member_dnt),
            "group": _object_ref(self.group, sid=self.group_sid, dnt=self.group_dnt),
        }


@dataclass(frozen=True)
class MembershipPath:
    """An ordered chain of membership edges.

    For an upward trace the first edge starts at the account and moves towards containing groups. For a downward
    trace the first edge starts at a group and moves towards its members.
    """

    edges: tuple[MembershipEdge, ...]
    direction: str = "up"

    def __iter__(self) -> Iterator[MembershipEdge]:
        """Iterate over the edges of this path."""
        return iter(self.edges)

    def __len__(self) -> int:
        """Return the number of edges in this path."""
        return len(self.edges)

    @property
    def start(self) -> Object | None:
        """Return the object the path starts at."""
        if not self.edges:
            return None
        return self.edges[0].member if self.direction == "up" else self.edges[0].group

    @property
    def end(self) -> Object | None:
        """Return the object the path ends at."""
        if not self.edges:
            return None
        return self.edges[-1].group if self.direction == "up" else self.edges[-1].member

    @property
    def principal(self) -> Object | None:
        """Return the object the path starts at."""
        return self.start

    @property
    def member(self) -> Object | None:
        """Return the member end of this path."""
        return self.start if self.direction == "up" else self.end

    @property
    def group(self) -> Object | None:
        """Return the group end of this path."""
        return self.end if self.direction == "up" else self.start

    @property
    def member_sid(self) -> str | None:
        """Return the SID of the member end of this path, even when the object is missing."""
        if not self.edges:
            return None
        return self.edges[0].member_sid if self.direction == "up" else self.edges[-1].member_sid

    @property
    def group_sid(self) -> str | None:
        """Return the SID of the group end of this path, even when the object is missing."""
        if not self.edges:
            return None
        return self.edges[-1].group_sid if self.direction == "up" else self.edges[0].group_sid

    @property
    def locally_proven(self) -> bool:
        """Return whether every edge relation was found in the offline database."""
        return all(edge.resolved for edge in self.edges)

    @property
    def expandable(self) -> bool:
        """Return whether every edge could be expanded past its target."""
        return all(edge.expandable for edge in self.edges)

    @property
    def resolved(self) -> bool:
        """Return whether this path is fully proven and expandable."""
        return self.locally_proven and self.expandable

    @property
    def steps(self) -> tuple[MembershipEdge, ...]:
        """Return the edges of this path."""
        return self.edges

    @property
    def objects(self) -> tuple[Object | None, ...]:
        """Return the objects visited by this path, including the start and end."""
        if not self.edges:
            return ()

        if self.direction == "up":
            return (self.edges[0].member, *(edge.group for edge in self.edges))
        return (self.edges[0].group, *(edge.member for edge in self.edges))

    @property
    def sids(self) -> tuple[str | None, ...]:
        """Return the SIDs visited by this path, including unresolved endpoints."""
        if not self.edges:
            return ()

        if self.direction == "up":
            return (self.edges[0].member_sid, *(edge.group_sid for edge in self.edges))
        return (self.edges[0].group_sid, *(edge.member_sid for edge in self.edges))

    @property
    def relations(self) -> tuple[MembershipRelation, ...]:
        """Return the relation type of every edge."""
        return tuple(edge.relation for edge in self.edges)

    @property
    def sources(self) -> tuple[str, ...]:
        """Return the canonical attribute of every edge."""
        return tuple(edge.attribute for edge in self.edges)

    @property
    def observed_sources(self) -> tuple[str, ...]:
        """Return the attributes that were actually observed for every edge."""
        return tuple(edge.source for edge in self.edges)

    @property
    def source(self) -> str:
        """Return the attribute evidence for this path as a readable chain."""
        return " -> ".join(self.observed_sources)

    @property
    def provenance(self) -> tuple[str, ...]:
        """Return the attributes that prove this path."""
        return self.observed_sources

    @property
    def evidence(self) -> tuple[str, ...]:
        """Return the attributes that prove this path."""
        return self.observed_sources

    @property
    def kind(self) -> str:
        """Return a label describing the evidence used by this path."""
        relations = set(self.relations)
        if relations == {MembershipRelation.MEMBER}:
            return "explicit_member"
        if relations == {MembershipRelation.PRIMARY_GROUP}:
            return "primaryGroupID"
        if MembershipRelation.FOREIGN_SECURITY_PRINCIPAL in relations:
            return "foreign_security_principal"
        return "mixed"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this path."""
        return {
            "direction": self.direction,
            "kind": self.kind,
            "locally_proven": self.locally_proven,
            "expandable": self.expandable,
            "resolved": self.resolved,
            "member": _object_ref(self.member),
            "member_sid": self.member_sid,
            "group": _object_ref(self.group),
            "group_sid": self.group_sid,
            "steps": [edge.to_dict() for edge in self.edges],
        }


@dataclass
class MembershipTrace:
    """The result of tracing membership relations for one principal or group.

    Confirmed paths only describe relations proven by the offline database. They are not evidence of live effective
    permissions. Unresolved edges, cycles and foreign identities are kept explicitly so a caller can explain which
    parts of the graph could not be expanded.
    """

    principal: Object | None
    direction: str
    paths: list[MembershipPath] = field(default_factory=list)
    unresolved_edges: list[MembershipEdge] = field(default_factory=list)
    cycles: list[tuple[str, ...]] = field(default_factory=list)
    duplicates: list[MembershipPath] = field(default_factory=list)
    foreign_principals: list[Object] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    max_depth_reached: bool = False

    def __iter__(self) -> Iterator[MembershipPath]:
        """Iterate over all paths, including incomplete paths."""
        return iter(self.paths)

    def __len__(self) -> int:
        """Return the number of paths."""
        return len(self.paths)

    @property
    def confirmed_paths(self) -> list[MembershipPath]:
        """Return the fully proven and expandable paths."""
        return [path for path in self.paths if path.resolved]

    @property
    def incomplete_paths(self) -> list[MembershipPath]:
        """Return the paths that hit a missing target, foreign boundary, cycle or depth limit."""
        return [path for path in self.paths if not path.resolved]

    @property
    def locally_proven_paths(self) -> list[MembershipPath]:
        """Return the paths whose edge relations were all found in the offline database."""
        return [path for path in self.paths if path.locally_proven]

    @property
    def memberships(self) -> list[MembershipPath]:
        """Return all membership paths, including incomplete ones."""
        return self.paths

    @property
    def unresolved(self) -> list[MembershipEdge]:
        """Return all unresolved edges."""
        return self.unresolved_edges

    @property
    def unresolved_paths(self) -> list[MembershipPath]:
        """Return all incomplete paths."""
        return self.incomplete_paths

    def by_group_sid(self) -> dict[str, list[MembershipPath]]:
        """Group all paths by the SID at the group end of the path."""
        result: dict[str, list[MembershipPath]] = {}
        for path in self.paths:
            if (sid := path.group_sid) is not None:
                result.setdefault(sid, []).append(path)
        return result

    def by_group(self) -> dict[str, list[MembershipPath]]:
        """Group all paths by group name, falling back to the group SID."""
        result: dict[str, list[MembershipPath]] = {}
        for path in self.paths:
            key = _name(path.group) or path.group_sid or "<unknown>"
            result.setdefault(key, []).append(path)
        return result

    @property
    def complete(self) -> bool:
        """Return whether the offline expansion completed without known gaps."""
        return not self.unresolved_edges and not self.cycles and not self.gaps and not self.max_depth_reached

    def explain(self) -> list[str]:
        """Return a human-readable explanation of confirmed paths and unknown parts."""
        lines = [f"confirmed: {_describe_path(path)} via {path.source}" for path in self.confirmed_paths]
        lines += [
            f"incomplete: {_describe_path(path)} "
            f"({(path.edges[-1].reason if path.edges else None) or 'unknown boundary'})"
            for path in self.incomplete_paths
        ]
        lines += [f"cycle: {' -> '.join(cycle)}" for cycle in self.cycles]
        lines += [f"gap: {gap}" for gap in self.gaps]
        if self.max_depth_reached:
            lines.append("gap: maximum traversal depth reached")
        if not self.complete:
            lines.append(
                "note: offline cross-domain expansion is incomplete; do not treat this as live effective access"
            )
        return lines

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable explanation of confirmed and unknown parts."""
        return {
            "principal": _object_ref(self.principal),
            "direction": self.direction,
            "offline": True,
            "warning": OFFLINE_WARNING,
            "complete": self.complete,
            "confirmed_paths": [path.to_dict() for path in self.confirmed_paths],
            "locally_proven_paths": [path.to_dict() for path in self.locally_proven_paths],
            "incomplete_paths": [path.to_dict() for path in self.incomplete_paths],
            "unresolved_edges": [edge.to_dict() for edge in self.unresolved_edges],
            "cycles": [list(cycle) for cycle in self.cycles],
            "duplicates": [path.to_dict() for path in self.duplicates],
            "foreign_principals": [_object_ref(obj) for obj in self.foreign_principals],
            "gaps": list(self.gaps),
            "explanation": self.explain(),
            "notes": list(self.notes),
        }


class MembershipTracer:
    """Trace group membership relations using only the offline NTDS database.

    Args:
        target: An :class:`~dissect.database.ese.ntds.ntds.NTDS` instance, a
            :class:`~dissect.database.ese.ntds.database.Database` instance, or a small compatible object graph.
        objects: Optional explicit object collection for fixtures or synthetic graphs. When provided, objects are
            indexed by DNT and SID and used for SID lookups instead of the database.
    """

    def __init__(self, target: NTDS | Database | None = None, *, objects: Sequence[Object] | None = None) -> None:
        if target is None and objects is None:
            raise TypeError("MembershipTracer requires a database or an explicit object collection")

        db = getattr(target, "db", target)
        if db is not None and not hasattr(db, "data"):
            raise TypeError("target does not look like an NTDS database")

        self.db: Database | None = db
        self._source = _NTDSSource(db, objects=objects)

    def primary_group(self, member: Object) -> tuple[str | None, Object | None]:
        """Return the expected primary group SID and matching object for a member.

        The expected SID is constructed within the member's own SID scope. A missing target is returned as
        ``(expected_sid, None)`` rather than falling back to a RID match in another domain.

        Args:
            member: The account whose ``primaryGroupID`` should be resolved.
        """
        return self._source.primary_group(member)

    def resolve_sid(self, sid: str | None) -> Object | None:
        """Resolve a SID to an object in the offline database.

        Args:
            sid: The SID to resolve.

        Returns:
            The matching object, or ``None`` if it is not present.
        """
        return self._source.get_sid(sid)

    def trace(self, principal: Object, *, direction: str = "up", max_depth: int = 64) -> MembershipTrace:
        """Trace membership relations for a principal.

        Args:
            principal: The account or group to start from.
            direction: ``"up"`` (default) follows membership towards containing groups. ``"down"`` follows a group
                towards its members.
            max_depth: Maximum number of edges in a single path.

        Returns:
            A :class:`MembershipTrace` containing every provable path and every unresolved edge or cycle encountered.
        """
        if direction not in ("up", "down"):
            raise ValueError(f"Unsupported membership direction: {direction!r}")
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")

        trace = MembershipTrace(principal=principal, direction=direction)
        trace.notes.append(OFFLINE_WARNING)

        if (reason := _foreign_reason(principal)) is not None:
            _add_foreign(trace, principal)
            if _is_foreign_security_principal(principal):
                _add_unresolved(
                    trace,
                    MembershipEdge(
                        relation=MembershipRelation.FOREIGN_SECURITY_PRINCIPAL,
                        member=principal,
                        group=None,
                        member_dnt=_dnt(principal),
                        member_sid=_sid(principal),
                        observed="objectSid",
                        resolved=False,
                        expandable=False,
                        reason=reason,
                    ),
                )
            else:
                _add_gap(trace, f"start object cannot be expanded offline: {reason}")
            trace.notes.append(f"Started from a non-expandable principal: {reason}")

        self._walk(trace, principal, direction=direction, max_depth=max_depth)

        if not trace.paths:
            trace.notes.append(
                "No membership relations were found in the offline data; this is not proof that no membership exists."
            )

        return trace

    def trace_groups(self, principal: Object, *, max_depth: int = 64) -> MembershipTrace:
        """Trace an account towards every containing group (an upward trace).

        Args:
            principal: The account to start from.
            max_depth: Maximum number of edges in a single path.
        """
        return self.trace(principal, direction="up", max_depth=max_depth)

    def trace_members(self, group: Object, *, max_depth: int = 64) -> MembershipTrace:
        """Trace a group towards its members, including nested groups (a downward trace).

        Args:
            group: The group to start from.
            max_depth: Maximum number of edges in a single path.
        """
        return self.trace(group, direction="down", max_depth=max_depth)

    def paths(self, principal: Object, *, direction: str = "up", max_depth: int = 64) -> list[MembershipPath]:
        """Return every membership path for a principal.

        Args:
            principal: The account or group to start from.
            direction: ``"up"`` or ``"down"``.
            max_depth: Maximum number of edges in a single path.
        """
        return self.trace(principal, direction=direction, max_depth=max_depth).paths

    def membership_paths(
        self, principal: Object, *, direction: str = "up", max_depth: int = 64
    ) -> list[MembershipPath]:
        """Return every membership path for a principal.

        Args:
            principal: The account or group to start from.
            direction: ``"up"`` or ``"down"``.
            max_depth: Maximum number of edges in a single path.
        """
        return self.paths(principal, direction=direction, max_depth=max_depth)

    def resolve(self, principal: Object, *, direction: str = "up", max_depth: int = 64) -> MembershipTrace:
        """Trace membership relations for a principal.

        Args:
            principal: The account or group to start from.
            direction: ``"up"`` or ``"down"``.
            max_depth: Maximum number of edges in a single path.
        """
        return self.trace(principal, direction=direction, max_depth=max_depth)

    def _walk(self, trace: MembershipTrace, start: Object, *, direction: str, max_depth: int) -> None:
        start_id = _identity(start)
        # Depth-first so that answers keep a stable, explainable order.
        stack: list[tuple[Object, tuple[MembershipEdge, ...], tuple[str, ...]]] = [(start, (), (start_id,))]
        seen_paths: set[tuple[tuple[str, str, str, str], ...]] = set()

        while stack:
            current, edges, visited = stack.pop()
            self._check_scope(trace, current, direction)
            if len(edges) >= max_depth:
                trace.max_depth_reached = True
                trace.notes.append(f"Maximum membership depth of {max_depth} reached at {_identity(current)}.")
                continue

            found = False
            for edge in self._edges(current, direction):
                found = True
                next_edges = (*edges, edge)
                next_edges_key = _path_key(next_edges)

                if next_edges_key in seen_paths:
                    trace.duplicates.append(MembershipPath(next_edges, direction))
                    continue
                seen_paths.add(next_edges_key)

                next_object = edge.group if direction == "up" else edge.member

                if not edge.resolved:
                    trace.paths.append(MembershipPath(next_edges, direction))
                    _add_unresolved(trace, edge)
                    _register_foreign(trace, edge.member, edge.group)
                    continue

                if not edge.expandable:
                    trace.paths.append(MembershipPath(next_edges, direction))
                    _add_unresolved(trace, edge)
                    _register_foreign(trace, edge.member, edge.group)
                    continue

                if next_object is None:
                    # Defensive: a resolved edge must have a target object.
                    unresolved = _replace_edge(edge, resolved=False, expandable=False, reason="missing target object")
                    trace.paths.append(MembershipPath((*edges, unresolved), direction))
                    _add_unresolved(trace, unresolved)
                    continue

                next_id = _identity(next_object)
                if next_id in visited:
                    # The relation itself is provable, but the cycle cannot be expanded further.
                    cycle_edge = _replace_edge(
                        edge,
                        expandable=False,
                        reason=f"group cycle detected: {' -> '.join((*visited, next_id))}",
                    )
                    trace.paths.append(MembershipPath((*edges, cycle_edge), direction))
                    trace.cycles.append((*visited, next_id))
                    _add_unresolved(trace, cycle_edge)
                    continue

                trace.paths.append(MembershipPath(next_edges, direction))

                if direction == "up" or _is_group(next_object):
                    stack.append((next_object, next_edges, (*visited, next_id)))

            if not found and edges and _foreign_reason(current) is not None:
                _add_foreign(trace, current)

    def _check_scope(self, trace: MembershipTrace, current: Object, direction: str) -> None:
        """Record relations that cannot be evaluated because a SID scope or DNT is missing."""
        if _dnt(current) is None:
            _add_gap(
                trace,
                f"{_identity(current)} has no DNT; its {direction} membership links cannot be read offline",
            )

        if direction == "up" and _primary_group_id(current) is not None and sid_domain(_sid(current)) is None:
            _add_gap(
                trace,
                f"{_identity(current)} has primaryGroupID but no usable SID; the primary group cannot be scoped",
            )

        if direction == "down" and sid_domain(_sid(current)) is None:
            _add_gap(
                trace,
                f"{_identity(current)} has no usable SID; primaryGroupID members cannot be evaluated for it",
            )

    def _edges(self, current: Object, direction: str) -> Iterator[MembershipEdge]:
        if direction == "up":
            yield from self._upward_edges(current)
        else:
            yield from self._downward_edges(current)

    def _upward_edges(self, member: Object) -> Iterator[MembershipEdge]:
        member_dnt = _dnt(member)
        member_sid = _sid(member)

        if member_dnt is not None:
            for group_dnt, group in self._source.explicit_groups(member_dnt):
                reason = None
                if group is None:
                    reason = f"member group target DNT {group_dnt!r} was not found in the offline database"
                yield self._edge(
                    MembershipRelation.MEMBER,
                    member=member,
                    group=group,
                    member_dnt=member_dnt,
                    group_dnt=group_dnt,
                    member_sid=member_sid,
                    group_sid=_sid(group) if group is not None else None,
                    observed="memberOf",
                    missing_reason=reason,
                    boundary_object=group,
                )

        expected_sid, group = self._source.primary_group(member)
        if expected_sid is not None:
            reason = None
            if group is None:
                reason = f"primary group SID {expected_sid!r} from primaryGroupID was not found in the offline database"
            yield self._edge(
                MembershipRelation.PRIMARY_GROUP,
                member=member,
                group=group,
                member_dnt=member_dnt,
                group_dnt=_dnt(group) if group is not None else None,
                member_sid=member_sid,
                group_sid=expected_sid,
                observed="primaryGroupID",
                missing_reason=reason,
                boundary_object=group,
            )

    def _downward_edges(self, group: Object) -> Iterator[MembershipEdge]:
        group_dnt = _dnt(group)
        group_sid = _sid(group)

        if group_dnt is not None:
            for member_dnt, member in self._source.explicit_members(group_dnt):
                reason = None
                if member is None:
                    reason = f"member target DNT {member_dnt!r} was not found in the offline database"
                yield self._edge(
                    MembershipRelation.MEMBER,
                    member=member,
                    group=group,
                    member_dnt=member_dnt,
                    group_dnt=group_dnt,
                    member_sid=_sid(member) if member is not None else None,
                    group_sid=group_sid,
                    observed="member",
                    missing_reason=reason,
                    boundary_object=member,
                )

        for member in self._source.primary_members(group):
            yield self._edge(
                MembershipRelation.PRIMARY_GROUP,
                member=member,
                group=group,
                member_dnt=_dnt(member),
                group_dnt=group_dnt,
                member_sid=_sid(member),
                group_sid=group_sid,
                observed="primaryGroupID",
                boundary_object=member,
            )

    def _edge(
        self,
        relation: MembershipRelation,
        *,
        member: Object | None,
        group: Object | None,
        member_dnt: int | None,
        group_dnt: int | None,
        member_sid: str | None,
        group_sid: str | None,
        observed: str,
        missing_reason: str | None = None,
        boundary_object: Object | None = None,
    ) -> MembershipEdge:
        resolved = missing_reason is None
        expandable = resolved
        reason = missing_reason

        boundary = _foreign_reason(boundary_object)
        if boundary is not None:
            expandable = False
            reason = boundary

        return MembershipEdge(
            relation=relation,
            member=member,
            group=group,
            member_dnt=member_dnt,
            group_dnt=group_dnt,
            member_sid=member_sid,
            group_sid=group_sid,
            observed=observed,
            resolved=resolved,
            expandable=expandable,
            reason=reason,
        )


class _NTDSSource:
    """Read membership facts from an NTDS database while preserving missing link targets."""

    def __init__(self, db: Database | None, *, objects: Sequence[Object] | None = None) -> None:
        self.db = db
        self._provided = list(objects) if objects is not None else None
        self._objects: list[Object] | None = self._provided
        self._by_dnt: dict[int, Object] | None = None
        self._by_sid: dict[str, Object] | None = None

    def all_objects(self) -> list[Object]:
        """Return all known objects, caching the result."""
        if self._objects is not None:
            return self._objects

        objects: list[Object] = []
        if self.db is not None:
            try:
                objects = list(self.db.data.iter())
            except _LOOKUP_ERRORS:
                objects = []

        self._objects = objects
        return objects

    def get_dnt(self, dnt: int | None) -> Object | None:
        """Resolve a DNT to an object without raising when the target is missing."""
        if dnt is None:
            return None

        if self._provided is not None:
            return self._dnt_index().get(dnt)

        if self.db is not None:
            try:
                return self.db.link.resolve(dnt)
            except _LOOKUP_ERRORS:
                try:
                    return self.db.data.get(dnt=dnt)
                except _LOOKUP_ERRORS:
                    pass

        return self._dnt_index().get(dnt)

    def get_sid(self, sid: str | None) -> Object | None:
        """Resolve a SID to an object without treating a missing SID as a cross-domain match."""
        if not sid:
            return None

        if self._provided is None and self.db is not None:
            try:
                if (obj := next(self.db.data.search(objectSid=sid), None)) is not None:
                    return obj
            except _LOOKUP_ERRORS:
                pass

        return self._sid_index().get(sid.upper())

    def explicit_groups(self, member_dnt: int) -> Iterator[tuple[int | None, Object | None]]:
        """Return containing groups for a member using the ``member`` link table."""
        if self.db is not None and hasattr(self.db.link, "raw_backlinks"):
            for _, group_dnt in self.db.link.raw_backlinks(member_dnt, "member"):
                yield group_dnt, self.get_dnt(group_dnt)
            return

        if self.db is not None:
            try:
                for group in self.db.link.backlinks(member_dnt, "memberOf"):
                    yield _dnt(group), group
            except _LOOKUP_ERRORS:
                return

            return

        for group in self.all_objects():
            if not _is_group(group):
                continue
            for candidate_dnt in self._explicit_member_dnts(group):
                if candidate_dnt == member_dnt:
                    yield _dnt(group), group

    def explicit_members(self, group_dnt: int) -> Iterator[tuple[int | None, Object | None]]:
        """Return members of a group using the ``member`` link table, preserving missing targets."""
        if self.db is not None and hasattr(self.db.link, "raw_links"):
            for _, member_dnt in self.db.link.raw_links(group_dnt, "member"):
                yield member_dnt, self.get_dnt(member_dnt)
            return

        if self.db is not None:
            try:
                for member in self.db.link.links(group_dnt, "member"):
                    yield _dnt(member), member
            except _LOOKUP_ERRORS:
                return

        if self._provided is None:
            return

        if (group := self._dnt_index().get(group_dnt)) is not None:
            for member_dnt in self._explicit_member_dnts(group):
                yield member_dnt, self.get_dnt(member_dnt)

    def primary_group(self, member: Object) -> tuple[str | None, Object | None]:
        """Resolve a member's primary group by constructing the SID within the member's domain scope.

        A RID is only meaningful inside its own domain SID. The expected SID is therefore built from the member's
        full SID prefix, and only an exact SID match is accepted.
        """
        primary_group_id = _primary_group_id(member)
        member_sid = _sid(member)
        domain = sid_domain(member_sid)

        if primary_group_id is None or domain is None:
            return None, None

        expected_sid = sid_for_rid(domain, primary_group_id)
        return expected_sid, self.get_sid(expected_sid)

    def primary_members(self, group: Object) -> Iterator[Object]:
        """Return members whose ``primaryGroupID`` points at this group within the same SID scope."""
        group_sid = _sid(group)
        domain = sid_domain(group_sid)
        rid = sid_rid(group_sid)
        if domain is None or rid is None:
            return

        candidates: list[Object] = []
        if self._provided is None and self.db is not None:
            try:
                candidates = list(self.db.data.search(primaryGroupID=rid))
            except _LOOKUP_ERRORS:
                candidates = []

        if not candidates and self._provided is not None:
            candidates = [obj for obj in self.all_objects() if _primary_group_id(obj) == rid]

        for member in candidates:
            if member is group:
                continue
            if sid_domain(_sid(member)) == domain:
                yield member

    def _dnt_index(self) -> dict[int, Object]:
        if self._by_dnt is None:
            self._by_dnt = {}
            for obj in self.all_objects():
                if (dnt := _dnt(obj)) is not None:
                    self._by_dnt.setdefault(dnt, obj)
        return self._by_dnt

    def _sid_index(self) -> dict[str, Object]:
        if self._by_sid is None:
            self._by_sid = {}
            for obj in self.all_objects():
                if (sid := _sid(obj)) is not None:
                    self._by_sid.setdefault(sid.upper(), obj)
        return self._by_sid

    def _explicit_member_dnts(self, group: Object) -> list[int]:
        members: Any = None
        try:
            members = group.get("member")
        except _LOOKUP_ERRORS:
            pass

        if not members:
            members = _attrv(group, "member")
        if not members:
            members = _attrv(group, "explicit_members")
        if not members:
            members = _attrv(group, "members")
        if not members:
            return []

        if not isinstance(members, (list, tuple, set)):
            members = [members]

        result = []
        for member in members:
            if isinstance(member, int):
                result.append(member)
            elif isinstance(member, str):
                if member.isdigit():
                    result.append(int(member))
                elif (
                    member.upper().startswith("S-")
                    and (obj := self.get_sid(member)) is not None
                    and (dnt := _dnt(obj)) is not None
                ):
                    result.append(dnt)
            elif (dnt := _dnt(member)) is not None:
                result.append(dnt)
        return result


def trace_memberships(ntds: NTDS | Database, principal: Object, **kwargs: Any) -> MembershipTrace:
    """Trace all offline group memberships for a principal.

    Args:
        ntds: The NTDS database to trace.
        principal: The account or group to start from.
        **kwargs: Additional arguments passed to :meth:`MembershipTracer.trace`.
    """
    return MembershipTracer(ntds).trace(principal, **kwargs)


def trace_group_members(ntds: NTDS | Database, group: Object, **kwargs: Any) -> MembershipTrace:
    """Trace all offline members of a group, including nested groups.

    Args:
        ntds: The NTDS database to trace.
        group: The group to start from.
        **kwargs: Additional arguments passed to :meth:`MembershipTracer.trace_members`.
    """
    return MembershipTracer(ntds).trace_members(group, **kwargs)


def resolve_membership(
    ntds: NTDS | Database, principal: Object, *, direction: str = "up", max_depth: int = 64
) -> MembershipTrace:
    """Trace offline membership relations for a principal.

    Args:
        ntds: The NTDS database to trace.
        principal: The account or group to start from.
        direction: ``"up"`` to follow containing groups, or ``"down"`` to follow a group's members.
        max_depth: Maximum number of edges in a single path.
    """
    return MembershipTracer(ntds).trace(principal, direction=direction, max_depth=max_depth)


def _describe_path(path: MembershipPath) -> str:
    if path.start is None and path.end is None:
        return "<empty path>"

    if path.direction == "up":
        start = _label(path.start, path.member_sid)
        end = _label(path.end, path.group_sid)
        return f"{start} -> {end}"

    start = _label(path.start, path.group_sid)
    end = _label(path.end, path.member_sid)
    return f"{start} -> {end}"


def _label(obj: Object | None, fallback_sid: str | None) -> str:
    if obj is not None and (name := _name(obj)) is not None:
        return name
    if fallback_sid is not None:
        return fallback_sid
    return "<unknown>"


def _replace_edge(edge: MembershipEdge, **kwargs: Any) -> MembershipEdge:
    return MembershipEdge(
        relation=kwargs.get("relation", edge.relation),
        member=kwargs.get("member", edge.member),
        group=kwargs.get("group", edge.group),
        member_dnt=kwargs.get("member_dnt", edge.member_dnt),
        group_dnt=kwargs.get("group_dnt", edge.group_dnt),
        member_sid=kwargs.get("member_sid", edge.member_sid),
        group_sid=kwargs.get("group_sid", edge.group_sid),
        observed=kwargs.get("observed", edge.observed),
        resolved=kwargs.get("resolved", edge.resolved),
        expandable=kwargs.get("expandable", edge.expandable),
        reason=kwargs.get("reason", edge.reason),
    )


def _register_foreign(trace: MembershipTrace, *objects: Object | None) -> None:
    for obj in objects:
        if obj is not None and _foreign_reason(obj) is not None:
            _add_foreign(trace, obj)


def _add_gap(trace: MembershipTrace, message: str) -> None:
    if message not in trace.gaps:
        trace.gaps.append(message)


def _add_foreign(trace: MembershipTrace, obj: Object) -> None:
    if not _is_foreign_security_principal(obj):
        return
    if all(_identity(existing) != _identity(obj) for existing in trace.foreign_principals):
        trace.foreign_principals.append(obj)


def _add_unresolved(trace: MembershipTrace, edge: MembershipEdge) -> None:
    key = (edge.member_dnt, edge.group_dnt, edge.relation.value, edge.reason)
    if all(
        (existing.member_dnt, existing.group_dnt, existing.relation.value, existing.reason) != key
        for existing in trace.unresolved_edges
    ):
        trace.unresolved_edges.append(edge)


def _path_key(edges: tuple[MembershipEdge, ...]) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (
            _identity(edge.member, fallback_dnt=edge.member_dnt, fallback_sid=edge.member_sid),
            _identity(edge.group, fallback_dnt=edge.group_dnt, fallback_sid=edge.group_sid),
            edge.relation.value,
            edge.observed,
        )
        for edge in edges
    )


def _identity(obj: Object | None, *, fallback_dnt: int | None = None, fallback_sid: str | None = None) -> str:
    if obj is not None:
        if (dnt := _dnt(obj)) is not None:
            return f"dnt:{dnt}"
        if (sid := _sid(obj)) is not None:
            return f"sid:{sid.upper()}"
        if (dn := _dn(obj)) is not None:
            return f"dn:{dn}"

    if fallback_dnt is not None:
        return f"dnt:{fallback_dnt}"
    if fallback_sid is not None:
        return f"sid:{fallback_sid.upper()}"
    return "unknown"


def _object_ref(obj: Object | None, *, sid: str | None = None, dnt: int | None = None) -> dict[str, Any] | None:
    if obj is None and sid is None and dnt is None:
        return None

    return {
        "dnt": dnt if dnt is not None else _dnt(obj),
        "sid": sid if sid is not None else _sid(obj),
        "dn": _dn(obj),
        "name": _name(obj),
        "object_class": _classes(obj),
        "phantom": _is_phantom(obj),
    }


def _attrv(obj: Object | None, name: str) -> Any:
    if obj is None:
        return None

    try:
        return getattr(obj, name)
    except _LOOKUP_ERRORS:
        return None


def _dnt(obj: Object | None) -> int | None:
    value = _attrv(obj, "dnt")
    return value if isinstance(value, int) else None


def _sid(obj: Object | None) -> str | None:
    value = _attrv(obj, "sid")
    if value is None:
        value = _attrv(obj, "objectSid")
    return value if isinstance(value, str) and value else None


def _dn(obj: Object | None) -> str | None:
    value = _attrv(obj, "distinguished_name")
    if value is None:
        value = _attrv(obj, "dn")
    return str(value) if value else None


def _name(obj: Object | None) -> str | None:
    value = _attrv(obj, "name")
    if value is None:
        value = _attrv(obj, "sam_account_name")
    return str(value) if value else None


def _classes(obj: Object | None) -> list[str]:
    value = _attrv(obj, "object_class")
    if value is None:
        value = _attrv(obj, "objectClass")
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(entry) for entry in value]


def _is_group(obj: Object | None) -> bool:
    return any(entry.lower() == "group" for entry in _classes(obj))


def _is_phantom(obj: Object | None) -> bool:
    return bool(_attrv(obj, "is_phantom"))


def _is_foreign_security_principal(obj: Object | None) -> bool:
    if any(entry.lower() == "foreignsecurityprincipal" for entry in _classes(obj)):
        return True
    return bool((dn := _dn(obj)) is not None and "CN=FOREIGNSECURITYPRINCIPALS" in dn.upper())


def _foreign_reason(obj: Object | None) -> str | None:
    if obj is None:
        return None
    if _is_foreign_security_principal(obj):
        return (
            "foreign security principal: the external identity is represented by a local placeholder and its "
            "domain was not expanded"
        )
    if _is_phantom(obj):
        return (
            "phantom (cross-domain) object: membership data for the referenced domain is not present in this "
            "offline database"
        )
    return None


def _primary_group_id(obj: Object | None) -> int | None:
    value = _attrv(obj, "primary_group_id")
    if value is None:
        value = _attrv(obj, "primaryGroupID")

    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None
