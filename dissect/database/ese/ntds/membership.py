from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.util import sid_domain

if TYPE_CHECKING:
    from collections.abc import Mapping

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.record import Record


class EdgeKind(str, Enum):
    """The provenance of a single membership edge."""

    EXPLICIT_MEMBER = "explicit_member"
    """The group's ``member`` link in the link table."""

    PRIMARY_GROUP = "primary_group"
    """The relationship derived from a principal's ``primaryGroupID`` attribute."""

    BOUNDARY = "unresolved_boundary"
    """A boundary marker for an expansion that cannot be performed offline."""


class UnresolvedReason(str, Enum):
    """Why an edge or path could not be fully resolved."""

    MISSING_TARGET = "missing_target"
    FOREIGN_DOMAIN = "foreign_domain"
    FOREIGN_SECURITY_PRINCIPAL = "foreign_security_principal"
    PHANTOM = "phantom"
    CYCLE = "cycle"
    DEPTH_LIMIT = "depth_limit"
    PATH_LIMIT = "path_limit"
    SUBJECT_WITHOUT_SID = "subject_without_sid"
    INVALID_PRIMARY_GROUP_ID = "invalid_primary_group_id"
    TARGET_NOT_GROUP = "target_not_group"


class PathStatus(str, Enum):
    """The overall status of a membership path."""

    CONFIRMED = "confirmed"
    PARTIAL = "partial"
    CYCLE = "cycle"
    FOREIGN = "foreign"


@dataclass(frozen=True, eq=False)
class MembershipEdge:
    """A single edge in the membership graph.

    The edge points from a security principal to a group it belongs to. ``kind`` records whether the edge came from
    an explicit ``member`` link or from the principal's ``primaryGroupID``.

    Args:
        source: The principal object, if it exists in the database.
        target: The group object, if it exists in the database.
        kind: The source of the relationship.
        source_dnt: The Directory Number Tag of the source, when known.
        target_dnt: The Directory Number Tag of the target, when known.
        reasons: Reasons why this edge is unresolved or cannot be expanded.
        evidence: The raw evidence backing this edge.
        occurrences: The number of identical link records backing this edge.
        note: Optional human readable context.
    """

    source: Object | None
    target: Object | None
    kind: EdgeKind
    source_dnt: int | None = None
    target_dnt: int | None = None
    reasons: tuple[UnresolvedReason, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
    occurrences: int = 1
    note: str | None = None

    @property
    def resolved(self) -> bool:
        """Return whether both ends of this edge refer to an object in the database."""
        return self.source is not None and self.target is not None

    @property
    def source_sid(self) -> str | None:
        """Return the SID of the source principal."""
        return _sid(self.source)

    @property
    def target_sid(self) -> str | None:
        """Return the SID of the target group."""
        return _sid(self.target)

    @property
    def source_dn(self) -> str | None:
        """Return the distinguished name of the source principal."""
        return _dn(self.source)

    @property
    def target_dn(self) -> str | None:
        """Return the distinguished name of the target group."""
        return _dn(self.target)

    @property
    def reason(self) -> UnresolvedReason | None:
        """Return the first reason this edge is unresolved, if any."""
        return self.reasons[0] if self.reasons else None

    def describe(self) -> str:
        """Return a one-line description of this edge."""
        label = self.kind.value
        target = _describe(self.target) if self.target is not None else f"<DNT {self.target_dnt}>"

        if self.reasons:
            target = f"{target} ({', '.join(reason.value for reason in self.reasons)})"

        return f"{label}: {_describe(self.source)} -> {target}"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON serialisable representation of this edge."""
        return {
            "kind": self.kind.value,
            "source": _object_dict(self.source, self.source_dnt),
            "target": _object_dict(self.target, self.target_dnt),
            "resolved": self.resolved,
            "reasons": [reason.value for reason in self.reasons],
            "occurrences": self.occurrences,
            "evidence": dict(self.evidence),
            "note": self.note,
        }


@dataclass(frozen=True, eq=False)
class MembershipPath:
    """A provable chain from a principal to a group.

    Every path is a sequence of :class:`MembershipEdge` objects. The final edge may be unresolved, in which case the
    path records the unknown part instead of silently dropping it.

    Args:
        subject: The principal the trace started from.
        edges: The ordered edges from the subject to the final group or unresolved target.
        status: The overall status of this path.
        reasons: All reasons that make this path incomplete.
        duplicate_count: How many identical paths were observed.
    """

    subject: Object
    edges: tuple[MembershipEdge, ...]
    status: PathStatus
    reasons: tuple[UnresolvedReason, ...] = ()
    duplicate_count: int = 1

    @property
    def subject_dnt(self) -> int | None:
        """Return the Directory Number Tag of the subject."""
        return _dnt(self.subject)

    @property
    def target(self) -> Object | None:
        """Return the final group object, if it was resolved."""
        return self.edges[-1].target if self.edges else None

    @property
    def target_dnt(self) -> int | None:
        """Return the Directory Number Tag of the final target."""
        return self.edges[-1].target_dnt if self.edges else None

    @property
    def target_sid(self) -> str | None:
        """Return the SID of the final target."""
        return self.edges[-1].target_sid if self.edges else None

    @property
    def target_dn(self) -> str | None:
        """Return the distinguished name of the final target."""
        return self.edges[-1].target_dn if self.edges else None

    @property
    def group(self) -> Object | None:
        """Return the final group object, if it was resolved."""
        return self.target

    @property
    def kinds(self) -> tuple[EdgeKind, ...]:
        """Return the provenance of every edge in this path."""
        return tuple(edge.kind for edge in self.edges)

    @property
    def sources(self) -> frozenset[EdgeKind]:
        """Return the distinct provenance kinds used by this path."""
        return frozenset(self.kinds)

    @property
    def complete(self) -> bool:
        """Return whether every edge in this path was resolved and expandable."""
        return self.status == PathStatus.CONFIRMED and all(edge.resolved for edge in self.edges) and not self.reasons

    @property
    def confirmed(self) -> bool:
        """Return whether this path is fully confirmed."""
        return self.complete

    def chain(self) -> str:
        """Return the edge chain of this path, without the subject."""
        if not self.edges:
            return "<no edges>"

        parts = []
        for edge in self.edges:
            target = edge.target_dn or (f"<DNT {edge.target_dnt}>" if edge.target_dnt is not None else "<unknown>")
            label = edge.kind.value
            if edge.reasons:
                label = f"{label} ({', '.join(reason.value for reason in edge.reasons)})"
            parts.append(f"{label} -> {target}")

        return " | ".join(parts)

    def describe(self) -> str:
        """Return a readable representation of this path, including the subject."""
        return f"{_describe(self.subject)} | {self.chain()}"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON serialisable representation of this path."""
        return {
            "subject": _object_dict(self.subject),
            "edges": [edge.as_dict() for edge in self.edges],
            "status": self.status.value,
            "complete": self.complete,
            "confirmed": self.confirmed,
            "reasons": [reason.value for reason in self.reasons],
            "sources": sorted(kind.value for kind in self.sources),
            "duplicate_count": self.duplicate_count,
            "target": _object_dict(self.target, self.target_dnt),
        }


@dataclass(eq=False)
class MembershipTrace:
    """The result of tracing offline group relationships for a principal.

    The trace contains all provable paths, all unresolved edges encountered while following those paths and the
    limitations that apply to the offline evidence.

    Args:
        tracer: The tracer that produced this result.
        subject: The principal the trace started from.
        paths: All discovered paths.
        unresolved_edges: Edges that could not be followed or expanded.
        duplicate_links: Duplicate raw link records that were collapsed into a single edge.
        truncated: Whether the trace stopped because a configured limit was reached.
        limitations: Limitations that apply to the result.
    """

    tracer: MembershipTracer
    subject: Object
    paths: list[MembershipPath] = field(default_factory=list)
    unresolved_edges: list[MembershipEdge] = field(default_factory=list)
    duplicate_links: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    limitations: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether the available offline relationships were fully resolved.

        A complete trace means every discovered edge was resolved and expandable. It does **not** mean the groups are
        currently effective for the account, and it does not include relationships from other domains.
        """
        return (
            not self.truncated
            and not self.unresolved_edges
            and all(path.complete for path in self.paths)
            and not _is_foreign_security_principal(self.subject)
            and not _is_phantom(self.subject)
        )

    @property
    def confirmed_paths(self) -> list[MembershipPath]:
        """Return all fully confirmed paths."""
        return [path for path in self.paths if path.complete]

    @property
    def partial_paths(self) -> list[MembershipPath]:
        """Return all paths that end in an unresolved or non-expandable edge."""
        return [path for path in self.paths if path.status == PathStatus.PARTIAL]

    @property
    def cycle_paths(self) -> list[MembershipPath]:
        """Return all paths that hit a group cycle."""
        return [path for path in self.paths if path.status == PathStatus.CYCLE]

    @property
    def explicit_paths(self) -> list[MembershipPath]:
        """Return all paths that consist solely of explicit ``member`` links."""
        return [path for path in self.paths if path.sources == {EdgeKind.EXPLICIT_MEMBER}]

    @property
    def primary_group_paths(self) -> list[MembershipPath]:
        """Return all paths that use at least one ``primaryGroupID`` derived edge."""
        return [path for path in self.paths if EdgeKind.PRIMARY_GROUP in path.sources]

    def paths_from(self, kind: EdgeKind) -> list[MembershipPath]:
        """Return the paths that contain an edge of the given provenance kind.

        Args:
            kind: The :class:`EdgeKind` to filter on.
        """
        return [path for path in self.paths if kind in path.sources]

    @property
    def foreign_paths(self) -> list[MembershipPath]:
        """Return all paths that cross a foreign domain boundary."""
        return [path for path in self.paths if path.status == PathStatus.FOREIGN]

    def paths_to(self, target: Object | int | str) -> list[MembershipPath]:
        """Return the paths that end at the given group.

        Args:
            target: A group object, a Directory Number Tag, a SID or a distinguished name.
        """
        if not isinstance(target, (int, str)):
            if (dnt := _dnt(target)) is not None:
                return [path for path in self.paths if path.target_dnt == dnt]
            target = _sid(target) or _dn(target) or ""

        if isinstance(target, int):
            return [path for path in self.paths if path.target_dnt == target]

        needle = target.upper()
        return [
            path
            for path in self.paths
            if (path.target_dn and path.target_dn.upper() == needle)
            or (path.target_sid and path.target_sid.upper() == needle)
        ]

    def group_paths(self) -> dict[int, list[MembershipPath]]:
        """Return all paths grouped by the Directory Number Tag of their final target."""
        result: dict[int, list[MembershipPath]] = defaultdict(list)
        for path in self.paths:
            if path.target_dnt is not None:
                result[path.target_dnt].append(path)
        return dict(result)

    def groups(self) -> list[Object]:
        """Return the distinct groups that were reached, ordered by Directory Number Tag."""
        groups = {path.target_dnt: path.target for path in self.paths if path.target is not None}
        return [groups[dnt] for dnt in sorted(groups)]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON serialisable representation of the trace."""
        return {
            "subject": _object_dict(self.subject),
            "direction": "member_of",
            "complete": self.complete,
            "truncated": self.truncated,
            "paths": [path.as_dict() for path in self.paths],
            "confirmed_paths": [path.as_dict() for path in self.confirmed_paths],
            "unresolved_edges": [edge.as_dict() for edge in self.unresolved_edges],
            "duplicate_links": self.duplicate_links,
            "limitations": list(self.limitations),
            "offline_evidence_only": True,
        }

    def explain(self) -> str:
        """Return a readable explanation of the confirmed paths and the unknown parts."""
        lines = [
            f"Offline membership trace for {_describe(self.subject)}",
            f"Direction: member-of (principal -> groups); complete={self.complete}",
            f"Confirmed paths: {len(self.confirmed_paths)}",
        ]
        lines.extend(f"  [{path.status.value}] {path.chain()}" for path in self.confirmed_paths)

        other_paths = [path for path in self.paths if path not in self.confirmed_paths]
        lines.append(f"Partial, cyclic or foreign paths: {len(other_paths)}")
        lines.extend(f"  [{path.status.value}] {path.chain()}" for path in other_paths)

        lines.append(f"Unresolved edges: {len(self.unresolved_edges)}")
        lines.extend(f"  - {edge.describe()}" for edge in self.unresolved_edges)

        repeated_paths = [path for path in self.paths if path.duplicate_count > 1]
        if repeated_paths:
            lines.append(f"Repeated paths (kept as evidence): {len(repeated_paths)}")
            lines.extend(f"  - x{path.duplicate_count} {path.chain()}" for path in repeated_paths)

        if self.duplicate_links:
            lines.append(f"Duplicate link records collapsed: {len(self.duplicate_links)}")
            lines.extend(f"  - {duplicate!r}" for duplicate in self.duplicate_links)

        if self.limitations:
            lines.append("Limitations:")
            lines.extend(f"  - {limitation}" for limitation in self.limitations)

        return "\n".join(lines)


class MembershipTracer:
    """Trace offline group relationships through an NTDS database.

    The tracer follows two kinds of edges:

    - Explicit ``member`` links stored in the link table.
    - Primary group relationships derived from the ``primaryGroupID`` attribute.

    Primary groups are resolved using the full SID of the principal and the group. A matching RID in another domain
    is never accepted as the primary group. Unresolved, foreign and cyclic edges are retained in the result.

    Args:
        db: The NTDS :class:`~dissect.database.ese.ntds.database.Database` to trace.
    """

    def __init__(self, db: Database):
        self.db = db
        self._raw_links: dict[int, list[tuple[int, Record, int]]] | None = None
        self._explicit_edges: dict[int, list[MembershipEdge]] = {}
        self._primary_edges: dict[int, list[MembershipEdge]] = {}
        self._objects_by_sid: dict[str, Object | None] = {}
        self._local_domain_sids: frozenset[str] | None = None
        self._duplicate_links: list[dict[str, Any]] = []
        self._inactive_links = 0

    @property
    def duplicate_links(self) -> list[dict[str, Any]]:
        """Return duplicate raw link records discovered while building the explicit member graph."""
        self._load_explicit_links()
        return self._duplicate_links

    @property
    def inactive_links(self) -> int:
        """Return the number of inactive or deleted link records skipped while building the explicit graph."""
        self._load_explicit_links()
        return self._inactive_links

    def trace(
        self,
        subject: Object | int | str,
        *,
        max_depth: int = 16,
        max_paths: int = 10000,
        include_primary_group: bool = True,
    ) -> MembershipTrace:
        """Trace all offline membership paths from a principal to the groups it belongs to.

        Args:
            subject: The principal to trace. May be an object, a Directory Number Tag, a SID or a distinguished name.
            max_depth: The maximum number of edges in a path.
            max_paths: The maximum number of paths to collect.
            include_primary_group: Whether to include ``primaryGroupID`` derived edges.

        Returns:
            A :class:`MembershipTrace` containing confirmed paths, unresolved edges and limitations.
        """
        subject = self._coerce_subject(subject)
        trace = MembershipTrace(
            tracer=self,
            subject=subject,
            limitations=self._limitations(subject),
        )

        if _is_foreign_security_principal(subject):
            boundary = MembershipEdge(
                source=subject,
                target=None,
                kind=EdgeKind.BOUNDARY,
                source_dnt=_dnt(subject),
                target_dnt=None,
                reasons=(UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL,),
                evidence={"objectSid": _sid(subject)},
                note="Foreign security principal; its home domain is not present in this NTDS database",
            )
            trace.paths.append(
                MembershipPath(
                    subject=subject,
                    edges=(boundary,),
                    status=PathStatus.FOREIGN,
                    reasons=(UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL,),
                )
            )
            trace.unresolved_edges.append(boundary)
            trace.limitations += (
                "Subject is a foreign security principal; relationships from its home domain were not expanded.",
            )

        seen_paths: dict[tuple[Any, ...], int] = {}
        seen_edges: set[tuple[Any, ...]] = set()
        stack: list[tuple[Object, tuple[MembershipEdge, ...], frozenset[int]]] = [
            (subject, (), frozenset({_dnt(subject)}))
        ]

        while stack and not trace.truncated:
            node, prefix, visited = stack.pop()
            for edge in self.edges_from(node, include_primary_group=include_primary_group):
                reasons = list(edge.reasons)
                target = edge.target
                boundary = False

                if target is None:
                    if not reasons:
                        reasons.append(UnresolvedReason.MISSING_TARGET)
                    boundary = True
                else:
                    # A phantom object is a cross-domain reference. We can name it, but not expand it here.
                    if _is_phantom(target) and UnresolvedReason.PHANTOM not in reasons:
                        reasons.append(UnresolvedReason.PHANTOM)
                        boundary = True
                    if _dnt(target) in visited:
                        if UnresolvedReason.CYCLE not in reasons:
                            reasons.append(UnresolvedReason.CYCLE)
                        boundary = True
                    if len(prefix) + 1 >= max_depth:
                        if UnresolvedReason.DEPTH_LIMIT not in reasons:
                            reasons.append(UnresolvedReason.DEPTH_LIMIT)
                        boundary = True

                final_edge = edge
                if tuple(reasons) != edge.reasons:
                    final_edge = replace(edge, reasons=tuple(dict.fromkeys(reasons)))

                path = self._make_path(subject, prefix + (final_edge,))
                signature = self._path_signature(path)

                if signature in seen_paths:
                    index = seen_paths[signature]
                    previous = trace.paths[index]
                    trace.paths[index] = replace(previous, duplicate_count=previous.duplicate_count + 1)
                elif len(trace.paths) >= max_paths:
                    trace.truncated = True
                    trace.unresolved_edges.append(
                        replace(final_edge, reasons=tuple(dict.fromkeys((*reasons, UnresolvedReason.PATH_LIMIT))))
                    )
                    trace.limitations += ("Trace stopped at the configured path limit; additional paths may exist.",)
                    break
                else:
                    seen_paths[signature] = len(trace.paths)
                    trace.paths.append(path)

                if boundary:
                    edge_signature = self._edge_signature(final_edge)
                    if edge_signature not in seen_edges:
                        seen_edges.add(edge_signature)
                        trace.unresolved_edges.append(final_edge)
                    continue

                stack.append((target, prefix + (final_edge,), visited | {_dnt(target)}))

        trace.duplicate_links = list(self.duplicate_links)
        trace.paths.sort(key=lambda path: (path.target_dnt if path.target_dnt is not None else -1, len(path.edges)))

        return trace

    def edges_from(self, obj: Object, *, include_primary_group: bool = True) -> list[MembershipEdge]:
        """Return all outgoing membership edges for a principal.

        Args:
            obj: The principal or group to return edges for.
            include_primary_group: Whether to include the ``primaryGroupID`` derived edge.
        """
        dnt = _dnt(obj)
        if dnt is None:
            return []

        edges = list(self._explicit_edges_for(dnt))
        if include_primary_group:
            edges.extend(self._primary_edges_for(dnt))
        return sorted(edges, key=lambda edge: (edge.target_dnt if edge.target_dnt is not None else -1, edge.kind.value))

    def _load_explicit_links(self) -> None:
        if self._raw_links is not None:
            return

        raw_links: dict[int, list[tuple[int, Record, int]]] = defaultdict(list)
        seen: dict[tuple[int, int, int], tuple[int, int]] = {}

        for link_dnt, backlink_dnt, record in self.db.link.link_records("member"):
            if _record_value(record, "link_deltime") or _record_value(record, "link_deactivetime"):
                self._inactive_links += 1
                continue

            base = _record_value(record, "link_base") or 0
            key = (backlink_dnt, link_dnt, base)
            if key in seen:
                index, count = seen[key]
                seen[key] = (index, count + 1)
                self._duplicate_links.append(
                    {
                        "link_DNT": link_dnt,
                        "backlink_DNT": backlink_dnt,
                        "link_base": base,
                        "reason": "duplicate_member_link",
                    }
                )
                raw_links[backlink_dnt][index] = (*raw_links[backlink_dnt][index][:2], count + 1)
                continue

            seen[key] = (len(raw_links[backlink_dnt]), 1)
            raw_links[backlink_dnt].append((link_dnt, record, 1))

        self._raw_links = dict(raw_links)

    def _explicit_edges_for(self, dnt: int) -> list[MembershipEdge]:
        if dnt in self._explicit_edges:
            return self._explicit_edges[dnt]

        self._load_explicit_links()
        source = self._resolve(dnt)
        edges = []

        for target_dnt, record, occurrences in self._raw_links.get(dnt, []):
            target = self._resolve(target_dnt)
            reasons: list[UnresolvedReason] = []
            if target is None:
                reasons.append(UnresolvedReason.MISSING_TARGET)
            elif not _is_group(target):
                reasons.append(UnresolvedReason.TARGET_NOT_GROUP)
            elif _is_foreign_security_principal(target):
                reasons.append(UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL)

            edges.append(
                MembershipEdge(
                    source=source,
                    target=target,
                    source_dnt=dnt,
                    target_dnt=target_dnt,
                    kind=EdgeKind.EXPLICIT_MEMBER,
                    reasons=tuple(reasons),
                    occurrences=occurrences,
                    evidence={
                        "attribute": "member",
                        "link_table": {
                            "link_DNT": _record_value(record, "link_DNT"),
                            "backlink_DNT": _record_value(record, "backlink_DNT"),
                            "link_base": _record_value(record, "link_base"),
                        },
                    },
                )
            )

        self._explicit_edges[dnt] = edges
        return edges

    def _primary_edges_for(self, dnt: int) -> list[MembershipEdge]:
        if dnt in self._primary_edges:
            return self._primary_edges[dnt]

        source = self._resolve(dnt)
        if source is None:
            self._primary_edges[dnt] = []
            return []

        raw_primary_group_id = _raw_primary_group_id(source)
        if raw_primary_group_id is None:
            self._primary_edges[dnt] = []
            return []

        primary_group_id = _parse_primary_group_id(raw_primary_group_id)
        if primary_group_id is None:
            edge = MembershipEdge(
                source=source,
                target=None,
                source_dnt=dnt,
                kind=EdgeKind.PRIMARY_GROUP,
                reasons=(UnresolvedReason.INVALID_PRIMARY_GROUP_ID,),
                evidence={"attribute": "primaryGroupID", "primaryGroupID": raw_primary_group_id},
            )
            self._primary_edges[dnt] = [edge]
            return [edge]

        sid = _sid(source)
        if sid is None:
            edge = MembershipEdge(
                source=source,
                target=None,
                source_dnt=dnt,
                kind=EdgeKind.PRIMARY_GROUP,
                reasons=(UnresolvedReason.SUBJECT_WITHOUT_SID,),
                evidence={"attribute": "primaryGroupID", "primaryGroupID": primary_group_id},
            )
            self._primary_edges[dnt] = [edge]
            return [edge]

        domain_sid = sid_domain(sid)
        if domain_sid is None:
            edge = MembershipEdge(
                source=source,
                target=None,
                source_dnt=dnt,
                kind=EdgeKind.PRIMARY_GROUP,
                reasons=(UnresolvedReason.SUBJECT_WITHOUT_SID,),
                evidence={"attribute": "primaryGroupID", "primaryGroupID": primary_group_id, "subject_objectSid": sid},
            )
            self._primary_edges[dnt] = [edge]
            return [edge]

        derived_sid = f"{domain_sid}-{primary_group_id}"
        target = self._find_by_sid(derived_sid)

        reasons: list[UnresolvedReason] = []
        if target is None:
            if domain_sid not in self.local_domain_sids:
                reasons.append(UnresolvedReason.FOREIGN_DOMAIN)
            else:
                reasons.append(UnresolvedReason.MISSING_TARGET)
        elif not _is_group(target):
            reasons.append(UnresolvedReason.TARGET_NOT_GROUP)
        elif _is_foreign_security_principal(target):
            reasons.append(UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL)
        elif _is_phantom(target):
            reasons.append(UnresolvedReason.PHANTOM)

        edge = MembershipEdge(
            source=source,
            target=target,
            source_dnt=dnt,
            target_dnt=_dnt(target) if target is not None else None,
            kind=EdgeKind.PRIMARY_GROUP,
            reasons=tuple(reasons),
            evidence={
                "attribute": "primaryGroupID",
                "primaryGroupID": primary_group_id,
                "subject_objectSid": sid,
                "domain_sid": domain_sid,
                "derived_objectSid": derived_sid,
                "sid_scope": "same_domain" if domain_sid in self.local_domain_sids else "foreign_domain",
            },
        )

        self._primary_edges[dnt] = [edge]
        return [edge]

    def _find_by_sid(self, sid: str) -> Object | None:
        if sid in self._objects_by_sid:
            return self._objects_by_sid[sid]

        target = None
        try:
            target = self.db.data.lookup(objectSid=sid)
        except (KeyNotFoundError, KeyError):
            # The indexed lookup succeeded but no object with this SID exists
            target = None
        except Exception:
            # No usable index; fall back to a bounded search
            try:
                target = next(self.db.data.search(objectSid=sid), None)
            except Exception:
                target = None

        self._objects_by_sid[sid] = target
        return target

    @property
    def local_domain_sids(self) -> frozenset[str]:
        """Return the SIDs of the hosted domains that are available in this database."""
        if self._local_domain_sids is None:
            # S-1-5-32 is the fixed BUILTIN domain SID, which is always hosted alongside the local domain.
            result = {"S-1-5-32"}

            try:
                domain = self.db.domain()
            except Exception:
                domain = None

            if domain is not None and (sid := _sid(domain)) is not None:
                result.add(sid)
            else:
                # AD LDS databases have no DSA domain; fall back to scanning for non-phantom domain objects.
                result.update(
                    sid
                    for obj in self.db.data.iter()
                    if _object_classes(obj) & {"domain", "domaindns", "builtindomain"}
                    and not _is_phantom(obj)
                    and (sid := _sid(obj)) is not None
                )

            # Only hosted (non-phantom) naming contexts count. A phantom domain object only proves that another
            # domain exists; its objects and groups are not available for local expansion.
            self._local_domain_sids = frozenset(result)
        return self._local_domain_sids

    def _resolve(self, dnt: int | None) -> Object | None:
        if dnt is None:
            return None

        try:
            return self.db.data.get(dnt)
        except (KeyNotFoundError, KeyError, ValueError, AttributeError):
            return None
        except Exception:
            # A malformed record should not hide the rest of the relationship evidence
            return None

    def _coerce_subject(self, subject: Object | int | str) -> Object:
        if not isinstance(subject, (int, str)):
            if _dnt(subject) is None:
                raise TypeError("Subject must be an NTDS object, DNT, SID or distinguished name")
            return subject

        if isinstance(subject, int):
            if (obj := self._resolve(subject)) is None:
                raise ValueError(f"No object found for DNT {subject}")
            return obj

        if subject.startswith("S-"):
            if (obj := self._find_by_sid(subject)) is None:
                raise ValueError(f"No object found for SID {subject}")
            return obj

        if (obj := self._search_unique("sAMAccountName", subject)) is not None:
            return obj
        if (obj := self._search_unique("name", subject)) is not None:
            return obj

        for obj in self.db.data.iter():
            if (_dn(obj) or "").upper() == subject.upper() or (_name(obj) or "").upper() == subject.upper():
                return obj

        raise ValueError(f"No object found for {subject!r}")

    def _search_unique(self, attribute: str, value: str) -> Object | None:
        try:
            return next(self.db.data.search(**{attribute: value}), None)
        except Exception:
            return None

    def _make_path(self, subject: Object, edges: tuple[MembershipEdge, ...]) -> MembershipPath:
        reasons: list[UnresolvedReason] = []
        for edge in edges:
            reasons.extend(edge.reasons)

        reasons = list(dict.fromkeys(reasons))
        if UnresolvedReason.CYCLE in reasons:
            status = PathStatus.CYCLE
        elif (
            UnresolvedReason.FOREIGN_DOMAIN in reasons
            or UnresolvedReason.FOREIGN_SECURITY_PRINCIPAL in reasons
            or UnresolvedReason.PHANTOM in reasons
        ):
            status = PathStatus.FOREIGN
        elif reasons or not all(edge.resolved for edge in edges):
            status = PathStatus.PARTIAL
        else:
            status = PathStatus.CONFIRMED

        return MembershipPath(subject=subject, edges=edges, status=status, reasons=tuple(reasons))

    @staticmethod
    def _path_signature(path: MembershipPath) -> tuple[Any, ...]:
        return tuple(MembershipTracer._edge_signature(edge) for edge in path.edges)

    @staticmethod
    def _edge_signature(edge: MembershipEdge) -> tuple[Any, ...]:
        return (edge.source_dnt, edge.target_dnt, edge.kind.value, tuple(reason.value for reason in edge.reasons))

    @staticmethod
    def _limitations(subject: Object) -> tuple[str, ...]:
        limitations = [
            "Offline NTDS evidence only; this is not a live access check or an effective permission evaluation.",
            "Expansion is limited to link and primary group data present in this database; deleted or replicated "
            "changes on a domain controller are not observed.",
            "Primary groups are resolved by full SID (domain SID plus primaryGroupID), never by RID alone.",
        ]
        if _is_foreign_security_principal(subject):
            limitations.append(
                "Foreign security principals are stubs in this database; their home-domain membership is unknown."
            )
        if _is_phantom(subject):
            limitations.append(
                "Subject is a non-local (phantom) reference; its own domain's data is not available in this database."
            )
        return tuple(limitations)


def _dnt(obj: Object | None) -> int | None:
    if obj is None:
        return None
    try:
        return obj.dnt
    except Exception:
        return None


def _sid(obj: Object | None) -> str | None:
    if obj is None:
        return None
    try:
        return obj.sid
    except Exception:
        return None


def _dn(obj: Object | None) -> str | None:
    if obj is None:
        return None
    try:
        return obj.dn
    except Exception:
        return None


def _name(obj: Object | None) -> str | None:
    if obj is None:
        return None

    try:
        value = getattr(obj, "sam_account_name", None)
    except Exception:
        value = None

    if not value:
        try:
            value = getattr(obj, "name", None)
        except Exception:
            value = None

    return value


def _object_classes(obj: Object | None) -> set[str]:
    if obj is None:
        return set()

    try:
        classes = obj.object_class or []
    except Exception:
        return set()

    return {value.lower() for value in classes}


def _is_group(obj: Object | None) -> bool:
    return "group" in _object_classes(obj)


def _is_foreign_security_principal(obj: Object | None) -> bool:
    return "foreignsecurityprincipal" in _object_classes(obj)


def _is_phantom(obj: Object | None) -> bool:
    if obj is None:
        return False
    try:
        return bool(obj.is_phantom)
    except Exception:
        return False


def _raw_primary_group_id(obj: Object | None) -> Any:
    if obj is None:
        return None

    try:
        value = obj.primary_group_id
    except Exception:
        value = None

    if value is None:
        try:
            value = obj.get("primaryGroupID")
        except (AttributeError, KeyError, ValueError):
            value = None

    return value


def _parse_primary_group_id(value: Any) -> int | None:
    if value is None or value == "":
        return None

    try:
        result = int(value)
    except (TypeError, ValueError):
        return None

    # The RID is a 32-bit unsigned value in the last sub authority of the SID
    if not 0 <= result <= 0xFFFFFFFF:
        return None

    return result


def _record_value(record: Record, name: str) -> Any:
    try:
        return record.get(name)
    except (KeyError, ValueError, AttributeError):
        return None


def _describe(obj: Object | None) -> str:
    if obj is None:
        return "<unknown>"

    if (dn := _dn(obj)) is not None:
        value = dn
    elif (name := _name(obj)) is not None:
        value = name
    else:
        value = f"DNT {_dnt(obj)}"

    if (sid := _sid(obj)) is not None:
        value = f"{value} ({sid})"

    return value


def _object_dict(obj: Object | None, dnt: int | None = None) -> dict[str, Any] | None:
    if obj is None and dnt is None:
        return None

    return {
        "dnt": _dnt(obj) if obj is not None else dnt,
        "dn": _dn(obj),
        "sid": _sid(obj),
        "name": _name(obj),
        "objectClasses": sorted(_object_classes(obj)),
    }
