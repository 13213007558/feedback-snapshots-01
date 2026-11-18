from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from enum import Enum
from typing import TYPE_CHECKING, Any

from asyncua import ua
from asyncua.common.structures104 import clean_name, make_structure

if TYPE_CHECKING:
    from asyncua import Client, Node, Server

_logger = logging.getLogger(__name__)

_SUPPORTED_STRUCTURE_TYPES = frozenset(
    (
        ua.StructureType.Structure,
        ua.StructureType.StructureWithOptionalFields,
        ua.StructureType.Union,
        ua.StructureType.StructureWithSubtypedValues,
    )
)


class RejectionReason(Enum):
    InheritanceCycle = "InheritanceCycle"
    DuplicateEncodingId = "DuplicateEncodingId"
    NameConflict = "NameConflict"
    UnsupportedDefinition = "UnsupportedDefinition"
    UnresolvedDependency = "UnresolvedDependency"
    GenerationFailed = "GenerationFailed"


@dataclass(frozen=True)
class TypeLoadLimits:
    """Hard bounds for a single bounded load: expanded nodes, followed references, expansion depth."""

    max_nodes: int = 512
    max_edges: int = 4096
    max_depth: int = 32


@dataclass
class TypeLoadStats:
    nodes_visited: int = 0
    edges_followed: int = 0
    max_depth_reached: int = 0
    types_registered: int = 0
    truncated: bool = False
    limit_hit: str | None = None


@dataclass
class NameConflict:
    """Two server-side names collapse to the same Python identifier after cleaning."""

    cleaned_name: str
    original_names: list[str]
    owner: ua.NodeId | None
    detail: str


@dataclass
class PendingType:
    """A type that was not published; the raw server definition is kept for inspection."""

    data_type: ua.NodeId
    name: str
    reason: RejectionReason
    detail: str
    raw_definition: Any
    pending_dependencies: list[ua.NodeId] = field(default_factory=list)


@dataclass
class BoundedTypeLoadResult:
    loaded: dict[str, type] = field(default_factory=dict)
    failed: list[PendingType] = field(default_factory=list)
    name_conflicts: list[NameConflict] = field(default_factory=list)
    stats: TypeLoadStats = field(default_factory=TypeLoadStats)


@dataclass
class _Candidate:
    data_type: ua.NodeId
    name: str
    browse_name: str
    sdef: ua.StructureDefinition
    merged_fields: list[ua.StructureField] | None = None


def _is_null_encoding(encoding_id: ua.NodeId) -> bool:
    return encoding_id.NamespaceIndex == 0 and encoding_id.Identifier == 0


def _resolvable_data_type(data_type: ua.NodeId) -> bool:
    if data_type.NamespaceIndex == 0 and data_type.Identifier in ua.ObjectIdNames:
        return True
    return (
        data_type in ua.extension_objects_by_datatype
        or data_type in ua.enums_by_datatype
        or data_type in ua.basetype_by_datatype
    )


def _strongly_connected_components(
    nodes: list[ua.NodeId], edges: dict[ua.NodeId, set[ua.NodeId]]
) -> list[list[ua.NodeId]]:
    index_of: dict[ua.NodeId, int] = {}
    lowlink: dict[ua.NodeId, int] = {}
    on_stack: set[ua.NodeId] = set()
    stack: list[ua.NodeId] = []
    components: list[list[ua.NodeId]] = []
    counter = 0
    for root in nodes:
        if root in index_of:
            continue
        work: list[tuple[ua.NodeId, Any]] = [(root, iter(edges.get(root, ())))]
        while work:
            node, successors = work[-1]
            if node not in index_of:
                index_of[node] = lowlink[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            descended = False
            for succ in successors:
                if succ not in index_of:
                    work.append((succ, iter(edges.get(succ, ()))))
                    descended = True
                    break
                if succ in on_stack:
                    lowlink[node] = min(lowlink[node], index_of[succ])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(component)
    return components


def _order_components(
    components: list[list[ua.NodeId]], edges: dict[ua.NodeId, set[ua.NodeId]]
) -> list[list[ua.NodeId]]:
    component_of: dict[ua.NodeId, int] = {}
    for idx, component in enumerate(components):
        for nid in component:
            component_of[nid] = idx
    indegree = [0] * len(components)
    enabling: dict[int, list[int]] = defaultdict(list)
    for nid, deps in edges.items():
        for dep in deps:
            source, target = component_of[dep], component_of[nid]
            if source != target:
                enabling[source].append(target)
                indegree[target] += 1
    queue = deque(idx for idx in range(len(components)) if indegree[idx] == 0)
    ordered = []
    while queue:
        idx = queue.popleft()
        ordered.append(components[idx])
        for target in enabling[idx]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return ordered


class _BoundedLoader:
    def __init__(self, server: Server | Client, limits: TypeLoadLimits, overwrite_existing: bool) -> None:
        self.server = server
        self.limits = limits
        self.overwrite_existing = overwrite_existing
        self.result = BoundedTypeLoadResult()
        self.candidates: dict[ua.NodeId, _Candidate] = {}
        self.order: list[ua.NodeId] = []
        self.parent_of: dict[ua.NodeId, ua.NodeId | None] = {}
        self.cyclic: set[ua.NodeId] = set()
        self.rejected: dict[ua.NodeId, PendingType] = {}
        self.skipped: set[ua.NodeId] = set()
        self.deps: dict[ua.NodeId, set[ua.NodeId]] = {}

    def _truncate(self, limit: str) -> None:
        stats = self.result.stats
        stats.truncated = True
        if stats.limit_hit is None:
            stats.limit_hit = limit
            _logger.warning("Bounded type loading truncated: %s limit reached", limit)

    @staticmethod
    def _cycle_path(
        start: ua.NodeId, target: ua.NodeId, parent_of: dict[ua.NodeId, ua.NodeId | None]
    ) -> list[ua.NodeId]:
        path = []
        current: ua.NodeId | None = start
        while current is not None:
            path.append(current)
            if current == target:
                return path
            current = parent_of.get(current)
        return []

    async def traverse(self, base_node: Node) -> None:
        stats = self.result.stats
        self.parent_of[base_node.nodeid] = None
        visited = {base_node.nodeid}
        queue: deque[tuple[Node, int]] = deque([(base_node, 0)])
        while queue:
            node, depth = queue.popleft()
            if stats.nodes_visited >= self.limits.max_nodes:
                self._truncate("max_nodes")
                break
            if depth > self.limits.max_depth:
                self._truncate("max_depth")
                continue
            stats.nodes_visited += 1
            stats.max_depth_reached = max(stats.max_depth_reached, depth)
            descs = await node.get_children_descriptions(refs=ua.ObjectIds.HasSubtype)
            children = [self.server.get_node(desc.NodeId) for desc in descs]
            if children:
                values = await self.server.read_attributes(children, ua.AttributeIds.DataTypeDefinition)
            else:
                values = []
            for desc, data_value in zip(descs, values):
                if stats.edges_followed >= self.limits.max_edges:
                    self._truncate("max_edges")
                    break
                stats.edges_followed += 1
                child_id = desc.NodeId
                if child_id in visited:
                    self.cyclic.update(self._cycle_path(node.nodeid, child_id, self.parent_of))
                    continue
                visited.add(child_id)
                self.parent_of[child_id] = node.nodeid
                sdef = data_value.Value.Value if data_value.Value is not None else None
                browse_name = desc.BrowseName.Name or ""
                if isinstance(sdef, ua.StructureDefinition):
                    self.candidates[child_id] = _Candidate(
                        data_type=child_id,
                        name=clean_name(browse_name),
                        browse_name=browse_name,
                        sdef=sdef,
                    )
                    self.order.append(child_id)
                elif sdef is not None:
                    self._reject_raw(child_id, browse_name, sdef)
                queue.append((self.server.get_node(child_id), depth + 1))

    def _reject(
        self,
        nid: ua.NodeId,
        reason: RejectionReason,
        detail: str,
        pending: list[ua.NodeId] | None = None,
    ) -> None:
        if nid in self.rejected:
            return
        cand = self.candidates[nid]
        _logger.warning("Rejecting data type %s (%s): %s", cand.name, nid, detail)
        pending_type = PendingType(
            data_type=nid,
            name=cand.name,
            reason=reason,
            detail=detail,
            raw_definition=cand.sdef,
            pending_dependencies=pending or [],
        )
        self.rejected[nid] = pending_type
        self.result.failed.append(pending_type)

    def _reject_raw(self, nid: ua.NodeId, browse_name: str, sdef: Any) -> None:
        _logger.warning("Rejecting data type %s (%s): unsupported DataTypeDefinition", browse_name, nid)
        pending_type = PendingType(
            data_type=nid,
            name=clean_name(browse_name),
            reason=RejectionReason.UnsupportedDefinition,
            detail=f"DataTypeDefinition is {type(sdef).__name__}, expected a StructureDefinition",
            raw_definition=sdef,
        )
        self.rejected[nid] = pending_type
        self.result.failed.append(pending_type)

    def _nearest_candidate_parent(self, nid: ua.NodeId) -> ua.NodeId | None:
        current = self.parent_of.get(nid)
        while current is not None:
            if current in self.candidates:
                return current
            current = self.parent_of.get(current)
        return None

    def validate(self) -> None:
        claimed_names: dict[str, ua.NodeId] = {}
        claimed_encodings: dict[ua.NodeId, ua.NodeId] = {}
        for nid in self.order:
            cand = self.candidates[nid]
            if nid in self.cyclic:
                others = [other for other in self.cyclic if other != nid]
                self._reject(
                    nid,
                    RejectionReason.InheritanceCycle,
                    f"HasSubtype inheritance cycle involving {cand.browse_name!r}",
                    others,
                )
                continue
            if cand.sdef.StructureType not in _SUPPORTED_STRUCTURE_TYPES:
                self._reject(
                    nid,
                    RejectionReason.UnsupportedDefinition,
                    f"StructureType {cand.sdef.StructureType!r} is not supported",
                )
                continue
            if cand.name in claimed_names:
                winner = self.candidates[claimed_names[cand.name]]
                detail = (
                    f"BrowseName {cand.browse_name!r} cleans to {cand.name!r}, "
                    f"already claimed by {winner.browse_name!r} ({winner.data_type})"
                )
                self.result.name_conflicts.append(
                    NameConflict(cand.name, [winner.browse_name, cand.browse_name], None, detail)
                )
                self._reject(nid, RejectionReason.NameConflict, detail)
                continue
            claimed_names[cand.name] = nid
            encoding_id = cand.sdef.DefaultEncodingId
            if not _is_null_encoding(encoding_id):
                if encoding_id in claimed_encodings:
                    self._reject(
                        nid,
                        RejectionReason.DuplicateEncodingId,
                        f"DefaultEncodingId {encoding_id} is shared with {claimed_encodings[encoding_id]}",
                    )
                    continue
                trusted = ua.extension_objects_by_typeid.get(encoding_id)
                if trusted is not None and getattr(trusted, "data_type", None) != nid:
                    self._reject(
                        nid,
                        RejectionReason.DuplicateEncodingId,
                        f"DefaultEncodingId {encoding_id} already belongs to trusted type {trusted.__name__}",
                    )
                    continue
                claimed_encodings[encoding_id] = nid
            existing = getattr(ua, cand.name, None)
            if existing is not None and getattr(existing, "data_type", None) != nid:
                self.result.name_conflicts.append(
                    NameConflict(
                        cand.name,
                        [cand.browse_name],
                        None,
                        f"ua.{cand.name} is already bound to another type; "
                        "the new type stays reachable through ua.get_type()",
                    )
                )
            if existing is not None and getattr(existing, "data_type", None) == nid and not self.overwrite_existing:
                self.skipped.add(nid)
        for nid in self.order:
            if nid in self.rejected:
                continue
            cand = self.candidates[nid]
            parent_id = self._nearest_candidate_parent(nid)
            inherited: list[ua.StructureField] = []
            if parent_id is not None:
                if parent_id in self.rejected:
                    self._reject(
                        nid,
                        RejectionReason.UnresolvedDependency,
                        f"parent type {self.candidates[parent_id].browse_name!r} was rejected",
                        [parent_id],
                    )
                    continue
                inherited = self.candidates[parent_id].merged_fields or []
            own = list(cand.sdef.Fields)
            own_names = {sfield.Name for sfield in own}
            cand.merged_fields = [sfield for sfield in inherited if sfield.Name not in own_names] + own
        for nid in self.order:
            if nid in self.rejected or nid in self.skipped:
                continue
            cand = self.candidates[nid]
            if not self._check_field_names(cand):
                continue
            if not self._check_field_dependencies(cand):
                continue

    def _check_field_names(self, cand: _Candidate) -> bool:
        first_seen: dict[str, str] = {}
        conflicts: list[tuple[str, str, str]] = []
        for sfield in cand.merged_fields or []:
            cleaned = clean_name(sfield.Name)
            if cleaned in first_seen:
                conflicts.append((cleaned, first_seen[cleaned], sfield.Name))
            else:
                first_seen[cleaned] = sfield.Name
        if cand.sdef.StructureType == ua.StructureType.StructureWithOptionalFields and "Encoding" in first_seen:
            conflicts.append(("Encoding", "Encoding", first_seen["Encoding"]))
        for cleaned, original, colliding in conflicts:
            detail = (
                f"fields {original!r} and {colliding!r} of {cand.browse_name!r} "
                f"both clean to Python identifier {cleaned!r}"
            )
            self.result.name_conflicts.append(NameConflict(cleaned, [original, colliding], cand.data_type, detail))
        if conflicts:
            self._reject(
                cand.data_type,
                RejectionReason.NameConflict,
                f"field names of {cand.browse_name!r} collide after cleaning: "
                + ", ".join(sorted({cleaned for cleaned, _, _ in conflicts})),
            )
            return False
        return True

    def _check_field_dependencies(self, cand: _Candidate) -> bool:
        deps: set[ua.NodeId] = set()
        unknown: list[ua.NodeId] = []
        for sfield in cand.merged_fields or []:
            data_type = sfield.DataType
            if data_type == cand.data_type or _resolvable_data_type(data_type):
                continue
            if data_type in self.candidates:
                deps.add(data_type)
            else:
                unknown.append(data_type)
        if unknown:
            self._reject(
                cand.data_type,
                RejectionReason.UnresolvedDependency,
                f"fields of {cand.browse_name!r} reference unknown DataTypes: {unknown}",
                unknown,
            )
            return False
        self.deps[cand.data_type] = deps
        return True

    def _merged_sdef(self, cand: _Candidate) -> ua.StructureDefinition:
        merged = ua.StructureDefinition()
        merged.DefaultEncodingId = cand.sdef.DefaultEncodingId
        merged.BaseDataType = cand.sdef.BaseDataType
        merged.StructureType = cand.sdef.StructureType
        merged.Fields = cand.merged_fields or []
        return merged

    def _generate_one(self, cand: _Candidate) -> type:
        env = make_structure(cand.data_type, cand.name, self._merged_sdef(cand), log_error=False)
        if not env or cand.name not in env:
            raise RuntimeError(f"class generation returned no type for {cand.name}")
        return env[cand.name]

    def _rollback_binding(self, name: str, previous: Any) -> None:
        if previous is None and getattr(ua, name, None) is not None:
            delattr(ua, name)

    def _publish(self, cand: _Candidate, cls: type) -> None:
        ua.register_extension_object(cand.name, cand.sdef.DefaultEncodingId, cls, cand.data_type)
        existing = getattr(ua, cand.name, None)
        if self.overwrite_existing and existing is not cls and getattr(existing, "data_type", None) == cand.data_type:
            setattr(ua, cand.name, cls)
        self.result.stats.types_registered += 1
        self.result.loaded[cand.name] = cls

    def _generate_component(self, nids: list[ua.NodeId]) -> None:
        if len(nids) == 1:
            nid = nids[0]
            cand = self.candidates[nid]
            previous = getattr(ua, cand.name, None)
            try:
                cls = self._generate_one(cand)
            except Exception as exc:
                self._rollback_binding(cand.name, previous)
                self._reject(nid, RejectionReason.GenerationFailed, str(exc))
                return
            self._publish(cand, cls)
            return
        self._generate_recursive_group(nids)

    def _generate_recursive_group(self, nids: list[ua.NodeId]) -> None:
        placeholders = {nid: type(f"_PendingPeer{position}", (), {}) for position, nid in enumerate(nids)}
        registry_backup = {}
        for nid, placeholder in placeholders.items():
            registry_backup[nid] = ua.extension_objects_by_datatype.get(nid)
            ua.extension_objects_by_datatype[nid] = placeholder
        previous_bindings = {nid: getattr(ua, self.candidates[nid].name, None) for nid in nids}
        generated: dict[ua.NodeId, type] = {}
        try:
            for nid in nids:
                generated[nid] = self._generate_one(self.candidates[nid])
        except Exception as exc:
            for nid in nids:
                self._rollback_binding(self.candidates[nid].name, previous_bindings[nid])
                others = [other for other in nids if other != nid]
                self._reject(
                    nid,
                    RejectionReason.GenerationFailed,
                    f"mutually recursive group could not be generated: {exc}",
                    others,
                )
            return
        finally:
            for nid in placeholders:
                if registry_backup[nid] is None:
                    ua.extension_objects_by_datatype.pop(nid, None)
                else:
                    ua.extension_objects_by_datatype[nid] = registry_backup[nid]
        real_types = {placeholder: generated[nid] for nid, placeholder in placeholders.items()}
        for nid in nids:
            cls = generated[nid]
            for attr, value in list(vars(cls).items()):
                if isinstance(value, type) and value in real_types:
                    setattr(cls, attr, real_types[value])
            for dataclass_field in dataclass_fields(cls):
                factory = dataclass_field.default_factory
                if isinstance(factory, type) and factory in real_types:
                    dataclass_field.default_factory = real_types[factory]  # type: ignore[misc]
            union_types = getattr(cls, "_union_types", None)
            if union_types:
                cls._union_types = [real_types.get(member, member) for member in union_types]  # type: ignore[attr-defined]
        for nid in nids:
            self._publish(self.candidates[nid], generated[nid])

    def generate(self) -> None:
        remaining = [nid for nid in self.order if nid not in self.rejected and nid not in self.skipped]
        remaining_set = set(remaining)
        edges = {nid: {dep for dep in self.deps.get(nid, ()) if dep in remaining_set} for nid in remaining}
        components = _strongly_connected_components(remaining, edges)
        for component in _order_components(components, edges):
            failed_deps = sorted(
                {dep for nid in component for dep in self.deps.get(nid, ()) if dep in self.rejected},
                key=str,
            )
            if failed_deps:
                for nid in component:
                    self._reject(
                        nid,
                        RejectionReason.UnresolvedDependency,
                        "members of its dependency group failed to load",
                        failed_deps,
                    )
                continue
            self._generate_component(component)


async def load_data_type_definitions_bounded(
    server: Server | Client,
    base_node: Node | None = None,
    *,
    limits: TypeLoadLimits | None = None,
    overwrite_existing: bool = False,
) -> BoundedTypeLoadResult:
    """
    Load structure DataTypeDefinitions below base_node under explicit traversal bounds.

    The HasSubtype graph is expanded iteratively and every visited node, followed
    reference and depth level is counted; once a limit in ``limits`` is hit the
    traversal stops and reports ``stats.truncated`` instead of wandering through a
    hostile or broken type graph. Legitimate self-references and mutually recursive
    field types are supported, while HasSubtype inheritance cycles, duplicated
    DefaultEncodingIds, colliding cleaned names and unknown StructureType variants
    are rejected with a concrete reason.

    Types are generated with make_structure only: server-provided strings are never
    evaluated as Python expressions. A dependency group is published atomically, so
    a failed group never appears as a decodable type; its members are reported in
    ``result.failed`` together with their raw StructureDefinition and the NodeIds
    of the dependencies that could not be resolved. Types that were already
    registered before this call are left untouched and stay usable.
    """
    if limits is None:
        limits = TypeLoadLimits()
    if base_node is None:
        base_node = server.nodes.base_structure_type
    loader = _BoundedLoader(server, limits, overwrite_existing)
    await loader.traverse(base_node)
    loader.validate()
    loader.generate()
    return loader.result
