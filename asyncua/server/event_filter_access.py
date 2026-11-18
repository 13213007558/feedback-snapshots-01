from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from asyncua import ua

from .address_space import AddressSpace, NodeData


@dataclass(frozen=True, slots=True)
class EventFieldTarget:
    nodeid: ua.NodeId
    attribute_id: ua.AttributeIds
    index_range: str | None


@dataclass(frozen=True, slots=True)
class EventFieldAccess:
    type_definition_id: ua.NodeId
    browse_path: tuple[tuple[str, int], ...]
    attribute_id: ua.AttributeIds = ua.AttributeIds.Value
    index_range: str | None = None

    @staticmethod
    def from_operand(operand: ua.SimpleAttributeOperand) -> "EventFieldAccess":
        try:
            attribute_id = ua.AttributeIds(operand.AttributeId)
        except ValueError:
            raise EventFilterAccessError(
                ua.StatusCodes.BadAttributeIdInvalid,
                f"Attribute id {operand.AttributeId} is not a valid OPC UA attribute",
            ) from None
        return EventFieldAccess(
            type_definition_id=operand.TypeDefinitionId,
            browse_path=tuple((name.Name, name.NamespaceIndex) for name in operand.BrowsePath),
            attribute_id=attribute_id,
            index_range=operand.IndexRange,
        )


class EventFilterAccessError(Exception):
    def __init__(self, status_code: ua.StatusCodes, message: str) -> None:
        super().__init__(message)
        self.status_code = ua.StatusCode(status_code)


class EventFieldAccessPolicy:
    """
    Decides which event fields a session may reference in an EventFilter.

    In allowlist mode only explicitly allowed fields are admitted. In deny mode
    (the default, preserving the historical server behaviour) every resolvable
    field is admitted except the explicitly denied ones. A field the server
    cannot prove to exist is always rejected, so a filter can never smuggle a
    read through an unresolvable BrowsePath.
    """

    def __init__(self, allowed_fields: set[EventFieldAccess] | None = None, *, allow_by_default: bool = True) -> None:
        self._allowed_fields: set[EventFieldAccess] = set(allowed_fields or ())
        self._denied_fields: set[EventFieldAccess] = set()
        self.allow_by_default = allow_by_default

    def allow(self, field_access: EventFieldAccess) -> None:
        self._denied_fields.discard(field_access)
        self._allowed_fields.add(field_access)

    def allow_operand(self, operand: ua.SimpleAttributeOperand) -> None:
        self.allow(EventFieldAccess.from_operand(operand))

    def deny(self, field_access: EventFieldAccess) -> None:
        self._allowed_fields.discard(field_access)
        self._denied_fields.add(field_access)

    def deny_operand(self, operand: ua.SimpleAttributeOperand) -> None:
        self.deny(EventFieldAccess.from_operand(operand))

    def is_allowed(self, field_access: EventFieldAccess) -> bool:
        if field_access in self._denied_fields:
            return False
        if self.allow_by_default:
            return True
        return field_access in self._allowed_fields


class EventFilterAccessValidator:
    """
    Resolves every field an EventFilter can read and enforces an EventFieldAccessPolicy
    before the monitored item is created. Admission happens up front: a filter that
    references a denied or unprovable field is rejected as a whole instead of being
    evaluated with masked output columns.
    """

    def __init__(
        self,
        aspace: AddressSpace,
        policy: EventFieldAccessPolicy | Callable[[], EventFieldAccessPolicy | None] | None = None,
    ) -> None:
        self._aspace = aspace
        if callable(policy):
            self._policy_provider: Callable[[], EventFieldAccessPolicy | None] = policy
        else:
            static_policy = policy
            self._policy_provider = lambda: static_policy

    def _current_policy(self) -> EventFieldAccessPolicy:
        return self._policy_provider() or EventFieldAccessPolicy()

    def validate_filter(self, event_filter: ua.EventFilter) -> None:
        policy = self._current_policy()
        if event_filter is None or event_filter.WhereClause is None:
            raise EventFilterAccessError(
                ua.StatusCodes.BadEventFilterInvalid,
                "Event filter or its WhereClause is missing",
            )
        for operand in event_filter.SelectClauses:
            self._validate_simple_attribute_operand(operand, policy)
        for element in event_filter.WhereClause.Elements:
            for operand in element.FilterOperands:
                self._validate_filter_operand(operand, policy)

    def _validate_filter_operand(self, operand: ua.FilterOperand, policy: EventFieldAccessPolicy) -> None:
        if isinstance(operand, ua.SimpleAttributeOperand):
            self._validate_simple_attribute_operand(operand, policy)
            return
        if isinstance(operand, ua.LiteralOperand | ua.ElementOperand):
            return
        raise EventFilterAccessError(
            ua.StatusCodes.BadFilterOperandInvalid,
            f"Event filter operand type {type(operand).__name__} is not supported",
        )

    def _validate_simple_attribute_operand(
        self, operand: ua.SimpleAttributeOperand, policy: EventFieldAccessPolicy
    ) -> None:
        field_access = EventFieldAccess.from_operand(operand)
        if not policy.is_allowed(field_access):
            raise EventFilterAccessError(
                ua.StatusCodes.BadUserAccessDenied,
                f"Access to event field {self._describe(operand)} is not allowed",
            )
        self.resolve_operand(operand)

    def resolve_operand(self, operand: ua.SimpleAttributeOperand) -> EventFieldTarget:
        try:
            attribute_id = ua.AttributeIds(operand.AttributeId)
        except ValueError:
            raise EventFilterAccessError(
                ua.StatusCodes.BadAttributeIdInvalid,
                f"Attribute id {operand.AttributeId} is not a valid OPC UA attribute",
            ) from None
        current = self._resolve_type_definition(operand.TypeDefinitionId)
        for browse_name in operand.BrowsePath:
            current = self._navigate_forward(current, browse_name)
        if attribute_id not in current.attributes:
            raise EventFilterAccessError(
                ua.StatusCodes.BadAttributeIdInvalid,
                f"Attribute {attribute_id.name} does not exist on node {current.nodeid}",
            )
        if operand.IndexRange:
            raise EventFilterAccessError(
                ua.StatusCodes.BadIndexRangeInvalid,
                f"IndexRange is not supported on event field {self._describe(operand)}",
            )
        return EventFieldTarget(current.nodeid, attribute_id, operand.IndexRange)

    def _resolve_type_definition(self, type_definition_id: ua.NodeId) -> NodeData:
        if type_definition_id is None or type_definition_id == ua.NodeId(ua.ObjectIds.Null):
            type_definition_id = ua.NodeId(ua.ObjectIds.BaseEventType)
        type_node = self._aspace.get(type_definition_id)
        if type_node is None:
            raise EventFilterAccessError(
                ua.StatusCodes.BadNodeIdUnknown,
                f"Event type definition {type_definition_id} does not exist in the address space",
            )
        node_class = self._read_node_class(type_node)
        if node_class != ua.NodeClass.ObjectType:
            raise EventFilterAccessError(
                ua.StatusCodes.BadTypeDefinitionInvalid,
                f"Node {type_definition_id} is not an event type definition (node class {node_class})",
            )
        return type_node

    @staticmethod
    def _read_node_class(node: NodeData) -> ua.NodeClass | None:
        attribute = node.attributes.get(ua.AttributeIds.NodeClass)
        if attribute is None or attribute.value is None or attribute.value.Value is None:
            return None
        node_class = attribute.value.Value.Value
        if node_class is None:
            return None
        return ua.NodeClass(node_class)

    def _navigate_forward(self, current: NodeData, browse_name: ua.QualifiedName) -> NodeData:
        for type_node in self._type_hierarchy(current):
            for ref in type_node.references:
                if ref.IsForward and ref.BrowseName == browse_name and ref.NodeId in self._aspace:
                    return self._aspace[ref.NodeId]
        raise EventFilterAccessError(
            ua.StatusCodes.BadNoMatch,
            f"Browse name {browse_name.to_string()} cannot be resolved from node {current.nodeid}",
        )

    def _type_hierarchy(self, start: NodeData) -> list[NodeData]:
        hierarchy: list[NodeData] = []
        seen: set[ua.NodeId] = set()
        current: NodeData | None = start
        while current is not None and current.nodeid not in seen:
            seen.add(current.nodeid)
            hierarchy.append(current)
            current = self._parent_type(current)
        return hierarchy

    def _parent_type(self, node: NodeData) -> NodeData | None:
        for ref in node.references:
            is_subtype = ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasSubtype)
            if is_subtype and not ref.IsForward and ref.NodeId in self._aspace:
                return self._aspace[ref.NodeId]
        return None

    @staticmethod
    def _describe(operand: ua.SimpleAttributeOperand) -> str:
        path = "/".join(name.to_string() for name in operand.BrowsePath) or "<instance>"
        try:
            attribute_name = ua.AttributeIds(operand.AttributeId).name
        except ValueError:
            attribute_name = f"UnknownAttribute({operand.AttributeId})"
        return f"{operand.TypeDefinitionId}:{path}:{attribute_name}"
