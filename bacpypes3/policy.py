"""
Property Write Access Policy
----------------------------

BACpypes3 exposes the BACnet object model through the WriteProperty and
WritePropertyMultiple services.  A commandable object's effective value is
not a single property value: it is selected from the highest occupied slot in
``priorityArray`` and falls back to ``relinquishDefault``.  Checking only the
value being written (or the resulting present-value) is therefore not enough
to decide whether a write is allowed.  Writing a value equal to the current
effective value at a higher priority, or writing NULL, can silently take
control of another subsystem's override without changing what is displayed.

This module implements a small, fail-closed policy layer for property writes.
The service layer hands the policy the complete target - object, property,
array index, priority and whether the write relinquishes a slot - before it
mutates the object.  A policy can allow ordinary writes from a limited set of
priorities and can refuse to relinquish a slot that it did not claim itself.
"""

from __future__ import annotations

import dataclasses

from typing import Any as _Any
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .basetypes import OptionalUnsigned, PropertyIdentifier
from .errors import ExecutionError
from .primitivedata import Null, ObjectIdentifier, ObjectType, TagClass, TagNumber

#
#   Any index sentinel
#

ANY_INDEX = object()

# marker used while a write decision has been made but not yet applied
_IN_FLIGHT = "<in-flight>"


def _property_attr(prop: Union[int, str, PropertyIdentifier, _Any]) -> str:
    """Return the attribute form of a property identifier."""
    if isinstance(prop, str):
        try:
            return PropertyIdentifier(prop).attr
        except ValueError:
            return prop
    if isinstance(prop, int):
        try:
            return PropertyIdentifier(prop).attr
        except ValueError:
            return str(prop)
    return getattr(prop, "attr", str(prop))


def _display(value: _Any) -> str:
    """Render a BACnet value for a report without changing its type."""
    if value is None:
        return "<null>"
    if isinstance(value, Null):
        return "<null>"
    return str(value)


def property_value_is_null(value: _Any) -> bool:
    """
    Return True when an ``Any`` property value carries a BACnet NULL.

    The check looks at the encoded tag list, before the value is cast to the
    property type, so a policy denial happens before any object state can
    change and malformed values still cannot slip past the policy.
    """
    tag_list = getattr(value, "tagList", None)
    if not tag_list:
        return False

    # ignore the context wrappers, the value itself must be a single NULL
    content = [
        tag
        for tag in tag_list
        if tag.tag_class not in (TagClass.opening, TagClass.closing)
    ]
    if len(content) != 1:
        return False
    tag = content[0]
    return (
        (tag.tag_class == TagClass.application)
        and (tag.tag_number == TagNumber.null)
        and (tag.tag_lvt == 0)
    )


def is_commandable(obj: _Any) -> bool:
    """
    Return True for a local object whose present-value is selected from a
    settled 16 slot priority array.
    """
    priority_array = getattr(obj, "priorityArray", None)
    if not isinstance(priority_array, list) or len(priority_array) != 16:
        return False
    if not hasattr(obj, "recalculating"):
        return False
    return "relinquishDefault" in getattr(obj, "_elements", {})


#
#   WriteTarget
#


@dataclasses.dataclass(frozen=True)
class WriteTarget:
    """
    The complete target of a property write.

    ``priority`` is the effective priority slot: for a write to
    ``presentValue`` on a commandable object without an explicit priority it
    is 16, and for a write to one element of ``priorityArray`` it is the
    array index.  ``requested_priority`` preserves the value carried by the
    request so a policy can distinguish an explicit slot from the implicit
    default.
    """

    object_identifier: ObjectIdentifier
    object_type: Optional[ObjectType]
    property_identifier: _Any
    property_name: str
    property_array_index: Optional[int]
    priority: Optional[int]
    requested_priority: Optional[int]
    relinquish: bool
    commandable: bool
    principal: str

    @property
    def slot(self) -> Optional[int]:
        """The priority slot this target would occupy, if any."""
        if (
            self.commandable
            and (self.property_name in ("presentValue", "priorityArray"))
            and (self.priority is not None)
            and (1 <= self.priority <= 16)
        ):
            return self.priority
        return None

    @property
    def is_bulk_priority_array(self) -> bool:
        return (self.property_name == "priorityArray") and (
            self.property_array_index in (None, 0)
        )

    def describe(self) -> str:
        """Return a stable one line description of the target."""
        text = f"{self.object_identifier} {self.property_name}"
        if self.property_array_index is not None:
            text += f"[{self.property_array_index}]"
        if self.priority is not None:
            text += f" priority {self.priority}"
        if self.relinquish:
            text += " (relinquish)"
        return text

    @classmethod
    def from_object(
        cls,
        obj: _Any,
        property_identifier: Union[int, str, PropertyIdentifier],
        property_array_index: Optional[int] = None,
        priority: Optional[int] = None,
        relinquish: bool = False,
        principal: str = "backend",
    ) -> "WriteTarget":
        object_identifier = getattr(obj, "objectIdentifier", None)
        if object_identifier is None:
            raise ValueError("write access policy requires an object identifier")
        object_identifier = ObjectIdentifier(object_identifier)

        property_class = getattr(obj, "_property_identifier_class", PropertyIdentifier)
        if isinstance(property_identifier, (int, str)) and not isinstance(
            property_identifier, PropertyIdentifier
        ):
            property_identifier = property_class(property_identifier)
        property_name = _property_attr(property_identifier)

        commandable = is_commandable(obj)

        # a commandable present-value write without a priority is at 16
        effective_priority = priority
        if commandable and (property_name == "presentValue") and (priority is None):
            effective_priority = 16
        elif (property_name == "priorityArray") and (
            property_array_index not in (None, 0)
        ):
            effective_priority = property_array_index

        return cls(
            object_identifier=object_identifier,
            object_type=object_identifier[0],
            property_identifier=property_identifier,
            property_name=property_name,
            property_array_index=property_array_index,
            priority=effective_priority,
            requested_priority=priority,
            relinquish=bool(relinquish),
            commandable=commandable,
            principal=principal,
        )


#
#   WriteRule
#


@dataclasses.dataclass(frozen=True)
class WriteRule:
    """
    One allow (or explicit deny) rule for property writes.

    A rule only matches a target if every specified field matches.  A rule
    with ``priorities`` leaves priority-less targets unmatched, and a rule
    without ``priorities`` matches only priority-less targets.  This makes it
    explicit which command priority slots are granted.
    """

    object_identifier: Optional[ObjectIdentifier] = None
    object_type: Optional[ObjectType] = None
    property_identifier: Optional[_Any] = None
    array_index: _Any = ANY_INDEX
    priorities: Optional[Iterable[int]] = None
    allow_relinquish: bool = False
    allow_relinquish_default: bool = False
    allow_foreign_relinquish: bool = False
    allowed: bool = True
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.object_identifier is not None and not isinstance(
            self.object_identifier, ObjectIdentifier
        ):
            object.__setattr__(
                self, "object_identifier", ObjectIdentifier(self.object_identifier)
            )
        if self.object_type is not None and not isinstance(
            self.object_type, ObjectType
        ):
            object.__setattr__(self, "object_type", ObjectType(self.object_type))
        if self.priorities is not None:
            priorities = frozenset(int(p) for p in self.priorities)
            if not priorities or any((p < 1) or (p > 16) for p in priorities):
                raise ValueError("priorities must be a non-empty subset of 1..16")
            object.__setattr__(self, "priorities", priorities)
        if self.name is None:
            object.__setattr__(self, "name", self._default_name())

    def _default_name(self) -> str:
        parts = [str(self.object_identifier or self.object_type or "*")]
        if self.property_identifier is not None:
            parts.append(_property_attr(self.property_identifier))
        else:
            parts.append("*")
        if self.array_index is not ANY_INDEX:
            parts.append(f"[{self.array_index}]")
        if self.priorities is not None:
            parts.append("priorities=" + _format_priorities(self.priorities))
        return " ".join(parts)

    def matches(self, target: WriteTarget) -> bool:
        if (
            self.object_identifier is not None
            and self.object_identifier != target.object_identifier
        ):
            return False
        if self.object_type is not None and self.object_type != target.object_type:
            return False
        if (
            self.property_identifier is not None
            and _property_attr(self.property_identifier) != target.property_name
        ):
            return False
        if (self.array_index is not ANY_INDEX) and (
            self.array_index != target.property_array_index
        ):
            return False

        # a broad present-value rule must not silently authorize changes to
        # the fallback value
        if (
            target.property_name == "relinquishDefault"
            and (self.property_identifier is None)
            and (not self.allow_relinquish_default)
        ):
            return False

        if self.priorities is None:
            if target.priority is not None:
                return False
        elif (target.priority is None) or (target.priority not in self.priorities):
            return False

        if (
            target.property_name == "relinquishDefault"
            and not self.allow_relinquish_default
        ):
            return False
        if target.relinquish and not self.allow_relinquish:
            return False

        # a priority grant only applies to commandable points; a plain
        # present-value has no slot and needs its own rule
        if (
            (target.property_name == "presentValue")
            and (not target.commandable)
            and (self.priorities is not None)
        ):
            return False

        return True


def _simulate(
    grants: Dict[Tuple[ObjectIdentifier, int], str], decision: WriteDecision
) -> Optional[Dict[Tuple[ObjectIdentifier, int], str]]:
    """Return the grant view a later write in the same batch would see."""
    target = decision.target
    slot = target.slot
    if (not decision.allowed) or (slot is None):
        return None

    key = (target.object_identifier, slot)
    if target.relinquish:
        if grants.get(key) != target.principal:
            return None
    elif grants.get(key) == target.principal:
        return None

    simulated = dict(grants)
    if target.relinquish:
        del simulated[key]
    else:
        simulated[key] = target.principal
    return simulated


def _format_priorities(priorities: Iterable[int]) -> str:
    values = sorted(set(int(p) for p in priorities))
    ranges: List[str] = []
    start = previous = None
    for value in values:
        if start is None:
            start = previous = value
        elif value == previous + 1:
            previous = value
        else:
            ranges.append(f"{start}" if start == previous else f"{start}-{previous}")
            start = previous = value
    if start is not None:
        ranges.append(f"{start}" if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


#
#   WriteDecision
#


@dataclasses.dataclass(frozen=True)
class WriteDecision:
    """The policy result for one property write target."""

    target: WriteTarget
    allowed: bool
    reason: str
    rule: Optional[str] = None
    error_class: str = "property"
    error_code: str = "writeAccessDenied"

    @property
    def slot(self) -> Optional[int]:
        """The priority slot this decision would affect, if any."""
        return self.target.slot

    def __str__(self) -> str:
        state = "allow" if self.allowed else "deny"
        return f"{state} {self.target.describe()}: {self.reason}"


class WriteAccessDenied(ExecutionError):
    """Raised by the service layer when the policy rejects a write."""

    def __init__(self, decision: WriteDecision) -> None:
        super().__init__(errorClass=decision.error_class, errorCode=decision.error_code)
        self.decision = decision

    def __str__(self) -> str:
        return f"{self.errorClass}: {self.errorCode} ({self.decision.reason})"


#
#   WriteAccessPolicy
#


class WriteAccessPolicy:
    """
    A fail-closed allow-list for local property writes.

    Without a matching rule every write is denied.  Installing a policy on an
    ``Application`` therefore limits the device to explicitly granted
    targets.  The policy also remembers which priority slots it has awarded
    to which principal, so a NULL write can only release an override that the
    same principal set through this policy.
    """

    def __init__(
        self,
        rules: Sequence[WriteRule] = (),
        *,
        principal: str = "backend",
        error_class: str = "property",
        error_code: str = "writeAccessDenied",
    ) -> None:
        self.rules: List[WriteRule] = list(rules)
        self.principal = principal
        self.error_class = error_class
        self.error_code = error_code
        self.audit: List[WriteDecision] = []
        self._grants: Dict[Tuple[ObjectIdentifier, int], str] = {}
        self._reservations: List[Tuple[ObjectIdentifier, int, Optional[str]]] = []

    def add_rule(self, rule: WriteRule) -> WriteRule:
        self.rules.append(rule)
        return rule

    def allow(self, **kwargs: _Any) -> WriteRule:
        """Add an allow rule and return it."""
        kwargs.setdefault("allowed", True)
        return self.add_rule(WriteRule(**kwargs))

    def deny(self, **kwargs: _Any) -> WriteRule:
        """Add an explicit deny rule and return it."""
        kwargs["allowed"] = False
        return self.add_rule(WriteRule(**kwargs))

    # -----

    def slot_owner(
        self, object_identifier: Union[ObjectIdentifier, _Any], priority: int
    ) -> Optional[str]:
        """Return the principal this policy granted a priority slot to."""
        key = (ObjectIdentifier(object_identifier), int(priority))
        owner = self._grants.get(key)
        if owner is not None:
            return owner
        for object_prefix, slot, principal in self._reservations:
            if (object_prefix, slot) == key:
                return principal
        return None

    def slot_owners(
        self, object_identifier: Union[ObjectIdentifier, _Any]
    ) -> Dict[int, str]:
        """Return a copy of the slots granted for an object."""
        object_identifier = ObjectIdentifier(object_identifier)
        return {
            priority: owner
            for (objid, priority), owner in self._grants.items()
            if objid == object_identifier
        }

    # -----

    def authorize(
        self,
        obj: _Any,
        property_identifier: Union[int, str, PropertyIdentifier],
        property_array_index: Optional[int] = None,
        priority: Optional[int] = None,
        relinquish: bool = False,
        principal: Optional[str] = None,
    ) -> WriteDecision:
        """
        Decide whether this write may proceed.  This method has no side
        effects on the BACnet object.  Call :meth:`note_written` after the
        object has accepted the write.
        """
        target = WriteTarget.from_object(
            obj,
            property_identifier,
            property_array_index=property_array_index,
            priority=priority,
            relinquish=relinquish,
            principal=principal or self.principal,
        )
        decision = self._evaluate(target, self._grant_view())
        self.audit.append(decision)
        self._reserve(decision)
        return decision

    def preflight(self, requests: Iterable[Dict[str, _Any]]) -> List[WriteDecision]:
        """
        Decide a batch of writes against a temporary view of the slot grants.

        The service layer uses this before applying any write of a
        WritePropertyMultiple request, so a denial anywhere in the request
        leaves every object unchanged.  Nothing is granted here; call
        :meth:`note_written` for each successfully applied write.
        """
        grants = self._grant_view()
        decisions: List[WriteDecision] = []
        for request in requests:
            target = WriteTarget.from_object(
                request["obj"],
                request["property_identifier"],
                property_array_index=request.get("property_array_index"),
                priority=request.get("priority"),
                relinquish=bool(request.get("relinquish", False)),
                principal=request.get("principal") or self.principal,
            )
            decision = self._evaluate(target, grants)
            decisions.append(decision)
            self.audit.append(decision)

            # let later writes in the same request see earlier grants
            simulation = _simulate(grants, decision)
            if simulation is not None:
                grants = simulation

        # reserve nothing when the batch will be refused in full
        if all(decision.allowed for decision in decisions):
            for decision in decisions:
                self._reserve(decision)

        return decisions

    def note_written(self, decision: WriteDecision) -> None:
        """
        Record a successfully applied write.  Only call this after the object
        has accepted the write; a failed write must not create a slot grant.
        """
        if not decision.allowed:
            return
        target = decision.target
        if target.slot is None:
            return

        key = (target.object_identifier, target.slot)
        if self._release_reservation(key):
            if target.relinquish:
                if self._grants.get(key) == target.principal:
                    del self._grants[key]
            else:
                self._grants[key] = target.principal
        elif not target.relinquish:
            # no reservation was made (for example a direct policy caller);
            # the successful write still awards the slot
            self._grants[key] = target.principal

    def cancel(self, decision: WriteDecision) -> None:
        """
        Drop the reservation made by :meth:`authorize` when the write did not
        reach the object, for example because the value failed to decode.
        """
        target = decision.target
        if target.slot is not None:
            key = (target.object_identifier, target.slot)
            self._release_reservation(key)
            # only this principal's provisional grant may be dropped
            if (
                (not target.relinquish)
                and (self._grants.get(key) == target.principal)
            ):
                del self._grants[key]

    # -----

    def _grant_view(self) -> Dict[Tuple[ObjectIdentifier, int], str]:
        """
        Return the grants plus any in-flight reservations.  A reservation for
        a NULL write is represented by an opaque marker so a competing
        release cannot slip in while the write is being applied.
        """
        view = dict(self._grants)
        for object_identifier, slot, _principal in self._reservations:
            # an in-flight write has not been confirmed by the object yet, so
            # neither a competing write nor a release may assume its outcome
            view.setdefault((object_identifier, slot), _IN_FLIGHT)
        return view

    def _reserve(self, decision: WriteDecision) -> None:
        """
        Reserve the slot a decision will affect so a concurrent denial cannot
        steal it while the object write is in flight.
        """
        target = decision.target
        if (not decision.allowed) or (target.slot is None):
            return
        if target.relinquish:
            self._reservations.append(
                (target.object_identifier, target.slot, None)
            )
        else:
            self._reservations.append(
                (target.object_identifier, target.slot, target.principal)
            )

    def _release_reservation(
        self, key: Tuple[ObjectIdentifier, int]
    ) -> bool:
        for i, (object_identifier, slot, _principal) in enumerate(self._reservations):
            if (object_identifier, slot) == key:
                del self._reservations[i]
                return True
        return False

    # -----

    def _evaluate(
        self, target: WriteTarget, grants: Dict[Tuple[ObjectIdentifier, int], str]
    ) -> WriteDecision:
        reason = self._structural_denial(target)
        if reason is not None:
            return self._decision(target, False, reason)

        matching = [rule for rule in self.rules if rule.matches(target)]
        denied_rules = [rule for rule in matching if not rule.allowed]
        allowed_rules = [rule for rule in matching if rule.allowed]

        if denied_rules:
            rule = denied_rules[0]
            return self._decision(target, False, f"denied by rule {rule.name!r}", rule)

        if not allowed_rules:
            reason = "no matching write rule"
            if target.priority is not None:
                reason += f" for priority {target.priority}"
            return self._decision(target, False, reason)

        rule = allowed_rules[0]
        if target.relinquish:
            reason = self._relinquish_denial(target, rule, grants)
            if reason is not None:
                return self._decision(target, False, reason, rule)

        return self._decision(target, True, f"allowed by rule {rule.name!r}", rule)

    def _structural_denial(self, target: WriteTarget) -> Optional[str]:
        if target.property_name == "priorityArray":
            if target.requested_priority is not None:
                return "priority is not part of a priority-array write"
            if target.is_bulk_priority_array:
                return (
                    "whole priority-array writes have no per-slot identity; "
                    "command present-value at a granted priority instead"
                )
            index = target.property_array_index
            if (index is None) or (index < 1) or (index > 16):
                return f"invalid priority-array index: {index!r}"
            return (
                f"priority-array[{index}] is read-only; "
                "command present-value at that priority instead"
            )

        if (
            target.property_name == "relinquishDefault"
            and target.requested_priority is not None
        ):
            return "priority is not part of a relinquish-default write"

        if target.requested_priority is not None:
            if (target.requested_priority < 1) or (target.requested_priority > 16):
                return f"invalid priority: {target.requested_priority}"
            if not target.commandable:
                return "this object is not commandable and has no priority slots"

        if target.relinquish and (target.slot is None):
            return "null can only relinquish a command priority slot"

        return None

    def _relinquish_denial(
        self,
        target: WriteTarget,
        rule: WriteRule,
        grants: Dict[Tuple[ObjectIdentifier, int], str],
    ) -> Optional[str]:
        # Release must be an explicit operation.  An implicit priority-16
        # release is ambiguous and could be confused with a normal write.
        if (
            target.property_name != "priorityArray"
            and target.requested_priority is None
        ):
            return "relinquish requires an explicit priority"

        slot = target.slot
        if slot is None:
            return "relinquish target has no priority slot"

        owner = grants.get((target.object_identifier, slot))
        if owner is None:
            return f"cannot relinquish priority {slot}: no slot owned by this principal"
        if (owner != target.principal) and (not rule.allow_foreign_relinquish):
            return f"cannot relinquish priority {slot}: slot is owned by {owner!r}"
        return None

    def _decision(
        self,
        target: WriteTarget,
        allowed: bool,
        reason: str,
        rule: Optional[WriteRule] = None,
    ) -> WriteDecision:
        return WriteDecision(
            target=target,
            allowed=allowed,
            reason=reason,
            rule=rule.name if rule is not None else None,
            error_class=self.error_class,
            error_code=self.error_code,
        )


#
#   Reporting
#


@dataclasses.dataclass(frozen=True)
class PrioritySlot:
    priority: int
    value: _Any
    is_null: bool
    owner: Optional[str] = None

    def __str__(self) -> str:
        text = f"priority {self.priority:2d}: {_display(self.value)}"
        if self.is_null:
            text = f"priority {self.priority:2d}: <null>"
        if self.owner is not None:
            text += f" (owner: {self.owner})"
        return text


@dataclasses.dataclass(frozen=True)
class CommandableSnapshot:
    object_identifier: ObjectIdentifier
    effective_value: _Any
    current_command_priority: Optional[int]
    relinquish_default: _Any
    slots: Tuple[PrioritySlot, ...]

    def format(self) -> str:
        """Return a stable report of the effective value and every slot."""
        if self.current_command_priority is None:
            current = "<none>"
        else:
            current = str(self.current_command_priority)
        lines = [
            f"object {self.object_identifier}",
            f"  present-value = {_display(self.effective_value)}",
            f"  current-command-priority = {current}",
            f"  relinquish-default = {_display(self.relinquish_default)}",
        ]
        lines.extend("  " + str(slot) for slot in self.slots)
        return "\n".join(lines)


def snapshot_commandable(
    obj: _Any, policy: Optional[WriteAccessPolicy] = None
) -> CommandableSnapshot:
    """
    Capture the effective value, current command priority, relinquish default
    and every priority-array slot of a commandable object.
    """
    priority_array = getattr(obj, "priorityArray", None)
    if not isinstance(priority_array, list) or len(priority_array) != 16:
        raise TypeError("commandable object with a 16 element priorityArray required")

    object_identifier = ObjectIdentifier(obj.objectIdentifier)
    slots: List[PrioritySlot] = []
    for i, priority_value in enumerate(priority_array):
        choice = getattr(priority_value, "_choice", None)
        is_null = (choice is None) or (choice == "null")
        value = None if is_null else getattr(priority_value, choice)
        slots.append(
            PrioritySlot(
                priority=i + 1,
                value=value,
                is_null=is_null,
                owner=policy.slot_owner(object_identifier, i + 1)
                if policy is not None
                else None,
            )
        )

    current_command_priority = getattr(obj, "currentCommandPriority", None)
    current_priority: Optional[int] = None
    if isinstance(current_command_priority, OptionalUnsigned):
        if current_command_priority._choice == "unsigned":
            current_priority = int(
                getattr(current_command_priority, current_command_priority._choice)
            )

    return CommandableSnapshot(
        object_identifier=object_identifier,
        effective_value=getattr(obj, "presentValue", None),
        current_command_priority=current_priority,
        relinquish_default=getattr(obj, "relinquishDefault", None),
        slots=tuple(slots),
    )


def format_priority_report(
    obj_or_snapshot: Union[_Any, CommandableSnapshot],
    policy: Optional[WriteAccessPolicy] = None,
) -> str:
    """Format a commandable object's effective value and all 16 slots."""
    if isinstance(obj_or_snapshot, CommandableSnapshot):
        snapshot = obj_or_snapshot
    else:
        snapshot = snapshot_commandable(obj_or_snapshot, policy=policy)
    return snapshot.format()


def format_audit(policy: WriteAccessPolicy) -> str:
    """Format every policy decision, including denied slot changes."""
    return "\n".join(str(decision) for decision in policy.audit)


@dataclasses.dataclass(frozen=True)
class SlotChange:
    """A single priority slot that differs between two snapshots."""

    priority: int
    before: Optional[PrioritySlot]
    after: Optional[PrioritySlot]

    def __str__(self) -> str:
        def side(slot: Optional[PrioritySlot]) -> str:
            if slot is None:
                return "<absent>"
            if slot.is_null:
                text = "<null>"
            else:
                text = _display(slot.value)
            if slot.owner is not None:
                text += f" (owner: {slot.owner})"
            return text

        return f"priority {self.priority:2d}: {side(self.before)} -> {side(self.after)}"


@dataclasses.dataclass(frozen=True)
class SnapshotDiff:
    """Difference between two commandable snapshots, including hidden slots."""

    before: CommandableSnapshot
    after: CommandableSnapshot
    effective_value_changed: bool
    current_command_priority_changed: bool
    relinquish_default_changed: bool
    slot_changes: Tuple[SlotChange, ...]

    @property
    def changed(self) -> bool:
        return (
            self.effective_value_changed
            or self.current_command_priority_changed
            or self.relinquish_default_changed
            or bool(self.slot_changes)
        )

    def format(self) -> str:
        lines = []
        if self.effective_value_changed:
            lines.append(
                "present-value: "
                f"{_display(self.before.effective_value)} -> "
                f"{_display(self.after.effective_value)}"
            )
        else:
            lines.append(
                f"present-value: unchanged ({_display(self.after.effective_value)})"
            )
        if self.current_command_priority_changed:
            lines.append(
                "current-command-priority: "
                f"{self.before.current_command_priority} -> "
                f"{self.after.current_command_priority}"
            )
        if self.relinquish_default_changed:
            lines.append(
                "relinquish-default: "
                f"{_display(self.before.relinquish_default)} -> "
                f"{_display(self.after.relinquish_default)}"
            )
        for change in self.slot_changes:
            lines.append(str(change))
        if not self.slot_changes:
            lines.append("priority slots: no change")
        return "\n".join(lines)


def diff_snapshots(
    before: CommandableSnapshot, after: CommandableSnapshot
) -> SnapshotDiff:
    """
    Compare two snapshots by value and by slot.

    Equal present-values do not make the snapshots equal: a write that changes
    a priority slot while leaving the effective value the same is reported as
    a slot change.
    """
    slot_changes: List[SlotChange] = []
    for before_slot, after_slot in zip(before.slots, after.slots):
        if (before_slot.value != after_slot.value) or (
            before_slot.is_null != after_slot.is_null
        ):
            slot_changes.append(
                SlotChange(
                    priority=before_slot.priority,
                    before=before_slot,
                    after=after_slot,
                )
            )

    return SnapshotDiff(
        before=before,
        after=after,
        effective_value_changed=before.effective_value != after.effective_value,
        current_command_priority_changed=(
            before.current_command_priority != after.current_command_priority
        ),
        relinquish_default_changed=(
            before.relinquish_default != after.relinquish_default
        ),
        slot_changes=tuple(slot_changes),
    )
