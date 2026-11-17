"""
Snapshot loading for the offline Schedule audit.

A snapshot is a JSON document describing the objects read from a BACnet
device (schedule, calendar, and the commandable target points) plus the
caller-supplied evaluation instant.  Hydration uses the real BACpypes3
object/type classes from :mod:`bacpypes3.object` and :mod:`bacpypes3.basetypes`
so the analyzer reasons over the same structure the stack itself uses.

The stock :func:`bacpypes3.json.json_to_sequence` cannot decode ``Any``
typed slots (``presentValue``, ``scheduleDefault``, ``TimeValue.value``) from
plain JSON literals, so this module provides a small recursive decoder that
treats those slots as BACnet atomic values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

from bacpypes3.basetypes import PriorityValue
from bacpypes3.constructeddata import (
    AnyAtomic,
    Array,
    Choice,
    ExtendedList,
    Sequence,
)
from bacpypes3.json.util import atomic_decode
from bacpypes3.object import CalendarObject, ScheduleObject
from bacpypes3.primitivedata import Atomic, Null, ObjectIdentifier

if TYPE_CHECKING:
    from bacpypes3.primitivedata import Enumerated

from .model import AuditInput


class SnapshotError(ValueError):
    """Raised when a snapshot document cannot be hydrated or is incomplete."""


# Object classes the audit understands, keyed by the BACnet object-type
# token used in JSON object identifiers ("schedule,1").
_OBJECT_CLASSES = {
    "schedule": ScheduleObject,
    "calendar": CalendarObject,
}


def _is_collection(element: Any) -> bool:
    return isinstance(element, type) and issubclass(element, (Array, ExtendedList))


def _decode_value(literal: Any, element: Any) -> Any:
    """Decode one JSON literal into the BACpypes3 ``element`` type."""
    if literal is None:
        return None

    # Any-typed atomic slots: presentValue, scheduleDefault, TimeValue.value.
    if isinstance(element, type) and issubclass(element, AnyAtomic):
        return _decode_any_atomic(literal)

    if isinstance(element, type) and issubclass(element, Atomic):
        return atomic_decode(literal, element)

    if isinstance(element, type) and issubclass(element, Choice):
        return _decode_choice(literal, element)

    if isinstance(element, type) and issubclass(element, Sequence):
        return _decode_sequence(literal, element)

    if _is_collection(element):
        return _decode_collection(literal, element)

    raise SnapshotError(f"unsupported element type: {element!r}")


def _decode_any_atomic(literal: Any) -> Atomic:
    """
    Decode a plain JSON literal into a BACnet atomic value for an ``Any``
    typed slot.  A single-key object may tag the type explicitly, which is
    required for enumerated values (the bare ``Enumerated`` class has no
    named members)::

        {"enumerated": "active"}      # via a value the enum class accepts
        {"real": 21.5}
        {"boolean": true}
        {"null": null}
    """
    if isinstance(literal, dict) and len(literal) == 1:
        tag, value = next(iter(literal.items()))
        tagged = _TAGGED_ATOMIC.get(tag)
        if tagged is None:
            raise SnapshotError(f"unknown atomic tag {tag!r}")
        if isinstance(tagged, str):
            module_name, class_name = tagged.rsplit(".", 1)
            import importlib

            tagged = getattr(importlib.import_module(module_name), class_name)
        return atomic_decode(value, tagged)

    if literal is None:
        return Null(())
    if isinstance(literal, bool):
        from bacpypes3.primitivedata import Boolean

        return Boolean(literal)
    if isinstance(literal, int):
        from bacpypes3.primitivedata import Integer

        # Whole-number schedule values are BACnet Integer by default; an
        # unsigned value can be expressed with the {"unsigned": n} tag.
        return Integer(literal)
    if isinstance(literal, float):
        from bacpypes3.primitivedata import Real

        return Real(literal)
    if isinstance(literal, str):
        # Dates, times and object identifiers are declared as such in the
        # schema and decoded via their own elements, so a bare string in an
        # Any slot is a CharacterString.
        from bacpypes3.primitivedata import CharacterString

        return CharacterString(literal)
    raise SnapshotError(f"cannot decode atomic literal: {literal!r}")


_TAGGED_ATOMIC = {
    "null": Null,
    "boolean": "bacpypes3.primitivedata.Boolean",
    "unsigned": "bacpypes3.primitivedata.Unsigned",
    "integer": "bacpypes3.primitivedata.Integer",
    "real": "bacpypes3.primitivedata.Real",
    "double": "bacpypes3.primitivedata.Double",
    "character-string": "bacpypes3.primitivedata.CharacterString",
}


def _decode_choice(literal: Any, choice_class: Any) -> Choice:
    """Decode a dict naming exactly one alternative of a Choice."""
    if not isinstance(literal, dict) or len(literal) != 1:
        raise SnapshotError(
            f"{choice_class.__name__} expects a single-key choice object, "
            f"got {literal!r}"
        )

    json_key, value = next(iter(literal.items()))
    alternative = _json_key_to_attr(json_key)
    if alternative not in choice_class._elements:
        raise SnapshotError(f"{choice_class.__name__} has no alternative {json_key!r}")

    element = choice_class._elements[alternative]
    decoded = _decode_value(value, element)
    return choice_class(**{alternative: decoded})


def _decode_sequence(literal: Any, seq_class: Any) -> Sequence:
    if not isinstance(literal, dict):
        raise SnapshotError(f"{seq_class.__name__} expects an object")

    seq = seq_class()
    for attr, element in seq_class._elements.items():
        json_key = _attr_to_json_key(attr)
        if json_key not in literal:
            continue
        decoded = _decode_value(literal[json_key], element)
        if decoded is not None:
            setattr(seq, attr, decoded)
    return seq


def _decode_collection(literal: Any, collection_class: Any) -> Any:
    if not isinstance(literal, list):
        raise SnapshotError(f"{collection_class.__name__} expects a list")
    subtype = collection_class._subtype
    return collection_class([_decode_value(item, subtype) for item in literal])


def _attr_to_json_key(attr: str) -> str:
    """Mirror BACpypes3's camelCase -> kebab-case JSON property names."""
    chars: List[str] = []
    for char in attr:
        if char.isupper():
            chars.append("-")
            chars.append(char.lower())
        else:
            chars.append(char)
    return "".join(chars)


def _json_key_to_attr(key: str) -> str:
    """Inverse of :func:`_attr_to_json_key` for choice alternative names."""
    parts = key.split("-")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


def _decode_priority_value(literal: Any) -> PriorityValue:
    """
    Decode one priorityArray slot.  ``null`` (or JSON null) means the slot is
    relinquished; otherwise the literal is decoded against the slot's atomic
    alternatives.  Enumerated names are ambiguous on the bare
    ``Enumerated`` type, so they are resolved through the standard BACnet
    enumerated subclasses (e.g. BinaryPV).
    """
    if literal is None or literal == "null":
        return PriorityValue(null=Null(()))
    if isinstance(literal, dict) and len(literal) == 1:
        alternative, value = next(iter(literal.items()))
        if alternative not in PriorityValue._elements:
            raise SnapshotError(f"PriorityValue has no alternative {alternative!r}")
        element = PriorityValue._elements[alternative]
        if alternative == "enumerated" and isinstance(value, str):
            decoded = _decode_enumerated_name(value)
        else:
            decoded = atomic_decode(value, element)
        return PriorityValue(**{alternative: decoded})
    raise SnapshotError(
        f"priorityArray slot must be null or a single-key object, got {literal!r}"
    )


def _all_enumeration_subclasses() -> list:
    from bacpypes3.primitivedata import Enumerated

    collected: list = []

    def walk(element: type) -> None:
        for subclass in element.__subclasses__():
            collected.append(subclass)
            walk(subclass)

    walk(Enumerated)
    return collected


def _decode_enumerated_name(name: str) -> "Enumerated":
    # The bare Enumerated type has no named members; resolve through the
    # standard BACnet enumerated subclasses (BinaryPV, ...).
    for enum_class in _all_enumeration_subclasses():
        if name in enum_class._enum_map:
            return enum_class(name)
    raise SnapshotError(f"cannot resolve enumerated value {name!r}")


def _hydrate_object(obj_json: Dict[str, Any]) -> Any:
    object_identifier = obj_json.get("object-identifier")
    if not object_identifier or not isinstance(object_identifier, str):
        raise SnapshotError("object missing string 'object-identifier'")
    object_type = object_identifier.split(",", 1)[0]
    object_class = _OBJECT_CLASSES.get(object_type)
    if object_class is None:
        raise SnapshotError(f"unsupported object type for audit: {object_type!r}")
    return _decode_sequence(obj_json, object_class)


def _hydrate_point(point_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Hydrate the observed state of a commandable target point.  Only the
    properties needed to decide whether the Schedule is actually in command
    are required; missing referenced points keep the verdict pending.
    """
    identifier = point_json.get("object-identifier")
    if not identifier:
        raise SnapshotError("point missing 'object-identifier'")
    object_identifier = ObjectIdentifier(identifier)

    point: Dict[str, Any] = {
        "objectIdentifier": object_identifier,
        "objectName": point_json.get("object-name"),
        "outOfService": bool(point_json.get("out-of-service", False)),
        "relinquishDefault": point_json.get("relinquish-default"),
        "observedPresentValue": point_json.get("present-value"),
        "currentCommandPriority": point_json.get("current-command-priority"),
        "priorityArray": None,
    }

    raw_array = point_json.get("priority-array")
    if raw_array is not None:
        if not isinstance(raw_array, list) or len(raw_array) != 16:
            raise SnapshotError(
                f"priority-array for {identifier} must have exactly 16 slots"
            )
        point["priorityArray"] = [_decode_priority_value(slot) for slot in raw_array]

    return point


def load_snapshot(document: Dict[str, Any]) -> AuditInput:
    """
    Validate and hydrate a snapshot document into an :class:`AuditInput`.

    The document shape is::

        {
          "evaluation-instant": "2026-12-25T10:30:00+08:00",
          "objects": [ <schedule/calendar JSON objects> ],
          "points":  [ <observed commandable point state> ]
        }
    """
    if not isinstance(document, dict):
        raise SnapshotError("snapshot root must be an object")

    instant_text = document.get("evaluation-instant")
    if not instant_text:
        raise SnapshotError(
            "snapshot must provide 'evaluation-instant' "
            "(timezone-aware ISO 8601, caller-supplied device-local time)"
        )

    objects = document.get("objects")
    if not isinstance(objects, list) or not objects:
        raise SnapshotError("snapshot must contain a non-empty 'objects' list")

    hydrated_objects = [_hydrate_object(item) for item in objects]
    points = [_hydrate_point(item) for item in document.get("points", [])]

    return AuditInput(
        instant_text=instant_text,
        objects=hydrated_objects,
        points=points,
        raw=document,
    )


def load_snapshot_file(path: str) -> AuditInput:
    """Load a snapshot document from a JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_snapshot(data)
