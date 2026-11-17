"""Abstract domain used by the bounded constant-propagation interpreter.

The lattice is deliberately small and finite so that branch/loop processing is
guaranteed to reach a fixed point:

* :data:`TOP`            - unknown / not determinable, the top element
* :class:`IntValue`      - constant (bounded-size) integer
* :class:`CharValue`     - constant UTF-16 code unit
* :class:`StringValue`   - constant string literal
* :class:`ArrayValue`    - finite array whose *length* is constant and whose
                           slots are independently tracked abstract values

Joining two different constants yields :data:`TOP`; joining two arrays aligns
their slots and keeps only slots that agree. Missing characters are therefore
preserved as top slots instead of being silently filled with zero.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence


class Confidence(enum.Enum):
    """How strongly a recovered value is known."""

    CERTAIN = "certain"
    PENDING = "pending"


@dataclass(frozen=True)
class Value:
    """Base class for abstract values.

    ``evidence`` holds the offsets of the instructions that produced or
    propagated the value, so every recovered expression can be traced back to
    concrete IL bytes.
    """

    evidence: frozenset[int] = field(default_factory=frozenset)

    @property
    def confidence(self) -> Confidence:
        raise NotImplementedError

    def with_evidence(self, offsets: Sequence[int]) -> "Value":
        raise NotImplementedError

    @staticmethod
    def _extend(evidence: frozenset[int], offsets: Sequence[int]) -> frozenset[int]:
        return frozenset(set(evidence) | set(offsets))


@dataclass(frozen=True)
class _Top(Value):
    """The single top element: the value is not statically determinable.

    ``alternatives`` optionally carries the concrete constants that met at a
    conflicting join. ``fragments`` carries array text proven in isolation even
    though the whole value is unknown. Neither is presented as a runtime-certain
    value; propagation still treats this element as top.
    """

    alternatives: tuple = ()
    fragments: tuple = ()
    gap_count: int = 0

    @property
    def confidence(self) -> Confidence:
        return Confidence.PENDING

    def with_evidence(self, offsets: Sequence[int]) -> "Value":
        return _Top(self._extend(self.evidence, offsets), self.alternatives, self.fragments, self.gap_count)

    def __str__(self) -> str:
        return "<unknown>"


TOP: Value = _Top()


def top_with_fragments(
    evidence: frozenset[int], fragments: Sequence[str], gap_count: int = 0
) -> Value:
    """Build a pending value that still names its proven text fragments."""
    deduped = tuple(dict.fromkeys(fragments))
    return _Top(evidence, (), deduped, gap_count)


@dataclass(frozen=True)
class IntValue(Value):
    """A constant integer (``i4``/``i8`` family)."""

    value: int = 0

    @property
    def confidence(self) -> Confidence:
        return Confidence.CERTAIN

    def with_evidence(self, offsets: Sequence[int]) -> "IntValue":
        return IntValue(self._extend(self.evidence, offsets), self.value)

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class CharValue(Value):
    """A constant UTF-16 code unit (``char``, unsigned 16-bit)."""

    code: int = 0

    @property
    def confidence(self) -> Confidence:
        return Confidence.CERTAIN

    def with_evidence(self, offsets: Sequence[int]) -> "CharValue":
        return CharValue(self._extend(self.evidence, offsets), self.code)

    def __str__(self) -> str:
        return repr(chr(self.code))


@dataclass(frozen=True)
class StringValue(Value):
    """A constant string literal originating from ``ldstr`` or a pure helper."""

    text: str = ""

    @property
    def confidence(self) -> Confidence:
        return Confidence.CERTAIN

    def with_evidence(self, offsets: Sequence[int]) -> "StringValue":
        return StringValue(self._extend(self.evidence, offsets), self.text)

    def __str__(self) -> str:
        return repr(self.text)


@dataclass(frozen=True)
class ArrayValue(Value):
    """A finite array.

    ``length`` is always a concrete integer. ``slots`` maps an index to an
    abstract value; an absent index means that slot has never been written and
    reads from it must stay unknown (never defaulted to zero/null).
    """

    length: int = 0
    slots: Dict[int, Value] = field(default_factory=dict)

    @property
    def confidence(self) -> Confidence:
        if all(slot.confidence is Confidence.CERTAIN for slot in self.slots.values()):
            return Confidence.CERTAIN
        return Confidence.PENDING

    def with_evidence(self, offsets: Sequence[int]) -> "ArrayValue":
        extra = frozenset(offsets)
        new_slots = {idx: slot.with_evidence(extra) for idx, slot in self.slots.items()}
        return ArrayValue(self._extend(self.evidence, offsets), self.length, new_slots)

    def read(self, index: int) -> Value:
        """Read one slot; an unwritten or out-of-range slot is unknown."""
        if not 0 <= index < self.length or index not in self.slots:
            return TOP
        return self.slots[index]

    def write(self, index: int, value: Value) -> Optional["ArrayValue"]:
        """Return an updated array, or ``None`` if the index is out of range."""
        if not 0 <= index < self.length:
            return None
        new_slots = dict(self.slots)
        new_slots[index] = value
        return ArrayValue(self.evidence, self.length, new_slots)


def _alternatives_of(value: Value) -> tuple:
    if isinstance(value, _Top):
        return value.alternatives
    if isinstance(value, (IntValue, CharValue, StringValue)):
        return (value,)
    return ()


def merge_values(left: Value, right: Value) -> Value:
    """Conservative lattice join.

    Conflicting constants go to :data:`TOP`; arrays join slot-by-slot and only
    retain slots that agree. Nothing is fabricated to fill a gap.
    """
    if left is TOP or isinstance(left, _Top):
        merged_alts = tuple(dict.fromkeys((*left.alternatives, *_alternatives_of(right))))
        return _Top(frozenset(set(left.evidence) | set(right.evidence)), merged_alts)
    if right is TOP or isinstance(right, _Top):
        merged_alts = tuple(dict.fromkeys((*_alternatives_of(left), *right.alternatives)))
        return _Top(frozenset(set(left.evidence) | set(right.evidence)), merged_alts)
    if isinstance(left, ArrayValue) and isinstance(right, ArrayValue):
        if left.length != right.length:
            return _Top(frozenset(set(left.evidence) | set(right.evidence)), ())
        merged: Dict[int, Value] = {}
        for index in range(left.length):
            if index in left.slots and index in right.slots:
                joined = merge_values(left.slots[index], right.slots[index])
                if not isinstance(joined, _Top):
                    merged[index] = joined
        return ArrayValue(frozenset(set(left.evidence) | set(right.evidence)), left.length, merged)
    if type(left) is not type(right):
        return _Top(frozenset(set(left.evidence) | set(right.evidence)), ())
    if isinstance(left, IntValue):
        same = left.value == right.value  # type: ignore[attr-defined]
    elif isinstance(left, CharValue):
        same = left.code == right.code  # type: ignore[attr-defined]
    elif isinstance(left, StringValue):
        same = left.text == right.text  # type: ignore[attr-defined]
    else:
        same = False
    if same:
        return left.with_evidence(sorted(right.evidence))
    return _Top(
        frozenset(set(left.evidence) | set(right.evidence)),
        tuple(dict.fromkeys((*_alternatives_of(left), *_alternatives_of(right)))),
    )
