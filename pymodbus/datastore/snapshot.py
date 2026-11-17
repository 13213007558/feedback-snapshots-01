"""Consistent (snapshot) reads of multi-register values from the in-memory datastore.

A safety threshold that physically occupies two 16-bit holding registers is a
single 32-bit quantity at the business level. The backend updates those two
half-words independently. If a reader fetches the two registers in separate
steps it can observe the *new* high half-word together with the *old* low
half-word (or vice versa) and assemble a 32-bit value that never existed in the
store. Such a "torn" read can mislead a safety decision.

This module provides three clearly separated layers:

1. **Snapshot consistency** (:class:`RegisterSnapshot`, :class:`SnapshotStore`):
   one range, one explicit point-in-time copy taken under a lock. Every register
   in the returned snapshot belongs to the same generation; a concurrent writer
   can never be caught half way through a multi-register update.
2. **Encoding interpretability** (:func:`decode_register_snapshot`,
   :func:`encode_to_registers`): pure, total functions turning a fixed snapshot
   into a python value. Byte order and word order are *always* supplied by the
   caller; nothing is guessed. Decoding never substitutes a value: a ``NaN`` is
   returned as ``NaN`` and an out-of-range integer is reported, not clamped.
3. **Business trustworthiness** (:class:`SafetyThreshold`): range / NaN policy
   applied to a decoded value. An invalid value raises instead of being silently
   replaced by a "normal" number.

The atomicity guarantee is deliberately scoped: a single PDU range read from one
snapshot is consistent. Two separate requests are two separate snapshots and are
*not* promised to be mutually atomic; a writer may commit between them.
"""

from __future__ import annotations

import enum
import math
import struct
import threading
from collections.abc import Callable, Sequence
from typing import Any


class SnapshotError(ValueError):
    """Base class for snapshot/encoding failures.

    Raised for problems that make a value un-interpretable or un-trustworthy.
    The message always explains the offending data; no fallback value is
    substituted.
    """


class SnapshotRangeError(SnapshotError):
    """A requested snapshot range does not fully lie inside the store."""


class SnapshotEncodingError(SnapshotError):
    """The snapshot cannot be interpreted with the requested datatype/layout."""


class SnapshotValueError(SnapshotError):
    """A decoded value is NaN or outside the caller's trusted business range."""


class WordOrder(enum.Enum):
    """Order in which 16-bit words are placed into a multi-register value."""

    #: The first register holds the most significant word (big-endian word order).
    HIGH_WORD_FIRST = "high_first"
    #: The first register holds the least significant word (little-endian word order).
    LOW_WORD_FIRST = "low_first"


#: struct format character -> (register count, signed handling).
_INT_FORMATS: dict[str, tuple[int, bool]] = {
    "h": (1, True),
    "H": (1, False),
    "i": (2, True),
    "I": (2, False),
    "q": (4, True),
    "Q": (4, False),
}
_FLOAT_FORMATS: dict[str, int] = {"f": 2, "d": 4}


def _reorder_words(registers: Sequence[int], word_order: WordOrder) -> list[int]:
    """Return registers in high-word-first order."""
    if word_order is WordOrder.HIGH_WORD_FIRST:
        return list(registers)
    return list(reversed(registers))


def _registers_to_bytes(
    registers: Sequence[int], byte_order: str, word_order: WordOrder
) -> bytes:
    """Pack a register snapshot into raw bytes using explicit orders.

    The two orders are independent: ``word_order`` arranges the 16-bit words
    relative to each other, while ``byte_order`` arranges the two bytes *inside*
    each word. After reordering, words are concatenated high-word-first and each
    word is packed in the requested byte order.
    """
    prefix = ">" if byte_order == "big" else "<"
    ordered = _reorder_words(registers, word_order)
    return b"".join(struct.pack(f"{prefix}H", word) for word in ordered)


def _check_registers(registers: Sequence[int], expected: int) -> None:
    """Validate register contents and length."""
    if len(registers) != expected:
        raise SnapshotEncodingError(
            f"expected {expected} register(s) for the datatype, "
            f"got {len(registers)}"
        )
    for word in registers:
        if not isinstance(word, int) or not 0 <= word <= 0xFFFF:
            raise SnapshotEncodingError(
                f"register word {word!r} is not an unsigned 16-bit integer"
            )


def decode_register_snapshot(
    registers: Sequence[int],
    datatype: str,
    *,
    byte_order: str = "big",
    word_order: WordOrder = WordOrder.HIGH_WORD_FIRST,
) -> int | float:
    """Interpret a register snapshot as a single value.

    The function is total with respect to the bits: any legal bit pattern is
    decoded to the exact python value it represents, including IEEE ``NaN`` and
    infinity. It never clamps, rounds away, or replaces a value.

    :param registers: register words taken from one :class:`RegisterSnapshot`.
    :param datatype: one of ``h H i I q Q f d`` (struct format characters).
    :param byte_order: ``"big"`` or ``"little"`` byte order inside each word.
    :param word_order: :class:`WordOrder` selecting the word sequence.
    :returns: the decoded integer or float.
    :raises SnapshotEncodingError: wrong length, illegal word, unknown datatype.
    """
    if byte_order not in ("big", "little"):
        raise SnapshotEncodingError(
            f"byte_order must be 'big' or 'little', got {byte_order!r}"
        )
    if datatype in _INT_FORMATS:
        reg_count = _INT_FORMATS[datatype][0]
        _check_registers(registers, reg_count)
        raw = _registers_to_bytes(registers, byte_order, word_order)
        return struct.unpack(f">{datatype}", raw)[0]
    if datatype in _FLOAT_FORMATS:
        reg_count = _FLOAT_FORMATS[datatype]
        _check_registers(registers, reg_count)
        raw = _registers_to_bytes(registers, byte_order, word_order)
        return struct.unpack(f">{datatype}", raw)[0]
    raise SnapshotEncodingError(f"unsupported datatype {datatype!r}")


def encode_to_registers(
    value: int | float,
    datatype: str,
    *,
    byte_order: str = "big",
    word_order: WordOrder = WordOrder.HIGH_WORD_FIRST,
) -> list[int]:
    """Encode a value into register words using the same explicit orders.

    This is the inverse of :func:`decode_register_snapshot` for finite values.
    An integer that does not fit the chosen width raises instead of being
    truncated, and a non-finite float (``NaN``/infinity) is only accepted for
    float datatypes where it has a defined representation.
    """
    if byte_order not in ("big", "little"):
        raise SnapshotEncodingError(
            f"byte_order must be 'big' or 'little', got {byte_order!r}"
        )
    if datatype in _INT_FORMATS:
        reg_count, signed = _INT_FORMATS[datatype]
        if not isinstance(value, int) or isinstance(value, bool):
            raise SnapshotEncodingError(
                f"{datatype!r} requires an integer, got {value!r}"
            )
        lower = -(2 ** (reg_count * 16 - 1)) if signed else 0
        upper = 2 ** (reg_count * 16 - 1) - 1 if signed else 2 ** (reg_count * 16) - 1
        if not lower <= value <= upper:
            raise SnapshotEncodingError(
                f"value {value} does not fit unsigned/signed {reg_count * 16}-bit "
                f"range [{lower}, {upper}]"
            )
        raw = int.to_bytes(
            value & (2 ** (reg_count * 16) - 1), reg_count * 2, "big"
        )
    elif datatype in _FLOAT_FORMATS:
        reg_count = _FLOAT_FORMATS[datatype]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise SnapshotEncodingError(
                f"{datatype!r} requires a number, got {value!r}"
            )
        raw = struct.pack(">f" if reg_count == 2 else ">d", float(value))
    else:
        raise SnapshotEncodingError(f"unsupported datatype {datatype!r}")
    # ``raw`` is the big-endian value; split into words, lay the words out in
    # the requested word order, and pack each word in the requested byte order.
    big_words = [
        int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)
    ]
    if word_order is WordOrder.LOW_WORD_FIRST:
        big_words.reverse()
    if byte_order == "little":
        big_words = [
            int.from_bytes(word.to_bytes(2, "big")[::-1], "big")
            for word in big_words
        ]
    return big_words


class RegisterSnapshot:
    """An immutable, point-in-time copy of one contiguous register range.

    Instances are produced only by :meth:`SnapshotStore.snapshot`; do not build
    them directly. ``registers`` is a fresh list, so later writes to the store
    cannot mutate a snapshot that is already being decoded.
    """

    __slots__ = ("address", "registers", "generation")

    def __init__(self, address: int, registers: list[int], generation: int) -> None:
        """Hold the copied words and their provenance."""
        self.address = address
        self.registers = registers
        #: Monotonic counter identifying the store generation of this copy.
        self.generation = generation

    def __len__(self) -> int:
        """Return the number of registers in the snapshot."""
        return len(self.registers)

    def decode(
        self,
        datatype: str,
        *,
        byte_order: str = "big",
        word_order: WordOrder = WordOrder.HIGH_WORD_FIRST,
        offset: int = 0,
    ) -> int | float:
        """Decode a value beginning at word ``offset`` within the snapshot."""
        width = _datatype_register_count(datatype)
        view = self.registers[offset : offset + width]
        return decode_register_snapshot(
            view, datatype, byte_order=byte_order, word_order=word_order
        )


def _datatype_register_count(datatype: str) -> int:
    """Return the register width for a supported datatype."""
    if datatype in _INT_FORMATS:
        return _INT_FORMATS[datatype][0]
    if datatype in _FLOAT_FORMATS:
        return _FLOAT_FORMATS[datatype]
    raise SnapshotEncodingError(f"unsupported datatype {datatype!r}")


class SnapshotStore:
    """Wrap a pymodbus in-memory register block with consistent access.

    The wrapped object is the live ``registers`` list held by a runtime block
    (``SimRuntime.block[block_id][2]``) or any mutable sequence of unsigned
    16-bit words. A re-entrant lock guards both the snapshot copy and the atomic
    multi-register update, so a reader can never observe a writer half way
    through a two-half-word threshold update.
    """

    def __init__(
        self,
        registers: list[int],
        *,
        start_address: int = 0,
        lock: threading.RLock | None = None,
    ) -> None:
        """Bind the store to a live register list.

        :param registers: the live list of 16-bit words to read/update.
        :param start_address: the Modbus address of ``registers[0]``.
        :param lock: optional shared lock; a new :class:`threading.RLock` if None.
        """
        if not isinstance(registers, list):
            raise TypeError("registers must be a mutable list so updates stay live")
        self._registers = registers
        self._start_address = start_address
        self._lock = lock if lock is not None else threading.RLock()
        self._generation = 0

    @property
    def generation(self) -> int:
        """Return the current store generation (incremented per committed write)."""
        return self._generation

    def snapshot(self, address: int, count: int) -> RegisterSnapshot:
        """Copy ``count`` registers starting at ``address`` atomically.

        :raises SnapshotRangeError: the range is not fully inside the block.
        """
        if count <= 0:
            raise SnapshotRangeError(f"count must be positive, got {count}")
        offset = address - self._start_address
        with self._lock:
            if offset < 0 or offset + count > len(self._registers):
                raise SnapshotRangeError(
                    f"range address={address} count={count} lies outside the "
                    f"block starting at {self._start_address} "
                    f"with {len(self._registers)} registers"
                )
            copied = list(self._registers[offset : offset + count])
            return RegisterSnapshot(address, copied, self._generation)

    def atomic_write(
        self,
        address: int,
        values: Sequence[int],
        *,
        on_update: Callable[[list[int], int, int], None] | None = None,
    ) -> None:
        """Replace a contiguous range in a single critical section.

        All half-words of a multi-register threshold become visible together.
        ``on_update(registers, offset, length)`` runs while the lock is held,
        allowing side effects that must observe the same generation.
        """
        offset = address - self._start_address
        length = len(values)
        with self._lock:
            if offset < 0 or offset + length > len(self._registers):
                raise SnapshotRangeError(
                    f"write address={address} length={length} lies outside the "
                    f"block starting at {self._start_address}"
                )
            for word in values:
                if not isinstance(word, int) or not 0 <= word <= 0xFFFF:
                    raise SnapshotEncodingError(
                        f"write word {word!r} is not an unsigned 16-bit integer"
                    )
            self._registers[offset : offset + length] = list(values)
            self._generation += 1
            if on_update is not None:
                on_update(self._registers, offset, length)

    def atomic_write_value(
        self,
        address: int,
        value: int | float,
        datatype: str,
        *,
        byte_order: str = "big",
        word_order: WordOrder = WordOrder.HIGH_WORD_FIRST,
    ) -> None:
        """Encode ``value`` and commit all of its words atomically."""
        words = encode_to_registers(
            value, datatype, byte_order=byte_order, word_order=word_order
        )
        self.atomic_write(address, words)


class SafetyThreshold:
    """Decode and validate a safety threshold read from a snapshot.

    The three concerns stay separate: the snapshot already guarantees the words
    are one generation; this class only fixes the encoding and the business
    trust policy. A value that fails the policy raises :class:`SnapshotValueError`
    rather than being silently replaced by a default.
    """

    def __init__(
        self,
        datatype: str,
        *,
        minimum: float | None = None,
        maximum: float | None = None,
        allow_nan: bool = False,
        byte_order: str = "big",
        word_order: WordOrder = WordOrder.HIGH_WORD_FIRST,
    ) -> None:
        """Fix the interpretation and the trusted value window.

        :param datatype: struct format character, e.g. ``"I"`` for uint32.
        :param minimum: inclusive lower bound; None disables the lower check.
        :param maximum: inclusive upper bound; None disables the upper check.
        :param allow_nan: if False a float NaN is rejected.
        :param byte_order: fixed byte order for every decode.
        :param word_order: fixed word order for every decode.
        """
        self.datatype = datatype
        self.minimum = minimum
        self.maximum = maximum
        self.allow_nan = allow_nan
        self.byte_order = byte_order
        self.word_order = word_order

    def read(self, snapshot: RegisterSnapshot, offset: int = 0) -> int | float:
        """Decode the threshold from a snapshot and enforce the trust policy.

        :raises SnapshotValueError: NaN when disallowed, or value out of range.
        """
        value = snapshot.decode(
            self.datatype,
            byte_order=self.byte_order,
            word_order=self.word_order,
            offset=offset,
        )
        if isinstance(value, float) and math.isnan(value):
            if not self.allow_nan:
                raise SnapshotValueError(
                    "decoded threshold is NaN; refusing to substitute a value"
                )
            return value
        if self.minimum is not None and value < self.minimum:
            raise SnapshotValueError(
                f"decoded threshold {value} is below trusted minimum {self.minimum}"
            )
        if self.maximum is not None and value > self.maximum:
            raise SnapshotValueError(
                f"decoded threshold {value} is above trusted maximum {self.maximum}"
            )
        return value


def snapshot_from_runtime(runtime: Any, block_id: str) -> SnapshotStore:
    """Build a :class:`SnapshotStore` bound to a ``SimRuntime`` block.

    Delegates to :meth:`SimRuntime.get_snapshot_store`, so the returned store
    shares the runtime lock. The same live register list the Modbus server reads
    and writes is wrapped, meaning external Modbus writes and snapshot reads are
    mutually exclusive on the critical section.

    :param runtime: a :class:`pymodbus.simulator.simruntime.SimRuntime`.
    :param block_id: one of ``"x"`` (shared) or ``"c" "d" "h" "i"``.
    """
    return runtime.get_snapshot_store(block_id)
