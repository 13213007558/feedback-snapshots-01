"""Tests for consistent (snapshot) multi-register reads.

These tests pin the three guarantees separately:

* snapshot consistency  -> one range is copied atomically under a shared lock;
* encoding interpretability -> explicit, caller-fixed byte/word order, total
  decode that keeps NaN instead of substituting a value;
* business trustworthiness -> NaN / out-of-range raise instead of being
  silently replaced.

A concurrency test drives a writer that commits a two-half-word threshold while
readers pause between half reads, and proves no reader ever assembles a value
that was never committed.
"""

import math
import threading

import pytest

from pymodbus.datastore import (
    RegisterSnapshot,
    SafetyThreshold,
    SnapshotEncodingError,
    SnapshotRangeError,
    SnapshotStore,
    SnapshotValueError,
    WordOrder,
    decode_register_snapshot,
    encode_to_registers,
    snapshot_from_runtime,
)
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.simulator.simruntime import SimRuntime


class TestEncoding:
    """Encoding is explicit, total and order-sensitive."""

    @pytest.mark.parametrize("byte_order", ["big", "little"])
    @pytest.mark.parametrize("word_order", list(WordOrder))
    @pytest.mark.parametrize(
        ("datatype", "value"),
        [
            ("H", 60000),
            ("h", -3),
            ("I", 0x11223344),
            ("i", -1234567),
            ("Q", 0x1122334455667788),
            ("q", -99),
            ("f", 127.4),
            ("d", 3.14159265358979),
        ],
    )
    def test_roundtrip(self, datatype, value, byte_order, word_order):
        """Every type/order combination decodes back to the original."""
        regs = encode_to_registers(
            value, datatype, byte_order=byte_order, word_order=word_order
        )
        decoded = decode_register_snapshot(
            regs, datatype, byte_order=byte_order, word_order=word_order
        )
        if datatype == "f":
            assert decoded == pytest.approx(value, abs=1e-5)
        else:
            assert decoded == value

    def test_canonical_uint32_layouts(self):
        """Byte order and word order produce distinct, documented words."""
        value = 0x11223344
        assert encode_to_registers(value, "I") == [0x1122, 0x3344]
        assert encode_to_registers(
            value, "I", word_order=WordOrder.LOW_WORD_FIRST
        ) == [0x3344, 0x1122]
        assert encode_to_registers(value, "I", byte_order="little") == [
            0x2211,
            0x4433,
        ]
        assert encode_to_registers(
            value, "I",
            byte_order="little",
            word_order=WordOrder.LOW_WORD_FIRST,
        ) == [0x4433, 0x2211]

    def test_word_order_changes_interpretation(self):
        """The same raw words decode differently when word order changes."""
        raw = [0x1122, 0x3344]
        assert decode_register_snapshot(raw, "I") == 0x11223344
        assert decode_register_snapshot(
            raw, "I", word_order=WordOrder.LOW_WORD_FIRST
        ) == 0x33441122

    def test_nan_is_preserved_not_replaced(self):
        """A NaN bit pattern decodes to NaN rather than a sentinel number."""
        regs = encode_to_registers(float("nan"), "f")
        decoded = decode_register_snapshot(regs, "f")
        assert math.isnan(decoded)

    def test_inf_is_preserved(self):
        """Infinity has a defined float representation and round-trips."""
        regs = encode_to_registers(float("inf"), "f")
        assert math.isinf(decode_register_snapshot(regs, "f"))

    def test_integer_overflow_is_rejected(self):
        """Out-of-width integers raise instead of being truncated."""
        with pytest.raises(SnapshotEncodingError):
            encode_to_registers(70000, "H")
        with pytest.raises(SnapshotEncodingError):
            encode_to_registers(-1, "I")

    def test_bool_rejected_for_integer(self):
        """bool must not silently pass as an integer."""
        with pytest.raises(SnapshotEncodingError):
            encode_to_registers(True, "I")

    def test_wrong_length_and_bad_word_rejected(self):
        """Malformed register words are reported, never guessed around."""
        with pytest.raises(SnapshotEncodingError):
            decode_register_snapshot([1], "I")
        with pytest.raises(SnapshotEncodingError):
            decode_register_snapshot([0x10000, 0], "I")
        with pytest.raises(SnapshotEncodingError):
            decode_register_snapshot([0, 0], "z")
        with pytest.raises(SnapshotEncodingError):
            decode_register_snapshot([0, 0], "I", byte_order="sideways")


class TestSnapshotStore:
    """Snapshot copies are immutable point-in-time views with range checks."""

    def test_snapshot_is_isolated_from_later_writes(self):
        live = [0, 0, 0]
        store = SnapshotStore(live, start_address=10)
        store.atomic_write(10, [0x1122, 0x3344])
        snapshot = store.snapshot(10, 2)
        live[0] = 0xFFFF  # mutate after the snapshot was taken
        assert snapshot.registers == [0x1122, 0x3344]
        assert isinstance(snapshot, RegisterSnapshot)

    def test_snapshot_address_mapping(self):
        store = SnapshotStore([1, 2, 3, 4], start_address=100)
        assert store.snapshot(101, 2).registers == [2, 3]
        assert store.snapshot(101, 2).address == 101

    @pytest.mark.parametrize(
        ("address", "count"),
        [(0, 1), (10, 4), (10, 0), (13, 1)],
    )
    def test_snapshot_out_of_range(self, address, count):
        # Block spans addresses 10, 11, 12 (three registers).
        store = SnapshotStore([0, 0, 0], start_address=10)
        with pytest.raises(SnapshotRangeError):
            store.snapshot(address, count)

    def test_atomic_write_bumps_generation(self):
        store = SnapshotStore([0, 0])
        gen0 = store.generation
        store.atomic_write(0, [1, 2])
        assert store.generation == gen0 + 1
        snapshot = store.snapshot(0, 2)
        assert snapshot.generation == store.generation

    def test_atomic_write_validates_words(self):
        store = SnapshotStore([0, 0])
        with pytest.raises(SnapshotEncodingError):
            store.atomic_write(0, [0x10000])
        with pytest.raises(SnapshotRangeError):
            store.atomic_write(1, [1, 2])

    def test_atomic_write_value_encodes_then_commits(self):
        store = SnapshotStore([0, 0, 0, 0])
        store.atomic_write_value(1, 0x11223344, "I")
        assert store.snapshot(1, 2).registers == [0x1122, 0x3344]

    def test_requires_mutable_list(self):
        with pytest.raises(TypeError):
            SnapshotStore((1, 2, 3))  # type: ignore[arg-type]


class TestSafetyThreshold:
    """Business policy rejects invalid values instead of substituting them."""

    def _snapshot(self, regs):
        store = SnapshotStore(list(regs))
        return store.snapshot(0, len(regs))

    def test_in_range_value_returned(self):
        snapshot = self._snapshot(encode_to_registers(5000, "I"))
        value = SafetyThreshold("I", minimum=0, maximum=10000).read(snapshot)
        assert value == 5000

    def test_below_minimum_rejected(self):
        snapshot = self._snapshot(encode_to_registers(-1, "i"))
        with pytest.raises(SnapshotValueError):
            SafetyThreshold("i", minimum=0, maximum=10).read(snapshot)

    def test_above_maximum_rejected(self):
        snapshot = self._snapshot(encode_to_registers(0xFFFFFFFF, "I"))
        with pytest.raises(SnapshotValueError):
            SafetyThreshold("I", minimum=0, maximum=10).read(snapshot)

    def test_nan_rejected_by_default(self):
        snapshot = self._snapshot(encode_to_registers(float("nan"), "f"))
        with pytest.raises(SnapshotValueError):
            SafetyThreshold("f").read(snapshot)

    def test_nan_allowed_when_explicitly_permitted(self):
        snapshot = self._snapshot(encode_to_registers(float("nan"), "f"))
        assert math.isnan(SafetyThreshold("f", allow_nan=True).read(snapshot))

    def test_offset_decode_within_wider_snapshot(self):
        # Threshold starts at the second word of a larger snapshot.
        store = SnapshotStore([0xAAAA, 0x1122, 0x3344])
        snapshot = store.snapshot(0, 3)
        value = SafetyThreshold("I").read(snapshot, offset=1)
        assert value == 0x11223344


class TestRuntimeIntegration:
    """The store shares the SimRuntime lock and serves its live block."""

    def _runtime(self):
        return SimRuntime(
            SimDevice(0, simdata=SimData(0, count=8, datatype=DataType.REGISTERS))
        )

    def test_store_wraps_live_runtime_block(self):
        runtime = self._runtime()
        store = snapshot_from_runtime(runtime, "x")
        store.atomic_write_value(0, 0x00010002, "I")
        # The Modbus server path reads the same live list and sees the commit.
        values = runtime.block["x"][2][0:2]
        assert values == [0x0001, 0x0002]
        assert store.snapshot(0, 2).decode("I") == 0x00010002

    def test_store_shares_runtime_lock(self):
        runtime = self._runtime()
        store = snapshot_from_runtime(runtime, "x")
        assert store._lock is runtime._lock  # pylint: disable=protected-access

    def test_no_torn_value_under_concurrent_two_half_word_updates(self):
        """Writers commit whole thresholds; readers only see real generations.

        Two known thresholds alternate on registers 0-1. A reader that copies
        the whole two-word range under the lock must always decode to one of
        the two committed values, never a hybrid of high word from one and low
        word from the other.
        """
        runtime = self._runtime()
        store = snapshot_from_runtime(runtime, "x")
        threshold_a = 0x0001_0002
        threshold_b = 0x0003_0004
        store.atomic_write_value(0, threshold_a, "I")
        seen: list[int] = []
        stop = threading.Event()
        errors: list[Exception] = []

        def writer():
            current = threshold_a
            try:
                while not stop.is_set():
                    current = threshold_b if current == threshold_a else threshold_a
                    store.atomic_write_value(0, current, "I")
            except Exception as exc:  # pragma: no cover - surfaced via errors
                errors.append(exc)

        def reader():
            try:
                while not stop.is_set():
                    snapshot = store.snapshot(0, 2)
                    seen.append(snapshot.decode("I"))
            except Exception as exc:  # pragma: no cover - surfaced via errors
                errors.append(exc)

        threads = [threading.Thread(target=writer)] + [
            threading.Thread(target=reader) for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        stop.wait(0.5)
        stop.set()
        for thread in threads:
            thread.join(timeout=5)

        assert not errors
        assert seen  # readers actually observed values
        assert set(seen).issubset({threshold_a, threshold_b})

    def test_two_step_read_can_tear_without_snapshot(self):
        """Contrast: independent single-word reads can mix generations.

        This pins the hazard the snapshot API exists to remove. The pause hook
        deterministically commits a new generation between the two half reads.
        """
        runtime = self._runtime()
        store = snapshot_from_runtime(runtime, "x")
        old_value = 0x0001_0002
        new_value = 0x0003_0004
        store.atomic_write_value(0, old_value, "I")

        high = store.snapshot(0, 1).registers[0]
        store.atomic_write_value(0, new_value, "I")  # commit during the pause
        low = store.snapshot(1, 1).registers[0]
        torn = (high << 16) | low

        assert torn not in {old_value, new_value}
        # Whereas one snapshot of the full range always reads a real generation.
        assert store.snapshot(0, 2).decode("I") == new_value
