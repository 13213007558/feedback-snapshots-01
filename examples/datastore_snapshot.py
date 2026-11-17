#!/usr/bin/env python3
"""Consistent (snapshot) read of a 32-bit safety threshold example.

A safety monitor interprets *two* 16-bit holding registers as *one* 32-bit
threshold. The backend updates those two half-words independently. If the
monitor reads the two registers in two separate steps it can catch the update
half way and assemble a 32-bit value that never existed, potentially hiding a
dangerous threshold. This example shows:

1. how a torn, two-step read fabricates a value from two generations,
2. how reading the whole range from one :class:`RegisterSnapshot` prevents it,
3. how byte order / word order are fixed by the caller (never guessed),
4. how NaN / out-of-range values are rejected instead of being silently
   replaced by a "normal" number.

Atomicity is deliberately scoped: one PDU range read from one snapshot is
consistent. Two separate requests are two snapshots and are not promised to be
mutually atomic.

The example runs without a socket: it drives the in-memory datastore
(:class:`pymodbus.simulator.simruntime.SimRuntime`) directly, the same block the
Modbus server serves, so the demonstration also applies to live requests.
"""

from __future__ import annotations

from collections.abc import Callable

from pymodbus.datastore import (
    SafetyThreshold,
    SnapshotValueError,
    WordOrder,
    snapshot_from_runtime,
)
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.simulator.simruntime import SimRuntime

# The 32-bit threshold lives in holding registers 10 (high word) and 11 (low).
THRESHOLD_ADDRESS = 10
THRESHOLD_REGISTERS = 2
# Fixed wire interpretation for this (fictional) device: big-endian bytes,
# high word first. A real deployment fixes these once from the device manual.
BYTE_ORDER = "big"
WORD_ORDER = WordOrder.HIGH_WORD_FIRST
# Trusted engineering window for the safety threshold.
THRESHOLD_MIN = 0
THRESHOLD_MAX = 200_000


def build_runtime() -> SimRuntime:
    """Build a runtime whose holding block contains the threshold registers."""
    device = SimDevice(
        0,
        simdata=[
            SimData(0, count=32, datatype=DataType.REGISTERS),
        ],
    )
    return SimRuntime(device)


def unsafe_two_step_read(
    runtime: SimRuntime, pause_between_halves: Callable[[], None] | None = None
) -> tuple[int, int, int]:
    """Read the two half-words in two independent steps (NOT consistent).

    Returns ``(high_word, low_word, assembled_value)``. Because there is no
    shared snapshot, a writer committing during ``pause_between_halves`` can
    leave a high word from one generation next to a low word from another.
    """
    store = snapshot_from_runtime(runtime, "x")
    high = store.snapshot(THRESHOLD_ADDRESS, 1).registers[0]
    if pause_between_halves is not None:
        pause_between_halves()
    low = store.snapshot(THRESHOLD_ADDRESS + 1, 1).registers[0]
    return high, low, (high << 16) | low


def consistent_snapshot_read(runtime: SimRuntime) -> tuple[int, int, int]:
    """Read the whole threshold range from a single point-in-time snapshot."""
    store = snapshot_from_runtime(runtime, "x")
    snapshot = store.snapshot(THRESHOLD_ADDRESS, THRESHOLD_REGISTERS)
    high, low = snapshot.registers
    threshold = SafetyThreshold(
        "I",
        minimum=THRESHOLD_MIN,
        maximum=THRESHOLD_MAX,
        byte_order=BYTE_ORDER,
        word_order=WORD_ORDER,
    )
    return high, low, int(threshold.read(snapshot))


def main() -> None:
    """Drive a deterministic torn read and compare it with the snapshot read."""
    runtime = build_runtime()
    store = snapshot_from_runtime(runtime, "x")

    # Both values stay inside the trusted window, but use distinct non-zero
    # high words so a mixed-generation read is provably never-committed data.
    old_threshold = 0x0001_0002  # high=0x0001 low=0x0002 -> 65538
    new_threshold = 0x0003_0004  # high=0x0003 low=0x0004 -> 196612
    store.atomic_write_value(
        THRESHOLD_ADDRESS,
        old_threshold,
        "I",
        byte_order=BYTE_ORDER,
        word_order=WORD_ORDER,
    )

    def commit_new_generation() -> None:
        """Simulate the backend committing while the monitor is paused."""
        store.atomic_write_value(
            THRESHOLD_ADDRESS,
            new_threshold,
            "I",
            byte_order=BYTE_ORDER,
            word_order=WORD_ORDER,
        )

    # --- Unsafe path: a generation change lands between the two half reads. ---
    high_word, low_word, torn_value = unsafe_two_step_read(
        runtime, pause_between_halves=commit_new_generation
    )
    print(
        "torn two-step read: "
        f"high=0x{high_word:04x} (old gen) low=0x{low_word:04x} (new gen) "
        f"-> fabricated value {torn_value}"
    )
    assert torn_value != old_threshold and torn_value != new_threshold

    # --- Safe path: one snapshot always reflects a single generation. ---
    high_safe, low_safe, safe_value = consistent_snapshot_read(runtime)
    print(
        "snapshot read: "
        f"high=0x{high_safe:04x} low=0x{low_safe:04x} "
        f"-> trusted value {safe_value}"
    )
    assert safe_value == new_threshold

    # --- Invalid values are reported, never silently replaced. ---
    store.atomic_write(THRESHOLD_ADDRESS, [0xFFFF, 0xFFFF])
    bad_snapshot = store.snapshot(THRESHOLD_ADDRESS, THRESHOLD_REGISTERS)
    threshold = SafetyThreshold(
        "I",
        minimum=THRESHOLD_MIN,
        maximum=THRESHOLD_MAX,
        byte_order=BYTE_ORDER,
        word_order=WORD_ORDER,
    )
    try:
        threshold.read(bad_snapshot)
    except SnapshotValueError as exc:
        print(f"out-of-range threshold rejected (no substitution): {exc}")


if __name__ == "__main__":
    main()
