from __future__ import annotations

import io

from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.lockcheck import (
    HEARTBEAT_BLOCK_SIZE,
    LOCK_BLOCK_SIZE,
    LockVerdict,
    cross_check_lock,
    format_report,
)

LOCK_OFFSET = 0x100000
HEARTBEAT_OFFSET = 0x140000

OWNER_TIME_LO = 0x6734A1B2
OWNER_TIME_HI = 0x11EC08F1
OWNER_RAND = 0x3F2A
OWNER_MAC = bytes.fromhex("005056abcdef")


def make_lock(
    hb_addr_offset: int = HEARTBEAT_OFFSET,
    hb_gen: int = 7,
    token: int = 0xC0FFEE,
    owner: tuple[int, int, int, bytes] | None = (OWNER_TIME_LO, OWNER_TIME_HI, OWNER_RAND, OWNER_MAC),
    num_holders: int = 0,
) -> bytes:
    lock = c_vmfs.FS3_DiskLock(bytes(LOCK_BLOCK_SIZE))
    lock.type = 1
    lock.addr.offset = LOCK_OFFSET
    lock.hbAddr.offset = hb_addr_offset
    lock.hbGen.gen = hb_gen
    lock.token = token
    lock.mode = 2
    if owner is not None:
        lock.owner.timeLo, lock.owner.timeHi, lock.owner.rand, lock.owner.macAddr = owner
    lock.mtime = 0x6550A100
    lock.numHolders = num_holders
    lock.gblNumHolders = num_holders
    lock.gblGen = hb_gen
    return lock.dumps()


def make_heartbeat(
    addr_offset: int = HEARTBEAT_OFFSET,
    hb_gen: int = 7,
    owner: tuple[int, int, int, bytes] = (OWNER_TIME_LO, OWNER_TIME_HI, OWNER_RAND, OWNER_MAC),
    stamp: int = 0x0123456789ABCDEF,
) -> bytes:
    hb = c_vmfs.FS3_Heartbeat(bytes(HEARTBEAT_BLOCK_SIZE))
    hb.state = 1
    hb.addr.offset = addr_offset
    hb.hbGen.gen = hb_gen
    hb.stamp = stamp
    hb.owner.timeLo, hb.owner.timeHi, hb.owner.rand, hb.owner.macAddr = owner
    hb.journalAddr = 0x2A
    hb.driveX = 3
    hb.driveY = 1
    hb.lockImpl = 1
    hb.ip = b"192.0.2.10\x00"
    hb.journalVolAddr = 0x200000
    return hb.dumps()


def make_volume(segments: dict[int, bytes], size: int = 0x200000) -> io.BytesIO:
    volume = io.BytesIO(b"\x00" * size)
    for offset, data in segments.items():
        volume.seek(offset)
        volume.write(data)
    volume.seek(0)
    return volume


def test_lock_heartbeat_consistent() -> None:
    """Lock and heartbeat agree: the records consistently claim a holder."""
    volume = make_volume(
        {
            LOCK_OFFSET: make_lock(hb_gen=7, token=0xC0FFEE),
            HEARTBEAT_OFFSET: make_heartbeat(hb_gen=7),
        }
    )

    result = cross_check_lock(volume, LOCK_OFFSET)

    assert result.verdict is LockVerdict.HOLDER_CLAIMED
    assert result.heartbeat is not None
    assert not result.mismatches

    # Raw values are preserved as read, not normalized away
    assert result.lock.token == 0xC0FFEE
    assert result.lock.hb_addr_offset == HEARTBEAT_OFFSET
    assert result.lock.hb_gen == 7
    assert str(result.lock.owner) == "6734a1b2-11ec08f1-3f2a-005056abcdef"
    assert result.heartbeat.owner == result.lock.owner
    assert result.heartbeat.stamp == 0x0123456789ABCDEF

    # Every conclusion is traceable to specific fields
    fields = {c.field for c in result.comparisons}
    assert fields == {"hbAddr.offset", "hbGen.gen", "owner"}

    report = format_report(result)
    assert "holder-claimed" in report
    assert "token=0xc0ffee" in report
    assert "hbGen.gen=7" in report
    # The report must not claim liveness or staleness
    assert "stale" not in report.lower() or "never declares a lock stale" in report


def test_lock_heartbeat_generation_mismatch() -> None:
    """Lock references a different heartbeat generation: evidence contradicts the claim."""
    volume = make_volume(
        {
            LOCK_OFFSET: make_lock(hb_gen=7),
            HEARTBEAT_OFFSET: make_heartbeat(hb_gen=9),
        }
    )

    result = cross_check_lock(volume, LOCK_OFFSET)

    assert result.verdict is LockVerdict.CONTRADICTED
    assert result.heartbeat is not None

    mismatches = {c.field: c for c in result.mismatches}
    assert set(mismatches) == {"hbGen.gen"}
    assert mismatches["hbGen.gen"].lock_value == "7"
    assert mismatches["hbGen.gen"].heartbeat_value == "9"

    # Raw values of both sides are still preserved
    assert result.lock.hb_gen == 7
    assert result.heartbeat.hb_gen == 9

    report = format_report(result)
    assert "contradicted" in report
    assert "lock.hbGen.gen=7 but heartbeat.hbGen.gen=9" in report


def test_lock_heartbeat_missing() -> None:
    """Heartbeat record is absent: insufficient data, neither confirmed nor contradicted."""
    # Case A: referenced offset contains only zeroes
    volume = make_volume({LOCK_OFFSET: make_lock(hb_gen=7)})
    result = cross_check_lock(volume, LOCK_OFFSET)
    assert result.verdict is LockVerdict.INSUFFICIENT
    assert result.heartbeat is None
    assert "all zeroes" in result.reasons[0]

    # Case B: lock references a null heartbeat address
    volume = make_volume({LOCK_OFFSET: make_lock(hb_addr_offset=0)})
    result = cross_check_lock(volume, LOCK_OFFSET)
    assert result.verdict is LockVerdict.INSUFFICIENT
    assert "null" in result.reasons[0]

    # Case C: heartbeat record is truncated (short read at end of image)
    lock_offset = 0x1000
    hb_offset = 0x2000
    size = hb_offset + 16  # less than a full heartbeat record
    volume = io.BytesIO(b"\x00" * size)
    volume.seek(lock_offset)
    volume.write(make_lock(hb_addr_offset=hb_offset))
    volume.seek(0)
    result = cross_check_lock(volume, lock_offset)
    assert result.verdict is LockVerdict.INSUFFICIENT
    assert "short read" in result.reasons[0]

    # In all cases the lock claim itself is preserved untouched
    assert result.lock.token == 0xC0FFEE
    assert not result.lock.owner.is_zero


def test_lock_without_holder_claim() -> None:
    """A lock with null owner and no holders does not claim a holder."""
    volume = make_volume({LOCK_OFFSET: make_lock(owner=None, num_holders=0)})
    result = cross_check_lock(volume, LOCK_OFFSET)
    assert result.verdict is LockVerdict.NO_HOLDER_CLAIMED


def test_cross_check_is_read_only() -> None:
    """The cross-check must never modify the image."""
    segments = {
        LOCK_OFFSET: make_lock(hb_gen=7),
        HEARTBEAT_OFFSET: make_heartbeat(hb_gen=7),
    }
    volume = make_volume(segments)
    before = volume.getvalue()

    cross_check_lock(volume, LOCK_OFFSET)

    assert volume.getvalue() == before
