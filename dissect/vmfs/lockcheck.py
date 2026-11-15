"""Read-only cross-check of VMFS disk locks against heartbeat records.

This module is meant for offline forensic images. It reads an ``FS3_DiskLock``
block and the ``FS3_Heartbeat`` record the lock points at (``hbAddr`` /
``hbGen``), preserves the raw field values of both, and checks whether the
lock's heartbeat reference points to a heartbeat record of the *same*
generation, owned by the *same* host.

The verdict is deliberately conservative and falls into one of four
categories:

- ``HOLDER_CLAIMED``: the lock record claims a holder and the referenced
  heartbeat record exists and is consistent (same address, same generation,
  same owner). This only means the *records* consistently claim a holder.
- ``NO_HOLDER_CLAIMED``: the lock record itself does not claim a holder
  (null owner UUID, zero holders).
- ``CONTRADICTED``: the lock claims a holder, but the heartbeat record it
  references contradicts the claim (different generation, different owner,
  or a self-referencing address that does not match).
- ``INSUFFICIENT``: the heartbeat record is missing or unreadable, so the
  claim can neither be confirmed nor contradicted.

Two things this module explicitly never does:

- It never declares a lock "stale" or "expired". An offline image is a
  frozen snapshot; a heartbeat ``stamp`` that looks old only tells us the
  last update persisted *before* acquisition, not whether the owning host
  was alive *at* acquisition time. Liveness cannot be established from a
  dead image.
- It never writes to, modifies, or clears a lock (or anything else) on the
  image. All functions below only perform ``seek``/``read`` operations.

Why printing debug text is not enough: a formatted dump of a lock block
(e.g. ``voma``/``vmkfstools`` style output) is an interpretation rendered
once, by one tool, at one moment. It flattens the raw ``owner``/``token``/
``hbAddr``/``hbGen`` values into a string that cannot be re-verified
field-by-field, cannot be correlated against the heartbeat record it
references, and cannot distinguish "the record claims a holder" from "the
holder was actually alive when the image was acquired". The cross-check
here keeps every raw value and ties every conclusion to specific fields so
the reasoning stays auditable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from dissect.vmfs.c_vmfs import c_vmfs

if TYPE_CHECKING:
    from collections.abc import Iterator

LOCK_BLOCK_SIZE = len(c_vmfs.FS3_DiskLock)
HEARTBEAT_BLOCK_SIZE = len(c_vmfs.FS3_Heartbeat)


class LockVerdict(enum.Enum):
    """Verdict of a lock/heartbeat cross-check."""

    HOLDER_CLAIMED = "holder-claimed"
    NO_HOLDER_CLAIMED = "no-holder-claimed"
    CONTRADICTED = "contradicted"
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class UUIDEvidence:
    """Raw value of a VMFS ``UUID`` structure, preserved as read."""

    time_lo: int
    time_hi: int
    rand: int
    mac_addr: bytes

    @classmethod
    def from_uuid(cls, uuid: c_vmfs.UUID) -> UUIDEvidence:
        return cls(
            time_lo=uuid.timeLo,
            time_hi=uuid.timeHi,
            rand=uuid.rand,
            mac_addr=bytes(uuid.macAddr),
        )

    @property
    def is_zero(self) -> bool:
        return self.time_lo == 0 and self.time_hi == 0 and self.rand == 0 and not any(self.mac_addr)

    def __str__(self) -> str:
        return f"{self.time_lo:08x}-{self.time_hi:08x}-{self.rand:04x}-{self.mac_addr.hex()}"


@dataclass(frozen=True)
class LockHolderEvidence:
    """Raw value of one ``FS3_LockHolder`` entry."""

    hb_addr_offset: int
    hb_gen: int
    uid: UUIDEvidence


@dataclass(frozen=True)
class LockEvidence:
    """Raw values of an ``FS3_DiskLock`` block, preserved as read."""

    offset: int
    type: int
    addr_offset: int
    hb_addr_offset: int
    hb_gen: int
    token: int
    mode: int
    owner: UUIDEvidence
    mtime: int
    num_holders: int
    holders: tuple[LockHolderEvidence, ...]
    gbl_num_holders: int
    gbl_gen: int
    gbl_brk: int

    @property
    def claims_holder(self) -> bool:
        """Whether the lock record itself claims a holder."""
        return not self.owner.is_zero or self.num_holders > 0


@dataclass(frozen=True)
class HeartbeatEvidence:
    """Raw values of an ``FS3_Heartbeat`` record, preserved as read."""

    offset: int
    state: int
    addr_offset: int
    hb_gen: int
    stamp: int
    owner: UUIDEvidence
    journal_addr: int
    drive_x: int
    drive_y: int
    lock_impl: int
    ip: bytes
    journal_vol_addr: int
    replay_host: UUIDEvidence
    replay_host_hb: int
    replay_host_hb_gen: int


@dataclass(frozen=True)
class FieldComparison:
    """Comparison of one lock field against one heartbeat field."""

    field: str
    lock_value: str
    heartbeat_value: str
    match: bool


@dataclass(frozen=True)
class LockCrossCheckResult:
    """Result of cross-checking a disk lock against its heartbeat record."""

    verdict: LockVerdict
    lock: LockEvidence
    heartbeat: HeartbeatEvidence | None
    comparisons: tuple[FieldComparison, ...] = ()
    reasons: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def mismatches(self) -> tuple[FieldComparison, ...]:
        return tuple(c for c in self.comparisons if not c.match)


def read_disk_lock(fh: BinaryIO, offset: int) -> LockEvidence:
    """Read an ``FS3_DiskLock`` block from a volume at ``offset``. Read-only."""
    fh.seek(offset)
    buf = fh.read(LOCK_BLOCK_SIZE)
    if len(buf) < LOCK_BLOCK_SIZE:
        raise EOFError(f"Short read on FS3_DiskLock at offset {offset:#x}")
    lock = c_vmfs.FS3_DiskLock(buf)
    return LockEvidence(
        offset=offset,
        type=lock.type,
        addr_offset=lock.addr.offset,
        hb_addr_offset=lock.hbAddr.offset,
        hb_gen=lock.hbGen.gen,
        token=lock.token,
        mode=lock.mode,
        owner=UUIDEvidence.from_uuid(lock.owner),
        mtime=lock.mtime,
        num_holders=lock.numHolders,
        holders=tuple(
            LockHolderEvidence(
                hb_addr_offset=holder.hbAddr.offset,
                hb_gen=holder.hbGen.gen,
                uid=UUIDEvidence.from_uuid(holder.uid),
            )
            for holder in lock.holders
        ),
        gbl_num_holders=lock.gblNumHolders,
        gbl_gen=lock.gblGen,
        gbl_brk=lock.gblBrk,
    )


def read_heartbeat(fh: BinaryIO, offset: int) -> HeartbeatEvidence:
    """Read an ``FS3_Heartbeat`` record from a volume at ``offset``. Read-only."""
    fh.seek(offset)
    buf = fh.read(HEARTBEAT_BLOCK_SIZE)
    if len(buf) < HEARTBEAT_BLOCK_SIZE:
        raise EOFError(f"Short read on FS3_Heartbeat at offset {offset:#x}")
    hb = c_vmfs.FS3_Heartbeat(buf)
    return HeartbeatEvidence(
        offset=offset,
        state=hb.state,
        addr_offset=hb.addr.offset,
        hb_gen=hb.hbGen.gen,
        stamp=hb.stamp,
        owner=UUIDEvidence.from_uuid(hb.owner),
        journal_addr=hb.journalAddr,
        drive_x=hb.driveX,
        drive_y=hb.driveY,
        lock_impl=hb.lockImpl,
        ip=bytes(hb.ip),
        journal_vol_addr=hb.journalVolAddr,
        replay_host=UUIDEvidence.from_uuid(hb.replayHost),
        replay_host_hb=hb.replayHostHB,
        replay_host_hb_gen=hb.replayHostHBgen.gen,
    )


def _is_empty_heartbeat(fh: BinaryIO, offset: int) -> bool:
    fh.seek(offset)
    return not any(fh.read(HEARTBEAT_BLOCK_SIZE))


def _compare(lock: LockEvidence, heartbeat: HeartbeatEvidence) -> Iterator[FieldComparison]:
    yield FieldComparison(
        field="hbAddr.offset",
        lock_value=f"{lock.hb_addr_offset:#x}",
        heartbeat_value=f"{heartbeat.addr_offset:#x}",
        match=lock.hb_addr_offset == heartbeat.addr_offset,
    )
    yield FieldComparison(
        field="hbGen.gen",
        lock_value=f"{lock.hb_gen}",
        heartbeat_value=f"{heartbeat.hb_gen}",
        match=lock.hb_gen == heartbeat.hb_gen,
    )
    yield FieldComparison(
        field="owner",
        lock_value=str(lock.owner),
        heartbeat_value=str(heartbeat.owner),
        match=lock.owner == heartbeat.owner,
    )


def cross_check_lock(
    fh: BinaryIO,
    lock_offset: int,
    heartbeat_offset: int | None = None,
) -> LockCrossCheckResult:
    """Cross-check a disk lock against the heartbeat record it references.

    Reads the ``FS3_DiskLock`` at ``lock_offset`` and the ``FS3_Heartbeat``
    at ``heartbeat_offset`` (defaults to the lock's own ``hbAddr.offset``),
    then compares the raw ``hbAddr``, ``hbGen`` and ``owner`` values.

    This function is strictly read-only: it never modifies, clears or
    breaks the lock, and it never concludes that a lock is stale or expired
    based on the age of the image or of the heartbeat stamp.

    Args:
        fh: A file-like object of the VMFS volume.
        lock_offset: Volume offset of the ``FS3_DiskLock`` block.
        heartbeat_offset: Optional override for the heartbeat record offset.
    """
    limitations = [
        "offline image: a heartbeat stamp only records the last update persisted before "
        "acquisition; it cannot prove the owning host was alive at acquisition time",
        "this check never declares a lock stale/expired and never modifies the image",
    ]

    lock = read_disk_lock(fh, lock_offset)

    if not lock.claims_holder:
        return LockCrossCheckResult(
            verdict=LockVerdict.NO_HOLDER_CLAIMED,
            lock=lock,
            heartbeat=None,
            reasons=(
                f"lock.owner is null ({lock.owner}) and lock.numHolders={lock.num_holders}: "
                "the lock record itself does not claim a holder",
            ),
            limitations=tuple(limitations),
        )

    if heartbeat_offset is None:
        heartbeat_offset = lock.hb_addr_offset

    if heartbeat_offset == 0:
        return LockCrossCheckResult(
            verdict=LockVerdict.INSUFFICIENT,
            lock=lock,
            heartbeat=None,
            reasons=(
                f"lock.hbAddr.offset={lock.hb_addr_offset:#x} is null: "
                "no heartbeat record is referenced, the claim can neither be confirmed nor contradicted",
            ),
            limitations=tuple(limitations),
        )

    try:
        heartbeat = read_heartbeat(fh, heartbeat_offset)
    except EOFError:
        return LockCrossCheckResult(
            verdict=LockVerdict.INSUFFICIENT,
            lock=lock,
            heartbeat=None,
            reasons=(
                f"heartbeat record at offset {heartbeat_offset:#x} is unreadable (short read): "
                "the claim can neither be confirmed nor contradicted",
            ),
            limitations=tuple(limitations),
        )

    if _is_empty_heartbeat(fh, heartbeat_offset):
        return LockCrossCheckResult(
            verdict=LockVerdict.INSUFFICIENT,
            lock=lock,
            heartbeat=None,
            reasons=(
                f"heartbeat record at offset {heartbeat_offset:#x} is all zeroes: "
                "no heartbeat data present, the claim can neither be confirmed nor contradicted",
            ),
            limitations=tuple(limitations),
        )

    comparisons = tuple(_compare(lock, heartbeat))
    mismatches = [c for c in comparisons if not c.match]

    if mismatches:
        return LockCrossCheckResult(
            verdict=LockVerdict.CONTRADICTED,
            lock=lock,
            heartbeat=heartbeat,
            comparisons=comparisons,
            reasons=tuple(
                f"lock.{c.field}={c.lock_value} but heartbeat.{c.field}={c.heartbeat_value}" for c in mismatches
            ),
            limitations=tuple(limitations),
        )

    return LockCrossCheckResult(
        verdict=LockVerdict.HOLDER_CLAIMED,
        lock=lock,
        heartbeat=heartbeat,
        comparisons=comparisons,
        reasons=(
            f"lock record claims owner {lock.owner} (token={lock.token:#x}) and the referenced heartbeat "
            f"record at offset {heartbeat_offset:#x} is consistent (same hbAddr, hbGen and owner)",
        ),
        limitations=tuple(limitations),
    )


def format_report(result: LockCrossCheckResult) -> str:
    """Format a cross-check result as an auditable, field-level report."""
    lock = result.lock
    lines = [
        f"verdict: {result.verdict.value}",
        f"lock @ {lock.offset:#x}:",
        f"  type={lock.type} mode={lock.mode} token={lock.token:#x} mtime={lock.mtime}",
        f"  owner={lock.owner}",
        f"  hbAddr.offset={lock.hb_addr_offset:#x} hbGen.gen={lock.hb_gen}",
        f"  numHolders={lock.num_holders} gblNumHolders={lock.gbl_num_holders} "
        f"gblGen={lock.gbl_gen} gblBrk={lock.gbl_brk}",
    ]
    for i, holder in enumerate(lock.holders[: lock.num_holders]):
        lines.append(
            f"  holders[{i}]: uid={holder.uid} hbAddr.offset={holder.hb_addr_offset:#x} hbGen.gen={holder.hb_gen}"
        )
    if result.heartbeat is not None:
        hb = result.heartbeat
        ip = hb.ip.split(b"\x00")[0].decode("utf-8", errors="replace")
        lines += [
            f"heartbeat @ {hb.offset:#x}:",
            f"  state={hb.state} addr.offset={hb.addr_offset:#x} hbGen.gen={hb.hb_gen} stamp={hb.stamp}",
            f"  owner={hb.owner}",
            f"  journalAddr={hb.journal_addr:#x} journalVolAddr={hb.journal_vol_addr:#x} "
            f"drive={hb.drive_x}.{hb.drive_y} lockImpl={hb.lock_impl} ip={ip!r}",
            f"  replayHost={hb.replay_host} replayHostHB={hb.replay_host_hb:#x} "
            f"replayHostHBgen={hb.replay_host_hb_gen}",
        ]
    else:
        lines.append("heartbeat: <not available>")
    if result.comparisons:
        lines.append("field comparisons:")
        for c in result.comparisons:
            mark = "OK " if c.match else "MISMATCH"
            lines.append(f"  [{mark}] lock.{c.field}={c.lock_value} heartbeat.{c.field}={c.heartbeat_value}")
    if result.reasons:
        lines.append("reasons:")
        lines += [f"  - {reason}" for reason in result.reasons]
    lines.append("limitations:")
    lines += [f"  - {limitation}" for limitation in result.limitations]
    return "\n".join(lines)
