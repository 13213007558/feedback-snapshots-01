"""Forensic cross-checking of VMFS disk locks against heartbeat records.

Every VMFS file descriptor starts with an ``FS3_DiskLock`` lock block. When a lock is held,
the lock block *claims* a holder: it records the owner UUID, a token, and a reference
(``hbAddr`` + ``hbGen``) to the heartbeat record of the holding host. The heartbeat record
(``FS3_Heartbeat``) lives elsewhere on the volume and is what the cluster actually uses to
decide liveness: a host periodically updates its heartbeat slot and bumps its generation.

This module performs a read-only evidence cross-check ("证据对照") between those two
structures on an offline image:

- It preserves the raw values of the owner, token, heartbeat address and generation.
- It resolves the lock's heartbeat reference and checks whether it points to a heartbeat
  record of the *same generation*, held by the *same owner*, at the *same address*.
- It distinguishes three outcomes:

  - ``HOLDER_CLAIMED`` (记录声称有持有者): lock block and heartbeat record are consistent.
  - ``CONTRADICTED`` (证据矛盾): the heartbeat record exists but disagrees with the lock.
  - ``INSUFFICIENT`` (资料不足): the heartbeat record is missing or unreadable.

  (A fourth outcome, ``UNLOCKED``, covers locks that do not claim a holder at all.)

What this can and cannot conclude
---------------------------------
A consistent lock/heartbeat pair only means the *on-disk records* claim a holder. An offline
image is a snapshot without a reference clock, so:

- We **cannot** conclude the owning host was actually alive at acquisition time. Liveness is
  a runtime property; a static image only shows the last persisted claim.
- We **must not** declare a lock stale or broken merely because the image (or the lock
  ``mtime`` / heartbeat ``stamp``) is old. Age alone is not evidence of release.
- We **must not** modify, clear or break locks. This module only reads.

Why ``FileDescriptor.debug()`` output is not enough
---------------------------------------------------
The debug text (mimicking ``vmkfstools -D``) only prints the lock block's own claim: owner,
token, ``hbAddr`` and ``hbGen`` as stored *in the lock*. It never resolves the heartbeat
record, so it cannot detect a generation mismatch, a missing heartbeat slot, or an owner
disagreement. Printing the claim is not the same as cross-checking the evidence.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.util import vmfs_uuid

if TYPE_CHECKING:
    from dissect.vmfs.descriptor import FileDescriptor

__all__ = [
    "FieldComparison",
    "HeartbeatEvidence",
    "LockAssessment",
    "LockEvidence",
    "LockVerdict",
    "assess_file_lock",
    "assess_lock",
    "read_heartbeat",
]

_ZERO_UUID = b"\x00" * 16

#: Limitations attached to every assessment. These are part of the evidence statement.
LIMITATIONS = (
    "离线镜像只是采集时刻的快照：锁与心跳一致仅表示记录声称有持有者，不能证明该主机在采集时真实存活。",
    "锁 mtime 或心跳 stamp 较旧不能作为锁已失效的证据；不得仅因镜像陈旧而宣布锁过期。",
    "本对照为只读操作，不修改、清除或打破任何锁。",
)


class LockVerdict(enum.Enum):
    """The conclusion of a lock/heartbeat cross-check."""

    #: The lock does not claim a holder (mode == 0).
    UNLOCKED = "unlocked"
    #: 记录声称有持有者: lock and heartbeat record are consistent.
    HOLDER_CLAIMED = "holder_claimed"
    #: 证据矛盾: the heartbeat record exists but contradicts the lock.
    CONTRADICTED = "contradicted"
    #: 资料不足: the heartbeat record is missing or unreadable.
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class LockEvidence:
    """Raw values preserved from an ``FS3_DiskLock`` lock block."""

    type: int
    addr_offset: int
    token: int
    mode: int
    owner: str
    owner_raw: str
    mtime: int
    hb_addr_offset: int
    hb_gen: int
    num_holders: int
    gbl_num_holders: int
    gbl_gen: int
    gbl_brk: int
    holders: tuple[tuple[int, int, str], ...]

    @classmethod
    def from_struct(cls, lock: c_vmfs.FS3_DiskLock) -> LockEvidence:
        return cls(
            type=lock.type,
            addr_offset=lock.addr.offset,
            token=lock.token,
            mode=lock.mode,
            owner=vmfs_uuid(lock.owner),
            owner_raw=lock.owner.dumps().hex(),
            mtime=lock.mtime,
            hb_addr_offset=lock.hbAddr.offset,
            hb_gen=lock.hbGen.gen,
            num_holders=lock.numHolders,
            gbl_num_holders=lock.gblNumHolders,
            gbl_gen=lock.gblGen,
            gbl_brk=lock.gblBrk,
            holders=tuple((h.hbAddr.offset, h.hbGen.gen, vmfs_uuid(h.uid)) for h in lock.holders),
        )


@dataclass(frozen=True)
class HeartbeatEvidence:
    """Raw values preserved from an ``FS3_Heartbeat`` record."""

    read_offset: int
    state: int
    addr_offset: int
    hb_gen: int
    stamp: int
    owner: str
    owner_raw: str
    ip: str
    journal_addr: int
    journal_vol_addr: int

    @classmethod
    def from_struct(cls, hb: c_vmfs.FS3_Heartbeat, read_offset: int) -> HeartbeatEvidence:
        return cls(
            read_offset=read_offset,
            state=hb.state,
            addr_offset=hb.addr.offset,
            hb_gen=hb.hbGen.gen,
            stamp=hb.stamp,
            owner=vmfs_uuid(hb.owner),
            owner_raw=hb.owner.dumps().hex(),
            ip=bytes(hb.ip).split(b"\x00")[0].decode("utf-8", errors="replace"),
            journal_addr=hb.journalAddr,
            journal_vol_addr=hb.journalVolAddr,
        )

    @property
    def is_blank(self) -> bool:
        """Whether the heartbeat slot is blank (all identifying fields zero)."""
        return (
            self.state == 0
            and self.addr_offset == 0
            and self.hb_gen == 0
            and self.stamp == 0
            and self.owner_raw == _ZERO_UUID.hex()
        )


@dataclass(frozen=True)
class FieldComparison:
    """A single field-level comparison between lock and heartbeat evidence."""

    field: str
    lock_value: str
    heartbeat_value: str
    matches: bool


@dataclass(frozen=True)
class LockAssessment:
    """The result of cross-checking a lock block against its heartbeat record."""

    verdict: LockVerdict
    lock: LockEvidence
    heartbeat: HeartbeatEvidence | None
    checks: tuple[FieldComparison, ...] = ()
    findings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = field(default=tuple(LIMITATIONS))

    def report(self) -> str:
        """Render a human-readable evidence report, traceable to concrete fields."""
        lines = [
            f"Verdict: {self.verdict.name} ({self.verdict.value})",
            "Lock block (FS3_DiskLock):",
            f"  type           = {self.lock.type:#x}",
            f"  addr.offset    = {self.lock.addr_offset:#x}",
            f"  token (v)      = {self.lock.token:#x}",
            f"  mode           = {self.lock.mode}",
            f"  owner          = {self.lock.owner} (raw {self.lock.owner_raw})",
            f"  mtime          = {self.lock.mtime}",
            f"  hbAddr.offset  = {self.lock.hb_addr_offset:#x}",
            f"  hbGen.gen      = {self.lock.hb_gen}",
            f"  numHolders     = {self.lock.num_holders} (gbl {self.lock.gbl_num_holders})",
            f"  gblGen/gblBrk  = {self.lock.gbl_gen} / {self.lock.gbl_brk}",
        ]
        if self.heartbeat is not None:
            lines += [
                "Heartbeat record (FS3_Heartbeat):",
                f"  read @offset   = {self.heartbeat.read_offset:#x}",
                f"  state          = {self.heartbeat.state}",
                f"  addr.offset    = {self.heartbeat.addr_offset:#x}",
                f"  hbGen.gen      = {self.heartbeat.hb_gen}",
                f"  stamp          = {self.heartbeat.stamp}",
                f"  owner          = {self.heartbeat.owner} (raw {self.heartbeat.owner_raw})",
                f"  ip             = {self.heartbeat.ip!r}",
            ]
        for check in self.checks:
            mark = "MATCH" if check.matches else "MISMATCH"
            lines.append(f"  [{mark}] {check.field}: lock={check.lock_value} heartbeat={check.heartbeat_value}")
        for finding in self.findings:
            lines.append(f"Finding: {finding}")
        for limitation in self.limitations:
            lines.append(f"Limitation: {limitation}")
        return "\n".join(lines)


def read_heartbeat(fh: BinaryIO, offset: int) -> c_vmfs.FS3_Heartbeat:
    """Read an ``FS3_Heartbeat`` record at a volume offset. Read-only; preserves stream position."""
    position = fh.tell()
    try:
        fh.seek(offset)
        buf = fh.read(len(c_vmfs.FS3_Heartbeat))
    finally:
        fh.seek(position)
    if len(buf) != len(c_vmfs.FS3_Heartbeat):
        raise ValueError(f"Short read on heartbeat at offset {offset:#x}: got {len(buf)} bytes")
    return c_vmfs.FS3_Heartbeat(buf)


def assess_lock(
    lock: c_vmfs.FS3_DiskLock,
    fh: BinaryIO | None = None,
    heartbeat: c_vmfs.FS3_Heartbeat | None = None,
) -> LockAssessment:
    """Cross-check a lock block against the heartbeat record it references.

    Args:
        lock: The ``FS3_DiskLock`` lock block to assess.
        fh: A file-like object of the VMFS volume, used to read the heartbeat record
            at ``lock.hbAddr.offset``. Only read operations are performed.
        heartbeat: An already-read ``FS3_Heartbeat`` record, if available.
    """
    evidence = LockEvidence.from_struct(lock)

    if evidence.mode == 0:
        return LockAssessment(
            verdict=LockVerdict.UNLOCKED,
            lock=evidence,
            heartbeat=None,
            findings=("锁记录 mode=0，未声称持有者；hbAddr/hbGen 为历史残留引用，不参与对照。",),
        )

    # The lock claims a holder; we must resolve the heartbeat reference to say more.
    if heartbeat is None:
        if fh is None:
            return LockAssessment(
                verdict=LockVerdict.INSUFFICIENT,
                lock=evidence,
                heartbeat=None,
                findings=(
                    f"锁声称持有者为 {evidence.owner}，但无卷句柄可读取 hbAddr.offset="
                    f"{evidence.hb_addr_offset:#x} 处的心跳记录（资料不足）。",
                ),
            )
        try:
            heartbeat = read_heartbeat(fh, evidence.hb_addr_offset)
        except (OSError, ValueError) as e:
            return LockAssessment(
                verdict=LockVerdict.INSUFFICIENT,
                lock=evidence,
                heartbeat=None,
                findings=(
                    f"锁声称持有者为 {evidence.owner}，但读取 hbAddr.offset="
                    f"{evidence.hb_addr_offset:#x} 处的心跳记录失败：{e}（资料不足）。",
                ),
            )

    hb_evidence = HeartbeatEvidence.from_struct(heartbeat, evidence.hb_addr_offset)

    if hb_evidence.is_blank:
        return LockAssessment(
            verdict=LockVerdict.INSUFFICIENT,
            lock=evidence,
            heartbeat=hb_evidence,
            findings=(
                f"锁声称持有者为 {evidence.owner}，但 hbAddr.offset={evidence.hb_addr_offset:#x} "
                "处的心跳槽为空（全零），无法对照（资料不足）。",
            ),
        )

    checks = (
        FieldComparison(
            field="hbAddr.offset vs heartbeat addr.offset",
            lock_value=f"{evidence.hb_addr_offset:#x}",
            heartbeat_value=f"{hb_evidence.addr_offset:#x}",
            matches=evidence.hb_addr_offset == hb_evidence.addr_offset,
        ),
        FieldComparison(
            field="hbGen.gen",
            lock_value=str(evidence.hb_gen),
            heartbeat_value=str(hb_evidence.hb_gen),
            matches=evidence.hb_gen == hb_evidence.hb_gen,
        ),
        FieldComparison(
            field="owner",
            lock_value=evidence.owner,
            heartbeat_value=hb_evidence.owner,
            matches=evidence.owner_raw == hb_evidence.owner_raw,
        ),
    )

    mismatches = [c for c in checks if not c.matches]
    if mismatches:
        findings = tuple(
            f"字段 {c.field} 矛盾：锁记录为 {c.lock_value}，心跳记录为 {c.heartbeat_value}（证据矛盾）。"
            for c in mismatches
        )
        return LockAssessment(
            verdict=LockVerdict.CONTRADICTED,
            lock=evidence,
            heartbeat=hb_evidence,
            checks=checks,
            findings=findings,
        )

    return LockAssessment(
        verdict=LockVerdict.HOLDER_CLAIMED,
        lock=evidence,
        heartbeat=hb_evidence,
        checks=checks,
        findings=(
            f"锁与心跳记录一致：记录声称 {evidence.owner} 在 hbGen.gen={evidence.hb_gen} 代持有该锁"
            "（仅表示记录声称有持有者，不代表采集时主机存活）。",
        ),
    )


def assess_file_lock(fd: FileDescriptor) -> LockAssessment:
    """Cross-check the lock block of a file descriptor against its heartbeat record.

    Uses the volume handle of the filesystem the file descriptor belongs to. If the
    filesystem was opened without a volume (e.g. from individual system files), the
    heartbeat cannot be read and the verdict will be ``INSUFFICIENT`` for held locks.
    """
    return assess_lock(fd.lock_info, fh=fd.vmfs.fh)
