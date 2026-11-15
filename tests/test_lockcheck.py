from __future__ import annotations

import gzip
import hashlib
import io
from types import SimpleNamespace

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.lockcheck import (
    LIMITATIONS,
    LockVerdict,
    assess_file_lock,
    assess_lock,
    read_heartbeat,
)
from dissect.vmfs.util import vmfs_uuid
from tests.conftest import absolute_path

HB_OFFSET = 0x342000
LOCK_OFFSET = 0x7B0000

OWNER = c_vmfs.UUID(timeLo=0x11111111, timeHi=0x22222222, rand=0x3333, macAddr=b"\xaa\xbb\xcc\xdd\xee\xff")
OTHER_OWNER = c_vmfs.UUID(timeLo=0x44444444, timeHi=0x55555555, rand=0x6666, macAddr=b"\x11\x22\x33\x44\x55\x66")


def make_lock(gen: int = 9, mode: int = 1, owner: c_vmfs.UUID = OWNER) -> c_vmfs.FS3_DiskLock:
    return c_vmfs.FS3_DiskLock(
        type=0x10C00001,
        addr=c_vmfs.FS3_VolAddress(offset=LOCK_OFFSET),
        hbAddr=c_vmfs.FS3_VolAddress(offset=HB_OFFSET),
        hbGen=c_vmfs.FS3_HBGen(gen=gen),
        token=0x1122334455667788,
        mode=mode,
        owner=owner,
        mtime=0x65000000,
        numHolders=1,
        gblNumHolders=1,
        gblGen=gen,
        gblBrk=0,
    )


def make_heartbeat(gen: int = 9, owner: c_vmfs.UUID = OWNER, self_offset: int = HB_OFFSET) -> c_vmfs.FS3_Heartbeat:
    return c_vmfs.FS3_Heartbeat(
        state=1,
        addr=c_vmfs.FS3_VolAddress(offset=self_offset),
        hbGen=c_vmfs.FS3_HBGen(gen=gen),
        stamp=0x1234567890,
        owner=owner,
        journalAddr=0x02000004,
        ip=b"10.0.0.229",
        journalVolAddr=0x2000000,
    )


def make_volume(heartbeat: c_vmfs.FS3_Heartbeat | None = None) -> io.BytesIO:
    buf = bytearray(HB_OFFSET + 0x1000)
    if heartbeat is not None:
        hb_buf = heartbeat.dumps()
        buf[HB_OFFSET : HB_OFFSET + len(hb_buf)] = hb_buf
    return io.BytesIO(bytes(buf))


def test_lock_heartbeat_consistent() -> None:
    """锁与心跳一致：记录声称有持有者 (HOLDER_CLAIMED)."""
    volume = make_volume(make_heartbeat(gen=9))
    before = volume.getvalue()

    assessment = assess_lock(make_lock(gen=9), fh=volume)

    assert assessment.verdict == LockVerdict.HOLDER_CLAIMED
    assert assessment.heartbeat is not None
    assert all(check.matches for check in assessment.checks)
    assert {check.field for check in assessment.checks} == {
        "hbAddr.offset vs heartbeat addr.offset",
        "hbGen.gen",
        "owner",
    }

    # Raw values are preserved and traceable
    assert assessment.lock.token == 0x1122334455667788
    assert assessment.lock.owner == vmfs_uuid(OWNER)
    assert assessment.lock.owner_raw == OWNER.dumps().hex()
    assert assessment.lock.hb_addr_offset == HB_OFFSET
    assert assessment.lock.hb_gen == 9
    assert assessment.heartbeat.hb_gen == 9
    assert assessment.heartbeat.owner == vmfs_uuid(OWNER)
    assert assessment.heartbeat.ip == "10.0.0.229"

    report = assessment.report()
    assert "HOLDER_CLAIMED" in report
    assert vmfs_uuid(OWNER) in report
    assert f"{HB_OFFSET:#x}" in report
    for limitation in LIMITATIONS:
        assert limitation in report

    # The cross-check is read-only: the volume is byte-identical afterwards
    assert volume.getvalue() == before


def test_lock_heartbeat_generation_mismatch() -> None:
    """Generation 不匹配：证据矛盾 (CONTRADICTED)."""
    volume = make_volume(make_heartbeat(gen=10))

    assessment = assess_lock(make_lock(gen=9), fh=volume)

    assert assessment.verdict == LockVerdict.CONTRADICTED
    gen_check = next(check for check in assessment.checks if check.field == "hbGen.gen")
    assert not gen_check.matches
    assert gen_check.lock_value == "9"
    assert gen_check.heartbeat_value == "10"
    assert any("hbGen.gen" in finding for finding in assessment.findings)

    # The mismatch is about the generation only; owner still matches
    owner_check = next(check for check in assessment.checks if check.field == "owner")
    assert owner_check.matches


def test_lock_heartbeat_owner_mismatch() -> None:
    """Owner 不匹配：证据矛盾 (CONTRADICTED)."""
    volume = make_volume(make_heartbeat(gen=9, owner=OTHER_OWNER))

    assessment = assess_lock(make_lock(gen=9), fh=volume)

    assert assessment.verdict == LockVerdict.CONTRADICTED
    owner_check = next(check for check in assessment.checks if check.field == "owner")
    assert not owner_check.matches
    assert owner_check.lock_value == vmfs_uuid(OWNER)
    assert owner_check.heartbeat_value == vmfs_uuid(OTHER_OWNER)


def test_lock_heartbeat_missing() -> None:
    """心跳缺失：资料不足 (INSUFFICIENT)."""
    # Case A: the heartbeat slot is blank (all zero)
    volume = make_volume(heartbeat=None)
    assessment = assess_lock(make_lock(gen=9), fh=volume)
    assert assessment.verdict == LockVerdict.INSUFFICIENT
    assert assessment.heartbeat is not None
    assert assessment.heartbeat.is_blank

    # Case B: no volume handle available at all
    assessment = assess_lock(make_lock(gen=9), fh=None)
    assert assessment.verdict == LockVerdict.INSUFFICIENT
    assert assessment.heartbeat is None

    # Case C: heartbeat reference points outside the volume (short read)
    volume = io.BytesIO(b"\x00" * 0x1000)
    assessment = assess_lock(make_lock(gen=9), fh=volume)
    assert assessment.verdict == LockVerdict.INSUFFICIENT


def test_unlocked_lock_is_not_cross_checked() -> None:
    """A free lock (mode 0) does not claim a holder, even if its hb reference is stale."""
    volume = make_volume(make_heartbeat(gen=99, owner=OTHER_OWNER))

    assessment = assess_lock(make_lock(gen=3, mode=0), fh=volume)

    assert assessment.verdict == LockVerdict.UNLOCKED
    assert assessment.heartbeat is None
    # Raw residual values are still preserved
    assert assessment.lock.hb_gen == 3
    assert assessment.lock.hb_addr_offset == HB_OFFSET


def test_read_heartbeat_preserves_stream_position() -> None:
    volume = make_volume(make_heartbeat(gen=9))
    volume.seek(0x1234)
    hb = read_heartbeat(volume, HB_OFFSET)
    assert volume.tell() == 0x1234
    assert hb.hbGen.gen == 9
    assert hb.addr.offset == HB_OFFSET


def test_assess_file_lock_on_real_image() -> None:
    """The real test image has free locks; assessment must be read-only."""
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        volume_bytes = io.BytesIO(fh.read())
    digest_before = hashlib.sha256(volume_bytes.getvalue()).hexdigest()

    vs = lvm.LVM(volume_bytes)
    fs = vmfs.VMFS(vs.volumes[0].open())

    for name in ("small", "big", "directory"):
        fd = fs.get(name)
        assessment = assess_file_lock(fd)
        # Locks in the image are free (mode 0), so no holder is claimed
        assert assessment.verdict == LockVerdict.UNLOCKED
        assert assessment.lock.mode == 0

    # A stub file descriptor with a held lock but no volume handle yields INSUFFICIENT
    stub_fd = SimpleNamespace(lock_info=make_lock(gen=9), vmfs=SimpleNamespace(fh=None))
    assert assess_file_lock(stub_fd).verdict == LockVerdict.INSUFFICIENT

    assert hashlib.sha256(volume_bytes.getvalue()).hexdigest() == digest_before


@pytest.mark.parametrize("mode", [1, 2, 3])
def test_held_lock_modes_are_cross_checked(mode: int) -> None:
    """Any non-zero lock mode claims a holder and must be cross-checked."""
    volume = make_volume(make_heartbeat(gen=9))
    assessment = assess_lock(make_lock(gen=9, mode=mode), fh=volume)
    assert assessment.verdict == LockVerdict.HOLDER_CLAIMED
