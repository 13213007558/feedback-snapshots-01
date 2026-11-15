from __future__ import annotations

import gzip
from collections.abc import Iterator
from contextlib import ExitStack

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.address import FileDescriptorAddr
from dissect.vmfs.c_vmfs import FS3_DescriptorType, c_vmfs
from dissect.vmfs.descriptor import (
    DescriptorReference,
    DescriptorState,
    classify_descriptor,
)
from dissect.vmfs.resource import ResourceSlot
from tests.conftest import absolute_path


@pytest.fixture(name="vmfs5")
def fixture_vmfs5() -> vmfs.VMFS:
    with ExitStack() as stack:
        fh = stack.enter_context(gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb"))
        vs = lvm.LVM(fh)
        yield vmfs.VMFS(vs.volumes[0].open())


@pytest.fixture(name="vmfs6")
def fixture_vmfs6() -> vmfs.VMFS:
    with ExitStack() as stack:
        fh = stack.enter_context(gzip.open(absolute_path("_data/vmfs/vmfs6.bin.gz"), "rb"))
        vs = lvm.LVM(fh)
        yield vmfs.VMFS(vs.volumes[0].open())


@pytest.fixture(name="vmfs6_zero")
def fixture_vmfs6_zero() -> vmfs.VMFS:
    with ExitStack() as stack:
        fh = stack.enter_context(gzip.open(absolute_path("_data/vmfs/zero6.bin.gz"), "rb"))
        vs = lvm.LVM(fh)
        yield vmfs.VMFS(vs.volumes[0].open())


def _reference(
    address: int,
    generation: int | None,
    *,
    slot_generation: int | None = None,
    name: str = "entry",
    path: str = "/",
) -> DescriptorReference:
    matches = generation is not None and slot_generation is not None and generation == slot_generation
    return DescriptorReference(
        address=address,
        name=name,
        path=path,
        generation=generation,
        matches_generation=matches,
    )


def test_classify_descriptor_allocated_referenced() -> None:
    ref = _reference(0x4, generation=3, slot_generation=3)
    state, reasons = classify_descriptor(0x4, allocated=True, metadata_valid=True, references=[ref])

    assert state == DescriptorState.ALLOCATED_REFERENCED
    assert reasons


def test_classify_descriptor_allocated_orphan() -> None:
    state, reasons = classify_descriptor(0x4, allocated=True, metadata_valid=True, references=[])

    assert state == DescriptorState.ALLOCATED_ORPHAN
    assert reasons


def test_classify_descriptor_unallocated_residual() -> None:
    state, reasons = classify_descriptor(0x4, allocated=False, metadata_valid=True, references=[])

    assert state == DescriptorState.UNALLOCATED_RESIDUAL
    assert reasons


def test_classify_descriptor_reused_address() -> None:
    # The directory entry keeps the generation of the previous occupant, while the free slot holds newer metadata.
    stale = _reference(0x4, generation=2, slot_generation=6)
    state, reasons = classify_descriptor(0x4, allocated=False, metadata_valid=True, references=[stale])

    assert state == DescriptorState.REUSED_ADDRESS
    assert reasons


def test_classify_descriptor_unknown_allocated_unparseable() -> None:
    state, reasons = classify_descriptor(0x4, allocated=True, metadata_valid=False, references=[])

    assert state == DescriptorState.UNKNOWN
    assert reasons


def test_classify_descriptor_contradictory_free_referenced() -> None:
    ref = _reference(0x4, generation=9)
    state, reasons = classify_descriptor(0x4, allocated=False, metadata_valid=False, references=[ref])

    assert state == DescriptorState.CONTRADICTORY
    assert reasons


def test_classify_descriptor_generation_mismatch_is_stale() -> None:
    current = _reference(0x4, generation=3, slot_generation=3, name="current")
    stale = _reference(0x4, generation=2, slot_generation=3, name="old")
    state, _ = classify_descriptor(
        0x4,
        allocated=True,
        metadata_valid=True,
        references=[current, stale],
    )

    assert state == DescriptorState.ALLOCATED_REFERENCED


def _metadata_buffer(fs: vmfs.VMFS, address: int, generation: int, type: FS3_DescriptorType) -> bytes:
    metadata = c_vmfs.FS3_FileMetadata()
    metadata.signature = c_vmfs.FS3_FDMD_SIGNATURE if fs.is_vmfs6 else 0
    metadata.generation = generation
    metadata.type = type
    metadata.descAddr = address
    metadata.linkCount = 0

    metadata_buf = metadata.dumps()
    buf = bytearray(fs._fd_size)
    buf[fs._fd_meta_offset : fs._fd_meta_offset + len(metadata_buf)] = metadata_buf
    return bytes(buf)


def _slot(address: int, *, allocated: bool) -> ResourceSlot:
    cluster, resource = FileDescriptorAddr.parse(address)
    return ResourceSlot(address=address, cluster=cluster, resource=resource, allocated=allocated)


# Slots live in a high, otherwise unused cluster so they cannot collide with real image slots.
REACHABLE_ADDR = FileDescriptorAddr.make(900, 1)
ORPHAN_ADDR = FileDescriptorAddr.make(900, 2)
RESIDUAL_ADDR = FileDescriptorAddr.make(900, 3)
REUSED_ADDR = FileDescriptorAddr.make(900, 4)
UNKNOWN_ADDR = FileDescriptorAddr.make(900, 5)
CONTRADICTION_ADDR = FileDescriptorAddr.make(900, 6)

SYNTHETIC_SLOTS = {
    REACHABLE_ADDR: (True, 3, FS3_DescriptorType.REGFILE),
    ORPHAN_ADDR: (True, 4, FS3_DescriptorType.REGFILE),
    RESIDUAL_ADDR: (False, 5, FS3_DescriptorType.REGFILE),
    # Slot holds generation 6 metadata, while the directory entry still references generation 1 of the old occupant.
    REUSED_ADDR: (False, 6, FS3_DescriptorType.REGFILE),
    UNKNOWN_ADDR: (True, None, FS3_DescriptorType.REGFILE),
    CONTRADICTION_ADDR: (False, None, FS3_DescriptorType.REGFILE),
}


def _patch_synthetic_environment(fs: vmfs.VMFS, monkeypatch: pytest.MonkeyPatch) -> None:
    fd_resource = fs.resources.FD

    real_iter_slots = fd_resource.iter_slots

    def patched_iter_slots() -> Iterator[ResourceSlot]:
        yield from real_iter_slots()
        for address, (allocated, _, _) in SYNTHETIC_SLOTS.items():
            yield _slot(address, allocated=allocated)

    real_read = fd_resource.read

    def patched_read(address: int) -> bytes:
        if address in SYNTHETIC_SLOTS:
            _, generation, type = SYNTHETIC_SLOTS[address]
            if generation is None:
                return b"\x00" * fs._fd_size
            return _metadata_buffer(fs, address, generation, type)
        return real_read(address)

    monkeypatch.setattr(fd_resource, "iter_slots", patched_iter_slots)
    monkeypatch.setattr(fd_resource, "read", patched_read)

    synthetic_references = {
        REACHABLE_ADDR: [_reference(REACHABLE_ADDR, generation=3, name="reachable")],
        REUSED_ADDR: [_reference(REUSED_ADDR, generation=1, name="stale-name")],
        CONTRADICTION_ADDR: [_reference(CONTRADICTION_ADDR, generation=7, name="contradictory")],
    }
    monkeypatch.setattr(fs, "collect_descriptor_references", lambda: synthetic_references)


@pytest.mark.parametrize("fixture_name", ["vmfs5", "vmfs6"])
def test_enumerate_descriptor_candidates_states(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    fixture_name: str,
) -> None:
    fs = request.getfixturevalue(fixture_name)
    _patch_synthetic_environment(fs, monkeypatch)

    candidates = {c.address: c for c in fs.enumerate_descriptor_candidates()}

    reachable = candidates[REACHABLE_ADDR]
    assert reachable.state == DescriptorState.ALLOCATED_REFERENCED
    assert reachable.allocated and reachable.metadata_valid
    assert reachable.generation == 3
    assert reachable.descriptor is not None
    assert reachable.current_references and reachable.current_references[0].name == "reachable"

    orphan = candidates[ORPHAN_ADDR]
    assert orphan.state == DescriptorState.ALLOCATED_ORPHAN
    assert orphan.allocated and orphan.metadata_valid and not orphan.references
    assert orphan.descriptor is not None

    residual = candidates[RESIDUAL_ADDR]
    assert residual.state == DescriptorState.UNALLOCATED_RESIDUAL
    assert not residual.allocated and residual.metadata_valid
    assert residual.generation == 5 and residual.references == []

    reused = candidates[REUSED_ADDR]
    assert reused.state == DescriptorState.REUSED_ADDRESS
    assert not reused.allocated and reused.metadata_valid
    assert reused.generation == 6
    assert not reused.current_references
    stale = reused.stale_references
    assert len(stale) == 1 and stale[0].name == "stale-name" and stale[0].generation == 1

    unknown = candidates[UNKNOWN_ADDR]
    assert unknown.state == DescriptorState.UNKNOWN
    assert unknown.allocated and not unknown.metadata_valid and unknown.generation is None
    assert unknown.descriptor is None

    contradiction = candidates[CONTRADICTION_ADDR]
    assert contradiction.state == DescriptorState.CONTRADICTORY
    assert not contradiction.allocated and not contradiction.metadata_valid
    assert contradiction.references


@pytest.mark.parametrize("fixture_name", ["vmfs5", "vmfs6"])
def test_enumeration_preserves_directory_listing(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    fixture_name: str,
) -> None:
    fs = request.getfixturevalue(fixture_name)

    def listing_snapshot() -> dict[str, int]:
        return {name: entry.address for name, entry in fs.root.listdir().items()}

    before = listing_snapshot()

    _patch_synthetic_environment(fs, monkeypatch)
    fs.enumerate_descriptor_candidates()

    assert listing_snapshot() == before


@pytest.mark.parametrize("fixture_name", ["vmfs5", "vmfs6"])
def test_healthy_image_has_no_residuals(request: pytest.FixtureRequest, fixture_name: str) -> None:
    fs = request.getfixturevalue(fixture_name)
    candidates = fs.enumerate_descriptor_candidates()

    residual_states = {
        DescriptorState.ALLOCATED_ORPHAN,
        DescriptorState.UNALLOCATED_RESIDUAL,
        DescriptorState.REUSED_ADDRESS,
        DescriptorState.CONTRADICTORY,
    }
    assert not any(c.state in residual_states for c in candidates)
    assert all(c.state in (DescriptorState.ALLOCATED_REFERENCED, DescriptorState.UNKNOWN) for c in candidates)


def test_real_unallocated_residuals_in_zero6(vmfs6_zero: vmfs.VMFS) -> None:
    # The zero6 image contains free descriptor slots that still hold parseable metadata from removed objects.
    candidates = vmfs6_zero.enumerate_descriptor_candidates()
    residuals = [c for c in candidates if c.state == DescriptorState.UNALLOCATED_RESIDUAL]

    assert residuals
    for candidate in residuals:
        assert not candidate.allocated
        assert candidate.metadata_valid
        assert candidate.generation is not None
        assert candidate.descriptor is not None
        assert not candidate.references
        assert candidate.reasons


@pytest.mark.parametrize("fixture_name", ["vmfs5", "vmfs6"])
def test_iter_slots_bounded_by_resource_count(request: pytest.FixtureRequest, fixture_name: str) -> None:
    fs = request.getfixturevalue(fixture_name)
    slots = list(fs.resources.FD.iter_slots())

    assert len(slots) == fs.resources.FD.num_resources
    assert all(isinstance(slot, ResourceSlot) for slot in slots)
    # In the healthy images every allocated slot is reachable through a directory.
    references = fs.collect_descriptor_references()
    allocated = [slot for slot in slots if slot.allocated]
    assert allocated
    assert all(slot.address in references for slot in allocated)
