from __future__ import annotations

import gzip
import struct
from bisect import bisect_right
from collections import Counter
from dataclasses import replace

import pytest

from dissect.vmfs import VMFS, ResidualState, lvm, vmfs
from dissect.vmfs.address import FileDescriptorAddr
from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.residual import (
    DescriptorRecord,
    DirectoryReference,
    _classify_record,
)
from dissect.vmfs.resource import ResourceFile
from tests.conftest import absolute_path


class MutableVolumeFile:
    """File-like object backed by a mutable bytearray.

    A regular ``io.BytesIO`` copies the bytearray into an immutable internal buffer, which would hide
    our mutations from newly opened LVM views. This thin wrapper keeps the bytearray shared instead.
    """

    def __init__(self, buf: bytearray):
        self.buf = buf
        self.pos = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 1:
            offset += self.pos
        elif whence == 2:
            offset += len(self.buf)
        self.pos = offset
        return offset

    def read(self, length: int = -1) -> bytes:
        end = len(self.buf) if length is None or length < 0 else min(self.pos + length, len(self.buf))
        data = bytes(self.buf[self.pos : end])
        self.pos = end
        return data

    def tell(self) -> int:
        return self.pos


class ImageMutator:
    """Read/write helper that translates VMFS logical offsets to physical device offsets."""

    def __init__(self, fs: VMFS, buf: bytearray, runs: list[tuple]):
        self.fs = fs
        self.buf = buf
        self._lookup = [run[0] for run in runs]
        self.runs = runs

    def physical(self, logical: int) -> int:
        index = bisect_right(self._lookup, logical) - 1
        logical_start, physical_start, run_length, _device = self.runs[index]
        assert logical - logical_start < run_length
        return physical_start + (logical - logical_start)

    @property
    def fdc(self) -> ResourceFile:
        return self.fs.resources.FD

    def slot_logical(self, cluster: int, resource: int) -> int:
        address = FileDescriptorAddr.make(cluster, resource)
        file_offset = self.fdc._resource_offset(cluster, resource)
        return self.fdc.fd._resolve_offset(file_offset)[0], address

    def set_bitmap(self, cluster: int, resource: int, free: bool) -> None:
        bitmap_offset = (
            self.fdc._cluster_header_offset(cluster)
            + self._cluster_meta_block_size()
            + self._bitmap_field_offset()
            + (resource >> 3)
        )
        physical = self.physical(self.fdc.fd._resolve_offset(bitmap_offset)[0])
        bit = resource & 7
        current = self.buf[physical]
        self.buf[physical] = (
            (current | (1 << bit)) if free else (current & ~(1 << bit) & 0xFF)
        )

    def set_metadata(self, address: int, field: str, value: int) -> None:
        cluster, resource = FileDescriptorAddr.parse(address)
        logical, _ = self.slot_logical(cluster, resource)
        field_def = c_vmfs.FS3_FileMetadata.fields[field]
        physical = self.physical(logical) + self.fs._fd_meta_offset + field_def.offset
        struct.pack_into("<Q" if field_def.type.size == 8 else "<I", self.buf, physical, value)

    def copy_slot(self, source: int, destination: int) -> None:
        source_cluster, source_resource = FileDescriptorAddr.parse(source)
        destination_cluster, destination_resource = FileDescriptorAddr.parse(destination)
        source_logical, _ = self.slot_logical(source_cluster, source_resource)
        destination_logical, _ = self.slot_logical(destination_cluster, destination_resource)
        size = self.fs._fd_size
        source_physical = self.physical(source_logical)
        destination_physical = self.physical(destination_logical)
        self.buf[destination_physical : destination_physical + size] = self.buf[
            source_physical : source_physical + size
        ]

    def append_root_entry(self, address: int, generation: int, name: str) -> None:
        root = self.fs.root
        entry_size = len(c_vmfs.FS3_DirEntry)
        entry_count = root.size // entry_size
        self.set_metadata(c_vmfs.rootDirDescAddr, "fileLength", (entry_count + 1) * entry_size)

        physical = self.physical(root._resolve_offset(0)[0]) + entry_count * entry_size
        struct.pack_into("<I", self.buf, physical + 0, c_vmfs.FS3_DescriptorType.REGFILE)
        struct.pack_into("<I", self.buf, physical + 4, address)
        struct.pack_into("<I", self.buf, physical + 8, generation)
        encoded = name.encode()
        self.buf[physical + 12 : physical + 12 + len(encoded)] = encoded

    def _cluster_meta_block_size(self) -> int:
        return self.fdc._cluster_header_size // 2

    def _bitmap_field_offset(self) -> int:
        if self.fs.is_vmfs5:
            return c_vmfs.FS3_ResourceClusterMD.fields["bitmap"].offset
        return 0x80


def load_mutated_image(path: str) -> tuple[bytearray, ImageMutator, MutableVolumeFile]:
    raw = bytearray(gzip.open(absolute_path(path), "rb").read())
    device = MutableVolumeFile(raw)
    volume = lvm.LVM(device).volumes[0]
    fs = vmfs.VMFS(volume.open())
    return raw, ImageMutator(fs, raw, volume.dataruns()), device


def reopen(raw: bytearray) -> VMFS:
    return vmfs.VMFS(lvm.LVM(MutableVolumeFile(raw)).volumes[0].open())


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("_data/vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("_data/vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_healthy_image_only_lists_reachable_descriptors(path: str) -> None:
    raw, _mutator, _device = load_mutated_image(path)
    fs = reopen(raw)

    candidates = list(fs.residual_candidates())
    assert Counter(candidate.state for candidate in candidates) == Counter(
        {ResidualState.ALLOCATED_REACHABLE: len(candidates)}
    )

    referenced = set(fs.directory_references())
    assert {candidate.address for candidate in candidates} == referenced

    for candidate in candidates:
        assert candidate.record.allocated
        assert candidate.record.parsable
        assert candidate.active_names
        assert not candidate.stale_names
        assert all(reference.generation_match for reference in candidate.active_names)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("_data/vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("_data/vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_descriptor_records_cover_every_slot(path: str) -> None:
    raw, _mutator, _device = load_mutated_image(path)
    fs = reopen(raw)

    records = list(fs.descriptor_records())
    fdc = fs.resources.FD
    expected_slots = sum(1 for _ in fdc.iter_slots())

    assert len(records) == expected_slots
    assert {FileDescriptorAddr.make(record.cluster, record.resource) for record in records} == {
        FileDescriptorAddr.make(cluster, resource)
        for cluster, resource, _allocated in fdc.iter_slots()
    }


def test_unallocated_slot_with_parsable_metadata_is_residual() -> None:
    raw, mutator, _device = load_mutated_image("_data/vmfs/vmfs5.bin.gz")
    fs = mutator.fs
    symlink = fs.get("symlink")
    symlink_address = symlink.address
    symlink_generation = symlink.metadata.generation

    # Free the descriptor slot but leave the directory entry and the slot metadata intact.
    cluster, resource = FileDescriptorAddr.parse(symlink_address)
    mutator.set_bitmap(cluster, resource, free=True)

    fs = reopen(raw)
    candidate = {entry.address: entry for entry in fs.residual_candidates()}[symlink_address]

    assert candidate.state == ResidualState.RESIDUAL_UNALLOCATED
    assert candidate.record.allocated is False
    assert candidate.record.parsable is True
    assert candidate.generation == symlink_generation
    assert candidate.record.descriptor_type == c_vmfs.FS3_DescriptorType.SYMLINK
    assert [reference.name for reference in candidate.active_names] == ["symlink"]
    assert not candidate.stale_names
    assert any("marked free" in reason for reason in candidate.reasons)


def test_reused_address_keeps_stale_name_separate_from_new_contents() -> None:
    raw, mutator, _device = load_mutated_image("_data/vmfs/vmfs5.bin.gz")
    fs = mutator.fs

    # Pick a currently empty slot and turn it into a freshly allocated regular file descriptor.
    reused_address = FileDescriptorAddr.make(1, 0)
    donor_address = fs.get("symlink").address
    mutator.copy_slot(donor_address, reused_address)
    mutator.set_metadata(reused_address, "descAddr", reused_address)
    mutator.set_metadata(reused_address, "generation", 42)
    mutator.set_metadata(reused_address, "type", c_vmfs.FS3_DescriptorType.REGFILE)
    mutator.set_metadata(reused_address, "linkCount", 1)
    reused_cluster, reused_resource = FileDescriptorAddr.parse(reused_address)
    mutator.set_bitmap(reused_cluster, reused_resource, free=False)

    # A directory entry still references the old occupant's generation at the same address.
    mutator.append_root_entry(reused_address, generation=1, name="stale-name")

    fs = reopen(raw)
    candidate = {entry.address: entry for entry in fs.residual_candidates()}[reused_address]

    assert candidate.state == ResidualState.ADDRESS_REUSED
    assert candidate.record.allocated is True
    assert candidate.generation == 42
    assert candidate.record.descriptor_type == c_vmfs.FS3_DescriptorType.REGFILE
    assert not candidate.active_names
    stale_evidence = [
        (reference.name, reference.generation, reference.generation_match)
        for reference in candidate.stale_names
    ]
    assert stale_evidence == [("stale-name", 1, False)]
    assert any("older generation" in reason for reason in candidate.reasons)

    # The stale entry remains raw directory evidence. On VMFS5 it can still be visible in a raw
    # directory listing, but resolving it must never associate the stale name with the new slot
    # generation: the residual enumeration keeps both pieces of evidence separate instead.
    assert candidate.record.generation != candidate.stale_names[0].generation
    assert fs.get(reused_address).metadata.generation == 42
    assert all(reference.generation_match is False for reference in candidate.stale_names)


def test_allocated_reachable_descriptor_is_listed_with_active_name() -> None:
    raw, _mutator, _device = load_mutated_image("_data/vmfs/vmfs5.bin.gz")
    fs = reopen(raw)

    small = fs.get("small")
    candidate = {entry.address: entry for entry in fs.residual_candidates()}[small.address]

    assert candidate.state == ResidualState.ALLOCATED_REACHABLE
    assert candidate.record.allocated is True
    assert candidate.generation == small.metadata.generation
    assert [reference.name for reference in candidate.active_names] == ["small"]
    assert not candidate.stale_names


def test_normal_directory_listing_is_not_affected_by_enumeration() -> None:
    raw, mutator, _device = load_mutated_image("_data/vmfs/vmfs5.bin.gz")
    fs = mutator.fs
    original_names = set(fs.root.listdir())

    symlink_address = fs.get("symlink").address
    cluster, resource = FileDescriptorAddr.parse(symlink_address)
    mutator.set_bitmap(cluster, resource, free=True)

    fs = reopen(raw)
    # Enumeration is read-only and repeated calls keep producing the same directory view.
    list(fs.residual_candidates())
    list(fs.descriptor_records())
    assert set(fs.root.listdir()) == original_names
    assert fs.get("symlink").address == symlink_address


def test_classify_unknown_contradictory_reference() -> None:
    record = DescriptorRecord(
        address=FileDescriptorAddr.make(2, 2),
        cluster=2,
        resource=2,
        allocated=False,
        parsable=True,
        generation=5,
        descriptor_type=c_vmfs.FS3_DescriptorType.REGFILE,
        links=1,
        signature_ok=True,
        address_consistent=True,
        references=[DirectoryReference("/", "broken", FileDescriptorAddr.make(2, 2), generation=2)],
    )
    record.references[0].generation_match = False

    candidate = _classify_record(record)

    assert candidate.state == ResidualState.UNKNOWN
    assert candidate.stale_names == record.references
    assert any("marked free" in reason for reason in candidate.reasons)


def test_unparsable_referenced_slot_is_unknown() -> None:
    record = DescriptorRecord(
        address=FileDescriptorAddr.make(3, 3),
        cluster=3,
        resource=3,
        allocated=False,
        parsable=False,
        references=[DirectoryReference("/", "ghost", FileDescriptorAddr.make(3, 3), generation=1)],
    )

    candidate = _classify_record(record)

    assert candidate.state == ResidualState.UNKNOWN
    assert candidate.record.references[0].generation_match is None
    assert any("cannot be parsed" in reason for reason in candidate.reasons)


def test_zeroed_free_slot_is_not_reported() -> None:
    record = DescriptorRecord(
        address=FileDescriptorAddr.make(4, 4),
        cluster=4,
        resource=4,
        allocated=False,
        parsable=True,
        generation=0,
        descriptor_type=c_vmfs.FS3_DescriptorType.INVALID,
        signature_ok=True,
        address_consistent=True,
    )

    assert _classify_record(record) is None


def test_allocated_unreferenced_slot_is_not_reported() -> None:
    record = DescriptorRecord(
        address=FileDescriptorAddr.make(5, 5),
        cluster=5,
        resource=5,
        allocated=True,
        parsable=True,
        generation=7,
        descriptor_type=c_vmfs.FS3_DescriptorType.REGFILE,
        links=0,
        signature_ok=True,
        address_consistent=True,
    )

    assert _classify_record(record) is None


def test_records_keep_address_and_generation_evidence() -> None:
    raw, _mutator, _device = load_mutated_image("_data/vmfs/vmfs6.bin.gz")
    fs = reopen(raw)
    record = next(fs.descriptor_records())

    assert FileDescriptorAddr.parse(record.address) == (record.cluster, record.resource)
    assert isinstance(record.allocated, bool)
    assert isinstance(record.parsable, bool)
    rebuilt = replace(record, references=list(record.references))
    assert rebuilt.address == record.address
    assert rebuilt.generation == record.generation


def test_enumeration_degrades_without_volume_handle() -> None:
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        donor = vmfs.VMFS(lvm.LVM(fh).volumes[0].open())
        fs = vmfs.VMFS(
            vh=donor.get(".vh.sf").open(),
            fdc=donor.get(".fdc.sf").open(),
            fbb=donor.get(".fbb.sf").open(),
            sbc=donor.get(".sbc.sf").open(),
            pbc=donor.get(".pbc.sf").open(),
            pb2=donor.get(".pb2.sf").open(),
        )

        # Directories stored in file blocks cannot be read, but this must not abort enumeration.
        assert fs.directory_references() == {}

        records = list(fs.descriptor_records())
        assert records
        assert sum(record.allocated for record in records) > 0
        assert all(
            FileDescriptorAddr.parse(record.address) == (record.cluster, record.resource) for record in records
        )

        # Without directory references nothing can be claimed reachable, so no candidate is invented.
        assert list(fs.residual_candidates()) == []
