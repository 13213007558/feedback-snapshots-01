from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from dissect.vmfs.address import FileDescriptorAddr, address_fmt
from dissect.vmfs.c_vmfs import (
    FS3_AddrType,
    FS3_DescriptorType,
    FS6_DirBlockType,
    c_vmfs,
)
from dissect.vmfs.descriptor import _iter_dir_blocks
from dissect.vmfs.exception import NotADirectoryError, VolumeNotAvailableError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.vmfs.c_vmfs import FS3_DirEntry, FS6_DirEntry
    from dissect.vmfs.descriptor import FileDescriptor
    from dissect.vmfs.vmfs import VMFS

# Raised while reading directory contents that live in blocks unavailable without a volume handle.
# Imported lazily by callers that only want the allocation bitmap based enumeration.
_DIRECTORY_READ_ERRORS = (NotADirectoryError, ValueError, KeyError, EOFError, VolumeNotAvailableError)


class ResidualState(str, Enum):
    """Classification of a file descriptor slot based on allocation state and directory references.

    The states intentionally describe only what can be observed on disk:

    - :attr:`ALLOCATED_REACHABLE`: the slot is allocated and referenced by a directory entry whose
      generation matches the metadata in the slot.
    - :attr:`RESIDUAL_UNALLOCATED`: the slot is marked free by the allocation bitmap but still
      contains parsable descriptor metadata. It is not a current file, nor proof of a recent deletion.
    - :attr:`ADDRESS_REUSED`: the slot is allocated and holds newer metadata, while a directory entry
      still points at the same address with an older generation. The stale name must not be combined
      with the new contents.
    - :attr:`UNKNOWN`: the observed state is contradictory or cannot be classified, for example a
      referenced slot that is marked free, or unparsable metadata.
    """

    ALLOCATED_REACHABLE = "allocated_reachable"
    RESIDUAL_UNALLOCATED = "residual_unallocated"
    ADDRESS_REUSED = "address_reused"
    UNKNOWN = "unknown"


@dataclass
class DirectoryReference:
    """A single reference to a file descriptor, as observed in a directory.

    A reference only establishes that a directory entry points at an address. Whether the reference is
    current depends on its generation matching the metadata generation in the referenced slot.

    Args:
        path: The path of the directory containing the entry.
        name: The name of the directory entry.
        address: The file descriptor address stored in the entry.
        generation: The generation stored alongside the directory entry.
        generation_match: Whether the entry generation matches the metadata of the referenced slot.
            ``None`` when the slot has no parsable metadata to compare against.
    """

    path: str
    name: str
    address: int
    generation: int
    generation_match: bool | None = None

    def __repr__(self) -> str:
        return (
            f"<DirectoryReference {self.path.rstrip('/')}/{self.name!r} "
            f"address={address_fmt(self.address)} gen={self.generation} match={self.generation_match}>"
        )


@dataclass
class DescriptorRecord:
    """The on-disk facts observed for a single file descriptor slot.

    This object never combines a stale directory name with newer slot contents: the slot metadata and
    the directory references are kept as separate, individually attributed fields.

    Args:
        address: The file descriptor address of the slot.
        cluster: The cluster part of the address.
        resource: The resource part of the address.
        allocated: Allocation state according to the resource allocation bitmap.
        parsable: Whether the slot contains parsable descriptor metadata.
        generation: The metadata generation, or ``None`` when not parsable.
        descriptor_type: The metadata descriptor type, or ``None`` when not parsable.
        links: The metadata link count, or ``None`` when not parsable.
        signature_ok: Whether the descriptor metadata signature is valid for this filesystem.
        address_consistent: Whether the metadata ``descAddr`` matches the slot address. ``None`` when
            not parsable.
        references: Directory entries that point at this slot's address.
    """

    address: int
    cluster: int
    resource: int
    allocated: bool
    parsable: bool
    generation: int | None = None
    descriptor_type: FS3_DescriptorType | None = None
    links: int | None = None
    signature_ok: bool = False
    address_consistent: bool | None = None
    references: list[DirectoryReference] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"<DescriptorRecord address={address_fmt(self.address)} allocated={self.allocated} "
            f"parsable={self.parsable} gen={self.generation} references={len(self.references)}>"
        )


@dataclass
class ResidualCandidate:
    """A file descriptor slot worth reporting during residual enumeration.

    Args:
        state: The classification of the slot.
        record: The observed on-disk facts for the slot.
        reasons: Human readable explanations for why the slot is listed.
        active_names: Directory names whose generation matches the current slot metadata. These are
            the only names that may be associated with the current slot contents.
        stale_names: Directory names whose generation does not match the current slot metadata. These
            names describe a previous occupant and must not be associated with the current contents.
    """

    state: ResidualState
    record: DescriptorRecord
    reasons: list[str] = field(default_factory=list)
    active_names: list[DirectoryReference] = field(default_factory=list)
    stale_names: list[DirectoryReference] = field(default_factory=list)

    @property
    def address(self) -> int:
        return self.record.address

    @property
    def generation(self) -> int | None:
        return self.record.generation

    def __repr__(self) -> str:
        return f"<ResidualCandidate state={self.state} address={address_fmt(self.address)}>"


def iter_directory_references(vmfs: VMFS) -> Iterator[DirectoryReference]:
    """Walk every readable directory and yield directory entries as descriptor references.

    The walk is read-only and reads the raw directory entry structures rather than going through the
    regular directory lookup path, so residual enumeration cannot influence a normal directory
    listing. A directory that cannot be parsed is skipped instead of aborting the enumeration.
    """
    pending: list[tuple[FileDescriptor, str]] = [(vmfs.root, "/")]
    visited: set[int] = set()

    while pending:
        directory, path = pending.pop()
        if directory.address in visited:
            continue
        visited.add(directory.address)

        try:
            raw_entries = list(_iter_raw_dir_entries(directory))
        except _DIRECTORY_READ_ERRORS:
            # A directory stored in blocks that are not available (for example when only system
            # files are supplied) is skipped; slot enumeration still works from the allocation bitmap.
            continue

        for raw_entry in raw_entries:
            address = _entry_address(raw_entry)
            if address & 0b111 != FS3_AddrType.FILE_DESCRIPTOR:
                continue

            name = raw_entry.name.decode().strip("\x00")
            yield DirectoryReference(
                path=path,
                name=name,
                address=address,
                generation=raw_entry.generation,
            )

            if name not in (".", ".."):
                child = _safe_file_descriptor(vmfs, address)
                if child is not None and child.is_dir():
                    pending.append((child, path.rstrip("/") + "/" + name))


def _entry_address(entry: FS3_DirEntry | FS6_DirEntry) -> int:
    # VMFS5 names the field descAddr, VMFS6 renamed it to address.
    return entry.descAddr if hasattr(entry, "descAddr") else entry.address


def collect_directory_references(vmfs: VMFS) -> dict[int, list[DirectoryReference]]:
    """Group all directory references by their target file descriptor address."""
    references: dict[int, list[DirectoryReference]] = {}
    for reference in iter_directory_references(vmfs):
        references.setdefault(reference.address, []).append(reference)
    return references


def iter_descriptor_records(
    vmfs: VMFS, references: dict[int, list[DirectoryReference]] | None = None
) -> Iterator[DescriptorRecord]:
    """Enumerate every file descriptor slot in the ``.fdc.sf`` resource as a read-only record."""
    if references is None:
        references = collect_directory_references(vmfs)

    fdc = vmfs.resources.FD
    for cluster, resource, allocated in fdc.iter_slots():
        address = FileDescriptorAddr.make(cluster, resource)
        yield _read_descriptor_record(vmfs, address, allocated, references.get(address, []))


def iter_residual_candidates(vmfs: VMFS) -> Iterator[ResidualCandidate]:
    """Enumerate residual file descriptor candidates without modifying the filesystem.

    The enumeration combines two independent sources of information:

    - the allocation bitmap of the file descriptor resource, which says whether a slot is allocated;
    - directory entries, which say which names point at a slot and with which generation.

    Every candidate carries the evidence for its classification, so callers can decide how to present
    it. No deletion timestamp is inferred, and stale names are never merged with reused slot contents.
    """
    references = collect_directory_references(vmfs)
    for record in iter_descriptor_records(vmfs, references):
        candidate = _classify_record(record)
        if candidate is not None:
            yield candidate


def _iter_raw_dir_entries(descriptor: FileDescriptor) -> Iterator[FS3_DirEntry | FS6_DirEntry]:
    """Yield the raw, on-disk directory entries of a directory.

    This mirrors the regular directory iteration but bypasses name lookup and keeps entries that the
    filesystem would otherwise consider stale, which is exactly what residual enumeration needs.
    """
    if descriptor.vmfs.is_vmfs5:
        yield from _iter_raw_dir_entries_vmfs5(descriptor)
    else:
        yield from _iter_raw_dir_entries_vmfs6(descriptor)


def _iter_raw_dir_entries_vmfs5(descriptor: FileDescriptor) -> Iterator[FS3_DirEntry]:
    with descriptor.open() as buf:
        for _ in range(descriptor.size // len(c_vmfs.FS3_DirEntry)):
            entry = c_vmfs.FS3_DirEntry(buf)
            if entry.descAddr:
                yield entry


def _iter_raw_dir_entries_vmfs6(descriptor: FileDescriptor) -> Iterator[FS6_DirEntry]:
    block_size = descriptor.vmfs.md_alignment
    with descriptor.open() as fh:
        header = c_vmfs.FS6_DirHeader(fh)
        if header.version not in (c_vmfs.FS6_DIR_HEADER_VERSION, c_vmfs.FS6_DIR_HEADER_DEBUG_VERSION):
            return

        if header.selfEntry.address:
            yield header.selfEntry
        if header.parentEntry.address:
            yield header.parentEntry

        for entry_type, block in _iter_dir_blocks(
            fh, header.allocationMapBlocks[: header.numAllocationMapBlocks], block_size
        ):
            if entry_type != FS6_DirBlockType.DIRENT:
                continue

            fh.seek(c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE + (block * block_size))
            block_buf = memoryview(fh.read(block_size))
            block_header = c_vmfs.FS6_DirBlockHeader(block_buf)
            block_entries = block_buf[len(c_vmfs.FS6_DirBlockHeader) :]

            for index in range(block_header.totalSlots):
                # A cleared bit marks an allocated directory entry slot.
                if (block_header.bitmap[index >> 3] >> (index & 7)) & 1 == 0:
                    yield c_vmfs.FS6_DirEntry(block_entries[index * len(c_vmfs.FS6_DirEntry) :])


def _read_descriptor_record(
    vmfs: VMFS, address: int, allocated: bool, slot_references: Sequence[DirectoryReference]
) -> DescriptorRecord:
    cluster, resource = FileDescriptorAddr.parse(address)
    record = DescriptorRecord(
        address=address,
        cluster=cluster,
        resource=resource,
        allocated=allocated,
        parsable=False,
        references=list(slot_references),
    )

    try:
        descriptor = vmfs.file_descriptor(address)
        metadata = descriptor.metadata
    except (ValueError, KeyError, EOFError):
        _mark_reference_match(record.references, None)
        return record

    record.parsable = True
    record.generation = metadata.generation
    record.descriptor_type = metadata.type
    record.links = metadata.linkCount
    record.signature_ok = _signature_valid(vmfs, metadata.signature)
    record.address_consistent = metadata.descAddr == address

    for reference in record.references:
        reference.generation_match = reference.generation == record.generation

    return record


def _classify_record(record: DescriptorRecord) -> ResidualCandidate | None:
    active = [ref for ref in record.references if ref.generation_match is True]
    stale = [ref for ref in record.references if ref.generation_match is False]
    unverifiable = [ref for ref in record.references if ref.generation_match is None]

    reasons: list[str] = []

    if not record.parsable:
        if not record.references:
            return None
        reasons.append("slot metadata cannot be parsed but a directory entry references its address")
        return ResidualCandidate(ResidualState.UNKNOWN, record, reasons, active, stale + unverifiable)

    metadata_coherent = record.signature_ok and record.address_consistent is not False
    if record.address_consistent is False:
        reasons.append("metadata descAddr does not match the slot address")
    if not record.signature_ok:
        reasons.append("descriptor metadata signature is not valid for this filesystem")

    if record.allocated:
        if active:
            reasons.append(
                "slot is allocated and referenced by a directory entry with matching generation"
            )
            if metadata_coherent:
                return ResidualCandidate(ResidualState.ALLOCATED_REACHABLE, record, reasons, active, stale)

            # Allocated and referenced, but the metadata does not describe this slot.
            reasons.append("allocated slot metadata is internally inconsistent")
            return ResidualCandidate(ResidualState.UNKNOWN, record, reasons, active, stale + unverifiable)

        if stale:
            reasons.append(
                "slot is allocated with newer metadata while a directory entry references an older generation"
            )
            return ResidualCandidate(ResidualState.ADDRESS_REUSED, record, reasons, active, stale)

        if not record.references:
            # Allocated but unreferenced: normal for system files and open-but-unlinked files.
            # It is neither a confirmed residual nor a contradiction, so it is not reported.
            return None

        reasons.append(
            "allocated slot is only referenced by entries whose generation cannot be confirmed"
        )
        return ResidualCandidate(ResidualState.UNKNOWN, record, reasons, active, stale + unverifiable)

    # The slot is marked free by the allocation bitmap.
    if record.references:
        reasons.append("slot is marked free by the allocation bitmap but is referenced by a directory entry")
        if active and metadata_coherent:
            reasons.append("the referencing directory entry generation matches the metadata left in the slot")
            return ResidualCandidate(
                ResidualState.RESIDUAL_UNALLOCATED, record, reasons, active, stale + unverifiable
            )

        if not metadata_coherent:
            reasons.append("the metadata left in the slot does not consistently describe this address")
        if stale:
            reasons.append("the referencing directory entry generation is older than the metadata in the slot")
        return ResidualCandidate(ResidualState.UNKNOWN, record, reasons, active, stale + unverifiable)

    if record.descriptor_type == FS3_DescriptorType.INVALID and record.generation == 0:
        # A zeroed or freshly initialized free slot carries no residual descriptor to report.
        return None

    if not metadata_coherent:
        # A free slot with parsable but internally inconsistent bytes is not enough to claim a
        # residual descriptor; report it as unknown instead of attaching a possibly invented identity.
        reasons.append(
            "free slot contains parsable bytes but the metadata does not consistently describe this address"
        )
        return ResidualCandidate(ResidualState.UNKNOWN, record, reasons, active, stale)

    reasons.append(
        "slot is marked free by the allocation bitmap but still contains parsable descriptor metadata"
    )
    return ResidualCandidate(ResidualState.RESIDUAL_UNALLOCATED, record, reasons)


def _signature_valid(vmfs: VMFS, signature: int) -> bool:
    # VMFS5 does not place the fdmd signature in the file metadata; only VMFS6 validates it.
    return vmfs.is_vmfs5 or signature == c_vmfs.FS3_FDMD_SIGNATURE


def _mark_reference_match(references: Sequence[DirectoryReference], match: bool | None) -> None:
    for reference in references:
        reference.generation_match = match


def _safe_file_descriptor(vmfs: VMFS, address: int) -> FileDescriptor | None:
    try:
        return vmfs.file_descriptor(address)
    except (TypeError, ValueError, KeyError, EOFError):
        return None
