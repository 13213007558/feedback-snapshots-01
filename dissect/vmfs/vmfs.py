# References:
# - /usr/lib/vmware/vmkmod/vmfs3
# - /bin/vmkfstools
# - /bin/voma
from __future__ import annotations

from functools import lru_cache
from typing import BinaryIO

from dissect.vmfs.address import FileDescriptorAddr, address_fmt, address_type
from dissect.vmfs.c_vmfs import (
    FS3_AddrType,
    FS3_Config,
    FS3_DescriptorType,
    FS3_ResourceTypeID,
    c_vmfs,
)
from dissect.vmfs.descriptor import (
    DescriptorCandidate,
    DescriptorReference,
    DirEntry,
    FileDescriptor,
    FileDescriptor5,
    FileDescriptor6,
    classify_descriptor,
)
from dissect.vmfs.exception import (
    FileNotFoundError,
    InvalidHeader,
)
from dissect.vmfs.resource import ResourceManager
from dissect.vmfs.util import bsf, vmfs_uuid


class VMFS:
    """VMFS filesystem implementation.

    The VMFS filesystem is a complex clustered filesystem used by VMware ESXi. This implementation
    aims to provide a read-only interface for reading VMFS filesystems, supporting VMFS5 and VMFS6.
    Locks and such are not implemented, so feel free to read any file to your heart's content.

    Within ESXi, the VMFS filesystem is tightly coupled with the VMFS LVM (Logical Volume Manager). You can have a
    raw LVM if you want, but VMFS must be placed on an LVM volume. The LVM is responsible for managing the physical
    storage across one or more physical disks (devices), while the VMFS filesystem is responsible for managing the
    files and directories. Both are multi-host aware, meaning that multiple ESXi hosts can access and claim locks on
    individual parts of both the LVM and the filesystem.

    Within our implementation, we decouple the LVM and VMFS filesystem. The LVM implementation behaves like any other
    volume manager, providing raw volume access to any underlying storage. The VMFS filesystem implementation can be
    used on any file-like object that contains a VMFS filesystem, not technically requiring it to be a volume managed by
    the LVM. However, in practice, you will most often use the LVM implementation to access the VMFS filesystem.
    Unless you imaged a VMFS filesystem directly from ``/dev/lvm``, for some reason 🤷‍♂️.

    This implementation can be initialized with a file-like object of a VMFS volume, or from individual system files.
    When initialized from a volume, a VMFS :class:`~dissect.vmfs.lvm.LVM` volume must already have been loaded.
    When initialized from individual system files, you can inspect most of the filesystem (including browing
    most directories), but you won't be able to access most file data directly.

    Note:
        A lot of the math consists of bitwise shifts and masks, which translate to modulo or multiplication operations.
        For the sake of "maintainability" in relation to the original "code", we keep this as bitwise masks, at the
        sacrifice of some human readability. Comments explaining as such are placed where appropriate.

    Args:
        volume: A file-like object of a VMFS volume.
        vh: An optional file-like object of the VMFS volume header file system file (``.vh.sf``).
        fdc: An optional file-like object of the file descriptor cluster system file (``.fdc.sf``).
        fbb: An optional file-like object of the file block system file (``.fbb.sf``).
        sbc: An optional file-like object of the sub-block cluster system file (``.sbc.sf``).
        pbc: An optional file-like object of the pointer block cluster system file (``.pbc.sf``).
        pb2: An optional file-like object of the pointer block 2 system file (``.pb2.sf``).
        jbc: An optional file-like object of the journal block cluster system file (``.jbc.sf``).
    """

    def __init__(
        self,
        volume: BinaryIO | None = None,
        vh: BinaryIO | None = None,
        fdc: BinaryIO | None = None,
        fbb: BinaryIO | None = None,
        sbc: BinaryIO | None = None,
        pbc: BinaryIO | None = None,
        pb2: BinaryIO | None = None,
        jbc: BinaryIO | None = None,
    ):
        self.fh = volume

        if volume:
            vh_fh = volume
        elif vh:
            vh_fh = vh
        else:
            raise ValueError("Need either volume or vh")

        vh_fh.seek(c_vmfs.FS3_FS_HEADER_OFFSET)
        self.descriptor = c_vmfs.FS3_Descriptor(vh_fh)
        if self.descriptor.magic not in (c_vmfs.VMFS_MAGIC_NUMBER, c_vmfs.VMFSL_MAGIC_NUMBER):
            raise InvalidHeader("Invalid FS3 descriptor")

        self.md_alignment = self.descriptor.mdAlignment
        self.file_block_size = self.descriptor.fileBlockSize
        self.sub_block_size = self.descriptor.subBlockSize
        # Shifting by block_offset_shift is the same as multiplying by file_block_size
        self._file_block_size_shift = bsf(self.file_block_size)
        self._sub_block_size_shift = bsf(self.sub_block_size)

        # VMFS6 = (24, 82)
        # VMFS5 = (14, 81)
        self.major_version = self.descriptor.majorVersion
        self.minor_version = self.descriptor.minorVersion

        self.uuid = vmfs_uuid(self.descriptor.uuid)
        self.label = self.descriptor.fsLabel.split(b"\x00")[0].decode("utf-8")

        # References: Vol3OpenStage1VMFS5 and Vol3OpenStage1VMFS6
        if self.is_vmfs5:
            # lockBlock (512), metaBlock (512), data (1024)
            self._fd_size = 2048
            # Size of the data portion
            # This can be used for the data pointer array, resident data or RDM mappings
            self._fd_data_size = 1024
            # Size of the data pointer array, in bytes
            # On VMFS5, the data pointer array and (resident) data are stored in the same place
            # So their size and location are the same
            self._fd_data_addrs_size = 1024

            # Offset to the file descriptor metadata (offsetof(FS3_FileDescriptor, metaBlock))
            self._fd_meta_offset = 512
            # Offset to the data (offsetof(FS3_FileDescriptor, data))
            self._fd_data_offset = 1024
            # Offset to the data pointer array (offsetof(FS3_FileDescriptor, dataAddrs))
            self._fd_data_addrs_offset = 1024

            # Data addresses/pointers are uint32
            self._fd_max_data_addrs = 256

            self._ptr_block_page_size = 0x1000
            self._ptr_block_max_ptrs = 1
            self._ptr_block_max_ptrs_shift = bsf(self._ptr_block_max_ptrs)
            self._ptr_block_num_ptrs = 1024
            self._ptr_block_num_shift = bsf(self._ptr_block_num_ptrs)

            self._sfb_size = 0
        else:
            # lockBlock in first MD block, metaBlock + data in second MD block
            self._fd_size = 2 * self.md_alignment
            # The data portion of a file descriptor starts at the end of the metadata, which is 512 bytes in size
            # That means that the remaining size of an MD block can be used for data
            # This can be used for resident data or RDM mappings
            self._fd_data_size = self.md_alignment - 512
            # Size of the data pointer array, in bytes
            # In VMFS6, the data pointer array is aligned to the end of the second MD block,
            # rather than at the end of the file metadata (like the data is)
            self._fd_data_addrs_size = 2560 if self.md_alignment <= 0x1000 else self.md_alignment >> 1

            # Offset to the file descriptor metadata
            self._fd_meta_offset = self.md_alignment
            # Offset to the data, which starts immediately after the metadata
            self._fd_data_offset = self._fd_size - self._fd_data_size
            # Offset to the data pointer array, which is aligned to the end of the file descriptor
            self._fd_data_addrs_offset = self._fd_size - self._fd_data_addrs_size

            # Data addresses/pointers are uint64
            self._fd_max_data_addrs = 320 if self.md_alignment <= 0x1000 else self.md_alignment >> 4

            self._ptr_block_page_size = 0x10000
            self._ptr_block_max_ptrs = max(0x10000, self.md_alignment) // self._ptr_block_page_size
            self._ptr_block_max_ptrs_shift = bsf(self._ptr_block_max_ptrs)
            self._ptr_block_num_ptrs = 8192 if self.md_alignment < 0x10000 else self.md_alignment >> 3
            self._ptr_block_num_shift = bsf(self._ptr_block_num_ptrs)

            # In VMFS6, file blocks (FB) are now called small file blocks (SFB)
            # Instead of being a simple number for a block, they now consist of a cluster
            # and a resource. The cluster needs to be multiplied by the number of blocks
            # per cluster to get the real block number.
            self._sfb_size = min(0x2000, 0x20000000 // self.file_block_size)

        self.resources = ResourceManager(self)
        self._open_resources(fdc, fbb, sbc, pbc, pb2, jbc)

        self.file_descriptor = lru_cache(4096)(self.file_descriptor)

        # Open the root directory
        self.root = self.file_descriptor(c_vmfs.rootDirDescAddr)

    def _open_resources(
        self,
        fdc: BinaryIO | None = None,
        fbb: BinaryIO | None = None,
        sbc: BinaryIO | None = None,
        pbc: BinaryIO | None = None,
        pb2: BinaryIO | None = None,
        jbc: BinaryIO | None = None,
    ) -> None:
        # https://kb.vmware.com/s/article/1001618
        # .pb2.sf - pointer block 2.system file
        # Contains the pointer blocks, used for indirect block referencing.
        # These eventually point to offsets on disk.
        if not self.resources.has(FS3_ResourceTypeID.PTR2_BLOCK):
            if pb2:
                self.resources.open(FS3_ResourceTypeID.PTR2_BLOCK, fileobj=pb2)
            elif self.descriptor.pb2VolAddr and self.fh:
                self.resources.open(
                    FS3_ResourceTypeID.PTR2_BLOCK, c_vmfs.pb2DescAddr if self.is_vmfs6 else self.descriptor.pb2FDAddr
                )

        # .pbc.sf - pointer block cluster.system file
        # Also contains the pointer blocks, used for indirect block referencing.
        # On VMFS5, these eventually point to offsets on disk.
        # On VMFS6, only the bitmap is used for allocation information, the pointer blocks are stored elsewhere
        if not self.resources.has(FS3_ResourceTypeID.PTR_BLOCK):
            if pbc:
                self.resources.open(FS3_ResourceTypeID.PTR_BLOCK, fileobj=pbc)
            elif self.fh:
                self.resources.open(FS3_ResourceTypeID.PTR_BLOCK, address=c_vmfs.pbcDescAddr)

        # .fbb.sf - file block bitmap(?).system file
        # Contains allocation information for file blocks.
        # On VMFS6, contains the large file block (LFB) bitmap, and the small file block (SFB) information is stored as
        # a "child".
        if self.is_vmfs5:
            if not self.resources.has(FS3_ResourceTypeID.FILE_BLOCK):
                if fbb:
                    self.resources.open(FS3_ResourceTypeID.FILE_BLOCK, fileobj=fbb)
                elif self.fh:
                    self.resources.open(FS3_ResourceTypeID.FILE_BLOCK, address=c_vmfs.fbbDescAddr)
        else:
            if not self.resources.has(FS3_ResourceTypeID.LARGE_FILE_BLOCK):
                if fbb:
                    self.resources.open(FS3_ResourceTypeID.LARGE_FILE_BLOCK, fileobj=fbb)
                elif self.fh:
                    self.resources.open(FS3_ResourceTypeID.LARGE_FILE_BLOCK, address=c_vmfs.fbbDescAddr)

            if not self.resources.has(FS3_ResourceTypeID.SMALL_FILE_BLOCK):
                metadata_offset = self.resources.LFB.metadata.childMetaOffset
                if fbb:
                    self.resources.open(
                        FS3_ResourceTypeID.SMALL_FILE_BLOCK, fileobj=fbb, metadata_offset=metadata_offset
                    )
                elif self.fh:
                    self.resources.open(
                        FS3_ResourceTypeID.SMALL_FILE_BLOCK, address=c_vmfs.fbbDescAddr, metadata_offset=metadata_offset
                    )

        # .fdc.sf -  file descriptor cluster.system file
        # Contains all the file descriptors.
        if not self.resources.has(FS3_ResourceTypeID.FILE_DESC):
            if fdc:
                self.resources.open(FS3_ResourceTypeID.FILE_DESC, fileobj=fdc)
            elif self.fh:
                self.resources.open(FS3_ResourceTypeID.FILE_DESC, address=c_vmfs.fdbcDescAddr)

        # .sbc.sf - sub-block cluster.system file
        # Contains sub-block data. Data that's too large to be resident, but too small for a full file block.
        # A lot of directory data is stored in sub-blocks, which is beneficial when we only have system files
        # to work with.
        if not self.resources.has(FS3_ResourceTypeID.SUB_BLOCK):
            if sbc:
                self.resources.open(FS3_ResourceTypeID.SUB_BLOCK, fileobj=sbc)
            elif self.fh:
                self.resources.open(FS3_ResourceTypeID.SUB_BLOCK, address=c_vmfs.sbDescAddr)

        # .jbc.sf - journal block cluster.system file
        # Unexplored territory, for now.
        if self.is_vmfs6 and not self.resources.has(FS3_ResourceTypeID.JOURNAL_BLOCK):
            if jbc:
                self.resources.open(FS3_ResourceTypeID.JOURNAL_BLOCK, fileobj=jbc)
            elif self.fh:
                self.resources.open(FS3_ResourceTypeID.JOURNAL_BLOCK, address=c_vmfs.jbDescAddr)

    def _get_sfd(self, address: int) -> FileDescriptor:
        fd_offset = _get_sfd_offset(self, address)
        self.fh.seek(fd_offset)
        buf = self.fh.read(self._fd_size)
        return FileDescriptor.from_bytes(self, address, buf)

    @property
    def is_vmfs5(self) -> bool:
        """Whether this is a VMFS5 filesystem."""
        return self.major_version < c_vmfs.FS3_VMFS6_MAJOR_VERSION

    @property
    def is_vmfs6(self) -> bool:
        """Whether this is a VMFS6 filesystem."""
        return self.major_version >= c_vmfs.FS3_VMFS6_MAJOR_VERSION

    @property
    def is_local(self) -> bool:
        """Whether this is a "local" VMFS filesystem (VMFS-L)."""
        return self.descriptor.magic == c_vmfs.VMFSL_MAGIC_NUMBER

    def file_descriptor(self, address: int) -> FileDescriptor:
        if address_type(address) != FS3_AddrType.FILE_DESCRIPTOR:
            raise TypeError(f"Invalid address type: {address_fmt(address)}")

        if self.is_vmfs5:
            cls = FileDescriptor5
        elif self.is_vmfs6:
            cls = FileDescriptor6
        else:
            cls = FileDescriptor

        return cls(self, address)

    def get(self, path: str | int | DirEntry, node: FileDescriptor | None = None) -> FileDescriptor:
        if isinstance(path, int):
            return self.file_descriptor(path)

        if isinstance(path, DirEntry):
            return self.file_descriptor(path.address)

        node = node or self.root
        for p in path.split("/"):
            if not p:
                continue

            try:
                node = node.get(p).file_descriptor
            except FileNotFoundError:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    def _read_descriptor_metadata(self, address: int) -> tuple[bool, int | None, c_vmfs.FS3_FileMetadata | None]:
        """Read and validate the metadata of a file descriptor slot.

        Returns a tuple of a validity flag, the recorded generation (or ``None`` when unparseable) and the parsed
        metadata structure (or ``None`` when unparseable).

        On VMFS6 the metadata carries an ``fdmd`` signature that must be present. On VMFS5 no such signature exists,
        so validity is a heuristic based on the descriptor type and on the metadata's ``descAddr`` matching the slot
        address. This method never raises on corrupted or reused slots; callers rely on the validity flag instead.
        """
        try:
            buf = self.resources.FD.read(address)
            metadata = c_vmfs.FS3_FileMetadata(buf[self._fd_meta_offset :])
        except Exception:
            return False, None, None

        if self.is_vmfs6 and metadata.signature != c_vmfs.FS3_FDMD_SIGNATURE:
            return False, None, None

        if metadata.type in (FS3_DescriptorType.INVALID, FS3_DescriptorType.SENTINEL):
            return False, None, None

        if metadata.descAddr != address:
            return False, None, None

        return True, metadata.generation, metadata

    def collect_descriptor_references(self) -> dict[int, list[DescriptorReference]]:
        """Walk every reachable directory and index directory entries by file descriptor address.

        The traversal is read-only and does not modify the filesystem or the regular directory listing behavior.
        Directories that cannot be read are skipped so that a single corrupt directory does not abort the whole
        enumeration. Every reference records its directory entry generation, which is later compared against the
        generation stored in the referenced slot to detect address reuse.

        Returns:
            A mapping of file descriptor address to the list of :class:`DescriptorReference` objects pointing at it.
        """
        references: dict[int, list[DescriptorReference]] = {}
        visited: set[int] = set()
        # Stack of (directory descriptor, path prefix including a trailing slash)
        stack: list[tuple[FileDescriptor, str]] = [(self.root, "/")]

        while stack:
            directory, prefix = stack.pop()
            if directory.address in visited:
                continue
            visited.add(directory.address)

            try:
                entries = list(directory.iterdir())
            except Exception:
                continue

            for entry in entries:
                references.setdefault(entry.address, []).append(
                    DescriptorReference(
                        address=entry.address,
                        name=entry.name,
                        path=prefix,
                        generation=entry.raw.generation if entry.raw is not None else None,
                        # Filled in once the slot generation is known during enumeration
                        matches_generation=False,
                    )
                )

                if entry.name in (".", ".."):
                    continue

                if entry.type == FS3_DescriptorType.DIRECTORY and entry.address not in visited:
                    try:
                        child = entry.file_descriptor
                    except Exception:
                        continue
                    stack.append((child, prefix + entry.name + "/"))

        return references

    def enumerate_descriptor_candidates(
        self,
        references: dict[int, list[DescriptorReference]] | None = None,
    ) -> list[DescriptorCandidate]:
        """Enumerate read-only residual file descriptor candidates.

        Every slot in the file descriptor resource (``.fdc.sf``) is inspected and classified by combining the
        resource allocation bitmap with directory references. This makes it possible to surface objects that are no
        longer reachable through a directory, without treating parseable metadata as proof of a current file or
        inferring a deletion time.

        Directory references are split into current (matching generation) and stale (mismatching generation) ones.
        A stale reference never binds its old name to the current contents of a reused address. Regular directory
        listing methods are unaffected; this is an additional, strictly read-only view.

        Args:
            references: An optional precomputed reference index from
                :meth:`collect_descriptor_references`. When omitted, the index is built by walking the directory tree.

        Returns:
            The list of :class:`DescriptorCandidate` objects, ordered by slot address.
        """
        if references is None:
            references = self.collect_descriptor_references()

        candidates: list[DescriptorCandidate] = []

        for slot in self.resources.FD.iter_slots():
            slot_references = references.get(slot.address, [])
            metadata_valid, generation, _ = self._read_descriptor_metadata(slot.address)

            matched_references: list[DescriptorReference] = []
            for ref in slot_references:
                matches = metadata_valid and ref.generation is not None and ref.generation == generation
                matched_references.append(
                    DescriptorReference(
                        address=ref.address,
                        name=ref.name,
                        path=ref.path,
                        generation=ref.generation,
                        matches_generation=matches,
                    )
                )

            state, reasons = classify_descriptor(
                slot.address,
                slot.allocated,
                metadata_valid,
                matched_references,
            )

            descriptor = None
            if metadata_valid:
                descriptor = self.file_descriptor(slot.address)

            candidates.append(
                DescriptorCandidate(
                    address=slot.address,
                    cluster=slot.cluster,
                    resource=slot.resource,
                    allocated=slot.allocated,
                    state=state,
                    reasons=reasons,
                    references=matched_references,
                    generation=generation,
                    metadata_valid=metadata_valid,
                    descriptor=descriptor,
                )
            )

        return sorted(candidates, key=lambda candidate: candidate.address)


def _get_sfd_offset(vmfs: VMFS, address: int) -> int:
    """Get the offset of a system file descriptor (SFD) address.

    This is used to bootstrap the VMFS filesystem, since we can't resolve the addresses through the FDC system file yet.

    References:
        - ``Res3_GetSFDOffset``
    """
    fsd = vmfs.descriptor
    _, resource = FileDescriptorAddr.parse(address)

    if vmfs.is_vmfs6:
        # No idea what this exactly calculates yet, just copied from the original kernel module
        cg_offset = (((fsd.mdAlignment << 10) + 0x3FFFFF) & 0xFFFFFFFFFFF00000) + fsd.fdcClusterGroupOffset

        resource_size = 2 * fsd.mdAlignment
        resource_offset = resource * resource_size
        return cg_offset + (fsd.fdcClustersPerGroup * resource_size) + resource_offset

    if FS3_Config.DENSE_SBPC not in fsd.config:
        if address == fsd.pb2FDAddr:
            return fsd.pb2VolAddr

        if address == fsd.sddFDAddr:
            return fsd.sddVolAddr

    # No idea what this exactly calculates yet, just copied from the original kernel module
    cg_offset = fsd.fileBlockSize * ((fsd.fileBlockSize + 0x3FFFFF) // fsd.fileBlockSize) + fsd.fdcClusterGroupOffset
    resource_size = 1024
    resource_offset = resource << 11
    return cg_offset + (fsd.fdcClustersPerGroup * resource_size) + resource_offset
