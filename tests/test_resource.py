from __future__ import annotations

import io

import pytest

from dissect.vmfs.address import SubBlockAddr64
from dissect.vmfs.c_vmfs import FS3_Config, FS3_ResourceTypeID, c_vmfs
from dissect.vmfs.exception import InvalidResourceError
from dissect.vmfs.resource import SubBlockResourceVMFS6

# Distinct byte markers so that a wrong offset can never accidentally return the expected payload
META_MARKER = 0x11
PARENT_HEADER_MARKER = 0x5C
CHILD_LOCK_MARKER = 0x5D
CHILD_META_MARKER = 0x5E
RESOURCE_MARKER = 0xA0
RESOURCE_MAGIC = b"DISSECT!"


class BufferHandle:
    """Seekable file handle over a shared, mutable bytearray.

    Every handle created for the same buffer observes writes made through any other handle.
    This models a resource file and the full volume pointing at the same underlying storage.
    """

    def __init__(self, buffer: bytearray):
        self.buffer = buffer
        self._pos = 0

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = len(self.buffer) + offset
        return self._pos

    def read(self, size: int = -1) -> bytes:
        end = len(self.buffer) if size is None or size < 0 else min(self._pos + size, len(self.buffer))
        data = bytes(self.buffer[self._pos : end])
        self._pos = end
        return data

    def write(self, data: bytes) -> int:
        end = self._pos + len(data)
        if end > len(self.buffer):
            self.buffer.extend(b"\x00" * (end - len(self.buffer)))
        self.buffer[self._pos : end] = data
        self._pos = end
        return len(data)

    def tell(self) -> int:
        return self._pos


class FakeDescriptor:
    """Minimal stand-in for ``FS3_Descriptor`` exposing the fields used by ``ResourceFile``."""

    def __init__(self, md_alignment: int):
        self.mdAlignment = md_alignment
        self.config = FS3_Config(0)


class FakeVMFS:
    """Minimal stand-in for a VMFS6 filesystem."""

    def __init__(self, volume: BufferHandle, md_alignment: int = 512):
        self.fh = volume
        self.descriptor = FakeDescriptor(md_alignment)
        self.major_version = c_vmfs.FS3_VMFS6_MAJOR_VERSION

    @property
    def is_vmfs5(self) -> bool:
        return False

    @property
    def is_vmfs6(self) -> bool:
        return True


class FakeFD:
    """File descriptor whose backing store is the same buffer as the fake volume.

    This makes the "volume" read path resolve to the exact same bytes as the resource file path.
    """

    def _resolve_offset(self, offset: int) -> tuple[int, int]:
        return offset, 0


def _resource_payload(cluster: int, resource: int) -> bytes:
    """Build a unique, recognizable payload for a single resource."""
    header = RESOURCE_MAGIC + bytes([cluster & 0xFF, resource & 0xFF])
    return header + bytes([RESOURCE_MARKER]) * (64 - len(header))


def _metadata(**kwargs) -> c_vmfs.FS3_ResFileMetadata:
    values = {
        "resourcesPerCluster": 0,
        "clustersPerGroup": 0,
        "clusterGroupOffset": 0,
        "resourceSize": 0,
        "clusterGroupSize": 0,
        "numResourcesLo": 0,
        "numClusterGroups": 0,
        "numResourcesHi": 0,
        "signature": c_vmfs.FS3_RFMD_SIGNATURE,
        "version": 1,
        "flags": 0,
        "affinityPerCluster": 0,
        "affinityPerResource": 0,
        "bitsPerResource": 0,
        "childMetaOffset": 0,
        "parentResourcesPerCluster": 0,
        "parentClustersPerGroup": 0,
        "parentClusterGroupSize": 0,
        "convertedClusters": 0,
    }
    values.update(kwargs)
    return c_vmfs.FS3_ResFileMetadata(**values)


def _build_parent_child_image() -> tuple[bytearray, SubBlockResourceVMFS6, FakeVMFS]:
    """Build a resource file containing a parent resource file and an embedded child resource.

    Geometry (two disk blocks per cluster header, md alignment 512):

    - Parent: 4 resources/cluster, 4 clusters/group, resource size 5120
    - Child: 4 resources/cluster, 4 clusters/group, resource size 64
    - 4 child cluster groups fit inside one parent cluster group
    - The image contains two parent cluster groups, hence eight child cluster groups
    """
    header_size = 1024

    child_rpc = 4
    child_cpg = 4
    child_rs = 64
    child_group_size = header_size * child_cpg + child_cpg * child_rpc * child_rs

    parent_rpc = 4
    parent_cpg = 4
    parent_rs = 5120
    parent_group_size = header_size * parent_cpg + parent_cpg * parent_rpc * parent_rs

    child_groups_per_parent = (parent_cpg * parent_rpc) // child_cpg
    num_parent_groups = 2
    num_child_groups = child_groups_per_parent * num_parent_groups
    num_resources = child_rpc * child_cpg * num_child_groups

    metadata_offset = 4096
    cluster_group_offset = 16384

    parent_md = _metadata(
        resourcesPerCluster=parent_rpc,
        clustersPerGroup=parent_cpg,
        clusterGroupOffset=cluster_group_offset,
        resourceSize=parent_rs,
        clusterGroupSize=parent_group_size,
        numResourcesLo=parent_rpc * parent_cpg * num_parent_groups,
        numClusterGroups=num_parent_groups,
        flags=0x20,
        childMetaOffset=metadata_offset,
    )
    child_md = _metadata(
        resourcesPerCluster=child_rpc,
        clustersPerGroup=child_cpg,
        clusterGroupOffset=cluster_group_offset,
        resourceSize=child_rs,
        clusterGroupSize=child_group_size,
        numResourcesLo=num_resources,
        numClusterGroups=num_child_groups,
        flags=0x2,
        parentResourcesPerCluster=parent_rpc,
        parentClustersPerGroup=parent_cpg,
        parentClusterGroupSize=parent_group_size,
    )

    image_size = cluster_group_offset + (num_parent_groups * parent_group_size)
    buffer = bytearray([META_MARKER]) * image_size

    buffer[0 : len(parent_md.dumps())] = parent_md.dumps()
    buffer[metadata_offset : metadata_offset + len(child_md.dumps())] = child_md.dumps()

    # The resource file handle and the volume handle share the same mutable buffer
    resource_handle = BufferHandle(buffer)
    volume_handle = BufferHandle(buffer)
    fake_vmfs = FakeVMFS(volume_handle)
    fd = FakeFD()

    # Fill the parent cluster headers with their own marker, so misreads into parent metadata stand out
    for parent_group in range(num_parent_groups):
        parent_base = cluster_group_offset + parent_group * parent_group_size
        for parent_cluster in range(parent_cpg):
            start = parent_base + parent_cluster * header_size
            buffer[start : start + header_size] = bytes([PARENT_HEADER_MARKER]) * header_size

    child_resource = SubBlockResourceVMFS6(
        fake_vmfs,
        FS3_ResourceTypeID.SUB_BLOCK,
        0,
        resource_handle,
        fd=fd,
        metadata_offset=metadata_offset,
    )
    assert child_resource._has_parent
    assert child_resource.num_resources == num_resources

    # Mark child cluster headers and write unique, byte-marked resource payloads
    for group in range(num_child_groups):
        group_base = child_resource._cluster_group_offset(group)
        for cluster_in_group in range(child_cpg):
            header_start = group_base + cluster_in_group * header_size
            buffer[header_start : header_start + 512] = bytes([CHILD_LOCK_MARKER]) * 512
            buffer[header_start + 512 : header_start + header_size] = bytes([CHILD_META_MARKER]) * 512

        for cluster_in_group in range(child_cpg):
            cluster = group * child_cpg + cluster_in_group
            for resource in range(child_rpc):
                payload = _resource_payload(cluster, resource)
                offset = child_resource._resource_offset(cluster, resource)
                buffer[offset : offset + child_rs] = payload

    return buffer, child_resource, fake_vmfs


@pytest.fixture()
def parent_child_image() -> tuple[bytearray, SubBlockResourceVMFS6, FakeVMFS]:
    return _build_parent_child_image()


def test_resource_geometry_parent_child(parent_child_image) -> None:
    _, resource, _ = parent_child_image
    md = resource.metadata

    child_groups_per_parent = (md.parentClustersPerGroup * md.parentResourcesPerCluster) // md.clustersPerGroup

    # Child group 0 starts after the parent cluster headers of parent group 0
    assert resource._cluster_group_offset(0) == (
        md.clusterGroupOffset + md.parentClustersPerGroup * resource._cluster_header_size
    )

    # Every child group inside one parent cluster group is spaced by the child group size
    for group in range(child_groups_per_parent):
        assert resource._cluster_group_offset(group) == (
            md.clusterGroupOffset
            + md.parentClustersPerGroup * resource._cluster_header_size
            + group * md.clusterGroupSize
        )

    # The first group of the second parent group crosses the parent group boundary
    assert resource._cluster_group_offset(child_groups_per_parent) == (
        md.clusterGroupOffset + md.parentClusterGroupSize + md.parentClustersPerGroup * resource._cluster_header_size
    )


@pytest.mark.parametrize(
    ("cluster", "resource"),
    [
        # First resource of the whole file
        (0, 0),
        # Last resource of the first child cluster group
        (3, 3),
        # First/last resources of the group right after the child group boundary
        (4, 0),
        (7, 3),
        # First child group of the second parent group (cross parent group boundary)
        (16, 0),
        (19, 3),
        # Final declared resource
        (31, 3),
    ],
)
def test_resource_read_paths_agree_parent_child(parent_child_image, cluster: int, resource: int) -> None:
    buffer, resource_file, fake_vmfs = parent_child_image
    address = SubBlockAddr64.make(cluster, resource)
    expected = _resource_payload(cluster, resource)

    file_offset = resource_file._resource_offset_from_address(address)
    volume_offset = resource_file.resolve_address(address)

    # Both paths must report the same source location inside the shared backing store
    assert file_offset == volume_offset
    assert buffer[file_offset : file_offset + len(RESOURCE_MAGIC)] == RESOURCE_MAGIC

    # Path 1: read through the resource file (no volume handle), i.e. an exported system file
    fake_vmfs.fh = None
    file_data = resource_file.read(address)

    # Path 2: read through the full volume
    fake_vmfs.fh = BufferHandle(buffer)
    volume_data = resource_file.read(address)

    assert file_data == expected
    assert volume_data == expected
    assert file_data == volume_data


def test_resource_does_not_read_parent_headers(parent_child_image) -> None:
    buffer, resource_file, fake_vmfs = parent_child_image
    address = SubBlockAddr64.make(0, 0)

    resource_offset = resource_file._resource_offset_from_address(address)
    parent_header_offset = resource_file.metadata.clusterGroupOffset

    # The first child resource lives after the parent header region, not inside it
    assert (
        resource_offset
        > parent_header_offset + resource_file.metadata.parentClustersPerGroup * resource_file._cluster_header_size
    )
    assert buffer[parent_header_offset] == PARENT_HEADER_MARKER
    assert buffer[resource_offset : resource_offset + len(RESOURCE_MAGIC)] == RESOURCE_MAGIC

    fake_vmfs.fh = None
    assert resource_file.read(address)[0 : len(RESOURCE_MAGIC)] == RESOURCE_MAGIC


@pytest.mark.parametrize(
    ("cluster", "resource"),
    [
        # Resource index beyond what fits in a single cluster
        (0, 4),
        # Cluster beyond the declared number of cluster groups
        (32, 0),
        # One past the final declared resource
        (31, 4),
    ],
)
def test_resource_rejects_out_of_range_address(parent_child_image, cluster: int, resource: int) -> None:
    _, resource_file, fake_vmfs = parent_child_image
    address = SubBlockAddr64.make(cluster, resource)

    with pytest.raises(InvalidResourceError):
        resource_file._resource_offset_from_address(address)
    with pytest.raises(InvalidResourceError):
        resource_file.resolve_address(address)

    fake_vmfs.fh = None
    with pytest.raises(InvalidResourceError):
        resource_file.read(address)


def test_resource_normal_layout_and_nonzero_metadata_offset() -> None:
    """A regular (non parent/child) resource keeps the original formula with a nonzero metadata offset."""
    header_size = 1024
    rpc = 4
    cpg = 4
    resource_size = 64
    num_groups = 3
    num_resources = rpc * cpg * num_groups
    cluster_group_offset = 8192
    metadata_offset = 2048
    group_size = header_size * cpg + cpg * rpc * resource_size

    md = _metadata(
        resourcesPerCluster=rpc,
        clustersPerGroup=cpg,
        clusterGroupOffset=cluster_group_offset,
        resourceSize=resource_size,
        clusterGroupSize=group_size,
        numResourcesLo=num_resources,
        numClusterGroups=num_groups,
        flags=0,
    )

    image_size = cluster_group_offset + num_groups * group_size
    buffer = bytearray([META_MARKER]) * image_size
    buffer[metadata_offset : metadata_offset + len(md.dumps())] = md.dumps()

    resource_handle = BufferHandle(buffer)
    volume_handle = BufferHandle(buffer)
    fake_vmfs = FakeVMFS(volume_handle)
    fd = FakeFD()
    resource_file = SubBlockResourceVMFS6(
        fake_vmfs,
        FS3_ResourceTypeID.SUB_BLOCK,
        0,
        resource_handle,
        fd=fd,
        metadata_offset=metadata_offset,
    )

    assert not resource_file._has_parent
    assert resource_file.metadata_offset == metadata_offset

    # Classic back-to-back group formula, unaffected by the nonzero metadata offset
    for group in range(num_groups):
        assert resource_file._cluster_group_offset(group) == cluster_group_offset + group * group_size

    for cluster in range(cpg * num_groups):
        for resource in range(rpc):
            payload = _resource_payload(cluster, resource)
            offset = resource_file._resource_offset(cluster, resource)
            buffer[offset : offset + resource_size] = payload

    for cluster, resource in ((0, 0), (3, 3), (4, 0), (11, 3)):
        address = SubBlockAddr64.make(cluster, resource)
        expected = _resource_payload(cluster, resource)
        assert resource_file._resource_offset_from_address(address) == resource_file.resolve_address(address)

        fake_vmfs.fh = None
        file_data = resource_file.read(address)
        fake_vmfs.fh = BufferHandle(buffer)
        volume_data = resource_file.read(address)

        assert file_data == expected
        assert volume_data == expected
