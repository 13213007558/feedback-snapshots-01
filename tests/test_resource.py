from __future__ import annotations

import io
import struct
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from dissect.vmfs.address import FileDescriptorAddr
from dissect.vmfs.c_vmfs import FS3_ResourceTypeID, c_vmfs
from dissect.vmfs.resource import FileDescriptorResourceVMFS6

MD_ALIGNMENT = 0x1000
CLUSTER_HEADER_SIZE = 2 * MD_ALIGNMENT

RESOURCES_PER_CLUSTER = 4
CLUSTERS_PER_GROUP = 2
RESOURCE_SIZE = 0x100
CLUSTER_GROUP_OFFSET = 0x10000
METADATA_OFFSET = 0x1000

# Child cluster group: cluster headers (2 * 0x2000) + cluster data (2 * 4 * 0x100)
CLUSTER_GROUP_SIZE = (CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE) + (
    CLUSTERS_PER_GROUP * RESOURCES_PER_CLUSTER * RESOURCE_SIZE
)
# Parent cluster group: parent cluster headers (2 * 0x2000) + 2 child cluster groups
PARENT_CLUSTERS_PER_GROUP = 2
PARENT_RESOURCES_PER_CLUSTER = 2
PARENT_CLUSTER_GROUP_SIZE = (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE) + (2 * CLUSTER_GROUP_SIZE)

NUM_CLUSTER_GROUPS = 3
NUM_RESOURCES = NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP * RESOURCES_PER_CLUSTER

# Child cluster groups 0 and 1 live in parent group 0, child cluster group 2 lives in parent group 1
GROUP_OFFSETS = [
    CLUSTER_GROUP_OFFSET + (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE),
    CLUSTER_GROUP_OFFSET + (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE) + CLUSTER_GROUP_SIZE,
    CLUSTER_GROUP_OFFSET + PARENT_CLUSTER_GROUP_SIZE + (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE),
]
IMAGE_SIZE = (
    CLUSTER_GROUP_OFFSET
    + PARENT_CLUSTER_GROUP_SIZE
    + (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE)
    + CLUSTER_GROUP_SIZE
)

VOLUME_BASE = 0x100000


def _resource_offset(cluster: int, resource: int) -> int:
    """Independently calculated offset of a resource in the synthetic parent/child resource file."""
    group, cluster_in_group = divmod(cluster, CLUSTERS_PER_GROUP)
    return (
        GROUP_OFFSETS[group]
        + (CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE)
        + (cluster_in_group * RESOURCES_PER_CLUSTER * RESOURCE_SIZE)
        + (resource * RESOURCE_SIZE)
    )


def _marker(cluster: int, resource: int) -> bytes:
    """Distinct byte marker for a resource."""
    return bytes([0x40 + (cluster * RESOURCES_PER_CLUSTER) + resource]) * RESOURCE_SIZE


def _metadata(flags: int = 0x2, num_resources: int = NUM_RESOURCES) -> bytes:
    return struct.pack(
        "<11I2H5I16sI",
        RESOURCES_PER_CLUSTER,  # resourcesPerCluster
        CLUSTERS_PER_GROUP,  # clustersPerGroup
        CLUSTER_GROUP_OFFSET,  # clusterGroupOffset
        RESOURCE_SIZE,  # resourceSize
        CLUSTER_GROUP_SIZE,  # clusterGroupSize
        num_resources & 0xFFFFFFFF,  # numResourcesLo
        NUM_CLUSTER_GROUPS,  # numClusterGroups
        num_resources >> 32,  # numResourcesHi
        c_vmfs.FS3_RFMD_SIGNATURE,  # signature
        1,  # version
        flags,  # flags
        0,  # affinityPerCluster
        0,  # affinityPerResource
        1,  # bitsPerResource
        0,  # childMetaOffset
        PARENT_RESOURCES_PER_CLUSTER,  # parentResourcesPerCluster
        PARENT_CLUSTERS_PER_GROUP,  # parentClustersPerGroup
        PARENT_CLUSTER_GROUP_SIZE,  # parentClusterGroupSize
        b"\x00" * 16,  # _unknown
        0,  # convertedClusters
    )


def _resource_file(metadata: bytes) -> bytes:
    """Build a synthetic resource file with a parent/child cluster group layout and distinct byte markers."""
    buf = bytearray(IMAGE_SIZE)
    buf[METADATA_OFFSET : METADATA_OFFSET + len(metadata)] = metadata
    for cluster in range(NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP):
        for resource in range(RESOURCES_PER_CLUSTER):
            offset = _resource_offset(cluster, resource)
            buf[offset : offset + RESOURCE_SIZE] = _marker(cluster, resource)
    return bytes(buf)


def _mock_vmfs(fh: BinaryIO | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        is_vmfs5=False,
        is_vmfs6=True,
        descriptor=SimpleNamespace(mdAlignment=MD_ALIGNMENT),
        fh=fh,
    )


def _open_resource(
    image: bytes, vmfs: SimpleNamespace, fd: SimpleNamespace | None = None
) -> FileDescriptorResourceVMFS6:
    return FileDescriptorResourceVMFS6(
        vmfs,
        FS3_ResourceTypeID.FILE_DESC,
        0,
        io.BytesIO(image),
        fd=fd,
        metadata_offset=METADATA_OFFSET,
    )


@pytest.fixture
def image() -> bytes:
    return _resource_file(_metadata())


@pytest.fixture
def resource_file(image: bytes) -> FileDescriptorResourceVMFS6:
    """Resource file read from an exported system file (no volume available)."""
    return _open_resource(image, _mock_vmfs())


@pytest.fixture
def resource_volume(image: bytes) -> FileDescriptorResourceVMFS6:
    """Resource file read from a volume, with the resource file placed at a fixed volume offset."""
    volume = io.BytesIO(b"\x00" * VOLUME_BASE + image)
    fd = SimpleNamespace(_resolve_offset=lambda offset: (VOLUME_BASE + offset, 0))
    return _open_resource(image, _mock_vmfs(fh=volume), fd=fd)


def test_resource_parent_child_layout(
    resource_file: FileDescriptorResourceVMFS6, resource_volume: FileDescriptorResourceVMFS6
) -> None:
    """Both read paths must locate the same resources in a parent/child cluster group layout."""
    assert resource_file.metadata.resourcesPerCluster == RESOURCES_PER_CLUSTER

    for cluster in range(NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP):
        for resource in range(RESOURCES_PER_CLUSTER):
            address = FileDescriptorAddr.make(cluster, resource)

            # Both the system file and the volume read path must return the same resource content
            assert resource_file.read(address) == _marker(cluster, resource)
            assert resource_volume.read(address) == _marker(cluster, resource)

            # Both paths must agree on the source location of the resource
            assert resource_file._resource_offset_from_address(address) == _resource_offset(cluster, resource)
            assert resource_volume.resolve_address(address) == VOLUME_BASE + _resource_offset(cluster, resource)


def test_resource_parent_group_boundary(
    resource_file: FileDescriptorResourceVMFS6, resource_volume: FileDescriptorResourceVMFS6
) -> None:
    """Resources directly before and after a parent cluster group boundary must resolve correctly."""
    last_cluster = (2 * CLUSTERS_PER_GROUP) - 1
    first_cluster = 2 * CLUSTERS_PER_GROUP

    before = FileDescriptorAddr.make(last_cluster, RESOURCES_PER_CLUSTER - 1)
    after = FileDescriptorAddr.make(first_cluster, 0)

    # The parent cluster headers of the next parent group and the child cluster headers
    # of the next child cluster group sit between these two resources
    assert _resource_offset(first_cluster, 0) - _resource_offset(last_cluster, RESOURCES_PER_CLUSTER - 1) == (
        RESOURCE_SIZE + (PARENT_CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE) + (CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE)
    )

    for resource in (resource_file, resource_volume):
        assert resource.read(before) == _marker(last_cluster, RESOURCES_PER_CLUSTER - 1)
        assert resource.read(after) == _marker(first_cluster, 0)


@pytest.mark.parametrize(
    ("cluster", "resource"),
    [
        # Resource index spills over into the data of the next cluster, which is a valid resource
        pytest.param(0, RESOURCES_PER_CLUSTER, id="resource-overlap"),
        # Cluster index beyond the declared cluster groups
        pytest.param(NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP, 0, id="cluster-out-of-bounds"),
    ],
)
def test_resource_out_of_bounds(
    resource_file: FileDescriptorResourceVMFS6,
    resource_volume: FileDescriptorResourceVMFS6,
    cluster: int,
    resource: int,
) -> None:
    """Out of bounds resource indices must raise an error instead of resolving to another resource."""
    address = FileDescriptorAddr.make(cluster, resource)
    for res in (resource_file, resource_volume):
        with pytest.raises(ValueError):  # noqa: PT011
            res._resource_offset_from_address(address)


def test_resource_num_resources(image: bytes) -> None:
    """Resource indices beyond the declared number of resources must raise an error."""
    # Declare one resource less than the layout can hold, invalidating the last resource
    metadata = _metadata(num_resources=NUM_RESOURCES - 1)
    resource = _open_resource(_resource_file(metadata), _mock_vmfs())

    last_cluster = (NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP) - 1
    address = FileDescriptorAddr.make(last_cluster, RESOURCES_PER_CLUSTER - 1)
    with pytest.raises(ValueError):  # noqa: PT011
        resource._resource_offset_from_address(address)

    address = FileDescriptorAddr.make(last_cluster, RESOURCES_PER_CLUSTER - 2)
    assert resource.read(address) == _marker(last_cluster, RESOURCES_PER_CLUSTER - 2)


def test_resource_plain_layout() -> None:
    """A resource file without a parent must keep using the plain layout formula."""
    metadata = bytearray(_metadata(flags=0))
    image = bytearray(IMAGE_SIZE)
    image[METADATA_OFFSET : METADATA_OFFSET + len(metadata)] = metadata

    group_offsets = [CLUSTER_GROUP_OFFSET + (group * CLUSTER_GROUP_SIZE) for group in range(NUM_CLUSTER_GROUPS)]
    for cluster in range(NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP):
        for resource in range(RESOURCES_PER_CLUSTER):
            group, cluster_in_group = divmod(cluster, CLUSTERS_PER_GROUP)
            offset = (
                group_offsets[group]
                + (CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE)
                + (cluster_in_group * RESOURCES_PER_CLUSTER * RESOURCE_SIZE)
                + (resource * RESOURCE_SIZE)
            )
            image[offset : offset + RESOURCE_SIZE] = _marker(cluster, resource)

    resource = _open_resource(bytes(image), _mock_vmfs())
    for cluster in range(NUM_CLUSTER_GROUPS * CLUSTERS_PER_GROUP):
        for res in range(RESOURCES_PER_CLUSTER):
            address = FileDescriptorAddr.make(cluster, res)
            assert resource.read(address) == _marker(cluster, res)
            group, cluster_in_group = divmod(cluster, CLUSTERS_PER_GROUP)
            assert resource._resource_offset_from_address(address) == (
                group_offsets[group]
                + (CLUSTERS_PER_GROUP * CLUSTER_HEADER_SIZE)
                + (cluster_in_group * RESOURCES_PER_CLUSTER * RESOURCE_SIZE)
                + (res * RESOURCE_SIZE)
            )
