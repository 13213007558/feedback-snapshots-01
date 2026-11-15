from __future__ import annotations

import io
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.vmfs.exception import NotAnRDMFileError, RDMCapacityError, RDMDeviceMismatchError

if TYPE_CHECKING:
    from dissect.vmfs.c_vmfs import c_vmfs
    from dissect.vmfs.descriptor import FileDescriptor


class RDM:
    """Read-only view of a Raw Device Mapping (RDM) file.

    An RDM file in a VMFS volume does not contain disk data itself. Its file descriptor only
    records a mapping (``FS3_RawDiskMap``) to an external SCSI device: the device identity and,
    through the file length, the device capacity at the time the mapping was created.

    For forensic use, the actual disk bytes must come from an evidence image that the caller
    explicitly supplies. This class never resolves device paths found in an image to local
    devices. Use :func:`describe` to inspect the mapping without any image, and :func:`bind`
    to validate a caller-supplied image against the mapping and read the mapped range from it.

    Args:
        fd: The file descriptor of the RDM mapping file.
    """

    def __init__(self, fd: FileDescriptor):
        if not fd.is_rdm():
            raise NotAnRDMFileError(f"{fd} is not an RDM file")
        self.fd = fd

    def __repr__(self) -> str:
        return f"<RDM device_id={self.device_id!r} size={self.size}>"

    @cached_property
    def mapping(self) -> c_vmfs.FS3_RawDiskMap:
        """The raw RDM mapping structure."""
        return self.fd.rdm_mapping

    @property
    def device_id(self) -> bytes:
        """The device identity recorded in the mapping.

        This is the significant portion (``len`` bytes) of the SCSI disk id.
        """
        disk_id = self.mapping.diskId
        return bytes(disk_id.id[: disk_id.len])

    @property
    def size(self) -> int | None:
        """The capacity of the mapped device in bytes, if recorded.

        The capacity basis is the file length of the mapping file. If it is zero,
        the mapping records no usable capacity and ``None`` is returned.
        """
        return self.fd.size or None

    @property
    def mode(self) -> str | None:
        """The device compatibility mode of the mapping, if recorded.

        The RDM mapping metadata does not record the device mode (e.g. physical or virtual
        compatibility), so this is always ``None``. It is deliberately *not* derived from
        file names or other heuristics.
        """
        return None

    def describe(self) -> str:
        """Return a human-readable description of the mapping.

        This only uses the mapping metadata and works without a bound evidence image.
        Missing information, such as the device mode or capacity, is stated explicitly.
        """
        disk_id = self.mapping.diskId
        vendor = bytes(disk_id.vendor).decode(errors="replace").strip("\x00").strip()
        model = bytes(disk_id.model).decode(errors="replace").strip("\x00").strip()
        revision = bytes(disk_id.revision).decode(errors="replace").strip("\x00").strip()

        lines = [
            f"Device identity: {self.device_id!r} (SCSI id type {disk_id.type}, {disk_id.len} bytes)",
            f"Device: vendor={vendor or 'unknown'} model={model or 'unknown'} "
            f"revision={revision or 'unknown'} lun={disk_id.lun}",
        ]
        if self.size is not None:
            lines.append(f"Capacity: {self.size} bytes (from mapping file length)")
        else:
            lines.append("Capacity: not recorded in mapping metadata")
        lines.append("Device mode: not recorded in mapping metadata")
        return "\n".join(lines)

    def bind(self, fh: BinaryIO, *, device_id: bytes | str) -> RangeStream:
        """Bind a caller-supplied evidence image to this mapping.

        The image is validated against the mapping metadata before any data is returned:

        - the device identity of the evidence must match the mapped device identity;
        - the mapping must record a capacity, and the evidence must be large enough
          to cover the entire mapped range.

        Args:
            fh: A file-like object of the evidence image, explicitly provided by the caller.
            device_id: The device identity of the evidence, as declared by the caller.

        Raises:
            RDMDeviceMismatchError: If the device identity does not match the mapping.
            RDMCapacityError: If the capacity basis is missing or the evidence is too small.

        Returns:
            A read-only stream of the mapped range of the evidence image.
        """
        expected = self.device_id
        provided = device_id.encode() if isinstance(device_id, str) else bytes(device_id)
        if provided != expected:
            raise RDMDeviceMismatchError(
                f"Device identity mismatch: mapping expects {expected!r}, evidence provides {provided!r}"
            )

        size = self.size
        if size is None:
            raise RDMCapacityError(
                "Mapping metadata records no capacity (file length is 0), cannot determine readable range"
            )

        evidence_size = _stream_size(fh)
        if evidence_size is None:
            raise RDMCapacityError("Cannot determine capacity of the provided evidence image (not seekable)")
        if evidence_size < size:
            raise RDMCapacityError(
                f"Evidence image too small: mapping requires {size} bytes, evidence provides {evidence_size} bytes"
            )

        return RangeStream(fh, 0, size)


def _stream_size(fh: BinaryIO) -> int | None:
    """Return the size of a file-like object, or ``None`` if it cannot be determined."""
    try:
        size = fh.seek(0, io.SEEK_END)
    except OSError:
        return None
    if size is None:
        try:
            size = fh.tell()
        except OSError:
            return None
    return size
