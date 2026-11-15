"""Read-only Raw Device Mapping (RDM) interpretation and evidence binding.

An RDM file descriptor describes an external SCSI device. The descriptor is
metadata, not disk content, and the device path recorded by ESXi is never
opened. Callers must supply the external disk image explicitly:

.. code-block:: python

    from dissect.vmfs.rdm import RDMDeviceMode, RDMImage

    image = RDMImage(
        evidence_fh,
        identity,  # RDMDeviceIdentity or c_vmfs.SCSI_DiskId
        mode=RDMDeviceMode.PHYSICAL,
        path="/evidence/rdm-rdm.img",  # descriptive only
    )
    binding = fd.bind_rdm(image)
    binding.read_range(0, 512)

The binding validates mapping metadata, device identity, device mode, declared
capacity, stream capacity, and the first/last byte of the mapped range before
returning a stream. It never falls back to the descriptor bytes.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import TYPE_CHECKING, BinaryIO

from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.exception import (
    NotAnRDMFileError,
    RDMReadError,
    RDMValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.vmfs.descriptor import FileDescriptor


class RDMDeviceMode(str, Enum):
    """Compatibility mode claimed by an RDM evidence image.

    The mode is supplied by the caller together with the evidence image. It is
    never derived from a file name or from the VMFS descriptor.
    """

    PHYSICAL = "physical"
    VIRTUAL = "virtual"


@dataclass(frozen=True)
class RDMValidationIssue:
    """A concrete reason why an RDM mapping could not be bound."""

    code: str
    message: str
    field: str | None = None
    image: str | None = None

    def __str__(self) -> str:
        location = f" [{self.field}]" if self.field else ""
        source = f" ({self.image})" if self.image else ""
        return f"{self.code}{location}{source}: {self.message}"


def _trim_bytes(value: bytes | bytearray | memoryview | str) -> bytes:
    value = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return value.rstrip(b"\x00")


@dataclass(frozen=True)
class RDMDeviceIdentity:
    """The SCSI identity that an RDM mapping associates with an external disk.

    The identity is evidence supplied with an :class:`RDMImage`. A path or a
    file name is deliberately not part of this structure.
    """

    type: int
    id: bytes
    lun: int = 0
    device_type: int = 0
    scsi_level: int = 0
    vendor: bytes = b""
    model: bytes = b""
    revision: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _trim_bytes(self.id))
        object.__setattr__(self, "vendor", _trim_bytes(self.vendor))
        object.__setattr__(self, "model", _trim_bytes(self.model))
        object.__setattr__(self, "revision", _trim_bytes(self.revision))

    @classmethod
    def from_scsi_disk_id(cls, disk_id: c_vmfs.SCSI_DiskId) -> RDMDeviceIdentity:
        """Create an identity from an on-disk ``FS3_RawDiskMap.diskId``."""
        raw_id = bytes(disk_id.id)
        length = int(disk_id.len)
        if 0 < length <= len(raw_id):
            raw_id = raw_id[:length]

        return cls(
            type=int(disk_id.type),
            id=raw_id,
            lun=int(disk_id.lun),
            device_type=int(disk_id.deviceType),
            scsi_level=int(disk_id.scsiLevel),
            vendor=_trim_bytes(disk_id.vendor),
            model=_trim_bytes(disk_id.model),
            revision=_trim_bytes(disk_id.revision),
        )

    @property
    def complete(self) -> bool:
        """Whether the identity contains the minimum evidence to compare."""
        return bool(self.id)


    def mismatch_reasons(self, other: RDMDeviceIdentity) -> list[str]:
        """Return the fields that conflict with another identity.

        Fields that are zero or empty on either side are treated as not
        recorded, not as a wildcard that silently accepts a conflicting value.
        """
        reasons = []

        if not self.id or not other.id or self.id != other.id:
            reasons.append("id")

        for name in ("type", "lun", "device_type", "scsi_level"):
            left = getattr(self, name)
            right = getattr(other, name)
            if left and right and left != right:
                reasons.append(name)

        for name in ("vendor", "model", "revision"):
            left = getattr(self, name)
            right = getattr(other, name)
            if left and right and left != right:
                reasons.append(name)

        return reasons

    def matches(self, other: RDMDeviceIdentity) -> bool:
        """Return whether two identities describe the same device."""
        return not self.mismatch_reasons(other)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation of this identity."""
        return {
            "type": self.type,
            "id": self.id.decode("utf-8", "backslashreplace"),
            "lun": self.lun,
            "device_type": self.device_type,
            "scsi_level": self.scsi_level,
            "vendor": self.vendor.decode("utf-8", "backslashreplace"),
            "model": self.model.decode("utf-8", "backslashreplace"),
            "revision": self.revision.decode("utf-8", "backslashreplace"),
        }


class RDMImage:
    """An explicitly supplied, read-only image of an external RDM disk.

    Only ``fh`` is ever read. ``path`` is descriptive metadata for reports and
    is never opened, resolved, or used to locate a host device.

    Args:
        fh: A seekable file-like object containing the external disk image.
        identity: The SCSI identity of the device represented by ``fh``.
        mode: The compatibility mode claimed by the evidence image.
        size: The capacity proven by the evidence. If omitted, it is derived
            from the seekable ``fh`` when possible.
        path: Optional descriptive path from the evidence inventory.
        label: Optional human readable label for validation messages.
    """

    def __init__(
        self,
        fh: BinaryIO,
        identity: RDMDeviceIdentity | c_vmfs.SCSI_DiskId,
        *,
        mode: RDMDeviceMode | str | None = None,
        size: int | None = None,
        path: str | None = None,
        label: str | None = None,
    ):
        if isinstance(identity, c_vmfs.SCSI_DiskId):
            identity = RDMDeviceIdentity.from_scsi_disk_id(identity)
        if not isinstance(identity, RDMDeviceIdentity):
            raise TypeError("identity must be an RDMDeviceIdentity or c_vmfs.SCSI_DiskId")

        if size is not None and size < 0:
            raise ValueError("size cannot be negative")

        self.fh = fh
        self.identity = identity
        self.mode = RDMDeviceMode(mode) if isinstance(mode, str) else mode
        self.size = size
        self.path = path
        self.label = label or path or f"image@{id(fh):x}"
        self._lock = Lock()
        self._measured_size: int | None = None

    @property
    def measured_size(self) -> int | None:
        """The capacity currently exposed by the evidence stream.

        This probes the stream with a seek to the end and caches the result. It
        is independent of :attr:`size`, which is the capacity declared by the
        caller. It returns ``None`` when the stream is not seekable.
        """
        if self._measured_size is not None:
            return self._measured_size

        seekable = getattr(self.fh, "seekable", None)
        if seekable is not None and not seekable():
            return None

        with self._lock:
            if self._measured_size is not None:
                return self._measured_size
            try:
                current = self.fh.tell()
                self.fh.seek(0, io.SEEK_END)
                self._measured_size = self.fh.tell()
                self.fh.seek(current)
            except (AttributeError, OSError):
                return None

        return self._measured_size

    @property
    def available_size(self) -> int | None:
        """The smallest capacity that the supplied evidence can currently prove.

        Both the caller-declared size and the size measured from the stream are
        evidence. The smallest value bounds the readable range. Returns ``None``
        when neither is available.
        """
        sizes = [size for size in (self.size, self.measured_size) if size is not None]
        return min(sizes) if sizes else None

    def size_issues(self) -> list[RDMValidationIssue]:
        """Return concrete issues about the capacity claims of this image."""
        issues = []
        declared = self.size
        measured = self.measured_size

        if declared is not None and measured is not None and measured < declared:
            issues.append(
                RDMValidationIssue(
                    "image_capacity_mismatch",
                    f"evidence declares {declared} bytes but the stream only exposes {measured} bytes",
                    field="size",
                    image=self.label,
                )
            )

        return issues

    def read(self, offset: int, length: int) -> bytes:
        """Read exactly ``length`` bytes at ``offset`` from the supplied image."""
        if offset < 0:
            raise ValueError("offset cannot be negative")
        if length < 0:
            raise ValueError("length cannot be negative")
        if length == 0:
            return b""

        with self._lock:
            self.fh.seek(offset)
            return self.fh.read(length)

    def __repr__(self) -> str:
        mode = self.mode.value if self.mode else "unknown"
        return f"<RDMImage label={self.label!r} mode={mode} size={self.measured_size}>"


class RDMMapping:
    """Read-only interpretation of the RDM metadata in a file descriptor.

    The mapping is deliberately separate from the disk content. It can be
    inspected without any evidence image, but it never acts as a readable disk
    stream and never falls back to the descriptor bytes.
    """

    def __init__(self, descriptor: FileDescriptor):
        if not descriptor.is_rdm():
            raise NotAnRDMFileError(f"{descriptor} is not an RDM file")

        self.descriptor = descriptor
        self._raw = c_vmfs.FS3_RawDiskMap(descriptor.data)
        self.diskId = self._raw.diskId
        self.device_id = RDMDeviceIdentity.from_scsi_disk_id(self.diskId)
        self.capacity = descriptor.size

    @property
    def raw(self) -> c_vmfs.FS3_RawDiskMap:
        """The raw ``FS3_RawDiskMap`` structure parsed from the descriptor."""
        return self._raw

    def validate_metadata(self) -> tuple[RDMValidationIssue, ...]:
        """Return the issues in the mapping metadata itself."""
        issues = []

        declared_length = int(self.diskId.len)
        if declared_length <= 0 or declared_length > len(self.diskId.id):
            issues.append(
                RDMValidationIssue(
                    "missing_mapping_identity_length",
                    f"RDM mapping declares an invalid device id length {declared_length}",
                    field="diskId.len",
                )
            )
        if not self.device_id.complete:
            issues.append(
                RDMValidationIssue(
                    "missing_mapping_identity",
                    "RDM mapping does not record a usable SCSI device id",
                    field="diskId.id",
                )
            )
        if self.capacity <= 0:
            issues.append(
                RDMValidationIssue(
                    "missing_mapping_capacity",
                    "RDM file descriptor does not record a positive capacity",
                    field="fileLength",
                )
            )
        return tuple(issues)

    def describe(self) -> str:
        """Return a human readable description of the mapping without reading a disk."""
        mode = "not recorded in mapping metadata"
        return "\n".join(
            (
                "RDM mapping",
                f"  descriptor: {self.descriptor}",
                f"  device id type: {int(self.diskId.type)}",
                f"  device id length: {int(self.diskId.len)}",
                f"  device id: {self.device_id.id!r}",
                f"  lun: {int(self.diskId.lun)}",
                f"  vendor: {self.device_id.vendor!r}",
                f"  model: {self.device_id.model!r}",
                f"  revision: {self.device_id.revision!r}",
                f"  capacity: {self.capacity} bytes",
                f"  device mode: {mode}",
                "  note: mapping metadata describes an external device; it is not disk content",
            )
        )

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly description of the mapping."""
        return {
            "device_id": self.device_id.as_dict(),
            "disk_id_type": int(self.diskId.type),
            "disk_id_len": int(self.diskId.len),
            "lun": int(self.diskId.lun),
            "vendor": self.device_id.vendor.decode("utf-8", "backslashreplace"),
            "model": self.device_id.model.decode("utf-8", "backslashreplace"),
            "revision": self.device_id.revision.decode("utf-8", "backslashreplace"),
            "capacity": self.capacity,
        }

    def bind(
        self,
        images: Iterable[RDMImage] | RDMImage,
        *,
        mode: RDMDeviceMode | str | None = None,
    ) -> RDMBinding:
        """Bind this mapping to exactly one explicitly supplied evidence image.

        Args:
            images: One or more evidence images. Only their explicitly supplied
                identity and capacity are used; their paths are never opened.
            mode: Optional expected device mode. When supplied, it must agree
                with the mode claimed by the evidence image.

        Raises:
            RDMValidationError: If the mapping or the evidence is missing,
                ambiguous, mismatched, or too small. The error contains every
                concrete issue found and the mapping description.
        """
        image_list = _coerce_images(images)
        expected_mode = RDMDeviceMode(mode) if isinstance(mode, str) else mode

        issues = list(self.validate_metadata())
        identity_matches = []
        identity_issues = []

        for image in image_list:
            if not image.identity.complete:
                identity_issues.append(
                    RDMValidationIssue(
                        "missing_device_identity",
                        "evidence image does not record a usable SCSI device id",
                        field="identity.id",
                        image=image.label,
                    )
                )
                continue

            reasons = self.device_id.mismatch_reasons(image.identity)
            if reasons:
                identity_issues.append(
                    RDMValidationIssue(
                        "device_identity_mismatch",
                        f"evidence identity differs from the RDM mapping in: {', '.join(reasons)}",
                        field="identity",
                        image=image.label,
                    )
                )
            else:
                identity_matches.append(image)

        if not image_list:
            issues.append(
                RDMValidationIssue(
                    "no_evidence_image",
                    "no evidence image was supplied for this RDM mapping",
                    field="images",
                )
            )
        elif len(identity_matches) > 1:
            labels = ", ".join(image.label for image in identity_matches)
            issues.append(
                RDMValidationIssue(
                    "ambiguous_image",
                    f"multiple supplied evidence images match the RDM device identity: {labels}",
                    field="identity",
                )
            )
        elif identity_matches:
            # Unrelated images in a larger evidence inventory are not errors,
            # as long as exactly one image is an unambiguous match.
            issues.extend(_validate_image(identity_matches[0], self, expected_mode))
        else:
            issues.extend(identity_issues)
            if all(not image.identity.complete for image in image_list):
                issues.append(
                    RDMValidationIssue(
                        "no_matching_image",
                        "no supplied evidence image records a comparable RDM device identity",
                        field="identity",
                    )
                )

        if issues:
            raise RDMValidationError(
                f"Cannot bind RDM mapping {self.descriptor} to the supplied evidence",
                issues=issues,
                mapping=self,
                images=image_list,
                descriptor=self.descriptor,
            )

        return RDMBinding(self, identity_matches[0])

    def __str__(self) -> str:
        return self.describe()


class RDMBinding(io.RawIOBase):
    """A read-only stream over the external disk bound to an RDM mapping.

    The stream serves bytes from the supplied evidence image only. It never
    exposes the VMFS RDM descriptor bytes and never opens a device path.
    """

    def __init__(self, mapping: RDMMapping, image: RDMImage):
        super().__init__()
        self.mapping = mapping
        self.image = image
        self.size = mapping.capacity
        self._pos = 0
        self._lock = Lock()

    @property
    def descriptor(self) -> FileDescriptor:
        """The RDM file descriptor this binding belongs to."""
        return self.mapping.descriptor

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed RDM binding")
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed RDM binding")
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == io.SEEK_END:
            new_pos = self.size + offset
        else:
            raise ValueError(f"invalid whence value {whence}")

        if new_pos < 0:
            raise ValueError(f"negative seek position {new_pos}")

        self._pos = new_pos
        return new_pos

    def read(self, n: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed RDM binding")
        if n is not None and n < -1:
            raise ValueError("invalid number of bytes to read")

        with self._lock:
            remaining = self.size - self._pos
            length = remaining if n == -1 or n is None else min(n, remaining)
            if length <= 0:
                return b""

            data = self._read_exact(self._pos, length)
            self._pos += length
            return data

    def readinto(self, buffer: bytearray) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a strict range without changing the stream position.

        Raises:
            RDMReadError: If the range exceeds the mapped capacity or the
                evidence image returns fewer bytes than requested. The error
                names the exact missing ranges.
        """
        if self.closed:
            raise ValueError("I/O operation on closed RDM binding")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        if length < 0:
            raise ValueError("length cannot be negative")
        if length == 0:
            return b""

        end = offset + length
        if end > self.size:
            missing_start = max(offset, self.size)
            raise RDMReadError(
                f"Requested range {offset:#x}+{length:#x} exceeds mapped capacity {self.size}",
                code="range_exceeds_capacity",
                requested_range=(offset, length),
                missing_ranges=((missing_start, end - missing_start),),
                image=self.image,
            )

        return self._read_exact(offset, length)

    def _read_exact(self, offset: int, length: int) -> bytes:
        try:
            data = self.image.read(offset, length)
        except RDMReadError:
            raise
        except (OSError, ValueError) as error:
            raise RDMReadError(
                f"Evidence image could not be read at {offset:#x}+{length:#x}: {error}",
                code="read_error",
                requested_range=(offset, length),
                missing_ranges=((offset, length),),
                image=self.image,
            ) from error

        if len(data) != length:
            missing = (offset + len(data), length - len(data))
            raise RDMReadError(
                f"Evidence image returned a short read at {offset:#x}: missing {missing[1]} bytes",
                code="short_read",
                requested_range=(offset, length),
                missing_ranges=(missing,),
                image=self.image,
            )
        return data

    def close(self) -> None:
        """Close this logical stream without closing the caller-owned evidence."""
        super().close()

    def __repr__(self) -> str:
        return f"<RDMBinding image={self.image.label!r} size={self.size}>"


def _coerce_images(images: Iterable[RDMImage] | RDMImage) -> list[RDMImage]:
    if isinstance(images, RDMImage):
        return [images]
    try:
        image_list = list(images)
    except TypeError:
        raise TypeError("images must be an RDMImage or an iterable of RDMImage objects") from None

    for image in image_list:
        if not isinstance(image, RDMImage):
            raise TypeError(f"Expected RDMImage, got {type(image).__name__}")
    return image_list


def _validate_image(
    image: RDMImage,
    mapping: RDMMapping,
    expected_mode: RDMDeviceMode | None,
) -> list[RDMValidationIssue]:
    issues = []
    effective_mode = image.mode if image.mode is not None else expected_mode

    if effective_mode is None:
        issues.append(
            RDMValidationIssue(
                "missing_device_mode",
                "evidence image does not state the RDM device mode; supply it with the evidence",
                field="mode",
                image=image.label,
            )
        )
    elif image.mode is not None and expected_mode is not None and image.mode != expected_mode:
        issues.append(
            RDMValidationIssue(
                "device_mode_mismatch",
                f"evidence image mode {image.mode.value!r} does not match expected mode {expected_mode.value!r}",
                field="mode",
                image=image.label,
            )
        )

    issues.extend(image.size_issues())

    image_size = image.available_size
    if image_size is None:
        issues.append(
            RDMValidationIssue(
                "missing_image_capacity",
                "evidence image does not declare a size and its stream is not seekable",
                field="size",
                image=image.label,
            )
        )
    elif mapping.capacity > 0 and image_size < mapping.capacity:
        issues.append(
            RDMValidationIssue(
                "image_capacity_insufficient",
                f"evidence image provides {image_size} bytes but the RDM mapping requires "
                f"{mapping.capacity} bytes",
                field="size",
                image=image.label,
            )
        )
    elif mapping.capacity > 0:
        issues.extend(_probe_readable(image, mapping.capacity))

    return issues


def _probe_readable(image: RDMImage, capacity: int) -> list[RDMValidationIssue]:
    """Probe the first and last mapped byte to validate the readable range.

    This is a boundary probe, not a full disk scan: it proves that the evidence
    can serve the start and end of the mapped range. Reads during actual use are
    still strict and report any later short read.
    """
    issues = []
    for offset in dict.fromkeys((0, capacity - 1)):
        try:
            data = image.read(offset, 1)
        except (OSError, ValueError) as error:
            issues.append(
                RDMValidationIssue(
                    "image_not_readable",
                    f"evidence image could not be read at offset {offset}: {error}",
                    field="range",
                    image=image.label,
                )
            )
            continue

        if len(data) != 1:
            issues.append(
                RDMValidationIssue(
                    "image_not_readable",
                    f"evidence image returned no data at offset {offset} of the mapped range",
                    field="range",
                    image=image.label,
                )
            )

    return issues


def check_rdm(
    descriptor: FileDescriptor,
    images: Iterable[RDMImage] | RDMImage,
    *,
    mode: RDMDeviceMode | str | None = None,
) -> list[RDMValidationIssue]:
    """Validate an RDM mapping against evidence without opening a disk stream.

    Returns an empty list when the binding would succeed. This is useful for
    producing a forensic report of missing evidence without granting read
    access to a partial image.

    Raises:
        NotAnRDMFileError: If ``descriptor`` is not an RDM file.
    """
    if not descriptor.is_rdm():
        raise NotAnRDMFileError(f"{descriptor} is not an RDM file")

    binding = None
    try:
        binding = descriptor.rdm_mapping.bind(images, mode=mode)
    except RDMValidationError as error:
        return list(error.issues)
    finally:
        if binding is not None:
            binding.close()

    return []


def bind_rdm(
    descriptor: FileDescriptor,
    images: Iterable[RDMImage] | RDMImage,
    *,
    mode: RDMDeviceMode | str | None = None,
) -> RDMBinding:
    """Bind an RDM file descriptor to explicitly supplied evidence.

    Args:
        descriptor: The RDM :class:`~dissect.vmfs.descriptor.FileDescriptor`.
        images: One or more :class:`RDMImage` objects supplied by the caller.
        mode: Optional expected device mode.

    Raises:
        NotAnRDMFileError: If ``descriptor`` is not an RDM file.
        RDMValidationError: If the mapping cannot be validated against the
            supplied evidence.
    """
    if not descriptor.is_rdm():
        raise NotAnRDMFileError(f"{descriptor} is not an RDM file")

    return descriptor.rdm_mapping.bind(images, mode=mode)
