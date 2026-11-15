from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.vmfs.descriptor import FileDescriptor
    from dissect.vmfs.rdm import RDMMapping, RDMValidationIssue


class Error(Exception):
    pass


class VolumeNotAvailableError(Error):
    pass


class InvalidHeader(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class RDMError(Error):
    """Base class for errors raised while interpreting or reading an RDM mapping."""


class RDMValidationError(RDMError):
    """The RDM mapping could not be bound to the supplied evidence image.

    Attributes:
        issues: The concrete validation problems found while binding.
        mapping: The RDM mapping that was being bound, if available.
        images: The evidence images that were considered.
        descriptor: The RDM file descriptor that was being bound.
    """

    def __init__(
        self,
        message: str,
        *,
        issues: Sequence[RDMValidationIssue] = (),
        mapping: RDMMapping | None = None,
        images: Sequence[object] = (),
        descriptor: FileDescriptor | None = None,
    ):
        self.issues = tuple(issues)
        self.mapping = mapping
        self.images = tuple(images)
        self.descriptor = descriptor

        if self.issues:
            message = f"{message}: " + "; ".join(str(issue) for issue in self.issues)
        super().__init__(message)

    @property
    def codes(self) -> tuple[str, ...]:
        """The machine readable validation issue codes."""
        return tuple(issue.code for issue in self.issues)


class RDMNotBoundError(RDMValidationError):
    """An RDM file was opened without a bound evidence image."""


class RDMReadError(RDMError):
    """A requested range could not be read from the evidence image.

    Attributes:
        code: The machine readable reason for the read failure.
        requested_range: The ``(offset, length)`` that was requested.
        missing_ranges: The parts of the requested range that are not available.
        image: The evidence image that was used.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "read_error",
        requested_range: tuple[int, int] | None = None,
        missing_ranges: Sequence[tuple[int, int]] = (),
        image: object = None,
    ):
        super().__init__(message)
        self.code = code
        self.requested_range = requested_range
        self.missing_ranges = tuple(missing_ranges)
        self.image = image


class NotAnRDMFileError(RDMError):
    pass
