from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.apfs.checkpoint import CheckpointReport


class Error(Exception):
    pass


class CheckpointError(Error):
    """Raised when no checkpoint superblock in the container can be proven consistent."""

    def __init__(self, report: CheckpointReport):
        self.report = report
        super().__init__(
            "No consistent checkpoint superblock found in the valid descriptor window. "
            f"Selection report:\n{report.describe()}"
        )


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass
