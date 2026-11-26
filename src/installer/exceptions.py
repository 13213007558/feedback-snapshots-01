"""Errors raised from this package."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from installer.update import UpdateConflict


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class UpdateConflictError(InstallerError):
    """When a safe update cannot account for all the files involved.

    The conflicting files are available in ``conflicts``. Nothing has been
    modified when this is raised.
    """

    def __init__(self, conflicts: "list[UpdateConflict]") -> None:
        """Initialize with the conflicting files."""
        self.conflicts = list(conflicts)
        details = ", ".join(
            f"{conflict.path} ({conflict.reason})" for conflict in self.conflicts
        )
        super().__init__(f"Cannot safely update, unconfirmed files: {details}")


class UpdateFailedError(InstallerError):
    """When a safe update failed midway.

    The previous installation has been restored when this is raised, and can
    still be verified against its approved install record.
    """
