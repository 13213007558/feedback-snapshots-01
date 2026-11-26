"""Errors used by the deployment reference and its test doubles."""

from installer.exceptions import InstallerError


class TransitReadError(IOError, InstallerError):
    """Raised when a source stream fails *while bytes are being read*.

    This models a remote object store / HTTP connection that resets halfway
    through a member, i.e. after some bytes have already been handed to the
    destination.
    """


class WriteOnceViolation(InstallerError):
    """Raised when a write-once target is asked to reuse a key or session."""


class CommitFailed(InstallerError):
    """Raised when promoting a staging directory into the final tree fails."""


class VerificationFailure(InstallerError):
    """Raised when independently read-back landing bytes do not match RECORD."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))
