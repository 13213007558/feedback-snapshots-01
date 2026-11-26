"""Errors raised from this package."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

MissingKind = Literal["library", "entry_point", "member", "record", "metadata"]


@dataclass(frozen=True)
class MissingRequirement:
    """A required part of a distribution that cannot be installed.

    Instances are exposed on :any:`UninstallableDistribution`, so callers can
    inspect exact reasons instead of parsing an error message.
    """

    kind: MissingKind
    """Category of the missing requirement."""

    name: str
    """Name of the missing requirement (a wheel path or script name)."""

    scheme: str | None = None
    """Installation scheme that the requirement would have been written to."""

    path: str | None = None
    """Destination path within ``scheme`` that would have received the member."""

    def __str__(self) -> str:
        if self.kind == "library":
            return (
                f"required library member {self.name!r} targets unapproved "
                f"scheme {self.scheme!r}"
            )
        if self.kind == "entry_point":
            return (
                f"required entry point {self.name!r} targets unapproved "
                f"scheme {self.scheme!r}"
            )
        if self.kind == "member":
            return (
                f"required wheel member {self.name!r} targets unapproved "
                f"scheme {self.scheme!r}"
            )
        if self.kind == "record":
            return (
                f"completion record {self.name!r} targets unapproved "
                f"scheme {self.scheme!r}"
            )
        return (
            f"required installation metadata {self.name!r} targets unapproved "
            f"scheme {self.scheme!r}"
        )


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class UninstallableDistribution(InstallerError):
    """When a distribution cannot be installed under the approved schemes.

    Raised before any file is written to the destination. ``missing`` contains
    the concrete requirements that prevented installation.
    """

    def __init__(
        self,
        *,
        distribution: str,
        version: str,
        missing: Iterable[MissingRequirement],
    ) -> None:
        self.distribution = distribution
        self.version = version
        self.missing = tuple(missing)
        details = "; ".join(str(item) for item in self.missing)
        super().__init__(f"Cannot install {distribution} {version}: {details}")
