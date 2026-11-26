"""A library for installing Python wheels."""

__version__ = "1.1.0"
__all__ = [
    "MissingRequirement",
    "OmittedMember",
    "PartialInstallResult",
    "UninstallableDistribution",
    "install",
    "install_partial",
]

from installer._core import OmittedMember, PartialInstallResult, install, install_partial
from installer.exceptions import MissingRequirement, UninstallableDistribution
