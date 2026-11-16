from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.regf.regf import HiveIntegrity


class Error(Exception):
    pass


class HiveIntegrityError(Error):
    """Raised when a hive is opened with ``strict=True`` and fails an integrity check."""

    def __init__(self, integrity: HiveIntegrity):
        self.integrity = integrity
        super().__init__(f"Hive {integrity.filename!r} failed integrity checks: {integrity.summary()}")


class HiveStructureError(Error):
    """Raised when a cell or hbin lies outside the structural bounds of the hive."""


class RegistryKeyNotFoundError(Error):
    pass


class RegistryValueNotFoundError(Error):
    pass
