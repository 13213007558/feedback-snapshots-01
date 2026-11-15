from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.squashfs.exceptions import (
    Error,
    FileNotFoundError,
    InvalidIDError,
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.identity import IdLookup
from dissect.squashfs.squashfs import FileStream, INode, SquashFS

if TYPE_CHECKING:
    from dissect.squashfs.manifest import (
        HardLinkGroup,
        InventoryOptions,
        PermissionEntry,
        PermissionManifest,
        build_permission_manifest,
    )

__all__ = [
    "Error",
    "FileNotFoundError",
    "FileStream",
    "HardLinkGroup",
    "INode",
    "IdLookup",
    "InvalidIDError",
    "InventoryOptions",
    "NotADirectoryError",
    "NotAFileError",
    "NotASymlinkError",
    "PermissionEntry",
    "PermissionManifest",
    "SquashFS",
    "build_permission_manifest",
]

# The manifest module is imported lazily so that ``python -m
# dissect.squashfs.manifest`` does not import it twice (once through this
# package and once as ``__main__``).
_MANIFEST_EXPORTS = frozenset(
    {
        "HardLinkGroup",
        "InventoryOptions",
        "PermissionEntry",
        "PermissionManifest",
        "build_permission_manifest",
    }
)


def __getattr__(name: str) -> Any:
    """Expose the permission inventory API without importing it eagerly."""
    if name in _MANIFEST_EXPORTS:
        from dissect.squashfs import manifest

        value = getattr(manifest, name)
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
