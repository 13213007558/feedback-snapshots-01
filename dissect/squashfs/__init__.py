from __future__ import annotations

from dissect.squashfs.consistency import (
    ConsistencyReport,
    DirectoryEntryEvidence,
    check_consistency,
)
from dissect.squashfs.exceptions import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.squashfs import FileStream, INode, SquashFS

__all__ = [
    "ConsistencyReport",
    "DirectoryEntryEvidence",
    "Error",
    "FileNotFoundError",
    "FileStream",
    "INode",
    "NotADirectoryError",
    "NotAFileError",
    "NotASymlinkError",
    "SquashFS",
    "check_consistency",
]
