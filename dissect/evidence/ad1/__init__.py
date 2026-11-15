from __future__ import annotations

from dissect.evidence.ad1.ad1 import AD1, FileEntry, FileMeta, LogicalImage, MetaType, SegmentFile
from dissect.evidence.ad1.stream import AD1Stream, FileStream
from dissect.evidence.ad1.verify import (
    AD1VerificationReport,
    AD1VerificationResult,
    AD1VerificationStatus,
    DigestResult,
    VerificationReport,
    VerificationResult,
    VerificationStatus,
    verify,
    verify_ad1,
    verify_entries,
    verify_file,
)
from dissect.evidence.exception import (
    DigestMismatchError,
    Error,
    FileNotFoundError,
    IncompleteReadError,
    InvalidDigestError,
    MissingDigestError,
    NotADirectoryError,
    NotASymlinkError,
    VerificationError,
)

__all__ = [
    "AD1",
    "AD1Stream",
    "AD1VerificationReport",
    "AD1VerificationResult",
    "AD1VerificationStatus",
    "DigestMismatchError",
    "DigestResult",
    "Error",
    "FileEntry",
    "FileMeta",
    "FileNotFoundError",
    "FileStream",
    "IncompleteReadError",
    "InvalidDigestError",
    "LogicalImage",
    "MetaType",
    "MissingDigestError",
    "NotADirectoryError",
    "NotASymlinkError",
    "SegmentFile",
    "VerificationError",
    "VerificationReport",
    "VerificationResult",
    "VerificationStatus",
    "verify",
    "verify_ad1",
    "verify_entries",
    "verify_file",
]
