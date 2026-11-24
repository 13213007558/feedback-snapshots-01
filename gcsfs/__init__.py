import logging
import os

try:
    from ._version import __version__  # noqa: F401
except ImportError:
    try:
        from importlib.metadata import PackageNotFoundError, version

        __version__ = version("gcsfs")
    except (ImportError, PackageNotFoundError):
        __version__ = "unknown"

logger = logging.getLogger(__name__)
from .commits import (
    check_commit,
    confirm_before_retry,
    confirm_commit,
    parse_upload_status,
    recover_commit,
    resolve_commit,
    safe_retry_commit,
)
from .core import GCSFileSystem
from .mapping import GCSMap
from .retry import (
    AmbiguousCommitError,
    CommitConfirmation,
    CommitConflict,
    CommitConflictError,
    CommitOutcome,
    CommitReceipt,
    CommitResult,
    CommitState,
    CommitStatus,
    CommitTicket,
    CommitToken,
    GenerationMismatchError,
    PendingCommit,
    PendingCommitError,
    UnconfirmedCommitError,
    UnknownCommitError,
    UploadReceipt,
    WriteReceipt,
    WriteResult,
)

if os.getenv("GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT", "true").lower() in ("true", "1"):
    try:
        from .extended_gcsfs import ExtendedGcsFileSystem as GCSFileSystem

        logger.info(
            "gcsfs experimental features enabled via GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT."
        )
    except ImportError as e:
        logger.warning(
            f"GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT is set, but failed to import experimental features: {e}"
        )
        # Fallback to core GCSFileSystem, do not register here

__all__ = [
    "AmbiguousCommitError",
    "CommitConfirmation",
    "CommitConflict",
    "CommitConflictError",
    "CommitOutcome",
    "CommitReceipt",
    "CommitResult",
    "CommitState",
    "CommitStatus",
    "CommitTicket",
    "CommitToken",
    "GCSFileSystem",
    "GCSMap",
    "GenerationMismatchError",
    "PendingCommit",
    "PendingCommitError",
    "UnconfirmedCommitError",
    "UnknownCommitError",
    "UploadReceipt",
    "WriteReceipt",
    "WriteResult",
    "check_commit",
    "confirm_before_retry",
    "confirm_commit",
    "parse_upload_status",
    "recover_commit",
    "resolve_commit",
    "safe_retry_commit",
]
