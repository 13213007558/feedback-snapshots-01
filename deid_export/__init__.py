"""Explicitly approved, fail-closed DICOM de-identification and export.

The package separates *preparation* (resolving every deferred element and
applying one explicit de-identification policy in memory) from *commit*
(an atomic write that leaves either a finished, verified file or nothing).
"""

from deid_export.core import (
    DeidentificationError,
    DeidentificationStrategy,
    PreparedDataset,
    SourceUnavailableError,
    export_deidentified,
    prepare_deidentified,
)

__all__ = [
    "DeidentificationError",
    "DeidentificationStrategy",
    "PreparedDataset",
    "SourceUnavailableError",
    "export_deidentified",
    "prepare_deidentified",
]
