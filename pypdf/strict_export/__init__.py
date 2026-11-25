"""Strict export decisions for pypdf.

This module answers one question precisely:

*Can a PDF be written with incremental saves while still guaranteeing that a
piece of sensitive material is gone from the bytes handed to an outsider?*

Incremental saving (``PdfWriter(..., incremental=True)``) keeps every byte of
the document it was built from and only appends a new revision. Removing an
object from the page tree therefore leaves the object's old bytes in the
history, where they can still be read. A non-incremental ("full") rewrite only
emits objects reachable from the trailer, so unreferenced material is dropped.

The functions here make that distinction explicit instead of leaving it to the
caller to guess, and they verify the produced bytes rather than trusting the
write mode.
"""

from ._strict_export import (
    ExportDecision,
    StrictExportError,
    SecretRemainsError,
    byte_ranges_for_token,
    evaluate_export,
    export_strict,
    source_contains_token,
)

__all__ = [
    "ExportDecision",
    "StrictExportError",
    "SecretRemainsError",
    "byte_ranges_for_token",
    "evaluate_export",
    "export_strict",
    "source_contains_token",
]
