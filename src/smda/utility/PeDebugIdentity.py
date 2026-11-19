"""CodeView identity a PE carries about its own PDB.

The only identifier a target binary can speak for itself is the CodeView record in
its debug directory: an "RSDS" (PDB 7.0) entry holds the GUID and age the linker
wrote for the PDB it produced. Everything else that links a PDB to an analysis --
the path the caller passed, the PDB file name the record happens to spell -- is a
claim by one side, not evidence the two were built together.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

import lief

from smda.utility.lief_helper import lief_name

LOGGER = logging.getLogger(__name__)

# purepdb marks a section executable from these same COFF flags; read the raw
# characteristics so the two sides classify a section identically.
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class PeCodeViewIdentity:
    """The GUID/age of the PDB a PE's own debug directory asks for.

    ``guid`` is stored in CodeView byte order, the same layout purepdb's
    :meth:`PDB.info` returns, so the two compare directly without a conversion.
    """

    guid: bytes
    age: int
    pdb_path: str


@dataclass(frozen=True)
class PeSectionLayout:
    """The section shape a PE's own headers describe, in image-relative terms."""

    name: str
    virtual_address: int
    virtual_size: int
    executable: bool


def _codeview_guid_bytes(guid) -> bytes | None:
    """Normalize lief's CodeView GUID to its on-disk (CodeView) byte order."""
    if isinstance(guid, bytes):
        return guid if len(guid) == 16 else None
    if isinstance(guid, uuid.UUID):
        return guid.bytes_le
    if isinstance(guid, str):
        try:
            return uuid.UUID(guid).bytes_le
        except ValueError:
            return None
    return None


def extract_codeview_identity(binary_info) -> PeCodeViewIdentity | None:
    """Read the RSDS CodeView record from a PE's debug directory.

    Returns None for anything that is not a PE, has no CodeView PDB record, or
    holds a GUID in a shape we cannot use. Such a target simply has no identity
    evidence; the caller decides what an unverifiable PDB is worth.
    """
    parsed_binary = binary_info.getLiefBinary()
    if not isinstance(parsed_binary, lief.PE.Binary):
        return None
    for entry in parsed_binary.debug:
        if not isinstance(entry, lief.PE.CodeViewPDB):
            continue
        if entry.cv_signature != lief.PE.CodeViewPDB.SIGNATURES.PDB_70:
            continue
        guid = _codeview_guid_bytes(entry.guid)
        if guid is None:
            LOGGER.warning("CodeView record in %s carries no usable GUID", binary_info.file_path or "the target")
            return None
        return PeCodeViewIdentity(guid=guid, age=int(entry.age), pdb_path=lief_name(entry, "filename"))
    return None


def extract_section_layout(binary_info) -> list[PeSectionLayout]:
    """Read a PE's section table in the same RVA terms a PDB's sections use."""
    parsed_binary = binary_info.getLiefBinary()
    if not isinstance(parsed_binary, lief.PE.Binary):
        return []
    layout = []
    for section in parsed_binary.sections:
        characteristics = int(section.characteristics)
        layout.append(
            PeSectionLayout(
                name=lief_name(section),
                virtual_address=int(section.virtual_address),
                virtual_size=int(section.virtual_size or section.sizeof_raw_data),
                executable=bool(characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)),
            )
        )
    return layout
