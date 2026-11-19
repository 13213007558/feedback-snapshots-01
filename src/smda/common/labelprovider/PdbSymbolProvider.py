#!/usr/bin/python

import logging
import os
from bisect import bisect_right

import purepdb

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.utility.PeDebugIdentity import extract_codeview_identity, extract_section_layout

from .AbstractLabelProvider import AbstractLabelProvider
from .MsvcDemangler import demangle_msvc_symbol
from .rust_demangler import demangle
from .RustSymbolEvidence import is_rust_language_evidence

LOGGER = logging.getLogger(__name__)

PDB_MAGIC = b"Microsoft C/C++"
IMPORT_MODULE_PREFIX = "Import:"

# A PDB the target binary itself vouches for: its CodeView GUID and age match.
IDENTITY_VERIFIED = "verified"
# The target has a CodeView record and it names a different PDB. Such a PDB must
# never label the target, no matter how plausible its symbols look.
IDENTITY_MISMATCH = "mismatch"
# Neither side can produce an identity record, so nothing proves the pairing.
IDENTITY_UNVERIFIABLE = "unverifiable"
# No PDB was offered or it yielded no symbols.
IDENTITY_NOT_LOADED = "not_loaded"


def _demangleSymbolName(name):
    """Return the readable form of an MSVC or Rust symbol, or the name as the PDB spells it."""
    try:
        if name.startswith("?"):
            return demangle_msvc_symbol(name)
        if is_rust_language_evidence(name):
            demangled = demangle(name)
            if demangled:
                return demangled
    except Exception as exc:
        reraise_non_operational_exception(exc)
        LOGGER.debug("Failed to demangle symbol %s: %s", name, exc)
    return name


class PdbSymbolProvider(AbstractLabelProvider):
    """Resolver for PDB symbols. MSVC and Rust names are demangled; every other name is
    reported as the PDB stores it.

    A PDB is only treated as evidence about the analyzed sample once the sample's own
    CodeView record confirms the pairing. A PDB that belongs to another binary is rejected,
    and one whose identity cannot be established stays unloaded rather than stamping the
    sample with names the sample itself never asked for.
    """

    def __init__(self, config):
        self._config = config
        self._base_addr = 0
        self._func_symbols = {}
        self._procedure_starts = []
        self._procedure_extents = []
        self._loaded_pdb_path = ""
        self._target_binary_info = None
        self.identity_status = IDENTITY_NOT_LOADED
        self.identity_reason = ""
        self._out_of_section_symbols = 0

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def bindTargetBinary(self, binary_info):
        """Record the analyzed sample so a later PDB update can be checked against it."""
        self._target_binary_info = binary_info

    def update(self, binary_info):
        self._func_symbols = {}
        self._procedure_starts = []
        self._procedure_extents = []
        self._out_of_section_symbols = 0
        self.identity_status = IDENTITY_NOT_LOADED
        self.identity_reason = ""
        self._base_addr = binary_info.base_addr
        if not binary_info.file_path:
            return
        binary_data = binary_info.getBinaryData()
        if not binary_data:
            return
        if binary_data[: len(PDB_MAGIC)] != PDB_MAGIC:
            self._warnAboutUnusedPdb(binary_info.file_path)
            return
        try:
            pdb = purepdb.PDB.from_bytes(binary_data)
            verdict, reason = self._checkIdentity(pdb, binary_info.file_path)
            self.identity_status = verdict
            self.identity_reason = reason
            if verdict != IDENTITY_VERIFIED:
                LOGGER.warning('Rejecting PDB "%s": %s', binary_info.file_path, reason)
                return
            self._parseSymbols(pdb)
            self._loaded_pdb_path = binary_info.file_path
            self._warnAboutThinPdb(binary_info.file_path, pdb)
            if self._out_of_section_symbols:
                LOGGER.warning(
                    'PDB "%s" names %d symbol(s) outside the target\'s sections; '
                    "they were left unlabelled rather than relocated across the mismatch",
                    binary_info.file_path,
                    self._out_of_section_symbols,
                )
        except Exception as exc:
            reraise_non_operational_exception(exc)
            LOGGER.warning('Failed parsing PDB "%s" with exception: %r', binary_info.file_path, exc)

    def _checkIdentity(self, pdb, file_path):
        """Decide whether the PDB may speak for the bound target, and why.

        The target's CodeView record is the only primary identity evidence. A matching
        GUID and age verify the pairing; a conflicting record rejects it outright. When
        neither the target nor the PDB carries an identity, section layout is still worth
        checking, but cannot promote the pairing to verified.
        """
        target = self._target_binary_info
        if target is None:
            return IDENTITY_UNVERIFIABLE, "no target binary is bound to the PDB provider"
        target_identity = extract_codeview_identity(target)
        try:
            pdb_info = pdb.info()
        except purepdb.PdbError as exc:
            return IDENTITY_UNVERIFIABLE, f"the PDB carries no readable identity record ({exc})"
        if target_identity is not None:
            if target_identity.guid == pdb_info.guid and target_identity.age == pdb_info.age:
                section_issue = self._sectionMismatch(pdb, target)
                if section_issue:
                    return IDENTITY_MISMATCH, section_issue
                return IDENTITY_VERIFIED, "CodeView GUID and age match the target"
            return (
                IDENTITY_MISMATCH,
                "the target's CodeView record names a different PDB "
                f"(target guid {target_identity.guid.hex()} age {target_identity.age}, "
                f"pdb guid {pdb_info.guid.hex()} age {pdb_info.age})",
            )
        section_issue = self._sectionMismatch(pdb, target)
        if section_issue:
            return IDENTITY_MISMATCH, section_issue
        return (
            IDENTITY_UNVERIFIABLE,
            "the target has no CodeView identity record, so the PDB cannot be confirmed as its own",
        )

    def _sectionMismatch(self, pdb, target):
        """Compare the PDB's section table with the target's own section layout.

        A PDB resolves its symbols to RVAs through exactly this table, so a differing
        table means the resolved addresses land in the wrong sections. Empty on a match
        or when the PDB has no section table to compare.
        """
        pdb_sections = pdb.sections
        if not pdb_sections:
            return ""
        target_sections = extract_section_layout(target)
        if not target_sections:
            return ""
        if len(pdb_sections) != len(target_sections):
            return (
                f"section count differs: the PDB describes {len(pdb_sections)} section(s), "
                f"the target {len(target_sections)}"
            )
        for index, (pdb_section, target_section) in enumerate(zip(pdb_sections, target_sections, strict=True)):
            if pdb_section.virtual_address != target_section.virtual_address:
                return (
                    f"section {index} ({target_section.name}) is at RVA "
                    f"{target_section.virtual_address:#x} in the target but "
                    f"{pdb_section.virtual_address:#x} in the PDB"
                )
            if pdb_section.virtual_size != target_section.virtual_size:
                return (
                    f"section {index} ({target_section.name}) has size "
                    f"{target_section.virtual_size:#x} in the target but "
                    f"{pdb_section.virtual_size:#x} in the PDB"
                )
        return ""

    def _warnAboutUnusedPdb(self, file_path):
        if self._loaded_pdb_path:
            return
        if file_path.lower().endswith(".pdb"):
            LOGGER.warning('"%s" is not a PDB file - no symbols were loaded from it.', file_path)
            return
        candidate = os.path.splitext(file_path)[0] + ".pdb"
        if os.path.isfile(candidate):
            LOGGER.warning(
                'Ignoring "%s" next to "%s" - pass it explicitly to use its symbols.',
                candidate,
                file_path,
            )

    def _warnAboutThinPdb(self, file_path, pdb):
        if self._func_symbols and self._procedure_starts:
            return
        if self._func_symbols:
            subject = "no procedure records, so no code sizes and no fragment attribution"
        else:
            subject = "no usable symbols"
        reasons = "; ".join(pdb.diagnose().warnings)
        LOGGER.warning('"%s" yielded %s%s', file_path, subject, f": {reasons}" if reasons else "")

    def _rvaFitsTargetSections(self, rva):
        target = self._target_binary_info
        if target is None:
            return True
        target_sections = extract_section_layout(target)
        # no section evidence means no grounds to reject a symbol; the identity gate above
        # already decided whether this PDB may speak at all
        if not target_sections:
            return True
        for section in target_sections:
            if section.virtual_address <= rva < section.virtual_address + max(section.virtual_size, 1):
                return True
        return False

    def _parseSymbols(self, pdb):
        procedures = []
        for function in pdb.functions():
            if function.rva is None:
                continue
            if not self._rvaFitsTargetSections(function.rva):
                self._out_of_section_symbols += 1
                continue
            address = self._base_addr + function.rva
            name = _demangleSymbolName(function.name)
            if not name or any(char < " " or char == "\x7f" for char in name):
                # a PDB string table holds whatever bytes were written into it, and this name
                # travels into the serialized report; the test is for control characters
                # rather than for non-ASCII, which a demangled Rust identifier legitimately is
                continue
            self._func_symbols[address] = name
            module = function.module or ""
            if function.code_size and not module.startswith(IMPORT_MODULE_PREFIX):
                procedures.append((address, address + function.code_size, name))
        procedures.sort()
        self._procedure_starts = [start for start, _, _ in procedures]
        self._procedure_extents = [(end, name) for _, end, name in procedures]

    def _getFragmentLabel(self, address):
        index = bisect_right(self._procedure_starts, address) - 1
        if index < 0:
            return ""
        start = self._procedure_starts[index]
        end, name = self._procedure_extents[index]
        if address >= end:
            return ""
        return f"{name}$+0x{address - start:x}"

    def getSymbol(self, address):
        symbol = self._func_symbols.get(address, "")
        if symbol:
            return symbol
        return self._getFragmentLabel(address)

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)
