#!/usr/bin/python
import logging

import lief

from .AbstractLabelProvider import AbstractLabelProvider
from .ElfSymbolProvider import parse_relocation_imports
from .import_parsers import parse_elf_relocation_evidence

lief.logging.disable()
LOGGER = logging.getLogger(__name__)


class ElfApiResolver(AbstractLabelProvider):
    """ELF API reference resolver: relocation-declared imports plus observed slot state.

    The resolver keeps two views, and they are not interchangeable:

    * ``_api_map["lief"]`` is the legacy ``(lib, name)`` view keyed by slot, kept for callers
      that only want a display string;
    * ``_relocation_evidence`` is the structured claim list, with the symbol version and the
      weak flag that the legacy view has to drop to stay a two-tuple.

    ``getApi`` only answers while the slot's claims agree. A same-named pair for two versions
    is a conflict, so it returns no name at all, and the call site stays unknown rather than
    silently picking the first spelling the relocation table happens to contain.
    """

    def __init__(self, config):
        self._api_map = {"lief": {}}
        self._relocation_evidence = {}

    def update(self, binary_info):
        # Gate on the parsed ELF type rather than is_buffer: a memory dump / raw buffer that LIEF
        # parses as an ELF still exposes its relocation table, so imported APIs remain resolvable
        # here. Non-ELF input (raw shellcode, PE, DEX) fails the isinstance check and is skipped.
        self._api_map["lief"] = {}
        self._relocation_evidence = {}
        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.ELF.Binary):
            return

        self._api_map["lief"] = parse_relocation_imports(lief_binary)
        self._relocation_evidence = parse_elf_relocation_evidence(lief_binary)

    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return True

    def isSymbolProvider(self):
        return False

    def getSymbol(self, address):
        return ""

    def getFunctionSymbols(self):
        return {}

    def getRelocationEvidence(self, slot_addr):
        """Every relocation claim about one slot, as structured evidence."""
        return list(self._relocation_evidence.get(slot_addr, ()))

    def getApi(self, to_addr, absolute_addr=None):
        """
        If the LabelProvider has any information about a used API for the given address, return (dll, api), else return (None, None).

        May return None for the `dll` if it cannot be determined.
        When it can be determined for ELF files, the `dll` field should be interpreted as the API version rather than shared library name.
        For example: "GLIBC_2.2.5".
        `absolute_addr` is part of the label-provider API but intentionally unused here:
        ELF lookups are keyed by relocation slot address (`to_addr`) in `_api_map["lief"]`.
        """
        claims = self._relocation_evidence.get(to_addr)
        if claims:
            identities = {claim.identity for claim in claims}
            if len(identities) > 1:
                # same base name, different version (or different weak flag): no single
                # answer exists, and the caller must not be handed one
                return (None, None)
        return self._api_map["lief"].get(to_addr, (None, None))

    def is_active(self):
        return bool(self._api_map.get("lief"))
