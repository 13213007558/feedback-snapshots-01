"""Shared LIEF import-table parsers keyed by slot address."""

import lief

from smda.common.labelprovider.OrdinalHelper import OrdinalHelper
from smda.utility.lief_helper import lief_name


def resolve_pe_base_addr(lief_binary, base_addr=None):
    if base_addr is None:
        return getattr(lief_binary, "imagebase", 0)
    return base_addr


def parse_pe_imports(lief_binary, base_addr=None):
    if not hasattr(lief_binary, "imports"):
        return {}
    active_base = resolve_pe_base_addr(lief_binary, base_addr)
    import_symbols = {}
    for imported_library in lief_binary.imports:
        lib_name_lower = lief_name(imported_library).lower()
        for func in imported_library.entries:
            func_name = lief_name(func)
            if func_name:
                import_symbols[func.iat_address + active_base] = (
                    lib_name_lower,
                    func_name,
                )
            elif func.is_ordinal:
                resolved_ordinal = OrdinalHelper.resolveOrdinal(lib_name_lower, func.ordinal)
                ordinal_name = resolved_ordinal if resolved_ordinal else f"#{func.ordinal}"
                import_symbols[func.iat_address + active_base] = (
                    lib_name_lower,
                    ordinal_name,
                )
    return import_symbols


def parse_pe_delay_imports(lief_binary, base_addr=None):
    if not hasattr(lief_binary, "delay_imports"):
        return {}
    if not lief_binary.has_delay_imports:
        return {}
    active_base = resolve_pe_base_addr(lief_binary, base_addr)
    magic = getattr(lief_binary.optional_header, "magic", None)
    ptr_size = 8 if magic is not None and magic == lief.PE.PE_TYPE.PE32_PLUS else 4
    import_symbols = {}
    for delay_import in lief_binary.delay_imports:
        lib_name_lower = lief_name(delay_import).lower()
        for index, func in enumerate(delay_import.entries):
            slot_addr = active_base + delay_import.iat + index * ptr_size
            func_name = lief_name(func)
            if func_name:
                import_symbols[slot_addr] = (lib_name_lower, func_name)
            elif func.is_ordinal:
                resolved_ordinal = OrdinalHelper.resolveOrdinal(lib_name_lower, func.ordinal)
                ordinal_name = resolved_ordinal if resolved_ordinal else f"#{func.ordinal}"
                import_symbols[slot_addr] = (lib_name_lower, ordinal_name)
    return import_symbols


def elf_symbol_version(symbol):
    """Return the version a dynamic symbol is bound as, or None when it states none.

    A version requirement is what distinguishes ``memcpy@GLIBC_2.2.5`` from
    ``memcpy@GLIBC_2.14``; the bare name alone cannot, so it is carried separately rather
    than folded into the name.
    """
    symbol_version = getattr(symbol, "symbol_version", None)
    if not getattr(symbol, "has_version", False) or not symbol_version:
        return None
    if not getattr(symbol_version, "has_auxiliary_version", False):
        return None
    auxiliary = getattr(symbol_version, "symbol_version_auxiliary", None)
    if auxiliary is None:
        return None
    return lief_name(auxiliary) or None


def elf_symbol_is_weak(symbol):
    """Whether the dynamic symbol is declared weak.

    An *undefined weak* import is allowed to resolve to zero; treating it like a strong
    import is what lets an unbound PLT slot look like a confirmed call.
    """
    binding = getattr(symbol, "binding", None)
    weak = getattr(getattr(lief.ELF, "Symbol", None), "BINDING", None)
    weak = getattr(weak, "WEAK", None)
    if weak is None:
        return None
    try:
        return binding == weak
    except TypeError:
        return None


def _relocation_type_name(relocation):
    relocation_type = getattr(relocation, "type", None)
    return getattr(relocation_type, "name", None) or str(relocation_type)


def parse_elf_relocation_evidence(lief_binary):
    """Return relocation claims keyed by slot address: addr -> [ElfCallEvidence].

    The claims keep name, version and weakness separate. A slot can carry several
    relocations (a ``GLOB_DAT`` beside a lazy ``JUMP_SLOT``, a TLS pair); those are kept,
    not collapsed. Names stay exactly as the dynamic symbol table spells them: API
    resolution is keyed by them, so they must remain comparable with PE and Mach-O imports,
    and synthesis writes them back into an import table.
    """
    from smda.common.labelprovider.ElfCallEvidence import RELOCATION, ElfCallEvidence

    if not isinstance(lief_binary, lief.ELF.Binary):
        return {}
    evidence = {}
    for relocation in lief_binary.relocations:
        if not relocation.has_symbol:
            continue
        symbol = relocation.symbol
        if symbol is None:
            continue
        if not symbol.imported or not symbol.is_function:
            continue
        symbol_name = lief_name(symbol)
        if not symbol_name:
            continue
        version = elf_symbol_version(symbol)
        claim = ElfCallEvidence(
            RELOCATION,
            symbol_name,
            version=version,
            library=version,
            weak=elf_symbol_is_weak(symbol),
            slot=relocation.address,
            detail=_relocation_type_name(relocation),
        )
        evidence.setdefault(relocation.address, []).append(claim)
    return evidence


def parse_elf_relocation_imports(lief_binary):
    """Build import map keyed by relocation slot address: addr -> (lib, name).

    The ``lib`` field of an ELF import entry is the symbol's version requirement, matching
    the long-standing ``GLIBC_2.2.5`` convention. The version is also kept on the evidence
    model, so consumers that need to tell same-named versions apart read it from there.

    A slot whose relocations name more than one identity is left out: the map can only hold
    one ``(lib, name)`` per slot, and writing the first one down would be the very merge by
    base name that the version is there to prevent. The claims remain available from
    :func:`parse_elf_relocation_evidence` and are what the report's evidence table carries.
    """
    import_map = {}
    for address, claims in parse_elf_relocation_evidence(lief_binary).items():
        identities = []
        for claim in claims:
            if claim.identity not in identities:
                identities.append(claim.identity)
        if len(identities) > 1:
            continue
        claim = claims[0]
        import_map[address] = (claim.version or claim.library, claim.name)
    return import_map


def parse_macho_bindings(lief_binary, adjustment=0):
    if not isinstance(lief_binary, lief.MachO.Binary):
        return {}
    imports = {}
    for binding in getattr(lief_binary, "bindings", []):
        try:
            symbol_name = lief_name(binding.symbol) if getattr(binding, "has_symbol", False) else ""
            if binding.address != 0 and symbol_name:
                lib_name = ""
                if getattr(binding, "has_library", False) and binding.library:
                    lib_name = lief_name(binding.library).lower()
                adjusted_addr = binding.address + adjustment
                imports[adjusted_addr] = (lib_name, symbol_name)
        except Exception:
            continue
    return imports
