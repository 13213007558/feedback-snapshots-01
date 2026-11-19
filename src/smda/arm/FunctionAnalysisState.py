"""Per-function analysis state for the ARM backend.

Adds the per-block scratch the ARM classifier keeps while it walks a function: register
values that a literal load or ``movw`` put in flight towards an ``add rd, pc`` or
``movt``, and the register branches left unresolved for the indirect-call pass.
"""

from smda.common.FunctionAnalysisState import FunctionAnalysisState as _CommonFunctionAnalysisState

from .definitions import BLOCK_CALL_MNEMONICS, BLOCK_END_MNEMONICS, interworkPointer, split_mnemonic


class FunctionAnalysisState(_CommonFunctionAnalysisState):
    CALL_MNEMONICS = BLOCK_CALL_MNEMONICS
    END_MNEMONICS = BLOCK_END_MNEMONICS

    def __init__(self, start_addr, disassembly):
        super().__init__(start_addr, disassembly)
        self.arm_pending = {}
        self.arm_movw = {}
        self.arm_indirect_jumps = []
        #: whether a symbol or unwind record states this start; set by the backend
        self.arm_declared = None
        #: interworking evidence per transfer instruction: instruction address -> {
        #: "target": normalized address, "thumb": target instruction set,
        #: "raw_pointer": the pointer the image/code names, with its bit 0,
        #: "switches": whether the transfer changes the instruction set,
        #: "kind": "direct" | "indirect" | "pointer"}
        self.arm_interwork = {}
        #: transfer instructions whose target - and therefore its instruction set - no
        #: constant-tracking pass could prove; the single-ISA-per-function model cannot
        #: say which set an unproven cross-mode transfer enters
        self.arm_unresolved_interwork = []

    @staticmethod
    def endsBlock(instruction, refs_from):
        # ``bx lr`` and ``pop {.., pc}`` share their mnemonics with instructions that fall
        # through; what ends the block is that nothing follows the instruction
        del instruction
        return refs_from is None

    def recordInterwork(self, instruction_addr, target, target_thumb, kind, source_thumb, raw_pointer=None):
        """Name the instruction-set identity a transfer reaches, keeping the raw pointer.

        ``target`` is the normalized (even) address the CFG edges use; ``target_thumb`` is
        the instruction set the transfer enters. ``raw_pointer`` is the pointer as the
        image or the code holds it, bit 0 included; when the caller has none (a direct
        branch's resolved address) it is reconstructed so the evidence never loses the
        interworking bit. Two transfers at the same address merge instead of overwriting.
        """
        evidence = self.arm_interwork.get(instruction_addr)
        if evidence is not None and evidence["target"] == target and evidence["thumb"] == target_thumb:
            evidence["kinds"].add(kind)
            return
        if raw_pointer is None:
            raw_pointer = interworkPointer(target, target_thumb)
        self.arm_interwork[instruction_addr] = {
            "target": target,
            "thumb": bool(target_thumb),
            "raw_pointer": raw_pointer,
            "switches": bool(target_thumb) != bool(source_thumb),
            "kinds": {kind},
        }

    def recordUnresolvedInterwork(self, instruction_addr, register):
        """Mark a register-indirect transfer no dataflow pass resolved a target for.

        With no provable target there is no provable instruction set either: a consumer
        cannot tell whether ``bx``/``blx`` leaves the function's single instruction set, so
        the report names the limitation instead of guessing a target identity.
        """
        entry = {"source": instruction_addr, "register": register}
        if entry not in self.arm_unresolved_interwork:
            self.arm_unresolved_interwork.append(entry)

    def unresolvedInterworkMetadata(self):
        return [dict(entry) for entry in self.arm_unresolved_interwork]

    def interworkMetadata(self):
        """The serializable interworking evidence, keyed by the transfer instruction address."""
        return {
            address: {
                "target": evidence["target"],
                "thumb": evidence["thumb"],
                "raw_pointer": evidence["raw_pointer"],
                "switches": evidence["switches"],
                "kinds": sorted(evidence["kinds"]),
            }
            for address, evidence in sorted(self.arm_interwork.items())
        }

    def _branchesOutsideImage(self):
        for _address, _size, mnemonic, op_str, _bytes in self.instructions:
            if not op_str.startswith("#") or split_mnemonic(mnemonic)[0] not in ("b", "bl", "blx"):
                continue
            try:
                target = int(op_str[1:], 0)
            except ValueError:
                continue
            if target and not self.disassembly.isAddrWithinMemoryImage(target):
                # address 0 is where a static link resolves an undefined weak symbol: a
                # ``b 0`` behind a null check is a tailcall the linker left there
                return True
        return False

    def finalizeAnalysis(self, as_gap=False):
        # compilers and linkers emit no direct branch or call out of the image (but to 0): one
        # that leaves it is data decoded as code, unless the image itself states the function
        if (as_gap or not self.arm_declared) and self._branchesOutsideImage():
            return False
        return super().finalizeAnalysis(as_gap)
