"""End-to-end negative regressions for x86 register-indirect call recovery.

These tests drive short, hand-assembled machine code through the whole disassembly
pipeline and assert on the report's final API references rather than on a single
backtracking helper. The property under test: an earlier register assignment may only
be confirmed as an indirect-call target when nothing on any path reaching the call can
have changed it. A partial register write, an unmodelled memory load, an unknown
instruction, an ABI clobber, or a second predecessor that supplies a different value
all leave the call indirect instead of binding it to a dead assignment.
"""

import struct
import unittest

import smda.intel.IndirectCallAnalyzer as indcall_module
from smda.Disassembler import Disassembler
from smda.intel.IndirectCallAnalyzer import IndirectCallAnalyzer
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
TEXT_RVA = 0x1000
IMAGE_SIZE = 0x10000
CALLER = BASE + TEXT_RVA
TARGET = BASE + 0x2000
OTHER_TARGET = BASE + 0x2100
DIRECT_CALL_DEST = BASE + 0x3000
SLOT = BASE + 0x3000
SLOT_VALUE = 0x500000

PROLOGUE = b"\x55\x8b\xec"  # push ebp ; mov ebp, esp
EPILOGUE = b"\x5d\xc3"  # pop ebp ; ret


def _mov_reg_const(reg_opcode, value):
    return bytes([reg_opcode]) + value.to_bytes(4, "little")


def _direct_call(source_addr, destination):
    rel = destination - (source_addr + 5)
    return b"\xe8" + rel.to_bytes(4, "little", signed=True)


class _SingleAddressApiProvider:
    """Resolves one in-image address to a named API, nothing else."""

    def __init__(self, address, dll_name, api_name):
        self.address = address
        self.dll_name = dll_name
        self.api_name = api_name

    def update(self, binary_info):
        return

    def isApiProvider(self):
        return True

    def isSymbolProvider(self):
        return False

    def is_active(self):
        return True

    def getApi(self, to_address, api_address=None):
        return (self.dll_name, self.api_name) if to_address == self.address else ("", "")

    def getFunctionSymbols(self):
        return {}


class _TwoAddressApiProvider:
    def __init__(self, first, first_api, second, second_api):
        self.mapping = {first: first_api, second: second_api}

    def update(self, binary_info):
        return

    def isApiProvider(self):
        return True

    def isSymbolProvider(self):
        return False

    def is_active(self):
        return True

    def getApi(self, to_address, api_address=None):
        return self.mapping.get(to_address, ("", ""))

    def getFunctionSymbols(self):
        return {}


def _config():
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    return config


def _analyze(code, provider=None):
    image = bytearray(IMAGE_SIZE)
    image[TEXT_RVA : TEXT_RVA + len(code)] = code
    disassembler = Disassembler(_config(), backend="intel")
    disassembler.disassembler.api_providers = [] if provider is None else [provider]
    report = disassembler.disassembleBuffer(bytes(image), BASE, bitness=32, architecture="intel")
    return report, report.getFunction(CALLER)


def _target_api_ref(function):
    """The call-site address that got an API reference, or None when the call stayed indirect."""
    if not function.apirefs:
        return None
    return next(iter(function.apirefs))


class CorrectTrackingTestSuite(unittest.TestCase):
    """Positive controls: evidence that is genuinely sufficient still resolves.

    Without these, a guard that simply refused every indirect call would satisfy every
    negative case below.
    """

    def test_a_constant_moved_into_the_call_register_resolves(self):
        # b8 TARGET  mov eax, TARGET
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(
            function.apirefs,
            {CALLER + len(PROLOGUE) + 5: "kernel32.dll!CreateFileA"},
        )

    def test_a_register_copy_chain_keeps_resolving(self):
        # ba TARGET  mov edx, TARGET
        # 89 d0      mov eax, edx
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xBA, TARGET) + b"\x89\xd0" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(
            function.apirefs,
            {CALLER + len(PROLOGUE) + 5 + 2: "kernel32.dll!CreateFileA"},
        )

    def test_a_modeled_absolute_slot_load_keeps_resolving(self):
        # a1 SLOT  mov eax, dword ptr [SLOT]
        # ff d0     call eax
        code = PROLOGUE + b"\xa1" + SLOT.to_bytes(4, "little") + b"\xff\xd0" + EPILOGUE
        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        struct.pack_into("<I", image, SLOT - BASE, SLOT_VALUE)
        provider = _SingleAddressApiProvider(SLOT, "kernel32.dll", "LoadLibraryA")
        disassembler = Disassembler(_config(), backend="intel")
        disassembler.disassembler.api_providers = [provider]
        report = disassembler.disassembleBuffer(bytes(image), BASE, bitness=32, architecture="intel")

        self.assertEqual(
            report.getFunction(CALLER).apirefs,
            {CALLER + len(PROLOGUE) + 5: "kernel32.dll!LoadLibraryA"},
        )

    def test_a_value_preserving_instruction_between_does_not_block_resolution(self):
        # cmp writes only the flags, so the eax definition reaches the call untouched.
        # b8 TARGET  mov eax, TARGET
        # 83 f9 01   cmp ecx, 1
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x83\xf9\x01" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertIsNotNone(_target_api_ref(function))


class InBlockClobberTestSuite(unittest.TestCase):
    """An instruction between the definition and the call that writes the call register."""

    def test_an_unknown_arith_mnemonic_clobbers_the_full_register(self):
        # b8 TARGET       mov eax, TARGET
        # 05 04000000     add eax, 4
        # ff d0           call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x05\x04\x00\x00\x00" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_an_unknown_logic_mnemonic_clobbers_the_full_register(self):
        # b8 TARGET  mov eax, TARGET
        # 31 c0      xor eax, eax
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x31\xc0" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_a_partial_register_write_clobbers_the_whole_register(self):
        # b8 TARGET  mov eax, TARGET
        # 8a 06      mov al, byte ptr [esi]
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x8a\x06" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_a_register_relative_memory_load_is_an_unmodelled_write(self):
        # b8 TARGET  mov eax, TARGET
        # 8b 03      mov eax, dword ptr [ebx]
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x8b\x03" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_an_unrelated_register_does_not_block_resolution(self):
        # Control for the cases above: cmp touches ecx and the flags, the call reads eax,
        # so the value stands even though an unknown-looking instruction sits in between.
        # b8 TARGET  mov eax, TARGET
        # 83 f9 01   cmp ecx, 1
        # ff d0      call eax
        code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x83\xf9\x01" + b"\xff\xd0" + EPILOGUE

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertIsNotNone(_target_api_ref(function))


class CallAbiClobberTestSuite(unittest.TestCase):
    """A call in between clobbers caller-saved registers but leaves callee-saved ones alone."""

    def test_a_caller_saved_register_does_not_survive_an_intervening_call(self):
        # b8 TARGET  mov eax, TARGET
        # e8 rel32   call DIRECT_CALL_DEST
        # ff d0      call eax
        mov = _mov_reg_const(0xB8, TARGET)
        code = (
            PROLOGUE + mov + _direct_call(CALLER + len(PROLOGUE) + len(mov), DIRECT_CALL_DEST) + b"\xff\xd0" + EPILOGUE
        )

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_a_callee_saved_register_survives_an_intervening_call(self):
        # bb TARGET  mov ebx, TARGET
        # e8 rel32   call DIRECT_CALL_DEST
        # ff d3      call ebx
        mov = _mov_reg_const(0xBB, TARGET)
        code = (
            PROLOGUE + mov + _direct_call(CALLER + len(PROLOGUE) + len(mov), DIRECT_CALL_DEST) + b"\xff\xd3" + EPILOGUE
        )

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertIsNotNone(_target_api_ref(function))


def _diamond(first_value, second_value):
    """A function whose two predecessors each define eax before one shared indirect call.

    push ebp ; mov ebp, esp
    test eax, eax ; je block_b
    block_a: mov eax, first_value ; jmp merge
    block_b: mov eax, second_value
    merge:   call eax ; pop ebp ; ret
    """
    branch_addr = CALLER + len(PROLOGUE)
    block_a = branch_addr + 2 + 6  # after test eax,eax (2) and je rel32 (6)
    mov_a = b"\xb8" + first_value.to_bytes(4, "little")
    block_b = block_a + len(mov_a) + 5  # mov (5) and jmp rel32 (5)
    mov_b = b"\xb8" + second_value.to_bytes(4, "little")
    merge = block_b + len(mov_b)
    je_rel = block_b - (branch_addr + 2 + 6)
    jmp_rel = merge - (block_a + len(mov_a) + 5)
    return (
        PROLOGUE
        + b"\x85\xc0"
        + b"\x0f\x84"
        + je_rel.to_bytes(4, "little", signed=True)
        + mov_a
        + b"\xe9"
        + jmp_rel.to_bytes(4, "little", signed=True)
        + mov_b
        + b"\xff\xd0"
        + EPILOGUE
    )


class CrossBlockConfluenceTestSuite(unittest.TestCase):
    """The backward walk spans blocks, so merges are where a dead assignment used to win."""

    def test_two_paths_that_disagree_keep_the_call_indirect(self):
        code = _diamond(TARGET, OTHER_TARGET)
        provider = _TwoAddressApiProvider(
            TARGET, ("kernel32.dll", "CreateFileA"), OTHER_TARGET, ("user32.dll", "MessageBoxA")
        )

        _report, function = _analyze(code, provider)

        self.assertEqual(function.apirefs, {})

    def test_two_paths_that_agree_still_resolve(self):
        code = _diamond(TARGET, TARGET)

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertIsNotNone(_target_api_ref(function))

    def test_a_clobber_on_one_predecessor_path_keeps_the_call_indirect(self):
        # test eax, eax ; je skip
        # mov eax, TARGET ; add eax, 4   (fallthrough path clobbers)
        # skip: call eax
        branch_addr = CALLER + len(PROLOGUE)
        skip = branch_addr + 2 + 6 + 5 + 5  # test + je + mov + add
        je_rel = skip - (branch_addr + 2 + 6)
        code = (
            PROLOGUE
            + b"\x85\xc0"
            + b"\x0f\x84"
            + je_rel.to_bytes(4, "little", signed=True)
            + _mov_reg_const(0xB8, TARGET)
            + b"\x05\x04\x00\x00\x00"
            + b"\xff\xd0"
            + EPILOGUE
        )

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertEqual(function.apirefs, {})

    def test_a_clean_predecessor_path_across_blocks_still_resolves(self):
        # Same diamond skeleton, nop instead of the clobber: every provable path reaches
        # the call with the definition intact.
        branch_addr = CALLER + len(PROLOGUE)
        skip = branch_addr + 2 + 6 + 5 + 1  # test + je + mov + nop
        je_rel = skip - (branch_addr + 2 + 6)
        code = (
            PROLOGUE
            + b"\x85\xc0"
            + b"\x0f\x84"
            + je_rel.to_bytes(4, "little", signed=True)
            + _mov_reg_const(0xB8, TARGET)
            + b"\x90"
            + b"\xff\xd0"
            + EPILOGUE
        )

        _report, function = _analyze(code, _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"))

        self.assertIsNotNone(_target_api_ref(function))


class GuardMutationTestSuite(unittest.TestCase):
    """The negative cases must be enforced by the real guards, not by an unrelated property.

    Each test temporarily restores a piece of the pre-fix behavior and shows that the
    corresponding regression assertion then fails (a target is wrongly confirmed). The
    analyzer is constructed inside disassembleBuffer, so the class method is patched.
    """

    @staticmethod
    def _analyze_with_collector(collector, code, provider):
        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(code)] = code
        disassembler = Disassembler(_config(), backend="intel")
        disassembler.disassembler.api_providers = [provider]
        original = IndirectCallAnalyzer._collectBlockCandidate
        IndirectCallAnalyzer._collectBlockCandidate = collector
        try:
            report = disassembler.disassembleBuffer(bytes(image), BASE, bitness=32, architecture="intel")
        finally:
            IndirectCallAnalyzer._collectBlockCandidate = original
        return report

    @staticmethod
    def _old_first_winning_merge():
        """A collector with the pre-fix merge policy: first concrete predecessor wins."""
        original = IndirectCallAnalyzer._collectBlockCandidate

        def old_first_winning_merge(analyzer, analysis_state, block, registers, register_name, processed, depth):
            verdict = original(analyzer, analysis_state, block, registers, register_name, list(processed), depth)
            if verdict is not indcall_module._UNRESOLVED or depth < 0 or not block:
                return verdict
            processed_addrs = frozenset(ins[0] for blk in processed for ins in blk)
            refs_in = [fr for fr in analysis_state.code_refs_to.get(block[0][0], ()) if fr not in processed_addrs]
            for predecessor in [analyzer.searchBlock(analysis_state, i) for i in refs_in]:
                candidate = original(
                    analyzer, analysis_state, predecessor, dict(registers), register_name, list(processed), depth - 1
                )
                if candidate is not None and candidate is not indcall_module._UNRESOLVED:
                    return candidate
            return None

        return old_first_winning_merge

    def test_the_old_first_winning_merge_policy_revives_a_conflicting_target(self):
        if not hasattr(IndirectCallAnalyzer, "_collectBlockCandidate"):
            self.skipTest("merge-aware collector introduced together with this regression")
        report = self._analyze_with_collector(
            self._old_first_winning_merge(),
            _diamond(TARGET, OTHER_TARGET),
            _TwoAddressApiProvider(
                TARGET, ("kernel32.dll", "CreateFileA"), OTHER_TARGET, ("user32.dll", "MessageBoxA")
            ),
        )

        self.assertNotEqual(report.getFunction(CALLER).apirefs, {})

    def test_neutralizing_the_in_block_clobber_guard_revives_a_dead_assignment(self):
        # The mnemonic allowlist is the guard that stops the walk at an instruction like
        # `add eax, 4`. Treating add as value-preserving for the duration of one analysis
        # makes the backward walk read past the real last write and confirm the dead
        # assignment before it.
        original_allowlist = indcall_module.VALUE_PRESERVING_MNEMONICS
        indcall_module.VALUE_PRESERVING_MNEMONICS = original_allowlist | {"add"}
        try:
            code = PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\x05\x04\x00\x00\x00" + b"\xff\xd0" + EPILOGUE
            image = bytearray(IMAGE_SIZE)
            image[TEXT_RVA : TEXT_RVA + len(code)] = code
            disassembler = Disassembler(_config(), backend="intel")
            disassembler.disassembler.api_providers = [_SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA")]
            report = disassembler.disassembleBuffer(bytes(image), BASE, bitness=32, architecture="intel")
        finally:
            indcall_module.VALUE_PRESERVING_MNEMONICS = original_allowlist

        self.assertNotEqual(report.getFunction(CALLER).apirefs, {})

    def test_positive_controls_survive_the_old_merge_policy(self):
        if not hasattr(IndirectCallAnalyzer, "_collectBlockCandidate"):
            self.skipTest("merge-aware collector introduced together with this regression")
        # The mutation must not break legitimate resolution, otherwise the assertion above
        # would measure a crash rather than the specific regression.
        for code in (
            PROLOGUE + _mov_reg_const(0xB8, TARGET) + b"\xff\xd0" + EPILOGUE,
            _diamond(TARGET, TARGET),
        ):
            report = self._analyze_with_collector(
                self._old_first_winning_merge(),
                code,
                _SingleAddressApiProvider(TARGET, "kernel32.dll", "CreateFileA"),
            )
            self.assertNotEqual(report.getFunction(CALLER).apirefs, {})


if __name__ == "__main__":
    unittest.main()
