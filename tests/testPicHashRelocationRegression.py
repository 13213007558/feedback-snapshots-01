"""Paired PicHash regression: relocation must normalize, behavior must not.

Malware clustering keys on SmdaFunction.pic_hash. Two properties make that hash
useful, and both are pinned here through the real SmdaInstruction /
SmdaFunction.getPicHash path (capstone-decoded instructions, IntelInstructionEscaper,
escape_intraprocedural_jumps=True, image bounds from BinaryInfo):

1. Relocation invariance ("change address -> same hash"): load base, external
   call targets, intra-function jump targets, and in-image data references are
   escaped, so relocating a function does not change its pic_hash.
2. Behavior sensitivity ("change behavior -> different hash"): comparison
   constants, bitmasks, and struct offsets are NOT escaped, so two functions
   that differ in them must NOT share a pic_hash. Equal hashes for a negative
   pair are a normalization collision and fail the test - they are never
   accepted as "compatible".

Normalization collision boundaries (unavoidable, pinned - not treated as
compatibility):
- An immediate that numerically falls inside [base_addr, base_addr + binary_size)
  is indistinguishable from an address and IS escaped; two different in-image
  constants collide. Unescaping them would break relocation invariance, so the
  boundary is documented, not "fixed".
- Immediate escaping only applies when base_addr > 0x100000
  (IntelInstructionEscaper.escapeBinary guard); at or below that base, relocated
  immediates leak into the hash.
- Absolute memory operands ("dword ptr [0x...]") are always escaped, even when
  the address lies outside the image; two different fixed low addresses collide.

The frozen corpus in tests/testEscaperFingerprint.py is untouched: these tests
pin escaping semantics, not a digest of them.
"""

import logging
import struct
import unittest

logging.disable(logging.CRITICAL)

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # noqa: E402

from smda.common.BinaryInfo import BinaryInfo  # noqa: E402
from smda.common.SmdaFunction import SmdaFunction  # noqa: E402
from smda.common.SmdaInstruction import SmdaInstruction  # noqa: E402
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper  # noqa: E402

BASE = 0x400000
IMAGE_SIZE = 0x10000
FUNCTION_RVA = 0x1000


def _disassemble(code, addr, bitness=32):
    md = Cs(CS_ARCH_X86, CS_MODE_32 if bitness == 32 else CS_MODE_64)
    return [
        SmdaInstruction.from_tuple((ins.address, ins.size, ins.mnemonic, ins.op_str, ins.bytes))
        for ins in md.disasm(code, addr)
    ]


def _make_function(blocks):
    function = SmdaFunction()
    function._escaper = IntelInstructionEscaper
    function.blocks = blocks
    function._sorted_block_keys = sorted(blocks.keys())
    return function


def _binary_info(base, size=IMAGE_SIZE):
    binary_info = BinaryInfo(b"")
    binary_info.base_addr = base
    binary_info.binary_size = size
    return binary_info


def _posfunc_code(base, call_target, jne_rel, data_addr, imm_addr):
    start = base + FUNCTION_RVA
    return b"".join(
        [
            b"\x55",  # 0x00 push ebp
            b"\x8b\xec",  # 0x01 mov ebp, esp
            b"\xa1" + struct.pack("<I", data_addr),  # 0x03 mov eax, [data_addr]
            b"\xe8" + struct.pack("<i", call_target - (start + 0x0D)),  # 0x08 call call_target
            b"\xb9" + struct.pack("<I", imm_addr),  # 0x0d mov ecx, imm_addr
            b"\x3d\x37\x13\x00\x00",  # 0x12 cmp eax, 0x1337
            b"\x75" + bytes([jne_rel]),  # 0x17 jne (intra-function)
            b"\x90\x90",  # 0x19
            b"\x90\x90",  # 0x1b <- jne target for rel 0x02
            b"\x25\xff\x00\x00\x00",  # 0x1d and eax, 0xff <- jne target for rel 0x04
            b"\x8b\x43\x10",  # 0x22 mov eax, [ebx + 0x10]
            b"\x5d",  # 0x25 pop ebp
            b"\xc3",  # 0x26 ret
        ]
    )


def _posfunc(base, call_target, jne_rel, data_addr, imm_addr):
    start = base + FUNCTION_RVA
    code = _posfunc_code(base, call_target, jne_rel, data_addr, imm_addr)
    blocks = {}
    for block_start, block_end in ((0x00, 0x19), (0x19, 0x1B), (0x1B, 0x1D), (0x1D, len(code))):
        blocks[start + block_start] = _disassemble(code[block_start:block_end], start + block_start)
    return _make_function(blocks)


def _negfunc(base, cmp_const=0x1337, mask=0xFF, struct_off=0x10):
    start = base + FUNCTION_RVA
    code = b"".join(
        [
            b"\x55",
            b"\x8b\xec",
            b"\x3d" + struct.pack("<I", cmp_const),
            b"\x25" + struct.pack("<I", mask),
            b"\x8b\x43" + bytes([struct_off]),
            b"\x5d",
            b"\xc3",
        ]
    )
    return _make_function({start: _disassemble(code, start)})


def _single_instruction_function(code_hex, addr, bitness=32):
    return _make_function({addr: _disassemble(bytes.fromhex(code_hex), addr, bitness)})


class RelocationInvarianceTestSuite(unittest.TestCase):
    """Change address -> same pic_hash."""

    def test_load_base_change_keeps_pic_hash(self):
        function_a = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x02, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        relocated_base = 0x500000
        function_b = _posfunc(
            relocated_base,
            call_target=relocated_base + 0x4000,
            jne_rel=0x02,
            data_addr=relocated_base + 0x3000,
            imm_addr=relocated_base + 0x4000,
        )
        raw_a = b"".join(ins.bytes.encode("ascii") for block in function_a.blocks.values() for ins in block)
        raw_b = b"".join(ins.bytes.encode("ascii") for block in function_b.blocks.values() for ins in block)
        self.assertNotEqual(
            raw_a, raw_b, "relocation must actually change the raw bytes, otherwise the pair proves nothing"
        )
        self.assertEqual(
            function_a.getPicHashSequence(_binary_info(BASE)),
            function_b.getPicHashSequence(_binary_info(relocated_base)),
        )
        self.assertEqual(function_a.getPicHash(_binary_info(BASE)), function_b.getPicHash(_binary_info(relocated_base)))

    def test_external_call_target_change_keeps_pic_hash(self):
        function_a = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x02, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        function_b = _posfunc(
            BASE, call_target=BASE + 0x8000, jne_rel=0x02, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        self.assertEqual(function_a.getPicHash(_binary_info(BASE)), function_b.getPicHash(_binary_info(BASE)))

    def test_intraprocedural_jump_target_change_keeps_pic_hash(self):
        function_a = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x02, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        function_b = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x04, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        self.assertEqual(function_a.getPicHash(_binary_info(BASE)), function_b.getPicHash(_binary_info(BASE)))

    def test_in_image_data_reference_change_keeps_pic_hash(self):
        function_a = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x02, data_addr=BASE + 0x3000, imm_addr=BASE + 0x4000
        )
        function_b = _posfunc(
            BASE, call_target=BASE + 0x4000, jne_rel=0x02, data_addr=BASE + 0x5000, imm_addr=BASE + 0x6000
        )
        self.assertEqual(function_a.getPicHash(_binary_info(BASE)), function_b.getPicHash(_binary_info(BASE)))


class BehaviorSensitivityTestSuite(unittest.TestCase):
    """Change behavior -> different pic_hash. Equality here is a collision, not compatibility."""

    def _assert_behavior_pair_differs(self, function_a, function_b, what):
        info = _binary_info(BASE)
        self.assertNotEqual(
            function_a.getPicHashSequence(info),
            function_b.getPicHashSequence(info),
            f"{what}: escaped sequences collided - two different programs must not share a fingerprint",
        )
        self.assertNotEqual(
            function_a.getPicHash(info),
            function_b.getPicHash(info),
            f"{what}: pic_hash collision between different programs is a bug, not compatibility",
        )

    def test_comparison_constant_change_flips_pic_hash(self):
        self._assert_behavior_pair_differs(
            _negfunc(BASE, cmp_const=0x1337), _negfunc(BASE, cmp_const=0x1338), "cmp constant"
        )

    def test_bitmask_change_flips_pic_hash(self):
        self._assert_behavior_pair_differs(_negfunc(BASE, mask=0xFF), _negfunc(BASE, mask=0xFFFF), "bitmask")

    def test_struct_offset_change_flips_pic_hash(self):
        self._assert_behavior_pair_differs(
            _negfunc(BASE, struct_off=0x10), _negfunc(BASE, struct_off=0x14), "struct offset"
        )


class EscapableByteMarkingTestSuite(unittest.TestCase):
    """Pin exactly which bytes of each instruction the PicHash path wildcards."""

    def test_escaped_bytes_mark_relocatable_positions(self):
        cases = [
            ("55", 0x401000, 32, "55", "push ebp: fully kept"),
            ("8bec", 0x401001, 32, "8bec", "mov ebp, esp: fully kept"),
            ("a100304000", 0x401003, 32, "a1????????", "mov eax, [0x403000]: absolute ref escaped"),
            ("e8f32f0000", 0x401008, 32, "e8????????", "call rel32: target escaped"),
            ("ff1500304000", 0x401008, 32, "ff15????????", "call dword ptr [0x403000]: import slot escaped"),
            ("b900404000", 0x40100D, 32, "b9????????", "mov ecx, 0x404000: in-image immediate escaped"),
            ("3d37130000", 0x401012, 32, "3d37130000", "cmp eax, 0x1337: behavior constant kept"),
            ("7502", 0x401017, 32, "75??", "jne rel8: intra-function target escaped"),
            ("0f8502000000", 0x401017, 32, "0f85????????", "jne rel32: intra-function target escaped"),
            ("eb02", 0x401017, 32, "eb??", "jmp rel8: intra-function target escaped"),
            ("e902000000", 0x401017, 32, "e9????????", "jmp rel32: target escaped"),
            ("e2fe", 0x401017, 32, "e2??", "loop rel8: intra-function target escaped"),
            ("25ff000000", 0x40101D, 32, "25ff000000", "and eax, 0xff: bitmask kept"),
            ("8b4310", 0x401022, 32, "8b4310", "mov eax, [ebx + 0x10]: struct offset kept"),
            ("5d", 0x401025, 32, "5d", "pop ebp: fully kept"),
            ("c3", 0x401026, 32, "c3", "ret: fully kept"),
            ("488b0500100000", 0x140001000, 64, "488b05????????", "mov rax, [rip + 0x1000]: RIP-relative disp escaped"),
            (
                "ff2500100000",
                0x140001007,
                64,
                "ff25????????",
                "jmp qword ptr [rip + 0x1000]: RIP-relative disp escaped",
            ),
            ("4889e5", 0x14000100E, 64, "4889e5", "mov rbp, rsp: fully kept"),
            ("483d37130000", 0x140001011, 64, "483d37130000", "cmp rax, 0x1337: behavior constant kept"),
        ]
        info = _binary_info(BASE)
        for code_hex, addr, bitness, expected, meaning in cases:
            with self.subTest(meaning=meaning):
                instruction = _disassemble(bytes.fromhex(code_hex), addr, bitness)[0]
                escaped = instruction.getEscapedBinary(
                    IntelInstructionEscaper,
                    escape_intraprocedural_jumps=True,
                    lower_addr=info.base_addr,
                    upper_addr=info.base_addr + info.binary_size,
                )
                self.assertEqual(escaped, expected, meaning)


class NormalizationCollisionBoundaryTestSuite(unittest.TestCase):
    """Unavoidable collisions, pinned to document the boundary - never compatibility."""

    def test_boundary_in_image_constant_is_indistinguishable_from_address(self):
        # mov eax, 0x405000 vs mov eax, 0x406000: both immediates lie inside the
        # image, so escapeBinaryValue wildcards both. Different behavior constants,
        # same pic_hash - the escaper cannot tell an in-image constant from an
        # address, and unescaping would break relocation invariance.
        function_a = _single_instruction_function("b800504000", BASE + FUNCTION_RVA)
        function_b = _single_instruction_function("b800604000", BASE + FUNCTION_RVA)
        info = _binary_info(BASE)
        self.assertEqual(function_a.getPicHashSequence(info), b"b8????????")
        self.assertEqual(function_a.getPicHash(info), function_b.getPicHash(info))

    def test_boundary_immediate_escaping_requires_base_above_0x100000(self):
        # escapeBinary only wildcards in-image immediates when lower_addr > 0x100000.
        # At base 0x100000 the immediate survives, so relocation across the gate
        # changes the hash.
        low_base = 0x100000
        function_low = _single_instruction_function("b800101000", low_base + FUNCTION_RVA)
        instruction = next(iter(function_low.blocks.values()))[0]
        self.assertEqual(
            instruction.getEscapedBinary(
                IntelInstructionEscaper,
                escape_intraprocedural_jumps=True,
                lower_addr=low_base,
                upper_addr=low_base + IMAGE_SIZE,
            ),
            "b800101000",
            "in-image immediate must survive unescaped at the 0x100000 base gate",
        )
        high_base = 0x110000
        function_high = _single_instruction_function("b800111000", high_base + FUNCTION_RVA)
        self.assertNotEqual(
            function_low.getPicHash(_binary_info(low_base)),
            function_high.getPicHash(_binary_info(high_base)),
        )

    def test_boundary_absolute_pointer_ref_always_escaped(self):
        # "mov eax, dword ptr [0x...]" is wildcarded without any image-range check,
        # so two different fixed low addresses (e.g. 0x1337 vs 0x1338) collide.
        function_a = _single_instruction_function("a137130000", BASE + FUNCTION_RVA)
        function_b = _single_instruction_function("a138130000", BASE + FUNCTION_RVA)
        info = _binary_info(BASE)
        self.assertEqual(function_a.getPicHashSequence(info), b"a1????????")
        self.assertEqual(function_a.getPicHash(info), function_b.getPicHash(info))


if __name__ == "__main__":
    unittest.main()
