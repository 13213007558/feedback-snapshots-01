"""Boundary-inference evidence for recovered x86 jump tables.

Every resolved dispatch records a JumpTableEvidence: what kind of table it read, what the
entry count was proven by (an explicit compare, an and-mask, the case-number table of a
two-level switch) or that nothing proved it, whether the register the bound was read from
survived to the branch, and for every target the table entry it was read from and whether
that bound covers it. Entries the scan admitted past a proven bound stay candidates: they
are recovered for completeness but are not definite branches, and must not surface as
function entries of their own.
"""

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.Disassembler import Disassembler
from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer
from smda.intel.JumpTableEvidence import (
    BOUND_COMPARE,
    BOUND_COMPARE_MASK,
    BOUND_INDEX_TABLE,
    BOUND_MASK,
    BOUND_NONE,
    BOUND_UNTIED_COMPARE,
    TABLE_EXPLICIT,
    TABLE_RELATIVE,
)
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
TEXT_RVA = 0x1000
TABLE_RVA = 0x2000
IMAGE_SIZE = 0x3000


def _makeAnalyzer(bitness=64):
    disassembler = MagicMock()
    disassembly = MagicMock()
    disassembly.binary_info = SimpleNamespace(
        binary=b"",
        base_addr=0x1000,
        binary_size=0x100,
        bitness=bitness,
        isInCodeAreas=MagicMock(return_value=True),
        isPositionIndependentElf=MagicMock(return_value=False),
    )
    disassembler.disassembly = disassembly
    disassembler.getBitMask.return_value = 0xFFFFFFFFFFFFFFFF
    return JumpTableAnalyzer(disassembler)


def _disassemble(image, bitness):
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.WITH_STRINGS = False
    config.TIMEOUT = 0
    disassembler = Disassembler(config=config)
    report = disassembler.disassembleBuffer(image, BASE, bitness=bitness)
    assert report.status == "ok"
    return disassembler, report


class BoundEvidenceKindTestSuite(unittest.TestCase):
    """The bound's kind names its evidence; the size alone never said where it came from."""

    def test_a_tied_compare_is_compare_evidence(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 0x9"),
            (0x1003, 2, "ja", "0x1100"),
            (0x1005, 2, "mov", "ecx, eax"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rcx"})

        self.assertEqual(bound.kind, BOUND_COMPARE)
        self.assertEqual(bound.size, 0xA)
        self.assertEqual(bound.source, 0x1000)
        self.assertEqual(bound.tied_to, "rax")
        self.assertTrue(bound.index_intact)

    def test_a_mask_alone_is_mask_evidence(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 4, "and", "r15d, 7"),
            (0x1004, 7, "lea", "rax, [rip + 0x100]"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"r15"})

        self.assertEqual(bound.kind, BOUND_MASK)
        self.assertEqual(bound.size, 8)
        self.assertEqual(bound.source, 0x1000)
        self.assertTrue(bound.index_intact)

    def test_a_compare_tighter_than_the_mask_combines_the_two(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 5"),
            (0x1003, 2, "ja", "0x1100"),
            (0x1005, 3, "and", "eax, 7"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_COMPARE_MASK)
        self.assertEqual(bound.size, 6)
        self.assertEqual(bound.source, 0x1000)

    def test_a_compare_looser_than_the_mask_leaves_the_mask(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 2, "ja", "0x1100"),
            (0x1007, 3, "and", "eax, 0x3f"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_MASK)
        self.assertEqual(bound.size, 0x40)

    def test_a_compare_whose_index_is_rewritten_before_the_branch_is_untied(self):
        """`cmp eax, 2` bounds eax, but the `xor` rewrites the index afterwards: the compare
        cannot prove the table's extent, so its size is a scan limit, not evidence."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 2"),
            (0x1003, 2, "ja", "0x1100"),
            (0x1005, 2, "xor", "eax, eax"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_UNTIED_COMPARE)
        self.assertEqual(bound.size, 3)
        self.assertEqual(bound.source, 0x1000)
        self.assertFalse(bound.index_intact)

    def test_a_compare_whose_index_is_reloaded_before_the_branch_is_untied(self):
        """The reload carries the tie to the cell it reads, and the compare tested the
        register: it bounds a value the dispatch no longer indexes with."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 2"),
            (0x1003, 2, "ja", "0x1100"),
            (0x1005, 2, "mov", "eax, dword ptr [rdi]"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_UNTIED_COMPARE)
        self.assertFalse(bound.index_intact)

    def test_the_same_compare_before_the_load_is_tied(self):
        """Positive control: with the load ahead of it, the compare tests what the dispatch
        indexes with and the bound is evidence."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 2, "mov", "eax, dword ptr [rdi]"),
            (0x1002, 3, "cmp", "eax, 2"),
            (0x1005, 2, "ja", "0x1100"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_COMPARE)
        self.assertEqual(bound.size, 3)
        self.assertTrue(bound.index_intact)

    def test_a_call_between_the_compare_and_the_branch_drops_the_tie(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 2"),
            (0x1003, 5, "call", "0x2000"),
        ]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_UNTIED_COMPARE)
        self.assertFalse(bound.index_intact)

    def test_no_bounding_instruction_is_unbounded(self):
        analyzer = _makeAnalyzer()
        backtracked = [(0x1000, 2, "mov", "ecx, 0x1")]

        bound = analyzer._traceJumpTableBound(backtracked, {"rax"})

        self.assertEqual(bound.kind, BOUND_NONE)
        self.assertEqual(bound.size, 0)
        self.assertFalse(bound.index_intact)

    def test_the_size_wrapper_matches_the_trace(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 5"),
            (0x1003, 3, "and", "eax, 7"),
        ]

        self.assertEqual(
            analyzer._findJumpTableSize(backtracked, {"rax"}),
            analyzer._traceJumpTableBound(backtracked, {"rax"}).size,
        )


class TwoLevelDispatchEvidenceTest(unittest.TestCase):
    """A two-level switch proves its jump table's bound through the case-number table:
    every byte of it is a valid jump table index. The compare only bounds the switch
    value, so without the index table the entries would be candidates."""

    HOST = 0x40
    CASES = (HOST + 0x18, HOST + 0x1B, HOST + 0x21, HOST + 0x27, HOST + 0x2D)
    DEFAULT = HOST + 0x33
    TABLE = HOST + 0x3C
    INDEX = TABLE + 4 * len(CASES)
    VALUES = 0x40
    JUMP = HOST + 17

    def _image(self):
        image = bytearray(b"\xcc" * 0x200)
        caller = b"\xe8" + (self.HOST - 5).to_bytes(4, "little", signed=True) + b"\xc3"
        image[: len(caller)] = caller
        host = (
            b"\x0f\xb6\x4c\x24\x04"  # movzx ecx, byte ptr [esp + 4]
            + b"\x83\xf9"  # cmp ecx, VALUES - 1
            + bytes([self.VALUES - 1])
            + b"\x77"  # ja default
            + bytes([self.DEFAULT - (self.HOST + 10)])
            + b"\x0f\xb6\x89"  # movzx ecx, byte ptr [ecx + index]
            + (BASE + self.INDEX).to_bytes(4, "little")
            + b"\xff\x24\x8d"  # jmp dword ptr [ecx*4 + table]
            + (BASE + self.TABLE).to_bytes(4, "little")
            + b"\x33\xc0\xc3"  # case 0: xor eax, eax; ret
            + b"".join(b"\xb8" + bytes([case]) + b"\x00\x00\x00\xc3" for case in range(1, len(self.CASES)))
            + b"\xb8\x0c\x00\x00\x00\xc3"  # default: mov eax, 12; ret
        )
        self.assertEqual(len(host), self.DEFAULT + 6 - self.HOST)
        image[self.HOST : self.HOST + len(host)] = host
        for index, target in enumerate(self.CASES):
            image[self.TABLE + 4 * index : self.TABLE + 4 * index + 4] = (BASE + target).to_bytes(4, "little")
        image[self.INDEX : self.INDEX + self.VALUES] = bytes(min(value, 4) for value in range(self.VALUES))
        return bytes(image)

    def setUp(self):
        disassembler, report = _disassemble(self._image(), 32)
        self.functions = {function.offset for function in report.getFunctions()}
        evidence = disassembler.disassembler.jumptable_analyzer.evidence
        self.record = evidence[BASE + self.JUMP]

    def test_the_bound_is_proven_by_the_index_table(self):
        self.assertEqual(self.record.table_kind, TABLE_EXPLICIT)
        self.assertEqual(self.record.bound.kind, BOUND_INDEX_TABLE)
        self.assertEqual(self.record.bound.size, len(self.CASES))
        self.assertTrue(self.record.bound.index_intact)

    def test_the_index_table_is_recorded_with_its_extent(self):
        index_table = self.record.index_table
        self.assertIsNotNone(index_table)
        self.assertEqual(index_table.address, BASE + self.INDEX)
        self.assertEqual(index_table.length, self.VALUES)
        self.assertEqual(index_table.proven_entries, len(self.CASES))

    def test_every_case_is_confirmed_and_traceable_to_its_entry(self):
        self.assertEqual(self.record.table_address, BASE + self.TABLE)
        self.assertEqual(self.record.confirmed_targets, sorted(BASE + case for case in self.CASES))
        self.assertEqual(self.record.candidate_targets, [])
        for entry in self.record.entries:
            self.assertTrue(entry.confirmed)
            self.assertEqual(entry.address, BASE + self.TABLE + entry.index * self.record.entry_size)
            self.assertIn(entry.target, self.record.confirmed_targets)

    def test_no_table_byte_becomes_a_function_entry(self):
        self.assertEqual(
            {start for start in self.functions if BASE + self.TABLE <= start < BASE + self.INDEX + self.VALUES},
            set(),
        )


class NegativeRelativeOffsetEvidenceTest(unittest.TestCase):
    """A relative table whose case bodies precede it stores negative int32 offsets. The
    bound is the compare against the cell the index is loaded from, and every recovered
    target traces back to a confirmed entry."""

    CASES = 4

    def _image(self):
        body = bytearray()
        body += b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
        call_at = len(body)
        body += b"\xe8" + struct.pack("<i", 0)
        body += b"\x5d\xc3"  # pop rbp ; ret
        while len(body) % 16:
            body += b"\x90"
        dispatch_offset = len(body)
        body += b"\x55\x48\x89\xe5"
        cmp_at = len(body)
        body += b"\x83\x3b" + bytes([self.CASES - 1])  # cmp dword ptr [rbx], 3
        ja_at = len(body)
        body += b"\x0f\x87" + struct.pack("<i", 0)
        body += b"\x8b\x03"  # mov eax, dword ptr [rbx]
        lea_at = len(body)
        body += b"\x48\x8d\x3d" + struct.pack("<i", 0)  # lea rdi, [rip + disp]
        body += b"\x48\x63\x04\x87"  # movsxd rax, dword ptr [rdi + rax*4]
        body += b"\x48\x01\xf8"  # add rax, rdi
        jmp_at = len(body)
        body += b"\xff\xe0"  # jmp rax
        case_offsets = []
        for index in range(self.CASES):
            case_offsets.append(len(body))
            body += b"\xb8" + struct.pack("<I", index) + b"\xc3"
        default_offset = len(body)
        body += b"\x31\xc0\xc3"

        struct.pack_into("<i", body, call_at + 1, dispatch_offset - (call_at + 5))
        struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))
        struct.pack_into("<i", body, lea_at + 3, (TABLE_RVA - TEXT_RVA) - (lea_at + 7))

        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(body)] = body
        # the cases precede the table, so every entry is a negative offset from its base
        table = b"".join(struct.pack("<i", (TEXT_RVA + offset) - TABLE_RVA) for offset in case_offsets)
        image[TABLE_RVA : TABLE_RVA + len(table)] = table + b"\x00" * 4

        def address(offset):
            return BASE + TEXT_RVA + offset

        return bytes(image), address(jmp_at), address(cmp_at), [address(offset) for offset in case_offsets]

    def setUp(self):
        image, jump, self.cmp, self.cases = self._image()
        disassembler, report = _disassemble(image, 64)
        self.functions = {function.offset: function for function in report.getFunctions()}
        evidence = disassembler.disassembler.jumptable_analyzer.evidence
        self.record = evidence[jump]

    def test_the_bound_is_the_compare_against_the_index_cell(self):
        self.assertEqual(self.record.table_kind, TABLE_RELATIVE)
        self.assertEqual(self.record.bound.kind, BOUND_COMPARE)
        self.assertEqual(self.record.bound.size, self.CASES)
        self.assertEqual(self.record.bound.source, self.cmp)
        self.assertEqual(self.record.bound.tied_to, "dword ptr [rbx]")
        self.assertTrue(self.record.bound.index_intact)

    def test_negative_offsets_resolve_to_confirmed_entries(self):
        self.assertEqual(self.record.table_address, BASE + TABLE_RVA)
        self.assertEqual(self.record.confirmed_targets, sorted(self.cases))
        self.assertEqual(self.record.candidate_targets, [])
        for entry in self.record.entries:
            self.assertTrue(entry.confirmed)
            self.assertEqual(entry.address, BASE + TABLE_RVA + entry.index * 4)

    def test_the_cases_are_blocks_of_the_dispatcher_not_functions(self):
        for case in self.cases:
            self.assertNotIn(case, self.functions)


class CompareRewriteCandidateTest(unittest.TestCase):
    """The compare bounds the index, but the index is rewritten before the branch: the
    bound cannot be proven, so the scan's results stay candidates. They are recovered for
    completeness - and a wrong one must not become a function entry of its own."""

    CASES = 3
    WRONG = 2

    def _image(self, tied):
        body = bytearray()
        body += b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
        call_at = len(body)
        body += b"\xe8" + struct.pack("<i", 0)
        body += b"\x5d\xc3"  # pop rbp ; ret
        while len(body) % 16:
            body += b"\x90"
        dispatch_offset = len(body)
        body += b"\x55\x48\x89\xe5"
        if tied:
            # the load feeds the compare: the bound is proven against the dispatch index
            body += b"\x8b\x07"  # mov eax, dword ptr [rdi]
            body += b"\x83\xf8" + bytes([self.CASES - 1])  # cmp eax, 2
        else:
            # the compare's bound dies at the reload: nothing bounds what is dispatched on
            body += b"\x83\xf8\x40"  # cmp eax, 0x40
            body += b"\x8b\x07"  # mov eax, dword ptr [rdi]
        ja_at = len(body)
        body += b"\x0f\x87" + struct.pack("<i", 0)
        jmp_at = len(body)
        body += b"\xff\x24\xc5" + struct.pack("<I", BASE + TABLE_RVA)  # jmp qword ptr [rax*8 + table]
        case_offsets = []
        for index in range(self.CASES):
            case_offsets.append(len(body))
            body += b"\xb8" + struct.pack("<I", index) + b"\xc3"
        default_offset = len(body)
        body += b"\x31\xc0\xc3"
        while len(body) % 16:
            body += b"\xcc"
        padding_offset = len(body)
        body += b"\xcc" * 0x20

        struct.pack_into("<i", body, call_at + 1, dispatch_offset - (call_at + 5))
        struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))

        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(body)] = body
        table = b"".join(struct.pack("<Q", BASE + TEXT_RVA + offset) for offset in case_offsets)
        # adjacent data past the table's end: in-image pointers a scan without a proven
        # bound reads as further entries, at the int3 padding rather than any case body
        table += b"".join(struct.pack("<Q", BASE + TEXT_RVA + padding_offset) for _ in range(self.WRONG))
        table += b"\x00" * 8
        image[TABLE_RVA : TABLE_RVA + len(table)] = table

        def address(offset):
            return BASE + TEXT_RVA + offset

        return (
            bytes(image),
            address(jmp_at),
            [address(offset) for offset in case_offsets],
            address(padding_offset),
        )

    def _analyze(self, tied):
        image, jump, cases, padding = self._image(tied)
        disassembler, report = _disassemble(image, 64)
        functions = {function.offset for function in report.getFunctions()}
        record = disassembler.disassembler.jumptable_analyzer.evidence[jump]
        return record, functions, cases, padding

    def test_a_rewritten_index_leaves_every_entry_a_candidate(self):
        record, functions, cases, padding = self._analyze(tied=False)

        self.assertEqual(record.bound.kind, BOUND_UNTIED_COMPARE)
        self.assertFalse(record.bound.index_intact)
        self.assertEqual(record.candidate_targets, sorted(entry.target for entry in record.entries))
        self.assertEqual(record.confirmed_targets, [])
        # the candidate range keeps the real cases and the wrong reads alike
        self.assertEqual(len(record.entries), self.CASES + self.WRONG)
        for case in cases:
            self.assertIn(case, [entry.target for entry in record.entries])

    def test_a_wrong_candidate_never_becomes_a_function_entry(self):
        record, functions, _cases, padding = self._analyze(tied=False)

        wrong = [entry for entry in record.entries if entry.target == padding]
        self.assertEqual(len(wrong), self.WRONG)
        self.assertFalse(any(entry.confirmed for entry in wrong))
        self.assertNotIn(padding, functions)

    def test_the_tied_control_confirms_exactly_its_cases(self):
        """Positive control: the same shape with the compare after the load proves the
        bound, so the entries are confirmed and the scan stops at the table's end."""
        record, functions, cases, padding = self._analyze(tied=True)

        self.assertEqual(record.bound.kind, BOUND_COMPARE)
        self.assertTrue(record.bound.index_intact)
        self.assertEqual(record.confirmed_targets, sorted(cases))
        self.assertEqual(record.candidate_targets, [])
        self.assertNotIn(padding, [entry.target for entry in record.entries])


if __name__ == "__main__":
    unittest.main()
