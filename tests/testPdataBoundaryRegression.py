#!/usr/bin/python
"""Regression coverage for x64 PE .pdata ranges that disagree with recursive traversal.

The exception directory is the image's own declaration of where routines begin and
how far they extend, but it is not above the instruction stream: a malformed or
hostile table can name adjacent functions, overlapping or out-of-order ranges, an
address in the middle of an instruction, a span that jumps a real code boundary, or
a begin inside a non-executable section. SMDA has to give each of those a verifiable
outcome instead of letting the table overwrite what recursive descent established.

Every case here is driven end to end through a hand-built spec-valid PE32+ image
(.text/.pdata/.xdata, plus an optional non-executable .data), the same fixture
convention as testPdataInteriorGaps.py, and then checked at two levels:

* the report keeps the functions the bytes actually define, with their blocks and
  cross-references intact - a bad entry never absorbs or deletes a complete function;
* the candidate manager keeps an audit trail of why a declared start did not become
  a function (a code-area refusal, a code collision, an untrusted extent), so the
  outcome is attributable rather than silent.

Two config arms matter: USE_PE_X64_PDATA_ENDS (off by default) performs the
boundary split, and USE_PE_X64_PDATA_INTERIOR_GAPS (on by default) performs the
interior-range refusal. Neither may relax the IDA-style function mutual-exclusion
model to buy recovery rate.
"""

import os
import struct
import tempfile
import unittest

from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

IMAGE_BASE = 0x140000000
TEXT_RVA, PDATA_RVA, XDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000, 0x5000
FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000

#: push rbp; mov rbp, rsp; pop rbp; ret - a complete function the prologue scan books.
ENTRY_SHAPED = bytes((0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3))
#: mov eax, 1; ret - decodes and returns but opens with no prologue, so only a call
#: reference or the gap scan can book it.
GAP_SHAPED = bytes((0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3))
#: UNWIND_INFO byte 0: Version 1 (bits 0-2) with no flags.
UNWIND_PRIMARY = 0x01
INT3 = b"\xcc"
FN_STRIDE = 0x20


def _record(begin_rva, end_rva, unwind_rva):
    return struct.pack("<III", begin_rva, end_rva, unwind_rva)


def _build_pe(text_bytes, pdata_bytes, xdata_bytes=None, data_sections=(), image_size=0x6000):
    """Minimal PE32+ x86-64 image with .text (RX), .pdata, .xdata and optional extra sections.

    Section headers follow the PE field order (VirtualSize before VirtualAddress);
    getting them swapped makes lief map every section to the same RVA and the table
    reads as garbage, so the builder pins the layout explicitly rather than sharing a
    helper that takes positional offsets.
    """
    if xdata_bytes is None:
        xdata_bytes = struct.pack("<BBBB", UNWIND_PRIMARY, 0, 0, 0)
    num_sections = 3 + len(data_sections)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)

    coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, 240, 0x0022)

    data_dirs = [(0, 0)] * 16
    data_dirs[3] = (PDATA_RVA, len(pdata_bytes))  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # magic PE32+
        14,
        0,  # linker versions
        len(text_bytes),
        0,
        0,  # code / init / uninit data sizes
        TEXT_RVA,  # entrypoint
        TEXT_RVA,  # base of code
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # win32 version
        image_size,
        FILE_ALIGN,  # size of headers
        0,  # checksum
        3,
        0,  # subsystem CUI, dll characteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,  # stack/heap reserve+commit
        0,  # loader flags
        16,  # number of data directories
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)

    def shdr(name, rva, raw_off, characteristics, virtual_size=SECT_ALIGN, raw_size=FILE_ALIGN):
        # <Name(8), VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, ...>
        return struct.pack(
            "<8sIIIIIIHHI",
            name,
            virtual_size,
            rva,
            raw_size,
            raw_off,
            0,
            0,
            0,
            0,
            characteristics,
        )

    sections = (
        shdr(b".text", TEXT_RVA, 0x200, 0x60000020)  # CODE | EXECUTE | READ
        + shdr(b".pdata", PDATA_RVA, 0x400, 0x40000040)  # INITIALIZED_DATA | READ
        + shdr(b".xdata", XDATA_RVA, 0x600, 0x40000040)
    )
    for index, (name, rva, characteristics) in enumerate(data_sections):
        sections += shdr(name, rva, 0x800 + index * FILE_ALIGN, characteristics)

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    assert len(headers) <= FILE_ALIGN
    blob = bytearray(FILE_ALIGN * (4 + len(data_sections)))
    blob[0 : len(headers)] = headers
    blob[0x200 : 0x200 + len(text_bytes)] = text_bytes
    blob[0x400 : 0x400 + len(pdata_bytes)] = pdata_bytes
    blob[0x600 : 0x600 + len(xdata_bytes)] = xdata_bytes
    return bytes(blob)


def _three_function_text():
    """Three complete, 0x20-strided entry-shaped functions separated by int3 padding."""
    body = ENTRY_SHAPED + INT3 * (FN_STRIDE - len(ENTRY_SHAPED))
    return body * 3


def _analyse(blob, **config_overrides):
    """Analyse through the file path so .pdata lands at its mapped RVA, not a flat offset."""
    config = SmdaConfig()
    for key, value in config_overrides.items():
        setattr(config, key, value)
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fixture.exe")
        with open(path, "wb") as handle:
            handle.write(blob)
        return Disassembler(config=config).disassembleFile(path)


def _manager(blob, **config_overrides):
    loader = FileLoader("/", map_file=True)
    loader._loadFile(blob)
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    config = SmdaConfig()
    for key, value in config_overrides.items():
        setattr(config, key, value)
    manager = FunctionCandidateManager(config)
    manager.init(disassembly)
    return manager


def _va(rva):
    return IMAGE_BASE + rva


def _function_instruction_sets(report):
    """The instruction bytes each recovered function owns, keyed by function offset."""
    return {
        function.offset: {instruction.offset for instruction in function.getInstructions()}
        for function in report.getFunctions()
    }


def _assert_functions_are_mutually_exclusive(test_case, report):
    """The IDA-style model: no instruction byte may belong to two functions.

    Every conflict case has to leave this invariant intact - a bad .pdata entry is never
    an excuse to relax function mutual exclusion for the sake of recovery rate.
    """
    owned = _function_instruction_sets(report)
    addresses = [address for byte_set in owned.values() for address in byte_set]
    test_case.assertEqual(len(addresses), len(set(addresses)))
    offsets = sorted(owned)
    for left_index, left in enumerate(offsets):
        for right in offsets[left_index + 1 :]:
            test_case.assertTrue(owned[left].isdisjoint(owned[right]))


class AdjacentFunctionsRegressionTestSuite(unittest.TestCase):
    """Valid back-to-back functions and a table that describes them honestly."""

    def test_two_adjacent_functions_are_both_recovered_with_their_own_blocks(self):
        text = _three_function_text()
        pdata = b"".join(
            _record(TEXT_RVA + index * FN_STRIDE, TEXT_RVA + (index + 1) * FN_STRIDE, XDATA_RVA) for index in range(3)
        )
        report = _analyse(_build_pe(text, pdata))

        offsets = {function.offset for function in report.getFunctions()}
        for index in range(3):
            self.assertIn(_va(TEXT_RVA + index * FN_STRIDE), offsets)
        # each honest function keeps its single, self-contained block of four instructions
        for index in range(3):
            function = report.getFunction(_va(TEXT_RVA + index * FN_STRIDE))
            self.assertEqual(function.num_blocks, 1)
            self.assertEqual(function.num_instructions, 4)
        # nothing overlaps: the recovered functions stay mutually exclusive
        _assert_functions_are_mutually_exclusive(self, report)

    def test_an_honest_table_records_one_extent_and_one_seed_per_function(self):
        text = _three_function_text()
        pdata = b"".join(
            _record(TEXT_RVA + index * FN_STRIDE, TEXT_RVA + (index + 1) * FN_STRIDE, XDATA_RVA) for index in range(3)
        )
        manager = _manager(_build_pe(text, pdata))

        seeded = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertEqual(seeded, {_va(TEXT_RVA + index * FN_STRIDE) for index in range(3)})
        self.assertEqual(
            sorted(manager._pdata_ranges),
            [
                (
                    _va(TEXT_RVA + index * FN_STRIDE),
                    _va(TEXT_RVA + (index + 1) * FN_STRIDE),
                    False,
                )
                for index in range(3)
            ],
        )


class OverlappingUnorderedRangesRegressionTestSuite(unittest.TestCase):
    """Tables a linker never emits: records that overlap or arrive out of order."""

    def _conflict_table(self):
        # an out-of-order record (third function listed first), the honest first record,
        # and a bad record beginning mid-instruction at +3 whose span overlaps both
        return (
            _record(TEXT_RVA + 2 * FN_STRIDE, TEXT_RVA + 3 * FN_STRIDE, XDATA_RVA)
            + _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, XDATA_RVA)
            + _record(TEXT_RVA + 3, TEXT_RVA + 2 * FN_STRIDE, XDATA_RVA)
        )

    def test_overlapping_and_unordered_records_do_not_delete_a_real_function(self):
        report = _analyse(_build_pe(_three_function_text(), self._conflict_table()))
        offsets = {function.offset for function in report.getFunctions()}
        for index in range(3):
            self.assertIn(_va(TEXT_RVA + index * FN_STRIDE), offsets)
        # the bad mid-instruction begin is not among the survivors
        self.assertNotIn(_va(TEXT_RVA + 3), offsets)
        # and no survivor absorbed a neighbour's bytes to get there
        _assert_functions_are_mutually_exclusive(self, report)

    def test_the_lookup_walk_survives_overlapping_and_unsorted_extents(self):
        manager = _manager(_build_pe(_three_function_text(), self._conflict_table()))
        # two records cover 0x1010 (the honest one and the overlapping bad one); the walk
        # must still return a containing extent rather than tripping on the unsorted input
        containing = manager.declaredExceptionRangeContaining(_va(TEXT_RVA + 0x10))
        self.assertIsNotNone(containing)
        self.assertLessEqual(containing[0], _va(TEXT_RVA + 0x10))
        self.assertGreater(containing[1], _va(TEXT_RVA + 0x10))
        # sorting by start does not order the ends, so a byte past the honest record's end
        # still has to answer from the overlapping bad record rather than ending the walk
        overlapped = manager.declaredExceptionRangeContaining(_va(TEXT_RVA + FN_STRIDE + 3))
        self.assertIsNotNone(overlapped)
        self.assertEqual(overlapped[0], _va(TEXT_RVA + 3))
        # a range's own start is an entry, never interior, even on an unsorted table
        self.assertIsNone(manager.declaredExceptionRangeContaining(_va(TEXT_RVA)))

    def test_a_mid_instruction_exception_seed_falls_back_to_a_collision_abort(self):
        # the image's own declaration names 0x1003, but recursive descent already owns
        # those bytes as part of the function at 0x1000; the seed must lose that contest
        # with a recorded reason rather than split the instruction stream.
        pdata = _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, XDATA_RVA) + _record(
            TEXT_RVA + 3, TEXT_RVA + FN_STRIDE, XDATA_RVA
        )
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "fixture.exe")
            with open(path, "wb") as handle:
                handle.write(_build_pe(_three_function_text(), pdata))
            disassembler = Disassembler(config=SmdaConfig())
            report = disassembler.disassembleFile(path)

        engine = disassembler.disassembler
        bad_candidate = engine.fc_manager.candidates.get(_va(TEXT_RVA + 3))
        self.assertIsNotNone(bad_candidate)
        self.assertTrue(bad_candidate.analysis_aborted)
        self.assertIn(_va(TEXT_RVA + 3), engine.disassembly.failed_analysis_addr)
        # the function the bad seed tried to cut into is still whole
        self.assertIn(_va(TEXT_RVA), {function.offset for function in report.getFunctions()})
        owner = engine.disassembly.ins2fn.get(_va(TEXT_RVA + 3))
        self.assertEqual(owner, _va(TEXT_RVA))
        self.assertFalse(engine.fc_manager.checkFunctionOverlap())


class NonExecutableMetadataRegressionTestSuite(unittest.TestCase):
    """A RUNTIME_FUNCTION whose BeginAddress lands outside every executable section."""

    def test_a_begin_in_a_data_section_is_refused_as_a_candidate(self):
        text = _three_function_text()
        pdata = _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, XDATA_RVA) + _record(DATA_RVA, DATA_RVA + 0x20, XDATA_RVA)
        blob = _build_pe(text, pdata, data_sections=((b".data", DATA_RVA, 0xC0000040),))
        manager = _manager(blob)

        seeded = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertIn(_va(TEXT_RVA), seeded)
        self.assertNotIn(_va(DATA_RVA), seeded)
        # the refusal is structural: the code-area filter is what rejects that address
        self.assertFalse(manager._passesCodeFilter(_va(DATA_RVA)))
        self.assertTrue(manager._passesCodeFilter(_va(TEXT_RVA)))

    def test_a_data_section_seed_cannot_appear_as_a_recovered_function(self):
        text = _three_function_text()
        pdata = _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, XDATA_RVA) + _record(DATA_RVA, DATA_RVA + 0x20, XDATA_RVA)
        blob = _build_pe(text, pdata, data_sections=((b".data", DATA_RVA, 0xC0000040),))
        report = _analyse(blob)
        self.assertNotIn(_va(DATA_RVA), {function.offset for function in report.getFunctions()})
        # the three real functions are untouched and still own disjoint bytes
        self.assertEqual(
            {function.offset for function in report.getFunctions()},
            {_va(TEXT_RVA + index * FN_STRIDE) for index in range(3)},
        )
        _assert_functions_are_mutually_exclusive(self, report)

    def test_an_extent_into_a_data_section_does_not_suppress_real_code(self):
        # a span that reaches from .text across into non-executable space must not send
        # the gap scan out of .text: a real gap-shaped function behind the span still has
        # to be recoverable. The extent itself is still recorded, since both ends stay
        # inside the mapped image - it simply has no executable bytes past .text to claim.
        text = bytearray(INT3 * (3 * FN_STRIDE))
        text[0 : len(ENTRY_SHAPED)] = ENTRY_SHAPED
        island_rva = TEXT_RVA + FN_STRIDE
        text[FN_STRIDE : FN_STRIDE + len(GAP_SHAPED)] = GAP_SHAPED
        pdata = _record(TEXT_RVA, DATA_RVA + 0x10, XDATA_RVA)
        blob = _build_pe(bytes(text), pdata, data_sections=((b".data", DATA_RVA, 0xC0000040),))
        manager = _manager(blob)

        # one extent was admitted and reaches into .data
        self.assertEqual(len(manager._pdata_ranges), 1)
        self.assertGreater(manager._pdata_ranges[0][1], _va(TEXT_RVA) + SECT_ALIGN)
        # nothing about that span marks an executable address as data
        self.assertNotIn(_va(island_rva), manager.disassembly.data_map)


class CodeSkipBoundaryRegressionTestSuite(unittest.TestCase):
    """A declared EndAddress that jumps over real code instead of ending at a boundary."""

    def _skipped_text_and_table(self):
        # f1 occupies [0x1000, 0x1006); a complete second function sits at 0x1020, but a
        # bad first record claims its extent runs all the way to 0x1040, skipping over f2.
        text = bytearray(INT3 * (3 * FN_STRIDE))
        text[0 : len(ENTRY_SHAPED)] = ENTRY_SHAPED
        text[FN_STRIDE : FN_STRIDE + len(ENTRY_SHAPED)] = ENTRY_SHAPED
        text[2 * FN_STRIDE : 2 * FN_STRIDE + len(ENTRY_SHAPED)] = ENTRY_SHAPED
        pdata = _record(TEXT_RVA, TEXT_RVA + 2 * FN_STRIDE, XDATA_RVA) + _record(
            TEXT_RVA + 2 * FN_STRIDE, TEXT_RVA + 3 * FN_STRIDE, XDATA_RVA
        )
        return bytes(text), pdata

    def test_a_span_that_skips_a_function_does_not_absorb_it(self):
        text, pdata = self._skipped_text_and_table()
        report = _analyse(_build_pe(text, pdata))
        offsets = {function.offset for function in report.getFunctions()}
        # the function the bad span jumped over is still recovered on its own evidence
        self.assertIn(_va(TEXT_RVA), offsets)
        self.assertIn(_va(TEXT_RVA + FN_STRIDE), offsets)
        self.assertIn(_va(TEXT_RVA + 2 * FN_STRIDE), offsets)
        skipped = report.getFunction(_va(TEXT_RVA + FN_STRIDE))
        self.assertEqual(skipped.num_instructions, 4)
        _assert_functions_are_mutually_exclusive(self, report)

    def test_a_call_reached_function_inside_a_bad_span_keeps_its_cross_reference(self):
        # f1 calls an island the bad span claims as interior; a direct call reference is
        # independent evidence the interior-gap rule must not overrule. The call has to be
        # reachable, so it sits in the straight-line body before the epilogue:
        # push rbp; mov rbp, rsp; call island; pop rbp; ret.
        text = bytearray(INT3 * (2 * FN_STRIDE))
        text[0:4] = bytes((0x55, 0x48, 0x89, 0xE5))  # push rbp; mov rbp, rsp
        call_offset = 0x4
        text[call_offset : call_offset + 5] = b"\xe8" + struct.pack("<i", FN_STRIDE - (call_offset + 5))
        text[call_offset + 5 : call_offset + 7] = b"\x5d\xc3"
        island_rva = TEXT_RVA + FN_STRIDE
        text[FN_STRIDE : FN_STRIDE + len(GAP_SHAPED)] = GAP_SHAPED
        # one bad span covers both f1 and the island; no record names the island itself
        pdata = _record(TEXT_RVA, TEXT_RVA + 2 * FN_STRIDE, XDATA_RVA)

        report = _analyse(_build_pe(bytes(text), pdata))
        island = report.getFunction(_va(island_rva))
        self.assertIsNotNone(island)
        self.assertEqual(island.inrefs, [_va(TEXT_RVA + call_offset)])
        # and f1 retains its outbound edge to the island
        caller = report.getFunction(_va(TEXT_RVA))
        outbound = {target for targets in caller.outrefs.values() for target in targets}
        self.assertIn(_va(island_rva), outbound)
        _assert_functions_are_mutually_exclusive(self, report)


class PdataEndSplitRegressionTestSuite(unittest.TestCase):
    """The opt-in USE_PE_X64_PDATA_ENDS split and the invariants around it."""

    def _merged_text_and_table(self):
        # nops up to 0x1010, a ret there, then at 0x1020 a jmp back into 0x1010 - the
        # non-fall-through inbound reference the split requires.
        text = bytearray(b"\x90" * 0x40)
        text[0x10] = 0xC3
        text[0x20:0x25] = b"\xe9" + struct.pack("<i", 0x10 - 0x25)
        pdata = (
            _record(TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA)
            + _record(TEXT_RVA + 0x10, TEXT_RVA + 0x11, XDATA_RVA)
            + _record(TEXT_RVA + 0x20, TEXT_RVA + 0x25, XDATA_RVA)
        )
        return bytes(text), pdata

    def test_the_default_config_keeps_the_merged_function_whole(self):
        text, pdata = self._merged_text_and_table()
        self.assertFalse(SmdaConfig().USE_PE_X64_PDATA_ENDS)
        report = _analyse(_build_pe(text, pdata))
        merged = report.getFunction(_va(TEXT_RVA))
        self.assertIsNotNone(merged)
        self.assertEqual(merged.num_blocks, 1)
        self.assertEqual(merged.num_instructions, 17)
        # the jmp's cross-reference is recorded regardless of the split arm
        jmp_fn = report.getFunction(_va(TEXT_RVA + 0x20))
        self.assertIn(_va(TEXT_RVA + 0x10), {t for ts in jmp_fn.outrefs.values() for t in ts})

    def test_enabling_the_split_partitions_blocks_without_losing_an_instruction(self):
        text, pdata = self._merged_text_and_table()
        report_off = _analyse(_build_pe(text, pdata))
        report_on = _analyse(_build_pe(text, pdata), USE_PE_X64_PDATA_ENDS=True)

        before = {ins.offset for fn in report_off.getFunctions() for ins in fn.getInstructions()}
        after = {ins.offset for fn in report_on.getFunctions() for ins in fn.getInstructions()}
        self.assertEqual(before, after)

        head = report_on.getFunction(_va(TEXT_RVA))
        split = report_on.getFunction(_va(TEXT_RVA + 0x10))
        self.assertEqual([ins.mnemonic for ins in head.getInstructions()], ["nop"] * 16)
        self.assertEqual([ins.mnemonic for ins in split.getInstructions()], ["ret"])
        # the cross-reference that justified the split now lands on the new function
        self.assertEqual(split.inrefs, [_va(TEXT_RVA + 0x20)])
        # and the two functions still own disjoint instruction bytes
        head_bytes = {ins.offset for ins in head.getInstructions()}
        split_bytes = {ins.offset for ins in split.getInstructions()}
        self.assertTrue(head_bytes.isdisjoint(split_bytes))
        # the partition never produces overlap anywhere, and never drops the tail-jmp fn
        _assert_functions_are_mutually_exclusive(self, report_on)
        self.assertIsNotNone(report_on.getFunction(_va(TEXT_RVA + 0x20)))

    def test_a_split_point_with_only_fall_through_evidence_is_not_taken(self):
        # no jmp targets 0x1010 here, so the declared end lacks the non-fall-through
        # inbound reference the guard demands: the function stays merged.
        text = bytearray(b"\x90" * 0x20)
        text[0x10] = 0xC3
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x10, XDATA_RVA) + _record(TEXT_RVA + 0x10, TEXT_RVA + 0x11, XDATA_RVA)
        report = _analyse(_build_pe(bytes(text), pdata), USE_PE_X64_PDATA_ENDS=True)
        offsets = {function.offset for function in report.getFunctions()}
        self.assertIn(_va(TEXT_RVA), offsets)
        self.assertNotIn(_va(TEXT_RVA + 0x10), offsets)
        merged = report.getFunction(_va(TEXT_RVA))
        self.assertEqual([ins.mnemonic for ins in merged.getInstructions()], ["nop"] * 16 + ["ret"])

    def test_a_degenerate_split_candidate_keeps_the_original_function_set(self):
        # an EndAddress equal to the Begin names nothing; the split pass must treat it
        # as no evidence rather than as a zero-width function.
        text, pdata = self._merged_text_and_table()
        pdata += _record(TEXT_RVA + 0x30, TEXT_RVA + 0x30, XDATA_RVA)
        report = _analyse(_build_pe(text, pdata), USE_PE_X64_PDATA_ENDS=True)
        offsets = {function.offset for function in report.getFunctions()}
        self.assertIn(_va(TEXT_RVA), offsets)
        self.assertIn(_va(TEXT_RVA + 0x10), offsets)
        self.assertNotIn(_va(TEXT_RVA + 0x30), offsets)


class UntrustworthyExtentRegressionTestSuite(unittest.TestCase):
    """Records that may still seed a candidate but must not be allowed to skip regions."""

    def test_an_oversized_extent_is_recorded_nowhere_but_its_start_still_seeds(self):
        text = _three_function_text()
        pdata = _record(TEXT_RVA, 0x7FFFFFF0, XDATA_RVA)
        manager = _manager(_build_pe(text, pdata))

        self.assertEqual(manager._pdata_ranges, [])
        seeded = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertIn(_va(TEXT_RVA), seeded)

    def test_a_bad_unwind_pointer_keeps_the_seed_but_drops_the_extent(self):
        # .text opens with 0x55, which is not a legal UNWIND_INFO header byte
        text = _three_function_text()
        pdata = _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, TEXT_RVA)
        manager = _manager(_build_pe(text, pdata))
        self.assertEqual(manager._pdata_ranges, [])
        seeded = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertIn(_va(TEXT_RVA), seeded)

    def test_a_refused_extent_never_ends_the_gap_scan(self):
        # the expensive failure mode: a bad extent that moved the gap pointer past the
        # image would silently end gap analysis. A bad chained record must instead leave
        # the following gap-shaped address bookable.
        text = bytearray(INT3 * (2 * FN_STRIDE))
        text[0 : len(ENTRY_SHAPED)] = ENTRY_SHAPED
        text[FN_STRIDE : FN_STRIDE + len(GAP_SHAPED)] = GAP_SHAPED
        pdata = _record(TEXT_RVA, TEXT_RVA + FN_STRIDE, XDATA_RVA) + _record(
            TEXT_RVA + FN_STRIDE, 0x7FFFFFF0, XDATA_RVA + 4
        )
        xdata = struct.pack("<BBBB", UNWIND_PRIMARY, 0, 0, 0) + struct.pack("<BBBB", 0x21, 0, 0, 0)
        manager = _manager(_build_pe(bytes(text), pdata, xdata_bytes=xdata))
        # the oversized chained record is kept out of the extent table entirely, so only
        # the honest first range remains to steer the gap scan
        self.assertEqual(
            manager._pdata_ranges,
            [(_va(TEXT_RVA), _va(TEXT_RVA + FN_STRIDE), False)],
        )
        manager.gap_pointer = _va(TEXT_RVA + FN_STRIDE)
        self.assertEqual(manager.nextGapCandidate(), _va(TEXT_RVA + FN_STRIDE))


if __name__ == "__main__":
    unittest.main()
