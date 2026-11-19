"""String inventory: scan findings versus recovered reference evidence."""

import json
import struct
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.StringInventory import (
    PROVENANCE_CODE,
    PROVENANCE_DATA,
    PROVENANCE_PADDING,
    PROVENANCE_RODATA,
    PROVENANCE_UNMAPPED,
    build_string_inventory,
    summarize_inventory,
)

BASE = 0x400000
MARKER = b"acme.example\x00"


def _lea_text(base, source_offset, target):
    """`lea rdi, [rip + disp]` bytes addressed at source_offset; callers append the terminator."""
    displacement = target - (base + source_offset + 7)
    return b"\x48\x8d\x3d" + struct.pack("<i", displacement) + b"\xc3"


def _function_prefix():
    return b"\x55\x48\x89\xe5"


def _build_elf(base=0x400000, marker=MARKER):
    """A minimal ELF64 with .text, .rodata and an unreachable padding region.

    .text holds one leaf function that loads .rodata, plus a copy of the marker inside its
    own bytes. .rodata holds the referenced copy. A third copy sits past the last section,
    in mapped-but-unowned padding.
    """
    text_va, ro_va = base + 0x1000, base + 0x2000
    text_off, ro_off, pad_off = 0x1000, 0x2000, 0x3000
    ehsize, phentsize, shentsize = 64, 56, 64
    shstr = b"\x00.text\x00.rodata\x00.shstrtab\x00"
    name_text = shstr.index(b".text")
    name_ro = shstr.index(b".rodata")
    name_str = shstr.index(b".shstrtab")

    text = bytearray(0x100)
    text[0:4] = _function_prefix()
    text[4:11] = _lea_text(text_va, 4, ro_va)[:7]
    text[11] = 0xC3
    text[0x40 : 0x40 + len(marker)] = marker
    rodata = bytearray(0x100)
    rodata[0 : len(marker)] = marker
    padding = bytearray(0x100)
    padding[0 : len(marker)] = marker

    shstr_off = 0x3200
    sh_off = shstr_off + len(shstr)

    def shdr(name, sh_type, flags, addr, offset, size, align):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, 0, 0, align, 0)

    section_headers = (
        shdr(0, 0, 0, 0, 0, 0, 0)
        + shdr(name_text, 1, 0x6, text_va, text_off, len(text), 16)
        + shdr(name_ro, 1, 0x2, ro_va, ro_off, len(rodata), 16)
        + shdr(name_str, 3, 0, 0, shstr_off, len(shstr), 1)
    )
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,
        62,
        1,
        text_va,
        ehsize,
        sh_off,
        0,
        ehsize,
        phentsize,
        1,
        shentsize,
        4,
        3,
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, 0x3200, 0x3200, 0x1000)
    image = bytearray(0x3200)
    image[0 : len(ehdr)] = ehdr
    image[ehsize : ehsize + len(phdr)] = phdr
    image[text_off : text_off + len(text)] = text
    image[ro_off : ro_off + len(rodata)] = rodata
    image[pad_off : pad_off + len(padding)] = padding
    image[shstr_off : shstr_off + len(shstr)] = shstr
    image += section_headers
    return bytes(image)


def _build_flat_buffer(base=0x400000, marker=MARKER):
    """A headerless buffer: one function in code, a referenced copy in data, a third copy in
    padding, and a stored pointer to a fourth copy that no instruction names."""
    image = bytearray(0x400)
    lea_at, referenced_at, padding_at, stored_target_at = 0x104, 0x200, 0x300, 0x380
    image[0x100:0x104] = _function_prefix()
    image[lea_at : lea_at + 7] = _lea_text(base, lea_at, base + referenced_at)[:7]
    image[lea_at + 7] = 0xC3
    image[0x40 : 0x40 + len(marker)] = marker
    image[referenced_at : referenced_at + len(marker)] = marker
    image[padding_at : padding_at + len(marker)] = marker
    image[stored_target_at : stored_target_at + len(marker)] = marker
    image[0x340:0x348] = (base + stored_target_at).to_bytes(8, "little")
    return bytes(image)


def _disassemble(raw, with_scan=True, with_strings=False, base=None, code_areas=None, store_buffer=False):
    config = SmdaConfig()
    config.WITH_STRING_SCAN = with_scan
    config.WITH_STRINGS = with_strings
    config.STORE_BUFFER = store_buffer
    if raw[:4] == b"\x7fELF":
        return Disassembler(config).disassembleUnmappedBuffer(raw)
    return Disassembler(config).disassembleBuffer(
        raw,
        base_addr=base or BASE,
        bitness=64,
        code_areas=code_areas,
        oep=(base or BASE) + 0x100,
        architecture="intel",
    )


def _entry_at(entries, addr):
    return next(entry for entry in entries if entry["data_addr"] == addr)


class InventoryProvenanceTest(unittest.TestCase):
    def test_three_sources_are_reported_separately(self):
        report = _disassemble(_build_elf())
        entries = [entry for entry in report.getStringInventory() if entry["string"] == "acme.example"]
        self.assertEqual(len(entries), 3)
        self.assertEqual(
            [entry["provenance"] for entry in entries],
            [PROVENANCE_CODE, PROVENANCE_RODATA, PROVENANCE_PADDING],
        )

    def test_only_the_referenced_copy_carries_instruction_evidence(self):
        report = _disassemble(_build_elf())
        entries = [entry for entry in report.getStringInventory() if entry["string"] == "acme.example"]
        referenced = [entry for entry in entries if entry["references"]]
        self.assertEqual(len(referenced), 1)
        self.assertEqual(referenced[0]["provenance"], PROVENANCE_RODATA)
        evidence = referenced[0]["references"][0]
        self.assertEqual(evidence["ins_addr"], BASE + 0x1004)
        self.assertEqual(evidence["mnemonic"], "lea")
        self.assertIn("[rip", evidence["operands"])
        self.assertEqual(evidence["via"], "direct")

    def test_byte_ranges_cover_the_content_and_not_the_terminator(self):
        report = _disassemble(_build_elf())
        for entry in report.getStringInventory():
            start, end = entry["byte_range"]
            self.assertEqual(end - start, len(entry["string"]))
            self.assertEqual(report.getStringBytes(entry), entry["string"].encode(entry["encoding"]))

    def test_summary_counts_referenced_occurrences(self):
        report = _disassemble(_build_elf())
        summary = summarize_inventory(report.getStringInventory())
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["referenced"], 1)
        self.assertEqual(summary["by_provenance"], {PROVENANCE_CODE: 1, PROVENANCE_PADDING: 1, PROVENANCE_RODATA: 1})


class InventoryReferenceEvidenceTest(unittest.TestCase):
    def test_a_headerless_buffer_links_only_the_named_copy(self):
        base = BASE
        report = _disassemble(_build_flat_buffer(), code_areas=[[base + 0x100, base + 0x120]], base=base)
        entries = {entry["data_addr"]: entry for entry in report.getStringInventory()}
        referenced = [addr for addr, entry in entries.items() if entry["references"]]
        self.assertEqual(referenced, [base + 0x200])

    def test_a_stored_pointer_is_not_reference_evidence(self):
        base = BASE
        report = _disassemble(_build_flat_buffer(), code_areas=[[base + 0x100, base + 0x120]], base=base)
        stored_target = _entry_at(report.getStringInventory(), base + 0x380)
        self.assertEqual(stored_target["references"], [])

    def test_an_immediate_that_matches_an_address_is_not_reference_evidence(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        image[0x104:0x10D] = b"\xb8" + struct.pack("<I", base + 0x200) + b"\xc3\x90\x90\x90"
        image[0x200 : 0x200 + len(MARKER)] = MARKER
        report = _disassemble(bytes(image), code_areas=[[base + 0x100, base + 0x120]], base=base)
        entry = _entry_at(report.getStringInventory(), base + 0x200)
        self.assertEqual(entry["references"], [])

    def test_a_stored_word_in_unmapped_data_does_not_link(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        image[0x104:0x10B] = _lea_text(base, 0x104, base + 0x200)[:7]
        image[0x10B] = 0xC3
        image[0x200 : 0x200 + len(MARKER)] = MARKER
        image[0x300:0x308] = (base + 0x200).to_bytes(8, "little")
        report = _disassemble(bytes(image), base=base)
        entry = _entry_at(report.getStringInventory(), base + 0x200)
        self.assertEqual([ref["ins_addr"] for ref in entry["references"]], [base + 0x104])

    def test_section_flags_outrank_a_broad_executable_segment(self):
        report = _disassemble(_build_elf())
        rodata_entry = _entry_at(report.getStringInventory(), BASE + 0x2000)
        self.assertEqual(rodata_entry["provenance"], PROVENANCE_RODATA)
        self.assertEqual(rodata_entry["section"], ".rodata")

    def test_unmapped_section_is_reported_as_unmapped(self):
        unidentified = SmdaReport(None)
        unidentified.buffer = b"acme.example\x00" + b"\x00" * 32
        unidentified.base_addr = 0
        unidentified.binary_size = len(unidentified.buffer)
        unidentified.architecture = "intel"
        unidentified.bitness = 64
        unidentified.code_areas = []
        unidentified.code_sections = [(".comment", 0, 16)]
        entries = build_string_inventory(unidentified)
        self.assertEqual(entries[0]["provenance"], PROVENANCE_UNMAPPED)


class InventoryPointerEvidenceTest(unittest.TestCase):
    def test_a_pointer_to_a_string_links_through_one_level(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        image[0x104:0x10B] = _lea_text(base, 0x104, base + 0x180)[:7]
        image[0x10B] = 0xC3
        image[0x180:0x188] = (base + 0x200).to_bytes(8, "little")
        image[0x200 : 0x200 + len(MARKER)] = MARKER
        report = _disassemble(bytes(image), base=base, code_areas=[[base + 0x100, base + 0x120]])
        entry = _entry_at(report.getStringInventory(), base + 0x200)
        self.assertEqual([(ref["ins_addr"], ref["via"]) for ref in entry["references"]], [(base + 0x104, "pointer")])

    def test_a_go_style_header_links_the_literal_it_points_at(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        image[0x104:0x10B] = _lea_text(base, 0x104, base + 0x180)[:7]
        image[0x10B] = 0xC3
        image[0x180:0x190] = (base + 0x200).to_bytes(8, "little") + (len(MARKER) - 1).to_bytes(8, "little")
        image[0x200 : 0x200 + len(MARKER)] = MARKER
        report = _disassemble(bytes(image), base=base, code_areas=[[base + 0x100, base + 0x120]])
        entry = _entry_at(report.getStringInventory(), base + 0x200)
        self.assertEqual(entry["references"][0]["via"], "string-header")


class InventoryEndToEndTest(unittest.TestCase):
    def test_referenced_copy_is_the_only_linked_one_at_every_base(self):
        for base in (0x400000, 0x700000):
            with self.subTest(base=hex(base)):
                report = _disassemble(_build_elf(base=base), base=base)
                entries = [entry for entry in report.getStringInventory() if entry["string"] == "acme.example"]
                linked = [entry for entry in entries if entry["references"]]
                self.assertEqual(len(linked), 1)
                self.assertEqual(linked[0]["provenance"], PROVENANCE_RODATA)
                self.assertEqual(linked[0]["byte_range"], [base + 0x2000, base + 0x200C])


class InventoryAcceptanceTest(unittest.TestCase):
    """The scenario in the request: one short string in code, .rodata and unused padding, plus
    a real reference. The report must distinguish the three sources, tie only the referenced copy
    to an instruction, and still do so after the image is analysed at a different base."""

    def test_three_sources_and_one_reference_survive_a_base_change(self):
        layouts = {}
        for base in (0x400000, 0x510000):
            report = _disassemble(_build_elf(base=base), base=base)
            entries = [entry for entry in report.getStringInventory() if entry["string"] == "acme.example"]
            layouts[base] = {
                entry["provenance"]: (
                    entry["byte_range"][0] - base,
                    entry["byte_range"][1] - base,
                    tuple((ref["ins_addr"] - base, ref["via"]) for ref in entry["references"]),
                )
                for entry in entries
            }
        self.assertEqual(set(layouts[0x400000]), {PROVENANCE_CODE, PROVENANCE_RODATA, PROVENANCE_PADDING})
        self.assertEqual(layouts[0x400000], layouts[0x510000])
        self.assertEqual(layouts[0x400000][PROVENANCE_CODE][2], ())
        self.assertEqual(layouts[0x400000][PROVENANCE_PADDING][2], ())
        self.assertEqual(layouts[0x400000][PROVENANCE_RODATA][2], ((0x1004, "direct"),))


class InventoryEncodingTest(unittest.TestCase):
    def test_utf16_literal_records_its_encoding_and_two_byte_terminator(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        image[0x104:0x10B] = _lea_text(base, 0x104, base + 0x200)[:7]
        image[0x10B] = 0xC3
        encoded = "wide.name".encode("utf-16-le")
        image[0x200 : 0x200 + len(encoded) + 2] = encoded + b"\x00\x00"
        report = _disassemble(bytes(image), base=base)
        entry = _entry_at(report.getStringInventory(), base + 0x200)
        self.assertEqual(entry["type"], "unicode")
        self.assertEqual(entry["encoding"], "utf-16-le")
        self.assertEqual(entry["terminator_bytes"], 2)
        self.assertEqual(entry["byte_range"], [base + 0x200, base + 0x200 + len(encoded)])
        self.assertEqual(entry["references"][0]["ins_addr"], base + 0x104)

    def test_packed_c_strings_are_split_at_referenced_starts(self):
        base = BASE
        image = bytearray(0x400)
        image[0x100:0x104] = _function_prefix()
        first_at, second_at = 0x300, 0x30B
        image[0x104:0x10B] = _lea_text(base, 0x104, base + first_at)[:7]
        image[0x10B] = 0x90
        image[0x10C:0x113] = _lea_text(base, 0x10C, base + second_at)[:7]
        image[0x113] = 0xC3
        packed = b"alpha.beta\x00gamma.delta\x00"
        image[first_at : first_at + len(packed)] = packed
        report = _disassemble(bytes(image), code_areas=[[base + 0x100, base + 0x300]], base=base)
        by_addr = {entry["data_addr"]: entry for entry in report.getStringInventory()}
        self.assertEqual(by_addr[base + first_at]["string"], "alpha.beta")
        self.assertEqual(by_addr[base + second_at]["string"], "gamma.delta")
        self.assertEqual([ref["ins_addr"] for ref in by_addr[base + second_at]["references"]], [base + 0x10C])


class InventorySwitchTest(unittest.TestCase):
    def test_scan_is_off_by_default(self):
        config = SmdaConfig()
        self.assertFalse(config.WITH_STRING_SCAN)
        report = _disassemble(_build_elf(), with_scan=False)
        self.assertIsNone(report.xstrings)
        self.assertEqual(report.getStringInventory(), [])
        self.assertNotIn("xstrings", report.toDict())

    def test_scan_does_not_require_reference_extraction(self):
        without_refs = _disassemble(_build_elf(), with_strings=False)
        with_refs = _disassemble(_build_elf(), with_strings=True)
        self.assertFalse(list(without_refs.getFunctions())[0].stringrefs)
        self.assertTrue(list(with_refs.getFunctions())[0].stringrefs)
        self.assertEqual(without_refs.getStringInventory(), with_refs.getStringInventory())

    def test_an_empty_inventory_is_distinct_from_no_scan(self):
        base = BASE
        image = bytearray(0x200)
        image[0x100:0x104] = _function_prefix()
        image[0x104] = 0xC3
        report = _disassemble(bytes(image), base=base, code_areas=[[base + 0x100, base + 0x200]])
        self.assertEqual(report.xstrings, [])
        self.assertIn("xstrings", report.toDict())


class InventoryRoundTripTest(unittest.TestCase):
    def test_inventory_survives_json_with_evidence_intact(self):
        original = _disassemble(_build_elf())
        restored = SmdaReport.fromDict(json.loads(json.dumps(original.toDict())))
        self.assertEqual(restored.getStringInventory(), original.getStringInventory())
        referenced = next(entry for entry in restored.getStringInventory() if entry["references"])
        self.assertEqual(referenced["references"][0]["ins_addr"], BASE + 0x1004)

    def test_get_string_bytes_falls_back_to_the_recorded_encoding(self):
        report = _disassemble(_build_elf())
        serialized = json.loads(json.dumps(report.toDict()))
        self.assertNotIn("buffer", serialized)
        restored = SmdaReport.fromDict(serialized)
        referenced = next(entry for entry in restored.getStringInventory() if entry["references"])
        self.assertEqual(restored.getStringBytes(referenced), b"acme.example")

    def test_old_reports_without_the_key_load_as_not_scanned(self):
        report_dict = _disassemble(_build_elf()).toDict()
        report_dict.pop("xstrings")
        self.assertIsNone(SmdaReport.fromDict(report_dict).xstrings)

    def test_malformed_inventory_is_rejected(self):
        report_dict = _disassemble(_build_elf()).toDict()
        report_dict["xstrings"] = {"not": "a list"}
        with self.assertRaises(ValueError):
            SmdaReport.fromDict(report_dict)


class InventoryAccessorTest(unittest.TestCase):
    def test_a_mutated_base_does_not_carve_bytes_from_a_stale_buffer(self):
        report = _disassemble(_build_elf(), store_buffer=True)
        referenced = next(entry for entry in report.getStringInventory() if entry["references"])
        self.assertEqual(report.getStringBytes(referenced), b"acme.example")
        report.base_addr += 0x100000
        self.assertIsNone(report.getStringBytes(referenced))

    def test_get_string_occurrences_returns_every_copy(self):
        report = _disassemble(_build_elf())
        occurrences = report.getStringOccurrences("acme.example")
        self.assertEqual(len(occurrences), 3)
        self.assertEqual(sum(1 for entry in occurrences if entry["references"]), 1)

    def test_unsupported_architectures_get_an_empty_inventory(self):
        report = SmdaReport(None)
        report.buffer = b"acme.example\x00"
        report.base_addr = 0
        report.binary_size = len(report.buffer)
        report.architecture = "cil"
        report.bitness = 32
        report.code_areas = []
        report.code_sections = []
        self.assertEqual(build_string_inventory(report)[0]["string"], "acme.example")


class InventoryCrossBaseTest(unittest.TestCase):
    def test_evidence_and_bytes_follow_the_base_address(self):
        for base in (0x400000, 0x600000, 0x800000):
            with self.subTest(base=hex(base)):
                report = _disassemble(_build_elf(base=base), base=base)
                referenced = next(
                    entry
                    for entry in report.getStringInventory()
                    if entry["string"] == "acme.example" and entry["references"]
                )
                self.assertEqual(referenced["provenance"], PROVENANCE_RODATA)
                self.assertEqual(referenced["byte_range"], [base + 0x2000, base + 0x200C])
                self.assertEqual(referenced["references"][0]["ins_addr"], base + 0x1004)
                self.assertEqual(report.getStringBytes(referenced), b"acme.example")

    def test_scan_findings_follow_the_base_address(self):
        for base in (0x400000, 0x900000):
            with self.subTest(base=hex(base)):
                report = _disassemble(_build_flat_buffer(base=base), base=base)
                addresses = [entry["data_addr"] for entry in report.getStringInventory()]
                self.assertEqual(addresses, [base + 0x40, base + 0x200, base + 0x300, base + 0x380])


class InventorySectionProvenanceTest(unittest.TestCase):
    def test_data_section_occurrence_is_writable_data(self):
        report = _disassemble(_build_elf(), store_buffer=True)
        report.code_sections = [
            ("", 0, 0),
            (".text", BASE + 0x1000, BASE + 0x1100),
            (".data", BASE + 0x2000, BASE + 0x2100),
        ]
        report.code_areas = [[BASE + 0x1000, BASE + 0x1100]]
        entries = [entry for entry in build_string_inventory(report) if entry["string"] == "acme.example"]
        self.assertEqual(
            [entry["provenance"] for entry in entries],
            [PROVENANCE_CODE, PROVENANCE_DATA, PROVENANCE_PADDING],
        )


if __name__ == "__main__":
    unittest.main()
