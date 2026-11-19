'''Machine-readable parse coverage summaries.

The summary must distinguish complete, partial and header-only parses from
what was actually interpreted, not from the boolean process() returned. It
must keep bytes from different coordinate spaces apart and must not count
padding as success.
'''

import contextlib
import io
import json
import os
import runpy
import struct
import sys
import tempfile
import unittest
import uuid
from unittest import mock

from uefi_firmware import AutoParser
from uefi_firmware import efi_compressor
from uefi_firmware.structs.uefi_structs import (
    FIRMWARE_GUIDED_GUIDS, FIRMWARE_VOLUME_GUIDS)
from uefi_firmware.uefi import FirmwareVolume

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
UNKNOWN_GUID = "deadbeef-dead-beef-dead-beefdeadbeef"
CLI = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "bin",
    "uefi-firmware-parser")


def make_section(section_type, body):
    '''A file section, padded so the next section is 4-byte aligned.'''
    size = 4 + len(body)
    data = struct.pack("<I", size)[:3] + bytes([section_type]) + body
    return data + b"\x00" * (-len(data) % 4)


def make_file(body, file_type=0x07):
    '''An FFS file with an 8-byte aligned size.'''
    size = 24 + len(body)
    header = FILE_GUID + struct.pack(
        "<HBB3sB", 0, file_type, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def make_volume(body=b"", size=None):
    '''An FFS2 volume of one block, sized to fit body unless size is given.'''
    block_map_size = 16
    hdrlen = FirmwareVolume._HEADER_SIZE + block_map_size
    if size is None:
        size = hdrlen + len(body) + (-len(body) % 8)
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", 0, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def unknown_guid_section(payload=b"SECRETDATA"):
    guid = uuid.UUID(UNKNOWN_GUID).bytes_le
    return make_section(0x02, guid + struct.pack("<HH", 24, 0) + payload)


def broken_volume_section():
    return make_section(0x17, b"\x00" * 0x40)


def compressed_section(data):
    stream = efi_compressor.LzmaCompress(data, len(data))
    return make_section(0x01, struct.pack("<IB", len(data), 0x02) + stream)


def parse(data):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return AutoParser(data).parse()


def regions(summary, kind=None, space="input"):
    found = summary["spaces"][space]["regions"]
    if kind is None:
        return found
    return [region for region in found if region["kind"] == kind]


class CompleteTest(unittest.TestCase):

    def test_a_parsed_volume_is_complete(self):
        data = make_volume(
            make_file(make_section(0x15, "name".encode("utf-16le") + b"\0\0")))
        summary = parse(data).coverage()

        self.assertEqual(summary["status"], "complete")
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["unresolved"], [])
        self.assertEqual(regions(summary, "unknown"), [])
        self.assertEqual(regions(summary, "failed"), [])
        self.assertEqual(
            summary["spaces"]["input"]["counts"]["parsedRatio"], 1.0)
        covered = sum(region["size"] for region in regions(summary))
        self.assertEqual(covered, len(data))

    def test_coverage_is_json_serializable(self):
        json.dumps(parse(make_volume()).coverage())

    def test_raw_bytes_are_preserved_not_interpreted(self):
        # A raw section's bytes are evidence. They are listed as unverified
        # so a caller can tell they were kept, not interpreted.
        firmware = parse(make_volume(make_file(
            make_section(0x19, b"vendor payload"))))
        summary = firmware.coverage()
        preserved = regions(summary, "preserved")
        self.assertEqual(len(preserved), 1)
        self.assertEqual(preserved[0]["size"], len(b"vendor payload"))
        self.assertEqual(summary["unverified"][0]["kind"], "preserved")
        # Nothing is unexplained, but the body was only kept verbatim, so
        # the analysis understood only the headers.
        self.assertEqual(summary["status"], "header-only")
        self.assertEqual(summary["unresolved"], [])


class UnknownGuidTest(unittest.TestCase):

    def test_unknown_guid_section_is_reported_with_its_guid(self):
        firmware = parse(make_volume(make_file(unknown_guid_section())))
        summary = firmware.coverage()

        self.assertEqual(summary["status"], "header-only")
        self.assertFalse(summary["complete"])
        unknown = regions(summary, "unknown")
        self.assertEqual(len(unknown), 1)
        self.assertIn(UNKNOWN_GUID, unknown[0]["reason"])
        self.assertEqual(unknown[0]["size"], len(b"SECRETDATA"))
        self.assertEqual(summary["unresolved"][0]["reason"],
                         unknown[0]["reason"])

    def test_unknown_guid_section_keeps_its_bytes(self):
        # The bytes are listed even though they were not interpreted, so a
        # caller can still extract them as evidence.
        firmware = parse(make_volume(make_file(unknown_guid_section())))
        unknown = regions(firmware.coverage(), "unknown")
        # The whole GUID-defined body is kept, including its 20-byte GUID
        # header, even though only the 10 payload bytes are unexplained.
        # The section is 34 bytes: a 4-byte header and a 30-byte body. The
        # make_section helper's alignment padding is outside the section.
        self.assertEqual(unknown[0]["retained"], 16 + 4 + len(b"SECRETDATA"))
        self.assertEqual(unknown[0]["size"], len(b"SECRETDATA"))


class BrokenChildTest(unittest.TestCase):

    def test_broken_nested_volume_fails_instead_of_completing(self):
        firmware = parse(make_volume(make_file(broken_volume_section())))
        summary = firmware.coverage()

        self.assertEqual(summary["status"], "header-only")
        failed = regions(summary, "failed")
        self.assertEqual(len(failed), 1)
        self.assertIn("firmware volume image", failed[0]["reason"])
        self.assertEqual(len(summary["unresolved"]), len(failed))
        self.assertEqual(
            [(r["path"], r["offset"], r["size"], r["reason"])
             for r in summary["unresolved"]],
            [(r["path"], r["offset"], r["size"], r["reason"])
             for r in failed])

    def test_parent_success_does_not_hide_a_failed_child(self):
        # FirmwareFileSystemSection.process returns True after dropping a
        # failed GUID-defined section, and the file around it returns True
        # too. The summary must still report the child.
        guid = uuid.UUID(FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"]).bytes_le
        firmware = parse(make_volume(make_file(
            make_section(0x02, guid + struct.pack("<HH", 24, 0) + b"not-lzma"))))
        summary = firmware.coverage()

        self.assertFalse(summary["complete"])
        self.assertTrue(regions(summary, "failed"))
        self.assertIn("decompress",
                      " ".join(r["reason"] for r in regions(summary, "failed")))

    def test_a_failing_child_keeps_its_siblings_evidence(self):
        # A good section before a broken volume still counts as parsed.
        good = make_section(0x15, "good".encode("utf-16le") + b"\0\0")
        firmware = parse(make_volume(make_file(good + broken_volume_section())))
        summary = firmware.coverage()

        self.assertEqual(summary["status"], "partial")
        self.assertGreater(len(regions(summary, "parsed")), 0)
        self.assertEqual(len(regions(summary, "failed")), 1)


class PaddingTest(unittest.TestCase):

    def test_erased_bytes_are_excluded_from_the_ratio(self):
        # One file in a mostly erased volume is completely explained, so the
        # erased tail must not be counted as unexplained.
        data = make_volume(
            make_file(make_section(0x15, "x".encode("utf-16le") + b"\0\0")),
            size=0x1000)
        summary = parse(data).coverage()

        self.assertEqual(summary["status"], "complete")
        counts = summary["spaces"]["input"]["counts"]
        self.assertEqual(counts["padding"], 0x1000 - 0x48 - 32)
        self.assertEqual(counts["parsedRatio"], 1.0)

    def test_padding_does_not_change_the_ratio(self):
        # A volume whose only content is an unknown GUID section. Growing the
        # erased area must not raise the parsed ratio: padding is removed
        # from the denominator instead of counting as parsed bytes.
        small = parse(make_volume(make_file(unknown_guid_section()), size=0x100))
        large = parse(make_volume(make_file(unknown_guid_section()),
                                  size=0x1000))
        small_counts = small.coverage()["spaces"]["input"]["counts"]
        large_counts = large.coverage()["spaces"]["input"]["counts"]
        self.assertGreater(large_counts["padding"], small_counts["padding"])
        self.assertLessEqual(large_counts["parsedRatio"],
                             small_counts["parsedRatio"])

    def test_an_empty_volume_is_complete(self):
        # There is no body to explain, so the header is all of it.
        summary = parse(make_volume()).coverage()
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["spaces"]["input"]["counts"]["bodyParsed"], 0)

    def test_header_only_when_only_structure_is_understood(self):
        # An unknown GUID section: every header is recognized, no body is.
        firmware = parse(make_volume(make_file(unknown_guid_section())))
        summary = firmware.coverage()
        self.assertEqual(summary["status"], "header-only")
        self.assertEqual(summary["spaces"]["input"]["counts"]["bodyParsed"], 0)


class TransformTest(unittest.TestCase):

    def compressed(self):
        # A payload large enough that compression shrinks it.
        payload = b"compressible firmware payload " * 64
        inner = make_section(0x19, payload)
        return parse(make_volume(make_file(compressed_section(inner))))

    def test_decompressed_bytes_are_a_separate_space(self):
        summary = self.compressed().coverage()

        self.assertEqual(len(summary["transformations"]), 1)
        transform = summary["transformations"][0]
        child = transform["to"]
        self.assertIn(child, summary["spaceOrder"])
        self.assertNotEqual(child, "input")
        self.assertEqual(summary["spaces"][child]["parent"], "input")

    def test_input_and_output_sizes_are_not_added(self):
        summary = self.compressed().coverage()
        transform = summary["transformations"][0]
        input_counts = summary["spaces"]["input"]["counts"]
        child_counts = summary["spaces"][transform["to"]]["counts"]

        # The compressed stream is charged once in the input space, and its
        # output once in the child space.
        self.assertEqual(child_counts["total"], transform["outputSize"])
        self.assertLess(transform["inputSize"], transform["outputSize"])
        # The inner raw section is kept as evidence, not interpreted.
        self.assertEqual(child_counts["preserved"], len(
            b"compressible firmware payload " * 64))
        self.assertEqual(child_counts["parsed"] + child_counts["preserved"],
                         transform["outputSize"])
        self.assertGreater(input_counts["total"], transform["inputSize"])
        # Adding the two spaces would double count; each reports its own.
        self.assertNotEqual(input_counts["total"],
                            child_counts["total"])

    def test_declared_and_actual_output_sizes_are_reported(self):
        transform = self.compressed().coverage()["transformations"][0]
        self.assertEqual(transform["declaredOutputSize"],
                         transform["outputSize"])

    def test_failed_decompression_is_reported_in_the_input_space(self):
        section = make_section(
            0x01, struct.pack("<IB", 0x100, 0x02) + b"not a stream")
        summary = parse(make_volume(make_file(section))).coverage()

        self.assertFalse(summary["complete"])
        self.assertEqual(summary["spaceOrder"], ["input"])
        failed = regions(summary, "failed")
        self.assertTrue(failed)
        self.assertIn("decompress", failed[0]["reason"])


class MixedInputTest(unittest.TestCase):
    '''The acceptance example: one good volume, one unknown GUID section and
    one corrupted nested volume in the same input.'''

    def setUp(self):
        self.good = make_volume(make_file(
            make_section(0x15, "ok".encode("utf-16le") + b"\0\0")))
        self.data = (self.good +
                     make_volume(make_file(unknown_guid_section())) +
                     make_volume(make_file(broken_volume_section())))
        self.summary = parse(self.data).coverage()

    def test_status_is_partial(self):
        self.assertEqual(self.summary["status"], "partial")
        self.assertFalse(self.summary["complete"])

    def test_each_unexplained_part_is_listed_with_its_reason(self):
        reasons = [region["reason"] for region in self.summary["unresolved"]]
        self.assertEqual(len(reasons), 2)
        self.assertTrue(any("GUID-defined" in reason and UNKNOWN_GUID in reason
                            for reason in reasons))
        self.assertTrue(any("firmware volume image" in reason
                            for reason in reasons))

    def test_the_good_volume_is_still_counted(self):
        parsed = sum(region["size"] for region in regions(
            self.summary, "parsed"))
        self.assertGreater(parsed, len(self.good))

    def test_regions_cover_the_whole_input(self):
        covered = sum(region["size"] for region in regions(self.summary))
        self.assertEqual(covered, len(self.data))

    def test_unresolved_sizes_match_the_bytes_they_describe(self):
        sizes = sorted(region["size"] for region in self.summary["unresolved"])
        self.assertEqual(sizes, [len(b"SECRETDATA"), 0x40])


class CliCoverageTest(unittest.TestCase):

    def run_cli(self, *argv):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [CLI] + list(argv)), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                runpy.run_path(CLI, run_name="__main__")
            except SystemExit as exit:
                self.assertEqual(exit.code, 0)
        return output.getvalue()

    def write(self, directory, data):
        path = os.path.join(directory, "image.fv")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_json_coverage_is_machine_readable(self):
        data = (make_volume(make_file(
                    make_section(0x15, "ok".encode("utf-16le") + b"\0\0"))) +
                make_volume(make_file(unknown_guid_section())) +
                make_volume(make_file(broken_volume_section())))
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write(temp_dir, data)
            output = self.run_cli("-p", "-j", "--coverage", path)

        summary = json.loads(output)["coverage"]
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(len(summary["unresolved"]), 2)
        for space in summary["spaces"].values():
            for region in space["regions"]:
                self.assertIn(region["kind"],
                              ("parsed", "preserved", "unknown", "failed",
                               "padding"))

    def test_json_without_the_flag_is_unchanged(self):
        data = make_volume(make_file(
            make_section(0x15, "ok".encode("utf-16le") + b"\0\0")))
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write(temp_dir, data)
            output = self.run_cli("-p", "-j", path)
        document = json.loads(output)
        self.assertIsInstance(document, dict)
        self.assertNotIn("coverage", document)

    def test_text_output_names_the_unresolved_regions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write(temp_dir, make_volume(
                make_file(unknown_guid_section())))
            output = self.run_cli("-p", "--coverage", path)
        self.assertIn("Coverage: header-only", output)
        self.assertIn(UNKNOWN_GUID, output)


if __name__ == '__main__':
    unittest.main()


class OtherFormatTest(unittest.TestCase):
    '''Coverage for the formats AutoParser also recognizes.'''

    def test_pfs_accounts_for_headers_sections_and_signatures(self):
        body = b"payload" * 4
        header = FILE_GUID + struct.pack(
            "<I4s8s8sIIII", 1, b"\x00" * 4, b"\x00" * 8, b"\x00" * 8,
            len(body), 0, 0, 0)
        section = header.ljust(0x48, b"\x00") + body
        data = (b"PFS.HDR." + struct.pack("<II", 1, len(section)) + section +
                struct.pack("<II", len(section), 0) + b"PFS.FTR.")

        summary = parse(data).coverage()
        counts = summary["spaces"]["input"]["counts"]
        self.assertEqual(counts["total"], len(data))
        self.assertEqual(
            counts["parsed"] + counts["preserved"] + counts["unknown"] +
            counts["failed"] + counts["padding"], len(data))
        self.assertGreater(counts["parsed"], 0)
        self.assertEqual(counts["unknown"], 0)

    def test_me_partition_table_and_partition_are_kept_apart(self):
        from uefi_firmware.structs.intel_me_structs import MePartitionTable
        table = MePartitionTable()
        table.Magic = b"$FPT"
        table.Entries = 1
        entry = b"FTPR" + b"\x00" * 4 + struct.pack("<II", 0x50, 0x10)
        data = bytes(table) + entry.ljust(0x20, b"\x00") + b"\x00" * 0x10

        summary = parse(data).coverage()
        counts = summary["spaces"]["input"]["counts"]
        self.assertEqual(counts["total"], len(data))
        self.assertGreater(counts["parsed"], 0)

    def test_heuristic_guid_parse_is_not_verified(self):
        # An unknown GUID whose body happens to be a firmware volume is
        # parsed by a heuristic; that must be reported as unverified.
        guid = uuid.UUID(UNKNOWN_GUID).bytes_le
        inner = make_volume()
        section = make_section(0x02, guid + struct.pack("<HH", 24, 0) + inner)
        summary = parse(make_volume(make_file(section))).coverage()

        self.assertNotEqual(summary["status"], "complete")
        self.assertTrue(any("heuristically" in item["reason"]
                            for item in summary["unverified"]))
        self.assertTrue(any("heuristically" in warning["reason"]
                            for warning in summary["warnings"]))

    def test_flash_regions_are_separate_spaces(self):
        from uefi_firmware.flash import (
            DescriptorMap, MasterSection, RegionSection)
        from uefi_firmware.structs.flash_structs import FLASH_HEADER

        size = 0x10000
        data = bytearray(size)
        data[16:20] = FLASH_HEADER
        descriptor_map = DescriptorMap(bytes(DescriptorMap.size))
        descriptor_map.structure.NumberOfFlashChips = 1
        descriptor_map.structure.RegionBase = 4
        descriptor_map.structure.NumberOfRegions = 4
        descriptor_map.structure.MasterBase = 3
        data[20:36] = bytes(descriptor_map.structure)
        region_section = RegionSection(bytes(RegionSection.size))
        region_section.structure.FlashBlockEraseSize = 0x1000
        region_section.structure.BiosBase = 4
        region_section.structure.BiosLimit = 7
        data[0x40:0x54] = bytes(region_section.structure)
        data[0x30:0x3c] = bytes(MasterSection(bytes(MasterSection.size)).structure)
        volume = make_volume()
        data[0x4000:0x4000 + len(volume)] = volume

        summary = parse(bytes(data)).coverage()
        region_spaces = [key for key in summary["spaceOrder"] if "region" in key]
        self.assertTrue(region_spaces)
        self.assertTrue(any(t["kind"].startswith("flash-region:")
                            for t in summary["transformations"]))
        # Region bytes are not merged into the descriptor's own offsets.
        for key in region_spaces:
            space = summary["spaces"][key]
            self.assertEqual(space["parent"], "input")
