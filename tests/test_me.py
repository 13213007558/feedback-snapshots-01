import ctypes
import json
import os
import runpy
import struct
import sys
import tempfile
import unittest
from unittest import mock

from uefi_firmware import AutoParser, me
from uefi_firmware.me import (
    COMP_TYPE_HUFFMAN, COMP_TYPE_NOT_COMPRESSED, CPDManifestHeader,
    MeContainer, MeLLUT, MeManifestHeader)
from uefi_firmware.structs.intel_me_structs import (
    HuffmanLUTHeader, MeManifestHeaderType, MeModuleHeader2Type,
    MePartitionTable)

HUFFMAN_FLAG = 0x02000000


def make_cpd(entries, header_length=0x10):
    '''A $CPD directory, with each entry's data following the entry table.'''
    table_end = header_length + 0x18 * len(entries)
    table = b""
    body = b""
    for name, data, flags in entries:
        offset = table_end + len(body)
        table += struct.pack("<12sIII", name, offset | flags, len(data), 0)
        body += data
    header = b"$CPD" + struct.pack("<IBBBB4s", len(entries), 1, 1,
                                   header_length, 0, b"FTPR")
    return header.ljust(header_length, b"\x00") + table + body


def make_fpt(partitions):
    '''A partition table, with each partition's data following the table.'''
    table = MePartitionTable()
    table.Magic = b"$FPT"
    table.Entries = len(partitions)
    table_end = 0x30 + 0x20 * len(partitions)
    entries = b""
    body = b""
    for name, data in partitions:
        entries += struct.pack(
            "<4s4sII", name, b"\x00" * 4, table_end + len(body), len(data)
        ).ljust(0x20, b"\x00")
        body += data
    return bytes(table) + entries + body


def me_manifest(size_dw=0):
    manifest = MeManifestHeaderType()
    manifest.ModuleType = 4
    manifest.HeaderLen = 0xA1
    manifest.Size = size_dw
    manifest.Tag = b"$MN2"
    manifest.PartitionName = b"FTPR"
    # Modules follow the header and its key, at the partition offset.
    return bytes(manifest).ljust(0xA1 * 4 + 12, b"\x00")


class MeContainerTest(unittest.TestCase):

    def test_size_is_the_length_of_its_data(self):
        # The size added the whole container's length for every partition.
        data = make_fpt([(b"FTPR", b"\x00" * 0x10), (b"NFTP", b"\x00" * 0x10)])
        container = MeContainer(data)
        self.assertTrue(container.process())
        self.assertEqual(container.size, len(data))

    def test_table_without_partitions(self):
        # A size of 8 left the rest of the table to be parsed as new objects.
        data = make_fpt([]) + b"\x00" * 0x100
        firmware = AutoParser(data).parse()
        self.assertIsInstance(firmware, MeContainer)
        self.assertEqual(firmware.size, len(data))

    def test_partitions_with_the_same_name_do_not_overwrite(self):
        container = MeContainer(make_fpt(
            [(b"FTPR", b"first"), (b"FTPR", b"second")]))
        self.assertTrue(container.process())

        with tempfile.TemporaryDirectory() as temp_dir:
            container.dump(temp_dir)

            partitions = os.path.join(temp_dir, "partitions")
            for name, data in (("FTPR.partition", b"first"),
                               ("FTPR-1.partition", b"second")):
                with open(os.path.join(partitions, name), "rb") as fh:
                    self.assertEqual(fh.read(), data)


class CPDManifestHeaderTest(unittest.TestCase):

    def entries(self, data):
        manifest = CPDManifestHeader(data)
        self.assertTrue(manifest.process())
        return manifest.modules

    def test_first_entry_is_parsed(self):
        modules = self.entries(make_cpd([
            (b"FTPR.man", b"manifest", 0), (b"kernel.met", b"metadata", 0)]))
        self.assertEqual(
            [module.name for module in modules], ["FTPR.man", "kernel.met"])
        self.assertEqual(modules[0].compression, COMP_TYPE_NOT_COMPRESSED)

    def test_huffman_entry(self):
        # The offset's huffman flag failed the bounds check, so huffman
        # entries were dropped.
        modules = self.entries(make_cpd([
            (b"FTPR.man", b"manifest", 0), (b"kernel", b"huffman", HUFFMAN_FLAG)]))
        self.assertEqual(len(modules), 2)
        self.assertEqual(modules[1].compression, COMP_TYPE_HUFFMAN)
        self.assertEqual(modules[1].data, b"huffman")

    def test_version_2_header(self):
        modules = self.entries(make_cpd(
            [(b"FTPR.man", b"manifest", 0)], header_length=0x14))
        self.assertEqual([module.name for module in modules], ["FTPR.man"])

    def test_entries_with_the_same_name_do_not_overwrite(self):
        manifest = CPDManifestHeader(make_cpd([
            (b"kernel.met", b"first", 0), (b"kernel.met", b"second", 0)]))
        self.assertTrue(manifest.process())

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest.dump(temp_dir)

            for name, data in (("kernel.met.module", b"first"),
                               ("kernel.met-1.module", b"second")):
                with open(os.path.join(temp_dir, name), "rb") as fh:
                    self.assertEqual(fh.read(), data)


class OverlapTest(unittest.TestCase):
    '''Each partition, module and CPD entry keeps a copy of its bytes, so a
    table pointing every entry at the same bytes used memory and dump space
    that grew with the square of the input.'''

    SIZE = 0x8000

    def claimed(self, entries):
        return sum(len(entry.data) for entry in entries)

    def test_overlapping_partitions(self):
        count = (self.SIZE - 0x30) // 0x20
        data = make_fpt([(b"PART", b"")] * count).ljust(self.SIZE, b"\x00")
        # Point every partition at all of the data after its first byte.
        table = bytearray(data)
        for i in range(count):
            struct.pack_into(
                "<II", table, 0x30 + i * 0x20 + 8, 1, self.SIZE - 1)
        container = MeContainer(bytes(table))
        container.process()
        self.assertLessEqual(self.claimed(container.partitions), 4 * self.SIZE)

    def test_partitions_ending_past_the_data(self):
        # These have no content but each still copied the rest of the data.
        count = (self.SIZE - 0x30) // 0x20
        data = bytearray(
            make_fpt([(b"PART", b"")] * count).ljust(self.SIZE, b"\x00"))
        for i in range(count):
            struct.pack_into("<II", data, 0x30 + i * 0x20 + 8, 1, self.SIZE)
        container = MeContainer(bytes(data))
        container.process()
        self.assertLessEqual(
            sum(len(getattr(p, "data", b"")) for p in container.partitions),
            4 * self.SIZE)

    def test_partly_overlapping_partitions_are_kept(self):
        # An update partition can cover others, as in CSME images.
        body = b"\x00" * 0x1000
        data = bytearray(make_fpt([(b"FTPR", body), (b"FTUP", body)]))
        struct.pack_into("<I", data, 0x30 + 0x20 + 8, 0x70)
        container = MeContainer(bytes(data))
        container.process()
        self.assertEqual(len(container.partitions), 2)

    def test_overlapping_cpd_entries(self):
        count = 0x400
        data = make_cpd([(b"mod", b"", 0)] * count).ljust(self.SIZE, b"\x00")
        table = bytearray(data)
        for i in range(count):
            struct.pack_into("<II", table, 0x10 + i * 0x18 + 12, 0, self.SIZE)
        manifest = CPDManifestHeader(bytes(table))
        manifest.process()
        self.assertLessEqual(self.claimed(manifest.modules), 4 * self.SIZE)

    def test_overlapping_modules(self):
        count = 0x100
        header = MeManifestHeaderType()
        header.ModuleType = 4
        header.HeaderLen = 0xA1
        header.Tag = b"$MN2"
        header.NumModules = count
        start = 0xA1 * 4 + 12
        modules = b""
        for i in range(count):
            # Each module's data starts at its own header and runs to the end.
            module = MeModuleHeader2Type()
            module.Tag = b"$MME"
            module.Offset = start + i * ctypes.sizeof(module)
            module.Size = self.SIZE
            modules += bytes(module)
        data = (bytes(header).ljust(start, b"\x00") + modules).ljust(
            self.SIZE, b"\x00")
        manifest = MeManifestHeader(data)
        manifest.process()
        self.assertLessEqual(self.claimed(manifest.modules), 4 * self.SIZE)


class HuffmanLUTTest(unittest.TestCase):

    def test_no_table_without_a_huffman_module(self):
        # Without a huffman module the table's offset was negative, so the
        # end of the partition was read as a table.
        tail = b"LLUT".ljust(0xA1 * 4 + 12, b"\x00")
        manifest = MeManifestHeader(me_manifest() + b"\x00" * 0x100 + tail)
        self.assertTrue(manifest.process())
        self.assertIsNone(manifest.huffman_llut)

    def test_data_cannot_start_before_the_table(self):
        header = HuffmanLUTHeader()
        header.Tag = b"LLUT"
        header.DataStart = 0x100
        header.Size = 0x10
        data = bytes(header) + b"\x00" * 0x100 + b"tail-of-the-data"
        self.assertFalse(MeLLUT(data, 0x200).valid_header)
        self.assertTrue(MeLLUT(data, 0x100).valid_header)


if __name__ == '__main__':
    unittest.main()


def make_cpd_ranges(entries, header_length=0x10, body=b""):
    '''A $CPD directory whose entries name their own offset and size.

    Each entry is (name, offset, size, flags), with offset relative to the
    body that follows the table. This allows entries to alias or partly
    overlap one another.
    '''
    body_start = header_length + 0x18 * len(entries)
    table = b""
    for name, offset, size, flags in entries:
        # Flags sit above the 25-bit offset field, so apply the mask first.
        table += struct.pack("<12sIII", name,
                             (body_start + offset) | flags, size, 0)
    header = b"$CPD" + struct.pack("<IBBBB4s", len(entries), 1, 1,
                                   header_length, 0, b"FTPR")
    return header.ljust(header_length, b"\x00") + table + body


class ContentInventoryTest(unittest.TestCase):
    '''A directory entry's identity is its slot in the table, while the
    content it obtains is its declared range. The two must not be conflated:
    aliases keep both records and count the content once, and an equal name
    or equal decompressed bytes never merge records.'''

    def inventory(self, entries, body=b"\x00" * 0x20, base_offset=0):
        table = make_cpd_ranges(entries, body=body)
        manifest = CPDManifestHeader(table, container_offset=base_offset)
        self.assertTrue(manifest.process())
        inventory = manifest.to_dict()['inventory']
        # The body follows the header and the entry table.
        inventory['body_start'] = 0x10 + 0x18 * len(entries)
        return inventory

    def test_two_exact_aliases_keep_both_records_and_count_once(self):
        # Two entries name the same 8 bytes; a third is independent.
        inventory = self.inventory([
            (b"kernel", 0x00, 8, 0),
            (b"kernel", 0x00, 8, 0),
            (b"other", 0x08, 8, 0),
        ], body=b"\x00" * 0x20)

        self.assertEqual(inventory['entry_count'], 3)
        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertEqual(inventory['duplicate_entry_count'], 1)
        # The alias group names both directory entries, in table order.
        self.assertEqual(len(inventory['aliases']), 1)
        self.assertEqual(inventory['aliases'][0]['entries'],
                         ['entry-0', 'entry-1'])
        body = inventory['body_start']
        self.assertEqual(inventory['aliases'][0]['range'], [body, body + 8])
        # Each record keeps its own identity and points at the first claim.
        records = inventory['entries']
        self.assertEqual([record['id'] for record in records],
                         ['entry-0', 'entry-1', 'entry-2'])
        self.assertIsNone(records[0]['alias_of'])
        self.assertEqual(records[1]['alias_of'], 'entry-0')
        self.assertIsNone(records[2]['alias_of'])
        # Aliases are reported as aliases, not as overlaps.
        self.assertEqual(inventory['overlaps'], [])
        self.assertEqual(records[0]['content_id'], records[1]['content_id'])
        self.assertNotEqual(records[2]['content_id'], records[0]['content_id'])
        self.assertEqual(inventory['claimed_bytes'], 24)
        self.assertEqual(inventory['covered_bytes'], 16)

    def test_partial_overlap_stays_two_records(self):
        # One entry covers bytes 0x100..0x108, the next 0x104..0x10c.
        inventory = self.inventory([
            (b"kernel", 0x00, 8, 0),
            (b"kernel", 0x04, 8, 0),
        ], body=b"\x00" * 0x20)

        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertEqual(inventory['aliases'], [])
        self.assertEqual(len(inventory['overlaps']), 1)
        body = inventory['body_start']
        overlap = inventory['overlaps'][0]
        self.assertEqual(overlap['entries'], ['entry-0', 'entry-1'])
        self.assertEqual(overlap['kind'], 'partial')
        self.assertEqual(overlap['range'], [body + 4, body + 8])
        self.assertEqual(inventory['entries'][0]['overlaps'], ['entry-1'])
        self.assertEqual(inventory['entries'][1]['overlaps'], ['entry-0'])
        self.assertEqual(inventory['claimed_bytes'], 16)
        self.assertEqual(inventory['covered_bytes'], 12)

    def test_containment_is_not_an_alias(self):
        inventory = self.inventory([
            (b"outer", 0x00, 0x10, 0),
            (b"inner", 0x08, 4, 0),
        ], body=b"\x00" * 0x20)

        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertEqual(inventory['aliases'], [])
        self.assertEqual(
            [(overlap['entries'], overlap['kind'])
             for overlap in inventory['overlaps']],
            [(['entry-0', 'entry-1'], 'contains')])

    def test_same_name_different_content_is_not_an_alias(self):
        # Equal names never group records; equal bytes at different ranges
        # are not even physically the same content.
        inventory = self.inventory([
            (b"kernel", 0x00, 4, 0),
            (b"kernel", 0x04, 4, 0),
        ], body=b"\x00" * 8)

        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertEqual(inventory['aliases'], [])
        self.assertEqual(inventory['overlaps'], [])
        self.assertEqual([record['name'] for record in inventory['entries']],
                         ['kernel', 'kernel'])
        self.assertNotEqual(
            inventory['entries'][0]['content_id'],
            inventory['entries'][1]['content_id'])

    def test_equal_derived_bytes_do_not_merge_records(self):
        # Two non-aliasing ranges holding the same bytes derive the same
        # digest; that is evidence about the bytes, not the directory.
        inventory = self.inventory([
            (b"first", 0x00, 4, 0),
            (b"second", 0x04, 4, 0),
        ], body=b"ABCDABCD")

        first, second = inventory['entries']
        self.assertEqual(first['derived']['sha256'],
                         second['derived']['sha256'])
        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertNotEqual(first['content_id'], second['content_id'])

    def test_compression_and_derived_content_are_separate(self):
        # A compressed entry records its form and derived output separately
        # from the range its directory entry claims.
        inventory = self.inventory([
            (b"kernel.met", 0x00, 4, 0),
            (b"kernel", 0x00, 4, HUFFMAN_FLAG),
        ], body=b"data")

        metadata, huffman = inventory['entries']
        self.assertEqual(metadata['compression_name'], 'COMP_TYPE_NOT_COMPRESSED')
        self.assertEqual(huffman['compression_name'], 'COMP_TYPE_HUFFMAN')
        # The huffman stream is decoded with its partition, not on its own.
        self.assertFalse(huffman['derived']['available'])
        # Same range, so they are exact aliases despite the different form.
        self.assertEqual(inventory['aliases'][0]['entries'],
                         ['entry-0', 'entry-1'])
        self.assertEqual(inventory['independent_content_count'], 1)

    def test_absolute_range_uses_the_container_offset(self):
        inventory = self.inventory(
            [(b"kernel", 0x00, 4, 0)], body=b"data", base_offset=0x2000)
        record = inventory['entries'][0]
        body = inventory['body_start']
        self.assertEqual(record['range'], [body, body + 4])
        self.assertEqual(record['absolute_range'], [0x2000 + body, 0x2004 + body])

    def test_manifest_modules_export_an_inventory(self):
        # A ME manifest's modules are directory entries too: two headers may
        # name the same range, and the same name means nothing.
        count = 3
        header = MeManifestHeaderType()
        header.ModuleType = 4
        header.HeaderLen = 0xA1
        header.Tag = b"$MN2"
        header.NumModules = count
        start = 0xA1 * 4 + 12
        modules = b""
        size = ctypes.sizeof(MeModuleHeader2Type)
        for name, offset in ((b"KERN", start), (b"KERN", start),
                             (b"TEST", start + size)):
            module = MeModuleHeader2Type()
            module.Tag = b"$MME"
            module.Name = name
            module.Offset = offset
            module.Size = 0x10
            modules += bytes(module)
        data = (bytes(header).ljust(start, b"\x00") + modules).ljust(
            start + 4 * size + 0x100, b"\x00")
        manifest = MeManifestHeader(data)
        self.assertTrue(manifest.process())

        inventory = manifest.to_dict()['inventory']
        self.assertEqual(inventory['entry_count'], 3)
        self.assertEqual(inventory['independent_content_count'], 2)
        self.assertEqual(len(inventory['aliases']), 1)
        self.assertEqual(inventory['aliases'][0]['entries'],
                         ['entry-0', 'entry-1'])
        self.assertIsNone(inventory['entries'][0]['alias_of'])
        self.assertEqual(inventory['entries'][1]['alias_of'], 'entry-0')

    def test_entries_without_data_keep_their_slot(self):
        # An entry pointing past the data has no bytes and is not a record,
        # but it still holds a slot in the directory: later slots must not
        # shift into its place.
        inventory = self.inventory([
            (b"gone", 0x00, 0x1000, 0),
            (b"kernel", 0x00, 4, 0),
            (b"verify", 0x04, 4, 0),
        ], body=b"dataBEEF")

        self.assertEqual([record['id'] for record in inventory['entries']],
                         ['entry-1', 'entry-2'])
        self.assertEqual(inventory['entry_count'], 2)
        self.assertEqual(inventory['independent_content_count'], 2)

    def test_overlap_report_is_capped(self):
        # Every entry overlaps every other one. The report stops at a fixed
        # number of pairs and says so, rather than growing with the square.
        count = 0x200
        body = b"\x00" * (count + 2)
        # Each entry covers two bytes and overlaps its neighbours: adjacent
        # ranges partly overlap without being identical, so no aliases.
        entries = [(b"kernel", index, 2, 0) for index in range(count)]
        table = make_cpd_ranges(entries, body=body)
        manifest = CPDManifestHeader(table)
        self.assertTrue(manifest.process())
        with mock.patch.object(me, "MAX_OVERLAP_PAIRS", 100):
            inventory = manifest.to_dict()['inventory']
        self.assertEqual(len(inventory['overlaps']), 100)
        self.assertTrue(inventory['overlapsTruncated'])

    def test_no_overlap_scan_is_linear(self):
        # Many entries, none overlapping, must not cost entries squared.
        count = 0x800
        body = b"\x00" * count
        inventory = self.inventory(
            [(b"mod", index, 1, 0) for index in range(count)], body=body)
        self.assertEqual(inventory['entry_count'], count)
        self.assertEqual(inventory['independent_content_count'], count)
        self.assertEqual(inventory['overlaps'], [])

    def test_equal_decompressed_bytes_do_not_merge_lzma_entries(self):
        # Two separate LZMA streams decompress to the same bytes. The
        # derived digest matches, but the directory entries and their
        # physical ranges remain distinct.
        from uefi_firmware import efi_compressor
        payload = b"same kernel bytes" * 4
        stream = efi_compressor.LzmaCompress(payload, len(payload))
        inventory = self.inventory([
            (b"kernel", 0x00, len(stream), 0),
            (b"kernel", len(stream), len(stream), 0),
        ], body=stream + stream)

        first, second = inventory['entries']
        self.assertEqual(first['compression_name'], 'COMP_TYPE_LZMA')
        self.assertEqual(first['derived']['sha256'],
                         second['derived']['sha256'])
        self.assertEqual(first['derived']['size'], len(payload))
        self.assertEqual(inventory['aliases'], [])
        self.assertEqual(inventory['independent_content_count'], 2)

    def test_exact_alias_of_a_compressed_entry_counts_once(self):
        # One stream, two entries naming it: one physical range, so one
        # content record, and both entries keep their identity.
        from uefi_firmware import efi_compressor
        payload = b"kernel bytes" * 4
        stream = efi_compressor.LzmaCompress(payload, len(payload))
        inventory = self.inventory([
            (b"kernel", 0x00, len(stream), 0),
            (b"kernel", 0x00, len(stream), 0),
        ], body=stream)

        self.assertEqual(inventory['entry_count'], 2)
        self.assertEqual(inventory['independent_content_count'], 1)
        self.assertEqual(inventory['covered_bytes'], len(stream))
        self.assertEqual(inventory['claimed_bytes'], 2 * len(stream))
        self.assertEqual(inventory['entries'][1]['alias_of'], 'entry-0')
        self.assertEqual(inventory['entries'][0]['derived']['size'],
                         len(payload))

    def test_unique_dump_matches_independent_content_count(self):
        # Two entries alias one range. A forensic extraction can write one
        # file per physical range; the only-file-per-entry behaviour stays
        # available by default.
        cpd = CPDManifestHeader(make_cpd_ranges([
            (b"kernel.man", 0x00, 4, 0),
            (b"kernel.man", 0x00, 4, 0),
        ], body=b"data"))
        self.assertTrue(cpd.process())
        self.assertEqual(
            cpd.to_dict()['inventory']['independent_content_count'], 1)

        with tempfile.TemporaryDirectory() as folder:
            with mock.patch("sys.stdout"):
                cpd.dump(folder, unique=True)
            self.assertEqual(
                [name for name in os.listdir(folder)],
                ["kernel.man.module"])

        with tempfile.TemporaryDirectory() as folder:
            with mock.patch("sys.stdout"):
                cpd.dump(folder)
            self.assertEqual(
                sorted(name for name in os.listdir(folder)),
                ["kernel.man-1.module", "kernel.man.module"])

class MeContainerJsonTest(unittest.TestCase):

    def test_json_keeps_inventory_relations(self):
        # A ME image with a CPD partition: -j must not raise, and the
        # relations must survive into the JSON document.
        cpd = make_cpd([
            (b"kernel", b"same-bytes", 0),
            (b"kernel", b"same-bytes", 0),
        ])
        data = make_fpt([(b"FTPR", cpd)])
        firmware = AutoParser(data).parse()
        self.assertIsInstance(firmware, MeContainer)

        document = json.loads(json.dumps(firmware.to_dict()))
        partition = document['partitions'][0]
        self.assertEqual(partition['name'], 'FTPR')
        inventory = partition['manifest']['inventory']
        self.assertEqual(inventory['entry_count'], 2)
        self.assertEqual(inventory['independent_content_count'], 2)
        # make_cpd gives each entry its own copy, so the ranges differ and
        # neither the equal name nor the equal bytes merge them.
        self.assertEqual(inventory['aliases'], [])
        self.assertEqual([record['name'] for record in inventory['entries']],
                         ['kernel', 'kernel'])
        self.assertEqual(
            inventory['entries'][0]['derived']['sha256'],
            inventory['entries'][1]['derived']['sha256'])

    def test_cli_json(self):
        cpd = make_cpd([(b"kernel", b"data", 0)])
        data = make_fpt([(b"FTPR", cpd)])
        cli = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "bin",
            "uefi-firmware-parser")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "image.me")
            with open(path, "wb") as fh:
                fh.write(data)
            import contextlib
            import io
            output = io.StringIO()
            with mock.patch.object(sys, "argv", [cli, "-j", path]), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    runpy.run_path(cli, run_name="__main__")
                except SystemExit as exit:
                    self.assertEqual(exit.code, 0)
            document = json.loads(output.getvalue())
        inventory = document['partitions'][0]['manifest']['inventory']
        self.assertEqual(inventory['entry_count'], 1)
        self.assertEqual(inventory['contents'][0]['size'], 4)
