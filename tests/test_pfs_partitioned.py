'''Provenance and completeness for Dell partitioned PFS chunks.

A partitioned section stores one logical stream as several chunk records. This
suite builds three small chunks and checks the normal reassembly, a removed
middle chunk and an inserted duplicate. Every case must keep each payload's
original range and its reassembled range, and must separate missing bytes,
repeated payloads, conflicting lengths and trailing data. Nothing may edit the
input bytes.
'''

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import uuid

from uefi_firmware import AutoParser
from uefi_firmware.pfs import (
    PFSFile, PFSPartitionedSection, _checksum)
from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS

SECTION_GUID = uuid.UUID("deadc0de-1234-4321-9876-0123456789ab")
FV_GUID = uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le
PAYLOAD_SIZE = 0x100


def make_volume(data=b"", size=0x300):
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = 0x38 + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB", b"\x00" * 16, FV_GUID, size, b"_FVH", 0x800,
        hdrlen, 0, 0, b"\x00", 2)
    return (header + block_map + data.ljust(size - hdrlen, b"\xff"))[:size]


def make_chunk(payload, declared=None, signatures=(0, 0, 0),
               version=b"AB\0\0"):
    '''One chunk record: header, 0x248 variable bytes, payload, signatures.'''
    header = bytearray(0x48)
    struct.pack_into("<I4s8s8s", header, 0x10, 1, version,
                     b"\x00" * 8, b"\x00" * 8)
    struct.pack_into("<IIII", header, 0x28,
                     0x248 + len(payload) if declared is None else declared,
                     *signatures)
    data = bytes(header) + b"\x00" * 0x248 + payload
    for size in signatures:
        data += b"S" * size
    return data


def make_container(chunks, footer_body=None, trailer=True):
    # The eight bytes after PFS.HDR. are opaque padding, not a body size.
    body = b"".join(chunks)
    footer_size = len(body) if footer_body is None else footer_body
    data = b"PFS.HDR." + b"\x00" * 8 + body
    if trailer:
        data += struct.pack("<II", footer_size, 0) + b"PFS.FTR."
    return data


def make_pfs_section(body):
    header = SECTION_GUID.bytes_le + struct.pack(
        "<I4s8s8sIIII", 1, b"\x00" * 4, b"\x00" * 8,
        b"\x00" * 8, len(body), 0, 0, 0)
    header = bytearray(header.ljust(0x48, b"\x00"))
    struct.pack_into("<I", header, 0x40, _checksum(body))
    return bytes(header) + body


def make_pfs(body):
    return b"PFS.HDR." + struct.pack("<II", 1, len(body)) + body + \
        struct.pack("<II", len(body), _checksum(body)) + b"PFS.FTR."


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


def split_volume():
    '''A 0x300-byte FFS2 volume cut into three distinct payloads.'''
    volume = make_volume(
        b"\x00" * 0x100 + b"\x01" * 0x100 + b"\x02" * 0x100)
    payloads = [volume[offset:offset + PAYLOAD_SIZE]
                for offset in range(0, len(volume), PAYLOAD_SIZE)]
    return payloads, volume


class PartitionedSectionTest(unittest.TestCase):

    def parse(self, data):
        section = PFSPartitionedSection(data)
        self.assertTrue(section.process())
        return section

    def test_normal_reassembly_keeps_order_and_ranges(self):
        payloads, volume = split_volume()
        container = make_container([make_chunk(data) for data in payloads])
        section = self.parse(container)

        self.assertTrue(section.complete)
        self.assertEqual(section.partitions, 3)
        self.assertEqual(section.section_data, volume)
        self.assertEqual([chunk["order"] for chunk in section.chunks],
                         [0, 1, 2])
        for index, chunk in enumerate(section.chunks):
            start = index * PAYLOAD_SIZE
            self.assertEqual(chunk["reassembly"],
                             [start, start + PAYLOAD_SIZE])
            self.assertEqual(chunk["placement"], "confirmed")
            self.assertEqual(
                container[chunk["payload"][0]:chunk["payload"][1]],
                payloads[index])
        self.assertEqual(section.coverage["unknown_ranges"], [])
        self.assertEqual(section.missing, [])
        self.assertEqual(section.duplicates, [])
        self.assertEqual(section.tail, [])
        self.assertEqual(section.length_conflicts, [])

    def test_reassembly_does_not_modify_the_input(self):
        payloads, volume = split_volume()
        container = make_container([make_chunk(data) for data in payloads])
        original = bytes(container)

        section = self.parse(container)
        self.assertEqual(section.section_data, volume)
        self.assertEqual(container, original)
        self.assertEqual(section.build(), original)

    def test_removed_middle_chunk_leaves_known_and_unknown_ranges(self):
        payloads, volume = split_volume()
        container = make_container(
            [make_chunk(payloads[0]), make_chunk(payloads[2])])
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(section.partitions, 2)
        self.assertEqual(section.coverage["confirmed_ranges"],
                         [[0, PAYLOAD_SIZE]])
        self.assertEqual(section.coverage["unknown_ranges"],
                         [[PAYLOAD_SIZE, len(volume)]])
        self.assertEqual(
            [(item["reason"], item["ranges"]) for item in section.missing],
            [("volume_declares_more", [[0x200, 0x300]])])
        self.assertEqual(section.chunks[0]["placement"], "confirmed")
        # The third payload is present, but it could not be placed at 0x100
        # with confidence: the gap may be before it.
        self.assertEqual(section.chunks[1]["placement"], "unconfirmed")
        self.assertEqual(section.chunks[1]["reassembly"],
                         [PAYLOAD_SIZE, 2 * PAYLOAD_SIZE])
        # The bytes are present, but their placement is not established.
        self.assertEqual(section.coverage["sourced_ranges"],
                         [[0, 2 * PAYLOAD_SIZE]])

    def test_inserted_duplicate_is_recorded_and_not_reassembled(self):
        payloads, volume = split_volume()
        container = make_container([
            make_chunk(payloads[0]), make_chunk(payloads[1]),
            make_chunk(payloads[1]), make_chunk(payloads[2])])
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(len(section.duplicates), 1)
        self.assertEqual(section.duplicates[0]["order"], 2)
        self.assertEqual(section.duplicates[0]["duplicate_of"], 1)
        self.assertEqual(section.chunks[2]["placement"], "duplicate")
        self.assertEqual(section.coverage["confirmed_ranges"],
                         [[0, 2 * PAYLOAD_SIZE]])
        self.assertEqual(section.tail[0]["reason"], "after_volumes")
        self.assertEqual(section.tail[0]["ranges"],
                         [[len(volume), len(volume) + PAYLOAD_SIZE]])

    def test_footer_length_conflict_is_reported_separately(self):
        payloads, _volume = split_volume()
        chunks = [make_chunk(data) for data in payloads]
        container = make_container(chunks, footer_body=len(chunks[0]))
        section = self.parse(container)

        self.assertFalse(section.complete)
        conflicts = {item["where"] for item in section.length_conflicts}
        # The footer's size disagrees with the bytes present; the chunks are
        # still framed, so the conflict is one record, not a truncation.
        self.assertEqual(conflicts, {"envelope.footer_body_size"})
        self.assertEqual(section.partitions, 3)

    def test_missing_trailer_is_a_container_error_not_a_chunk(self):
        payloads, _volume = split_volume()
        chunks = [make_chunk(data) for data in payloads]
        container = make_container(chunks, trailer=False)
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(section.container_errors[0]["where"], "footer.magic")
        self.assertEqual(section.partitions, 3)

    def test_header_only_chunk_does_not_become_a_payload(self):
        payloads, _volume = split_volume()
        header = bytearray(0x48)
        struct.pack_into("<IIII", header, 0x28, 0x248 + PAYLOAD_SIZE, 0, 0, 0)
        container = make_container([make_chunk(payloads[0]), bytes(header)])
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(section.partitions, 2)
        self.assertEqual(section.chunks[1]["payload_length"], 0)
        self.assertEqual(section.chunks[1]["placement"], "unparsed")
        self.assertEqual(section.length_conflicts[0]["where"],
                         "chunk[1].payload_range")
        self.assertEqual(section.section_data, payloads[0])
        self.assertIn("framing_lost",
                      [item["reason"] for item in section.tail])

    def test_short_chunk_header_is_tail_data(self):
        payloads, _volume = split_volume()
        chunks = [make_chunk(data) for data in payloads]
        container = make_container(chunks + [b"\x00" * 0x20])
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(section.partitions, 3)
        self.assertEqual(section.tail[0]["reason"], "chunk_framing_leftover")
        self.assertEqual(section.coverage["unframed_ranges"],
                         section.tail[0]["ranges"])

    def test_declared_version_is_not_used_as_identity(self):
        payloads, _volume = split_volume()
        container = make_container([
            make_chunk(payloads[0]),
            make_chunk(payloads[1], version=b"CD\0\0"),
            make_chunk(payloads[2], version=b"EF\0\0")])
        section = self.parse(container)

        # Declared versions differ, but the payloads are still distinct, so
        # nothing is merged or dropped on the strength of the declaration.
        self.assertTrue(section.complete)
        self.assertEqual(section.duplicates, [])
        self.assertEqual(len({chunk["declared"]["version_type"]
                              for chunk in section.chunks}), 3)

    def test_truncated_chunk_reports_the_absent_range(self):
        payloads, _volume = split_volume()
        # A chunk that claims a 0x100-byte payload but holds only 0x80.
        second = make_chunk(payloads[1][:PAYLOAD_SIZE // 2],
                            declared=0x248 + PAYLOAD_SIZE)
        container = make_container([make_chunk(payloads[0]), second])
        section = self.parse(container)

        self.assertFalse(section.complete)
        self.assertEqual(section.chunks[1]["payload_length"],
                         PAYLOAD_SIZE // 2)
        reasons = [(item["reason"], item["space"])
                   for item in section.missing]
        self.assertIn(("chunk_payload_absent", "container"), reasons)
        self.assertEqual(section.chunks[1]["status"], "truncated")
        # The volume still declares 0x300 bytes but only 0x180 were sourced,
        # which is a separate statement about the reassembled stream.
        self.assertIn(("volume_declares_more", "reassembly"), reasons)
        self.assertEqual(section.coverage["unknown_ranges"],
                         [[PAYLOAD_SIZE, 0x300]])

    def test_to_dict_and_dump_keep_the_trace(self):
        payloads, volume = split_volume()
        container = make_container(
            [make_chunk(payloads[0]), make_chunk(payloads[2])])
        section = self.parse(container)
        exported = section.to_dict()

        # The partitioned body has no meaningful GUID of its own; the
        # enclosing PFSSection carries the identity and is tested below.
        self.assertFalse(exported["complete"])
        self.assertEqual(len(exported["chunks"]), 2)
        self.assertEqual(exported["coverage"]["unknown_ranges"],
                         [[PAYLOAD_SIZE, len(volume)]])

        with tempfile.TemporaryDirectory() as temp_dir:
            quietly(section.dump, temp_dir)
            base = os.path.join(temp_dir, "partitioned")
            with open(base + ".provenance.json", "r") as handle:
                manifest = json.load(handle)
            with open(base + ".data", "rb") as handle:
                self.assertEqual(handle.read(), section.section_data)
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["coverage"]["unknown_ranges"],
                         [[PAYLOAD_SIZE, len(volume)]])

    def test_through_pfs_file_and_section(self):
        payloads, volume = split_volume()
        container = make_container(
            [make_chunk(data) for data in payloads])
        data = make_pfs(make_pfs_section(container))
        pfs_file = PFSFile(data)
        self.assertTrue(pfs_file.valid_header)
        self.assertTrue(quietly(pfs_file.process))

        self.assertEqual(len(pfs_file.sections), 1)
        section = pfs_file.sections[0]
        self.assertEqual(len(section.section_objects), 1)
        rom = section.section_objects[0]
        self.assertIsInstance(rom, PFSPartitionedSection)
        self.assertTrue(rom.complete)
        self.assertEqual(rom.section_data, volume)
        self.assertEqual(quietly(pfs_file.build), data)

    def test_autoparser_finds_the_partitioned_section(self):
        payloads, volume = split_volume()
        data = make_pfs(make_pfs_section(make_container(
            [make_chunk(payload) for payload in payloads])))
        parsed = AutoParser(data).parse()

        self.assertIsInstance(parsed, PFSFile)
        rom = parsed.sections[0].section_objects[0]
        self.assertIsInstance(rom, PFSPartitionedSection)
        self.assertEqual(rom.section_data, volume)


if __name__ == '__main__':
    unittest.main()
