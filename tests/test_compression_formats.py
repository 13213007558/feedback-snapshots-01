'''The compression section format chain.

Each test builds a short sample in one compression format and checks that
the parser either takes it, with the decoded bytes equal to the original,
or refuses it and names the conversion stage that failed. A format must not
be decoded as another one, and a truncated, padded or corrupt stream must
not be reported as an empty or valid section.
'''

import contextlib
import gzip
import io
import struct
import unittest
import unittest.mock
import uuid
import zlib

from uefi_firmware import efi_compressor
from uefi_firmware.structs.uefi_structs import FIRMWARE_GUIDED_GUIDS
from uefi_firmware.uefi import CompressedSection, GuidDefinedSection

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
PAYLOAD = b"firmware payload"


def make_section(section_type, body):
    size = 4 + len(body)
    data = struct.pack("<I", size)[:3] + bytes([section_type]) + body
    return data + b"\x00" * (-len(data) % 4)


def raw_child(payload=PAYLOAD):
    '''A raw section, the usual content of a compressed section.'''
    return make_section(0x19, payload)


def standard(type_, stream, declared=None, payload=PAYLOAD):
    child = raw_child(payload)
    body = struct.pack(
        "<IB", len(child) if declared is None else declared, type_) + stream
    return CompressedSection(body, FILE_GUID)


def guided(name, stream, offset=24, preamble=b"", attrs=1):
    body = uuid.UUID(FIRMWARE_GUIDED_GUIDS[name]).bytes_le + \
        struct.pack("<HH", offset, attrs) + preamble + stream
    return GuidDefinedSection(body, large_header=False)


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


class Decoded:
    '''The facts a test asserts on after processing a section.'''

    def __init__(self, section):
        self.section = section
        self.decoder = getattr(section, "decoder", None)
        self.declared_size = getattr(section, "declared_size", None)
        self.decoded_size = getattr(section, "decode_size", None)
        self.trailing_bytes = getattr(section, "trailing_bytes", None)
        self.failure_stage = getattr(section, "failure_stage", None)
        self.data = getattr(section, "data", None)


class Base:
    def parse(self, section):
        quietly(section.process)
        return Decoded(section)

    def assertAccepted(self, section, payload=PAYLOAD):
        result = self.parse(section)
        expected = raw_child(payload)
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data, expected)
        self.assertIsNone(result.failure_stage)
        self.assertEqual(result.declared_size, len(expected))
        self.assertEqual(result.decoded_size, len(expected))
        self.assertEqual(len(result.section.subsections), 1)
        self.assertEqual(result.section.subsections[0].data, payload)
        return result

    def assertRejected(self, section, stage, payload=PAYLOAD):
        result = self.parse(section)
        self.assertIsNone(result.decoder)
        self.assertEqual(result.failure_stage, stage)
        # Neither the undecoded stream nor an empty result stands in for the
        # payload the section claimed to hold.
        self.assertNotEqual(result.data, raw_child(payload))
        self.assertNotEqual(result.data, b"")


class StandardCompressionTest(Base, unittest.TestCase):
    '''Section type 0x01 (EFI/Tiano) and 0x02 (customized) streams.'''

    def test_efi_stream_is_identified(self):
        stream = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        for type_ in (0x01, 0x02):
            with self.subTest(type_=type_):
                result = self.assertAccepted(standard(type_, stream))
                self.assertEqual(result.decoder, "efi")

    def test_tiano_stream_is_identified(self):
        stream = efi_compressor.TianoCompress(raw_child(), len(raw_child()))
        for type_ in (0x01, 0x02):
            with self.subTest(type_=type_):
                result = self.assertAccepted(standard(type_, stream))
                self.assertEqual(result.decoder, "tiano")

    def test_lzma_stream_is_identified(self):
        stream = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        result = self.assertAccepted(standard(0x02, stream))
        self.assertEqual(result.decoder, "lzma")

    def test_lzma_stream_is_not_a_standard_section(self):
        # A standard section (0x01) only holds EFI/Tiano streams. An LZMA
        # stream was previously tried as one and its header was used as the
        # size of a Huffman body.
        stream = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        self.assertRejected(standard(0x01, stream), "truncated-stream")

    def test_same_content_in_each_format(self):
        # The same child section in EFI, Tiano and LZMA streams. Each is
        # accepted with the original bytes, and by its own decoder, so a
        # format is never mistaken for another one that happens to decode.
        child = raw_child()
        formats = (
            ("efi", 0x01, efi_compressor.EfiCompress),
            ("tiano", 0x01, efi_compressor.TianoCompress),
            ("lzma", 0x02, efi_compressor.LzmaCompress),
        )
        decoded = {}
        for name, type_, compress in formats:
            stream = compress(child, len(child))
            with self.subTest(format=name):
                result = self.assertAccepted(standard(type_, stream))
                self.assertEqual(result.decoder, name)
                self.assertEqual(result.data, child)
                decoded[name] = result.decoded_size
        self.assertEqual(set(decoded.values()), {len(child)})

    def test_tiano_stream_in_an_efi_wrapper_is_caught(self):
        # Every Tiano section was decoded with the EFI decoder first. Both
        # decoders return bytes, so the EFI decoder's output, not the
        # original payload, was kept.
        stream = efi_compressor.TianoCompress(raw_child(), len(raw_child()))
        result = self.assertAccepted(standard(0x01, stream))
        self.assertEqual(result.decoder, "tiano")

    def test_uncompressed_section_has_no_decoder(self):
        child = raw_child()
        section = standard(0x00, child, declared=len(child))
        result = self.parse(section)
        self.assertEqual(result.data, child)
        self.assertIsNone(result.decoder)
        self.assertIsNone(result.failure_stage)

    def test_unknown_type_is_not_guessed(self):
        for type_ in (0x03, 0x7F, 0xFF):
            with self.subTest(type_=type_):
                stream = efi_compressor.EfiCompress(
                    raw_child(), len(raw_child()))
                self.assertRejected(
                    standard(type_, stream), "unsupported-type")

    def test_empty_stream_only_when_both_sizes_are_zero(self):
        # An empty stream with a zero declared size is a real, empty result.
        empty = standard(0x01, efi_compressor.EfiCompress(b"", 0), declared=0)
        result = self.parse(empty)
        self.assertEqual(result.data, b"")
        self.assertEqual(result.decoder, "efi")
        self.assertIsNone(result.failure_stage)

        # A stream that decodes to nothing cannot stand in for a payload the
        # container says it holds.
        claimed = standard(0x01, efi_compressor.EfiCompress(b"", 0),
                           declared=len(raw_child()))
        self.assertRejected(claimed, "empty-output")


class TrailingBytesTest(Base, unittest.TestCase):
    '''Bytes after a stream are not part of it.'''

    def test_trailing_junk_is_rejected(self):
        for name, stream in (
                ("efi", efi_compressor.EfiCompress),
                ("tiano", efi_compressor.TianoCompress)):
            with self.subTest(stream=name):
                encoded = stream(raw_child(), len(raw_child()))
                section = standard(0x01, encoded + b"JUNK")
                self.assertRejected(section, "trailing-bytes")

    def test_trailing_junk_after_lzma_is_rejected(self):
        encoded = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        self.assertRejected(
            standard(0x02, encoded + b"JUNK"), "trailing-bytes")

    def test_alignment_padding_is_allowed(self):
        # Section sizes are 4-byte aligned, so up to three zero bytes pad a
        # stream and must not be reported as a damaged stream.
        encoded = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        padded = encoded + b"\x00" * (-len(encoded) % 4)
        result = self.assertAccepted(standard(0x01, padded))
        self.assertEqual(result.trailing_bytes, len(padded) - len(encoded))

    def test_erased_flash_padding_is_allowed(self):
        # Vendors also fill alignment with erased flash (0xFF).
        encoded = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        padded = encoded + b"\xff" * (-len(encoded) % 4)
        result = self.assertAccepted(standard(0x01, padded))
        self.assertEqual(result.trailing_bytes, len(padded) - len(encoded))

    def test_four_bytes_after_a_stream_are_not_padding(self):
        encoded = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        self.assertRejected(
            standard(0x01, encoded + b"\x00" * 4), "trailing-bytes")


class DamagedHeaderTest(Base, unittest.TestCase):
    '''A header that does not describe the bytes it is followed by.'''

    def test_truncated_stream(self):
        for name, stream, type_ in (
                ("efi", efi_compressor.EfiCompress, 0x01),
                ("tiano", efi_compressor.TianoCompress, 0x01),
                ("lzma", efi_compressor.LzmaCompress, 0x02)):
            with self.subTest(stream=name):
                encoded = stream(raw_child(), len(raw_child()))
                self.assertRejected(
                    standard(type_, encoded[:-1]), "truncated-stream")

    def test_body_size_larger_than_the_data(self):
        encoded = bytearray(
            efi_compressor.EfiCompress(raw_child(), len(raw_child())))
        struct.pack_into("<I", encoded, 0, len(encoded))
        self.assertRejected(
            standard(0x01, bytes(encoded)), "truncated-stream")

    def test_stream_short_of_its_declared_output(self):
        encoded = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        self.assertRejected(standard(0x01, encoded, declared=len(PAYLOAD)),
                            "declared-size")

    def test_stream_longer_than_its_declared_output(self):
        encoded = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        self.assertRejected(
            standard(0x01, encoded, declared=len(raw_child()) + 8),
            "declared-size")

    def test_lzma_header_claiming_the_wrong_size(self):
        # The stream ends before the size its properties claim.
        encoded = bytearray(
            efi_compressor.LzmaCompress(raw_child(), len(raw_child())))
        struct.pack_into("<Q", encoded, 5, 1 << 20)
        self.assertRejected(
            standard(0x02, bytes(encoded)), "truncated-stream")

    def test_corrupt_body_is_not_an_empty_section(self):
        encoded = bytearray(
            efi_compressor.LzmaCompress(raw_child(), len(raw_child())))
        encoded[20] ^= 0xFF
        self.assertRejected(standard(0x02, bytes(encoded)), "truncated-stream")


class BudgetTest(Base, unittest.TestCase):
    '''A stream whose claimed output exceeds the parse budget.'''

    def test_budget_exhaustion_is_named(self):
        from uefi_firmware import utils
        header = struct.pack("<II", 0, 100 * 1000 * 1000)
        section = standard(0x01, header, declared=0)
        with unittest.mock.patch.object(
                utils, "MAX_DECOMPRESSED_BYTES", 1024):
            result = self.parse(section)
        self.assertIsNone(result.data)
        self.assertEqual(result.failure_stage, "budget")


class GuidDefinedTest(Base, unittest.TestCase):
    '''Section type 0x02 bodies, selected by GUID.'''

    def test_lzma_guid(self):
        stream = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        for name in ("LZMA_COMPRESSED", "LZMA_COMPRESSED_HP"):
            with self.subTest(guid=name):
                result = self.assertAccepted(guided(name, stream))
                self.assertEqual(result.decoder, "lzma")

    def test_tiano_guid(self):
        stream = efi_compressor.TianoCompress(raw_child(), len(raw_child()))
        result = self.assertAccepted(guided("TIANO_COMPRESSED", stream))
        self.assertEqual(result.decoder, "tiano")

    def test_wrong_format_for_the_guid(self):
        # Each format is offered to a GUID that names another format. None
        # of these may be decoded as the named format.
        efi = efi_compressor.EfiCompress(raw_child(), len(raw_child()))
        tiano = efi_compressor.TianoCompress(raw_child(), len(raw_child()))
        lzma = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        cases = (
            ("LZMA_COMPRESSED", efi, "decode", "lzma"),
            ("LZMA_COMPRESSED", tiano, "decode", "lzma"),
            ("TIANO_COMPRESSED", efi, "roundtrip", "tiano"),
            ("TIANO_COMPRESSED", lzma, "truncated-stream", "tiano"),
        )
        for name, stream, stage, decoder in cases:
            with self.subTest(guid=name, stage=stage):
                result = self.parse(guided(name, stream))
                self.assertNotEqual(result.decoder, decoder)
                self.assertEqual(result.failure_stage, stage)
                self.assertNotEqual(result.data, raw_child())

    def test_zero_prefixed_tiano_guid_section(self):
        # With a 4-byte preamble the stream no longer starts at offset 20.
        # The decoder must use the offset, not the first bytes.
        stream = efi_compressor.TianoCompress(raw_child(), len(raw_child()))
        result = self.assertAccepted(
            guided("TIANO_COMPRESSED", b"\x00" * 4 + stream, offset=28))
        self.assertEqual(result.decoder, "tiano")

    def test_trailing_bytes_after_a_guid_stream(self):
        stream = efi_compressor.LzmaCompress(raw_child(), len(raw_child()))
        self.assertRejected(
            guided("LZMA_COMPRESSED", stream + b"JUNK"), "trailing-bytes")

    def test_corrupt_guid_stream(self):
        stream = bytearray(
            efi_compressor.LzmaCompress(raw_child(), len(raw_child())))
        stream[20] ^= 0xFF
        self.assertRejected(guided("LZMA_COMPRESSED", bytes(stream)), "decode")

    def test_zlib_and_gzip_guids(self):
        payload = raw_child()
        amd_header = bytearray(0x100)
        compressed = zlib.compress(payload)
        struct.pack_into("<I", amd_header, 0x14, len(compressed))
        for name, body, decoder in (
                ("ZLIB_COMPRESSED_AMD", bytes(amd_header) + compressed,
                 "zlib"),
                ("GZIP_COMPRESSED_QC", gzip.compress(payload, mtime=0),
                 "gzip")):
            with self.subTest(guid=name):
                result = self.parse(guided(name, body))
                self.assertEqual(result.decoder, decoder)
                self.assertIsNone(result.failure_stage)
                self.assertEqual(result.data, payload)
                # These formats do not declare the uncompressed size.
                self.assertIsNone(result.declared_size)

    def test_amd_header_with_the_wrong_compressed_size(self):
        payload = raw_child()
        compressed = zlib.compress(payload)
        amd_header = bytearray(0x100)
        struct.pack_into("<I", amd_header, 0x14, len(compressed) + 1)
        self.assertRejected(
            guided("ZLIB_COMPRESSED_AMD", bytes(amd_header) + compressed),
            "trailing-bytes")

    def test_uncompressed_guids_have_no_decoder(self):
        for name in ("STATIC_GUID", "FIRMWARE_VOLUME"):
            with self.subTest(guid=name):
                result = self.parse(guided(name, raw_child()))
                self.assertEqual(result.decoder, "none")
                self.assertNotIn(result.decoder, ("efi", "tiano", "lzma"))


class SectionContentTest(Base, unittest.TestCase):
    '''The chosen decoder must reproduce the payload, not just bytes.'''

    def test_payload_equal_to_a_header_is_not_taken_as_one(self):
        # The payload starts with bytes that look like a Tiano header. The
        # wrong decoder still returns an equally sized result.
        payload = struct.pack("<II", 16, 12) + b"srcd-ata-bytes"
        child = raw_child(payload)
        stream = efi_compressor.TianoCompress(child, len(child))
        result = self.assertAccepted(
            standard(0x01, stream, payload=payload), payload=payload)
        self.assertEqual(result.decoder, "tiano")
        self.assertEqual(result.data, child)

    def test_subsection_failure_names_the_stage(self):
        # The stream decodes, but its result is not a section header.
        blob = b"\xff\xff\xff\x10"
        stream = efi_compressor.EfiCompress(blob, len(blob))
        result = self.parse(standard(0x01, stream, declared=len(blob)))
        self.assertEqual(result.data, blob)
        self.assertEqual(result.failure_stage, "subsections")


class RoundTripTest(unittest.TestCase):
    '''A decoded section rebuilds to the bytes it was parsed from.'''

    def test_build_keeps_the_original_stream(self):
        child = raw_child()
        stream = efi_compressor.TianoCompress(child, len(child))
        section = standard(0x01, stream)
        quietly(section.process)
        self.assertEqual(section.decoder, "tiano")
        self.assertEqual(section.build(), section._body)


if __name__ == "__main__":
    unittest.main()
