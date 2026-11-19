'''Regression: volume, FFS header and file data checksums are separate layers.

Every fixture builds its checksums with the arithmetic below, from raw
offsets, rather than by calling build(generate_checksum=True). The expected
coverage of each sample is therefore independent of the code under test:
a rebuild result is never used to explain why the original bytes pass.

The parser's rules, which these expectations follow, are:

* volume header: 16-bit sum over [0, hdrlen), stored at 0x32;
* FFS header: 8-bit sum over the 24-byte header (32 for a large file), with
  bytes 0x10, 0x11 and 0x17 treated as zero, stored at 0x10;
* file data: 8-bit sum over [header_size, size), stored at 0x11, present
  only when attribute 0x40 is set. Without it 0x11 is a fixed filler.

Checksums are not signatures. They use no key, name no publisher, and can
be recomputed after any edit; the counterexample tests keep that property
in the suite.
'''

import struct
import unittest
import uuid

from uefi_firmware import AutoParser
from uefi_firmware.checksum import (
    EXTENDED_HEADER, FILE_DATA, FFS_HEADER, INVALID, NOT_COVERED,
    NOT_PRESENT, VALID, VOLUME_HEADER, first_invalid,
    format_report, invalid_layers, protected_ranges, verify_ffs_header,
    verify_file_data, verify_volume, verify_volume_header)
from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS


def checksum8(data):
    return -sum(data) & 0xFF


def checksum16(data):
    if len(data) % 2:
        data += b'\x00'
    return -sum(word for word, in struct.iter_unpack('<H', data)) & 0xFFFF


def little(value, length):
    return value.to_bytes(length, 'little')


def header_checksum(header):
    '''8-bit FFS header sum with 0x10, 0x11 and 0x17 treated as zero.'''
    raw = bytearray(header)
    raw[0x10] = 0
    raw[0x11] = 0
    raw[0x17] = 0
    return checksum8(bytes(raw))


def make_file(body, guid, file_type=0x07, attributes=0x40, large=False,
              filler=0xAA):
    '''An FFS file with locally calculated header and data checksums.'''
    header_size = 32 if large else 24
    size = header_size + len(body)
    header = bytearray(header_size)
    header[0x00:0x10] = guid
    header[0x12] = file_type
    header[0x13] = attributes
    if large:
        struct.pack_into('<Q', header, 0x18, size)
    else:
        header[0x14:0x17] = little(size, 3)
    header[0x17] = 0xF8
    header[0x11] = checksum8(body) if attributes & 0x40 else filler
    header[0x10] = header_checksum(header)
    data = bytes(header) + body
    return data + b'\xff' * (-len(data) % 8)


def make_volume(body, size=0x800, fvname=None, revision=2):
    '''An FFS2 volume with a locally calculated 16-bit header checksum.'''
    block_map = struct.pack('<II', 1, size) + b'\x00' * 8
    hdrlen = 56 + len(block_map)
    exthdroff = 0
    if fvname is not None:
        extended_header_pad = make_file(
            struct.pack('<16sI', fvname, 0x14), b'\xff' * 16,
            file_type=0xF0, attributes=0x00)
        exthdroff = hdrlen + 24
        body = extended_header_pad + body
    header = bytearray(56)
    header[0x10:0x20] = uuid.UUID(FIRMWARE_VOLUME_GUIDS['FFS2']).bytes_le
    struct.pack_into('<Q', header, 0x20, size)
    header[0x28:0x2C] = b'_FVH'
    struct.pack_into('<I', header, 0x2C, 0x800)
    struct.pack_into('<H', header, 0x30, hdrlen)
    struct.pack_into('<H', header, 0x34, exthdroff)
    header[0x37] = revision
    struct.pack_into('<H', header, 0x32, checksum16(bytes(header) + block_map))
    data = bytes(header) + block_map + body
    return data + b'\xff' * (size - len(data))


LARGE_GUID = uuid.UUID('11111111-2222-4333-8444-555555555555').bytes_le
FIXED_GUID = uuid.UUID('66666666-7777-4888-9999-aaaaaaaaaaaa').bytes_le
CHECKED_GUID = uuid.UUID('bbbbbbbb-cccc-4ddd-8eee-ffffffffffff').bytes_le
FVNAME = uuid.UUID('01234567-89ab-4cde-8f01-23456789abcd').bytes_le

# A raw section, 4-byte aligned padding, then a second raw section. The
# padding is inside the file body and so inside the data checksum.
SECTION_ALPHA = struct.pack('<I', 9)[:3] + b'\x19' + b'alpha'
SECTION_BETA = struct.pack('<I', 8)[:3] + b'\x19' + b'beta'
CHECKED_BODY = SECTION_ALPHA + b'\x00' * 3 + SECTION_BETA
INTERNAL_PADDING = 9  # body offset of the first alignment byte

LARGE_BODY = b'L' * 24
FIXED_BODY = SECTION_ALPHA + b'\x00' * 3 + \
    struct.pack('<I', 8)[:3] + b'\x19' + b'zeta'


def build_sample():
    '''A volume with an extended header, a large file, and two normal files.'''
    large_file = make_file(
        LARGE_BODY, LARGE_GUID, file_type=0x01, attributes=0x41, large=True)
    fixed_file = make_file(
        FIXED_BODY, FIXED_GUID, attributes=0x00)
    checked_file = make_file(CHECKED_BODY, CHECKED_GUID, attributes=0x40)
    data = make_volume(
        large_file + fixed_file + checked_file, size=0x800, fvname=FVNAME)

    hdrlen = 56 + 16
    # make_volume prepends a 0xf0 pad file holding the extended header.
    ext_pad_length = 48
    files = []
    offset = hdrlen + ext_pad_length
    for enc in (large_file, fixed_file, checked_file):
        size, header_size = _layout_at(data, offset)
        files.append({
            'start': offset,
            'size': size,
            'header_size': header_size,
            'encoding': enc,
        })
        offset += (size + 7) & ~7
    return {
        'data': data,
        'hdrlen': hdrlen,
        'size': 0x800,
        'starts': [file_record['start'] for file_record in files],
        'files': files,
        'ext_offset': hdrlen + 24,
        'ext_pad_length': ext_pad_length,
        'free_space_offset': offset,
    }


def _layout_at(data, offset):
    if data[offset + 0x13] & 0x01 and data[offset + 0x14:offset + 0x17] == \
            b'\x00\x00\x00':
        return struct.unpack_from('<Q', data, offset + 0x18)[0], 32
    size = int.from_bytes(data[offset + 0x14:offset + 0x17], 'little')
    return size, 24


def flip(data, offset, value=None):
    result = bytearray(data)
    if value is None:
        result[offset] ^= 0xFF
    else:
        result[offset] = value
    return bytes(result)


class CoverageTest(unittest.TestCase):

    def setUp(self):
        self.sample = build_sample()
        self.data = self.sample['data']

    def test_volume_header_covers_header_and_block_map(self):
        result = verify_volume_header(self.data)
        self.assertEqual(result.status, VALID)
        self.assertEqual(result.checksum_offset, 0x32)
        self.assertEqual(result.checksum_size, 2)
        self.assertEqual(
            (result.covered_start, result.covered_end),
            (0, self.sample['hdrlen']))
        covered = bytearray(self.data[:self.sample['hdrlen']])
        stored = struct.unpack_from('<H', covered, 0x32)[0]
        covered[0x32:0x34] = b'\x00\x00'
        self.assertEqual(checksum16(bytes(covered)), stored)

    def test_large_file_header_is_32_bytes(self):
        large = self.sample['files'][0]
        self.assertEqual(large['header_size'], 32)
        result = verify_ffs_header(self.data, large['start'])
        self.assertEqual(result.status, VALID)
        self.assertEqual(
            (result.covered_start, result.covered_end),
            (large['start'], large['start'] + 32))

    def test_normal_file_header_is_24_bytes(self):
        for file_record in self.sample['files'][1:]:
            result = verify_ffs_header(self.data, file_record['start'])
            self.assertEqual(result.status, VALID)
            self.assertEqual(
                (result.covered_start, result.covered_end),
                (file_record['start'], file_record['start'] + 24))

    def test_data_checksum_covers_only_the_file_body(self):
        checked = self.sample['files'][2]
        result = verify_file_data(self.data, checked['start'])
        self.assertEqual(result.status, VALID)
        self.assertEqual(result.checksum_offset, checked['start'] + 0x11)
        self.assertEqual(
            (result.covered_start, result.covered_end),
            (checked['start'] + 24, checked['start'] + checked['size']))

    def test_file_without_attribute_0x40_has_no_data_checksum(self):
        fixed = self.sample['files'][1]
        result = verify_file_data(self.data, fixed['start'])
        self.assertEqual(result.status, NOT_COVERED)
        self.assertFalse(result.protects_bytes)
        self.assertEqual(self.data[fixed['start'] + 0x11], 0xAA)
        self.assertEqual(self.data[fixed['start'] + 0x13], 0x00)

    def test_extended_header_is_outside_every_checksum(self):
        results = verify_volume(self.data)
        extended = [r for r in results if r.layer == EXTENDED_HEADER]
        self.assertEqual(len(extended), 1)
        self.assertEqual(extended[0].status, NOT_COVERED)
        self.assertEqual(extended[0].covered_start, self.sample['ext_offset'])
        self.assertEqual(
            extended[0].covered_end, self.sample['ext_offset'] + 0x14)

    def test_layers_are_listed_in_raw_order(self):
        results = verify_volume(self.data)

        self.assertEqual(
            [r.layer for r in results],
            [VOLUME_HEADER, EXTENDED_HEADER] +
            [layer for _ in self.sample['files']
             for layer in (FFS_HEADER, FILE_DATA)])
        self.assertEqual(invalid_layers(results), [])
        expected = [(0, self.sample['hdrlen'])]
        for file_record in self.sample['files']:
            start = file_record['start']
            expected.append((start, start + file_record['header_size']))
            if self.data[start + 0x13] & 0x40:
                expected.append((start + file_record['header_size'],
                                 start + file_record['size']))
        self.assertEqual(
            [(start, end) for start, end, _ in protected_ranges(results)],
            expected)


class ParserAgreementTest(unittest.TestCase):
    '''The regression fixtures are the bytes the parser itself accepts.'''

    def test_sample_parses_and_stored_checksums_match(self):
        sample = build_sample()
        firmware = AutoParser(sample['data']).parse()
        self.assertIsNotNone(firmware)
        files = firmware.firmware_filesystems[0].files
        # The extended-header pad file is first in the volume.
        self.assertEqual(len(files), 4)
        self.assertEqual(files[0].type, 0xF0)
        for parsed, file_record in zip(files[1:], sample['files']):
            self.assertEqual(parsed.size, file_record['size'])
            start = file_record['start']
            expected_header = header_checksum(sample['data'][
                start:start + file_record['header_size']])
            self.assertEqual(parsed.checksum & 0xFF, expected_header)
            if sample['data'][file_record['start'] + 0x13] & 0x40:
                self.assertEqual(
                    parsed.checksum >> 8,
                    checksum8(sample['data'][
                        file_record['start'] + file_record['header_size']:
                        file_record['start'] + file_record['size']]))
        self.assertEqual(
            firmware.checksum, struct.unpack_from(
                '<H', sample['data'], 0x32)[0])
        self.assertEqual(
            verify_volume_header(sample['data']).status, VALID)

    def test_large_file_header_size_from_parser(self):
        sample = build_sample()
        firmware = AutoParser(sample['data']).parse()
        large = firmware.firmware_filesystems[0].files[1]
        self.assertTrue(large.large_file)
        self.assertEqual(large.header_size, 32)


class SingleChangeTest(unittest.TestCase):
    '''Change one protected byte at a time and check which layer notices.'''

    def setUp(self):
        self.sample = build_sample()
        self.data = self.sample['data']
        self.large, self.fixed, self.checked = self.sample['files']

    def assert_only_layer(self, results, layer, offset):
        failing = [result for result in results if result.failed]
        self.assertEqual([result.layer for result in failing], [layer])
        self.assertEqual(failing[0].checksum_offset, offset)

    def test_volume_header_field_fails_only_the_volume_header(self):
        # Header length is inside [0, hdrlen), but it also decides where
        # the file scan starts, so it is covered separately below.
        for offset in (0x00, 0x20, 0x2C, 0x34, 0x37):
            data = flip(self.data, offset)
            results = verify_volume(data)
            self.assert_only_layer(results, VOLUME_HEADER, 0x32)
            self.assertEqual(first_invalid(results).layer, VOLUME_HEADER)

    def test_block_map_entry_fails_only_the_volume_header(self):
        data = flip(self.data, 0x38)
        self.assert_only_layer(verify_volume(data), VOLUME_HEADER, 0x32)

    def test_large_file_header_field_fails_only_that_header(self):
        start = self.large['start']
        # GUID and type are in the 32-byte large header and nowhere else.
        for offset in (start + 0x03, start + 0x12):
            data = flip(self.data, offset)
            results = verify_volume(data)
            self.assert_only_layer(results, FFS_HEADER, start + 0x10)

        # ExtendedSize is covered by the header checksum, but it is also
        # where the data layer ends, so the data layer legitimately moves.
        data = flip(self.data, start + 0x18)
        results = verify_volume(data)
        self.assertEqual(
            [result.layer for result in results if result.failed],
            [FFS_HEADER, FILE_DATA])

    def test_large_attribute_bit_is_part_of_the_header(self):
        start = self.large['start']
        # Clear an unrelated attribute bit, keeping the large-file bit.
        data = bytearray(self.data)
        data[start + 0x13] ^= 0x80
        result = verify_ffs_header(bytes(data), start)
        self.assertEqual(result.status, INVALID)

    def test_state_byte_is_excluded_from_the_header_checksum(self):
        # FFS State (0x17) is not part of IntegrityCheck.Checksum.Header.
        start = self.checked['start']
        data = flip(self.data, start + 0x17)
        self.assertEqual(verify_ffs_header(data, start).status, VALID)
        self.assertEqual(invalid_layers(verify_volume(data)), [])

    def test_header_length_change_is_structural(self):
        # Moving hdrlen changes where files begin, so it is not a
        # single-field checksum test. The volume header still fails.
        data = flip(self.data, 0x30)
        results = verify_volume(data)
        self.assertEqual(
            first_invalid(results).layer, VOLUME_HEADER)
        self.assertEqual(results[0].checksum_offset, 0x32)

    def test_extended_size_byte_is_inside_the_large_header(self):
        start = self.large['start']
        result = verify_ffs_header(flip(self.data, start + 0x18), start)
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.checksum_offset, start + 0x10)

    def test_normal_file_body_fails_only_the_data_checksum(self):
        start = self.checked['start'] + self.checked['header_size']
        data = flip(self.data, start + 4)
        self.assert_only_layer(verify_volume(data), FILE_DATA,
                               self.checked['start'] + 0x11)

    def test_section_alignment_padding_is_inside_the_data_checksum(self):
        # Padding between two sections belongs to the file body.
        offset = self.checked['start'] + self.checked['header_size'] + \
            INTERNAL_PADDING
        self.assertEqual(self.data[offset], 0x00)
        data = flip(self.data, offset)
        self.assert_only_layer(verify_volume(data), FILE_DATA,
                               self.checked['start'] + 0x11)

    def test_normal_file_header_field_fails_only_that_header(self):
        start = self.checked['start']
        data = flip(self.data, start + 0x12)
        self.assert_only_layer(verify_volume(data), FFS_HEADER, start + 0x10)

    def test_fixed_checksum_byte_is_not_a_file_data_checksum(self):
        # The fixed-filler file has every body byte unchecked. Byte 0x11 is
        # a filler, not a checksum, so changing the body fails nothing.
        start = self.fixed['start']
        body_offset = start + self.fixed['header_size'] + 4
        data = flip(self.data, body_offset)
        results = verify_volume(data)
        self.assertEqual(invalid_layers(results), [])
        # Rewriting the filler itself is outside every checksum too.
        data = flip(self.data, start + 0x11)
        results = verify_volume(data)
        self.assertEqual(invalid_layers(results), [])
        self.assertEqual(
            verify_file_data(data, start).status, NOT_COVERED)

    def test_extended_header_bytes_fail_nothing(self):
        # FvName lives in the extended header, outside the volume header
        # checksum, and the pad file holding it is not a parsed file.
        offset = self.sample['ext_offset']
        data = flip(self.data, offset)
        self.assertEqual(invalid_layers(verify_volume(data)), [])
        data = flip(self.data, offset + 0x10)
        self.assertEqual(invalid_layers(verify_volume(data)), [])

    def test_trailing_free_space_fails_nothing(self):
        # Erased free space after the last file is outside every range.
        offset = self.sample['free_space_offset'] + 0x100
        self.assertEqual(self.data[offset], 0xFF)
        data = flip(self.data, offset, 0x01)
        self.assertEqual(invalid_layers(verify_volume(data)), [])

    def test_file_alignment_padding_fails_nothing(self):
        # The 0xff bytes between the end of a file and the next aligned
        # header are not part of either checksum.
        start = self.checked['start'] + self.checked['size']
        self.assertLess(start, self.sample['free_space_offset'])
        self.assertTrue(all(byte == 0xFF for byte in
                            self.data[start:self.sample['free_space_offset']]))
        data = flip(self.data, start, 0x01)
        self.assertEqual(invalid_layers(verify_volume(data)), [])


class HeaderSweepTest(unittest.TestCase):
    '''Every header byte except the excluded three is covered.'''

    def test_each_header_byte_is_inside_the_header_checksum(self):
        sample = build_sample()
        data = sample['data']
        for file_record in sample['files']:
            start = file_record['start']
            for offset in range(file_record['header_size']):
                if offset in (0x10, 0x11, 0x17):
                    continue
                changed = flip(data, start + offset)
                result = verify_ffs_header(changed, start)
                self.assertNotEqual(
                    result.status, VALID,
                    'header byte 0x%x at 0x%x was not covered' % (
                        offset, start + offset))

    def test_excluded_header_bytes_stay_valid(self):
        # Byte 0x10 is the stored header checksum, so it is not one of the
        # zeroed fields: changing it must fail. Only the data checksum byte
        # (0x11) and State (0x17) are excluded from the header sum.
        sample = build_sample()
        data = sample['data']
        for file_record in sample['files']:
            start = file_record['start']
            for offset in (0x11, 0x17):
                changed = flip(data, start + offset)
                self.assertEqual(
                    verify_ffs_header(changed, start).status, VALID,
                    'header byte 0x%x at 0x%x should be excluded' % (
                        offset, start + offset))
            changed = flip(data, start + 0x10)
            self.assertEqual(
                verify_ffs_header(changed, start).status, INVALID)


class ReportTest(unittest.TestCase):

    def test_report_names_layer_offset_and_range(self):
        sample = build_sample()
        data = flip(sample['data'], sample['files'][2]['start'] + 24 + 4)

        report = format_report(verify_volume(data))
        self.assertIn(
            'file_data: invalid checksum at 0x%x' % (
                sample['files'][2]['start'] + 0x11), report)
        self.assertIn('volume_header: valid checksum at 0x32', report)
        self.assertIn('ffs_header: valid checksum at 0x%x' % (
            sample['files'][2]['start'] + 0x10), report)

    def test_each_layer_keeps_its_own_verdict(self):
        sample = build_sample()
        large = sample['files'][0]
        data = flip(sample['data'], large['start'] + 0x12)
        results = verify_volume(data)

        by_layer = {}
        for result in results:
            by_layer.setdefault(result.layer, []).append(result.status)
        self.assertEqual(by_layer[VOLUME_HEADER], [VALID])
        self.assertEqual(by_layer[FFS_HEADER],
                         [INVALID, VALID, VALID])
        self.assertEqual(by_layer[FILE_DATA],
                         [VALID, NOT_COVERED, VALID])

    def test_missing_volume_header_is_not_a_pass(self):
        result = verify_volume_header(b'\x00' * 0x40)
        self.assertEqual(result.status, NOT_PRESENT)
        self.assertFalse(result.protects_bytes)
        self.assertNotEqual(result.status, VALID)

    def test_truncated_file_body_is_not_reported_valid(self):
        checked = build_sample()['files'][2]
        sample = build_sample()
        data = sample['data'][:checked['start'] + checked['size'] - 1]
        result = verify_file_data(data, checked['start'])
        self.assertEqual(result.status, NOT_PRESENT)
        self.assertFalse(result.protects_bytes)


class RecomputedChecksumTest(unittest.TestCase):
    '''A matching checksum does not identify a publisher.

    Both samples below are edited, then have every layer recomputed with
    the same public arithmetic. All checks pass, which is exactly why a
    green report must not be read as "the vendor signed this image".
    '''

    def test_all_layers_can_be_recomputed_after_an_edit(self):
        sample = build_sample()
        data = bytearray(sample['data'])
        checked = sample['files'][2]
        body_offset = checked['start'] + checked['header_size'] + 2
        data[body_offset] ^= 0xFF

        # Recompute the file data checksum from the edited body.
        body = bytes(data[checked['start'] + 24:
                          checked['start'] + checked['size']])
        data[checked['start'] + 0x11] = checksum8(body)
        # Recompute that file's header checksum.
        data[checked['start'] + 0x10] = header_checksum(
            bytes(data[checked['start']:checked['start'] + 24]))

        results = verify_volume(bytes(data))
        self.assertEqual(invalid_layers(results), [])
        self.assertTrue(all(
            result.status == VALID
            for result in results if result.protects_bytes))
        self.assertEqual(
            bytes(data[checked['start'] + 24:
                      checked['start'] + checked['size']]), body)
        self.assertNotEqual(bytes(data), sample['data'])

    def test_volume_header_can_be_recomputed_after_an_edit(self):
        sample = build_sample()
        data = bytearray(sample['data'])
        # Change the volume revision, then recompute only the header sum.
        data[0x37] = 1
        data[0x32:0x34] = b'\x00\x00'
        struct.pack_into(
            '<H', data, 0x32, checksum16(bytes(data[:sample['hdrlen']])))
        result = verify_volume_header(bytes(data))
        self.assertEqual(result.status, VALID)
        self.assertNotEqual(bytes(data), sample['data'])


if __name__ == '__main__':
    unittest.main()
