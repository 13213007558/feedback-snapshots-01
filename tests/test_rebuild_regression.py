'''Rebuild regressions: parsing and rebuilding must not rewrite the image.

The review tool is build(): without generate_checksum it must give back the
parsed bytes, padding, unknown sections, blobs, headers and even stale
checksum bytes included. Only generate_checksum=True may recompute sizes,
checksums and the block map, and neither mode may mark a signed section as
trusted.
'''

import contextlib
import io
import struct
import unittest
import uuid

from uefi_firmware.audit import CHECKSUM_KINDS, audit_rebuild
from uefi_firmware.structs.uefi_structs import (
    FIRMWARE_GUIDED_GUIDS, FIRMWARE_VOLUME_GUIDS)
from uefi_firmware.uefi import (
    FirmwareFileSystem, FirmwareFileSystemSection, FirmwareVolume,
    calculate_checksum16)

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
OTHER_GUID = uuid.UUID("01234567-89ab-4def-8123-456789abcdef").bytes_le
STATIC_GUID = uuid.UUID(FIRMWARE_GUIDED_GUIDS["STATIC_GUID"]).bytes_le
FIRMWARE_VOLUME_GUID = uuid.UUID(
    FIRMWARE_GUIDED_GUIDS["FIRMWARE_VOLUME"]).bytes_le


def quietly(function, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args, **kwargs)


def rebuild(firmware_object, generate_checksum=False):
    built = quietly(firmware_object.build, generate_checksum)
    if isinstance(built, tuple):
        built = built[1]
    return built


def make_section(section_type, body, large=False):
    if large:
        return b"\xff\xff\xff" + bytes([section_type]) + \
            struct.pack("<I", 8 + len(body)) + body
    return struct.pack("<I", 4 + len(body))[:3] + \
        bytes([section_type]) + body


def make_guided_section(guid, body, preamble=b"", attrs=0):
    offset = 4 + 20 + len(preamble)
    return make_section(
        0x02, guid + struct.pack("<HH", offset, attrs) + preamble + body)


def make_file(body, guid=FILE_GUID, file_type=0x07, attributes=0x00,
              checksum=0xAA, state=0xF8, size=None):
    if size is None:
        size = 24 + len(body)
    header = guid + struct.pack(
        "<BBBB3sB", 0, 0xAA, file_type, attributes,
        struct.pack("<I", size)[:3], state)
    # Keep a caller-supplied checksum byte in the second checksum byte.
    header = header[:17] + bytes([checksum]) + header[18:]
    return header + body


def make_large_file(body, extended_size=None, attributes=0x01):
    if extended_size is None:
        extended_size = 0x20 + len(body)
    return FILE_GUID + struct.pack(
        "<BBBB3sB", 0, 0xAA, 0x07, attributes, b"\x00" * 3, 0xF8) + \
        struct.pack("<Q", extended_size) + body


def make_volume(body=b"", size=0x1000, guid="FFS2", attributes=0x800,
                header_length=None, extended_header=None,
                extended_offset=None, blocks=None):
    block_map = b"".join(
        struct.pack("<II", *block) for block in (blocks or [(1, size)]))
    block_map += b"\x00" * 8
    header_length = header_length if header_length is not None \
        else FirmwareVolume._HEADER_SIZE + len(block_map)
    extended_offset = extended_offset or 0
    prefix = b""
    if extended_header is not None:
        # EDK2 stores the extended header in a leading pad file.
        prefix = make_file(extended_header, guid=b"\xff" * 16, file_type=0xF0)
        prefix += b"\xff" * (-len(prefix) % 8)
        extended_offset = header_length + 24
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS[guid]).bytes_le,
        size, b"_FVH", attributes, header_length, 0, extended_offset,
        b"\x00", 2)
    body = prefix + body
    return header + block_map + body.ljust(size - header_length, b"\xff")


def parse_volume(data):
    volume = FirmwareVolume(data)
    assert quietly(volume.process), 'fixture did not parse'
    return volume


def first_section(volume, index=0):
    return volume.firmware_filesystems[0].files[0].sections[index]


class PreserveModeTest(unittest.TestCase):
    '''build() without a request to recompute must reproduce the image.'''

    def assert_preserved(self, data, firmware_object=None):
        firmware_object = firmware_object or parse_volume(data)
        self.assertEqual(rebuild(firmware_object), data)

    def test_section_padding_and_unknown_blob(self):
        # 0x00 alignment between sections, and an unknown section type.
        body = make_section(0x19, b"first") + b"\x00\x00" + \
            make_section(0x99, b"vendor data")
        self.assert_preserved(make_volume(make_file(body)))

    def test_file_alignment_between_files(self):
        first = make_file(make_section(0x19, b"a"))
        first += b"\x00" * (-len(first) % 8)
        second = make_file(make_section(0x19, b"b"))
        self.assert_preserved(make_volume(first + second))

    def test_large_file_header_and_extended_size(self):
        body = make_section(0x19, b"large body")
        self.assert_preserved(make_volume(make_large_file(body)))

    def test_large_section_header(self):
        body = make_section(0x19, b"large section", large=True)
        self.assert_preserved(make_volume(make_file(body)))

    def test_unknown_section_inside_a_large_section_header(self):
        body = make_section(0x99, b"vendor", large=True)
        self.assert_preserved(make_volume(make_file(body)))

    def test_volume_extended_header(self):
        extended = uuid.UUID(
            "8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le + \
            struct.pack("<I", 0x14)
        data = make_volume(make_file(make_section(0x19, b"x")),
                           size=0x400, extended_header=extended)
        volume = parse_volume(data)
        self.assertEqual(volume.fvname, extended[:16])
        self.assert_preserved(data, volume)

    def test_unknown_volume_body_is_kept(self):
        data = make_volume(b"$VSS" + b"\x5a" * 0x40, size=0x200,
                           guid="NVRAM_EVSA")
        self.assert_preserved(data)

    def test_stale_checksums_are_kept(self):
        # The volume and file checksum bytes are not valid, and are not
        # recomputed unless asked.
        data = bytearray(make_volume(make_file(make_section(0x19, b"x"))))
        struct.pack_into("<H", data, 0x32, 0xBEEF)
        data = bytes(data)
        volume = parse_volume(data)
        self.assertEqual(volume.checksum, 0xBEEF)
        self.assert_preserved(data, volume)

    def test_bytes_after_a_nested_volume_are_kept(self):
        # A raw section whose nested volume is followed by vendor bytes.
        inner = make_volume(size=0x100)
        self.assert_preserved(
            make_volume(make_file(make_section(0x19, inner + b"TRAILER"))))

    def test_volume_section_with_skipped_header_is_kept(self):
        # A FFSv3 volume section stores 4 bytes before the volume header.
        inner = make_volume(size=0x100)
        self.assert_preserved(
            make_volume(make_file(make_section(0x17, b"\xde\xad\xbe\xef" +
                                               inner))))

    def test_hp_prefixed_volume_is_kept(self):
        inner = make_volume(size=0x100)
        self.assert_preserved(make_volume(make_file(make_section(
            0x19, b"123456789A" + b"\x00\x00" + inner))))

    def test_raw_file_with_several_volumes_and_trailing_data(self):
        inner = make_volume(size=0x100)
        second = make_volume(size=0x100)
        self.assert_preserved(make_volume(make_file(
            inner + second + b"END", file_type=0x01)))

    def test_file_system_rebuild_keeps_free_space(self):
        data = make_file(make_section(0x19, b"a")) + b"\x00" * 16
        filesystem = FirmwareFileSystem(data)
        self.assertTrue(quietly(filesystem.process))
        self.assertEqual(quietly(filesystem.build), data)


class RecomputeModeTest(unittest.TestCase):
    '''generate_checksum=True may only touch sizes and checksums.'''

    def make_volume(self):
        # One byte aligns the second section, so only checksum bytes move.
        body = make_section(0x19, b"payload") + b"\x00" + \
            make_section(0x99, b"vendor")
        return make_volume(make_file(body), size=0x400)

    def test_preserve_and_recompute_are_separate_modes(self):
        data = self.make_volume()
        volume = parse_volume(data)
        preserved = rebuild(volume, False)
        recomputed = rebuild(volume, True)
        self.assertEqual(preserved, data)
        self.assertNotEqual(recomputed, data)

    def test_recomputed_volume_checksum_is_valid(self):
        volume = parse_volume(self.make_volume())
        recomputed = rebuild(volume, True)
        header_length = struct.unpack_from("<H", recomputed, 0x30)[0]
        self.assertEqual(calculate_checksum16(
            recomputed[:header_length] +
            b"\x00" * (header_length % 2)), 0)

    def test_audit_names_each_allowed_change(self):
        volume = parse_volume(self.make_volume())
        report = audit_rebuild(volume, recompute_checksums=True)
        self.assertTrue(report.changes)
        # Sizes are untouched here; only the checksum bytes may move.
        kinds = [kind for change in report.changes for kind in change.kinds]
        self.assertIn('volume-checksum', kinds)
        self.assertIn('file-header-checksum', kinds)
        self.assertTrue(all(change.kinds for change in report.changes))
        for change in report.changes:
            self.assertTrue(set(change.kinds) <= CHECKSUM_KINDS)
        self.assertFalse(report.unexpected)

    def test_audit_quiets_build_warnings(self):
        # A section that outgrows its volume prints size warnings while
        # building. The report captures them instead of mixing them into
        # whatever the caller prints.
        data = make_volume(make_file(make_section(0x19, b"a" * 4)), size=0x80)
        volume = parse_volume(data)
        section = volume.firmware_filesystems[0].files[0].sections[0]
        section.regen(make_section(0x19, b"b" * 200))
        quietly(section.process)

        report = audit_rebuild(volume)
        self.assertIn('truncating', report.output)
        self.assertFalse(report.identical)

    def test_audit_restores_the_object(self):
        volume = parse_volume(self.make_volume())
        original = (volume.size, volume.checksum)
        audit_rebuild(volume, recompute_checksums=True)
        self.assertEqual((volume.size, volume.checksum), original)


class AuditPreserveTest(unittest.TestCase):
    '''An unchanged image audits clean; a changed one names the range.'''

    def make_signed_volume(self, payload=b"original"):
        signature = b"\x30\x82" + b"S" * 0x40
        inner = make_section(0x19, payload)
        signed = make_guided_section(STATIC_GUID, inner, signature, attrs=0x02)
        return make_volume(make_file(signed), size=0x400)

    def test_unchanged_image_has_no_changes(self):
        report = audit_rebuild(parse_volume(
            make_volume(make_file(make_section(0x19, b"x")))))
        self.assertTrue(report.identical)
        self.assertEqual(report.unexpected, [])
        self.assertIn('unchanged', report.render())

    def test_same_length_edit_reports_one_range(self):
        # A same-length edit changes only the payload bytes: the size fields
        # that would move for a resize stay as they are.
        volume = parse_volume(self.make_signed_volume())
        subsection = first_section(volume).parsed_object.subsections[0]
        subsection.regen(make_section(0x19, b"attacker"))
        quietly(subsection.process)

        report = audit_rebuild(volume)
        self.assertEqual(len(report.changes), 1)
        change = report.changes[0]
        self.assertEqual(change.status, 'content')
        self.assertEqual(len(change.original), len(b"attacker"))
        self.assertEqual(change.original, b"original")

    def test_resize_reports_sizes_and_the_payload(self):
        data = self.make_signed_volume()
        volume = parse_volume(data)
        report = audit_rebuild(volume)
        self.assertTrue(report.identical)

        subsection = first_section(volume).parsed_object.subsections[0]
        subsection.regen(make_section(0x19, b"changed payload"))
        quietly(subsection.process)

        report = audit_rebuild(volume)
        self.assertFalse(report.identical)
        # Sizes follow the new payload, and that is all: the volume header
        # and the signature preamble stay where they were.
        kinds = {kind for change in report.changes for kind in change.kinds}
        self.assertIn('derived', {change.status for change in report.changes})
        self.assertNotIn('unexpected',
                         {change.status for change in report.changes})
        self.assertTrue(kinds & {'section-size', 'file-size'})
        for change in report.changes:
            self.assertGreater(change.start, 0x38)

    def test_changed_signature_is_invalidated_not_trusted(self):
        volume = parse_volume(self.make_signed_volume())
        signed_section = first_section(volume)
        self.assertEqual(signed_section.parsed_object.attrs['attrs'], 0x02)

        inner = signed_section.parsed_object.subsections[0]
        inner.regen(make_section(0x19, b"attacker payload"))
        quietly(inner.process)

        report = audit_rebuild(volume)
        self.assertEqual(len(report.signatures), 1)
        signature = report.signatures[0]
        self.assertTrue(signature['invalidated'])
        self.assertEqual(signature['attributes'], 0x02)
        rendered = report.render()
        self.assertIn('INVALIDATED', rendered)
        self.assertIn('re-sign and re-verify', rendered)

    def test_reparse_alone_would_not_catch_a_rewrite(self):
        # A rebuilt image that changed a padding byte still parses, so the
        # regression compares bytes instead.
        data = make_volume(make_file(make_section(0x19, b"a")))
        rewritten = bytearray(data)
        rewritten[-1] = 0x00
        rewritten = bytes(rewritten)
        parse_volume(rewritten)
        report = audit_rebuild(parse_volume(data))
        self.assertTrue(report.identical)
        self.assertNotEqual(rewritten, data)


if __name__ == '__main__':
    unittest.main()


class NestedAuditTest(unittest.TestCase):

    def make_pfs(self):
        from uefi_firmware.pfs import PFSFile
        def pfs_section(section_data):
            header = bytearray(0x48)
            header[0:16] = uuid.UUID(
                "7ec6c2b0-3fe3-42a0-a316-22dd0517c1e8").bytes_le
            struct.pack_into("<II", header, 0x10, 1, 0)
            struct.pack_into("<8sIIII", header, 0x20, b"\x00" * 8,
                             len(section_data), 4, 0, 4)
            body = bytes(header) + section_data + b"SIG1" + b"SIG2"
            return b"PFS.HDR." + struct.pack("<II", 1, len(body)) + body + \
                struct.pack("<II", len(body), 0) + b"PFS.FTR."
        data = pfs_section(make_volume(
            make_file(make_section(0x19, b"x")), size=0x100))
        pfs_file = PFSFile(data)
        self.assertTrue(quietly(pfs_file.process))
        return data, pfs_file

    def test_pfs_preserves_its_signature_chunks(self):
        data, pfs_file = self.make_pfs()
        self.assertEqual(rebuild(pfs_file), data)
        report = audit_rebuild(pfs_file)
        self.assertTrue(report.identical)

    def test_pfs_change_reports_size_and_checksum_fields(self):
        data, pfs_file = self.make_pfs()
        firmware_file = pfs_file.sections[0].section_objects[0] \
            .firmware_filesystems[0].files[0]
        firmware_file.sections[0].regen(
            make_section(0x19, b"changed payload"))
        quietly(firmware_file.sections[0].process)

        report = audit_rebuild(pfs_file)
        self.assertFalse(report.identical)
        kinds = {kind for change in report.changes for kind in change.kinds}
        self.assertIn('pfs-checksum', kinds)
        self.assertIn('section-size', kinds)
        # The signature chunks are never rewritten.
        for change in report.changes:
            spans = [region for region in change.labels
                     if 'rsa' in region or 'pmim' in region]
            self.assertEqual(spans, [])
        self.assertNotIn('unexpected',
                         {change.status for change in report.changes})


class CapsuleAuditTest(unittest.TestCase):

    def make_capsule(self, body, signature=b""):
        from uefi_firmware.structs.uefi_structs import (
            APTIO_SIGNED_CAPSULE_GUID)
        rom_offset = 0x30
        header = uuid.UUID(APTIO_SIGNED_CAPSULE_GUID).bytes_le + struct.pack(
            "<IIIHH", 0x20, 0, rom_offset + len(body) + len(signature),
            rom_offset, 0)
        return header + body + signature

    def test_aptio_capsule_with_unparsed_body_is_kept_whole(self):
        from uefi_firmware.uefi import FirmwareCapsule
        # A ROM image that is not a volume still has to come back unchanged.
        data = self.make_capsule(b"JUNK" * 16)
        capsule = FirmwareCapsule(data)
        quietly(capsule.process)
        self.assertEqual(rebuild(capsule), data)
        report = audit_rebuild(capsule)
        self.assertTrue(report.identical)

    def test_trailing_bytes_after_the_rom_image_are_kept(self):
        from uefi_firmware.uefi import FirmwareCapsule
        data = self.make_capsule(b"JUNK" * 16) + b"TRAILING"
        capsule = FirmwareCapsule(data)
        quietly(capsule.process)
        self.assertEqual(rebuild(capsule), data)


class MultiObjectAuditTest(unittest.TestCase):

    def test_audit_refuses_an_object_that_cannot_rebuild(self):
        from uefi_firmware import AutoParser
        data = (make_volume(make_file(make_section(0x19, b"x"))) +
                b"GAP" * 8 + make_volume(size=0x200))
        firmware = AutoParser(data).parse()
        with self.assertRaises(ValueError):
            audit_rebuild(firmware)

    def test_the_same_image_audits_through_each_volume(self):
        from uefi_firmware import AutoParser
        data = (make_volume(make_file(make_section(0x19, b"x"))) +
                b"GAP" * 8 + make_volume(size=0x200))
        firmware = AutoParser(data).parse()
        for volume in firmware.objects:
            if isinstance(volume, FirmwareVolume):
                self.assertTrue(audit_rebuild(volume).identical)


class SignedCompressedAuditTest(unittest.TestCase):

    def make_volume(self):
        # A signed GUID-defined section whose body is a compression section
        # that stores its payload uncompressed.
        signature = b"\x30\x82" + b"S" * 0x20
        inner = make_section(0x19, b"payload")
        stream = struct.pack("<IB", len(inner), 0x00) + inner
        signed = make_guided_section(STATIC_GUID, stream, signature, attrs=0x02)
        return make_volume(make_file(signed), size=0x300)

    def test_signed_compressed_body_is_reported_when_it_changes(self):
        volume = parse_volume(self.make_volume())
        self.assertTrue(audit_rebuild(volume).identical)

        guided = first_section(volume).parsed_object
        guided.subsections[0].regen(make_section(0x19, b"attacker"))
        quietly(guided.subsections[0].process)

        report = audit_rebuild(volume)
        self.assertEqual(len(report.signatures), 1)
        self.assertTrue(report.signatures[0]['invalidated'])
        self.assertNotIn('unexpected',
                         {change.status for change in report.changes})
