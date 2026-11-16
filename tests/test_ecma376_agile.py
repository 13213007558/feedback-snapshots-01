"""Agile encryption with a hash shorter than the AES block-padded values (SHA1)."""

import io
import os
import unittest
from os.path import dirname, join
from tempfile import NamedTemporaryFile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.ooxml import OOXMLFile
from msoffcrypto.method.ecma376_agile import (
    ECMA376Agile,
    ECMA376AgilePackageView,
)

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: agile SHA1/AES-128 and agile SHA512/AES-256
EXAMPLE_FILES = (
    ("ecma376agile_sha1_password.xlsx", "example.xlsx"),
    ("example_password.xlsx", "example.xlsx"),
)


class ECMA376AgileTest(unittest.TestCase):
    """See module doc."""

    def test_verify_password_and_integrity(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD, verify_password=True)
                outfile = io.BytesIO()
                ofile.decrypt(outfile, verify_integrity=True)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())

    def test_wrong_password(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.load_key(password="Password1234", verify_password=True)

    def test_tampered_package(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD)
                with ofile.file.openstream("EncryptedPackage") as stream:
                    package = bytearray(stream.read())

            info = ofile.info
            args = (
                ofile.secret_key,
                info["keyDataSalt"],
                info["keyDataHashAlgorithm"],
                info["keyDataBlockSize"],
                info["encryptedHmacKey"],
                info["encryptedHmacValue"],
            )
            self.assertTrue(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

            package[100] ^= 0x01
            self.assertFalse(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))


class ECMA376AgilePackageViewTest(unittest.TestCase):
    """Random-access reads over the decrypted Agile payload."""

    PATH = join(DATA_DIR, "example_password.docx")
    #: plaintext length and segment layout of the fixture above
    DECLARED_LENGTH = 11995
    SEGMENT_LENGTH = 4096

    def _open_ofile(self):
        handle = open(self.PATH, "rb")
        self.addCleanup(handle.close)
        ofile = OOXMLFile(handle)
        ofile.load_key(password=PASSWORD, verify_password=True)
        return ofile

    def _full_decrypt(self):
        with open(self.PATH, "rb") as f:
            ofile = OfficeFile(f)
            ofile.load_key(password=PASSWORD, verify_password=True)
            out = io.BytesIO()
            ofile.decrypt(out)
        return out.getvalue()

    def _package_bytes(self):
        ofile = self._open_ofile()
        stream = ofile.file.openstream("EncryptedPackage")
        self.addCleanup(stream.close)
        return bytearray(stream.read())

    def test_range_equals_full_decrypt(self):
        expected = self._full_decrypt()
        view = self._open_ofile().open_package_view()

        self.assertEqual(view.declared_size, len(expected))
        self.assertEqual(view.available_size, len(expected))
        self.assertFalse(view.truncated)

        ranges = [
            (0, 4),  # start of the package
            (100, 50),  # inside the first segment
            (4090, 20),  # starts in one segment, ends inside the next
            (4000, 300),  # unaligned cross-segment range
            (self.SEGMENT_LENGTH * 2 - 3, self.SEGMENT_LENGTH + 10),
            (len(expected) - 5, 100),  # end short read
            (len(expected) - 1, 1),
            (len(expected), 10),  # at EOF
            (len(expected) + 100, 10),  # past EOF
            (len(expected) - 10, 0),  # zero length
        ]
        for offset, length in ranges:
            with self.subTest(offset=offset, length=length):
                self.assertEqual(
                    view.read_range(offset, length),
                    expected[offset : offset + length],
                )

    def test_seek_and_read(self):
        expected = self._full_decrypt()
        view = self._open_ofile().open_package_view()

        self.assertEqual(view.read(2), expected[:2])
        view.seek(0)
        self.assertEqual(view.read(), expected)
        view.seek(-10, os.SEEK_END)
        self.assertEqual(view.read(), expected[-10:])
        view.seek(100)
        view.seek(-20, os.SEEK_CUR)
        self.assertEqual(view.read(20), expected[80:100])
        view.seek(0)
        self.assertEqual(view.read(8192 + 7), expected[: 8192 + 7])

        with self.assertRaises(ValueError):
            view.seek(-1)
        with self.assertRaises(ValueError):
            view.seek(0, whence=999)

    def test_partial_reads_do_not_decrypt_everything(self):
        view = self._open_ofile().open_package_view()
        stats = view.stats
        self.assertEqual(stats.source_bytes_read, 8)  # size header only
        self.assertEqual(stats.segments_decrypted, 0)

        view.read_range(100, 50)
        stats = view.stats
        self.assertEqual(stats.segments_decrypted, 1)
        self.assertEqual(stats.source_bytes_read, 8 + self.SEGMENT_LENGTH)

        # Re-reading the same area is served from the segment cache.
        view.read_range(200, 10)
        view.read_range(100, 50)
        stats = view.stats
        self.assertEqual(stats.segments_decrypted, 1)
        self.assertEqual(stats.segment_cache_hits, 2)
        self.assertEqual(stats.source_bytes_read, 8 + self.SEGMENT_LENGTH)

        # A read in another segment decrypts exactly one more segment.
        view.read_range(self.SEGMENT_LENGTH + 10, 5)
        self.assertEqual(view.stats.segments_decrypted, 2)

    def test_integrity_is_whole_package_and_tamper_is_detected(self):
        package = self._package_bytes()
        view = self._open_ofile().open_package_view(
            require_integrity=True, cache_segments=0
        )

        # Only the first segment is requested ...
        first = view.read_range(0, 16)
        self.assertTrue(first)
        stats = view.stats
        # ... but verification read/authenticated the entire EncryptedPackage.
        self.assertEqual(stats.integrity_verifications, 1)
        self.assertEqual(stats.integrity_bytes_read, len(package))
        # 8-byte size header + entire stream HMAC pass + the one ciphertext
        # segment needed for the 16 requested plaintext bytes.
        self.assertEqual(
            stats.source_bytes_read, len(package) + 8 + self.SEGMENT_LENGTH
        )
        self.assertEqual(stats.segments_decrypted, 1)
        self.assertTrue(view.verified)

        # A second range read reuses the completed verification; the only new
        # bytes read are the requested ciphertext.
        before = view.stats
        view.read_range(self.SEGMENT_LENGTH + 32, 32)
        after = view.stats
        self.assertEqual(after.integrity_verifications, 1)
        self.assertEqual(after.integrity_bytes_read, before.integrity_bytes_read)
        self.assertEqual(
            after.source_bytes_read, before.source_bytes_read + self.SEGMENT_LENGTH
        )

        # Mutate a ciphertext region that none of the reads above requested
        # (both reads touched segments 0 and 1; this is segment 2).
        untouched_offset = 8 + 2 * self.SEGMENT_LENGTH + 1000
        tampered = bytearray(package)
        tampered[untouched_offset] ^= 0x01

        tampered_view = self._open_ofile().open_package_view(
            require_integrity=True
        )
        tampered_view.replace_source(bytes(tampered))
        with self.assertRaises(exceptions.InvalidKeyError):
            tampered_view.read_range(0, 16)

        # Without the integrity requirement the local read still succeeds;
        # a partial read is not authentication.
        unchecked = ECMA376AgilePackageView(
            *self._view_args(), bytes(tampered), require_integrity=False
        )
        self.addCleanup(unchecked.close)
        self.assertEqual(unchecked.read_range(0, 16), first)

    def test_verification_is_bound_to_same_ciphertext(self):
        package = self._package_bytes()

        # An in-memory bytes source is immutable and can safely reuse its
        # successful verification.
        view = ECMA376AgilePackageView(
            *self._view_args(), bytes(package), require_integrity=True
        )
        self.addCleanup(view.close)
        view.read_range(0, 4)
        self.assertEqual(view.stats.integrity_verifications, 1)
        view.read_range(0, 4)
        self.assertEqual(view.stats.integrity_verifications, 1)

        # Replacing the source discards the verification even if the plaintext
        # happens to still decrypt on the requested range.
        tampered = bytearray(package)
        tampered[8 + 2 * self.SEGMENT_LENGTH + 9] ^= 0x01
        view.replace_source(bytes(tampered))
        self.assertFalse(view.verified)
        with self.assertRaises(exceptions.InvalidKeyError):
            view.read_range(0, 4)
        self.assertEqual(view.stats.integrity_verifications, 2)

        # A seekable file source ties reuse to the file's identity/metadata.
        with open(self.PATH, "rb") as original:
            pristine = original.read()

        temp = NamedTemporaryFile(prefix="msoffcrypto-view-", suffix=".docx", delete=False)
        self.addCleanup(os.unlink, temp.name)
        temp.write(pristine)
        temp.flush()
        temp.close()

        handle = open(temp.name, "rb")
        self.addCleanup(handle.close)
        ofile = OOXMLFile(handle)
        ofile.load_key(password=PASSWORD)
        file_view = ofile.open_package_view(require_integrity=True)
        file_view.read_range(0, 4)
        self.assertEqual(file_view.stats.integrity_verifications, 1)
        file_view.read_range(10, 4)
        self.assertEqual(file_view.stats.integrity_verifications, 1)

        # Rewrite one ciphertext byte in place.  The same open file object now
        # exposes changed metadata/content, so the previous verification must
        # not be reused.
        tampered_package = bytearray(package)
        tampered_package[8 + 2 * self.SEGMENT_LENGTH + 1234] ^= 0x01
        with open(temp.name, "r+b") as writable:
            writable.seek(
                _ole_stream_offset(ofile.file, self.SEGMENT_LENGTH * 2 + 1234)
            )
            writable.write(
                bytes([tampered_package[8 + 2 * self.SEGMENT_LENGTH + 1234]])
            )
        with self.assertRaises(exceptions.InvalidKeyError):
            file_view.read_range(0, 4)
        self.assertEqual(file_view.stats.integrity_verifications, 2)

    def _view_args(self):
        ofile = self._open_ofile()
        info = ofile.info
        return (
            ofile.secret_key,
            info["keyDataSalt"],
            info["keyDataHashAlgorithm"],
            info["keyDataBlockSize"],
            info["encryptedHmacKey"],
            info["encryptedHmacValue"],
        )

    def test_declared_size_padding_and_truncation(self):
        package = self._package_bytes()
        declared = len(self._full_decrypt())
        self.assertEqual(declared, self.DECLARED_LENGTH)

        # Ciphertext normally exceeds the declared plaintext size because the
        # final block is padded; reported sizes must not be confused.
        view = self._open_ofile().open_package_view()
        self.assertGreater(view.encrypted_size, view.declared_size)
        self.assertEqual(view.available_size, view.declared_size)
        self.assertEqual(view.decryptable_size % 16, 0)
        self.assertEqual(
            view.declared_size + (16 - view.declared_size % 16) % 16,
            view.decryptable_size,
        )

        # Truncate the ciphertext mid-way through a segment: only the complete
        # AES blocks that remain can be returned, and the last read is short.
        truncated = package[: 8 + self.SEGMENT_LENGTH * 2 + 37]
        view = ECMA376AgilePackageView(
            *self._view_args(), bytes(truncated), require_integrity=False
        )
        self.addCleanup(view.close)
        self.assertTrue(view.truncated)
        self.assertEqual(view.encrypted_size, self.SEGMENT_LENGTH * 2 + 37)
        self.assertEqual(view.decryptable_size, self.SEGMENT_LENGTH * 2 + 32)
        self.assertEqual(view.available_size, self.SEGMENT_LENGTH * 2 + 32)

        expected = self._full_decrypt()
        self.assertEqual(
            view.read_range(0, view.declared_size),
            expected[: view.available_size],
        )
        self.assertEqual(
            view.read_range(view.available_size - 8, 100),
            expected[view.available_size - 8 : view.available_size],
        )

    def test_rejects_non_agile(self):
        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            ofile = OOXMLFile(f)
            ofile.load_key(password=PASSWORD)
            with self.assertRaises(exceptions.DecryptionError):
                ofile.open_package_view()

    def test_ole_source_reads_incrementally(self):
        """The view must not materialise the OLE stream up front."""

        class CountingFile:
            def __init__(self, wrapped):
                self._wrapped = wrapped
                self.bytes_read = 0

            def seek(self, *args):
                return self._wrapped.seek(*args)

            def read(self, size=-1):
                data = self._wrapped.read(size)
                self.bytes_read += len(data)
                return data

            def __getattr__(self, name):
                return getattr(self._wrapped, name)

        ofile = self._open_ofile()
        from msoffcrypto.method.ecma376_agile import OleStreamPackageSource

        original_fp = ofile.file.fp
        counter = CountingFile(original_fp)
        ofile.file.fp = counter
        self.addCleanup(setattr, ofile.file, "fp", original_fp)

        view = ofile.open_package_view()
        package_size = view.encrypted_size
        # Construction reads only the 8-byte size header from the stream.
        self.assertLessEqual(counter.bytes_read, ofile.file.sector_size)

        counter.bytes_read = 0
        view.read_range(0, 1)
        # One segment (plus at most one OLE sector of slack), not the package.
        self.assertLessEqual(counter.bytes_read, self.SEGMENT_LENGTH + ofile.file.sector_size)
        self.assertLess(counter.bytes_read, package_size)

    def test_mini_stream_source_matches_olefile(self):
        """Small OLE streams live in the mini-stream; reading must still work."""
        from msoffcrypto.method.ecma376_agile import OleStreamPackageSource

        ofile = self._open_ofile()
        entry = ofile.file.direntries[ofile.file._find("EncryptionInfo")]
        self.assertTrue(entry.is_minifat)

        source = OleStreamPackageSource(ofile.file, "EncryptionInfo")
        expected = ofile.file.openstream("EncryptionInfo").read()
        self.assertEqual(source.size, len(expected))

        chunks = [
            source.read_at(offset, 7)
            for offset in range(0, source.size, 7)
        ]
        self.assertEqual(b"".join(chunks)[: source.size], expected)


def _ole_stream_offset(ole, stream_offset, stream_name="EncryptedPackage"):
    """Translate an offset inside an OLE stream to a byte offset in the file."""
    entry = ole.direntries[ole._find(stream_name)]
    if entry.is_minifat:
        raise unittest.SkipTest("offset mapping for mini-streams is not needed here")
    if not entry.sect_chain:
        entry.build_sect_chain(ole)
    sector_index, within_sector = divmod(stream_offset, ole.sector_size)
    return ole.sector_size * (entry.sect_chain[sector_index] + 1) + within_sector


if __name__ == "__main__":
    unittest.main()
