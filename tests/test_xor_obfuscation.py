"""Tests for legacy XLS XOR obfuscation (MS-OFFCRYPTO 2.3.7, "Method 1").

The XOR password verifier is a weak 15-bit value: it can only hint that a
password might be right.  These tests therefore go beyond "password check
passed" and confirm that the whole workbook stream can actually be restored
record by record.  An independent reference implementation of the transform
(fixed known vectors grounded in an Excel-produced file) provides the
expected record bytes; every record is compared after OfficeFile decodes.

Key properties pinned here:

* The obfuscation array index of a payload byte depends on its absolute
  position in the stream ((offset + record_size) % 16), not on a per-record
  or per-1024-byte-block reset as used by the RC4 variants.
* Record headers, the lbPlyPos field of BoundSheet8, and a fixed set of
  record types (BOF, FilePass, UsrExcl, FileLock, InterfaceHdr, RRDInfo,
  RRDHead) never take part in the transform.
* Passwords are 1-15 characters, each in the single-byte range
  U+0000-U+00FF; longer passwords have no XOR key and characters outside
  the single-byte range are collapsed by the key schedule.
"""

import io
import unittest
from os.path import dirname, join
from struct import pack, unpack

import olefile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.xor_obfuscation import DocumentXOR

#: directory with input files
DATA_DIR = join(dirname(__file__), "inputs")
#: directory with known-plaintext output files
OUTPUT_DIR = join(dirname(__file__), "outputs")

#: record types that MUST NOT be obfuscated (MS-XLS 2.4 / MS-OFFCRYPTO 2.3.7.3)
UNENCRYPTED_RECORDS = frozenset([2057, 47, 404, 405, 225, 406, 312])
#: BoundSheet8: its lbPlyPos field (first 4 payload bytes) is never transformed
BOUNDSHEET8 = 133
#: FilePass record, replaced by zeros in decrypted output
FILEPASS = 47

#: Fixed known vectors: password -> (vKey, vVerifier, obfuscation array).
#: The entry for "123456789012345" is grounded in the Excel-produced
#: tests/inputs/xor_password_123456789012345.xls: vKey/vVerifier are the
#: FilePass values stored in that file, and all 16 array entries were
#: extracted byte-by-byte from its leading records (cross-checked for
#: consistency across 22 records of differing sizes and positions).
PASSWORD_VECTORS = {
    "123456789012345": (
        0x8265,
        0x9EB1,
        [0x2A, 0x58, 0x2B, 0x5B, 0x28, 0x5A, 0x29, 0x5D,
         0x2E, 0x59, 0x2A, 0x58, 0x2B, 0x5B, 0x28, 0x9C],
    ),
    "12345678901234": (
        0xFCCA,
        0x9E85,
        [0xFD, 0x67, 0xFC, 0x64, 0xFF, 0x65, 0xFE, 0x62,
         0xF9, 0x66, 0xFD, 0x67, 0xFC, 0x64, 0xB8, 0x81],
    ),
    "a": (
        0x9D77,
        0xCE88,
        [0x0B, 0x13, 0x44, 0x31, 0xE6, 0x31, 0x44, 0x12,
         0xFB, 0xCE, 0xE4, 0x49, 0xBB, 0x11, 0x3C, 0xCE],
    ),
    # "ac" and "cb" collide on the 15-bit verifier but derive different keys
    "ac": (
        0x79D1,
        0xCF07,
        [0x58, 0x0D, 0x35, 0x43, 0x17, 0xE1, 0x17, 0x43,
         0x34, 0xFC, 0xE8, 0xE3, 0x6F, 0xBC, 0x37, 0x3B],
    ),
    "cb": (
        0x0F92,
        0xCF07,
        [0xF8, 0xB6, 0x94, 0x78, 0xB6, 0xDA, 0xB6, 0x78,
         0x95, 0xC7, 0x49, 0xD8, 0xCE, 0x87, 0x96, 0x00],
    ),
    # Latin-1 characters up to U+00FF are inside the supported range
    "pässwörd": (
        0xB02F,
        0xA7FB,
        [0xAF, 0x2A, 0x2E, 0xE1, 0x2C, 0x23, 0xAE, 0x6A,
         0x4A, 0xA7, 0x68, 0x05, 0x68, 0xA7, 0x4B, 0x18],
    ),
    # 15 characters, the documented maximum; verifier 0x9A0A per MS-OFFCRYPTO
    "VelvetSweatshop": (
        0xB359,
        0x9A0A,
        [0x87, 0x6B, 0x9A, 0xE2, 0x1E, 0xE3, 0x05, 0x62,
         0x1E, 0x69, 0x96, 0x60, 0x98, 0x6E, 0x94, 0x04],
    ),
}


def _rol(value, rotations, width):
    return (2 ** width - 1) & (value << rotations | value >> (width - rotations))


def _ror(value, rotations, width):
    return (2 ** width - 1) & (value >> rotations | value << (width - rotations))


def _ref_verifier(password):
    """Independent reference for MS-OFFCRYPTO 2.3.7.1 (Method 1)."""
    verifier = 0
    for byte in reversed([len(password)] + [ord(c) for c in password]):
        verifier = (((verifier * 2) & 0x7FFF) | (1 if verifier & 0x4000 else 0)) ^ byte
    return verifier ^ 0xCE4B


def _apply_xor_transform(stream, array, decrypt):
    """Independent reference for MS-OFFCRYPTO 2.3.7.3/2.3.7.4 (Method 1).

    Record headers, the lbPlyPos field of BoundSheet8 and the record types
    in UNENCRYPTED_RECORDS are copied as-is.  Every other payload byte is
    combined with the obfuscation array entry selected by its absolute
    stream position, (offset + record_size) % 16; the index runs
    continuously across the stream with no block-wise reset (unlike RC4).
    """
    out = bytearray(stream)
    pos = 0
    while pos + 4 <= len(stream):
        num, size = unpack("<HH", stream[pos:pos + 4])
        if num not in UNENCRYPTED_RECORDS:
            first = pos + 4 + (4 if num == BOUNDSHEET8 else 0)
            for p in range(first, pos + 4 + size):
                index = (p + size) % 16
                if decrypt:
                    out[p] = _ror(stream[p] ^ array[index], 5, 8)
                else:
                    out[p] = _rol(stream[p], 5, 8) ^ array[index]
        pos += 4 + size
    return bytes(out)


def _record(num, payload):
    return pack("<HH", num, len(payload)) + payload


def _parse_records(stream):
    records = []
    pos = 0
    while pos + 4 <= len(stream):
        num, size = unpack("<HH", stream[pos:pos + 4])
        records.append((pos, num, size, stream[pos + 4:pos + 4 + size]))
        pos += 4 + size
    return records


def _read_workbook_stream(path):
    ole = olefile.OleFileIO(path)
    try:
        return ole.openstream("Workbook").read()
    finally:
        ole.close()


def _template_stream_size():
    return len(_read_workbook_stream(join(DATA_DIR, "plain.xls")))


#: identical plaintext placed at two different stream positions
LABEL_PAYLOAD = bytes(range(1, 10))
#: patterned payload large enough to span stream offset 1024
BIG_PAYLOAD = bytes((i * 13 + 5) % 256 for i in range(1100))


def _synthetic_workbook(password):
    """Build (plaintext, XOR-obfuscated) Workbook streams for the password.

    The plaintext stream tiles the template stream size exactly with BIFF
    records (zero padding parses as empty records), so that every record
    can be compared after a round trip through OfficeFile.
    """
    vkey, vverifier, array = PASSWORD_VECTORS[password]
    records = [
        _record(2057, pack("<HHHHII", 0x0600, 0x0005, 0x0DBB, 0x07CC, 0x41, 0x06)),  # BOF
        _record(FILEPASS, pack("<HHH", 0x0000, vkey, vverifier)),
        _record(225, pack("<H", 0x04B0)),  # InterfaceHdr, never transformed
        _record(92, b"Test User".ljust(32, b"\x00")),  # WriteAccess
        _record(66, pack("<H", 1200)),  # CodePage
        _record(BOUNDSHEET8, pack("<IBB", 0x00001000, 0, 0) + b"\x06\x00Sheet1"),
        _record(404, pack("<I", 0x11)),  # UsrExcl, never transformed
        _record(405, pack("<I", 0x22)),  # FileLock, never transformed
        _record(406, pack("<I", 0x33)),  # RRDInfo, never transformed
        _record(312, pack("<HHH", 1, 2, 3)),  # RRDHead, never transformed
        _record(512, pack("<IIHH", 0, 100, 0, 10)),  # Dimensions
        _record(516, LABEL_PAYLOAD),  # Label, first copy
        _record(515, bytes(range(17))),  # odd size shifts the mod-16 phase
        _record(516, LABEL_PAYLOAD),  # Label, second copy at another offset
        _record(252, BIG_PAYLOAD),  # SST-sized record crossing offset 1024
        _record(520, pack("<HHHH", 1, 0, 255, 0)),  # Row
        _record(10, b""),  # EOF
    ]
    plain = b"".join(records)
    stream_size = _template_stream_size()
    pad = stream_size - len(plain)
    assert pad >= 4
    # filler record so the remaining zero padding tiles as empty records
    plain += _record(60, bytes((pad - 4) % 4))
    plain += b"\x00" * (stream_size - len(plain))
    encrypted = _apply_xor_transform(plain, array, decrypt=False)
    return plain, encrypted


def _expected_decrypted(plain):
    """Plaintext stream as OfficeFile.decrypt emits it (FilePass zeroed)."""
    for offset, num, size, _payload in _parse_records(plain):
        if num == FILEPASS:
            return plain[:offset] + pack("<HH", 0, size) + b"\x00" * size + plain[offset + 4 + size:]
    raise AssertionError("no FilePass record")


def _make_xls(stream):
    """Pack a Workbook stream into a real OLE container (in memory)."""
    with open(join(DATA_DIR, "plain.xls"), "rb") as file_handle:
        blob = io.BytesIO(file_handle.read())
    ole = olefile.OleFileIO(blob, write_mode=True)
    ole.write_stream("Workbook", stream)
    blob.seek(0)
    return blob


def _decrypt_workbook(blob, password):
    officefile = OfficeFile(blob)
    officefile.load_key(password=password)
    out = io.BytesIO()
    officefile.decrypt(out)
    out.seek(0)
    ole = olefile.OleFileIO(out)
    try:
        return ole.openstream("Workbook").read()
    finally:
        ole.close()


class XorKeyScheduleTest(unittest.TestCase):
    """Verifier, XOR key and obfuscation array against fixed known vectors."""

    def test_known_vectors(self):
        for password, (vkey, vverifier, array) in PASSWORD_VECTORS.items():
            with self.subTest(password=password):
                self.assertEqual(DocumentXOR.create_xor_key_method1(password), vkey)
                self.assertEqual(DocumentXOR.create_xor_array_method1(password), array)
                self.assertTrue(DocumentXOR.verifypw(password, vverifier))
                self.assertEqual(_ref_verifier(password), vverifier)

    def test_same_verifier_for_different_passwords(self):
        # "ac" and "cb" share the 15-bit verifier 0xCF07 ...
        self.assertTrue(DocumentXOR.verifypw("ac", 0xCF07))
        self.assertTrue(DocumentXOR.verifypw("cb", 0xCF07))
        # ... yet derive different keys and obfuscation arrays, so a verifier
        # match says nothing about which array will decode the content
        self.assertNotEqual(
            DocumentXOR.create_xor_key_method1("ac"),
            DocumentXOR.create_xor_key_method1("cb"),
        )
        self.assertNotEqual(
            DocumentXOR.create_xor_array_method1("ac"),
            DocumentXOR.create_xor_array_method1("cb"),
        )

    def test_password_length_boundary_is_15(self):
        for length in range(1, 16):
            with self.subTest(length=length):
                DocumentXOR.create_xor_key_method1("x" * length)
                DocumentXOR.create_xor_array_method1("x" * length)
        # the initial_code table has exactly 15 entries: no key exists for
        # 16 characters, even though the verifier itself performs no
        # length check and would still "verify" such a password
        with self.assertRaises(IndexError):
            DocumentXOR.create_xor_key_method1("x" * 16)
        self.assertIsInstance(DocumentXOR.verifypw("x" * 16, 0), bool)

    def test_password_charset_is_single_byte(self):
        # the key schedule consumes only the low 8 bits of each character
        self.assertEqual(
            DocumentXOR.create_xor_key_method1("Ā"),
            DocumentXOR.create_xor_key_method1("\x00"),
        )
        # while the verifier uses full code points, so passwords containing
        # characters outside U+0000-U+00FF cannot round-trip and are not
        # part of the supported range
        self.assertNotEqual(_ref_verifier("Ā"), _ref_verifier("\x00"))
        self.assertFalse(DocumentXOR.verifypw("Ā", _ref_verifier("\x00")))


class XorRealFileTest(unittest.TestCase):
    """The Excel-produced XOR file must be restorable, not just verifiable."""

    ENCRYPTED = join(DATA_DIR, "xor_password_123456789012345.xls")
    PLAIN = join(OUTPUT_DIR, "xor_password_123456789012345_plain.xls")
    PASSWORD = "123456789012345"

    def test_filepass_matches_known_vector(self):
        stream = _read_workbook_stream(self.ENCRYPTED)
        payload = next(r[3] for r in _parse_records(stream) if r[1] == FILEPASS)
        wtype, vkey, vverifier = unpack("<HHH", payload)
        self.assertEqual(wtype, 0x0000)  # XOR obfuscation
        self.assertEqual((vkey, vverifier), PASSWORD_VECTORS[self.PASSWORD][:2])

    def test_reference_transform_reproduces_excel_plaintext(self):
        array = PASSWORD_VECTORS[self.PASSWORD][2]
        encrypted = _read_workbook_stream(self.ENCRYPTED)
        plain = _read_workbook_stream(self.PLAIN)
        decrypted = _apply_xor_transform(encrypted, array, decrypt=True)
        # the known-plaintext file was re-written by another tool, so the
        # layouts eventually diverge; the leading records (including the
        # 112-byte WriteAccess record) must match byte for byte
        dec_records = [r for r in _parse_records(decrypted) if r[1] != FILEPASS]
        plain_records = _parse_records(plain)
        matched = 0
        for dec_rec, plain_rec in zip(dec_records, plain_records):
            if dec_rec[1:] != plain_rec[1:]:
                break
            matched += 1
        self.assertGreaterEqual(matched, 16)
        self.assertGreater(max(r[2] for r in dec_records[:matched]), 100)
        # BoundSheet8: lbPlyPos is stored untransformed and the transformed
        # tail must decode to the bytes the other tool produced
        enc_bs = next(r for r in _parse_records(encrypted) if r[1] == BOUNDSHEET8)
        dec_bs = next(r for r in _parse_records(decrypted) if r[1] == BOUNDSHEET8)
        plain_bs = next(r for r in _parse_records(plain) if r[1] == BOUNDSHEET8)
        self.assertEqual(enc_bs[3][:4], dec_bs[3][:4])
        self.assertEqual(dec_bs[3][4:], plain_bs[3][4:])

    def test_officefile_restores_every_record(self):
        array = PASSWORD_VECTORS[self.PASSWORD][2]
        encrypted = _read_workbook_stream(self.ENCRYPTED)
        expected = bytearray(_apply_xor_transform(encrypted, array, decrypt=True))
        for offset, num, size, _payload in _parse_records(encrypted):
            if num == FILEPASS:
                expected[offset:offset + 4 + size] = pack("<HH", 0, size) + b"\x00" * size
        with open(self.ENCRYPTED, "rb") as file_handle:
            actual = _decrypt_workbook(io.BytesIO(file_handle.read()), self.PASSWORD)
        self.assertEqual(actual, bytes(expected))
        self.assertEqual(len(_parse_records(actual)), len(_parse_records(encrypted)))


class XorSyntheticWorkbookTest(unittest.TestCase):
    """Round trip of crafted streams through OfficeFile, all records checked."""

    def test_roundtrip_restores_every_record(self):
        # 1, 8 (Latin-1), 14 and 15 characters: the supported length range
        for password in ("a", "pässwörd", "12345678901234", "123456789012345"):
            with self.subTest(password=password):
                plain, encrypted = _synthetic_workbook(password)
                actual = _decrypt_workbook(_make_xls(encrypted), password)
                self.assertEqual(actual, _expected_decrypted(plain))

    def test_wrong_password_rejected(self):
        _plain, encrypted = _synthetic_workbook("123456789012345")
        self.assertNotEqual(_ref_verifier("wrongpassword"), 0x9EB1)
        officefile = OfficeFile(_make_xls(encrypted))
        with self.assertRaises(exceptions.InvalidKeyError):
            officefile.load_key(password="wrongpassword")

    def test_headers_and_reserved_fields_not_transformed(self):
        plain, encrypted = _synthetic_workbook("123456789012345")
        plain_records = _parse_records(plain)
        encrypted_records = _parse_records(encrypted)
        self.assertEqual(len(plain_records), len(encrypted_records))
        transformed = 0
        for (_po, pnum, psize, pp), (_eo, enum, esize, ep) in zip(plain_records, encrypted_records):
            # record headers stay readable without the password
            self.assertEqual((pnum, psize), (enum, esize))
            if pnum in UNENCRYPTED_RECORDS:
                self.assertEqual(pp, ep)
            elif pnum == BOUNDSHEET8:
                self.assertEqual(pp[:4], ep[:4])  # lbPlyPos stays readable
                transformed += pp[4:] != ep[4:]
            else:
                transformed += pp != ep
        self.assertGreater(transformed, 0)  # transform actually applied

    def test_array_index_depends_on_record_position(self):
        plain, encrypted = _synthetic_workbook("123456789012345")
        plain_labels = [r for r in _parse_records(plain) if r[1] == 516]
        encrypted_labels = [r for r in _parse_records(encrypted) if r[1] == 516]
        self.assertEqual(len(plain_labels), 2)
        # identical plaintext at different stream positions ...
        self.assertEqual(plain_labels[0][3], plain_labels[1][3])
        self.assertNotEqual(plain_labels[0][0], plain_labels[1][0])
        # ... must obfuscate to different bytes: the array index follows the
        # absolute position, so a per-record index reset cannot decode this
        self.assertNotEqual(encrypted_labels[0][3], encrypted_labels[1][3])
        actual = _decrypt_workbook(_make_xls(encrypted), "123456789012345")
        decoded_labels = [r[3] for r in _parse_records(actual) if r[1] == 516]
        self.assertEqual(decoded_labels, [LABEL_PAYLOAD, LABEL_PAYLOAD])

    def test_no_rc4_style_block_reset(self):
        plain, encrypted = _synthetic_workbook("123456789012345")
        big = next(r for r in _parse_records(plain) if r[1] == 252)
        # the record spans offset 1024, where RC4 decryption would restart
        # its key schedule; XOR obfuscation must continue seamlessly
        self.assertLess(big[0], 1024)
        self.assertGreater(big[0] + 4 + big[2], 1024)
        actual = _decrypt_workbook(_make_xls(encrypted), "123456789012345")
        decoded_big = next(r for r in _parse_records(actual) if r[1] == 252)
        self.assertEqual(decoded_big[3], BIG_PAYLOAD)


class XorWeakVerifierTest(unittest.TestCase):
    """A passing verifier must not be promoted to a content integrity proof.

    The XOR verifier is 15 bits and collisions are easy to find.  A wrong
    password that happens to match the verifier passes load_key() without
    error, yet decodes the workbook to different bytes.  Since record
    headers are never transformed, the bogus output even keeps a valid
    record structure - neither the verifier nor the parseability of the
    result can confirm the content.
    """

    def test_verifier_pass_does_not_confirm_content(self):
        plain, encrypted = _synthetic_workbook("ac")
        vverifier = PASSWORD_VECTORS["ac"][1]
        self.assertTrue(DocumentXOR.verifypw("ac", vverifier))
        self.assertTrue(DocumentXOR.verifypw("cb", vverifier))  # collision

        # the colliding password passes verification without any error ...
        actual = _decrypt_workbook(_make_xls(encrypted), "cb")
        expected = _expected_decrypted(plain)
        # ... but the decoded content cannot be relied upon
        self.assertNotEqual(actual, expected)
        # record structure survives (headers are never transformed), so the
        # garbage still parses as a well-formed sequence of BIFF records
        self.assertEqual(
            [(num, size) for _o, num, size, _p in _parse_records(actual)],
            [(num, size) for _o, num, size, _p in _parse_records(expected)],
        )
        # control: the correct password restores every record byte
        self.assertEqual(_decrypt_workbook(_make_xls(encrypted), "ac"), expected)


if __name__ == "__main__":
    unittest.main()
