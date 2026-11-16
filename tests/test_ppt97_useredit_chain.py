#!/usr/bin/env python

"""Tests for the MS-PPT UserEdit chain traversal and encryption session
selection in msoffcrypto.format.ppt97.

Covers:
- persistIds overridden by a later edit (newest mapping wins, unmodified
  historical entries are retained),
- encryptSessionPersistIdRef pointing to a missing persist object,
- loops in the UserEditAtom chain,
- offsets outside the PowerPoint Document stream,
- identical validation with and without ``python -O``,
- decrypt() leaving unrelated OLE streams untouched.
"""

import io
import os
import subprocess
import sys
import unittest
from collections import namedtuple
from struct import pack
from tempfile import mkstemp

import olefile

TEST_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_BASE_DIR = os.path.dirname(TEST_BASE_DIR)
if sys.path[0] != MODULE_BASE_DIR:
    sys.path.insert(0, MODULE_BASE_DIR)

import msoffcrypto
from msoffcrypto import exceptions
from msoffcrypto.format import ppt97

PASSWORD = "Password1234_"
SAMPLE_PPT = os.path.join(TEST_BASE_DIR, "inputs", "rc4cryptoapi_password.ppt")

Data = namedtuple("Data", ["currentuser", "powerpointdocument"])


def _record_header(rec_ver, rec_instance, rec_type, rec_len):
    return pack(
        "<HHI",
        (rec_ver & 0xF) | ((rec_instance & 0xFFF) << 4),
        rec_type,
        rec_len,
    )


def _current_user_stream(offset_to_current_edit):
    body = pack(
        "<IIIHHBB2sI",
        0x00000014,  # size
        0xE391C05F,  # headerToken (not encrypted)
        offset_to_current_edit,
        0,  # lenUserName
        0,  # docFileVersion
        3,  # majorVersion
        8,  # minorVersion
        b"\x00\x00",  # unused
        0,  # relVersion
    )
    return _record_header(0x0, 0x000, 0x0FF6, len(body)) + body


def _user_edit_atom(
    offset_last_edit, offset_persist_directory, encrypt_session_persist_id_ref=None
):
    body = pack(
        "<IHBBIIIIH2s",
        0,  # lastSlideIdRef
        0,  # version
        0,  # minorVersion
        0,  # majorVersion
        offset_last_edit,
        offset_persist_directory,
        0,  # docPersistIdRef
        0,  # persistIdSeed
        0,  # lastView
        b"\x00\x00",  # unused
    )
    if encrypt_session_persist_id_ref is not None:
        body += pack("<I", encrypt_session_persist_id_ref)
    return _record_header(0x0, 0x000, 0x0FF5, len(body)) + body


def _persist_directory_atom(entries):
    body = b""
    for persist_id, offsets in entries:
        body += pack("<I", (persist_id & 0xFFFFF) | ((len(offsets) & 0xFFF) << 20))
        for offset in offsets:
            body += pack("<I", offset)
    return _record_header(0x0, 0x000, 0x1772, len(body)) + body


# Layout of the synthetic PowerPoint Document stream
EDIT1, DIR1 = 0x0100, 0x0200
EDIT2, DIR2 = 0x0300, 0x0400
STREAM_SIZE = 0x0500


def _build_chain_data(
    edit1_last_edit=0x00000000,
    edit2_last_edit=EDIT1,
    edit1_persist_directory=DIR1,
    edit2_persist_directory=DIR2,
    dir1_entries=((1, [0x0010]), (2, [0x0020])),
    dir2_entries=((2, [0x0030]),),
    offset_to_current_edit=EDIT2,
):
    stream = bytearray(STREAM_SIZE)
    stream[EDIT1 : EDIT1 + 0x24] = _user_edit_atom(edit1_last_edit, edit1_persist_directory)
    dir1 = _persist_directory_atom(dir1_entries)
    stream[DIR1 : DIR1 + len(dir1)] = dir1
    stream[EDIT2 : EDIT2 + 0x28] = _user_edit_atom(
        edit2_last_edit, edit2_persist_directory, encrypt_session_persist_id_ref=2
    )
    dir2 = _persist_directory_atom(dir2_entries)
    stream[DIR2 : DIR2 + len(dir2)] = dir2
    return Data(
        currentuser=io.BytesIO(_current_user_stream(offset_to_current_edit)),
        powerpointdocument=io.BytesIO(bytes(stream)),
    )


def check_validation_under_optimization():
    """Entry point for the ``python -O`` subprocess test.

    Exits nonzero unless every corrupted input raises ParseError.
    """
    cases = [
        _build_chain_data(edit2_last_edit=EDIT2),  # self-loop
        _build_chain_data(edit2_last_edit=0xFFFFFFF0),  # out of bounds
        _build_chain_data(edit2_persist_directory=0xFFFFFFF0),  # out of bounds
    ]
    for data in cases:
        try:
            ppt97.construct_persistobjectdirectory(data)
        except exceptions.ParseError:
            continue
        except Exception as e:  # wrong exception type: validation regressed
            print("unexpected exception type: {!r}".format(e))
            return 1
        else:
            print("corrupted chain was silently accepted")
            return 1
    return 0


class TestUserEditChainTraversal(unittest.TestCase):
    def test_two_edit_chain_newest_mapping_wins(self):
        data = _build_chain_data()
        directory = ppt97.construct_persistobjectdirectory(data)
        # persistId 2 is overridden by the later edit; persistId 1 only
        # exists in the historical directory and must be retained.
        self.assertEqual(directory, {1: 0x0010, 2: 0x0030})

    def test_chain_loop_raises_parse_error_with_offset(self):
        data = _build_chain_data(edit2_last_edit=EDIT2)  # self-loop
        with self.assertRaises(exceptions.ParseError) as cm:
            ppt97.construct_persistobjectdirectory(data)
        self.assertIn(hex(EDIT2), str(cm.exception))

    def test_chain_loop_between_two_edits(self):
        data = _build_chain_data(edit1_last_edit=EDIT2)  # EDIT2 -> EDIT1 -> EDIT2
        with self.assertRaises(exceptions.ParseError) as cm:
            ppt97.construct_persistobjectdirectory(data)
        self.assertIn(hex(EDIT2), str(cm.exception))

    def test_last_edit_offset_out_of_bounds(self):
        data = _build_chain_data(edit2_last_edit=0xFFFFFFF0)
        with self.assertRaises(exceptions.ParseError):
            ppt97.construct_persistobjectdirectory(data)

    def test_persist_directory_offset_out_of_bounds(self):
        data = _build_chain_data(edit2_persist_directory=0xFFFFFFF0)
        with self.assertRaises(exceptions.ParseError):
            ppt97.construct_persistobjectdirectory(data)

    def test_current_edit_offset_out_of_bounds(self):
        data = _build_chain_data(offset_to_current_edit=0xFFFFFFF0)
        with self.assertRaises(exceptions.ParseError):
            ppt97.construct_persistobjectdirectory(data)

    def test_validation_identical_under_python_O(self):
        script = (
            "import sys; sys.path.insert(0, {!r});"
            "import test_ppt97_useredit_chain as t;"
            "sys.exit(t.check_validation_under_optimization())".format(TEST_BASE_DIR)
        )
        for flags in ([], ["-O"]):
            proc = subprocess.run(
                [sys.executable] + flags + ["-c", script],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                "flags={} stdout={} stderr={}".format(flags, proc.stdout, proc.stderr),
            )


def _patch_encrypt_session_ref(path, new_ref):
    ole = olefile.OleFileIO(path, write_mode=True)
    currentuser = ppt97._parseCurrentUser(io.BytesIO(ole.openstream("Current User").read()))
    offset_to_current_edit = currentuser.currentuseratom.offsetToCurrentEdit
    stream = bytearray(ole.openstream("PowerPoint Document").read())
    # encryptSessionPersistIdRef sits 8 (rh) + 28 (fixed body) bytes into the UserEditAtom
    stream[offset_to_current_edit + 36 : offset_to_current_edit + 40] = pack("<I", new_ref)
    ole.write_stream("PowerPoint Document", bytes(stream))
    ole.close()


class TestEncryptionSessionSelection(unittest.TestCase):
    def _patched_sample(self, new_ref):
        fd, path = mkstemp(suffix=".ppt")
        try:
            with open(SAMPLE_PPT, "rb") as f_in, os.fdopen(fd, "wb") as f_out:
                f_out.write(f_in.read())
            _patch_encrypt_session_ref(path, new_ref)
            yield_path = path
        except Exception:
            os.unlink(path)
            raise
        return yield_path

    def test_session_ref_missing_from_directory(self):
        path = self._patched_sample(0x00ABCDEF)
        try:
            with open(path, "rb") as f:
                officefile = msoffcrypto.OfficeFile(f)
                with self.assertRaises(exceptions.ParseError) as cm:
                    officefile.load_key(password=PASSWORD)
            self.assertIn(hex(0x00ABCDEF), str(cm.exception))
        finally:
            os.unlink(path)

    def test_session_ref_uses_latest_edit_record(self):
        # persistId 1 exists in the directory but does not point to a
        # CryptSession10Container; selecting it must fail, proving the
        # reference is taken from the current (latest) UserEditAtom.
        path = self._patched_sample(1)
        try:
            with open(path, "rb") as f:
                officefile = msoffcrypto.OfficeFile(f)
                with self.assertRaises(exceptions.ParseError):
                    officefile.load_key(password=PASSWORD)
        finally:
            os.unlink(path)

    def test_unmodified_sample_still_loads(self):
        with open(SAMPLE_PPT, "rb") as f:
            officefile = msoffcrypto.OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            self.assertEqual(officefile.type, "rc4_cryptoapi")


class TestDecryptPreservesOtherStreams(unittest.TestCase):
    def test_unrelated_ole_streams_are_not_modified(self):
        with open(SAMPLE_PPT, "rb") as f:
            officefile = msoffcrypto.OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            out = io.BytesIO()
            officefile.decrypt(out)

        managed = {"Current User", "PowerPoint Document"}
        in_ole = olefile.OleFileIO(SAMPLE_PPT)
        out.seek(0)
        out_ole = olefile.OleFileIO(out)

        in_streams = {"/".join(entry) for entry in in_ole.listdir()}
        out_streams = {"/".join(entry) for entry in out_ole.listdir()}
        self.assertEqual(in_streams, out_streams)
        self.assertTrue(managed.issubset(in_streams))

        for name in in_streams - managed:
            self.assertEqual(
                in_ole.openstream(name).read(),
                out_ole.openstream(name).read(),
                "unrelated stream {!r} was modified".format(name),
            )
        # sanity: the document stream itself must have been rewritten
        self.assertNotEqual(
            in_ole.openstream("PowerPoint Document").read(),
            out_ole.openstream("PowerPoint Document").read(),
        )
        in_ole.close()
        out_ole.close()


if __name__ == "__main__":
    unittest.main()
