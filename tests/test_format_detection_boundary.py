"""Reproduce and pin down OfficeFile format-detection boundaries.

An evidence container may carry features of several formats at once
(e.g. an EncryptionInfo stream next to a legacy WordDocument stream).
OfficeFile() auto-detection is first-match by stream name, so it must
not be the only evidence considered.  These tests record which streams
each code path actually reads and how each outcome is classified, so
that a format conflict is never misreported as a password error.
"""

import contextlib
import io
import zipfile

import olefile
import pytest

import msoffcrypto
from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.doc97 import Doc97File
from msoffcrypto.format.ooxml import OOXMLFile
from tests import multicontainers as mc


@contextlib.contextmanager
def traced_ole_reads():
    """Record OleFileIO.exists() queries and openstream() reads."""
    queries, reads = [], []
    orig_exists = olefile.OleFileIO.exists
    orig_openstream = olefile.OleFileIO.openstream

    def exists(self, filename):
        queries.append(filename)
        return orig_exists(self, filename)

    def openstream(self, filename):
        reads.append(filename if isinstance(filename, str) else "/".join(filename))
        return orig_openstream(self, filename)

    olefile.OleFileIO.exists = exists
    olefile.OleFileIO.openstream = openstream
    try:
        yield queries, reads
    finally:
        olefile.OleFileIO.exists = orig_exists
        olefile.OleFileIO.openstream = orig_openstream


def test_auto_detection_on_conflict_reads_only_encryptioninfo():
    buf = mc.conflict_ooxml_and_plain_doc97()
    with traced_ole_reads() as (queries, reads):
        officefile = OfficeFile(io.BytesIO(buf))
    assert type(officefile) is OOXMLFile
    # First match wins: detection stops at EncryptionInfo and never
    # queries the legacy WordDocument/Workbook/PowerPoint candidates.
    assert queries == ["EncryptionInfo"]
    assert reads == ["EncryptionInfo"]
    assert officefile.is_encrypted() is True


def test_explicit_doc97_on_conflict_reads_only_worddocument():
    buf = mc.conflict_ooxml_and_plain_doc97()
    with traced_ole_reads() as (queries, reads):
        officefile = Doc97File(io.BytesIO(buf))
    assert type(officefile) is Doc97File
    assert reads == ["wordDocument"]
    # The WordDocument candidate in this container is a plain document.
    assert officefile.is_encrypted() is False


def test_conflict_container_supports_two_independent_candidates():
    # Candidate 1 (auto-detected): agile-encrypted OOXML package.
    officefile = OfficeFile(io.BytesIO(mc.conflict_ooxml_and_encrypted_doc97()))
    assert type(officefile) is OOXMLFile
    officefile.load_key(password=mc.PASSWORD, verify_password=True)
    out = io.BytesIO()
    officefile.decrypt(out)
    out.seek(0)
    assert zipfile.is_zipfile(out)

    # Candidate 2 (only reachable explicitly): RC4-CryptoAPI doc97.
    doc = Doc97File(io.BytesIO(mc.conflict_ooxml_and_encrypted_doc97()))
    assert doc.is_encrypted() is True
    doc.load_key(password=mc.PASSWORD)
    assert doc.type == "rc4_cryptoapi"


def test_wrong_password_reports_key_error_for_ooxml_candidate_only():
    # Auto-detection verifies the password against EncryptionInfo only;
    # an InvalidKeyError here says nothing about the doc97 candidate.
    officefile = OfficeFile(io.BytesIO(mc.conflict_ooxml_and_encrypted_doc97()))
    with pytest.raises(exceptions.InvalidKeyError):
        officefile.load_key(password="wrong", verify_password=True)
    # The same "wrong" password is not wrong for the whole file: the
    # doc97 candidate still accepts the real password.
    doc = Doc97File(io.BytesIO(mc.conflict_ooxml_and_encrypted_doc97()))
    doc.load_key(password=mc.PASSWORD)


def test_unsupported_encryptioninfo_is_not_a_password_error():
    buf = mc.unsupported_encryptioninfo_plus_plain_doc97()
    handle = io.BytesIO(buf)
    with pytest.raises(exceptions.DecryptionError) as excinfo:
        OfficeFile(handle)
    assert not isinstance(excinfo.value, exceptions.InvalidKeyError)
    assert "Extensible" in str(excinfo.value)
    # Detection failure does not close or corrupt the caller's handle:
    # the same handle still yields the doc97 candidate explicitly.
    assert not handle.closed
    doc = Doc97File(handle)
    assert doc.is_encrypted() is False


def test_unrecognized_ole_leaves_handle_usable():
    handle = io.BytesIO(mc.unknown_ole())
    with pytest.raises(exceptions.FileFormatError):
        OfficeFile(handle)
    assert not handle.closed
    handle.seek(0)
    assert olefile.isOleFile(handle)
    ole = olefile.OleFileIO(handle)
    assert ole.listdir() == [["RandomStream"]]


def test_plain_doc97_load_key_is_not_a_password_error():
    officefile = OfficeFile(io.BytesIO(mc.plain_doc97()))
    assert type(officefile) is Doc97File
    assert officefile.is_encrypted() is False
    with pytest.raises(exceptions.DecryptionError) as excinfo:
        officefile.load_key(password="whatever")
    assert not isinstance(excinfo.value, exceptions.InvalidKeyError)


def test_missing_encryptedpackage_surfaces_as_oserror_at_decrypt():
    # Boundary: EncryptionInfo parses, is_encrypted() is True, but the
    # missing EncryptedPackage stream currently surfaces as a bare
    # OSError from olefile, not as a msoffcrypto exception.
    officefile = OfficeFile(io.BytesIO(mc.encryptioninfo_without_package()))
    assert type(officefile) is OOXMLFile
    assert officefile.is_encrypted() is True
    officefile.load_key(password=mc.PASSWORD)
    with pytest.raises(OSError):
        officefile.decrypt(io.BytesIO())


def test_explicit_format_selection_overrides_auto_detection():
    officefile = OfficeFile(
        io.BytesIO(mc.conflict_ooxml_and_plain_doc97()), format="doc97"
    )
    assert type(officefile) is Doc97File
    officefile = OfficeFile(io.BytesIO(mc.plain_doc97()), format="doc97")
    assert type(officefile) is Doc97File


def test_explicit_format_selection_still_validates_structure():
    # ooxml requires a parseable EncryptionInfo stream.
    with pytest.raises(exceptions.FileFormatError):
        OfficeFile(io.BytesIO(mc.plain_doc97()), format="ooxml")
    # doc97 requires a WordDocument stream.
    with pytest.raises(OSError):
        OfficeFile(io.BytesIO(mc.unknown_ole()), format="doc97")
    # Unknown format names are rejected before touching the file.
    with pytest.raises(exceptions.FileFormatError):
        OfficeFile(io.BytesIO(mc.plain_doc97()), format="bogus")


def test_explicit_format_selection_accepts_every_known_format():
    for fmt in ("ooxml", "doc97", "xls97", "ppt97"):
        try:
            OfficeFile(io.BytesIO(mc.unknown_ole()), format=fmt)
        except exceptions.FileFormatError as e:
            # Must fail structural validation, not name lookup.
            assert "Unknown format" not in str(e)
        except OSError:
            pass
