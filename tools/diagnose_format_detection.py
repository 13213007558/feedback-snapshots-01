#!/usr/bin/env python
"""Diagnose msoffcrypto-tool format-detection boundaries on multi-candidate OLE containers.

Builds structurally valid OLE containers that carry features of several
formats at once (EncryptionInfo next to legacy WordDocument streams),
then compares:

* OfficeFile() auto-detection (first match by stream name), and
* explicit format parsing (OOXMLFile / Doc97File / OfficeFile(format=...)).

For each container and path it prints which streams were queried and
read, how the outcome is classified, and whether the caller can keep
reading the handle after a detection failure.

Run from the repository root:

    .venv/bin/python tools/diagnose_format_detection.py
"""

import contextlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import olefile  # noqa: E402

from msoffcrypto import OfficeFile, exceptions  # noqa: E402
from msoffcrypto.format.doc97 import Doc97File  # noqa: E402
from msoffcrypto.format.ooxml import OOXMLFile  # noqa: E402
from tests import multicontainers as mc  # noqa: E402


@contextlib.contextmanager
def traced_ole_reads():
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


def classify_exception(exc):
    """Map an exception to an evidence category.

    InvalidKeyError is the *only* category that may be reported as a
    password problem; structural and detection failures must stay
    distinguishable from it.
    """
    if isinstance(exc, exceptions.InvalidKeyError):
        return "KEY-REJECTED (password verification failed for this candidate)"
    if isinstance(exc, exceptions.DecryptionError):
        return "UNSUPPORTED/STRUCTURAL (not a password error)"
    if isinstance(exc, exceptions.FileFormatError):
        return "FORMAT-UNRECOGNIZED (not a password error)"
    return "UNEXPECTED {} (not a msoffcrypto exception)".format(type(exc).__name__)


def probe(buf, label, factory):
    handle = io.BytesIO(buf)
    with traced_ole_reads() as (queries, reads):
        try:
            officefile = factory(handle)
        except Exception as exc:
            outcome = "raise {}: {}".format(type(exc).__name__, exc)
            category = classify_exception(exc)
            officefile = None
        else:
            outcome = "{} is_encrypted={}".format(
                type(officefile).__name__, officefile.is_encrypted()
            )
            category = "ENCRYPTED" if officefile.is_encrypted() else "PLAIN"
    print("  {:<28} {}".format(label, outcome))
    print("  {:<28} category: {}".format("", category))
    print("  {:<28} exists() queried: {}".format("", queries or "-"))
    print("  {:<28} streams read: {}".format("", reads or "-"))
    # After any outcome, the caller's handle must still be usable.
    handle.seek(0)
    reusable = not handle.closed and olefile.isOleFile(handle)
    print("  {:<28} handle reusable afterwards: {}".format("", reusable))
    print()
    return officefile


CONTAINERS = [
    ("conflict: agile EncryptionInfo + plain WordDocument",
     mc.conflict_ooxml_and_plain_doc97),
    ("conflict: agile EncryptionInfo + RC4-CryptoAPI WordDocument/1Table",
     mc.conflict_ooxml_and_encrypted_doc97),
    ("unsupported EncryptionInfo (Extensible 4.3) + plain WordDocument",
     mc.unsupported_encryptioninfo_plus_plain_doc97),
    ("EncryptionInfo without EncryptedPackage",
     mc.encryptioninfo_without_package),
    ("plain WordDocument only",
     mc.plain_doc97),
    ("no known streams",
     mc.unknown_ole),
]


def main():
    for title, builder in CONTAINERS:
        buf = builder()
        print("=" * 78)
        print(title)
        ole = olefile.OleFileIO(io.BytesIO(buf))
        print("  streams: {}".format(["/".join(s) for s in ole.listdir()]))
        ole.close()
        print()
        probe(buf, "auto OfficeFile()", lambda h: OfficeFile(h))
        probe(buf, "explicit OOXMLFile", lambda h: OOXMLFile(h))
        probe(buf, "explicit Doc97File", lambda h: Doc97File(h))
        probe(buf, "OfficeFile(format='doc97')", lambda h: OfficeFile(h, format="doc97"))

    print("=" * 78)
    print("Password verification on the fully encrypted conflict container")
    print()
    buf = mc.conflict_ooxml_and_encrypted_doc97()

    officefile = OfficeFile(io.BytesIO(buf))
    officefile.load_key(password=mc.PASSWORD, verify_password=True)
    out = io.BytesIO()
    officefile.decrypt(out)
    out.seek(0)
    print("  auto path, correct password: decrypted payload is zip:",
          zipfile.is_zipfile(out))

    officefile = OfficeFile(io.BytesIO(buf))
    try:
        officefile.load_key(password="wrong", verify_password=True)
    except exceptions.InvalidKeyError as exc:
        print("  auto path, wrong password:   InvalidKeyError ({})".format(exc))
        print("    -> accurate for the OOXML candidate, but the doc97")
        print("       candidate was never examined; do not report the file")
        print("       itself as 'wrong password' on this evidence alone.")

    doc = Doc97File(io.BytesIO(buf))
    doc.load_key(password=mc.PASSWORD)
    print("  explicit doc97, same container: password verified ({})".format(doc.type))


if __name__ == "__main__":
    main()
