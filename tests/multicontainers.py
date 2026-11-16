"""Structurally valid multi-candidate OLE containers for detection tests.

Each builder returns ``bytes`` of a CFB container whose streams are taken
from real fixtures in ``tests/inputs`` whenever possible, so that every
candidate format present in the container is independently parseable by
its explicit format class.
"""

import os

import olefile

from tests.cfbbuild import MINI_CUTOFF, build_cfb

INPUTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")

PASSWORD = "Password1234_"


def _read_stream(fixture, name):
    with open(os.path.join(INPUTS, fixture), "rb") as f:
        ole = olefile.OleFileIO(f)
        try:
            with ole.openstream(name) as stream:
                return stream.read()
        finally:
            ole.close()


def _pad(data, pad_byte):
    size = max(MINI_CUTOFF, len(data))
    return data + pad_byte * (size - len(data))


def _pad_sector(data, pad_byte):
    size = max(MINI_CUTOFF, -(-len(data) // 512) * 512)
    return data + pad_byte * (size - len(data))


def _encryptioninfo_agile():
    # Trailing whitespace after the XML root element is legal (XML Misc),
    # so space-padding does not break _parseinfo_agile's parseString.
    return _pad(_read_stream("example_password.docx", "EncryptionInfo"), b" ")


def _encrypted_package():
    # The recorded stream size must stay the true size: ECMA376Agile
    # decrypts the stream in AES-block-aligned segments, so padding the
    # recorded size would desync the block alignment.  Sector padding is
    # stored but not recorded, exactly like real CFB producers do.
    data = _read_stream("example_password.docx", "EncryptedPackage")
    return (_pad_sector(data, b"\x00"), len(data))


def _worddocument_plain():
    return _pad(_read_stream("plain.doc", "WordDocument"), b"\x00")


def _worddocument_rc4cryptoapi():
    return _pad(_read_stream("rc4cryptoapi_password.doc", "WordDocument"), b"\x00")


def _table_rc4cryptoapi():
    return _pad(_read_stream("rc4cryptoapi_password.doc", "1Table"), b"\x00")


def conflict_ooxml_and_plain_doc97():
    """EncryptionInfo/EncryptedPackage (agile, password) + plain WordDocument."""
    return build_cfb({
        "EncryptionInfo": _encryptioninfo_agile(),
        "EncryptedPackage": _encrypted_package(),
        "WordDocument": _worddocument_plain(),
    })


def conflict_ooxml_and_encrypted_doc97():
    """EncryptionInfo/EncryptedPackage (agile) + RC4-CryptoAPI WordDocument/1Table."""
    return build_cfb({
        "EncryptionInfo": _encryptioninfo_agile(),
        "EncryptedPackage": _encrypted_package(),
        "WordDocument": _worddocument_rc4cryptoapi(),
        "1Table": _table_rc4cryptoapi(),
    })


def unsupported_encryptioninfo_plus_plain_doc97():
    """EncryptionInfo with Extensible version (4.3) + plain WordDocument."""
    return build_cfb({
        "EncryptionInfo": _pad(b"\x04\x00\x03\x00" + b"\x00" * 100, b"\x00"),
        "WordDocument": _worddocument_plain(),
    })


def encryptioninfo_without_package():
    """Valid agile EncryptionInfo but no EncryptedPackage stream."""
    return build_cfb({
        "EncryptionInfo": _encryptioninfo_agile(),
    })


def plain_doc97():
    """Only a plain (unencrypted) WordDocument stream."""
    return build_cfb({
        "WordDocument": _worddocument_plain(),
    })


def unknown_ole():
    """A valid OLE container with no stream known to any format class."""
    return build_cfb({
        "RandomStream": _pad(b"\xde\xad\xbe\xef" * 16, b"\x00"),
    })
