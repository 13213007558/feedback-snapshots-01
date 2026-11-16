import base64
import binascii
import io
import logging
import re
import zipfile
from struct import unpack
from xml.dom import Node
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

import olefile

from msoffcrypto import exceptions
from msoffcrypto.format import base
from msoffcrypto.format.common import _parse_encryptionheader, _parse_encryptionverifier
from msoffcrypto.method.ecma376_agile import ALGORITHM_HASH, ECMA376Agile
from msoffcrypto.method.ecma376_standard import ECMA376Standard

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _is_ooxml(file):
    if not zipfile.is_zipfile(file):
        return False
    try:
        zfile = zipfile.ZipFile(file)
        with zfile.open("[Content_Types].xml") as stream:
            xml = parseString(stream.read())
            # Heuristic
            if (
                xml.documentElement.tagName == "Types"
                and xml.documentElement.namespaceURI
                == "http://schemas.openxmlformats.org/package/2006/content-types"
            ):
                return True
            else:
                return False
    except Exception:
        return False


def _parseinfo_standard(ole):
    (headerFlags,) = unpack("<I", ole.read(4))
    (encryptionHeaderSize,) = unpack("<I", ole.read(4))
    block = ole.read(encryptionHeaderSize)
    blob = io.BytesIO(block)
    header = _parse_encryptionheader(blob)
    block = ole.read()
    blob = io.BytesIO(block)
    algIdMap = {
        0x0000660E: "AES-128",
        0x0000660F: "AES-192",
        0x00006610: "AES-256",
    }
    verifier = _parse_encryptionverifier(
        blob, "AES" if header["algId"] & 0xFF00 == 0x6600 else "RC4"
    )  # TODO: Fix
    info = {
        "header": header,
        "verifier": verifier,
    }
    return info


AGILE_ENCRYPTION_NS = "http://schemas.microsoft.com/office/2006/encryption"
AGILE_PASSWORD_NS = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
)
_AGILE_AES_BLOCK_SIZE = 16
_AGILE_KEY_BITS = frozenset((128, 192, 256))


def _agile_direct_children(node, namespace, local_name):
    """Return direct element children with the exact namespace and local name."""
    return [
        child
        for child in node.childNodes
        if child.nodeType == Node.ELEMENT_NODE
        and child.namespaceURI == namespace
        and child.localName == local_name
    ]


def _agile_single_child(node, namespace, local_name, path):
    children = _agile_direct_children(node, namespace, local_name)
    if len(children) != 1:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo must contain exactly one {} element (found {})".format(
                path, len(children)
            )
        )
    return children[0]


def _agile_required_attr(node, name, path):
    value = node.getAttribute(name)
    if not value:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo is missing required attribute {}@{}".format(path, name)
        )
    return value


def _agile_int_attr(node, name, path):
    value = _agile_required_attr(node, name, path)
    if len(value) > 10 or re.fullmatch(r"[0-9]+", value) is None:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo attribute {}@{} must be an unsigned integer".format(
                path, name
            )
        )
    return int(value)


def _agile_b64_attr(node, name, path):
    # XML Schema base64Binary allows whitespace; normalize before decoding.
    value = re.sub(r"\s+", "", _agile_required_attr(node, name, path))
    if not value:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo attribute {}@{} is empty".format(path, name)
        )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo attribute {}@{} is not valid base64".format(path, name)
        ) from exc


def _agile_round_up(size, block_size):
    return (size + block_size - 1) // block_size * block_size


def _agile_cipher_params(node, path):
    cipher_algorithm = _agile_required_attr(node, "cipherAlgorithm", path)
    if cipher_algorithm != "AES":
        raise exceptions.DecryptionError(
            "Unsupported Agile cipher algorithm {!r} in {}".format(
                cipher_algorithm, path
            )
        )

    cipher_chaining = _agile_required_attr(node, "cipherChaining", path)
    if cipher_chaining != "ChainingModeCBC":
        raise exceptions.DecryptionError(
            "Unsupported Agile cipher chaining {!r} in {}".format(
                cipher_chaining, path
            )
        )

    hash_algorithm = _agile_required_attr(node, "hashAlgorithm", path)
    hash_cls = ALGORITHM_HASH.get(hash_algorithm)
    if hash_cls is None:
        raise exceptions.DecryptionError(
            "Unsupported Agile hash algorithm {!r} in {}".format(hash_algorithm, path)
        )
    digest_size = hash_cls().digest_size

    hash_size = _agile_int_attr(node, "hashSize", path)
    if hash_size != digest_size:
        raise exceptions.DecryptionError(
            "Agile {} hashSize {} does not match {} digest size {}".format(
                path, hash_size, hash_algorithm, digest_size
            )
        )

    block_size = _agile_int_attr(node, "blockSize", path)
    if block_size != _AGILE_AES_BLOCK_SIZE:
        raise exceptions.DecryptionError(
            "Agile {} blockSize must be {} for AES".format(
                path, _AGILE_AES_BLOCK_SIZE
            )
        )

    key_bits = _agile_int_attr(node, "keyBits", path)
    if key_bits not in _AGILE_KEY_BITS:
        raise exceptions.DecryptionError(
            "Unsupported Agile keyBits {} in {}".format(key_bits, path)
        )

    salt_size = _agile_int_attr(node, "saltSize", path)
    if salt_size != block_size:
        raise exceptions.DecryptionError(
            "Agile {} saltSize {} does not match blockSize {}".format(
                path, salt_size, block_size
            )
        )

    salt_value = _agile_b64_attr(node, "saltValue", path)
    if len(salt_value) != salt_size:
        raise exceptions.DecryptionError(
            "Agile {} saltValue has length {}, expected {}".format(
                path, len(salt_value), salt_size
            )
        )

    return {
        "salt": salt_value,
        "saltSize": salt_size,
        "blockSize": block_size,
        "keyBits": key_bits,
        "hashSize": hash_size,
        "hashAlgorithm": hash_algorithm,
    }


def _agile_expected_length(size, block_size, path, value, attribute):
    expected = _agile_round_up(size, block_size)
    if len(value) != expected:
        raise exceptions.DecryptionError(
            "Agile {} {} has length {}, expected {}".format(
                path, attribute, len(value), expected
            )
        )


def _parseinfo_agile(ole):
    ole.seek(8)
    try:
        xml = parseString(ole.read())
    except ExpatError as exc:
        raise exceptions.DecryptionError(
            "Invalid Agile EncryptionInfo XML: {}".format(exc)
        ) from exc

    root = xml.documentElement
    if root.namespaceURI != AGILE_ENCRYPTION_NS or root.localName != "encryption":
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo root must be encryption in the {} namespace".format(
                AGILE_ENCRYPTION_NS
            )
        )

    key_data_node = _agile_single_child(
        root, AGILE_ENCRYPTION_NS, "keyData", "encryption/keyData"
    )
    key_data = _agile_cipher_params(key_data_node, "encryption/keyData")

    data_integrity_node = _agile_single_child(
        root, AGILE_ENCRYPTION_NS, "dataIntegrity", "encryption/dataIntegrity"
    )
    encryptedHmacKey = _agile_b64_attr(
        data_integrity_node, "encryptedHmacKey", "encryption/dataIntegrity"
    )
    encryptedHmacValue = _agile_b64_attr(
        data_integrity_node, "encryptedHmacValue", "encryption/dataIntegrity"
    )
    _agile_expected_length(
        key_data["hashSize"],
        key_data["blockSize"],
        "encryption/dataIntegrity",
        encryptedHmacKey,
        "encryptedHmacKey",
    )
    _agile_expected_length(
        key_data["hashSize"],
        key_data["blockSize"],
        "encryption/dataIntegrity",
        encryptedHmacValue,
        "encryptedHmacValue",
    )

    key_encryptors_node = _agile_single_child(
        root, AGILE_ENCRYPTION_NS, "keyEncryptors", "encryption/keyEncryptors"
    )
    password_encryptors = [
        node
        for node in _agile_direct_children(
            key_encryptors_node, AGILE_ENCRYPTION_NS, "keyEncryptor"
        )
        if node.getAttribute("uri") == AGILE_PASSWORD_NS
    ]
    if len(password_encryptors) != 1:
        raise exceptions.DecryptionError(
            "Agile EncryptionInfo must contain exactly one password keyEncryptor "
            "(found {})".format(len(password_encryptors))
        )

    password_path = "encryption/keyEncryptors/keyEncryptor/p:encryptedKey"
    password_node = _agile_single_child(
        password_encryptors[0], AGILE_PASSWORD_NS, "encryptedKey", password_path
    )
    password = _agile_cipher_params(password_node, password_path)

    spinValue = _agile_int_attr(password_node, "spinCount", password_path)
    # [MS-OFFCRYPTO] 2.3.4.10 SpinCount: An unsigned integer that specifies the number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000.
    # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/87020a34-e73f-4139-99bc-bbdf6cf6fa55
    if not 0 <= spinValue <= 10_000_000:
        raise exceptions.DecryptionError("Agile spinCount must be between 0 and 10000000")

    encryptedVerifierHashInput = _agile_b64_attr(
        password_node, "encryptedVerifierHashInput", password_path
    )
    encryptedVerifierHashValue = _agile_b64_attr(
        password_node, "encryptedVerifierHashValue", password_path
    )
    encryptedKeyValue = _agile_b64_attr(
        password_node, "encryptedKeyValue", password_path
    )

    _agile_expected_length(
        password["saltSize"],
        password["blockSize"],
        password_path,
        encryptedVerifierHashInput,
        "encryptedVerifierHashInput",
    )
    _agile_expected_length(
        password["hashSize"],
        password["blockSize"],
        password_path,
        encryptedVerifierHashValue,
        "encryptedVerifierHashValue",
    )
    if password["blockSize"] != key_data["blockSize"]:
        raise exceptions.DecryptionError(
            "Agile keyData and encryptedKey blockSize values do not match"
        )

    # The secret key protected by encryptedKeyValue is the keyData key, not the
    # password-derived key described by the encryptedKey's own keyBits.
    expected_key_value_size = _agile_round_up(
        key_data["keyBits"] // 8, key_data["blockSize"]
    )
    if len(encryptedKeyValue) != expected_key_value_size:
        raise exceptions.DecryptionError(
            "Agile {} encryptedKeyValue has length {}, expected {}".format(
                password_path, len(encryptedKeyValue), expected_key_value_size
            )
        )

    keyDataSalt = key_data["salt"]
    keyDataHashAlgorithm = key_data["hashAlgorithm"]
    keyDataBlockSize = key_data["blockSize"]
    passwordSalt = password["salt"]
    passwordHashAlgorithm = password["hashAlgorithm"]
    passwordKeyBits = password["keyBits"]
    info = {
        "keyDataSalt": keyDataSalt,
        "keyDataHashAlgorithm": keyDataHashAlgorithm,
        "keyDataBlockSize": keyDataBlockSize,
        "encryptedHmacKey": encryptedHmacKey,
        "encryptedHmacValue": encryptedHmacValue,
        "encryptedVerifierHashInput": encryptedVerifierHashInput,
        "encryptedVerifierHashValue": encryptedVerifierHashValue,
        "encryptedKeyValue": encryptedKeyValue,
        "spinValue": spinValue,
        "passwordSalt": passwordSalt,
        "passwordHashAlgorithm": passwordHashAlgorithm,
        "passwordKeyBits": passwordKeyBits,
    }
    return info


def _parseinfo(ole):
    versionMajor, versionMinor = unpack("<HH", ole.read(4))
    if versionMajor == 4 and versionMinor == 4:  # Agile
        return "agile", _parseinfo_agile(ole)
    elif versionMajor in [2, 3, 4] and versionMinor == 2:  # Standard
        return "standard", _parseinfo_standard(ole)
    elif versionMajor in [3, 4] and versionMinor == 3:  # Extensible
        raise exceptions.DecryptionError(
            "Unsupported EncryptionInfo version (Extensible Encryption)"
        )
    raise exceptions.DecryptionError(
        "Unsupported EncryptionInfo version ({}:{})".format(versionMajor, versionMinor)
    )


class OOXMLFile(base.BaseOfficeFile):
    """Return an OOXML file object.

    Examples:
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="Password1234_", verify_password=True)

        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="0000", verify_password=True)
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.InvalidKeyError: ...
    """

    def __init__(self, file):
        self.format = "ooxml"

        file.seek(0)  # TODO: Investigate the effect (required for olefile.isOleFile)

        # olefile cannot process non password protected ooxml files.
        # TODO: this code is duplicate of OfficeFile(). Merge?
        if olefile.isOleFile(file):
            ole = olefile.OleFileIO(file)
            self.file = ole

            try:
                with self.file.openstream("EncryptionInfo") as stream:
                    self.type, self.info = _parseinfo(stream)
            except IOError:
                raise exceptions.FileFormatError(
                    "Supposed to be an encrypted OOXML file, but no EncryptionInfo stream found"
                )

            logger.debug("OOXMLFile.type: {}".format(self.type))

            self.secret_key = None

            if self.type == "agile":
                # TODO: Support aliases?
                self.keyTypes = ("password", "private_key", "secret_key")
            elif self.type == "standard":
                self.keyTypes = ("password", "secret_key")
            elif self.type == "extensible":
                pass
        elif _is_ooxml(file):
            self.type = "plain"
            self.file = file
        else:
            raise exceptions.FileFormatError("Unsupported file format")

    def load_key(
        self, password=None, private_key=None, secret_key=None, verify_password=False
    ):
        """
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")
        """
        if password:
            if self.type == "agile":
                self.secret_key = ECMA376Agile.makekey_from_password(
                    password,
                    self.info["passwordSalt"],
                    self.info["passwordHashAlgorithm"],
                    self.info["encryptedKeyValue"],
                    self.info["spinValue"],
                    self.info["passwordKeyBits"],
                )
                if verify_password:
                    verified = ECMA376Agile.verify_password(
                        password,
                        self.info["passwordSalt"],
                        self.info["passwordHashAlgorithm"],
                        self.info["encryptedVerifierHashInput"],
                        self.info["encryptedVerifierHashValue"],
                        self.info["spinValue"],
                        self.info["passwordKeyBits"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "standard":
                self.secret_key = ECMA376Standard.makekey_from_password(
                    password,
                    self.info["header"]["algId"],
                    self.info["header"]["algIdHash"],
                    self.info["header"]["providerType"],
                    self.info["header"]["keySize"],
                    self.info["verifier"]["saltSize"],
                    self.info["verifier"]["salt"],
                )
                if verify_password:
                    verified = ECMA376Standard.verifykey(
                        self.secret_key,
                        self.info["verifier"]["encryptedVerifier"],
                        self.info["verifier"]["encryptedVerifierHash"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "extensible":
                pass
            elif self.type == "plain":
                pass
        elif private_key:
            if self.type == "agile":
                self.secret_key = ECMA376Agile.makekey_from_privkey(
                    private_key, self.info["encryptedKeyValue"]
                )
            else:
                raise exceptions.DecryptionError(
                    "Unsupported key type for the encryption method"
                )
        elif secret_key:
            self.secret_key = secret_key
        else:
            raise exceptions.DecryptionError("No key specified")

    def decrypt(self, outfile, verify_integrity=False):
        """
        >>> from msoffcrypto import exceptions
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")
        ...     officefile.decrypt(outfile)
        Traceback (most recent call last):
        msoffcrypto.exceptions.DecryptionError: Document is not encrypted
        """
        if self.type == "agile":
            with self.file.openstream("EncryptedPackage") as stream:
                if verify_integrity:
                    verified = ECMA376Agile.verify_integrity(
                        self.secret_key,
                        self.info["keyDataSalt"],
                        self.info["keyDataHashAlgorithm"],
                        self.info["keyDataBlockSize"],
                        self.info["encryptedHmacKey"],
                        self.info["encryptedHmacValue"],
                        stream,
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError(
                            "Payload integrity verification failed"
                        )

                obuf = ECMA376Agile.decrypt(
                    self.secret_key,
                    self.info["keyDataSalt"],
                    self.info["keyDataHashAlgorithm"],
                    stream,
                )
            outfile.write(obuf)
        elif self.type == "standard":
            with self.file.openstream("EncryptedPackage") as stream:
                obuf = ECMA376Standard.decrypt(self.secret_key, stream)
            outfile.write(obuf)
        elif self.type == "plain":
            raise exceptions.DecryptionError("Document is not encrypted")
        else:
            raise exceptions.DecryptionError("Unsupported encryption method")

        # If the file is successfully decrypted, there must be a valid OOXML file, i.e. a valid zip file
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise exceptions.InvalidKeyError(
                "The file could not be decrypted with this password"
            )

    def encrypt(self, password, outfile):
        """
        >>> from msoffcrypto.format.ooxml import OOXMLFile
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/example.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.encrypt("1234", outfile)
        """
        if self.is_encrypted():
            raise exceptions.EncryptionError("File is already encrypted")

        self.file.seek(0)

        buf = ECMA376Agile.encrypt(password, self.file)

        if not olefile.isOleFile(buf):
            raise exceptions.EncryptionError("Unable to encrypt this file")

        outfile.write(buf)

    def is_encrypted(self):
        """
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.is_encrypted()
        True
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.is_encrypted()
        False
        """
        # Heuristic
        if self.type == "plain":
            return False
        elif isinstance(self.file, olefile.OleFileIO):
            return True
        else:
            return False
