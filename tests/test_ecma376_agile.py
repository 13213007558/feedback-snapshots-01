"""Agile encryption with a hash shorter than the AES block-padded values (SHA1)."""

import io
import unittest
from os.path import dirname, join
from xml.dom.minidom import parseString

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.ooxml import OOXMLFile
from msoffcrypto.method.ecma376_agile import ECMA376Agile

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


if __name__ == "__main__":
    unittest.main()


AGILE_ENCRYPTION_NS = "http://schemas.microsoft.com/office/2006/encryption"
AGILE_PASSWORD_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
FOREIGN_NS = "urn:example:not-an-ooxml-encryption-namespace"


def _direct_children(parent, namespace, local_name):
    return [
        child
        for child in parent.childNodes
        if child.nodeType == child.ELEMENT_NODE
        and child.namespaceURI == namespace
        and child.localName == local_name
    ]


def _single_child(parent, namespace, local_name):
    children = _direct_children(parent, namespace, local_name)
    assert len(children) == 1, (namespace, local_name, len(children))
    return children[0]


class AgileDescriptorValidationTest(unittest.TestCase):
    """Validate that Agile EncryptionInfo XML is assembled from related nodes only."""

    SOURCE = join(DATA_DIR, "example_password.xlsx")

    def _encryption_parts(self, source=None):
        import olefile

        source = source or self.SOURCE
        with open(source, "rb") as f:
            ole = olefile.OleFileIO(f)
            info = ole.openstream("EncryptionInfo").read()
            package = ole.openstream("EncryptedPackage").read()
            ole.close()
        return info[:8], info[8:], package

    def _ole_from_descriptor(self, mutate, source=None):
        from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted

        header, xml, package = self._encryption_parts(source)
        doc = parseString(xml)
        mutate(doc, doc.documentElement)
        outfile = io.BytesIO()
        ECMA376Encrypted(package, header + doc.toxml().encode("utf-8")).write_to(
            outfile
        )
        outfile.seek(0)
        return outfile

    def _assert_rejected(self, mutate, message, source=None):
        from unittest import mock

        outfile = self._ole_from_descriptor(mutate, source)
        with mock.patch.object(
            ECMA376Agile, "_derive_iterated_hash_from_password"
        ) as derive:
            with self.assertRaisesRegex(exceptions.DecryptionError, message):
                OOXMLFile(outfile)
            derive.assert_not_called()

    def _duplicate(self, doc, parent, namespace, local_name):
        node = _single_child(parent, namespace, local_name)
        parent.insertBefore(node.cloneNode(deep=True), node)

    def test_duplicate_key_data_rejected(self):
        def mutate(doc, root):
            self._duplicate(doc, root, AGILE_ENCRYPTION_NS, "keyData")

        self._assert_rejected(mutate, "exactly one encryption/keyData")

    def test_duplicate_data_integrity_rejected(self):
        def mutate(doc, root):
            self._duplicate(doc, root, AGILE_ENCRYPTION_NS, "dataIntegrity")

        self._assert_rejected(mutate, "exactly one encryption/dataIntegrity")

    def test_duplicate_password_encrypted_key_rejected(self):
        def mutate(doc, root):
            encryptors = _single_child(
                root, AGILE_ENCRYPTION_NS, "keyEncryptors"
            )
            password_encryptor = _single_child(
                encryptors, AGILE_ENCRYPTION_NS, "keyEncryptor"
            )
            password_node = _single_child(
                password_encryptor, AGILE_PASSWORD_NS, "encryptedKey"
            )
            password_encryptor.insertBefore(
                password_node.cloneNode(deep=True), password_node
            )

        self._assert_rejected(mutate, "exactly one.*encryptedKey")

    def test_duplicate_password_key_encryptor_rejected(self):
        def mutate(doc, root):
            encryptors = _single_child(
                root, AGILE_ENCRYPTION_NS, "keyEncryptors"
            )
            encryptor = _single_child(
                encryptors, AGILE_ENCRYPTION_NS, "keyEncryptor"
            )
            encryptors.insertBefore(encryptor.cloneNode(deep=True), encryptor)

        self._assert_rejected(mutate, "exactly one password keyEncryptor")

    def test_wrong_namespace_key_data_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            foreign = doc.createElementNS(FOREIGN_NS, "x:keyData")
            self._copy_attributes(key_data, foreign)
            foreign.setAttribute("xmlns:x", FOREIGN_NS)
            root.replaceChild(foreign, key_data)

        self._assert_rejected(mutate, "exactly one encryption/keyData")

    def test_wrong_namespace_key_encryptor_uri_rejected(self):
        def mutate(doc, root):
            encryptors = _single_child(
                root, AGILE_ENCRYPTION_NS, "keyEncryptors"
            )
            encryptor = _single_child(
                encryptors, AGILE_ENCRYPTION_NS, "keyEncryptor"
            )
            foreign = doc.createElementNS(FOREIGN_NS, "x:keyEncryptor")
            self._copy_attributes(encryptor, foreign)
            foreign.setAttribute("xmlns:x", FOREIGN_NS)
            for child in list(encryptor.childNodes):
                foreign.appendChild(child)
            encryptors.replaceChild(foreign, encryptor)

        self._assert_rejected(mutate, "exactly one password keyEncryptor")

    def test_wrong_namespace_password_node_rejected(self):
        def mutate(doc, root):
            encryptors = _single_child(
                root, AGILE_ENCRYPTION_NS, "keyEncryptors"
            )
            password_encryptor = _single_child(
                encryptors, AGILE_ENCRYPTION_NS, "keyEncryptor"
            )
            password_node = _single_child(
                password_encryptor, AGILE_PASSWORD_NS, "encryptedKey"
            )
            foreign = doc.createElementNS(FOREIGN_NS, "x:encryptedKey")
            self._copy_attributes(password_node, foreign)
            foreign.setAttribute("xmlns:x", FOREIGN_NS)
            password_encryptor.replaceChild(foreign, password_node)

        self._assert_rejected(mutate, "exactly one.*encryptedKey")

    def test_salt_value_length_mismatch_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("saltValue", "AAAAAAAAAAA=")

        self._assert_rejected(mutate, "saltValue has length 8, expected 16")

    def test_declared_salt_size_mismatch_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("saltSize", "8")

        self._assert_rejected(mutate, "saltSize 8 does not match blockSize 16")

    def test_block_size_mismatch_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("blockSize", "8")

        self._assert_rejected(mutate, "blockSize must be 16 for AES")

    def test_hash_size_mismatch_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("hashSize", "32")

        self._assert_rejected(mutate, "hashSize 32 does not match SHA512")

    def test_unknown_hash_algorithm_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("hashAlgorithm", "MD5")

        self._assert_rejected(mutate, "Unsupported Agile hash algorithm 'MD5'")

    def test_unknown_cipher_algorithm_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("cipherAlgorithm", "3DES")

        self._assert_rejected(mutate, "Unsupported Agile cipher algorithm '3DES'")

    def test_unknown_chaining_mode_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("cipherChaining", "ChainingModeCFB")

        self._assert_rejected(mutate, "Unsupported Agile cipher chaining")

    def test_key_bits_and_encrypted_key_value_conflict_rejected(self):
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            key_data.setAttribute("keyBits", "128")

        self._assert_rejected(
            mutate, "encryptedKeyValue has length 32, expected 16"
        )

    def test_integrity_ciphertext_length_mismatch_rejected(self):
        def mutate(doc, root):
            integrity = _single_child(
                root, AGILE_ENCRYPTION_NS, "dataIntegrity"
            )
            integrity.setAttribute("encryptedHmacValue", "AA==")

        self._assert_rejected(
            mutate, "encryptedHmacValue has length 1, expected 64"
        )

    def test_verifier_hash_input_length_mismatch_rejected(self):
        def mutate(doc, root):
            encryptors = _single_child(
                root, AGILE_ENCRYPTION_NS, "keyEncryptors"
            )
            password_encryptor = _single_child(
                encryptors, AGILE_ENCRYPTION_NS, "keyEncryptor"
            )
            password_node = _single_child(
                password_encryptor, AGILE_PASSWORD_NS, "encryptedKey"
            )
            password_node.setAttribute("encryptedVerifierHashInput", "AA==")

        self._assert_rejected(
            mutate, "encryptedVerifierHashInput has length 1, expected 16"
        )

    def _assert_valid(self, mutate):
        outfile = self._ole_from_descriptor(mutate)
        ofile = OOXMLFile(outfile)
        ofile.load_key(password=PASSWORD, verify_password=True)
        out = io.BytesIO()
        ofile.decrypt(out, verify_integrity=True)

        with open(join(OUTPUT_DIR, "example.xlsx"), "rb") as expected:
            self.assertEqual(out.getvalue(), expected.read())

    def _copy_attributes(self, source, target):
        for i in range(source.attributes.length):
            attr = source.attributes.item(i)
            target.setAttribute(attr.name, attr.value)

    def test_foreign_namespace_decoys_ignored(self):
        """Same-name nodes in another namespace must not replace the real ones."""
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            decoy_key_data = doc.createElementNS(FOREIGN_NS, "x:keyData")
            self._copy_attributes(key_data, decoy_key_data)
            decoy_key_data.setAttribute("saltValue", "AAAAAAAAAAA=")
            decoy_key_data.setAttribute("xmlns:x", FOREIGN_NS)
            root.insertBefore(decoy_key_data, root.firstChild)

            integrity = _single_child(root, AGILE_ENCRYPTION_NS, "dataIntegrity")
            decoy_integrity = doc.createElementNS(FOREIGN_NS, "x:dataIntegrity")
            self._copy_attributes(integrity, decoy_integrity)
            decoy_integrity.setAttribute("encryptedHmacValue", "AA==")
            decoy_integrity.setAttribute("xmlns:x", FOREIGN_NS)
            root.insertBefore(decoy_integrity, root.firstChild)

        self._assert_valid(mutate)

    def test_nested_decoy_key_data_ignored(self):
        """Only direct encryption/keyData children are part of the config."""
        def mutate(doc, root):
            key_data = _single_child(root, AGILE_ENCRYPTION_NS, "keyData")
            wrapper = doc.createElementNS(AGILE_ENCRYPTION_NS, "decoy")
            decoy = doc.createElementNS(AGILE_ENCRYPTION_NS, "keyData")
            self._copy_attributes(key_data, decoy)
            decoy.setAttribute("hashAlgorithm", "MD5")
            wrapper.appendChild(decoy)
            root.insertBefore(wrapper, root.firstChild)

        self._assert_valid(mutate)

    def test_prefixed_descriptor_still_decrypts(self):
        """Changing legal namespace prefixes must not change descriptor meaning."""
        from xml.dom.minidom import Document

        def clone(node, parent, new_doc):
            if node.nodeType == node.ELEMENT_NODE:
                prefix = "pw" if node.namespaceURI == AGILE_PASSWORD_NS else "enc"
                new = new_doc.createElementNS(
                    node.namespaceURI, prefix + ":" + node.localName
                )
                for i in range(node.attributes.length):
                    attr = node.attributes.item(i)
                    if attr.name.startswith("xmlns"):
                        continue
                    new.setAttribute(attr.name, attr.value)
                parent.appendChild(new)
                for child in node.childNodes:
                    clone(child, new, new_doc)
            elif node.nodeType in (node.TEXT_NODE, node.CDATA_SECTION_NODE):
                parent.appendChild(new_doc.createTextNode(node.data))

        def mutate(doc, root):
            new_doc = Document()
            new_root = new_doc.createElementNS(
                AGILE_ENCRYPTION_NS, "enc:encryption"
            )
            new_root.setAttribute("xmlns:enc", AGILE_ENCRYPTION_NS)
            new_root.setAttribute("xmlns:pw", AGILE_PASSWORD_NS)
            new_doc.appendChild(new_root)
            for child in root.childNodes:
                clone(child, new_root, new_doc)
            doc.removeChild(root)
            doc.appendChild(new_root)

        outfile = self._ole_from_descriptor(mutate)
        ofile = OOXMLFile(outfile)
        ofile.load_key(password=PASSWORD, verify_password=True)
        out = io.BytesIO()
        ofile.decrypt(out, verify_integrity=True)

        with open(join(OUTPUT_DIR, "example.xlsx"), "rb") as expected:
            self.assertEqual(out.getvalue(), expected.read())
