import io
import logging
from hashlib import sha1
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from msoffcrypto import exceptions

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# [MS-OFFCRYPTO] 2.3.6 EncryptionHeader (Standard Encryption):
# the only algorithm suite permitted for ECMA-376 Standard Encryption is
# AES (ECB) in combination with SHA-1. These rules are specific to the
# Standard Encryption version of the header and must not be confused with
# the parameter negotiation used by Agile Encryption.
STANDARD_ALG_IDS = {
    0x0000660E: 128,  # AES-128
    0x0000660F: 192,  # AES-192
    0x00006610: 256,  # AES-256
}
STANDARD_ALG_ID_HASH = 0x00008004  # SHA-1
STANDARD_PROVIDER_TYPE = 0x00000018  # PROV_RSA_AES
STANDARD_SALT_SIZE = 16  # bytes
STANDARD_ITER_COUNT = 50000


class ECMA376Standard:
    def __init__(self):
        pass

    @staticmethod
    def validate_standard_parameters(algId, algIdHash, providerType, keySize, saltSize, salt):
        r"""
        Validate that an EncryptionHeader/EncryptionVerifier combination is one of
        the suites allowed by [MS-OFFCRYPTO] Standard Encryption.

        Raises DecryptionError on any unsupported or contradictory declaration so
        that a file cannot be decrypted under an algorithm different from the one
        its header advertises.
        """
        if algId not in STANDARD_ALG_IDS:
            raise exceptions.DecryptionError(
                "Unsupported Standard Encryption algId 0x{:08X}".format(algId)
            )
        if algIdHash != STANDARD_ALG_ID_HASH:
            raise exceptions.DecryptionError(
                "Unsupported Standard Encryption algIdHash 0x{:08X}; only SHA-1 (0x{:08X}) is supported".format(
                    algIdHash, STANDARD_ALG_ID_HASH
                )
            )
        if providerType != STANDARD_PROVIDER_TYPE:
            raise exceptions.DecryptionError(
                "Unsupported Standard Encryption providerType 0x{:08X}; only PROV_RSA_AES (0x{:08X}) is supported".format(
                    providerType, STANDARD_PROVIDER_TYPE
                )
            )
        expected_key_size = STANDARD_ALG_IDS[algId]
        if keySize != expected_key_size:
            raise exceptions.DecryptionError(
                "Contradictory Standard Encryption keySize {} for algId 0x{:08X}; expected {}".format(
                    keySize, algId, expected_key_size
                )
            )
        if saltSize != STANDARD_SALT_SIZE:
            raise exceptions.DecryptionError(
                "Unsupported Standard Encryption saltSize {}; expected {} bytes".format(
                    saltSize, STANDARD_SALT_SIZE
                )
            )
        if len(salt) != STANDARD_SALT_SIZE:
            raise exceptions.DecryptionError(
                "Unsupported Standard Encryption salt length {}; expected {} bytes".format(
                    len(salt), STANDARD_SALT_SIZE
                )
            )

    @staticmethod
    def decrypt(key, ibuf):
        r"""
        Return decrypted data.

        """
        obuf = io.BytesIO()
        totalSize = unpack("<I", ibuf.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        ibuf.seek(8)
        aes = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = aes.decryptor()
        x = ibuf.read()
        dec = decryptor.update(x) + decryptor.finalize()
        obuf.write(dec[:totalSize])
        return obuf.getvalue()  # return obuf.getbuffer()

    @staticmethod
    def verifykey(key, encryptedVerifier, encryptedVerifierHash):
        r"""
        Return True if the given intermediate key is valid.

            >>> key = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> encryptedVerifier = b'Qos.\x96o\xac\x17\xb1\xc5\xd7\xd8\xcc6\xc9('
            >>> encryptedVerifierHash = b'+ah\xda\xbe)\x11\xad+\xd3|\x17Ft\\\x14\xd3\xcf\x1b\xb1@\xa4\x8fNo=#\x88\x08r\xb1j'
            >>> ECMA376Standard.verifykey(key, encryptedVerifier, encryptedVerifierHash)
            True
        """
        # TODO: For consistency with Agile, rename method to verify_password or the like
        logger.debug([key, encryptedVerifier, encryptedVerifierHash])
        # https://msdn.microsoft.com/en-us/library/dd926426(v=office.12).aspx
        aes = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = aes.decryptor()
        verifier = decryptor.update(encryptedVerifier)
        expected_hash = sha1(verifier).digest()
        decryptor = aes.decryptor()
        verifierHash = decryptor.update(encryptedVerifierHash)[: sha1().digest_size]
        return expected_hash == verifierHash

    @staticmethod
    def makekey_from_password(
        password, algId, algIdHash, providerType, keySize, saltSize, salt
    ):
        r"""
        Generate intermediate key from given password.

            >>> password = 'Password1234_'
            >>> algId = 0x660e
            >>> algIdHash = 0x8004
            >>> providerType = 0x18
            >>> keySize = 128
            >>> saltSize = 16
            >>> salt = b'\xe8\x82fI\x0c[\xd1\xee\xbd+C\x94\xe3\xf80\xef'
            >>> expected = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> ECMA376Standard.makekey_from_password(password, algId, algIdHash, providerType, keySize, saltSize, salt) == expected
            True
        """
        logger.debug(
            [
                password,
                hex(algId),
                hex(algIdHash),
                hex(providerType),
                keySize,
                saltSize,
                salt,
            ]
        )
        # Reject declarations we cannot honor before deriving anything, so an
        # unsupported algId/hash/provider/key-length can never silently fall
        # back to another algorithm and still produce a working key.
        ECMA376Standard.validate_standard_parameters(
            algId, algIdHash, providerType, keySize, saltSize, salt
        )
        xor_bytes = lambda a, b: bytearray(
            [p ^ q for p, q in zip(bytearray(a), bytearray(b))]
        )  # bytearray() for Python 2 compat.

        # https://msdn.microsoft.com/en-us/library/dd925430(v=office.12).aspx
        ITER_COUNT = STANDARD_ITER_COUNT

        password = password.encode("UTF-16LE")
        h = sha1(salt + password).digest()
        for i in range(ITER_COUNT):
            ibytes = pack("<I", i)
            h = sha1(ibytes + h).digest()
        block = 0
        blockbytes = pack("<I", block)
        hfinal = sha1(h + blockbytes).digest()
        cbRequiredKeyLength = keySize // 8
        cbHash = sha1().digest_size
        buf1 = b"\x36" * 64
        buf1 = xor_bytes(hfinal, buf1[:cbHash]) + buf1[cbHash:]
        x1 = sha1(buf1).digest()
        buf2 = b"\x5c" * 64
        buf2 = xor_bytes(hfinal, buf2[:cbHash]) + buf2[cbHash:]
        x2 = sha1(buf2).digest()  # In spec but unused
        x3 = x1 + x2
        keyDerived = x3[:cbRequiredKeyLength]
        logger.debug(keyDerived)
        return keyDerived
