# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Local demonstration of verified, atomic streaming decryption delivery.

``client.stream(mode="d", ...)`` returns plaintext a frame at a time, before the
message footer signature has necessarily been verified.  A compliance archive
that hands files to an index service wants a stricter boundary: a file should
appear only once the whole message has been verified, and a failed read must not
leave a partial file for consumers to pick up.

``client.decrypt_to_file(...)`` returns a
:class:`aws_encryption_sdk.VerifiedFileDelivery`.  Calling ``commit()`` drains
the message from a non-rewindable source with bounded memory, verifies the whole
message, and atomically publishes the plaintext.  Two records are encrypted from
the same small local file; both are started against the same destination.  The
good record commits exactly once, and the truncated record fails without ever
exposing a temporary file next to the destination.

Everything runs locally with a static raw key; no network or AWS calls are made.

Run it directly::

    python examples/src/verified_delivery/verified_file_delivery_example.py
"""
import io
import os
import secrets
import tempfile

import attr

import aws_encryption_sdk
from aws_encryption_sdk.file_delivery import DeliveryStatus
from aws_encryption_sdk.identifiers import Algorithm, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

# A deliberately small staging budget so a modest archive spills out of memory.
MEMORY_LIMIT = 1024


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    static_key = attr.ib()


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "local-static"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self.config.static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


class OneShotReader(object):
    """A source that only supports reading: it cannot be rewound."""

    def __init__(self, data):
        self._stream = io.BytesIO(data)

    def read(self, size=-1):
        return self._stream.read(size)

    def seekable(self):
        return False


def build_key_provider():
    provider = StaticRawMasterKeyProvider(static_key=secrets.token_bytes(32))
    provider.add_master_key(b"archive-key")
    return provider


def encrypt(client, key_provider, plaintext):
    ciphertext, _header = client.encrypt(
        source=plaintext,
        key_provider=key_provider,
        # A signing suite makes the final-authentication boundary meaningful.
        algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    )
    return ciphertext


def main():
    client = aws_encryption_sdk.EncryptionSDKClient()
    key_provider = build_key_provider()
    plaintext = b"compliance-archive-record\n" * 200

    good_ciphertext = encrypt(client, key_provider, plaintext)
    # The second record is the same plaintext, but its final frame is cut short.
    truncated_ciphertext = encrypt(client, key_provider, plaintext)[:-40]

    with tempfile.TemporaryDirectory() as workdir:
        destination = os.path.join(workdir, "record.bin")

        good = client.decrypt_to_file(
            source=OneShotReader(good_ciphertext),
            destination=destination,
            key_provider=key_provider,
            staging_memory_limit=MEMORY_LIMIT,
        )
        bad = client.decrypt_to_file(
            source=OneShotReader(truncated_ciphertext),
            destination=destination,
            key_provider=key_provider,
            staging_memory_limit=MEMORY_LIMIT,
        )

        # Neither delivery has published anything yet.
        print("before commit, destination directory:", sorted(os.listdir(workdir)))

        good_result = good.commit()
        print("good delivery:", good_result.status, good_result.bytes_written, "bytes")
        print("destination directory after good commit:", sorted(os.listdir(workdir)))

        try:
            bad.commit()
        except Exception as error:  # noqa: BLE001 - demonstration only
            print("bad delivery failed:", type(error).__name__)

        print("bad delivery status:", bad.status)
        print("destination directory after bad failure:", sorted(os.listdir(workdir)))

        assert good_result.status is DeliveryStatus.COMMITTED
        assert bad.status is DeliveryStatus.FAILED
        assert sorted(os.listdir(workdir)) == ["record.bin"]
        with open(destination, "rb") as delivered:
            assert delivered.read() == plaintext

        # An intentional early stop is reported distinctly from a complete commit.
        aborted = client.decrypt_to_file(
            source=OneShotReader(good_ciphertext),
            destination=os.path.join(workdir, "other.bin"),
            key_provider=key_provider,
        )
        aborted.close()
        print("aborted delivery status:", aborted.status)

        # The original streaming API still serves callers that read incrementally.
        with client.stream(mode="d", source=good_ciphertext, key_provider=key_provider) as decryptor:
            assert decryptor.read() == plaintext
        print("existing stream() decrypt entry point still works")


if __name__ == "__main__":
    main()
