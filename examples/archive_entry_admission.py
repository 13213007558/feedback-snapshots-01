# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Cross-check: what the archive entry read before handing the stream down.

Run from the repository root::

    .venv/bin/python examples/archive_entry_admission.py

The script uses a local raw AES key provider, so it needs no network.  It
builds one ciphertext and feeds it to ``admit_message_stream`` twice:

* once through a seekable ``BytesIO`` that logs ``read``/``seek`` calls, and
* once through a non-seekable pipe that only ever returns short reads.

Both must show the same number of consumed bytes and no ``seek`` calls.  The
byte count is compared against an independent recomputation of header +
header authentication (+ non-framed preamble) parsed from a fresh copy.
"""
import io
import os

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import CustomMaximumValueExceeded, SerializationError
from aws_encryption_sdk.identifiers import (
    Algorithm,
    CommitmentPolicy,
    EncryptionKeyType,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_header, deserialize_header_auth
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.streaming_admission import AdmissionBudgetExceeded, admit_message_stream

PLAINTEXT = b"archive entry admission payload\n" * 200
FRAME_LENGTH = 1024
ALGORITHM = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
POLICY = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
WRAPPING_KEY = os.urandom(32)


class _StaticConfig(MasterKeyProviderConfig):
    pass


class _StaticRawKeyProvider(RawMasterKeyProvider):
    provider_id = "archive-entry-static"
    _config_class = _StaticConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=WRAPPING_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def provider():
    result = _StaticRawKeyProvider()
    result.add_master_key(b"key-0")
    return result


class RecordingSeekableSource(io.BytesIO):
    def __init__(self, data):
        super(RecordingSeekableSource, self).__init__(data)
        self.reads = []
        self.seeks = []

    def read(self, size=-1):
        data = super(RecordingSeekableSource, self).read(size)
        self.reads.append((size, len(data)))
        return data

    def seek(self, offset, whence=0):
        self.seeks.append((offset, whence))
        return super(RecordingSeekableSource, self).seek(offset, whence)


class RecordingPipe(object):
    """Non-seekable source that returns at most ``chunk`` bytes per read."""

    def __init__(self, data, chunk=7):
        self._buffer = io.BytesIO(data)
        self._chunk = chunk
        self.reads = []

    def read(self, size=-1):
        if size is None or size < 0 or size > self._chunk:
            size = self._chunk
        data = self._buffer.read(size)
        self.reads.append((size, len(data)))
        return data

    def seek(self, *args):
        raise IOError("pipe is not seekable")

    def tell(self):
        raise IOError("pipe is not seekable")

    def seekable(self):
        return False


def consume(source):
    return sum(returned for _, returned in source.reads)


def expected_admission_bytes(ciphertext):
    stream = io.BytesIO(ciphertext)
    header, raw_header = deserialize_header(stream)
    deserialize_header_auth(version=header.version, stream=stream, algorithm=header.algorithm)
    end = stream.tell()
    preamble = header.algorithm.iv_len + 8 if header.frame_length == 0 else 0
    return len(raw_header), end, end + preamble


def main():
    ciphertext, _header = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=POLICY).encrypt(
        source=PLAINTEXT,
        key_provider=provider(),
        algorithm=ALGORITHM,
        frame_length=FRAME_LENGTH,
    )
    raw_header, header_and_auth, admission = expected_admission_bytes(ciphertext)
    print("ciphertext {} bytes; header {}; header+auth {}; admission {}".format(
        len(ciphertext), raw_header, header_and_auth, admission))

    print("\n== read accounting on two independent local sources ==")
    for label, source in (
        ("seekable BytesIO", RecordingSeekableSource(ciphertext)),
        ("non-seekable pipe", RecordingPipe(ciphertext)),
    ):
        result = admit_message_stream(source, key_provider=provider(), commitment_policy=POLICY)
        print("  {:<18} admission consumed {:>4} bytes; source saw {:>4}; seeks={}".format(
            label,
            result.consumed_bytes,
            consume(source),
            len(getattr(source, "seeks", [])),
        ))
        assert result.consumed_bytes == consume(source) == admission
        assert len(getattr(source, "seeks", [])) == 0
        assert result.consumed_bytes >= header_and_auth
        assert result.decryptor.read() == PLAINTEXT
        result.decryptor.close()

    print("\n== rejection example: header-only decision, body untouched ==")
    source = RecordingSeekableSource(ciphertext)
    try:
        admit_message_stream(
            source,
            key_provider=provider(),
            commitment_policy=POLICY,
            max_body_length=FRAME_LENGTH - 1,
        )
    except CustomMaximumValueExceeded as error:
        print("  rejected with {}: {}".format(type(error).__name__, error))
        print("  consumed {} bytes == header body only; header auth and body untouched".format(consume(source)))
        assert consume(source) == raw_header
        assert consume(source) < admission

    print("\n== failure layers ==")
    source = RecordingSeekableSource(ciphertext)
    try:
        admit_message_stream(source, budget_bytes=16, key_provider=provider(), commitment_policy=POLICY)
    except AdmissionBudgetExceeded as error:
        print("  gate layer: {} (input may still have data; not EOF)".format(error))
        assert consume(source) <= 16

    source = RecordingSeekableSource(ciphertext[: admission - 1])
    try:
        admit_message_stream(source, key_provider=provider(), commitment_policy=POLICY)
    except SerializationError as error:
        print("  SDK deserialize layer: {}".format(str(error).splitlines()[0]))
        assert not isinstance(error, AdmissionBudgetExceeded)

    print("\nall cross-checks passed")


if __name__ == "__main__":
    main()
