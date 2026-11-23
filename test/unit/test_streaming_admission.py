# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for aws_encryption_sdk.streaming_admission.

These tests build real ciphertexts with a local raw AES key provider, so the
read accounting below reflects the SDK's actual deserialization calls rather
than mocks.
"""
import io

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import (
    CustomMaximumValueExceeded,
    MaxEncryptedDataKeysExceeded,
    NotSupportedError,
    SerializationError,
)
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
from aws_encryption_sdk.streaming_admission import (
    AdmissionBudgetExceeded,
    AdmissionError,
    AdmissionMeter,
    DEFAULT_ADMISSION_BUDGET_BYTES,
    abandon_admitted_stream,
    admit_message_stream,
)
from aws_encryption_sdk.streaming_client import DecryptorConfig, StreamDecryptor

pytestmark = [pytest.mark.unit, pytest.mark.local]

PLAINTEXT = b"archive entry admission payload\n" * 120
WRAPPING_KEY = b"12345678901234567890123456789012"
COMMITTING_ALGORITHM = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
FRAME_LENGTH = 1024


class StaticRawKeyProvider(RawMasterKeyProvider):
    provider_id = "admission-static"
    _config_class = MasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=WRAPPING_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def build_provider(number_of_keys=1):
    provider = StaticRawKeyProvider()
    for index in range(number_of_keys):
        provider.add_master_key("key-{}".format(index).encode("utf-8"))
    return provider


def encrypt(frame_length, number_of_keys=1):
    ciphertext, header = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    ).encrypt(
        source=PLAINTEXT,
        key_provider=build_provider(number_of_keys),
        algorithm=COMMITTING_ALGORITHM,
        frame_length=frame_length,
        encryption_context={"purpose": "admission-test"},
    )
    return ciphertext, header


def decryptor_kwargs(number_of_keys=1, **overrides):
    kwargs = dict(
        key_provider=build_provider(number_of_keys),
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    kwargs.update(overrides)
    return kwargs


class RecordingSeekableSource(io.BytesIO):
    """Seekable local source recording read/seek calls."""

    def __init__(self, data):
        super(RecordingSeekableSource, self).__init__(data)
        self.reads = []
        self.seeks = []

    def read(self, size=-1):
        position = self.tell()
        data = super(RecordingSeekableSource, self).read(size)
        self.reads.append((position, size, len(data)))
        return data

    def seek(self, offset, whence=0):
        self.seeks.append((offset, whence))
        return super(RecordingSeekableSource, self).seek(offset, whence)

    @property
    def bytes_returned(self):
        return sum(returned for _, _, returned in self.reads)


class RecordingPipe(object):
    """Non-seekable local source that only ever returns short reads."""

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

    @property
    def bytes_returned(self):
        return sum(returned for _, returned in self.reads)


def header_footprint(ciphertext):
    """Ground-truth byte counts for header, header auth, and admission.

    Computed on a fresh copy by replaying exactly what StreamDecryptor parses.
    """
    stream = io.BytesIO(ciphertext)
    header, raw_header = deserialize_header(stream)
    deserialize_header_auth(version=header.version, stream=stream, algorithm=header.algorithm)
    header_and_auth = stream.tell()
    preamble = header.algorithm.iv_len + 8 if header.frame_length == 0 else 0
    return {
        "header": len(raw_header),
        "header_and_auth": header_and_auth,
        "admission": header_and_auth + preamble,
    }


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
def test_construction_consumes_nothing(frame_length):
    ciphertext, _header = encrypt(frame_length)
    source = RecordingSeekableSource(ciphertext)
    meter = AdmissionMeter(source, budget_bytes=DEFAULT_ADMISSION_BUDGET_BYTES)

    StreamDecryptor(source=meter, **decryptor_kwargs())

    assert source.reads == []
    assert meter.reads == []
    assert meter.consumed_bytes == 0
    assert source.seeks == []


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_admission_consumes_exactly_header_and_auth(frame_length, source_factory):
    ciphertext, _header = encrypt(frame_length)
    expected = header_footprint(ciphertext)
    source = source_factory(ciphertext)

    result = admit_message_stream(source, **decryptor_kwargs())

    assert source.bytes_returned == expected["admission"]
    assert result.consumed_bytes == expected["admission"]
    assert result.meter.consumed_bytes == expected["admission"]
    assert sum(returned for _, returned in result.reads) == expected["admission"]
    if source_factory is RecordingSeekableSource:
        assert source.tell() == expected["admission"]
        assert source.seeks == []
    # A framed message must stop before the first body byte; a non-framed
    # message also reads its fixed 20-byte IV + length preamble.
    assert result.consumed_bytes >= expected["header_and_auth"]
    assert result.consumed_bytes - expected["header_and_auth"] in (0, result.header.algorithm.iv_len + 8)


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
def test_two_sources_cross_check_no_readahead(frame_length):
    ciphertext, _header = encrypt(frame_length, number_of_keys=2)
    expected = header_footprint(ciphertext)

    seekable = RecordingSeekableSource(ciphertext)
    pipe = RecordingPipe(ciphertext)
    seekable_result = admit_message_stream(seekable, **decryptor_kwargs(number_of_keys=2))
    pipe_result = admit_message_stream(pipe, **decryptor_kwargs(number_of_keys=2))

    assert seekable.bytes_returned == pipe.bytes_returned == expected["admission"]
    # The meter's log is the SDK's read sequence; the source sees exactly those
    # same requests. A mismatch here would mean the SDK read ahead of the meter.
    assert [returned for _, returned in seekable_result.reads] == [
        returned for _, _, returned in seekable.reads
    ]
    # A pipe may short-read, so compare the byte sequence rather than the
    # requested sizes: the meter never returns more than the source gave.
    assert [returned for _, returned in pipe_result.reads] == [returned for _, returned in pipe.reads]
    assert seekable_result.consumed_bytes == pipe_result.consumed_bytes


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_admitted_output_matches_direct_read(frame_length, source_factory):
    ciphertext, _header = encrypt(frame_length)

    direct = StreamDecryptor(source=io.BytesIO(ciphertext), **decryptor_kwargs())
    direct_output = direct.read()
    direct.close()

    admitted = admit_message_stream(source_factory(ciphertext), **decryptor_kwargs())
    first_chunk = admitted.decryptor.read(17)
    remaining = admitted.decryptor.read()
    admitted.decryptor.close()

    assert first_chunk + remaining == direct_output == PLAINTEXT


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_budget_exceeded_is_gate_layer_and_does_not_read_past_budget(frame_length, source_factory):
    ciphertext, _header = encrypt(frame_length)
    expected = header_footprint(ciphertext)
    budget = expected["admission"] - 1
    source = source_factory(ciphertext)

    with pytest.raises(AdmissionBudgetExceeded) as excinfo:
        admit_message_stream(source, budget_bytes=budget, **decryptor_kwargs())

    error = excinfo.value
    assert isinstance(error, AdmissionError)
    assert source.bytes_returned <= budget
    assert error.consumed_bytes == source.bytes_returned
    # The input was not exhausted; the gate stopped the read.
    assert source.bytes_returned < len(ciphertext)


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
def test_budget_equal_to_admission_footprint_passes(frame_length):
    ciphertext, _header = encrypt(frame_length)
    expected = header_footprint(ciphertext)
    source = RecordingSeekableSource(ciphertext)

    result = admit_message_stream(source, budget_bytes=expected["admission"], **decryptor_kwargs())

    assert result.consumed_bytes == expected["admission"]


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_truncated_input_is_sdk_serialization_error_not_budget_stop(frame_length, source_factory):
    ciphertext, _header = encrypt(frame_length)
    expected = header_footprint(ciphertext)
    source = source_factory(ciphertext[: expected["admission"] - 1])

    with pytest.raises(SerializationError) as excinfo:
        admit_message_stream(source, **decryptor_kwargs())

    assert not isinstance(excinfo.value, AdmissionBudgetExceeded)
    assert not isinstance(excinfo.value, AdmissionError)
    assert excinfo.value.admission_bytes_consumed == source.bytes_returned


@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_rejection_by_frame_size_reads_header_only(source_factory):
    ciphertext, _header = encrypt(FRAME_LENGTH)
    expected = header_footprint(ciphertext)
    source = source_factory(ciphertext)

    with pytest.raises(CustomMaximumValueExceeded):
        admit_message_stream(source, **decryptor_kwargs(max_body_length=FRAME_LENGTH - 1))

    # Rejection happens immediately after the header body, before header auth.
    assert source.bytes_returned == expected["header"]
    assert source.bytes_returned < expected["header_and_auth"]
    assert source.bytes_returned < len(ciphertext)


@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_rejection_by_encrypted_data_key_count_stops_inside_header(source_factory):
    ciphertext, _header = encrypt(FRAME_LENGTH, number_of_keys=2)
    expected = header_footprint(ciphertext)
    source = source_factory(ciphertext)

    with pytest.raises(MaxEncryptedDataKeysExceeded):
        admit_message_stream(source, **decryptor_kwargs(number_of_keys=2, max_encrypted_data_keys=1))

    assert source.bytes_returned < expected["header"]


@pytest.mark.parametrize("source_factory", (RecordingSeekableSource, RecordingPipe))
def test_rejection_by_unknown_version_stops_after_two_bytes(source_factory):
    ciphertext, _header = encrypt(FRAME_LENGTH)
    source = source_factory(b"\x99" + ciphertext[1:])

    with pytest.raises(NotSupportedError):
        admit_message_stream(source, **decryptor_kwargs())

    assert source.bytes_returned == 2


def test_base64_message_rejection_is_two_bytes():
    ciphertext, _header = encrypt(FRAME_LENGTH)
    source = RecordingPipe(b"AY" + ciphertext[2:])

    with pytest.raises(NotSupportedError) as excinfo:
        admit_message_stream(source, **decryptor_kwargs())

    assert "Base64" in str(excinfo.value)
    assert source.bytes_returned == 2


@pytest.mark.parametrize("frame_length", (FRAME_LENGTH, 0))
def test_close_after_admission_without_body_read_is_sdk_state_error(frame_length):
    ciphertext, _header = encrypt(frame_length)
    source = RecordingSeekableSource(ciphertext)
    result = admit_message_stream(source, **decryptor_kwargs())
    consumed_at_admission = source.bytes_returned

    with pytest.raises(SerializationError) as excinfo:
        result.decryptor.close()

    assert "Footer not read" in str(excinfo.value)
    # close() is a state assertion; it does not read from the source.
    assert source.bytes_returned == consumed_at_admission
    assert not result.decryptor.closed


def test_abandon_after_admission_releases_without_reading():
    ciphertext, _header = encrypt(FRAME_LENGTH)
    source = RecordingSeekableSource(ciphertext)
    result = admit_message_stream(source, **decryptor_kwargs())
    consumed_at_admission = source.bytes_returned

    abandon_admitted_stream(result)

    assert result.decryptor.closed
    assert source.bytes_returned == consumed_at_admission
    assert not source.closed


def test_config_object_is_metered_too():
    ciphertext, _header = encrypt(FRAME_LENGTH)
    expected = header_footprint(ciphertext)
    source = RecordingSeekableSource(ciphertext)
    config = DecryptorConfig(
        source=io.BytesIO(b""),
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        key_provider=build_provider(),
    )

    result = admit_message_stream(source, config=config)

    assert source.bytes_returned == expected["admission"] == result.consumed_bytes
    assert result.decryptor.read() == PLAINTEXT


def test_source_argument_cannot_bypass_meter():
    with pytest.raises(TypeError):
        admit_message_stream(io.BytesIO(b""), source=io.BytesIO(b""), **decryptor_kwargs())


def test_meter_blocks_seek_tell_and_unmetered_reads():
    meter = AdmissionMeter(io.BytesIO(b"abcdef"), budget_bytes=3)

    pytest.raises(io.UnsupportedOperation, meter.seek, 0)
    pytest.raises(io.UnsupportedOperation, meter.tell)
    pytest.raises(io.UnsupportedOperation, meter.readline)
    assert meter.seekable() is False

    assert meter.read(3) == b"abc"
    with pytest.raises(AdmissionBudgetExceeded):
        meter.read(1)


def test_meter_rejects_non_binary_source():
    source = io.StringIO("text")
    meter = AdmissionMeter(source, budget_bytes=10)

    with pytest.raises(TypeError):
        meter.read(1)


def test_non_blocking_source_is_not_reported_as_eof():
    class NonBlockingSource(object):
        def read(self, size=-1):
            return None

    meter = AdmissionMeter(NonBlockingSource(), budget_bytes=10)
    with pytest.raises(AdmissionError) as excinfo:
        meter.read(1)
    assert not isinstance(excinfo.value, AdmissionBudgetExceeded)
    assert "end of stream" in str(excinfo.value)


def test_invalid_budget_is_rejected():
    with pytest.raises(ValueError):
        admit_message_stream(io.BytesIO(b""), budget_bytes=-1, **decryptor_kwargs())


def test_source_without_read_is_rejected():
    with pytest.raises(TypeError):
        admit_message_stream(object(), **decryptor_kwargs())
