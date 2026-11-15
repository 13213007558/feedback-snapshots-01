"""Interface-simulation tests for the LZ4 adaptation layer.

These tests do **not** run a real LZ4 decompressor. They inject a fake ``lz4`` module with
a scripted ``decompress`` to pin down what the adaptation in
:mod:`dissect.archive.tibx.codec` must guarantee regardless of which dissect.util backend
is installed underneath:

- every backend failure type becomes :class:`CorruptArchiveError`;
- a short return value (declared length mismatch) is rejected, never accepted;
- a return longer than declared is rejected;
- the frame walk is what catches trailing bytes when the backend itself does not.

The real end-to-end behaviour of both shipped backends is covered, actually executed, in
``test_codec_backend_parity.py``. Think of this file as testing the seam, not the engine.
"""

from __future__ import annotations

import struct

import pytest

from dissect.archive.tibx import codec
from dissect.archive.tibx.codec import decompress_linked_lz4, lz4_block_decompress
from dissect.archive.tibx.exception import CorruptArchiveError


class FakeLZ4:
    """A stand-in for a dissect.util LZ4 backend with a scripted ``decompress``.

    ``result`` is returned verbatim; ``raises`` is thrown instead. Calls are recorded so a
    test can assert the dictionary and declared size the adaptation passed through.
    """

    def __init__(self, *, result: bytes | None = None, raises: Exception | None = None):
        self._result = result
        self._raises = raises
        self.calls: list[tuple[bytes, int, bytes]] = []

    def decompress(self, src, uncompressed_size=-1, return_bytearray=False, dictionary=None):
        self.calls.append((src, uncompressed_size, bytes(dictionary or b"")))
        if self._raises is not None:
            raise self._raises
        return self._result


def _chain_header(compressed: int, uncompressed: int) -> bytes:
    return struct.pack(">II", compressed, uncompressed)


def test_value_error_from_backend_is_mapped(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Rust backend's native failure mode
    fake = FakeLZ4(raises=ValueError("rust said no"))
    monkeypatch.setattr(codec, "lz4", fake)
    with pytest.raises(CorruptArchiveError, match="rust said no"):
        lz4_block_decompress(b"\x00", 4)


def test_corrupt_data_error_from_backend_is_mapped(monkeypatch: pytest.MonkeyPatch) -> None:
    # The pure-Python backend's native failure mode (not itself a ValueError)
    from dissect.util.exceptions import CorruptDataError

    fake = FakeLZ4(raises=CorruptDataError("python said no"))
    monkeypatch.setattr(codec, "lz4", fake)
    with pytest.raises(CorruptArchiveError, match="python said no"):
        lz4_block_decompress(b"\x00", 4)


def test_short_return_is_rejected_even_if_backend_accepts_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # A lenient backend hands back five bytes for a declared ten: the adaptation must notice
    fake = FakeLZ4(result=b"hello")
    monkeypatch.setattr(codec, "lz4", fake)
    with pytest.raises(CorruptArchiveError, match="declared 10"):
        lz4_block_decompress(b"whatever", 10)


def test_oversized_return_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLZ4(result=b"x" * 11)
    monkeypatch.setattr(codec, "lz4", fake)
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(b"whatever", 10)


def test_exact_length_return_passes_when_frame_ends_at_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    # A real literals-only frame for five bytes: token 0x50 then the five literal bytes
    frame = bytes([0x50]) + b"hello"
    fake = FakeLZ4(result=b"hello")
    monkeypatch.setattr(codec, "lz4", fake)
    assert lz4_block_decompress(frame, 5) == b"hello"


def test_trailing_bytes_caught_by_frame_walk_when_backend_is_lax(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake "succeeds" like the lenient pure-Python backend, ignoring the spare byte;
    # the adaptation's own frame walk must still reject it.
    frame = bytes([0x50]) + b"hello" + b"\x00"
    fake = FakeLZ4(result=b"hello")
    monkeypatch.setattr(codec, "lz4", fake)
    with pytest.raises(CorruptArchiveError, match="trailing"):
        lz4_block_decompress(frame, 5)


def test_dictionary_is_passed_through_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    frame = bytes([0x50]) + b"hello"
    fake = FakeLZ4(result=b"hello")
    monkeypatch.setattr(codec, "lz4", fake)
    lz4_block_decompress(frame, 5, dictionary=b"dict-bytes")
    assert fake.calls == [(frame, 5, b"dict-bytes")]


def test_invalid_size_is_rejected_before_calling_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLZ4(result=b"")
    monkeypatch.setattr(codec, "lz4", fake)
    for bad_size in (0, -1):
        with pytest.raises(CorruptArchiveError):
            lz4_block_decompress(b"x", bad_size)
    assert fake.calls == []  # an unbounded decode must never reach a backend


def test_chain_passes_only_the_dictionary_window(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two blocks; the second must receive at most the last 64 KiB of the first's output.
    first_output = b"a" * (codec.LZ4_MAX_DISTANCE + 100)
    second_output = b"b" * 8
    seen_dictionaries: list[bytes] = []

    def literals_frame(data: bytes) -> bytes:
        length = len(data)
        if length < 15:
            return bytes([length << 4]) + data
        rest = length - 15
        return b"\xf0" + b"\xff" * (rest // 255) + bytes([rest % 255]) + data

    class Scripted:
        def decompress(self, src, uncompressed_size=-1, return_bytearray=False, dictionary=None):
            seen_dictionaries.append(bytes(dictionary or b""))
            return first_output if len(seen_dictionaries) == 1 else second_output

    monkeypatch.setattr(codec, "lz4", Scripted())
    first_frame = literals_frame(first_output)
    second_frame = literals_frame(second_output)
    body = (
        _chain_header(len(first_frame), len(first_output)) + first_frame
        + _chain_header(len(second_frame), len(second_output)) + second_frame
    )
    assert decompress_linked_lz4(body, len(first_output) + len(second_output)) == first_output + second_output
    assert seen_dictionaries[0] == b""  # first block has no prior output
    assert len(seen_dictionaries[1]) == codec.LZ4_MAX_DISTANCE
    assert seen_dictionaries[1] == first_output[-codec.LZ4_MAX_DISTANCE:]


def test_best_effort_chain_exposes_only_confirmed_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    # First block decodes; the scripted second block raises. Best-effort must return just the
    # first block's bytes and must not invent an empty block or continue.
    first = b"prefix"
    first_frame = bytes([len(first) << 4]) + first

    class Flaky:
        def __init__(self) -> None:
            self.attempt = 0

        def decompress(self, src, uncompressed_size=-1, return_bytearray=False, dictionary=None):
            self.attempt += 1
            if self.attempt == 1:
                return first
            raise ValueError("backend failure on block two")

    body = (
        _chain_header(len(first_frame), len(first)) + first_frame
        + _chain_header(8, 16) + b"\xff" * 8
    )
    # Strict mode propagates the failure (a fresh fake so its first call succeeds)
    monkeypatch.setattr(codec, "lz4", Flaky())
    with pytest.raises(CorruptArchiveError):
        decompress_linked_lz4(body, len(first) + 16, strict=True)
    # Best-effort stops at the confirmed prefix
    monkeypatch.setattr(codec, "lz4", Flaky())
    assert decompress_linked_lz4(body, len(first) + 16, strict=False) == first


def test_zero_compressed_header_is_not_an_empty_block(monkeypatch: pytest.MonkeyPatch) -> None:
    # Even in best-effort mode a compressed=0 header must surface as a stop, not decode as empty
    first = b"prefix"
    first_frame = bytes([len(first) << 4]) + first
    fake = FakeLZ4(result=first)
    monkeypatch.setattr(codec, "lz4", fake)
    body = _chain_header(len(first_frame), len(first)) + first_frame + _chain_header(0, 16)
    with pytest.raises(CorruptArchiveError, match="empty payload"):
        decompress_linked_lz4(body, len(first) + 16, strict=True)
    assert decompress_linked_lz4(body, len(first) + 16, strict=False) == first
