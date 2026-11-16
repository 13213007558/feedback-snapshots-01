# Copyright (c) 2026 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fido2 import cbor
from fido2.ctap2 import Info
from fido2.ctap2.blob import LargeBlobs, _compress, _lb_ad, _lb_pack
from fido2.utils import sha256

import fido2.ctap2.blob as blob_module


class FakeCtap2:
    """Minimal stand-in for Ctap2 serving a static largeBlob array."""

    def __init__(self, storage, max_msg_size=1024):
        self.info = Info(
            versions=["FIDO_2_0"],
            options={"largeBlobs": True},
            max_msg_size=max_msg_size,
        )
        self._storage = storage

    def large_blobs(
        self,
        offset,
        get=None,
        set=None,
        length=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
    ):
        assert get is not None
        return {1: self._storage[offset : offset + get]}


def make_lb(entries, max_msg_size=1024):
    data = cbor.encode(entries)
    storage = data + sha256(data)[:16]
    return LargeBlobs(FakeCtap2(storage, max_msg_size))


def pack_entry(key, compressed, orig_size):
    """Encrypts a raw (possibly malformed) payload as a largeBlob entry."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, _lb_ad(orig_size))
    return {1: ciphertext, 2: nonce, 3: orig_size}


@pytest.fixture
def decompress_calls(monkeypatch):
    """Records invocations of the blob decompressor."""
    calls = []
    real = blob_module._decompress

    def spy(data, max_size=None):
        calls.append({"compressed": len(data), "max_size": max_size})
        return real(data, max_size)

    monkeypatch.setattr(blob_module, "_decompress", spy)
    return calls


@pytest.fixture
def zlib_stats(monkeypatch):
    """Records peak temporary output produced inside zlib decompression."""
    stats = {"decompress_objects": 0, "max_output": 0}
    real_decompressobj = zlib.decompressobj

    class Recorder:
        def __init__(self, *args, **kwargs):
            self._inner = real_decompressobj(*args, **kwargs)
            self._produced = 0
            stats["decompress_objects"] += 1

        def _record(self, out):
            self._produced += len(out)
            stats["max_output"] = max(stats["max_output"], self._produced)
            return out

        def decompress(self, data, *args):
            return self._record(self._inner.decompress(data, *args))

        def flush(self, *args):
            return self._record(self._inner.flush(*args))

        @property
        def eof(self):
            return self._inner.eof

        @property
        def unconsumed_tail(self):
            return self._inner.unconsumed_tail

        @property
        def unused_data(self):
            return self._inner.unused_data

    monkeypatch.setattr(zlib, "decompressobj", Recorder)
    return stats


def test_authenticated_target_returns_exact_bytes(decompress_calls):
    key = os.urandom(32)
    data = b"the exact secret payload" * 7
    others = [_lb_pack(os.urandom(32), os.urandom(50)) for _ in range(3)]
    entries = [others[0], _lb_pack(key, data), others[1], others[2]]
    # Small max_msg_size forces the array to be read in multiple fragments
    lb = make_lb(entries, max_msg_size=128)

    assert lb.get_blob(key, max_size=len(data), max_entries=10) == data
    # Only the authenticated target entry reached the decompressor
    assert len(decompress_calls) == 1
    assert decompress_calls[0]["max_size"] == len(data)


def test_max_size_boundary(decompress_calls):
    key = os.urandom(32)
    data = b"boundary data"
    lb = make_lb([_lb_pack(key, data)])

    assert lb.get_blob(key, max_size=len(data)) == data
    with pytest.raises(ValueError, match="exceeds maximum size"):
        lb.get_blob(key, max_size=len(data) - 1)


def test_unauthenticated_data_never_enters_decompressor(decompress_calls):
    entries = [_lb_pack(os.urandom(32), b"not for you") for _ in range(5)]
    lb = make_lb(entries)

    assert lb.get_blob(os.urandom(32), max_size=64) is None
    assert decompress_calls == []


def test_wrong_key_candidates_skipped_target_found(decompress_calls):
    key = os.urandom(32)
    data = b"target"
    entries = [_lb_pack(os.urandom(32), b"decoy") for _ in range(4)]
    entries.append(_lb_pack(key, data))
    lb = make_lb(entries)

    assert lb.get_blob(key, max_size=100) == data
    assert len(decompress_calls) == 1


def test_high_inflation_payload_bounded(zlib_stats):
    key = os.urandom(32)
    # ~4 MB of zeros compresses to a few KB: small payload, huge expansion
    data = b"\0" * 4_000_000
    compressed = _compress(data)
    assert len(compressed) < 10_000
    lb = make_lb([pack_entry(key, compressed, len(data))])

    with pytest.raises(ValueError, match="exceeds maximum size"):
        lb.get_blob(key, max_size=1024)
    # Temporary decompression output never exceeded the budget
    assert zlib_stats["decompress_objects"] == 1
    assert zlib_stats["max_output"] <= 1024 + 1


def test_declared_orig_size_not_used_for_allocation():
    key = os.urandom(32)
    data = b"tiny"
    # Lies about orig_size: claims ~1 TB for a 4 byte payload
    lb = make_lb([pack_entry(key, _compress(data), 2**40)])

    with pytest.raises(ValueError, match="orig_size"):
        lb.get_blob(key, max_size=1024)


def test_orig_size_mismatch_raises():
    key = os.urandom(32)
    data = b"real content"
    lb = make_lb([pack_entry(key, _compress(data), len(data) + 1)])

    with pytest.raises(ValueError, match="orig_size"):
        lb.get_blob(key, max_size=1024)


def test_trailing_compressed_stream_rejected():
    key = os.urandom(32)
    data = b"real content"
    compressed = _compress(data) + _compress(b"trailing stream")
    lb = make_lb([pack_entry(key, compressed, len(data))])

    with pytest.raises(ValueError, match="Trailing data"):
        lb.get_blob(key, max_size=1024)


def test_truncated_stream_raises():
    key = os.urandom(32)
    data = b"some truncated content"
    compressed = _compress(data)[:3]
    lb = make_lb([pack_entry(key, compressed, len(data))])

    with pytest.raises(zlib.error, match="Incomplete"):
        lb.get_blob(key, max_size=1024)


def test_authenticated_bomb_not_masked_as_missing():
    # A resource-limit hit on the target must surface, not become None,
    # even when a later entry for the same key would be valid.
    key = os.urandom(32)
    bomb = pack_entry(key, _compress(b"\0" * 1_000_000), 1_000_000)
    valid = _lb_pack(key, b"valid")
    lb = make_lb([bomb, valid])

    with pytest.raises(ValueError, match="exceeds maximum size"):
        lb.get_blob(key, max_size=100)


def test_max_entries_limit():
    entries = [_lb_pack(os.urandom(32), b"x") for _ in range(4)]
    lb = make_lb(entries)

    with pytest.raises(ValueError, match="Too many candidate entries"):
        lb.get_blob(os.urandom(32), max_entries=2)
    assert lb.get_blob(os.urandom(32), max_entries=4) is None


def test_read_blob_array_size_limit():
    entries = [_lb_pack(os.urandom(32), b"x" * 100) for _ in range(3)]
    lb = make_lb(entries)
    stored_size = len(cbor.encode(entries)) + 16

    assert len(lb.read_blob_array(stored_size)) == 3
    with pytest.raises(ValueError, match="exceeds maximum size"):
        lb.read_blob_array(stored_size - 1)
    with pytest.raises(ValueError, match="exceeds maximum size"):
        lb.get_blob(os.urandom(32), max_array_size=stored_size - 1)


def test_unbounded_read_still_works():
    key = os.urandom(32)
    data = os.urandom(5000)
    lb = make_lb([_lb_pack(key, data)])

    assert lb.get_blob(key) == data
