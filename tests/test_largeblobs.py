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
import unittest

from fido2 import cbor
from fido2.ctap2 import Info
from fido2.ctap2.blob import LargeBlobs
from fido2.utils import sha256


class FakeCtap2:
    """Minimal CTAP2 large-blobs device emulation, counting write commands."""

    def __init__(self, storage=b""):
        self.info = Info(
            versions=["FIDO_2_1"],
            options={"largeBlobs": True},
            max_msg_size=1024,
            max_large_blob=1024,
        )
        self.storage = storage
        self.write_count = 0
        self._pending = bytearray()

    def large_blobs(
        self,
        offset,
        get=None,
        set=None,
        length=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
    ):
        if set is not None:
            self.write_count += 1
            if offset == 0:
                self._pending = bytearray(length)
            self._pending[offset : offset + len(set)] = set
            if offset + len(set) == len(self._pending):
                self.storage = bytes(self._pending)
            return {}
        return {1: self.storage[offset : offset + get]}


def get_lb(ctap):
    return LargeBlobs(ctap)


def store_raw(ctap, decoded):
    """Crafts raw storage holding the given CBOR value, with valid checksum."""
    data = cbor.encode(decoded)
    ctap.storage = data + sha256(data)[:16]


class TestLargeBlobs(unittest.TestCase):
    def test_empty_store(self):
        ctap = FakeCtap2()
        lb = get_lb(ctap)

        self.assertEqual(lb.read_blob_array(), [])
        self.assertIsNone(lb.get_blob(os.urandom(32)))

        # Deleting a non-existing entry is a no-op: no write commands
        lb.delete_blob(os.urandom(32))
        self.assertEqual(ctap.write_count, 0)

    def test_corrupted_checksum_no_write(self):
        ctap = FakeCtap2()
        lb = get_lb(ctap)
        key1, key2 = os.urandom(32), os.urandom(32)
        lb.put_blob(key1, b"data one")
        lb.put_blob(key2, b"data two")
        self.assertEqual(ctap.write_count, 2)

        # Corrupt the trailing checksum byte of the stored array
        storage = bytearray(ctap.storage)
        storage[-1] ^= 0xFF
        ctap.storage = bytes(storage)

        # The lenient compat read still behaves as before
        self.assertEqual(lb.read_blob_array(), [])

        # Writes must refuse to touch the corrupted array
        with self.assertRaises(ValueError):
            lb.put_blob(os.urandom(32), b"new data")
        with self.assertRaises(ValueError):
            lb.put_blob(key1, b"updated")
        with self.assertRaises(ValueError):
            lb.delete_blob(key1)
        self.assertEqual(ctap.write_count, 2)

        # The corrupted array is left untouched, not "repaired" to empty
        self.assertEqual(ctap.storage, bytes(storage))

    def test_non_array_no_write(self):
        ctap = FakeCtap2()
        lb = get_lb(ctap)

        # Valid checksum, but the top-level CBOR value is not an array
        store_raw(ctap, {1: b"not an array"})

        with self.assertRaises(ValueError):
            lb.put_blob(os.urandom(32), b"new data")
        with self.assertRaises(ValueError):
            lb.delete_blob(os.urandom(32))
        self.assertEqual(ctap.write_count, 0)

    def test_mixed_entries_read_modify_write(self):
        ctap = FakeCtap2()
        lb = get_lb(ctap)
        key1, key2, key3 = os.urandom(32), os.urandom(32), os.urandom(32)

        lb.put_blob(key1, b"data one")
        lb.put_blob(key2, b"data two")

        # Inject an entry in an unsupported format, directly into the array
        unsupported = {4: b"unsupported entry format"}
        store_raw(ctap, [*lb.read_blob_array(), unsupported])
        ctap.write_count = 0

        # Updating one entry rewrites the array in a single write command
        lb.put_blob(key1, b"updated one")
        self.assertEqual(ctap.write_count, 1)

        # The updated entry holds the new data...
        self.assertEqual(lb.get_blob(key1), b"updated one")
        # ...other entries still decrypt with their original keys...
        self.assertEqual(lb.get_blob(key2), b"data two")
        # ...and the unsupported entry is preserved as-is
        self.assertIn(unsupported, lb.read_blob_array())

        # Deleting a non-existing entry is a no-op: no write commands
        lb.delete_blob(key3)
        self.assertEqual(ctap.write_count, 1)

        # Deleting an existing entry only removes that entry
        lb.delete_blob(key1)
        self.assertEqual(ctap.write_count, 2)
        self.assertIsNone(lb.get_blob(key1))
        self.assertEqual(lb.get_blob(key2), b"data two")
        self.assertIn(unsupported, lb.read_blob_array())


if __name__ == "__main__":
    unittest.main()
