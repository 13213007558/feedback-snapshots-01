"""Reproduction / demonstration for APFS object interpretation selection.

Covers four cases against dissect.apfs.objects.Object.from_block:
  1. legitimate plaintext object (physical OMAP)
  2. legitimate encrypted object (XTS-encrypted virtual btree node)
  3. an unverifiable block (random bytes, wrong key)
  4. the counterexample: ciphertext whose first 32 bytes happen to look like a
     valid obj_phys header (known o_type + storage class + oid)
"""

import os

from dissect.fve.crypto import create_cipher

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import InvalidObjectError
from dissect.apfs.objects import BTreeNode, Object, ObjectMap
from dissect.apfs.util import fletcher64

BLOCK_SIZE = c_apfs.NX_DEFAULT_BLOCK_SIZE
ADDRESS = 0x42
SPB = BLOCK_SIZE // 512
KEY = b"A" * 32


class FakeContainer:
    """Minimal container standing in for dissect.apfs.APFS in from_block."""

    block_size = BLOCK_SIZE

    @property
    def sectors_per_block(self):
        return self.block_size // 512


def make_block(o_type, o_oid, o_xid=1, subtype=0, fill=b"payload-payload-"):
    block = bytearray((fill * (BLOCK_SIZE // len(fill) + 1))[:BLOCK_SIZE])
    block[8:16] = o_oid.to_bytes(8, "little")
    block[16:24] = o_xid.to_bytes(8, "little")
    block[24:28] = o_type.to_bytes(4, "little")
    block[28:32] = subtype.to_bytes(4, "little")
    cksum = fletcher64(bytes(block[8:]))
    block[0:8] = cksum.to_bytes(8, "little")
    return bytes(block)


def header(block):
    h = c_apfs.obj_phys(block)
    return f"o_type={h.o_type:#010x} o_oid={h.o_oid} o_xid={h.o_xid}"


container = FakeContainer()
cipher = create_cipher("aes-xts-128", KEY)
wrong_cipher = create_cipher("aes-xts-128", b"B" * 32)

print("=" * 78)
print("Case 1: legitimate PLAINTEXT physical object")
plain = make_block(c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_OMAP, ADDRESS)
obj = ObjectMap.from_block(container, ADDRESS, plain)
print("  loaded:", repr(obj))
print("  is_valid:", obj.is_valid(), "| is_physical:", obj.is_physical, "| oid==address:", obj.oid == ADDRESS)

print("=" * 78)
print("Case 2: legitimate ENCRYPTED object (virtual btree node, OBJ_ENCRYPTED set)")
enc_type = c_apfs.OBJ_ENCRYPTED | c_apfs.OBJECT_TYPE_BTREE_NODE
decrypted_plain = make_block(enc_type, o_oid=1028)
ciphertext = cipher.encrypt(decrypted_plain, ADDRESS * SPB)
print(
    "  raw ciphertext header:",
    header(ciphertext),
    "-> low16 known?",
    (c_apfs.obj_phys(ciphertext).o_type & 0xFFFF) in c_apfs.OBJECT_TYPE,
)
obj = BTreeNode.from_block(container, ADDRESS, ciphertext, cipher=cipher)
print("  loaded:", repr(obj))
print("  is_encrypted:", obj.is_encrypted, "| is_virtual:", obj.is_virtual, "| is_valid:", obj.is_valid())

print("=" * 78)
print("Case 3: UNVERIFIABLE block (random bytes; wrong key cannot rescue it)")
random_block = os.urandom(BLOCK_SIZE)
try:
    Object.from_block(container, ADDRESS, random_block, cipher=wrong_cipher)
except InvalidObjectError as e:
    print("  raised InvalidObjectError at interpretation stage:")
    print("   ", str(e).replace(": ", ":\n     ", 1))

print("=" * 78)
print("Case 4 (counterexample): ciphertext that *looks* like a valid header")
# Build a header that any type-only heuristic accepts: known btree-node type, a
# plausible storage class, and an oid matching the block address. The checksum is
# left untouched, so the block is still really ciphertext (no valid checksum).
spoof = bytearray(ciphertext)
spoof[8:16] = ADDRESS.to_bytes(8, "little")
spoof[24:28] = (c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_BTREE_NODE).to_bytes(4, "little")
spoof = bytes(spoof)
h = c_apfs.obj_phys(spoof)
print("  spoofed raw header:", header(spoof))
print(
    "  old heuristic would see known type:",
    (h.o_type & c_apfs.OBJECT_TYPE_MASK) in c_apfs.OBJECT_TYPE,
    "and therefore SKIP decryption, then parse garbage deep fields",
)
try:
    BTreeNode.from_block(container, ADDRESS, spoof, cipher=cipher)
except InvalidObjectError as e:
    print("  fixed loader raised InvalidObjectError:")
    print("   ", str(e).replace(": ", ":\n     ", 1))

# Demonstrate the old behaviour directly, to make the contrast reproducible.
print("-" * 78)
print("  Simulating the OLD type-only decision on the spoofed block:")
old_would_decrypt = not (h.o_type in c_apfs.OBJECT_TYPE or h.o_type & c_apfs.OBJECT_TYPE_MASK in c_apfs.OBJECT_TYPE)
print(
    "  old code decides 'needs decryption'? ->",
    old_would_decrypt,
    "(False means it parses the ciphertext as a plaintext node)",
)
