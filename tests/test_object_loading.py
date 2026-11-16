from __future__ import annotations

import os

import pytest
from dissect.fve.crypto import create_cipher

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import InvalidObjectError
from dissect.apfs.objects import BTreeNode, Object, ObjectMap
from dissect.apfs.util import fletcher64

BLOCK_SIZE = c_apfs.NX_DEFAULT_BLOCK_SIZE
ADDRESS = 0x42
SECTORS_PER_BLOCK = BLOCK_SIZE // 512


class FakeContainer:
    """Minimal container standing in for :class:`dissect.apfs.APFS`."""

    block_size = BLOCK_SIZE

    @property
    def sectors_per_block(self) -> int:
        return self.block_size // 512


def make_block(o_type: int, o_oid: int, *, o_xid: int = 1, subtype: int = 0) -> bytes:
    """Build a block with a valid Fletcher checksum for the given object header."""
    block = bytearray(b"payload" * (BLOCK_SIZE // 7 + 1))[:BLOCK_SIZE]
    block[8:16] = o_oid.to_bytes(8, "little")
    block[16:24] = o_xid.to_bytes(8, "little")
    block[24:28] = o_type.to_bytes(4, "little")
    block[28:32] = subtype.to_bytes(4, "little")
    block[0:8] = fletcher64(bytes(block[8:])).to_bytes(8, "little")
    return bytes(block)


@pytest.fixture
def container() -> FakeContainer:
    return FakeContainer()


@pytest.fixture
def cipher():
    return create_cipher("aes-xts-128", b"A" * 32)


@pytest.fixture
def wrong_cipher():
    return create_cipher("aes-xts-128", b"B" * 32)


def test_legitimate_plaintext_object(container: FakeContainer) -> None:
    """A valid plaintext physical object loads without any decryption context."""
    block = make_block(c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_OMAP, ADDRESS)

    obj = ObjectMap.from_block(container, ADDRESS, block)

    assert isinstance(obj, ObjectMap)
    assert obj.is_valid()
    assert obj.is_physical
    assert obj.oid == ADDRESS


def test_legitimate_encrypted_object(container: FakeContainer, cipher) -> None:
    """A real encrypted block is decrypted and validated when a cipher is supplied."""
    plain = make_block(c_apfs.OBJ_ENCRYPTED | c_apfs.OBJECT_TYPE_BTREE_NODE, o_oid=1028)
    ciphertext = cipher.encrypt(plain, ADDRESS * SECTORS_PER_BLOCK)

    # The raw ciphertext does not look like a known object type.
    assert (c_apfs.obj_phys(ciphertext).o_type & c_apfs.OBJECT_TYPE_MASK) not in c_apfs.OBJECT_TYPE

    obj = BTreeNode.from_block(container, ADDRESS, ciphertext, cipher=cipher)

    assert isinstance(obj, BTreeNode)
    assert obj.is_valid()
    assert obj.is_encrypted
    assert obj.is_virtual
    assert obj.oid == 1028


def test_already_decrypted_block_is_not_redecrypted(container: FakeContainer, cipher) -> None:
    """Plaintext that validates is preferred even when a cipher is in scope."""
    block = make_block(c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_OMAP, ADDRESS)

    obj = ObjectMap.from_block(container, ADDRESS, block, cipher=cipher)

    assert isinstance(obj, ObjectMap)
    assert obj.is_valid()
    assert obj.oid == ADDRESS


def test_unverifiable_block_with_wrong_key(container: FakeContainer, wrong_cipher) -> None:
    """Neither interpretation validating raises at the interpretation stage, not deep in field parsing."""
    block = os.urandom(BLOCK_SIZE)

    with pytest.raises(InvalidObjectError) as exc:
        Object.from_block(container, ADDRESS, block, cipher=wrong_cipher)

    message = str(exc.value)
    assert "plaintext interpretation rejected" in message
    assert "decrypted interpretation rejected" in message


def test_spoofed_ciphertext_header_is_rejected(container: FakeContainer, cipher) -> None:
    """Ciphertext whose header is forged to look like a known type is still rejected.

    The spoofed header carries a known btree-node type and a physical oid matching the block
    address, so a type-only heuristic skips decryption; the missing checksum must still reject it.
    """
    plain = make_block(c_apfs.OBJ_ENCRYPTED | c_apfs.OBJECT_TYPE_BTREE_NODE, o_oid=1028)
    ciphertext = bytearray(cipher.encrypt(plain, ADDRESS * SECTORS_PER_BLOCK))
    ciphertext[8:16] = ADDRESS.to_bytes(8, "little")
    ciphertext[24:28] = (c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_BTREE_NODE).to_bytes(4, "little")
    spoofed = bytes(ciphertext)

    # The forged header passes the legacy "does the type look known" heuristic.
    spoofed_type = c_apfs.obj_phys(spoofed).o_type
    assert (spoofed_type & c_apfs.OBJECT_TYPE_MASK) in c_apfs.OBJECT_TYPE

    with pytest.raises(InvalidObjectError, match="plaintext interpretation rejected .*checksum"):
        BTreeNode.from_block(container, ADDRESS, spoofed, cipher=cipher)


def test_physical_oid_address_mismatch_is_rejected(container: FakeContainer, cipher) -> None:
    """A physical object whose oid does not match its block address fails identity validation."""
    block = make_block(c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_OMAP, o_oid=ADDRESS + 1)
    ciphertext = cipher.encrypt(block, ADDRESS * SECTORS_PER_BLOCK)

    with pytest.raises(InvalidObjectError, match="does not match block address"):
        ObjectMap.from_block(container, ADDRESS, ciphertext, cipher=cipher)


def test_undefined_storage_class_is_rejected(container: FakeContainer, cipher) -> None:
    """A header with an invalid storage class cannot be accepted as an object."""
    block = make_block(c_apfs.OBJECT_TYPE_OMAP, ADDRESS)
    # Force both storage bits (0xc0000000), which is not a valid storage class.
    corrupt = bytearray(block)
    corrupt[24:28] = (0xC0000000 | c_apfs.OBJECT_TYPE_OMAP).to_bytes(4, "little")
    corrupt[0:8] = fletcher64(bytes(corrupt[8:])).to_bytes(8, "little")
    ciphertext = cipher.encrypt(bytes(corrupt), ADDRESS * SECTORS_PER_BLOCK)

    with pytest.raises(InvalidObjectError, match="invalid storage class"):
        ObjectMap.from_block(container, ADDRESS, ciphertext, cipher=cipher)


def test_unexpected_type_for_concrete_loader(container: FakeContainer, cipher) -> None:
    """A concrete loader rejects a block whose object type does not match the expected one."""
    block = make_block(c_apfs.OBJ_PHYSICAL | c_apfs.OBJECT_TYPE_SPACEMAN, ADDRESS)
    ciphertext = cipher.encrypt(block, ADDRESS * SECTORS_PER_BLOCK)

    with pytest.raises(InvalidObjectError, match="unexpected object type"):
        ObjectMap.from_block(container, ADDRESS, ciphertext, cipher=cipher)


def test_no_cipher_keeps_permissive_plaintext_loading(container: FakeContainer) -> None:
    """Without a decryption context, generic loading stays permissive for backward compatibility."""
    # An unknown type still resolves to the generic Object class when no cipher is involved.
    block = bytearray(BLOCK_SIZE)
    block[24:28] = (0xABCD).to_bytes(4, "little")

    obj = Object.from_block(container, ADDRESS, bytes(block))

    assert type(obj) is Object


def test_ciphertext_is_not_decrypted_without_cipher(container: FakeContainer, cipher) -> None:
    """Ciphertext must never be decrypted implicitly: without a cipher it is treated as a raw block."""
    plain = make_block(c_apfs.OBJ_ENCRYPTED | c_apfs.OBJECT_TYPE_BTREE_NODE, o_oid=1028)
    ciphertext = cipher.encrypt(plain, ADDRESS * SECTORS_PER_BLOCK)

    obj = Object.from_block(container, ADDRESS, ciphertext)

    # The raw bytes are preserved untouched and exposed through the generic object.
    assert type(obj) is Object
    assert bytes(obj.block) == ciphertext
