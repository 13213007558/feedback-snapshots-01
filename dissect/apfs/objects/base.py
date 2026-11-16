from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, ClassVar

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import InvalidObjectError
from dissect.apfs.util import fletcher64

if TYPE_CHECKING:
    from dissect.fve.crypto import Cipher
    from typing_extensions import Self

    from dissect.apfs.apfs import APFS


class Object:
    """Base class for APFS objects.

    The way we use this is a little unorthodox OOP-wise, but it works well for our use case.
    For the core of our APFS implementation we want to be able to read any object directly from a known type,
    but for interactive use it would also be nice to be able to read an object from its address and have it
    automatically be the correct subclass.

    Subclasses should define the ``__type__`` and ``__struct__`` class variables.

    Args:
        container: The APFS container the object belongs to.
        address: The block address of the object within the container.
        block: Optionally, the raw block data of the object. If not provided, it will be read from the container.
        cipher: Optionally, a cipher to decrypt the object (or child objects).
    """

    __type__ = c_apfs.OBJECT_TYPE_INVALID
    __struct__ = c_apfs.obj_phys

    __known_types__: ClassVar[dict[int, type[Object]]] = {}

    def __init_subclass__(cls):
        if cls.__type__:
            cls.__known_types__[cls.__type__] = cls

    def __init__(self, container: APFS, address: int, *, block: bytes | None = None, cipher: Cipher | None = None):
        self.container = container
        self.address = address
        self.block = memoryview(block or container._read_block(address))
        self.cipher = cipher

        self.object = self.__struct__(self.block)
        if self.__struct__ is Object.__struct__:
            self.header = self.object
        else:
            # Get the first field of the struct, which is always the obj_phys header
            self.header = getattr(self.object, self.__struct__.__fields__[0].name)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"oid={self.oid} xid={self.xid} "
            f"type={self.type.name} flags={self.type_flags} storage={self.storage_type.name}>"
        )

    @classmethod
    def from_address(cls, container: APFS, address: int, count: int = 1, *, cipher: Cipher | None = None) -> Self:
        """Load an object from its address, automatically determining the correct subclass."""
        block = container._read_block(address, count)
        return cls.from_block(container, address, block, cipher=cipher)

    @classmethod
    def from_block(cls, container: APFS, address: int, block: bytes, *, cipher: Cipher | None = None) -> Self:
        """Load an object from its raw block data, automatically determining the correct subclass.

        When no ``cipher`` is provided the block is assumed to be plaintext, matching the on-disk layout
        of unencrypted containers. When a decryption context *is* provided, merely looking like a valid
        object header is not enough: ciphertext can start with bytes that happen to form a known
        ``o_type``. Both interpretations are therefore subjected to full object validation, and the
        plaintext interpretation is preferred whenever it holds (blocks may already be decrypted).
        Decryption is only attempted when the plaintext interpretation fails, and a block that validates
        under neither interpretation raises :class:`InvalidObjectError` instead of being silently treated
        as a generic object.
        """
        expected_type = cls._expected_type()

        if cipher is None:
            return cls._instantiate(container, address, block, cipher=None)

        plain_reason = cls._validate_block(block, address, expected_type)
        if plain_reason is None:
            # The block is already plaintext (or stored unencrypted even though a cipher is in scope).
            return cls._instantiate(container, address, block, cipher=cipher)

        decrypted = cipher.decrypt(bytes(block), address * container.sectors_per_block)
        encrypted_reason = cls._validate_block(decrypted, address, expected_type)
        if encrypted_reason is None:
            return cls._instantiate(container, address, decrypted, cipher=cipher)

        raise InvalidObjectError(
            f"Block at address {address} could not be validated as an APFS object: "
            f"plaintext interpretation rejected ({plain_reason}); "
            f"decrypted interpretation rejected ({encrypted_reason})"
        )

    @classmethod
    def _instantiate(cls, container: APFS, address: int, block: bytes, *, cipher: Cipher | None) -> Self:
        """Construct the appropriate (sub)class for an already validated block."""
        if cls is not Object:
            return cls(container, address, block=block, cipher=cipher)

        header = c_apfs.obj_phys(block)
        subcls = Object.__known_types__.get(header.o_type, None) or Object.__known_types__.get(
            header.o_type & c_apfs.OBJECT_TYPE_MASK, Object
        )
        return subcls(container, address, block=block, cipher=cipher)

    @classmethod
    def _expected_type(cls) -> int | None:
        """The object type a concrete loader expects, or ``None`` for generic, type-agnostic loading."""
        if cls is Object or cls.__type__ == c_apfs.OBJECT_TYPE_INVALID:
            return None

        # A BTree's addressable root block is stored with the BTREE type; its child nodes use BTREE_NODE.
        if cls.__type__ == c_apfs.OBJECT_TYPE_BTREE:
            return c_apfs.OBJECT_TYPE_BTREE

        return cls.__type__

    @classmethod
    def _validate_block(cls, block: bytes, address: int, expected_type: int | None) -> str | None:
        """Validate an object interpretation without constructing any subclass.

        Returns ``None`` when the block is a valid object, otherwise a human readable reason describing
        the first failed check. Validation covers the object type, the storage class, the checksum and,
        where applicable, the physical address / oid identity.
        """
        if len(block) < len(c_apfs.obj_phys):
            return f"block too small for obj_phys ({len(block)} bytes)"

        header = c_apfs.obj_phys(block)
        type_value = header.o_type
        base_type = type_value & c_apfs.OBJECT_TYPE_MASK

        # Keybag types are four-character-codes stored in the full 32-bit word, not a low-16-bit type.
        is_keybag = type_value in (
            c_apfs.OBJECT_TYPE_CONTAINER_KEYBAG,
            c_apfs.OBJECT_TYPE_VOLUME_KEYBAG,
            c_apfs.OBJECT_TYPE_MEDIA_KEYBAG,
        )

        if not is_keybag and base_type not in c_apfs.OBJECT_TYPE:
            return f"unknown object type {base_type:#x}"

        if expected_type is not None:
            if expected_type >= c_apfs.OBJECT_TYPE_CONTAINER_KEYBAG:
                if type_value != expected_type:
                    return f"unexpected object type {type_value:#x}, expected {expected_type:#x}"
            elif base_type != expected_type:
                return f"unexpected object type {base_type:#x}, expected {expected_type:#x}"
        elif not is_keybag and type_value not in c_apfs.OBJECT_TYPE:
            return f"unknown object type flags {type_value:#x}"

        storage = type_value & c_apfs.OBJ_STORAGETYPE_MASK
        if storage not in (c_apfs.OBJ_VIRTUAL, c_apfs.OBJ_EPHEMERAL, c_apfs.OBJ_PHYSICAL):
            return f"invalid storage class {storage:#x}"

        if not is_keybag and type_value & ~c_apfs.OBJECT_TYPE_FLAGS_DEFINED_MASK != base_type:
            return f"undefined object type flags set in {type_value:#x}"

        checksum = int.from_bytes(header.o_cksum, "little")
        if fletcher64(bytes(block[c_apfs.MAX_CKSUM_SIZE :])) != checksum:
            return "invalid object checksum"

        # Physical objects are addressed directly: their oid must equal their block address.
        # Virtual and ephemeral objects are addressed through an object map, so no such constraint holds.
        # Keybags occupy a physical block range but carry no addressing oid, so they are exempt.
        if not is_keybag and storage == c_apfs.OBJ_PHYSICAL and header.o_oid != address:
            return f"physical object oid {header.o_oid} does not match block address {address}"

        return None

    @cached_property
    def checksum(self) -> int:
        """The object's checksum."""
        return int.from_bytes(self.header.o_cksum, "little")

    def _checksum(self) -> int:
        """Calculate the object's checksum."""
        return fletcher64(self.block[c_apfs.MAX_CKSUM_SIZE :])

    def is_valid(self) -> bool:
        """Check if the object's checksum is valid."""
        return self._checksum() == self.checksum

    @cached_property
    def oid(self) -> int:
        """The object's ID."""
        return self.header.o_oid

    @cached_property
    def xid(self) -> int:
        """The object's transaction ID."""
        return self.header.o_xid

    @cached_property
    def type(self) -> c_apfs.OBJECT_TYPE:
        """The object's type."""
        return c_apfs.OBJECT_TYPE(self.header.o_type & c_apfs.OBJECT_TYPE_MASK)

    @cached_property
    def type_flags(self) -> c_apfs.OBJ:
        """The object's type flags."""
        return c_apfs.OBJ(self.header.o_type & c_apfs.OBJECT_TYPE_FLAGS_MASK)

    @cached_property
    def storage_type(self) -> c_apfs.OBJ:
        """The object's storage type."""
        return c_apfs.OBJ(self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK)

    @cached_property
    def is_virtual(self) -> bool:
        """Check if the object is stored as a virtual object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_VIRTUAL

    @cached_property
    def is_ephemeral(self) -> bool:
        """Check if the object is stored as an ephemeral object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_EPHEMERAL

    @cached_property
    def is_physical(self) -> bool:
        """Check if the object is stored as a physical object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_PHYSICAL

    @cached_property
    def is_encrypted(self) -> bool:
        """Check if the object is encrypted."""
        return bool(self.header.o_type & c_apfs.OBJ_ENCRYPTED)

    @cached_property
    def subtype(self) -> c_apfs.OBJECT_TYPE:
        """The object's subtype."""
        return c_apfs.OBJECT_TYPE(self.header.o_subtype)
