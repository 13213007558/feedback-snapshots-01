from __future__ import annotations

import stat
import unicodedata
from dataclasses import dataclass
from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.fve.crypto import create_cipher
from dissect.util.hash.crc32c import crc32c
from dissect.util.stream import BufferedStream
from dissect.util.ts import from_unix, from_unix_ns

from dissect.apfs.c_apfs import FILESYSTEM_OBJECT_TYPE_MAP, XF_MAP, c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import (
    EncryptionError,
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    UnsupportedEncryptionError,
    UnsupportedKeyGenerationError,
    VolumeLockedError,
    VolumeMismatchError,
)
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.objects.omap import ObjectMap
from dissect.apfs.stream import DecmpfsStream, FileStream
from dissect.apfs.util import cmp_fs, cmp_fs_dir, cmp_fs_dir_hash, parse_fs_object_key

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.fve.crypto import Cipher

    from dissect.apfs.objects.btree_node import BTreeNode
    from dissect.apfs.objects.keybag import VolumeKeybag


@dataclass(frozen=True)
class CryptoState:
    """The volume metadata crypto state that determines which key generation is in use.

    APFS records this state in every ``apfs_superblock``, including the ones stored for snapshots.
    A snapshot is only decryptable with the same key generation as the volume it belongs to, so this
    state is captured in a :class:`VolumeKeyContext` and compared when opening a snapshot.
    """

    major_version: int
    minor_version: int
    cpflags: int
    persistent_class: int
    key_os_version: int
    key_revision: int

    @classmethod
    def from_superblock(cls, sb: c_apfs.apfs_superblock) -> CryptoState:
        """Capture the crypto state of an ``apfs_superblock``."""
        crypto = sb.apfs_meta_crypto
        return cls(
            major_version=crypto.major_version,
            minor_version=crypto.minor_version,
            cpflags=crypto.cpflags,
            persistent_class=crypto.persistent_class,
            key_os_version=crypto.key_os_version,
            key_revision=crypto.key_revision,
        )

    @property
    def key_generation(self) -> tuple[int, int, int, int, int]:
        """The fields that define the key generation of this crypto state.

        ``key_os_version`` is informational about the OS that wrote the metadata and is not part of
        the key identity: it may differ between a volume and its snapshots while both still use the
        same key.
        """
        return (
            self.major_version,
            self.minor_version,
            self.cpflags,
            self.persistent_class,
            self.key_revision,
        )

    def is_supported(self) -> bool:
        """Whether this module can use the key generation described by this crypto state."""
        # Key revisions are the mechanism APFS uses to roll volume keys, and non-zero crypto flags
        # signal an in-progress key roll. We only understand the initial revision of the metadata
        # crypto scheme that the supported encrypted volumes use.
        return (
            self.major_version == 5
            and self.minor_version == 0
            and self.cpflags == 0
            and self.key_revision == 1
        )


class VolumeKeyContext:
    """A verified volume encryption context, bound to one volume identity.

    A context is created when a volume is unlocked and only wraps the derived volume encryption key
    and the identity it was derived for. It intentionally does not hold any filesystem tree,
    object map or transaction state: those are per volume and, for snapshots, per snapshot transaction.

    Args:
        uuid: The UUID of the volume the key was derived for.
        vek: The unwrapped volume encryption key.
        crypto_state: The crypto state of the volume the key was unlocked with.
        keybag_uuid: The UUID of the VEK record the key was unwrapped from.
        container_uuid: The UUID of the container the volume belongs to.
    """

    __slots__ = ("_cipher", "_container_uuid", "_crypto_state", "_keybag_uuid", "_uuid")

    def __init__(
        self,
        uuid: UUID,
        vek: bytes,
        crypto_state: CryptoState,
        keybag_uuid: UUID | None = None,
        container_uuid: UUID | None = None,
    ):
        self._uuid = uuid
        self._container_uuid = container_uuid
        self._keybag_uuid = keybag_uuid
        self._crypto_state = crypto_state
        self._cipher = create_cipher("aes-xts-128", vek)

    def __repr__(self) -> str:
        return f"<VolumeKeyContext uuid={self._uuid} key_revision={self._crypto_state.key_revision}>"

    @property
    def uuid(self) -> UUID:
        """The UUID of the volume this context belongs to."""
        return self._uuid

    @property
    def crypto_state(self) -> CryptoState:
        """The crypto state of the volume this context belongs to."""
        return self._crypto_state

    @property
    def keybag_uuid(self) -> UUID | None:
        """The UUID of the keybag record this context was derived from, if known."""
        return self._keybag_uuid

    @property
    def container_uuid(self) -> UUID | None:
        """The UUID of the container this context was derived in, if known."""
        return self._container_uuid

    @property
    def cipher(self) -> Cipher:
        """The cipher for this volume."""
        return self._cipher

    def apply_to(self, fs: FS) -> None:
        """Attach this context to a filesystem object after verifying the volume identity.

        Args:
            fs: The volume or snapshot filesystem to attach the context to.

        Raises:
            VolumeMismatchError: If the context belongs to a different volume.
            UnsupportedKeyGenerationError: If the filesystem requires a different key generation.
        """
        self.validate(fs)

        fs._cipher = self._cipher
        fs._key_context = self

    def validate(self, fs: FS) -> None:
        """Verify that this context may be used for a filesystem object.

        Args:
            fs: The volume or snapshot filesystem to validate against.

        Raises:
            VolumeMismatchError: If the context belongs to a different volume.
            UnsupportedKeyGenerationError: If the filesystem requires a different key generation.
        """
        if fs.uuid != self._uuid:
            raise VolumeMismatchError(
                f"Encryption context for volume {self._uuid} can not be used for volume {fs.uuid}"
            )

        if self._container_uuid is not None and fs.container.uuid != self._container_uuid:
            raise VolumeMismatchError(
                f"Encryption context for container {self._container_uuid} can not be used in "
                f"container {fs.container.uuid}"
            )

        crypto_state = fs.crypto_state
        if crypto_state.key_generation != self._crypto_state.key_generation:
            raise UnsupportedKeyGenerationError(
                f"Encryption context for key generation {self._crypto_state.key_generation} can not be "
                f"used for volume {fs.uuid} with key generation {crypto_state.key_generation}"
            )

        if not crypto_state.is_supported():
            raise UnsupportedKeyGenerationError(
                f"Volume {fs.uuid} uses unsupported key generation {crypto_state}"
            )

        if not fs.is_onekey:
            raise UnsupportedEncryptionError(
                f"Volume {fs.uuid} uses multi-key encryption, which is not supported"
            )


class FS(Object):
    """APFS Filesystem object, also referred to as the "volume"."""

    __type__ = c_apfs.OBJECT_TYPE_FS
    __struct__ = c_apfs.apfs_superblock
    object: c_apfs.apfs_superblock

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.object.apfs_magic.to_bytes(4, "big") != c_apfs.APFS_MAGIC:
            raise Error(
                "Invalid apfs_superblock magic "
                f"(expected {c_apfs.APFS_MAGIC!r}, got {self.object.apfs_magic.to_bytes(4, 'big')!r})"
            )

        self._cipher = None
        self._crypto_state = None
        self._key_context = None
        # Transaction used to resolve virtual objects (like the root tree) through the volume OMAP.
        # Snapshots must resolve their trees using their own transaction, not the live volume's.
        self._tree_xid = None

        self.inode = lru_cache(4096)(self.inode)
        self._cursor_state = lru_cache(128)(self._cursor_state)

        self.root = self.inode(c_apfs.ROOT_DIR_INO_NUM)

    def __repr__(self) -> str:
        return f"<FS name={self.name!r} uuid={self.uuid}>"

    @cached_property
    def index(self) -> int:
        """The volume index within the container."""
        return self.object.apfs_fs_index

    @cached_property
    def features(self) -> c_apfs.APFS_FEATURE:
        """The features supported by this filesystem."""
        return c_apfs.APFS_FEATURE(self.object.apfs_features)

    @cached_property
    def incompatible_features(self) -> c_apfs.APFS_INCOMPAT:
        """The incompatible features supported by this filesystem."""
        return c_apfs.APFS_INCOMPAT(self.object.apfs_incompatible_features)

    @cached_property
    def is_case_insensitive(self) -> bool:
        """Whether the filesystem is case insensitive."""
        return c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE in self.incompatible_features

    @cached_property
    def is_normalization_insensitive(self) -> bool:
        """Whether the filesystem is normalization insensitive."""
        return c_apfs.APFS_INCOMPAT.NORMALIZATION_INSENSITIVE in self.incompatible_features

    @cached_property
    def is_sealed(self) -> bool:
        """Whether the filesystem is sealed (read-only)."""
        return c_apfs.APFS_INCOMPAT.SEALED_VOLUME in self.incompatible_features

    @cached_property
    def unmount_time(self) -> datetime:
        """The last unmount time of the filesystem."""
        return from_unix(self.object.apfs_unmount_time)

    @cached_property
    def omap(self) -> ObjectMap:
        """The object map for the filesystem."""
        return ObjectMap.from_address(self.container, self.object.apfs_omap_oid)

    @property
    def tree_xid(self) -> int:
        """The transaction ID used to resolve this filesystem's virtual objects.

        For a live volume this is the transaction of its superblock. Snapshots override this with
        the transaction the snapshot was taken at, so their trees are resolved at that point in
        time instead of resolving to the current version of the volume.
        """
        return self.xid if self._tree_xid is None else self._tree_xid

    @property
    def crypto_state(self) -> CryptoState:
        """The crypto state recorded in this filesystem's superblock."""
        if self._crypto_state is None:
            self._crypto_state = CryptoState.from_superblock(self.object)
        return self._crypto_state

    @property
    def key_context(self) -> VolumeKeyContext | None:
        """The encryption context this filesystem was opened with, if any."""
        return self._key_context

    def require_cipher(self) -> Cipher | None:
        """Return the cipher needed to read this filesystem's metadata and file data.

        Raises:
            VolumeLockedError: If the filesystem is encrypted and no unlock context was applied.
            UnsupportedKeyGenerationError: If the volume uses an unsupported key generation.
            UnsupportedEncryptionError: If the encryption mode is not supported.
        """
        if not self.is_encrypted:
            return self._cipher

        if self._cipher is None:
            raise VolumeLockedError(f"Volume {self.uuid} is encrypted, unlock it first")

        if not self.crypto_state.is_supported():
            raise UnsupportedKeyGenerationError(
                f"Volume {self.uuid} uses an unsupported key generation {self.crypto_state}"
            )

        if not self.is_onekey:
            raise UnsupportedEncryptionError(
                f"Volume {self.uuid} uses multi-key encryption, which is not supported"
            )

        return self._cipher

    @cached_property
    def root_tree(self) -> BTree:
        """The root B-tree for the filesystem."""
        return BTree.from_address(
            self.container,
            self.omap.lookup(self.object.apfs_root_tree_oid, self.tree_xid),
            cipher=self.require_cipher(),
        )

    @cached_property
    def snap_meta_tree(self) -> BTree:
        """The snapshot metadata B-tree for the filesystem."""
        if self.object.apfs_snap_meta_tree_oid == 0:
            raise Error(f"Volume {self.uuid} has no snapshot metadata tree")

        # The snapshot metadata tree is a physical object without an object map record. It is only
        # encrypted when the volume metadata is encrypted, so only require an unlock context then.
        tree = BTree.from_address(
            self.container,
            self.object.apfs_snap_meta_tree_oid,
            cipher=self._cipher,
        )

        if self._cipher is None and self.is_encrypted:
            node_type = tree.root.header.o_type
            if node_type & c_apfs.OBJECT_TYPE_MASK != c_apfs.OBJECT_TYPE_BTREE:
                raise VolumeLockedError(f"Volume {self.uuid} is encrypted, unlock it first")

        return tree

    @cached_property
    def uuid(self) -> UUID:
        """The filesystem UUID."""
        return UUID(bytes_le=self.object.apfs_vol_uuid)

    @cached_property
    def mtime(self) -> datetime:
        """The last modification time of the filesystem."""
        return from_unix(self.object.apfs_last_mod_time)

    @cached_property
    def flags(self) -> c_apfs.APFS_FS:
        return c_apfs.APFS_FS(self.object.apfs_fs_flags)

    @cached_property
    def is_unencrypted(self) -> bool:
        """Whether the filesystem is unencrypted."""
        return c_apfs.APFS_FS.UNENCRYPTED in self.flags

    @cached_property
    def is_encrypted(self) -> bool:
        """Whether the filesystem is encrypted."""
        return (
            not self.is_unencrypted
            # Related to FileVault, but does not imply full volume encryption
            and c_apfs.APFS_FS.PFK not in self.flags
        )

    @cached_property
    def is_onekey(self) -> bool:
        """Whether the filesystem uses the volume encryption key for all."""
        return c_apfs.APFS_FS.ONEKEY in self.flags

    @cached_property
    def formatted_by(self) -> tuple[str, datetime, int]:
        """Information about the tool that formatted the filesystem."""
        return (
            self.object.apfs_formatted_by.id.split(b"\x00", 1)[0].decode(),
            from_unix(self.object.apfs_formatted_by.timestamp),
            self.object.apfs_formatted_by.last_xid,
        )

    @cached_property
    def modified_by(self) -> list[tuple[str, datetime, int]]:
        """Information about the tools that modified the filesystem."""
        result = []
        for entry in self.object.apfs_modified_by:
            if entry.id == b"\x00" * 64:
                continue

            result.append(
                (
                    entry.id.split(b"\x00", 1)[0].decode(),
                    from_unix(entry.timestamp),
                    entry.last_xid,
                )
            )

        return result

    @cached_property
    def name(self) -> str:
        """The volume name."""
        return self.object.apfs_volname.split(b"\x00", 1)[0].decode()

    @cached_property
    def role(self) -> c_apfs.APFS_VOL_ROLE:
        """The volume role."""
        return c_apfs.APFS_VOL_ROLE(self.object.apfs_role)

    @cached_property
    def snapshots(self) -> list[Snapshot]:
        """All snapshots in the filesystem."""
        result = []

        cursor = Cursor(self.snap_meta_tree)
        for key, value in cursor.walk():
            xid, type = parse_fs_object_key(key)
            if type != c_apfs.APFS_TYPE.SNAP_METADATA:
                continue
            result.append(Snapshot(self, xid, value))

        return result

    @cached_property
    def fext_tree(self) -> BTree:
        """The file extent B-tree for the filesystem."""
        return BTree.from_address(
            self.container,
            self.object.apfs_fext_tree_oid,
            cipher=self.require_cipher(),
        )

    @cached_property
    def keybag(self) -> VolumeKeybag | None:
        """The volume keybag, if present."""
        return self.container.keybag.volume_keybag(self.object.apfs_vol_uuid)

    @cached_property
    def password_hint(self) -> str | None:
        """The password hint for the volume, if present."""
        if not self.keybag:
            return None

        return self.keybag.password_hint(self.object.apfs_vol_uuid)

    def unlock(self, password: str, uuid: UUID | str | None = None) -> None:
        """Unlock this volume and remember the verified key as a :class:`VolumeKeyContext`.

        The resulting context can be used to read this volume and its snapshots, but nothing else.
        It does not carry filesystem trees, object maps or transaction state.

        Args:
            password: The password to unlock the volume with.
            uuid: Optionally, the UUID of the KEK to use.
        """
        if (keybag := self.container.keybag) is None:
            raise Error(f"Volume {self.uuid} has no container keybag")

        if (vek := keybag.vek(self.object.apfs_vol_uuid)) is None:
            raise Error("No VEK found for this volume")

        if not vek.verify():
            raise Error(f"VEK for volume {self.uuid} failed verification")

        unlocked = False
        for kek in self.keybag.keks():
            if uuid is not None and str(kek.uuid) != str(uuid):
                continue

            if not kek.verify():
                continue

            try:
                unwrapped = vek.unwrap(kek.unwrap(password))
            except Exception:
                continue
            else:
                self.apply_key_context(
                    VolumeKeyContext(
                        self.uuid,
                        unwrapped,
                        self.crypto_state,
                        keybag_uuid=vek.uuid,
                        container_uuid=self.container.uuid,
                    )
                )
                unlocked = True
                break

        if not unlocked:
            raise Error("Failed to unlock volume with the given password")

    def apply_key_context(self, context: VolumeKeyContext) -> None:
        """Apply a verified encryption context to this filesystem.

        The context is validated against this filesystem's volume identity and crypto state before
        it is applied.

        Args:
            context: The encryption context to apply.

        Raises:
            VolumeMismatchError: If the context belongs to a different volume.
            UnsupportedKeyGenerationError: If the filesystem requires a different key generation.
        """
        if self.is_unencrypted:
            raise VolumeMismatchError(f"Volume {self.uuid} is not encrypted, refusing an encryption context")

        context.apply_to(self)

    def cursor(self) -> Cursor:
        """Create a new cursor for the volume's root B-tree."""
        return Cursor(
            self.root_tree,
            self.omap,
            self.object.apfs_root_tree_oid if self.is_sealed else 0,
            self.tree_xid,
        )

    def _cursor_state(self, oid: int) -> tuple[BTreeNode, int, list[tuple[BTreeNode, int]]]:
        """Precompute the cursor state for a given object ID.

        Args:
            oid: The object ID to position the cursor at.
        """
        cursor = self.cursor()
        cursor.search((oid, c_apfs.APFS_TYPE.ANY.value), cmp=cmp_fs)

        return cursor.state

    def _cursor(self, oid: int) -> Cursor:
        """Get a cursor positioned at the first record for a given object ID.

        Args:
            oid: The object ID to position the cursor at.
        """
        cursor = self.cursor()
        cursor.state = self._cursor_state(oid)
        return cursor

    def _records(self, oid: int, type: c_apfs.APFS_TYPE) -> Iterator[tuple[c_apfs.APFS_TYPE, bytes, bytes]]:
        """Iterate over all records for a given object ID and type.

        Args:
            oid: The object ID to search for.
            type: The object type to search for, or ``APFS_TYPE.ANY`` for all types.
        """
        cursor = self._cursor(oid)

        while True:
            current_oid, current_type = parse_fs_object_key(cursor.key())
            if current_oid < oid:
                if not cursor.next():
                    break
                continue

            if current_oid > oid or (type != c_apfs.APFS_TYPE.ANY and current_type > type):
                break

            if type == c_apfs.APFS_TYPE.ANY or current_type == type:
                yield current_type, cursor.key(), cursor.value()

            if not cursor.next():
                break

    def records(self, oid: int) -> dict[c_apfs.APFS_TYPE, list[Any]]:
        """Get all records for a given object ID.

        Args:
            oid: The object ID to search for.
        """
        result = {}
        for type, key, value in self._records(oid, c_apfs.APFS_TYPE.ANY):
            key_struct, value_struct = FILESYSTEM_OBJECT_TYPE_MAP[type]
            result.setdefault(type, []).append((key_struct(key), value_struct(value)))
        return result

    def inode(self, oid: int | str, sibling_id: int | None = None) -> INode:
        """Get an inode by its object ID.

        Args:
            oid: The object ID of the inode to retrieve.
            sibling_id: The sibling ID of the inode to retrieve, if applicable.
        """
        if isinstance(oid, str):
            if ":" not in oid:
                raise ValueError("Invalid inode string, expected format 'oid:sibling_id'")
            oid, sibling_id = map(int, oid.split(":", 1))
        return INode(self, oid, sibling_id)

    def inodes(self) -> Iterator[INode]:
        """Iterate over all inodes in the filesystem."""
        cursor = self.cursor()

        for key, value in cursor.walk():
            oid, type = parse_fs_object_key(key)
            if type == c_apfs.APFS_TYPE.INODE:
                inode = self.inode(oid)
                inode._inode_raw = value
                yield inode

    def get(self, path: str | int | DirectoryEntry, node: INode | None = None) -> INode:
        """Get an inode by its path, object ID, or directory entry.

        Args:
            path: The path, object ID, or directory entry of the inode to retrieve.
            node: The starting inode for relative paths. Defaults to the root inode.
        """
        if isinstance(path, int):
            return self.inode(path)

        if isinstance(path, DirectoryEntry):
            return self.inode(path.file_id)

        node = node or self.root
        for p in path.split("/"):
            if not p:
                continue

            if p == ".":
                continue

            if p == "..":
                node = node.parent
                continue

            try:
                node = node.get(p).inode
            except FileNotFoundError:
                raise FileNotFoundError(f"File not found: {path}")

        return node


class Snapshot:
    def __init__(self, fs: FS, xid: int, value: bytes):
        self.fs = fs
        self.xid = xid
        self.value = c_apfs.j_snap_metadata_val(value)

    def __repr__(self) -> str:
        return (
            f"<Snapshot xid={self.xid} name={self.name!r} "
            f"create_time={self.create_time} change_time={self.change_time}>"
        )

    @cached_property
    def create_time(self) -> datetime:
        """The creation time of the snapshot."""
        return from_unix_ns(self.value.create_time)

    @cached_property
    def change_time(self) -> datetime:
        """The change time of the snapshot."""
        return from_unix_ns(self.value.change_time)

    @cached_property
    def name(self) -> str:
        """The name of the snapshot."""
        return self.value.name.decode().rstrip("\x00")

    def open(self, key_context: VolumeKeyContext | None = None) -> FS:
        """Open the snapshot as a filesystem.

        The snapshot is read at the transaction it was taken at, using the volume's object map.
        For encrypted volumes the unlock context of the parent volume is inherited, because a
        snapshot shares the volume identity and key generation of the volume it belongs to.

        All state needed to read the snapshot is validated before this method returns, so a
        snapshot that can not be decrypted never produces a partially readable filesystem.

        Args:
            key_context: Optionally, an explicit encryption context to use. This is validated
                against the volume identity and crypto state of both the parent volume and the
                snapshot before it is used.

        Raises:
            VolumeLockedError: If the volume is encrypted and neither the parent volume nor an
                explicit context provides a key.
            VolumeMismatchError: If an explicit context belongs to another volume, or the snapshot
                does not belong to the volume it was found in.
            UnsupportedKeyGenerationError: If the snapshot requires a key generation that is not
                supported, or does not match the context.
            UnsupportedEncryptionError: If the volume uses an unsupported encryption mode.
        """
        parent = self.fs

        if key_context is not None:
            if parent.is_encrypted:
                # Validate against the parent volume first so a context for the wrong volume or
                # the wrong key generation never reaches the snapshot. Validation does not unlock
                # the parent: the context only applies where it is explicitly used.
                key_context.validate(parent)
            else:
                raise VolumeMismatchError(
                    f"Volume {parent.uuid} is not encrypted, refusing an encryption context"
                )
        elif parent.is_encrypted:
            if parent.key_context is None:
                raise VolumeLockedError(
                    f"Volume {parent.uuid} is encrypted, unlock it before opening snapshot {self.name!r}"
                )
            key_context = parent.key_context

        snap_fs = FS.from_address(
            parent.container,
            self.value.sblock_oid,
        )

        if not snap_fs.is_valid() or snap_fs.type != c_apfs.OBJECT_TYPE.FS:
            raise Error(
                f"Snapshot {self.name!r} has an invalid superblock at {self.value.sblock_oid:#x}"
            )

        if snap_fs.uuid != parent.uuid:
            raise VolumeMismatchError(
                f"Snapshot {self.name!r} belongs to volume {snap_fs.uuid}, "
                f"not to the volume it was found in ({parent.uuid})"
            )

        # A snapshot superblock does not carry its own object map, so share the volume's object map.
        # This is the only piece of parent state a snapshot needs; all lookups use the snapshot's
        # own transaction.
        snap_fs.__dict__["omap"] = parent.omap

        # Resolve the snapshot's virtual objects at the transaction the snapshot was taken at.
        snap_fs._tree_xid = self.xid

        if key_context is not None:
            snap_fs.apply_key_context(key_context)
        elif snap_fs.is_encrypted:
            raise VolumeLockedError(
                f"Snapshot {self.name!r} of volume {snap_fs.uuid} is encrypted, unlock it first"
            )

        # Resolve and validate the root tree now, so unsupported encryption or a bad transaction is
        # reported here instead of on the first directory access.
        if not snap_fs.root_tree.root.is_valid():
            if snap_fs.is_encrypted:
                raise EncryptionError(
                    f"Snapshot {self.name!r} could not be decrypted with the given key context "
                    f"(invalid root tree at xid {self.xid})"
                )
            raise Error(f"Snapshot {self.name!r} has an invalid root tree at xid {self.xid}")

        return snap_fs


class INode:
    """APFS inode.

    Represents a file or directory in an APFS volume.

    Args:
        volume: Parent APFS volume.
        oid: The object ID of the inode.
        sibling_id: The sibling ID of the inode, if applicable.
    """

    def __init__(self, volume: FS, oid: int, sibling_id: int | None = None):
        self.volume = volume
        self.oid = oid
        self.sibling_id = sibling_id

    def __repr__(self) -> str:
        oid = f"{self.oid}:{self.sibling_id}" if self.sibling_id is not None else str(self.oid)
        return f"<INode oid={oid} name={self.name!r}>"

    @cached_property
    def records(self) -> dict[c_apfs.APFS_TYPE, list[Any]]:
        """All records for this inode."""
        return self.volume.records(self.oid)

    @cached_property
    def _inode_raw(self) -> bytes:
        """The raw inode data."""
        _, _, value = next(self.volume._records(self.oid, c_apfs.APFS_TYPE.INODE), (None, None, None))
        if value is None:
            raise KeyError(f"INode {self.oid} not found in volume")
        return value

    @cached_property
    def inode(self) -> c_apfs.j_inode_val:
        """The parsed inode structure."""
        return c_apfs.j_inode_val(self._inode_raw)

    @cached_property
    def xfields(self) -> dict:
        """The extended fields for this inode."""
        if len(self._inode_raw) == len(c_apfs.j_inode_val):
            return {}

        result = {}
        for field, value in _read_xfields(self._inode_raw[len(c_apfs.j_inode_val) :]):
            type = c_apfs.INO_EXT_TYPE(field.x_type)
            result[type] = (c_apfs.XF(field.x_flags), XF_MAP.get(type, lambda buf: buf)(value))

        return result

    @cached_property
    def xattr(self) -> dict[str, XAttr]:
        """The extended attributes for this inode."""
        result = {}

        for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.XATTR):
            xattr = XAttr(self, key, value)
            result[xattr.name] = xattr

        return result

    @property
    def parent(self) -> INode:
        """The parent inode."""
        if self.oid in (c_apfs.ROOT_DIR_INO_NUM, c_apfs.PRIV_DIR_INO_NUM):
            return self

        if self.sibling_id is not None:
            parent_id, _ = self.sibling_link or (None, None)
        else:
            parent_id = self.inode.parent_id

        return self.volume.inode(parent_id)

    @property
    def parents(self) -> Iterator[INode]:
        """Iterate over the parent inodes of this inode, up to the root."""
        obj = self
        while obj.parent is not obj:
            obj = obj.parent
            yield obj

    @cached_property
    def private_id(self) -> int:
        """The private ID of this inode."""
        return self.inode.private_id

    @cached_property
    def btime(self) -> datetime:
        """The birth time of this inode."""
        return from_unix_ns(self.inode.create_time)

    @cached_property
    def mtime(self) -> datetime:
        """The modification time of this inode."""
        return from_unix_ns(self.inode.mod_time)

    @cached_property
    def ctime(self) -> datetime:
        """The change time of this inode."""
        return from_unix_ns(self.inode.change_time)

    @cached_property
    def atime(self) -> datetime:
        """The access time of this inode."""
        return from_unix_ns(self.inode.access_time)

    @cached_property
    def internal_flags(self) -> c_apfs.INODE:
        """The inode internal flags."""
        return c_apfs.INODE(self.inode.internal_flags)

    @cached_property
    def bsd_flags(self) -> int:
        """The inode BSD flags."""
        return self.inode.bsd_flags

    def is_compressed(self) -> bool:
        """Return whether this inode is compressed."""
        return bool(self.bsd_flags & c_apfs.UF_COMPRESSED)

    @cached_property
    def uid(self) -> int:
        """The owner user ID of this inode."""
        return self.inode.owner

    @cached_property
    def gid(self) -> int:
        """The owner group ID of this inode."""
        return self.inode.group

    @cached_property
    def mode(self) -> int:
        """The file mode of this inode."""
        return self.inode.mode

    @cached_property
    def type(self) -> int:
        """The file type of this inode."""
        return stat.S_IFMT(self.mode)

    def is_dir(self) -> bool:
        """Return whether this inode is a directory."""
        return stat.S_ISDIR(self.mode)

    def is_file(self) -> bool:
        """Return whether this inode is a regular file."""
        return stat.S_ISREG(self.mode)

    def is_symlink(self) -> bool:
        """Return whether this inode is a symbolic link."""
        return stat.S_ISLNK(self.mode)

    def is_block_device(self) -> bool:
        """Return whether this inode is a block device."""
        return stat.S_ISBLK(self.mode)

    def is_character_device(self) -> bool:
        """Return whether this inode is a character device."""
        return stat.S_ISCHR(self.mode)

    def is_device(self) -> bool:
        """Return whether this inode is a device (block or character)."""
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        """Return whether this inode is a FIFO."""
        return stat.S_ISFIFO(self.mode)

    def is_socket(self) -> bool:
        """Return whether this inode is a socket."""
        return stat.S_ISSOCK(self.mode)

    def is_whiteout(self) -> bool:
        """Return whether this inode is a whiteout."""
        return stat.S_ISWHT(self.mode)

    @cached_property
    def size(self) -> int:
        """The size of this inode in bytes."""
        if c_apfs.INODE.HAS_UNCOMPRESSED_SIZE in self.internal_flags:
            return self.inode.uncompressed_size

        if decmpfs := self.xattr.get("com.apple.decmpfs"):
            header = c_apfs.decmpfs_header(decmpfs.open())
            return header.uncompressed_size

        if dstream := self.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM):
            _, dstream = dstream
            return dstream.size

        return 0

    @cached_property
    def siblings(self) -> list[INode]:
        """All sibling inodes of this inode."""
        result = []
        for _, key, _ in self.volume._records(self.oid, c_apfs.APFS_TYPE.SIBLING_LINK):
            key = c_apfs.j_sibling_key(key)
            if self.sibling_id is not None and key.sibling_id == self.sibling_id:
                continue
            result.append(self.volume.inode(self.oid, key.sibling_id))
        return result

    @cached_property
    def sibling_link(self) -> tuple[int, str] | None:
        """The sibling link (``parent_id``, ``name``) tuple of this inode, if available."""
        if self.sibling_id is not None:
            for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.SIBLING_LINK):
                if c_apfs.j_sibling_key(key).sibling_id == self.sibling_id:
                    value = c_apfs.j_sibling_val(value)
                    return value.parent_id, value.name.decode().rstrip("\x00")
        return None

    @cached_property
    def name(self) -> str | None:
        """The name of this inode, if available."""
        name = None
        if self.sibling_id is not None:
            _, name = self.sibling_link or (None, None)
        else:
            if c_apfs.INO_EXT_TYPE.NAME in self.xfields:
                _, name = self.xfields[c_apfs.INO_EXT_TYPE.NAME]
                name = name.decode().rstrip("\x00")
        return name

    @cached_property
    def names(self) -> list[str]:
        """All names of this inode, if available."""
        names = {self.name} | {sibling.name for sibling in self.siblings if sibling.name}
        return list(names)

    @cached_property
    def path(self) -> str:
        """The full path of this inode, if available."""
        parts = [self.name or f"<unlinked:{self.oid}>"]
        parts.extend(parent.name or f"<unlinked:{parent.oid}>" for parent in self.parents)

        return "/" + "/".join(parts[::-1])

    @cached_property
    def paths(self) -> list[str]:
        """All full paths of this inode, if available."""
        return [self.path] + [sibling.path for sibling in self.siblings]

    def get(self, name: str) -> DirectoryEntry:
        """Get a directory entry by name."""
        if not self.volume.is_case_insensitive and not self.volume.is_normalization_insensitive:
            # APFS beta's didn't have normalization insensitivity, so when the filesystem is case sensitive
            # we can do a simple exact match
            key = ((self.oid, c_apfs.APFS_TYPE.DIR_REC.value), name.encode() + b"\x00")
            cmp = cmp_fs_dir
        else:
            # Length is not used in the key comparison
            name_hash = (
                _hash_filename(name, self.volume.is_case_insensitive) << c_apfs.J_DREC_HASH_SHIFT
            ) & c_apfs.J_DREC_HASH_MASK
            # If the volume is case sensitive, we can use the name in the search key for an exact match
            # Otherwise, we set it to None to ignore it in the comparison
            name_search = None if self.volume.is_case_insensitive else (name.encode() + b"\x00")

            key = ((self.oid, c_apfs.APFS_TYPE.DIR_REC.value), name_hash, name_search)
            cmp = cmp_fs_dir_hash

        cursor = self.volume.cursor()
        try:
            cursor.search(key, exact=True, cmp=cmp)
        except KeyError:
            raise FileNotFoundError(f"File not found: {name}")

        if not self.volume.is_case_insensitive:
            # On case sensitive volumes, the search is already exact, so no need to check further
            return DirectoryEntry(self.volume, cursor.key(), cursor.value())

        lname = name.casefold()
        while True:
            try:
                dirent = DirectoryEntry(self.volume, cursor.key(), cursor.value())
            except Exception:
                raise FileNotFoundError(f"File not found: {name}")

            # To deal with the possibility of hash collisions, verify the name matches
            oid = dirent.key.hdr.obj_id_and_type & c_apfs.OBJ_ID_MASK
            type = (dirent.key.hdr.obj_id_and_type & c_apfs.OBJ_TYPE_MASK) >> c_apfs.OBJ_TYPE_SHIFT
            if oid != self.oid or type != c_apfs.APFS_TYPE.DIR_REC:
                raise FileNotFoundError(f"File not found: {name}")

            if lname == dirent.name.casefold():
                return dirent

            if not cursor.next():
                raise FileNotFoundError(f"File not found: {name}")

    def listdir(self) -> dict[str, DirectoryEntry]:
        """List the directory entries in this inode."""
        return {e.name: e for e in self.iterdir()}

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Iterate over the directory entries in this inode."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self} is not a directory")

        for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.DIR_REC):
            yield DirectoryEntry(self.volume, key, value)

    def readlink(self) -> str:
        """The target of this inode if it is a symbolic link."""
        if not self.is_symlink():
            raise NotASymlinkError(f"{self} is not a symlink")

        if c_apfs.SYMLINK_EA_NAME not in self.xattr:
            raise Error(f"Symlink {self} does not have SYMLINK_EA_NAME xattr")

        return self.xattr[c_apfs.SYMLINK_EA_NAME].open().read().decode().rstrip("\x00")

    def open(self) -> BufferedStream | DecmpfsStream | FileStream:
        """Open a stream for reading the inode data."""
        if self.is_compressed():
            return DecmpfsStream(self)

        if dstream := self.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM):
            _, dstream = dstream
            return FileStream(self.volume, self.private_id, dstream.size)

        return BufferedStream(BytesIO(b""), size=0)


class DirectoryEntry:
    """APFS directory entry.

    Args:
        volume: Parent APFS volume.
        key: The raw directory entry key.
        value: The raw directory entry value.
    """

    def __init__(self, volume: FS, key: bytes, value: bytes):
        self.volume = volume
        if self.volume.is_case_insensitive or self.volume.is_normalization_insensitive:
            self.key = c_apfs.j_drec_hashed_key(key)
        else:
            self.key = c_apfs.j_drec_key(key)
        self.value = c_apfs.j_drec_val(value)

        self.xfields = {}
        if len(value) != len(c_apfs.j_drec_val):
            for field, data in _read_xfields(value[len(c_apfs.j_drec_val) :]):
                type = c_apfs.DREC_EXT_TYPE(field.x_type)
                self.xfields[type] = (c_apfs.XF(field.x_flags), XF_MAP.get(type, lambda buf: buf)(data))

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r} file_id={self.file_id} dt={self.dt.name}>"

    @cached_property
    def name(self) -> str:
        """The name of this directory entry."""
        return self.key.name.decode().rstrip("\x00")

    @cached_property
    def hash(self) -> int | None:
        """The hash of this directory entry, if available."""
        if isinstance(self.key, c_apfs.j_drec_key):
            return None
        return (self.key.name_len_and_hash & c_apfs.J_DREC_HASH_MASK) >> c_apfs.J_DREC_HASH_SHIFT

    @cached_property
    def file_id(self) -> int:
        """The object ID of the inode this directory entry refers to."""
        return self.value.file_id

    @cached_property
    def sibling_id(self) -> int | None:
        """The sibling ID of the inode this directory entry refers to, if available."""
        return self.xfields.get(c_apfs.DREC_EXT_TYPE.SIBLING_ID, (None, None))[1]

    @property
    def inode(self) -> INode:
        """The inode this directory entry refers to."""
        return self.volume.inode(self.file_id, self.sibling_id)

    @cached_property
    def date_added(self) -> datetime:
        """The date and time this directory entry was added."""
        return from_unix_ns(self.value.date_added)

    @cached_property
    def dt(self) -> c_apfs.DT:
        """The directory entry type."""
        return c_apfs.DT(self.value.flags & c_apfs.DREC_TYPE_MASK)

    @cached_property
    def type(self) -> int:
        """The file type of this directory entry."""
        return (self.value.flags & c_apfs.DREC_TYPE_MASK) << 12

    def is_dir(self) -> bool:
        """Return whether this directory entry is a directory."""
        return stat.S_ISDIR(self.type)

    def is_file(self) -> bool:
        """Return whether this directory entry is a regular file."""
        return stat.S_ISREG(self.type)

    def is_symlink(self) -> bool:
        """Return whether this directory entry is a symbolic link."""
        return stat.S_ISLNK(self.type)

    def is_block_device(self) -> bool:
        """Return whether this directory entry is a block device."""
        return stat.S_ISBLK(self.type)

    def is_character_device(self) -> bool:
        """Return whether this directory entry is a character device."""
        return stat.S_ISCHR(self.type)

    def is_device(self) -> bool:
        """Return whether this directory entry is a device (block or character)."""
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        """Return whether this directory entry is a FIFO."""
        return stat.S_ISFIFO(self.type)

    def is_socket(self) -> bool:
        """Return whether this directory entry is a socket."""
        return stat.S_ISSOCK(self.type)

    def is_whiteout(self) -> bool:
        """Return whether this directory entry is a whiteout."""
        return stat.S_ISWHT(self.type)


class XAttr:
    """APFS extended attribute.

    Args:
        inode: The inode this xattr belongs to.
        key: The raw xattr key.
        value: The raw xattr value.
    """

    def __init__(self, inode: INode, key: bytes, value: bytes):
        self.inode = inode

        self.key = c_apfs.j_xattr_key(key)
        self.value = c_apfs.j_xattr_val(value)

    def __repr__(self) -> str:
        return f"<XAttr name={self.name!r} flags={self.flags}>"

    @cached_property
    def name(self) -> str:
        """The name of this xattr."""
        return self.key.name.decode().rstrip("\x00")

    @cached_property
    def flags(self) -> c_apfs.XATTR:
        """The flags of this xattr."""
        return c_apfs.XATTR(self.value.flags)

    def open(self) -> BufferedStream | FileStream:
        """Open a stream for reading the xattr data."""
        if c_apfs.XATTR.DATA_STREAM in self.flags:
            dstream = c_apfs.j_xattr_dstream(self.value.xdata)
            return FileStream(self.inode.volume, dstream.xattr_obj_id, dstream.dstream.size)

        return BufferedStream(BytesIO(self.value.xdata), size=self.value.xdata_len)


def _read_xfields(data: bytes) -> Iterator[tuple[c_apfs.x_field, bytes]]:
    """Read extended fields from a buffer."""
    blob = c_apfs.xf_blob(data)
    buf = BytesIO(blob.xf_data)
    for field in blob.xf_exts:
        yield field, buf.read(field.x_size)
        # Align to 8 bytes
        buf.seek((buf.tell() + 7) & (-8))


def _hash_filename(name: str, casefold: bool) -> int:
    """Hash a filename according to APFS rules."""
    normalized = unicodedata.normalize("NFD", name)
    if casefold:
        normalized = normalized.casefold()
    return crc32c(normalized.encode("utf-32-le")) ^ 0xFFFFFFFF
