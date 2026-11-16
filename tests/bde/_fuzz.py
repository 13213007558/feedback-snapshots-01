"""Deterministic builders and instrumentation for BitLocker metadata fuzzing.

Everything in this module is synthetic: keys are derived from fixed strings and every byte the
tests feed to the parser is either generated here or an explicit mutation of generated data.
"""

from __future__ import annotations

import hashlib
import struct
from binascii import crc32
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING

from Crypto.Cipher import AES

from dissect.fve.bde.c_bde import (
    FVE_DATUM_ROLE,
    FVE_DATUM_TYPE,
    FVE_KEY_PROTECTOR,
    FVE_KEY_TYPE,
    FVE_STATE,
    INFORMATION_OFFSET_GUID,
    c_bde,
)

if TYPE_CHECKING:
    from collections.abc import Callable


CORPUS_DIR = Path(__file__).parent.parent / "_data" / "bde" / "fuzz"

SECTOR_SIZE = 512
CLUSTER_SIZE = 4096
INFORMATION_OFFSET = 0x1000

VMK_KEY = hashlib.sha256(b"dissect.fve fuzz vmk key").digest()
FVEK_KEY = hashlib.sha256(b"dissect.fve fuzz fvek key").digest()
CORPUS_KEY = hashlib.sha256(b"dissect.fve fuzz corpus key").digest()
WRONG_KEY = hashlib.sha256(b"dissect.fve fuzz wrong key").digest()
VMK_IDENTIFIER = hashlib.sha256(b"dissect.fve fuzz vmk identifier").digest()[:16]


def datum(
    role: int | FVE_DATUM_ROLE,
    type_: int | FVE_DATUM_TYPE,
    payload: bytes = b"",
    *,
    size: int | None = None,
    flags: int = 0,
) -> bytes:
    """Build a raw datum with an optional deliberately wrong size field."""
    declared = len(payload) + c_bde.FVE_DATUM.size if size is None else size
    return c_bde.FVE_DATUM(Size=declared, Role=int(role), Type=int(type_), Flags=flags).dumps() + payload


def dataset(
    datums: bytes,
    *,
    fvek_type: int | FVE_KEY_TYPE = FVE_KEY_TYPE.AES_128,
    size: int | None = None,
    start: int = c_bde.FVE_DATASET.size,
    end: int | None = None,
    version: int = 1,
) -> bytes:
    """Build a raw dataset around the given datum bytes."""
    declared = c_bde.FVE_DATASET.size + len(datums) if size is None else size
    declared_end = declared if end is None else end
    return (
        c_bde.FVE_DATASET(
            Size=declared,
            Version=version,
            StartOffset=start,
            EndOffset=declared_end,
            Identification=b"\x11" * 16,
            NonceCounter=7,
            FvekType=int(fvek_type),
            FvekPrefType=int(fvek_type),
            CreationTime=0,
        ).dumps()
        + datums
    )


def key_datum(role: int | FVE_DATUM_ROLE, key: bytes, key_type: int | FVE_KEY_TYPE, flags: int = 0) -> bytes:
    return datum(
        role,
        FVE_DATUM_TYPE.KEY,
        c_bde.FVE_DATUM_KEY(KeyType=int(key_type), KeyFlags=flags).dumps() + key,
    )


def ccm_datum(
    role: int | FVE_DATUM_ROLE,
    key: bytes,
    plaintext: bytes,
    *,
    counter: int = 1,
    type_: int | FVE_DATUM_TYPE = FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
) -> bytes:
    """Build an AES-CCM encrypted datum, i.e. a fully authenticated shell."""
    nonce = c_bde.FVE_NONCE(DateTime=0, Counter=counter).dumps()
    ciphertext, mac = AES.new(key, AES.MODE_CCM, nonce=nonce).encrypt_and_digest(plaintext)
    return datum(role, type_, nonce + mac + ciphertext)


def vmk_datum(
    properties: bytes,
    *,
    identifier: bytes = VMK_IDENTIFIER,
    priority: int | FVE_KEY_PROTECTOR = FVE_KEY_PROTECTOR.CLEAR,
    hints: int = 0,
) -> bytes:
    header = c_bde.FVE_DATUM_VMK_INFO(
        Identifier=identifier,
        DateTime=0,
        VmkHints=hints,
        Priority=int(priority),
    ).dumps()
    return datum(
        FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
        FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO,
        header + properties,
    )


def stretch_datum(
    key: bytes, *, salt: bytes = b"\x22" * 16, key_type: int | FVE_KEY_TYPE = FVE_KEY_TYPE.STRETCH_KEY_1
) -> bytes:
    header = c_bde.FVE_DATUM_STRETCH_KEY(KeyType=int(key_type), KeyFlags=0, Salt=salt).dumps()
    return datum(
        FVE_DATUM_ROLE.PROPERTY,
        FVE_DATUM_TYPE.STRETCH_KEY,
        header + key_datum(FVE_DATUM_ROLE.PROPERTY, key, FVE_KEY_TYPE.VMK),
    )


def internal_fvek(key: bytes = FVEK_KEY) -> bytes:
    return key_datum(FVE_DATUM_ROLE.PROPERTY, key, FVE_KEY_TYPE.AES_128)


def clear_vmk_properties(vmk_key: bytes = VMK_KEY) -> bytes:
    """Properties for a clear-key VMK, usable with ``unlock_with_clear_key``.

    The VMK carries its own key in the clear and an authenticated copy of that same VMK key. The
    volume-level FVEK is a separate datum encrypted with this VMK key.
    """
    return key_datum(FVE_DATUM_ROLE.PROPERTY, vmk_key, FVE_KEY_TYPE.VMK) + ccm_datum(
        FVE_DATUM_ROLE.PROPERTY,
        vmk_key,
        key_datum(FVE_DATUM_ROLE.PROPERTY, vmk_key, FVE_KEY_TYPE.VMK),
        counter=2,
    )


def build_information(data: bytes, *, version: int = 2) -> bytes:
    size = c_bde.FVE_INFORMATION.size + len(data)
    size = (size + 15) // 16 * 16
    header = c_bde.FVE_INFORMATION(
        Signature=b"-FVE-FS-",
        HeaderSize=size >> 4,
        Version=version,
        CurrentState=int(FVE_STATE.ENCRYPTED),
        NextState=int(FVE_STATE.ENCRYPTED),
        StateOffset=0,
        StateSize=0,
        VirtualizedSectors=0,
        InformationOffset=[INFORMATION_OFFSET, 0, 0],
    ).dumps()
    return (header + data).ljust(size, b"\x00")


def build_volume(
    data: bytes,
    *,
    vmk_key: bytes = VMK_KEY,
    integrity_plaintext: bytes | None = None,
    version: int = 2,
) -> bytes:
    """Build a complete volume with a valid CRC32 and integrity datum.

    ``data`` is the dataset bytes. The integrity datum protects the whole information buffer, so
    a volume built like this passes the authenticated integrity check with ``vmk_key``.
    """
    information = build_information(data, version=version)
    integrity_plaintext = integrity_plaintext or key_datum(
        FVE_DATUM_ROLE.PROPERTY, hashlib.sha256(information).digest(), FVE_KEY_TYPE.VMK
    )
    integrity = ccm_datum(FVE_DATUM_ROLE.PROPERTY, vmk_key, integrity_plaintext)
    validation = c_bde.FVE_VALIDATION(Size=12, Version=2, Crc32=crc32(information)).dumps()

    boot_sector = bytearray(SECTOR_SIZE)
    boot_sector[3:11] = b"-FVE-FS-"
    struct.pack_into("<H", boot_sector, 11, SECTOR_SIZE)
    boot_sector[13] = CLUSTER_SIZE // SECTOR_SIZE
    guid_offset = 0x100
    boot_sector[guid_offset : guid_offset + 16] = INFORMATION_OFFSET_GUID.bytes_le
    struct.pack_into("<QQQ", boot_sector, guid_offset + 16, INFORMATION_OFFSET, 0, 0)

    volume = bytearray(INFORMATION_OFFSET)
    volume[:SECTOR_SIZE] = boot_sector
    volume += information + validation + integrity
    return bytes(volume)


def default_dataset(*, vmk_key: bytes = VMK_KEY, fvek_key: bytes = FVEK_KEY, include_fvek: bool = True) -> bytes:
    """A small valid volume: one clear VMK containing a VMK KEY and encrypted inner KEY."""
    datums = vmk_datum(clear_vmk_properties(vmk_key))
    if include_fvek:
        datums += ccm_datum(
            FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
            vmk_key,
            key_datum(FVE_DATUM_ROLE.PROPERTY, fvek_key, FVE_KEY_TYPE.AES_128),
            counter=3,
        )
    return dataset(datums)


def default_volume(**kwargs) -> bytes:
    vmk_key = kwargs.pop("vmk_key", VMK_KEY)
    return build_volume(default_dataset(vmk_key=vmk_key, **kwargs), vmk_key=vmk_key)


class RecordingReader:
    """File wrapper that records every read request and the furthest offset touched.

    This is a read budget instrument: tests assert on consumed ranges and the final position
    instead of only asserting that *some* exception was raised.
    """

    def __init__(self, data: bytes):
        self.data = data
        self._fh = BytesIO(data)
        self.reads: list[tuple[int, int, int]] = []
        self.max_offset = 0
        self.bytes_read = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def read(self, size: int = -1) -> bytes:
        start = self._fh.tell()
        result = self._fh.read(size)
        self.reads.append((start, size, len(result)))
        self.max_offset = max(self.max_offset, start + len(result))
        self.bytes_read += len(result)
        return result

    def seekable(self) -> bool:
        return True


def minimize(
    mutate: Callable[[bytes], bytes],
    predicate: Callable[[bytes], bool],
    data: bytes,
) -> bytes:
    """Greedily delete chunks from ``data`` while ``predicate(mutate(candidate))`` holds.

    The predicate must reproduce the failure through the real parser, so the result is a minimal
    input that still exhibits the same observable behavior, not merely a byte string that happens
    to be short.
    """
    chunk = max(1, len(data) // 2)
    while chunk >= 1:
        offset = 0
        while offset < len(data):
            candidate = data[:offset] + data[offset + chunk :]
            if candidate and predicate(mutate(candidate)):
                data = candidate
            else:
                offset += chunk
        chunk //= 2
    return data
