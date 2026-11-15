from __future__ import annotations

from binascii import crc32
from io import BytesIO
from typing import BinaryIO
from uuid import UUID, uuid4

from dissect.fve.bde.c_bde import (
    BITLOCKER_SIGNATURE,
    FVE_DATUM_ROLE,
    FVE_DATUM_TYPE,
    FVE_KEY_FLAG,
    FVE_KEY_PROTECTOR,
    FVE_KEY_TYPE,
    FVE_STATE,
    INFORMATION_OFFSET_GUID,
    c_bde,
)
from dissect.fve.bde.c_tpm import c_tpm

SECTOR_SIZE = 512
DATASET_START_OFFSET = len(c_bde.FVE_DATASET)

# Distinct dummy material, used to assert secret bytes never surface in a protector listing.
DUMMY_SALT = bytes.fromhex("0123456789abcdef0123456789abcdef")
DUMMY_KEY = bytes(range(0x20))
DUMMY_NONCE = bytes(range(0x0C))
DUMMY_MAC = bytes(range(0x10, 0x20))
DUMMY_CLEAR_KEY = bytes(range(0x30, 0x50))


def _datum(role: FVE_DATUM_ROLE, type_: FVE_DATUM_TYPE, payload: bytes, flags: int = 0) -> bytes:
    size = len(c_bde.FVE_DATUM) + len(payload)
    return c_bde.FVE_DATUM(Size=size, Role=role.value, Type=type_.value, Flags=flags).dumps() + payload


def _aes_ccm_datum() -> bytes:
    payload = (
        c_bde.FVE_DATUM_AESCCM_ENC(
            Nonce=c_bde.FVE_NONCE(DateTime=0, Counter=0),
            MAC=DUMMY_MAC,
        ).dumps()
        + DUMMY_NONCE
    )
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY, payload)


def _stretch_key_datum(key_type: FVE_KEY_TYPE, key_flags: FVE_KEY_FLAG = FVE_KEY_FLAG.NONE) -> bytes:
    payload = c_bde.FVE_DATUM_STRETCH_KEY(KeyType=key_type.value, KeyFlags=key_flags.value, Salt=DUMMY_SALT).dumps()
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.STRETCH_KEY, payload)


def _use_key_datum() -> bytes:
    nested_header = c_bde.FVE_DATUM(
        Size=len(c_bde.FVE_DATUM_USE_KEY),
        Role=FVE_DATUM_ROLE.PROPERTY.value,
        Type=FVE_DATUM_TYPE.USE_KEY.value,
        Flags=0,
    ).dumps()
    payload = (
        nested_header
        + c_bde.USHORT(FVE_KEY_TYPE.EXTERNAL.value).dumps()
        + c_bde.USHORT(FVE_KEY_FLAG.NONE.value).dumps()
    )
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.USE_KEY, payload)


def _key_datum(material: bytes) -> bytes:
    payload = c_bde.FVE_DATUM_KEY(KeyType=FVE_KEY_TYPE.VMK.value, KeyFlags=FVE_KEY_FLAG.NONE.value).dumps() + material
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.KEY, payload)


def _unicode_datum(text: str) -> bytes:
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.UNICODE, text.encode("utf-16-le") + b"\x00\x00")


def _tpm_blob_datum(pcr_bitmap: bytes, digest: bytes) -> bytes:
    payload = c_tpm.FVE_DATUM_TPM_ENC_BLOB(
        PcrBitmap=int.from_bytes(pcr_bitmap, "little"),
        PublicSize=0,
        Public=b"",
        PrivateSize=0,
        Private=b"",
        PcrDigestSize=len(digest),
        PcrDigest=digest,
        PcrBitmapSize=len(pcr_bitmap),
        PcrBitmap2=pcr_bitmap,
    ).dumps()
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.TPM_ENCRYPTED_BLOB, payload)


def _vmk_datum(identifier: UUID, priority: FVE_KEY_PROTECTOR, properties: list[bytes]) -> bytes:
    payload = c_bde.FVE_DATUM_VMK_INFO(
        Identifier=identifier.bytes_le,
        DateTime=0,
        VmkHints=0,
        Priority=priority.value,
    ).dumps() + b"".join(properties)
    return _datum(FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO, payload)


def _build_vmk_datums() -> list[bytes]:
    clear_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.CLEAR,
        [_key_datum(DUMMY_CLEAR_KEY), _aes_ccm_datum()],
    )
    external_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.EXTERNAL,
        [_unicode_datum("ExternalKey"), _use_key_datum(), _aes_ccm_datum()],
    )
    passphrase_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.PASSPHRASE,
        [_stretch_key_datum(FVE_KEY_TYPE.STRETCH_KEY_1), _aes_ccm_datum()],
    )
    recovery_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.RECOVERY_PASSWORD,
        [_unicode_datum("DiskPassword"), _stretch_key_datum(FVE_KEY_TYPE.STRETCH_KEY), _aes_ccm_datum()],
    )
    tpm_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.TPM,
        [_tpm_blob_datum(b"\x07", DUMMY_KEY), _aes_ccm_datum()],
    )
    tpm_pin_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR.TPM | FVE_KEY_PROTECTOR.TPM_PIN,
        [
            _tpm_blob_datum(b"\x07", DUMMY_KEY),
            _stretch_key_datum(FVE_KEY_TYPE.AES_CCM_256_2, FVE_KEY_FLAG.ENHANCED_PIN),
            _aes_ccm_datum(),
        ],
    )
    unknown_vmk = _vmk_datum(
        uuid4(),
        FVE_KEY_PROTECTOR(0x7700),
        [_aes_ccm_datum()],
    )
    return [clear_vmk, external_vmk, passphrase_vmk, recovery_vmk, tpm_vmk, tpm_pin_vmk, unknown_vmk]


def _build_information(vmk_datums: list[bytes]) -> bytes:
    dataset_identification = uuid4()
    datum_blob = b"".join(vmk_datums)
    end_offset = DATASET_START_OFFSET + len(datum_blob)

    dataset = (
        c_bde.FVE_DATASET(
            Size=end_offset,
            Version=1,
            StartOffset=DATASET_START_OFFSET,
            EndOffset=end_offset,
            Identification=dataset_identification.bytes_le,
            NonceCounter=0,
            FvekType=FVE_KEY_TYPE.AES_XTS_128.value,
            FvekPrefType=FVE_KEY_TYPE.AES_XTS_128.value,
            CreationTime=0,
        ).dumps()
        + datum_blob
    )

    # Information.size (the region covered by the CRC) is HeaderSize shifted left by 4 for version >= 2.
    information_size = (len(c_bde.FVE_INFORMATION) + len(dataset) + 0xF) & ~(SECTOR_SIZE - 1)
    header_size = information_size >> 4
    information = (
        c_bde.FVE_INFORMATION(
            Signature=BITLOCKER_SIGNATURE,
            HeaderSize=header_size,
            Version=2,
            CurrentState=FVE_STATE.ENCRYPTED.value,
            NextState=FVE_STATE.ENCRYPTED.value,
            StateOffset=0,
            StateSize=0,
            VirtualizedSectors=0,
            InformationOffset=[0, 0, 0],
        ).dumps()
        + dataset
    ).ljust(information_size, b"\x00")

    validation = c_bde.FVE_VALIDATION(Size=len(c_bde.FVE_VALIDATION), Version=2, Crc32=crc32(information)).dumps()

    block = information + validation
    return block.ljust(((len(block) + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE, b"\x00")


def build_mixed_protector_volume() -> BinaryIO:
    """Build an in-memory BDE volume whose metadata contains every supported protector type."""
    information_block = _build_information(_build_vmk_datums())
    block_sectors = len(information_block) // SECTOR_SIZE

    information_offsets = [
        SECTOR_SIZE * 8,
        SECTOR_SIZE * (8 + block_sectors),
        SECTOR_SIZE * (8 + 2 * block_sectors),
    ]
    recognition = c_bde.FVE_GUID_RECOGNITION(
        Guid=INFORMATION_OFFSET_GUID.bytes_le,
        InformationOffset=information_offsets,
    ).dumps()

    boot_sector = bytearray(SECTOR_SIZE)
    boot_sector[0xA0 : 0xA0 + len(recognition)] = recognition

    volume = BytesIO()
    volume.write(boot_sector)
    for offset in information_offsets:
        volume.seek(offset)
        volume.write(information_block)

    volume.seek(0)
    return volume
