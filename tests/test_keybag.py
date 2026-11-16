from __future__ import annotations

import gzip
import hashlib
import hmac
import struct
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import Error
from dissect.apfs.objects.keybag import (
    CONVERTED_VOLUME_KEY_FLAG,
    KEK,
    VEK,
    ContainerKeybag,
    Keybag,
    VolumeKeybag,
    _create_cipher,
)
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS

ENCRYPTED_IMAGE = "_data/encrypted.bin.gz"
CONVERTED_IMAGE = "_data/jhfs_encrypted.bin.gz"
PASSWORD = "password"


def _load_container(path: str) -> APFS:
    with gzip.open(absolute_path(path), "rb") as fh:
        return APFS(BytesIO(fh.read()))


def _entry_raw(uuid: bytes, tag: int, data: bytes) -> bytes:
    entry = c_apfs.keybag_entry()
    entry.ke_uuid = uuid
    entry.ke_tag = tag
    entry.ke_keylen = len(data)
    entry.padding = b"\x00" * 4
    raw = entry.dumps() + data
    return raw + b"\x00" * ((16 - len(raw) % 16) % 16)


def _rebuild_keybag(template: Keybag, entries: list[tuple[bytes, int, bytes]]) -> bytes:
    """Rebuild a keybag block with the given (outer uuid, tag, keydata) records."""
    payload = b"".join(_entry_raw(uuid, tag, data) for uuid, tag, data in entries)

    locker = c_apfs.kb_locker()
    locker.kl_version = c_apfs.APFS_KEYBAG_VERSION
    locker.kl_nkeys = len(entries)
    locker.kl_nbytes = len(payload)
    locker.padding = b"\x00" * 8

    media_keybag = c_apfs.media_keybag()
    media_keybag.mk_obj = template.header
    media_keybag.mk_locker = locker

    block = bytearray(media_keybag.dumps() + payload)
    block += b"\x00" * (len(template.block) - len(block))
    return bytes(block)


def _aes_wrap(kek: bytes, plaintext: bytes, iv: int = 0xA6A6A6A6A6A6A6A6) -> bytes:
    """AES key wrapping (RFC3394), the inverse of ``keybag.aes_unwrap``."""
    quad = struct.Struct(">Q")
    n = len(plaintext) // 8
    blocks = [None] + [plaintext[i * 8 : (i + 1) * 8] for i in range(n)]
    a = iv
    encrypt = _create_cipher(kek, mode="ecb").encrypt
    for j in range(6):
        for i in range(1, n + 1):
            b = encrypt(quad.pack(a) + blocks[i])
            a = quad.unpack(b[:8])[0] ^ (n * j + i)
            blocks[i] = b[8:]
    return quad.pack(a) + b"".join(blocks[1:])


def _record_hmac(record: KEK | VEK) -> bytes:
    return hmac.digest(
        hashlib.sha256(b"\x01\x16\x20\x17\x15\x05" + record["salt"].native).digest(),
        record["blob"].dump(),
        "sha256",
    )


def _container_entries(container: APFS) -> list[tuple[bytes, int, bytes]]:
    return [(entry.ke_uuid, entry.ke_tag, entry.ke_keydata) for entry in container.keybag.entries.values()]


def _volume_entries(volume: FS) -> list[tuple[bytes, int, bytes]]:
    return [(entry.ke_uuid, entry.ke_tag, entry.ke_keydata) for entry in volume.keybag.entries.values()]


def _install_container_keybag(container: APFS, block: bytes) -> ContainerKeybag:
    keybag = ContainerKeybag(container, 0, block=block)
    container.sb.__dict__["keylocker"] = keybag
    return keybag


def _install_volume_keybag(volume: FS, block: bytes) -> VolumeKeybag:
    keybag = VolumeKeybag(volume.container, 0, block=block)
    volume.__dict__["keybag"] = keybag
    return keybag


def _vek_data(container: APFS, volume_uuid: bytes) -> bytes:
    return container.keybag.entries[(volume_uuid, c_apfs.KB_TAG.VOLUME_KEY.value)].ke_keydata


def _kek_data(volume: FS, volume_uuid: bytes) -> bytes:
    return volume.keybag.entries[(volume_uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value)].ke_keydata


def test_unlock_valid_volume_reads_known_file() -> None:
    """A correctly bound, intact keybag unlocks and exposes the known test file."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]

    assert volume.is_encrypted
    volume.unlock(PASSWORD)
    assert volume._cipher is not None

    assert volume.get("dir/file").open().read().decode() == " File System\n"


def test_unlock_tampered_vek_hmac_is_rejected() -> None:
    """A correct password must not unlock when the VEK HMAC has been modified."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    vek = VEK.load(_vek_data(container, volume_uuid))
    assert vek.verify()
    vek["hmac"] = b"\x00" * len(vek["hmac"].native)
    assert not vek.verify()

    entries = [
        (uuid, tag, vek.dump() if tag == c_apfs.KB_TAG.VOLUME_KEY.value else data)
        for uuid, tag, data in _container_entries(container)
    ]
    _install_container_keybag(container, _rebuild_keybag(container.keybag, entries))

    with pytest.raises(Error, match="VEK.*HMAC") as exc_info:
        volume.unlock(PASSWORD)

    assert "VEK" in str(exc_info.value)
    assert volume._cipher is None


def test_unlock_vek_outer_identity_mismatch_is_rejected() -> None:
    """The VEK record must be bound to the volume through its outer keybag UUID."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]

    foreign_uuid = uuid4().bytes_le
    entries = [
        (foreign_uuid if tag == c_apfs.KB_TAG.VOLUME_KEY.value else uuid, tag, data)
        for uuid, tag, data in _container_entries(container)
    ]
    _install_container_keybag(container, _rebuild_keybag(container.keybag, entries))

    with pytest.raises(Error, match="No VEK found for this volume"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None


def test_unlock_vek_inner_identity_mismatch_is_rejected() -> None:
    """A VEK blob whose inner UUID names another volume is rejected at the verification stage."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    vek = VEK.load(_vek_data(container, volume_uuid))
    vek["blob"]["uuid"] = uuid4().bytes_le
    # Re-sign so the HMAC passes and the inner identity binding is what rejects the record.
    vek["hmac"] = _record_hmac(vek)
    assert vek.verify()

    entries = [
        (uuid, tag, vek.dump() if tag == c_apfs.KB_TAG.VOLUME_KEY.value else data)
        for uuid, tag, data in _container_entries(container)
    ]
    _install_container_keybag(container, _rebuild_keybag(container.keybag, entries))

    with pytest.raises(Error, match="VEK.*UUID"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None


def test_unlock_kek_outer_inner_identity_mismatch_is_rejected() -> None:
    """A KEK entry whose outer UUID no longer matches its blob UUID must be rejected."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]

    foreign_uuid = uuid4().bytes_le
    entries = [
        (foreign_uuid if tag == c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value else uuid, tag, data)
        for uuid, tag, data in _volume_entries(volume)
    ]
    _install_volume_keybag(volume, _rebuild_keybag(volume.keybag, entries))

    with pytest.raises(Error, match="KEK.*UUID"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None


def test_unlock_tampered_kek_hmac_is_rejected() -> None:
    """A modified KEK blob must be rejected at the HMAC stage."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    kek = KEK.load(_kek_data(volume, volume_uuid))
    kek["hmac"] = b"\x00" * len(kek["hmac"].native)
    assert not kek.verify()

    entries = [
        (uuid, tag, kek.dump() if tag == c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value else data)
        for uuid, tag, data in _volume_entries(volume)
    ]
    _install_volume_keybag(volume, _rebuild_keybag(volume.keybag, entries))

    with pytest.raises(Error, match="KEK.*HMAC"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None


def test_unlock_multi_user_records_each_unlock() -> None:
    """Multiple legitimate user KEKs can be tried; both valid records unlock the volume."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    original = KEK.load(_kek_data(volume, volume_uuid))

    # Derive a second, distinct user KEK that wraps the same underlying key with the same password.
    second_user_uuid = uuid4().bytes_le
    second_kek = KEK.load(_kek_data(volume, volume_uuid))
    wrapping_key = hashlib.pbkdf2_hmac(
        "sha256",
        PASSWORD.encode(),
        second_kek["blob"]["salt"].native,
        second_kek["blob"]["iterations"].native,
        dklen=32,
    )
    second_kek["blob"]["uuid"] = second_user_uuid
    second_kek["blob"]["wrapped"] = _aes_wrap(wrapping_key, original.unwrap(PASSWORD))
    second_kek["hmac"] = _record_hmac(second_kek)
    assert second_kek.verify()
    assert second_kek.uuid != original.uuid

    entries = [
        (entry_uuid, tag, data)
        for entry_uuid, tag, data in _volume_entries(volume)
        if tag != c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value
    ]
    entries.append((volume_uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value, original.dump()))
    entries.append((second_user_uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value, second_kek.dump()))
    _install_volume_keybag(volume, _rebuild_keybag(volume.keybag, entries))

    # Default iteration tries every valid record and succeeds.
    volume.unlock(PASSWORD)
    assert volume._cipher is not None
    assert volume.get("dir/file").open().read().decode() == " File System\n"

    # Selecting the second inner user UUID explicitly also unlocks.
    volume._cipher = None
    volume.unlock(PASSWORD, uuid=second_kek.uuid)
    assert volume._cipher is not None
    assert volume.get("dir/file").open().read().decode() == " File System\n"


def test_unlock_duplicate_conflicting_records_are_rejected() -> None:
    """Conflicting records sharing one (uuid, tag) must not be silently overwritten in order."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    kek_data = _kek_data(volume, volume_uuid)
    conflicting = KEK.load(kek_data)
    conflicting["hmac"] = b"\x01" * len(conflicting["hmac"].native)

    entries = [
        (volume_uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value, kek_data),
        (volume_uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value, conflicting.dump()),
    ]
    block = _rebuild_keybag(volume.keybag, entries)

    with pytest.raises(Error, match="Conflicting keybag records"):
        VolumeKeybag(volume.container, 0, block=block)


def test_unlock_wrong_password_keeps_generic_error_and_no_cipher() -> None:
    """A wrong password leaves no cipher behind and reports only the unlock failure."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]

    with pytest.raises(Error, match="Failed to unlock volume"):
        volume.unlock("definitely-not-the-password")

    assert volume._cipher is None
    with pytest.raises(Error, match="unlock volume first"):
        volume.get("dir/file")


def test_failed_reunlock_does_not_keep_previous_cipher() -> None:
    """A failed re-unlock must invalidate a previously working cipher."""
    container = _load_container(ENCRYPTED_IMAGE)
    volume = container.volumes[0]
    volume.unlock(PASSWORD)
    assert volume._cipher is not None

    with pytest.raises(Error):
        volume.unlock("wrong-password")

    assert volume._cipher is None


def test_converted_volume_flag_path_unlocks() -> None:
    """The converted-volume flag path (128-bit wrapped keys) validates and unlocks."""
    container = _load_container(CONVERTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    vek = VEK.load(_vek_data(container, volume_uuid))
    kek = KEK.load(_kek_data(volume, volume_uuid))
    assert vek.flags & CONVERTED_VOLUME_KEY_FLAG
    assert kek.flags & CONVERTED_VOLUME_KEY_FLAG
    assert vek.verify() and kek.verify()

    volume.unlock(PASSWORD)
    assert volume._cipher is not None
    assert volume.get("dir/file").open().read().decode() == " File System\n"


def test_converted_volume_flag_mismatch_is_rejected() -> None:
    """A KEK and VEK disagreeing on the converted-volume flag cannot be used together."""
    container = _load_container(CONVERTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    kek = KEK.load(_kek_data(volume, volume_uuid))
    # Clear the converted flag in the info field (first uint32) and re-sign the blob.
    info = bytearray(kek["blob"]["info"].native)
    info[:4] = (0).to_bytes(4, "little")
    kek["blob"]["info"] = bytes(info)
    kek["hmac"] = _record_hmac(kek)
    assert kek.verify()

    entries = [
        (uuid, tag, kek.dump() if tag == c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value else data)
        for uuid, tag, data in _volume_entries(volume)
    ]
    _install_volume_keybag(volume, _rebuild_keybag(volume.keybag, entries))

    with pytest.raises(Error, match="flag mismatch"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None


def test_converted_volume_inner_uuid_mismatch_is_rejected() -> None:
    """On a converted volume the KEK inner crypto UUID must match the VEK inner crypto UUID."""
    container = _load_container(CONVERTED_IMAGE)
    volume = container.volumes[0]
    volume_uuid = volume.object.apfs_vol_uuid

    kek = KEK.load(_kek_data(volume, volume_uuid))
    vek = VEK.load(_vek_data(container, volume_uuid))
    assert kek.uuid == vek.uuid

    # Give the KEK blob a different crypto UUID but keep the converted flag and a valid HMAC.
    kek["blob"]["uuid"] = uuid4().bytes_le
    kek["hmac"] = _record_hmac(kek)
    assert kek.verify()
    assert kek.uuid != vek.uuid

    entries = [
        (uuid, tag, kek.dump() if tag == c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value else data)
        for uuid, tag, data in _volume_entries(volume)
    ]
    _install_volume_keybag(volume, _rebuild_keybag(volume.keybag, entries))

    with pytest.raises(Error, match="KEK.*VEK.*UUID"):
        volume.unlock(PASSWORD)
    assert volume._cipher is None
