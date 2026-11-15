from __future__ import annotations

import gzip
import json
import struct
from io import BytesIO
from types import SimpleNamespace
from uuid import uuid4

import pytest

from dissect.fve.bde import BDE, Protector, ProtectorRequirement, ProtectorType, ProtectorUnlock
from dissect.fve.bde import bde as bde_module
from dissect.fve.bde.c_bde import (
    FVE_DATUM_ROLE,
    FVE_DATUM_TYPE,
    FVE_KEY_FLAG,
    FVE_KEY_PROTECTOR,
    FVE_KEY_TYPE,
    FVE_STATE,
)
from dissect.fve.bde.information import Dataset
from dissect.fve.bde.protector import _classify
from tests._util import absolute_path

FVEK_TYPE = FVE_KEY_TYPE.AES_XTS_128
SECRET = b"\xde\xad\xbe\xef" * 8


def _datum(role: FVE_DATUM_ROLE, type_: FVE_DATUM_TYPE, data: bytes, flags: int = 0) -> bytes:
    return struct.pack("<HHHH", 8 + len(data), role, type_, flags) + data


def _unicode(text: str) -> bytes:
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.UNICODE, text.encode("utf-16-le"))


def _stretch_key(key_type: FVE_KEY_TYPE, key_flags: FVE_KEY_FLAG = FVE_KEY_FLAG.NONE) -> bytes:
    data = struct.pack("<HH16s", key_type, key_flags, b"S" * 16)
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.STRETCH_KEY, data)


def _use_key(key_type: FVE_KEY_TYPE = FVE_KEY_TYPE.EXTERNAL) -> bytes:
    data = b"\x00" * 8 + struct.pack("<HH", key_type, 0)
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.USE_KEY, data)


def _clear_key() -> bytes:
    return _datum(FVE_DATUM_ROLE.PROPERTY, FVE_DATUM_TYPE.KEY, struct.pack("<HH", FVE_KEY_TYPE.VMK, 0))


def _aes_ccm_encrypted_key() -> bytes:
    # A nonce and MAC followed by opaque encrypted key material.
    return _datum(
        FVE_DATUM_ROLE.PROPERTY,
        FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
        b"\x00" * 20 + b"M" * 16 + SECRET,
    )


def _tpm_blob() -> bytes:
    # The TPM blob structure is big endian.
    return _datum(
        FVE_DATUM_ROLE.PROPERTY,
        FVE_DATUM_TYPE.TPM_ENCRYPTED_BLOB,
        struct.pack(">IH", 0x03, 0) + struct.pack(">H", 0) + struct.pack(">H", 32) + b"D" * 32 + b"\x01\x03",
    )


def _vmk(priority: int, properties: list[bytes], label: str | None = None) -> bytes:
    props = list(properties)
    if label is not None:
        props.insert(0, _unicode(label))

    data = struct.pack("<16sQHH", uuid4().bytes_le, 0, 0, priority) + b"".join(props)
    return _datum(FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO, data)


def _mixed_dataset() -> Dataset:
    datums = [
        _vmk(int(FVE_KEY_PROTECTOR.CLEAR), [_clear_key(), _aes_ccm_encrypted_key()], "PausedClearkey"),
        _vmk(
            int(FVE_KEY_PROTECTOR.RECOVERY_PASSWORD),
            [_stretch_key(FVE_KEY_TYPE.STRETCH_KEY, FVE_KEY_FLAG.PBKDF2), _aes_ccm_encrypted_key()],
            "RecoveryPassword",
        ),
        _vmk(int(FVE_KEY_PROTECTOR.EXTERNAL), [_use_key(), _aes_ccm_encrypted_key()], "ExternalKey"),
        _vmk(
            int(FVE_KEY_PROTECTOR.PASSPHRASE),
            [_stretch_key(FVE_KEY_TYPE.STRETCH_KEY), _aes_ccm_encrypted_key()],
            "UserPassphrase",
        ),
        _vmk(
            int(FVE_KEY_PROTECTOR.PASSPHRASE),
            [_stretch_key(FVE_KEY_TYPE.STRETCH_KEY), _aes_ccm_encrypted_key()],
            "SecondPassphrase",
        ),
        _vmk(int(FVE_KEY_PROTECTOR.TPM), [_tpm_blob(), _aes_ccm_encrypted_key()], "Tpm"),
        _vmk(
            int(FVE_KEY_PROTECTOR.TPM_PIN),
            [_stretch_key(FVE_KEY_TYPE.AES_CCM_256_2, FVE_KEY_FLAG.ENHANCED_PIN), _tpm_blob()],
            "EnhancedPin",
        ),
        _vmk(0x3000, [_aes_ccm_encrypted_key()], "UnknownProtector"),
    ]

    body = b"".join(datums)
    size = 48 + len(body)
    header = struct.pack(
        "<IIII16sIHHQ",
        size,
        0x0002,
        48,
        size,
        uuid4().bytes_le,
        0,
        int(FVEK_TYPE),
        int(FVEK_TYPE),
        0,
    )
    assert len(header) == 48

    return Dataset(BytesIO(header + body))


def _metadata_bde(dataset: Dataset) -> BDE:
    bde = object.__new__(BDE)
    bde.information = SimpleNamespace(dataset=dataset, current_state=FVE_STATE.ENCRYPTED)
    bde._vmk_datum = None
    bde._vmk = None
    bde._fvek_datum = None
    bde._fvek_type = None
    bde._fvek = None
    return bde


def _by_label(protectors: list[Protector]) -> dict[str, Protector]:
    return {protector.label: protector for protector in protectors}


def test_protector_mixed_metadata_capabilities() -> None:
    bde = _metadata_bde(_mixed_dataset())

    protectors = bde.protectors
    assert len(protectors) == 8
    assert all(isinstance(protector, Protector) for protector in protectors)

    by_label = _by_label(protectors)

    clear = by_label["PausedClearkey"]
    assert clear.type is ProtectorType.CLEAR_KEY
    assert clear.unlock_method is ProtectorUnlock.CLEAR_KEY
    assert clear.requirement is ProtectorRequirement.NONE
    assert clear.supported

    recovery = by_label["RecoveryPassword"]
    assert recovery.type is ProtectorType.RECOVERY_PASSWORD
    assert recovery.unlock_method is ProtectorUnlock.RECOVERY_PASSWORD
    assert recovery.requirement is ProtectorRequirement.RECOVERY_PASSWORD
    assert recovery.pbkdf2

    external = by_label["ExternalKey"]
    assert external.type is ProtectorType.EXTERNAL_KEY
    assert external.unlock_method is ProtectorUnlock.BEK
    assert external.requirement is ProtectorRequirement.BEK

    passphrase = by_label["UserPassphrase"]
    assert passphrase.type is ProtectorType.PASSPHRASE
    assert passphrase.unlock_method is ProtectorUnlock.PASSPHRASE
    assert passphrase.requirement is ProtectorRequirement.PASSPHRASE
    assert by_label["SecondPassphrase"].type is ProtectorType.PASSPHRASE

    tpm = by_label["Tpm"]
    assert tpm.type is ProtectorType.TPM
    assert tpm.unlock_method is None
    assert tpm.requirement is ProtectorRequirement.HARDWARE
    assert not tpm.supported
    assert tpm.pcr_policy is not None
    assert [int(pcr) for pcr in tpm.pcr_policy] == [0, 1]
    assert tpm.pcr_digest_algo == "sha256"

    enhanced_pin = by_label["EnhancedPin"]
    assert enhanced_pin.type is ProtectorType.ENHANCED_PIN
    assert enhanced_pin.type is not ProtectorType.PASSPHRASE
    assert enhanced_pin.enhanced_pin
    assert enhanced_pin.unlock_method is None
    assert enhanced_pin.requirement is ProtectorRequirement.HARDWARE
    assert not enhanced_pin.supported

    unknown = by_label["UnknownProtector"]
    assert unknown.type is ProtectorType.UNKNOWN
    assert unknown.unlock_method is None
    assert unknown.requirement is ProtectorRequirement.UNSUPPORTED
    assert not unknown.supported


def test_protector_retains_distinct_datum_sources() -> None:
    protectors = _metadata_bde(_mixed_dataset()).protectors

    assert len({protector.identifier for protector in protectors}) == len(protectors)
    assert len({id(protector.datum) for protector in protectors}) == len(protectors)
    assert len({protector.datum_index for protector in protectors}) == len(protectors)
    assert all(protector.source is protector.datum for protector in protectors)
    assert all(protector.datum_source is protector.datum for protector in protectors)
    dataset = _mixed_dataset()
    assert all(
        protector.source is dataset.data[protector.datum_index]  # type: ignore[index]
        for protector in _metadata_bde(dataset).protectors
    )

    passphrases = [protector for protector in protectors if protector.type is ProtectorType.PASSPHRASE]
    assert len(passphrases) == 2
    assert passphrases[0].datum is not passphrases[1].datum
    assert passphrases[0].identifier != passphrases[1].identifier


def test_protector_inventory_does_not_leak_key_material() -> None:
    bde = _metadata_bde(_mixed_dataset())

    result = json.dumps([protector.to_dict() for protector in bde.protectors])
    assert SECRET.hex() not in result
    assert "deadbeef" not in result
    assert "encrypted" not in result.lower()

    for protector in bde.protectors:
        assert SECRET.hex() not in repr(protector)
        assert "deadbeef" not in repr(protector)
        dumped = protector.to_dict()
        assert all(not isinstance(value, bytes) for value in dumped.values())
        assert dumped["source"]["type"] == "VOLUME_MASTER_KEY_INFO"
        assert dumped["source"]["size"] > 0


def test_protector_inventory_reads_without_unlocking_or_deriving(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("protector inventory must not derive keys or unlock the volume")

    monkeypatch.setattr(bde_module, "stretch", boom)
    monkeypatch.setattr(bde_module, "derive_user_key", boom)
    monkeypatch.setattr(bde_module, "derive_recovery_key", boom)
    monkeypatch.setattr(bde_module.BDE, "unlock", boom)
    monkeypatch.setattr(bde_module.BDE, "open", boom)

    bde = _metadata_bde(_mixed_dataset())

    protectors = bde.protectors
    assert len(protectors) == 8
    assert not bde.unlocked
    assert bde._fvek is None
    assert bde._vmk is None


def test_protector_inventory_on_real_volume_does_not_modify_state() -> None:
    with gzip.open(absolute_path("_data/bde/aes_128.bin.gz"), "rb") as fh:
        bde = BDE(fh)

        assert not bde.unlocked
        assert bde._fvek is None
        assert bde._vmk is None

        protectors = bde.protectors
        assert len(protectors) == 1
        assert protectors[0].type is ProtectorType.PASSPHRASE
        assert protectors[0].unlock_method is ProtectorUnlock.PASSPHRASE
        assert protectors[0].identifier == bde.identifiers[0]

        assert not bde.unlocked
        assert bde._fvek is None
        assert bde._vmk is None

        assert bde.protector_inventory() == protectors


def test_protector_clear_priority_bounds() -> None:
    assert _classify(0x0000, False) is ProtectorType.CLEAR_KEY
    assert _classify(0x00FF, False) is ProtectorType.CLEAR_KEY
    assert _classify(0x0100, False) is ProtectorType.TPM
    assert _classify(0x0500, False) is ProtectorType.TPM_PIN
    assert _classify(0x0800, False) is ProtectorType.RECOVERY_PASSWORD
    assert _classify(0x2000, False) is ProtectorType.PASSPHRASE
    assert _classify(0x2000, True) is ProtectorType.ENHANCED_PIN
    assert _classify(0x0400, True) is ProtectorType.ENHANCED_PIN
    assert _classify(0x0100, True) is ProtectorType.TPM
    assert _classify(0x3000, False) is ProtectorType.UNKNOWN


@pytest.mark.parametrize(
    ("fixture_name", "expected_types"),
    [
        ("bde_suspended", [ProtectorType.CLEAR_KEY]),
        ("bde_win7_partial", [ProtectorType.EXTERNAL_KEY, ProtectorType.RECOVERY_PASSWORD, ProtectorType.CLEAR_KEY]),
        ("bde_vista", [ProtectorType.EXTERNAL_KEY, ProtectorType.RECOVERY_PASSWORD]),
    ],
)
def test_protector_inventory_real_mixed_volumes(
    request: pytest.FixtureRequest,
    fixture_name: str,
    expected_types: list[ProtectorType],
) -> None:
    bde = BDE(request.getfixturevalue(fixture_name))
    assert not bde.unlocked

    protectors = bde.protectors
    assert [protector.type for protector in protectors] == expected_types
    assert [protector.identifier for protector in protectors] == bde.identifiers
    assert len({id(protector.datum) for protector in protectors}) == len(protectors)

    assert not bde.unlocked
    assert bde._fvek is None
    assert bde._vmk is None


def test_protector_inventory_preserves_an_unlocked_volume() -> None:
    with gzip.open(absolute_path("_data/bde/aes_128.bin.gz"), "rb") as fh:
        bde = BDE(fh).unlock_with_passphrase("password12!@")
        fvek = bde._fvek
        vmk = bde._vmk

        protectors = bde.protectors
        assert len(protectors) == 1
        assert protectors[0].supported
        assert bde.unlocked
        assert bde._fvek is fvek
        assert bde._vmk is vmk
