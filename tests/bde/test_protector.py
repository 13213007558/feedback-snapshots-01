from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.bde.bde import BDE
from dissect.fve.bde.information import VmkInfoDatum
from dissect.fve.bde.protector import Protector, ProtectorType, UnlockAvailability
from tests._util import open_file_gz
from tests.bde.metadata import DUMMY_CLEAR_KEY, DUMMY_KEY, DUMMY_MAC, DUMMY_NONCE, DUMMY_SALT

if TYPE_CHECKING:
    import pytest


def _protectors_by_type(bde_obj: BDE) -> dict[ProtectorType, Protector]:
    return {protector.protector_type: protector for protector in bde_obj.protectors}


def test_protector_listing_mixed_metadata(bde_mixed_protectors: BinaryIO) -> None:
    bde_obj = BDE(bde_mixed_protectors)

    protectors = bde_obj.protectors
    assert len(protectors) == 7

    by_type = _protectors_by_type(bde_obj)
    assert set(by_type) == {
        ProtectorType.CLEAR_KEY,
        ProtectorType.EXTERNAL_BEK,
        ProtectorType.PASSPHRASE,
        ProtectorType.RECOVERY_PASSWORD,
        ProtectorType.TPM,
        ProtectorType.TPM_PIN,
        ProtectorType.UNKNOWN,
    }

    expected = {
        ProtectorType.CLEAR_KEY: (
            UnlockAvailability.NO_ADDITIONAL_MATERIAL,
            "unlock_with_clear_key",
        ),
        ProtectorType.EXTERNAL_BEK: (
            UnlockAvailability.NEEDS_MATCHING_BEK,
            "unlock_with_bek",
        ),
        ProtectorType.PASSPHRASE: (
            UnlockAvailability.NEEDS_PASSPHRASE,
            "unlock_with_passphrase",
        ),
        ProtectorType.RECOVERY_PASSWORD: (
            UnlockAvailability.NEEDS_RECOVERY_PASSWORD,
            "unlock_with_recovery_password",
        ),
        ProtectorType.TPM: (
            UnlockAvailability.NEEDS_HARDWARE_OR_UNSUPPORTED,
            None,
        ),
        ProtectorType.TPM_PIN: (
            UnlockAvailability.NEEDS_HARDWARE_OR_UNSUPPORTED,
            None,
        ),
        ProtectorType.UNKNOWN: (
            UnlockAvailability.NEEDS_HARDWARE_OR_UNSUPPORTED,
            None,
        ),
    }

    for protector_type, (availability, unlock_method) in expected.items():
        protector = by_type[protector_type]
        assert protector.availability == availability
        assert protector.unlock_method == unlock_method
        assert protector.identifier.version == 4


def test_protector_keeps_datum_source(bde_mixed_protectors: BinaryIO) -> None:
    bde_obj = BDE(bde_mixed_protectors)

    dataset_datums = bde_obj.information.dataset.data
    vmk_identifiers = {datum.identifier for datum in dataset_datums if isinstance(datum, VmkInfoDatum)}

    for protector in bde_obj.protectors:
        # Each protector retains the exact VMK datum it was derived from, including its identifier.
        assert protector.datum in dataset_datums
        assert protector.identifier == protector.datum.identifier
        assert protector.identifier in vmk_identifiers

    assert len({protector.datum for protector in bde_obj.protectors}) == len(bde_obj.protectors)
    assert len(vmk_identifiers) == len(bde_obj.protectors)


def test_tpm_pin_is_not_passphrase(bde_mixed_protectors: BinaryIO) -> None:
    bde_obj = BDE(bde_mixed_protectors)
    by_type = _protectors_by_type(bde_obj)

    tpm_pin = by_type[ProtectorType.TPM_PIN]
    assert tpm_pin.protector_type == ProtectorType.TPM_PIN
    assert tpm_pin.protector_type != ProtectorType.PASSPHRASE
    assert tpm_pin.enhanced_pin is True
    assert tpm_pin.unlock_method is None
    assert tpm_pin.availability == UnlockAvailability.NEEDS_HARDWARE_OR_UNSUPPORTED

    unknown = by_type[ProtectorType.UNKNOWN]
    assert unknown.protector_type == ProtectorType.UNKNOWN
    assert unknown.protector_type != ProtectorType.PASSPHRASE
    assert unknown.unlock_method is None


def test_tpm_policy_is_visible(bde_mixed_protectors: BinaryIO) -> None:
    bde_obj = BDE(bde_mixed_protectors)
    by_type = _protectors_by_type(bde_obj)

    tpm = by_type[ProtectorType.TPM]
    assert tpm.pcr_digest_algorithm == "sha256"
    assert [pcr.value for pcr in tpm.pcr_profile] == [0, 1, 2]

    passphrase = by_type[ProtectorType.PASSPHRASE]
    assert passphrase.pcr_profile is None
    assert passphrase.pcr_digest_algorithm is None


def test_listing_does_not_derive_or_unlock(bde_mixed_protectors: BinaryIO, monkeypatch: pytest.MonkeyPatch) -> None:
    bde_obj = BDE(bde_mixed_protectors)

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("protector listing must not perform key derivation or decryption")

    monkeypatch.setattr("dissect.fve.bde.bde.stretch", fail)
    monkeypatch.setattr("dissect.fve.bde.bde.derive_user_key", fail)
    monkeypatch.setattr("dissect.fve.bde.bde.derive_recovery_key", fail)
    monkeypatch.setattr(bde_obj, "unlock", fail)

    assert bde_obj.unlocked is False
    protectors = bde_obj.protectors
    assert len(protectors) == 7
    assert bde_obj.unlocked is False
    assert bde_obj._fvek is None
    assert bde_obj._vmk is None


def test_listing_exposes_no_secret_material(bde_mixed_protectors: BinaryIO) -> None:
    bde_obj = BDE(bde_mixed_protectors)

    rendered = []
    for protector in bde_obj.protectors:
        rendered.append(repr(protector))
        rendered.append(str(protector.identifier))
        rendered.append(protector.protector_type.value)
        rendered.append(protector.availability.value)
        rendered.append(protector.label or "")
        rendered.append(protector.pcr_digest_algorithm or "")
        rendered.append(str(protector.key_protector.value))

    blob = "\n".join(rendered)
    for secret in (DUMMY_SALT, DUMMY_KEY, DUMMY_MAC, DUMMY_NONCE, DUMMY_CLEAR_KEY):
        assert secret.hex() not in blob
        assert secret not in blob.encode()


def test_protector_listing_real_passphrase_volume(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("protector listing must not derive or stretch any key material")

    monkeypatch.setattr("dissect.fve.bde.bde.stretch", fail)
    monkeypatch.setattr("dissect.fve.bde.bde.derive_user_key", fail)

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_128.bin.gz") as fh:
        bde_obj = BDE(fh)
        protectors = bde_obj.protectors

        assert len(protectors) == 1
        protector = protectors[0]
        assert protector.protector_type == ProtectorType.PASSPHRASE
        assert protector.availability == UnlockAvailability.NEEDS_PASSPHRASE
        assert protector.unlock_method == "unlock_with_passphrase"
        assert protector.pcr_profile is None
        assert protector.key_protector == bde_obj.vmk_types[0]
        assert protector.identifier == bde_obj.identifiers[0]

        # Repeated reads return fresh views backed by the same VMK datums and keep the volume locked.
        again = bde_obj.protectors
        assert [p.identifier for p in again] == [protector.identifier]
        assert again[0].datum is protector.datum
        assert bde_obj.unlocked is False


def test_protector_listing_real_recovery_and_external_volumes() -> None:
    expectations = {
        "_data/bde/recovery_password.bin.gz": {
            ProtectorType.RECOVERY_PASSWORD,
            ProtectorType.PASSPHRASE,
        },
        "_data/bde/recovery_key.bin.gz": {
            ProtectorType.EXTERNAL_BEK,
            ProtectorType.PASSPHRASE,
        },
        "_data/bde/startup_key.bin.gz": {
            ProtectorType.EXTERNAL_BEK,
            ProtectorType.PASSPHRASE,
        },
        "_data/bde/vista.bin.gz": {
            ProtectorType.EXTERNAL_BEK,
            ProtectorType.RECOVERY_PASSWORD,
        },
    }

    for filename, expected_types in expectations.items():
        with contextlib.contextmanager(open_file_gz)(filename) as fh:
            bde_obj = BDE(fh)
            assert {p.protector_type for p in bde_obj.protectors} == expected_types
            assert bde_obj.unlocked is False


def test_protector_listing_clear_key_volume() -> None:
    with contextlib.contextmanager(open_file_gz)("_data/bde/suspended.bin.gz") as fh:
        bde_obj = BDE(fh)
        protectors = bde_obj.protectors

        assert len(protectors) == 1
        protector = protectors[0]
        assert protector.protector_type == ProtectorType.CLEAR_KEY
        assert protector.availability == UnlockAvailability.NO_ADDITIONAL_MATERIAL
        assert protector.unlock_method == "unlock_with_clear_key"
        # Listing the clear key protector must not unlock the volume or expose the key itself.
        assert bde_obj.unlocked is False
        clear_key_datum = protector.datum.clear_key()
        assert clear_key_datum is not None
        assert clear_key_datum.data.hex() not in repr(protector)


def test_protector_listing_decrypted_volume() -> None:
    with contextlib.contextmanager(open_file_gz)("_data/bde/decrypted.bin.gz") as fh:
        bde_obj = BDE(fh)
        assert bde_obj.protectors == []
