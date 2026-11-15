from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.fve.bde.c_bde import FVE_KEY_PROTECTOR

if TYPE_CHECKING:
    import datetime

    from dissect.fve.bde.c_tpm import c_tpm
    from dissect.fve.bde.information import VmkInfoDatum

# The protector type is encoded in the high byte of the VMK priority field.
_PROTECTOR_TYPE_MASK = 0xFF00


class ProtectorType(Enum):
    """Normalized classification of a BitLocker key protector.

    The numeric values are stable identifiers suitable for reporting; they are not the on-disk priority values.
    """

    CLEAR_KEY = "clear_key"
    TPM = "tpm"
    TPM_PIN = "tpm_pin"
    EXTERNAL_BEK = "external_bek"
    RECOVERY_PASSWORD = "recovery_password"
    PASSPHRASE = "passphrase"
    UNKNOWN = "unknown"


class UnlockAvailability(Enum):
    """What (if anything) is additionally required before this protector can unlock the volume."""

    # All required material is present in the volume metadata itself.
    NO_ADDITIONAL_MATERIAL = "no_additional_material"
    # A matching external startup key (BEK file or raw external key) has to be supplied.
    NEEDS_MATCHING_BEK = "needs_matching_bek"
    # A user passphrase has to be supplied.
    NEEDS_PASSPHRASE = "needs_passphrase"
    # A recovery password has to be supplied.
    NEEDS_RECOVERY_PASSWORD = "needs_recovery_password"
    # Unlocking requires hardware (such as a TPM) or is not supported by this implementation.
    NEEDS_HARDWARE_OR_UNSUPPORTED = "needs_hardware_or_unsupported"


class Protector:
    """Read-only view of a BitLocker volume master key protector.

    Only exposes metadata that is visible without performing key derivation or decryption. No key material,
    salts, password-derived values or other reusable secrets are exposed, and constructing a protector never
    changes the unlock state of the underlying volume.
    """

    def __init__(self, vmk: VmkInfoDatum):
        self._vmk = vmk

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} identifier={self.identifier} "
            f"protector_type={self.protector_type.value} availability={self.availability.value}>"
        )

    @property
    def datum(self) -> VmkInfoDatum:
        """Return the VMK datum this protector was derived from."""
        return self._vmk

    @property
    def identifier(self) -> UUID:
        """Return the protector identifier stored in the VMK datum."""
        return self._vmk.identifier

    @property
    def created(self) -> datetime.datetime:
        """Return the creation timestamp stored in the VMK datum."""
        return self._vmk.datetime

    @property
    def key_protector(self) -> FVE_KEY_PROTECTOR:
        """Return the raw key protector flag as stored in the VMK priority field."""
        return self._vmk.priority

    @property
    def protector_type(self) -> ProtectorType:
        """Return the normalized protector type.

        TPM with PIN (including enhanced PIN) is never classified as a regular passphrase, and priorities with
        an unknown protector type are reported as :class:`ProtectorType.UNKNOWN`.
        """
        priority = self._vmk.priority.value
        if priority <= 0xFF:
            return ProtectorType.CLEAR_KEY

        # Match the full protector byte exactly so that priorities with unknown bits stay unknown instead of
        # being folded into a known, bitwise-overlapping protector such as TPM with PIN.
        masked_priority = priority & _PROTECTOR_TYPE_MASK
        tpm_pin_priorities = (
            FVE_KEY_PROTECTOR.TPM_PIN.value,
            FVE_KEY_PROTECTOR.TPM_PIN.value | FVE_KEY_PROTECTOR.TPM.value,
        )
        if masked_priority in tpm_pin_priorities:
            return ProtectorType.TPM_PIN
        if masked_priority == FVE_KEY_PROTECTOR.TPM.value:
            return ProtectorType.TPM
        if masked_priority == FVE_KEY_PROTECTOR.EXTERNAL.value:
            return ProtectorType.EXTERNAL_BEK
        if masked_priority == FVE_KEY_PROTECTOR.RECOVERY_PASSWORD.value:
            return ProtectorType.RECOVERY_PASSWORD
        if masked_priority == FVE_KEY_PROTECTOR.PASSPHRASE.value:
            return ProtectorType.PASSPHRASE
        return ProtectorType.UNKNOWN

    @property
    def availability(self) -> UnlockAvailability:
        """Return which additional material, if any, is required to use this protector."""
        protector_type = self.protector_type
        if protector_type == ProtectorType.CLEAR_KEY:
            return UnlockAvailability.NO_ADDITIONAL_MATERIAL
        if protector_type == ProtectorType.EXTERNAL_BEK:
            return UnlockAvailability.NEEDS_MATCHING_BEK
        if protector_type == ProtectorType.PASSPHRASE:
            return UnlockAvailability.NEEDS_PASSPHRASE
        if protector_type == ProtectorType.RECOVERY_PASSWORD:
            return UnlockAvailability.NEEDS_RECOVERY_PASSWORD
        return UnlockAvailability.NEEDS_HARDWARE_OR_UNSUPPORTED

    @property
    def unlock_method(self) -> str | None:
        """Return the name of the supported ``BDE`` unlock method, or ``None`` if it cannot be unlocked."""
        return {
            ProtectorType.CLEAR_KEY: "unlock_with_clear_key",
            ProtectorType.EXTERNAL_BEK: "unlock_with_bek",
            ProtectorType.PASSPHRASE: "unlock_with_passphrase",
            ProtectorType.RECOVERY_PASSWORD: "unlock_with_recovery_password",
        }.get(self.protector_type)

    @property
    def label(self) -> str | None:
        """Return the optional protector label stored in a unicode datum."""
        return self._vmk.label()

    @property
    def enhanced_pin(self) -> bool:
        """Return whether this protector uses an enhanced PIN."""
        return self._vmk.is_enhanced_pin()

    @property
    def enhanced_crypto(self) -> bool:
        """Return whether this protector uses the enhanced crypto (Win10 1511+) stretch key."""
        return self._vmk.is_enhanced_crypto()

    @property
    def uses_pbkdf2(self) -> bool:
        """Return whether the stretch key of this protector is PBKDF2 based."""
        return self._vmk.uses_pbkdf2()

    @property
    def pcr_profile(self) -> list[c_tpm.PCR_BITMAP] | None:
        """Return the TPM PCR validation profile, or ``None`` when the protector has no TPM policy."""
        tpm_blob = self._vmk.tpm_encrypted_blob()
        if tpm_blob is None:
            return None
        return tpm_blob.pcr_policy

    @property
    def pcr_digest_algorithm(self) -> str | None:
        """Return the TPM PCR digest algorithm name, or ``None`` when the protector has no TPM policy."""
        tpm_blob = self._vmk.tpm_encrypted_blob()
        if tpm_blob is None:
            return None
        return tpm_blob.pcr_digest_algo
