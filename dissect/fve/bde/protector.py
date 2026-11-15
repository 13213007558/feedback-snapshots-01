from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from dissect.fve.bde.c_bde import FVE_KEY_FLAG, FVE_KEY_PROTECTOR

if TYPE_CHECKING:
    from uuid import UUID

    from dissect.fve.bde.c_tpm import PCR_BITMAP
    from dissect.fve.bde.information import VmkInfoDatum


class ProtectorType(str, Enum):
    """The kind of key protector declared by a BitLocker VMK datum."""

    CLEAR_KEY = "clear_key"
    TPM = "tpm"
    TPM_PIN = "tpm_pin"
    RECOVERY_PASSWORD = "recovery_password"
    PASSPHRASE = "passphrase"
    ENHANCED_PIN = "enhanced_pin"
    EXTERNAL_KEY = "external_key"
    UNKNOWN = "unknown"


class ProtectorUnlock(str, Enum):
    """An unlock entry point currently implemented by :class:`dissect.fve.bde.BDE`."""

    CLEAR_KEY = "clear_key"
    RECOVERY_PASSWORD = "recovery_password"
    PASSPHRASE = "passphrase"
    BEK = "bek"


class ProtectorRequirement(str, Enum):
    """The additional material or capability needed to use a protector."""

    NONE = "none"
    RECOVERY_PASSWORD = "recovery_password"
    PASSPHRASE = "passphrase"
    BEK = "bek"
    HARDWARE = "hardware"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ProtectorPolicy:
    """Policy data visible in a protector's metadata.

    Only values that are already stored in the protector metadata are exposed. No key material is
    included.
    """

    priority: int
    label: str | None = None
    vmk_hints: int = 0
    pcr_policy: tuple[PCR_BITMAP, ...] | None = None
    pcr_digest_algo: str | None = None
    pcr_bitmap: int | None = None
    enhanced_pin: bool = False
    enhanced_crypto: bool = False
    pbkdf2: bool = False


@dataclass(frozen=True)
class Protector:
    """A read-only description of a BitLocker key protector.

    The ``datum`` attribute retains the exact VMK datum this protector was parsed from, so multiple
    protectors of the same type remain distinguishable. It is excluded from the representation and
    from :meth:`to_dict` so inventory output cannot leak encrypted key material.
    """

    identifier: UUID
    type: ProtectorType
    unlock_method: ProtectorUnlock | None
    requirement: ProtectorRequirement
    policy: ProtectorPolicy
    datum: VmkInfoDatum = field(repr=False, compare=False)
    datum_index: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_vmk(cls, vmk: VmkInfoDatum, datum_index: int | None = None) -> Protector:
        """Build a protector description from a VMK info datum without deriving keys."""
        priority = int(vmk.priority)
        protector_type = _classify(priority, vmk.is_enhanced_pin())
        unlock_method, requirement = _capability(protector_type)

        stretch_keys = vmk.stretch_keys()
        tpm_blob = vmk.tpm_encrypted_blob()
        policy = ProtectorPolicy(
            priority=priority,
            label=vmk.label(),
            vmk_hints=vmk.vmk_hints,
            pcr_policy=tuple(tpm_blob.pcr_policy) if tpm_blob else None,
            pcr_digest_algo=tpm_blob.pcr_digest_algo if tpm_blob else None,
            pcr_bitmap=int(tpm_blob.pcr_bitmap) if tpm_blob else None,
            enhanced_pin=vmk.is_enhanced_pin(),
            enhanced_crypto=vmk.is_enhanced_crypto(),
            pbkdf2=any(stretch_key.key_flags & FVE_KEY_FLAG.PBKDF2 for stretch_key in stretch_keys),
        )

        return cls(
            identifier=vmk.identifier,
            type=protector_type,
            unlock_method=unlock_method,
            requirement=requirement,
            policy=policy,
            datum=vmk,
            datum_index=datum_index,
        )

    def __repr__(self) -> str:
        unlock_method = self.unlock_method.value if self.unlock_method is not None else None
        return (
            f"<{self.__class__.__name__} identifier={self.identifier} type={self.type.value} "
            f"requirement={self.requirement.value} unlock_method={unlock_method}>"
        )

    @property
    def supported(self) -> bool:
        """Return whether the current implementation has an unlock path for this protector."""
        return self.unlock_method is not None

    @property
    def method(self) -> ProtectorUnlock | None:
        """Alias for :attr:`unlock_method`."""
        return self.unlock_method

    @property
    def kind(self) -> ProtectorType:
        """Alias for :attr:`type`."""
        return self.type

    @property
    def requires(self) -> ProtectorRequirement:
        """Alias for :attr:`requirement`."""
        return self.requirement

    @property
    def source(self) -> VmkInfoDatum:
        """Return the VMK datum this protector was parsed from."""
        return self.datum

    @property
    def datum_source(self) -> VmkInfoDatum:
        """Alias for :attr:`datum`."""
        return self.datum

    @property
    def priority(self) -> int:
        """Return the raw protector priority value."""
        return self.policy.priority

    @property
    def label(self) -> str | None:
        """Return the visible protector label, if present."""
        return self.policy.label

    @property
    def pcr_policy(self) -> tuple[PCR_BITMAP, ...] | None:
        """Return the PCR validation profile, if this is a TPM protector."""
        return self.policy.pcr_policy

    @property
    def pcr_digest_algo(self) -> str | None:
        """Return the TPM PCR digest algorithm, if available."""
        return self.policy.pcr_digest_algo

    @property
    def enhanced_pin(self) -> bool:
        """Return whether this protector uses an enhanced PIN."""
        return self.policy.enhanced_pin

    @property
    def enhanced_crypto(self) -> bool:
        """Return whether this protector uses enhanced crypto."""
        return self.policy.enhanced_crypto

    @property
    def pbkdf2(self) -> bool:
        """Return whether this protector uses PBKDF2."""
        return self.policy.pbkdf2

    def to_dict(self) -> dict[str, object]:
        """Return a serializable inventory entry without key material or derived secrets."""
        return {
            "identifier": str(self.identifier),
            "type": self.type.value,
            "unlock_method": self.unlock_method.value if self.unlock_method is not None else None,
            "requirement": self.requirement.value,
            "supported": self.supported,
            "source": {
                "index": self.datum_index,
                "role": self.datum.role.name,
                "type": self.datum.type.name,
                "size": self.datum.size,
            },
            "policy": {
                "priority": self.policy.priority,
                "label": self.policy.label,
                "vmk_hints": self.policy.vmk_hints,
                "pcr_policy": [int(pcr) for pcr in self.policy.pcr_policy]
                if self.policy.pcr_policy is not None
                else None,
                "pcr_bitmap": self.policy.pcr_bitmap,
                "pcr_digest_algo": self.policy.pcr_digest_algo,
                "enhanced_pin": self.policy.enhanced_pin,
                "enhanced_crypto": self.policy.enhanced_crypto,
                "pbkdf2": self.policy.pbkdf2,
            },
        }


_PROTECTOR_TYPES = {
    int(FVE_KEY_PROTECTOR.TPM): ProtectorType.TPM,
    int(FVE_KEY_PROTECTOR.EXTERNAL): ProtectorType.EXTERNAL_KEY,
    int(FVE_KEY_PROTECTOR.TPM_PIN): ProtectorType.TPM_PIN,
    int(FVE_KEY_PROTECTOR.TPM | FVE_KEY_PROTECTOR.TPM_PIN): ProtectorType.TPM_PIN,
    int(FVE_KEY_PROTECTOR.RECOVERY_PASSWORD): ProtectorType.RECOVERY_PASSWORD,
    int(FVE_KEY_PROTECTOR.PASSPHRASE): ProtectorType.PASSPHRASE,
}

_ENHANCED_PIN_TYPES = (ProtectorType.TPM_PIN, ProtectorType.PASSPHRASE)


def _classify(priority: int, enhanced_pin: bool) -> ProtectorType:
    if priority <= 0xFF:
        result = ProtectorType.CLEAR_KEY
    else:
        result = _PROTECTOR_TYPES.get(priority & 0xFF00, ProtectorType.UNKNOWN)

    # An enhanced PIN has different unlock semantics from a normal passphrase. Keep it as a distinct
    # type even when the priority alone would suggest a passphrase protector.
    if enhanced_pin and result in _ENHANCED_PIN_TYPES:
        result = ProtectorType.ENHANCED_PIN

    return result


def _capability(protector_type: ProtectorType) -> tuple[ProtectorUnlock | None, ProtectorRequirement]:
    if protector_type is ProtectorType.CLEAR_KEY:
        return ProtectorUnlock.CLEAR_KEY, ProtectorRequirement.NONE
    if protector_type is ProtectorType.RECOVERY_PASSWORD:
        return ProtectorUnlock.RECOVERY_PASSWORD, ProtectorRequirement.RECOVERY_PASSWORD
    if protector_type is ProtectorType.PASSPHRASE:
        return ProtectorUnlock.PASSPHRASE, ProtectorRequirement.PASSPHRASE
    if protector_type is ProtectorType.EXTERNAL_KEY:
        return ProtectorUnlock.BEK, ProtectorRequirement.BEK
    if protector_type in (ProtectorType.TPM, ProtectorType.TPM_PIN, ProtectorType.ENHANCED_PIN):
        return None, ProtectorRequirement.HARDWARE
    return None, ProtectorRequirement.UNSUPPORTED
