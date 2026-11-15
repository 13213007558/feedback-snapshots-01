"""L3 key verification.

A verifier only returns an L3 :class:`Evidence` when the format's *own* cryptographic
check succeeds. Any failure (wrong password, unsupported KDF/cipher, truncated header) is
reported as a non-upgraded result and must never be reinterpreted as "unencrypted".

We deliberately do not implement new decryption; we drive the public dissect.fve APIs and
treat a successful unlock + parser confirmation as the authorisation proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

from dissect.fve.bde.bde import BDE
from dissect.fve.luks.luks import LUKS
from dissect.fve.veracrypt.veracrypt import VeraCrypt

from .contract import Evidence, EvidenceLevel


@dataclass
class VerificationResult:
    verified: bool
    evidence: Evidence | None
    error: str | None = None


def _restore(fh: BinaryIO, start: int) -> None:
    fh.seek(start)


def verify_luks(fh: BinaryIO, passphrase: str | bytes) -> VerificationResult:
    start = fh.tell()
    try:
        luks = LUKS(fh)
        try:
            luks.unlock_with_passphrase(passphrase)
        except Exception as exc:  # wrong passphrase / no usable keyslot
            return VerificationResult(False, None, f"luks unlock rejected: {exc}")
        if not luks.unlocked:
            return VerificationResult(False, None, "luks reported locked after unlock attempt")
        return VerificationResult(
            True,
            Evidence(
                detector="luks_passphrase_verify",
                level=EvidenceLevel.KEY_VERIFIED,
                detail={"active_keyslot": luks._active_keyslot_id},
                supports_claim="LUKS volume key matched stored digest with an authorised passphrase",
            ),
        )
    except Exception as exc:  # header parse failure / unsupported construction
        return VerificationResult(False, None, f"luks verify error: {type(exc).__name__}: {exc}")
    finally:
        _restore(fh, start)


def verify_bde(fh: BinaryIO, passphrase: str) -> VerificationResult:
    start = fh.tell()
    try:
        bde = BDE(fh)
        if not bde.has_passphrase():
            return VerificationResult(
                False, None, "bde volume offers no passphrase protector (recovery key/BEK/FVEK needed)"
            )
        try:
            bde.unlock_with_passphrase(passphrase)
        except Exception as exc:
            return VerificationResult(False, None, f"bde unlock rejected: {exc}")
        if not bde.unlocked:
            return VerificationResult(False, None, "bde reported locked after unlock attempt")
        return VerificationResult(
            True,
            Evidence(
                detector="bde_passphrase_verify",
                level=EvidenceLevel.KEY_VERIFIED,
                detail={"fvek_type": str(bde.information.dataset.fvek_type)},
                supports_claim="BitLocker VMK/FVEK recovered with an authorised passphrase protector",
            ),
        )
    except Exception as exc:
        return VerificationResult(False, None, f"bde verify error: {type(exc).__name__}: {exc}")
    finally:
        _restore(fh, start)


def verify_veracrypt(fh: BinaryIO, passphrase: str) -> VerificationResult:
    start = fh.tell()
    try:
        vc = VeraCrypt(fh)
        try:
            vc.unlock_with_passphrase(passphrase)
        except Exception as exc:
            return VerificationResult(False, None, f"veracrypt unlock rejected: {exc}")
        # The library only flips unlocked when the decrypted header carries the VERA magic,
        # which is the cryptographic confirmation, not the entropy smell test.
        if not vc.unlocked or vc.header is None or vc.header.magic != b"VERA":
            return VerificationResult(False, None, "veracrypt header magic not confirmed after decrypt")
        return VerificationResult(
            True,
            Evidence(
                detector="veracrypt_passphrase_verify",
                level=EvidenceLevel.KEY_VERIFIED,
                detail={
                    "decrypted_header_magic": vc.header.magic.decode("latin-1"),
                    "cipher": vc.cipher,
                    "version": vc.version,
                },
                supports_claim="VeraCrypt header decrypted and VERA magic confirmed with an authorised passphrase",
            ),
        )
    except Exception as exc:
        return VerificationResult(False, None, f"veracrypt verify error: {type(exc).__name__}: {exc}")
    finally:
        _restore(fh, start)
