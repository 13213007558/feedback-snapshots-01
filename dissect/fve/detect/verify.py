"""Authorized-key verification.

Verification is deliberately separate from detection.  A probe can say "this looks like format X";
only these functions may say "this key belongs to this volume".

Every function returns a :class:`~dissect.fve.detect.contract.VerificationResult` and never raises
for expected failures (wrong key, unsupported variant).  Unexpected exceptions are captured as
``ERROR`` so callers cannot mistake a crash for a rejection.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Mapping
from typing import Any

from dissect.fve.bde import BDE
from dissect.fve.detect.contract import Format, VerificationResult, VerificationStatus
from dissect.fve.luks import LUKS
from dissect.fve.veracrypt.crypto import CIPHERS
from dissect.fve.veracrypt.veracrypt import VeraCrypt

#: Authorized key material supplied by a caller, keyed by credential name.
KeyMaterial = Mapping[str, Any]


def _result(
    fmt: Format,
    status: VerificationStatus,
    method: str,
    detail: str,
    *,
    error: str | None = None,
    **details: Any,
) -> VerificationResult:
    return VerificationResult(fmt, status, method=method, detail=detail, error=error, details=details)


def verify_bde(fh: Any, material: KeyMaterial) -> VerificationResult:
    """Verify a BitLocker key.

    Accepted material keys: ``passphrase``, ``recovery_password``, ``bek`` (file-like object),
    ``external_key`` and ``fvek`` (raw bytes).  Success means the AES-CCM unboxing of the VMK (or
    the FVEK integrity check) authenticated, which is a cryptographic proof.
    """
    method = next(
        (key for key in ("passphrase", "recovery_password", "bek", "external_key", "fvek") if key in material), None
    )
    if method is None:
        return _result(
            Format.BITLOCKER, VerificationStatus.UNSUPPORTED, "none", "no supported BDE key material supplied"
        )
    try:
        bde = BDE(fh)
    except Exception as exc:  # noqa: BLE001
        return _result(Format.BITLOCKER, VerificationStatus.ERROR, method, "could not parse BDE volume", error=str(exc))
    if bde.decrypted:
        # A decrypted volume has no key to prove; report that instead of inventing a verification.
        return _result(
            Format.BITLOCKER,
            VerificationStatus.NOT_APPLICABLE,
            "clear-state",
            "volume is already in the decrypted state; there is no key to verify",
            state=str(bde.information.current_state),
        )
    try:
        if method == "passphrase":
            bde.unlock_with_passphrase(material["passphrase"])
        elif method == "recovery_password":
            bde.unlock_with_recovery_password(material["recovery_password"])
        elif method == "bek":
            bde.unlock_with_bek(_as_stream(material["bek"]))
        elif method == "external_key":
            bde.unlock_with_external_key(material["external_key"])
        elif method == "fvek":
            bde.unlock_with_fvek(material["fvek"])
    except NotImplementedError as exc:
        return _result(
            Format.BITLOCKER, VerificationStatus.UNSUPPORTED, method, "BDE key type not implemented", error=str(exc)
        )
    except ValueError as exc:
        return _result(
            Format.BITLOCKER, VerificationStatus.REJECTED, method, "key rejected by BDE metadata", error=str(exc)
        )
    except Exception as exc:  # noqa: BLE001
        return _result(
            Format.BITLOCKER, VerificationStatus.ERROR, method, "unexpected error during BDE unlock", error=str(exc)
        )

    if not bde.unlocked:
        return _result(
            Format.BITLOCKER, VerificationStatus.REJECTED, method, "BDE did not report an unlocked state"
        )
    return _result(
        Format.BITLOCKER,
        VerificationStatus.VERIFIED,
        method,
        "BDE VMK/FVEK authenticated",
        fvek_type=str(bde._fvek_type),
        state=str(bde.information.current_state),
    )


def verify_luks(fh: Any, material: KeyMaterial) -> VerificationResult:
    """Verify a LUKS key.

    Accepted material keys: ``passphrase`` (str/bytes), ``key_file`` (file-like), ``volume_key``
    (raw bytes plus ``keyslot``).  Success means a keyslot digest matched the derived volume key,
    which is a cryptographic proof.
    """
    method = next((key for key in ("passphrase", "key_file", "volume_key") if key in material), None)
    if method is None:
        return _result(
            Format.LUKS, VerificationStatus.UNSUPPORTED, "none", "no supported LUKS key material supplied"
        )
    try:
        luks = LUKS(fh)
    except Exception as exc:  # noqa: BLE001
        return _result(Format.LUKS, VerificationStatus.ERROR, method, "could not parse LUKS volume", error=str(exc))

    keyslot = material.get("keyslot")
    try:
        if method == "passphrase":
            luks.unlock_with_passphrase(material["passphrase"], keyslot=keyslot)
        elif method == "key_file":
            luks.unlock_with_key_fh(_as_stream(material["key_file"]), keyslot=keyslot)
        else:
            if keyslot is None:
                return _result(
                    Format.LUKS, VerificationStatus.UNSUPPORTED, method, "volume_key requires an explicit keyslot"
                )
            luks.unlock(material["volume_key"], keyslot)
    except NotImplementedError as exc:
        return _result(
            Format.LUKS, VerificationStatus.UNSUPPORTED, method, "LUKS variant not implemented", error=str(exc)
        )
    except ValueError as exc:
        message = str(exc)
        if "Argon2 implementation is not available" in message:
            return _result(Format.LUKS, VerificationStatus.UNSUPPORTED, method, "no Argon2 backend available")
        if "out of memory" in message:
            return _result(Format.LUKS, VerificationStatus.UNSUPPORTED, method, "Argon2 ran out of memory")
        return _result(
            Format.LUKS, VerificationStatus.REJECTED, method, "key rejected by LUKS keyslot digest", error=message
        )
    except RuntimeError as exc:
        return _result(
            Format.LUKS, VerificationStatus.UNSUPPORTED, method, "required crypto backend missing", error=str(exc)
        )
    except Exception as exc:  # noqa: BLE001
        return _result(
            Format.LUKS, VerificationStatus.ERROR, method, "unexpected error during LUKS unlock", error=str(exc)
        )

    if not luks.unlocked:
        return _result(Format.LUKS, VerificationStatus.REJECTED, method, "LUKS did not report an unlocked state")
    return _result(
        Format.LUKS,
        VerificationStatus.VERIFIED,
        method,
        "LUKS volume key matched a keyslot digest",
        keyslot=luks._active_keyslot_id,
        version=luks.header.version,
    )


def verify_veracrypt(fh: Any, material: KeyMaterial, *, is_system: bool = False) -> VerificationResult:
    """Verify a VeraCrypt key.

    Accepted material keys: ``passphrase`` (with optional ``pim``) and ``header_key`` (raw bytes).
    Success means the decrypted header carried the ``VERA`` magic *and* both header CRC32 values
    matched, which is a cryptographic proof.

    VeraCrypt system volumes store the header at sector 62; pass ``is_system=True`` for those.
    """
    method = next((key for key in ("header_key", "passphrase") if key in material), None)
    if method is None:
        return _result(
            Format.VERACRYPT, VerificationStatus.UNSUPPORTED, "none", "no supported VeraCrypt key material supplied"
        )
    try:
        vc = VeraCrypt(fh, is_system=is_system)
    except Exception as exc:  # noqa: BLE001
        return _result(
            Format.VERACRYPT, VerificationStatus.ERROR, method, "could not read VeraCrypt header", error=str(exc)
        )

    try:
        if method == "passphrase":
            vc.unlock_with_passphrase(material["passphrase"], pim=material.get("pim"))
        else:
            vc.unlock_with_header_key(material["header_key"])
    except NotImplementedError as exc:
        return _result(
            Format.VERACRYPT,
            VerificationStatus.UNSUPPORTED,
            method,
            "VeraCrypt variant not implemented",
            error=str(exc),
        )
    except ValueError as exc:
        return _result(
            Format.VERACRYPT, VerificationStatus.REJECTED, method, "VeraCrypt header did not decrypt", error=str(exc)
        )
    except Exception as exc:  # noqa: BLE001
        return _result(
            Format.VERACRYPT,
            VerificationStatus.ERROR,
            method,
            "unexpected error during VeraCrypt unlock",
            error=str(exc),
        )

    if not vc.unlocked or vc.header is None:
        return _result(
            Format.VERACRYPT, VerificationStatus.REJECTED, method, "VeraCrypt did not report an unlocked state"
        )
    ok, detail = _verify_veracrypt_crc(vc)
    if not ok:
        return _result(Format.VERACRYPT, VerificationStatus.ERROR, method, f"header decrypted but {detail}")
    return _result(
        Format.VERACRYPT,
        VerificationStatus.VERIFIED,
        method,
        "VeraCrypt header decrypted, magic and CRC32 fields valid",
        version=vc.version,
        client_version=vc.client_version,
        cipher=str(vc.cipher),
    )


def _verify_veracrypt_crc(vc: VeraCrypt) -> tuple[bool, str]:
    """Re-check the two CRC32 fields of the decrypted VeraCrypt header."""
    header = vc.header
    if header is None:
        return False, "no decrypted header"
    # ``_decrypt_header`` does not expose the plaintext, so recompute it from the ciphertext.
    cipher = next((c for c in CIPHERS if c.__type__ == vc.cipher), None)
    if cipher is None:
        return False, "no cipher implementation for the decrypted header"
    buf = cipher(io.BytesIO(vc.header_ciphertext), vc.header_keys, 0, 512).open().read()
    stored_crc = int.from_bytes(bytes(header.crc32), "big")
    stored_crc_dec = int.from_bytes(bytes(header.crc32_decrypted), "big")
    if (zlib.crc32(buf[192:448]) & 0xFFFFFFFF) != stored_crc:
        return False, "header CRC32 over bytes 192-448 does not match"
    if (zlib.crc32(buf[0:188]) & 0xFFFFFFFF) != stored_crc_dec:
        return False, "decrypted header CRC32 over bytes 0-188 does not match"
    return True, "ok"


def _as_stream(value: Any) -> Any:
    if hasattr(value, "read"):
        return value
    if isinstance(value, (bytes, bytearray)):
        return io.BytesIO(bytes(value))
    raise TypeError(f"expected a binary stream or bytes, got {type(value)!r}")
