"""
Verifiable, lossless migration of pre-stable Double Ratchet JSON state.

The pre-stable serialization format (releases older than 1.0.0) stored the internal state of a whole
:class:`~doubleratchet.double_ratchet.DoubleRatchet` in a different shape than the stable pydantic models.
:func:`~doubleratchet.migrations.parse_double_ratchet_model` already performs the field-level translation.
This module adds the operational safeguards required around that translation:

* A read-only :func:`preflight_check` that inspects an archive *before* anything is written, classifies it as
  pre-stable or stable, reports what would be migrated and refuses archives that are structurally invalid, of
  ambiguous version or internally contradictory.
* A :func:`migrate_json_file` routine that keeps the original file untouched on failure, writes atomically and
  keeps a backup on success.
* Strict parsing that rejects unknown versions and unexpected fields instead of silently ignoring them.

The code in this module never generates cryptographic material. Missing private or public keys are reported as
errors, never replaced with freshly generated/random values. None of the reporting functions return or print
private keys, chain keys or skipped message keys.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .migrations import InconsistentSerializationException, parse_double_ratchet_model
from .models import DoubleRatchetModel
from .types import JSONObject


__all__ = [
    "PRE_STABLE",
    "STABLE",
    "UNKNOWN_FORMAT",
    "MigrationError",
    "PreflightReport",
    "MigrationResult",
    "detect_format",
    "preflight_check",
    "strict_parse_double_ratchet",
    "migrate_json",
    "migrate_json_file",
    "redact_archive"
]


PRE_STABLE = "pre-stable"
STABLE = "stable"
UNKNOWN_FORMAT = "unknown"


# The exact set of fields expected in each pre-stable nesting level. Anything else means the archive comes
# from a different/unknown serializer and must not be migrated on assumptions. The pre-stable pydantic base
# class additionally emitted a "super": null marker in nested objects, which is accepted only when null.
_PRE_STABLE_TOP_FIELDS = frozenset({"super", "skr", "ad", "smks"})
_PRE_STABLE_DHR_FIELDS = frozenset({"super", "root_chain", "own_key", "other_pub"})
_PRE_STABLE_KEYPAIR_FIELDS = frozenset({"super", "priv", "pub"})
_PRE_STABLE_CHAIN_FIELDS = frozenset({"length", "key"})
_PRE_STABLE_SKR_FIELDS = frozenset({"super", "schain", "rchain", "prev_schain_length"})
_STABLE_TOP_FIELDS = frozenset({"version", "diffie_hellman_ratchet", "skipped_message_keys"})
_SUPPORTED_STABLE_VERSIONS = frozenset({"1.0.0", "1.0.1"})

_X25519_PUB_LEN = 32
_X448_PUB_LEN = 56
_X25519_PRIV_LEN = 32
_X448_PRIV_LEN = 56
_CHAIN_KEY_LEN = 32
_MESSAGE_KEY_LEN = 32


class MigrationError(Exception):
    """
    Raised when an archive cannot be migrated losslessly.

    The original file is never modified by code that raises this exception. The message describes the problem
    without containing any secret key material.
    """


@dataclass(frozen=True)
class PreflightReport:
    """
    The result of :func:`preflight_check`.

    Attributes:
        file_format: One of :data:`PRE_STABLE`, :data:`STABLE` or :data:`UNKNOWN_FORMAT`.
        migratable: ``True`` only if the archive can be migrated without losing information.
        errors: Fatal problems that block migration. Each entry is a short, secret-free description.
        warnings: Non-fatal observations worth surfacing (the migration still proceeds).
        summary: Secret-free, structural facts about the archive (key counts, chain lengths, ...).
    """

    file_format: str
    migratable: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    @property
    def needs_migration(self) -> bool:
        """Whether the archive is pre-stable and therefore has to be translated to the stable format."""

        return self.file_format == PRE_STABLE and self.migratable


@dataclass(frozen=True)
class MigrationResult:
    """
    The result of :func:`migrate_json_file`.

    Attributes:
        output_path: The path of the newly written stable JSON file.
        backup_path: The path of the verbatim copy of the original file (always present on success).
        report: The :class:`PreflightReport` that authorized the migration.
        migrated: The migrated, stable JSON-serializable state (contains secret key material by design).
    """

    output_path: str
    backup_path: str
    report: PreflightReport
    migrated: JSONObject


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _check_legacy_marker(node: Mapping[str, Any], label: str, errors: List[str]) -> None:
    """The pre-stable base-class marker 'super' is only tolerated when it is explicitly null."""

    if "super" in node and node["super"] is not None:
        errors.append(f"The 'super' legacy marker in the {label} section must be null.")


def detect_format(serialized: Any) -> str:
    """
    Classify a parsed JSON archive without raising.

    Args:
        serialized: The result of :func:`json.loads` on an archive.

    Returns:
        :data:`PRE_STABLE` for version-less pre-stable state, :data:`STABLE` for versioned stable state or
        :data:`UNKNOWN_FORMAT` if the shape matches neither.
    """

    if not _is_mapping(serialized):
        return UNKNOWN_FORMAT

    keys = frozenset(serialized.keys())
    if "version" in serialized:
        if keys <= _STABLE_TOP_FIELDS and _is_mapping(serialized.get("diffie_hellman_ratchet")):
            return STABLE
        return UNKNOWN_FORMAT

    if keys == _PRE_STABLE_TOP_FIELDS:
        return PRE_STABLE
    return UNKNOWN_FORMAT


def _b64_decode(value: Any) -> Optional[bytes]:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value.encode("ASCII"), validate=True)
    except (binascii.Error, ValueError):
        return None


def _check_chain(chain: Any, label: str, errors: List[str], warnings: List[str]) -> None:
    if chain is None:
        return
    if not _is_mapping(chain) or frozenset(chain.keys()) != _PRE_STABLE_CHAIN_FIELDS:
        errors.append(f"The {label} chain is malformed (expected exactly 'length' and 'key').")
        return
    if not isinstance(chain["length"], int) or isinstance(chain["length"], bool) or chain["length"] < 0:
        errors.append(f"The {label} chain length must be a non-negative integer.")
    decoded = _b64_decode(chain["key"])
    if decoded is None:
        errors.append(f"The {label} chain key is not valid base64.")
    elif len(decoded) != _CHAIN_KEY_LEN:
        errors.append(f"The {label} chain key must decode to {_CHAIN_KEY_LEN} bytes, got {len(decoded)}.")


def _check_keypair(
    keypair: Any,
    label: str,
    require_priv: bool,
    require_pub: bool,
    errors: List[str],
    warnings: List[str]
) -> Tuple[Optional[bytes], Optional[bytes]]:
    if not _is_mapping(keypair) or frozenset(keypair.keys()) != _PRE_STABLE_KEYPAIR_FIELDS:
        errors.append(f"The {label} key pair is malformed (expected exactly 'priv' and 'pub').")
        return None, None
    _check_legacy_marker(keypair, label, errors)

    priv_bytes = _b64_decode(keypair["priv"]) if keypair["priv"] is not None else None
    pub_bytes = _b64_decode(keypair["pub"]) if keypair["pub"] is not None else None

    if require_priv and keypair["priv"] is None:
        errors.append(f"The {label} private key is missing; it cannot be reconstructed without the secret.")
    elif keypair["priv"] is not None and priv_bytes is None:
        errors.append(f"The {label} private key is not valid base64.")

    if require_pub and keypair["pub"] is None:
        errors.append(f"The {label} public key is missing; out-of-order messages would be undecryptable.")
    elif keypair["pub"] is not None and pub_bytes is None:
        errors.append(f"The {label} public key is not valid base64.")

    return priv_bytes, pub_bytes


def _public_from_private(priv: bytes) -> Optional[bytes]:
    try:
        if len(priv) == _X25519_PRIV_LEN:
            return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
        if len(priv) == _X448_PRIV_LEN:
            return X448PrivateKey.from_private_bytes(priv).public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
    except Exception:  # noqa: BLE001 - an invalid key is reported, never raised with key material
        return None
    return None


def _is_known_public_key(pub: bytes) -> bool:
    try:
        if len(pub) == _X25519_PUB_LEN:
            X25519PublicKey.from_public_bytes(pub)
            return True
        if len(pub) == _X448_PUB_LEN:
            X448PublicKey.from_public_bytes(pub)
            return True
    except Exception:  # noqa: BLE001
        return False
    return False


def _validate_pre_stable(serialized: Mapping[str, Any]) -> Tuple[List[str], List[str], Dict[str, Any]]:
    errors: List[str] = []
    warnings: List[str] = []
    summary: Dict[str, Any] = {}

    dhr = serialized["super"]
    skr = serialized["skr"]
    smks = serialized["smks"]
    associated_data = serialized["ad"]

    if not _is_mapping(dhr) or frozenset(dhr.keys()) != _PRE_STABLE_DHR_FIELDS:
        errors.append("The 'super' (Diffie-Hellman ratchet) section has an unexpected field set.")
        return errors, warnings, summary
    if not _is_mapping(skr) or frozenset(skr.keys()) != _PRE_STABLE_SKR_FIELDS:
        errors.append("The 'skr' (symmetric-key ratchet) section has an unexpected field set.")
        return errors, warnings, summary
    _check_legacy_marker(dhr, "Diffie-Hellman ratchet", errors)
    _check_legacy_marker(skr, "symmetric-key ratchet", errors)
    if not isinstance(smks, Mapping):
        errors.append("The 'smks' section must be a JSON object of skipped message keys.")
        return errors, warnings, summary
    if not isinstance(associated_data, str):
        errors.append("The 'ad' (associated data) must be a base64 string.")

    own_priv, own_pub = _check_keypair(dhr["own_key"], "own ratchet", True, False, errors, warnings)
    other_priv, other_pub = _check_keypair(
        dhr["other_pub"], "recipient ratchet", False, True, errors, warnings
    )

    if other_priv is not None:
        warnings.append("The recipient key pair carries a private key, which is unusual and is ignored by the"
                        " ratchet; only its public key is used.")

    # The own key pair must be internally consistent: the stored public key has to match the private key.
    if own_priv is not None and own_pub is not None:
        derived_pub = _public_from_private(own_priv)
        if derived_pub is None:
            errors.append("The own ratchet private key is not a valid X25519/X448 key.")
        elif derived_pub != own_pub:
            errors.append(
                "The own ratchet public key does not match the stored private key (contradictory key pair)."
            )
    elif own_priv is not None:
        derived_pub = _public_from_private(own_priv)
        if derived_pub is None:
            errors.append("The own ratchet private key is not a valid X25519/X448 key.")

    if other_pub is not None and not _is_known_public_key(other_pub):
        errors.append("The recipient ratchet public key is not a valid X25519/X448 public key.")

    _check_chain(dhr["root_chain"], "root", errors, warnings)
    _check_chain(skr["schain"], "sending", errors, warnings)
    _check_chain(skr["rchain"], "receiving", errors, warnings)

    # A usable ratchet always has a sending chain; the receiving chain may legitimately be absent early on.
    if skr.get("schain") is None:
        errors.append("No sending chain is present; the instance is not fully initialized and cannot resume"
                      " sending.")
    if not isinstance(skr.get("prev_schain_length"), (type(None), int)) or \
            isinstance(skr.get("prev_schain_length"), bool):
        errors.append("The previous sending chain length must be an integer or null.")
    elif skr["prev_schain_length"] is not None and skr["prev_schain_length"] < 0:
        errors.append("The previous sending chain length must not be negative.")

    # Validate every skipped message key entry, including the JSON-encoded (pub, index) dictionary key.
    smk_pubs: List[bytes] = []
    smk_indices: Dict[bytes, List[int]] = {}
    for raw_key, raw_message_key in smks.items():
        if not isinstance(raw_key, str):
            errors.append("A skipped message key entry has a non-string key.")
            continue
        try:
            key_obj = json.loads(raw_key)
        except (json.JSONDecodeError, TypeError):
            errors.append("A skipped message key has a key that is not valid JSON.")
            continue
        if not _is_mapping(key_obj) or frozenset(key_obj.keys()) != frozenset({"pub", "index"}):
            errors.append(
                "A skipped message key has an unexpected key structure (expected 'pub' and 'index')."
            )
            continue
        ratchet_pub = _b64_decode(key_obj["pub"])
        index = key_obj["index"]
        if ratchet_pub is None:
            errors.append("A skipped message key references a ratchet public key that is not valid base64.")
            continue
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            errors.append("A skipped message key has a non-integer or negative index.")
            continue
        message_key = _b64_decode(raw_message_key)
        if message_key is None:
            errors.append("A skipped message key value is not valid base64.")
        elif len(message_key) != _MESSAGE_KEY_LEN:
            errors.append(
                f"A skipped message key must decode to {_MESSAGE_KEY_LEN} bytes, got {len(message_key)}."
            )
        if not _is_known_public_key(ratchet_pub):
            errors.append("A skipped message key references an unrecognized ratchet public key.")
        smk_pubs.append(ratchet_pub)
        smk_indices.setdefault(ratchet_pub, []).append(index)

    # Duplicate (ratchet_pub, index) pairs would mean two different keys for the same message position.
    for ratchet_pub, indices in smk_indices.items():
        if len(indices) != len(set(indices)):
            errors.append("Two skipped message keys share the same ratchet public key and index (ambiguous"
                          " state).")

    summary.update({
        "format": PRE_STABLE,
        "skipped_message_keys": len(smks),
        "distinct_skipped_ratchet_pubs": len(set(smk_pubs)),
        "has_sending_chain": skr.get("schain") is not None,
        "has_receiving_chain": skr.get("rchain") is not None,
        "sending_chain_length": None if skr.get("schain") is None else skr["schain"]["length"],
        "receiving_chain_length": None if skr.get("rchain") is None else skr["rchain"]["length"],
        "root_chain_length": dhr["root_chain"]["length"],
        "previous_sending_chain_length": skr.get("prev_schain_length"),
        "own_key_sizes": _key_sizes(own_priv, own_pub),
        "recipient_pub_size": None if other_pub is None else len(other_pub)
    })
    return errors, warnings, summary


def _key_sizes(priv: Optional[bytes], pub: Optional[bytes]) -> Dict[str, Optional[int]]:
    return {"private": None if priv is None else len(priv), "public": None if pub is None else len(pub)}


def _validate_stable(serialized: Mapping[str, Any]) -> Tuple[List[str], List[str], Dict[str, Any]]:
    errors: List[str] = []
    warnings: List[str] = []
    summary: Dict[str, Any] = {}

    if frozenset(serialized.keys()) != _STABLE_TOP_FIELDS:
        errors.append("The stable archive has unexpected top-level fields.")
    version = serialized.get("version")
    if version not in _SUPPORTED_STABLE_VERSIONS:
        errors.append(f"Unsupported or ambiguous stable serialization version: {version!r}.")

    try:
        model = DoubleRatchetModel.model_validate(serialized)
    except Exception as exc:  # noqa: BLE001 - surface a clean, secret-free message
        errors.append(f"The stable archive fails model validation: {exc.__class__.__name__}.")
        return errors, warnings, summary

    skr = model.diffie_hellman_ratchet.symmetric_key_ratchet
    summary.update({
        "format": STABLE,
        "version": version,
        "skipped_message_keys": len(model.skipped_message_keys),
        "distinct_skipped_ratchet_pubs": len({smk.ratchet_pub for smk in model.skipped_message_keys}),
        "has_sending_chain": skr.sending_chain is not None,
        "has_receiving_chain": skr.receiving_chain is not None,
        "sending_chain_length": None if skr.sending_chain is None else skr.sending_chain.length,
        "receiving_chain_length": None if skr.receiving_chain is None else skr.receiving_chain.length,
        "root_chain_length": model.diffie_hellman_ratchet.root_chain.length,
        "previous_sending_chain_length": skr.previous_sending_chain_length,
        "own_key_sizes": {
            "private": len(model.diffie_hellman_ratchet.own_ratchet_priv),
            "public": None
        },
        "recipient_pub_size": len(model.diffie_hellman_ratchet.other_ratchet_pub)
    })
    return errors, warnings, summary


def preflight_check(serialized: Any) -> PreflightReport:
    """
    Inspect a parsed JSON archive read-only and decide whether it can be migrated without losing information.

    Args:
        serialized: The result of :func:`json.loads` on the archive. The object is not modified.

    Returns:
        A :class:`PreflightReport`. ``migratable`` is ``True`` only when there are no errors. The report never
        embeds private or symmetric key material; only structural facts and byte sizes are summarized.
    """

    file_format = detect_format(serialized)
    if file_format == UNKNOWN_FORMAT:
        return PreflightReport(
            file_format=UNKNOWN_FORMAT,
            migratable=False,
            errors=["The archive matches neither the pre-stable nor the stable serialization shape, or it has"
                    " an unknown/ambiguous version."],
            summary={"format": UNKNOWN_FORMAT}
        )

    if file_format == PRE_STABLE:
        errors, warnings, summary = _validate_pre_stable(serialized)
    else:
        errors, warnings, summary = _validate_stable(serialized)

    return PreflightReport(
        file_format=file_format,
        migratable=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        summary=summary
    )


def strict_parse_double_ratchet(serialized: JSONObject) -> DoubleRatchetModel:
    """
    Parse an archive after running :func:`preflight_check`.

    Args:
        serialized: The parsed JSON archive.

    Returns:
        The migrated :class:`~doubleratchet.models.DoubleRatchetModel`. Stable input is returned as-is.

    Raises:
        MigrationError: if the preflight reports any fatal problem. No random key is ever substituted for
            missing data.
    """

    report = preflight_check(serialized)
    if not report.migratable:
        raise MigrationError("; ".join(report.errors))
    try:
        return parse_double_ratchet_model(serialized)
    except InconsistentSerializationException as exc:
        raise MigrationError(str(exc)) from exc


def migrate_json(serialized: JSONObject) -> Tuple[JSONObject, PreflightReport]:
    """
    Translate a parsed pre-stable archive into the stable JSON representation.

    Args:
        serialized: The parsed JSON archive.

    Returns:
        A tuple of the stable JSON-serializable state and the authorizing :class:`PreflightReport`.

    Raises:
        MigrationError: if the archive is not safely migratable. The input object is left untouched.
    """

    report = preflight_check(serialized)
    if not report.migratable:
        raise MigrationError("; ".join(report.errors))
    if report.file_format == STABLE:
        # Nothing to translate; return a stable round-trip without inventing data.
        return dict(serialized), report
    model = strict_parse_double_ratchet(serialized)
    migrated: JSONObject = model.model_dump(mode="json")
    return migrated, report


def redact_archive(serialized: Any) -> Any:
    """
    Return a deep copy of an archive with every secret value replaced by a non-reversible placeholder.

    Public keys, counts, lengths and the version are retained so the structure can still be audited. Private
    keys, chain keys and skipped message keys are replaced by strings describing only their byte length. The
    output is safe to log.
    """

    secret_leaf_names = frozenset({
        "priv", "key", "message_key", "own_ratchet_priv"
    })

    def _secret_size(value: Any) -> Optional[int]:
        """Length of a secret string, whether it is base64-encoded (pre-stable) or chr-encoded (stable)."""

        if not isinstance(value, str):
            return None
        decoded = _b64_decode(value)
        return len(decoded) if decoded is not None else len(value.encode("utf-8", errors="ignore"))

    def walk(node: Any, key_name: Optional[str] = None) -> Any:
        if key_name in secret_leaf_names and isinstance(node, str):
            return f"<redacted:{_secret_size(node)}b>"
        if _is_mapping(node):
            redacted_mapping: Dict[str, Any] = {}
            for key, value in node.items():
                if key_name == "smks" and isinstance(value, str):
                    # In pre-stable state, every value of the skipped message keys mapping is a message key.
                    redacted_mapping[key] = f"<redacted:{_secret_size(value)}b>"
                else:
                    redacted_mapping[key] = walk(value, key)
            return redacted_mapping
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(serialized)


def _atomic_write(path: str, payload: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(prefix=".dr-migrate-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def migrate_json_file(
    input_path: str,
    output_path: Optional[str] = None,
    *,
    backup_suffix: str = ".bak",
    overwrite: bool = False
) -> MigrationResult:
    """
    Migrate a JSON archive on disk with strict failure safety.

    The original file is read and fully validated before anything is written. On any validation failure the
    function raises :class:`MigrationError` and no file is created, replaced or deleted. On success the input
    file is copied verbatim to ``input_path + backup_suffix`` and the stable state is written atomically to
    ``output_path`` (defaulting to ``input_path``).

    Args:
        input_path: Path to the existing JSON archive.
        output_path: Where to write the stable JSON. Defaults to overwriting ``input_path`` after backup.
        backup_suffix: Suffix appended to ``input_path`` for the verbatim backup.
        overwrite: Must be ``True`` to write into an existing ``output_path`` that differs from the input.

    Raises:
        MigrationError: on validation failure, or when an output file already exists and ``overwrite`` is
            ``False``. No key material is included in the exception message.
    """

    output_path = input_path if output_path is None else output_path

    with open(input_path, "r", encoding="utf-8") as handle:
        raw = handle.read()

    try:
        serialized = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MigrationError(f"The archive is not valid JSON: {exc.msg} at line {exc.lineno}.") from exc

    report = preflight_check(serialized)
    if not report.migratable:
        raise MigrationError("Migration refused: " + "; ".join(report.errors))

    migrated, report = migrate_json(serialized)

    if os.path.abspath(output_path) != os.path.abspath(input_path) and \
            os.path.exists(output_path) and not overwrite:
        raise MigrationError("The output path already exists; pass overwrite=True to replace it.")

    backup_path = input_path + backup_suffix
    if os.path.exists(backup_path) and not overwrite:
        raise MigrationError("A backup file already exists; pass overwrite=True to replace it.")

    # Keep the original bytes byte-for-byte, then publish the migrated state atomically.
    _atomic_write(backup_path, raw)
    try:
        _atomic_write(output_path, json.dumps(migrated, indent=2, sort_keys=True) + "\n")
    except BaseException:
        # Roll back so a half-finished migration never shadows the untouched backup.
        try:
            os.unlink(backup_path)
        except OSError:
            pass
        raise

    return MigrationResult(
        output_path=output_path,
        backup_path=backup_path,
        report=report,
        migrated=migrated
    )
