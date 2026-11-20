"""
Versioned, per-environment trust configuration for an artifact
verification service.

The same service verifies both "internal preview" and "official release"
packages. Each environment gets its own trust configuration with a fixed
identity: a config loaded into the ``preview`` slot can never be used for
``release`` and vice versa, and a missing/unavailable config is never
papered over by borrowing another environment's root material.

Consistency guarantees:

* Configs are immutable, versioned snapshots. ``TrustConfigManager.update``
  validates the candidate and swaps it in atomically.
* A verification that has already started (a ``VerificationSession``) keeps
  the exact root material it began with, even if the config is swapped
  mid-verification.
* The application can inspect the current version via
  ``TrustConfigManager.current_version``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


class TrustConfigError(Exception):
    """Base class for trust configuration errors."""


class ConfigValidationError(TrustConfigError):
    """A candidate trust configuration failed validation."""


class ConfigUnavailableError(TrustConfigError):
    """No trust configuration is available for the requested environment."""


class ArtifactVerificationError(Exception):
    """An artifact failed verification against the pinned root material."""


def _parse_public_key(key_id: object, public_key_hex: object) -> Ed25519PublicKey:
    if not isinstance(key_id, str) or not key_id:
        raise ConfigValidationError("each root needs a non-empty string key_id")
    if not isinstance(public_key_hex, str):
        raise ConfigValidationError(f"root {key_id!r}: public_key must be hex")
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError:
        raise ConfigValidationError(
            f"root {key_id!r}: public_key is not valid hex"
        ) from None
    if len(raw) != 32:
        raise ConfigValidationError(
            f"root {key_id!r}: expected a 32-byte Ed25519 key, got {len(raw)} bytes"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class TrustConfig:
    """
    An immutable, versioned set of root material for one environment.
    """

    environment: str
    version: int
    roots: dict[str, Ed25519PublicKey]

    @classmethod
    def from_dict(cls, data: object) -> TrustConfig:
        if not isinstance(data, dict):
            raise ConfigValidationError("config must be a JSON object")

        environment = data.get("environment")
        if not isinstance(environment, str) or not environment:
            raise ConfigValidationError("config needs a non-empty 'environment'")

        version = data.get("version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ConfigValidationError("config needs an integer 'version' >= 1")

        raw_roots = data.get("roots")
        if not isinstance(raw_roots, list) or not raw_roots:
            raise ConfigValidationError("config needs a non-empty 'roots' list")

        roots: dict[str, Ed25519PublicKey] = {}
        for entry in raw_roots:
            if not isinstance(entry, dict):
                raise ConfigValidationError("each root must be an object")
            key_id = entry.get("key_id")
            public_key = _parse_public_key(key_id, entry.get("public_key"))
            if key_id in roots:
                raise ConfigValidationError(f"duplicate root key_id {key_id!r}")
            roots[key_id] = public_key

        return cls(environment=environment, version=version, roots=roots)

    @classmethod
    def from_file(cls, path: str | Path) -> TrustConfig:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigValidationError(f"cannot load config {path}: {exc}") from exc
        return cls.from_dict(data)


class TrustConfigManager:
    """
    Holds the current trust config for each environment slot.

    Slot identity is fixed at load time: an update must carry the same
    environment name and a strictly greater version, and is swapped in
    atomically. Readers always see one whole config or the other, never a
    mixture.
    """

    def __init__(self) -> None:
        self._slots: dict[str, TrustConfig] = {}
        self._lock = threading.Lock()

    def load(self, path: str | Path) -> TrustConfig:
        """
        Load the initial config for its declared environment slot.
        """
        config = TrustConfig.from_file(path)
        with self._lock:
            if config.environment in self._slots:
                raise ConfigValidationError(
                    f"environment {config.environment!r} is already loaded; "
                    "use update() to rotate it"
                )
            self._slots[config.environment] = config
        return config

    def update(self, environment: str, path: str | Path) -> TrustConfig:
        """
        Validate and atomically swap in a new config for ``environment``.

        The candidate must match the slot's fixed identity and carry a
        strictly greater version. On any validation failure the current
        config is left untouched.
        """
        candidate = TrustConfig.from_file(path)
        with self._lock:
            current = self._slots.get(environment)
            if current is None:
                raise ConfigUnavailableError(
                    f"no trust config loaded for environment {environment!r}"
                )
            if candidate.environment != environment:
                raise ConfigValidationError(
                    f"config identity {candidate.environment!r} does not match "
                    f"environment slot {environment!r}"
                )
            if candidate.version <= current.version:
                raise ConfigValidationError(
                    f"config version {candidate.version} does not advance past "
                    f"current version {current.version}"
                )
            self._slots[environment] = candidate
        return candidate

    def snapshot(self, environment: str) -> TrustConfig:
        """
        Return the current immutable config for ``environment``.

        Raises ``ConfigUnavailableError`` if the environment has no config;
        there is deliberately no fallback to any other environment's
        material.
        """
        with self._lock:
            config = self._slots.get(environment)
        if config is None:
            raise ConfigUnavailableError(
                f"no trust config available for environment {environment!r}"
            )
        return config

    def current_version(self, environment: str) -> int:
        """
        The version of the config currently active for ``environment``.
        """
        return self.snapshot(environment).version


@dataclass(frozen=True)
class VerificationResult:
    environment: str
    config_version: int
    key_id: str


class VerificationSession:
    """
    A verification in progress, pinned to one consistent config snapshot.

    Root material is captured once at ``begin`` time; every artifact checked
    through this session uses exactly that snapshot, even if the manager
    swaps in a newer config meanwhile.
    """

    def __init__(self, config: TrustConfig) -> None:
        self._config = config

    @property
    def environment(self) -> str:
        return self._config.environment

    @property
    def config_version(self) -> int:
        return self._config.version

    def verify(self, artifact_path: str | Path) -> VerificationResult:
        try:
            artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArtifactVerificationError(
                f"cannot read artifact {artifact_path}: {exc}"
            ) from exc

        key_id = artifact.get("key_id")
        payload = artifact.get("payload")
        signature_hex = artifact.get("signature")
        if not all(isinstance(v, str) for v in (key_id, payload, signature_hex)):
            raise ArtifactVerificationError(
                "artifact needs string 'payload', 'key_id' and 'signature'"
            )

        key = self._config.roots.get(key_id)
        if key is None:
            raise ArtifactVerificationError(
                f"key {key_id!r} is not trusted by environment "
                f"{self._config.environment!r} config v{self._config.version}"
            )

        try:
            key.verify(bytes.fromhex(signature_hex), payload.encode("utf-8"))
        except (InvalidSignature, ValueError) as exc:
            raise ArtifactVerificationError(
                f"signature verification failed: {exc}"
            ) from exc

        return VerificationResult(
            environment=self._config.environment,
            config_version=self._config.version,
            key_id=key_id,
        )


class VerificationService:
    """
    Verifies artifacts for multiple environments against their own
    fixed-identity trust configs.
    """

    def __init__(self, manager: TrustConfigManager) -> None:
        self._manager = manager

    def begin(self, environment: str) -> VerificationSession:
        """
        Start a verification, pinning the config snapshot now in effect.
        """
        return VerificationSession(self._manager.snapshot(environment))

    def verify(self, environment: str, artifact_path: str | Path) -> VerificationResult:
        """
        One-shot verification against the environment's current config.
        """
        return self.begin(environment).verify(artifact_path)
