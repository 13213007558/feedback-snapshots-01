from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .api_jwk import PyJWK, PyJWKSet


class JWKSetChangeType(str, Enum):
    """The kind of change observed for a single key in a JWK Set."""

    ADDED = "added"
    REMOVED = "removed"
    REPLACED = "replaced"


@dataclass(frozen=True)
class JWKSetKeyChange:
    """A single key-level change in an accepted JWK Set.

    Instances deliberately contain no key material: only the ``kid`` and
    SHA-256 fingerprints derived from the public members of the key. They are
    therefore safe to include in monitoring or application logs.
    """

    change_type: JWKSetChangeType
    key_id: str | None
    fingerprint: str
    previous_fingerprint: str | None = None

    @property
    def kind(self) -> JWKSetChangeType:
        """Alias for :attr:`change_type`."""
        return self.change_type

    @property
    def kid(self) -> str | None:
        """Alias for :attr:`key_id`."""
        return self.key_id


@dataclass(frozen=True)
class JWKSetUpdate:
    """The changes between two consecutive accepted JWK Sets.

    A :class:`~jwt.PyJWKClient` invokes its observers with one instance of
    this class at most once per accepted fetch. The first accepted set only
    establishes a baseline and is not reported.

    ``fingerprint`` is a stable fingerprint of the whole set. ``added``,
    ``removed``, and ``replaced`` are deterministic tuples of key-level
    changes. A replaced key keeps its ``kid`` but its material (and therefore
    its fingerprint) changed.
    """

    fingerprint: str
    previous_fingerprint: str | None = None
    added: tuple[JWKSetKeyChange, ...] = ()
    removed: tuple[JWKSetKeyChange, ...] = ()
    replaced: tuple[JWKSetKeyChange, ...] = ()

    @property
    def changes(self) -> tuple[JWKSetKeyChange, ...]:
        """All key-level changes, grouped by change type."""
        return self.added + self.removed + self.replaced

    @property
    def has_changes(self) -> bool:
        """Whether any key was added, removed, or replaced."""
        return bool(self.changes)

    def to_dict(self) -> dict[str, Any]:
        """Return a log-safe representation of the update."""
        return {
            "fingerprint": self.fingerprint,
            "previous_fingerprint": self.previous_fingerprint,
            "added": [_change_to_dict(change) for change in self.added],
            "removed": [_change_to_dict(change) for change in self.removed],
            "replaced": [_change_to_dict(change) for change in self.replaced],
        }


JWKSetObserver = Callable[[JWKSetUpdate], None]


def _change_to_dict(change: JWKSetKeyChange) -> dict[str, Any]:
    return {
        "change_type": change.change_type.value,
        "key_id": change.key_id,
        "fingerprint": change.fingerprint,
        "previous_fingerprint": change.previous_fingerprint,
    }


def _fingerprint(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


_THUMBPRINT_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "oct": ("k", "kty"),
}


def jwk_thumbprint(jwk: PyJWK) -> str:
    """Return a stable SHA-256 fingerprint for *jwk*.

    The fingerprint follows the member selection defined by RFC 7638, so it
    changes when the key material changes but not when unrelated metadata such
    as ``kid``, ``use``, ``alg``, or certificate hints change.
    """
    data = jwk._jwk_data
    kty = jwk.key_type
    members = _THUMBPRINT_MEMBERS.get(kty) if kty is not None else None
    if members is not None:
        thumbprint_input = {name: data.get(name) for name in members}
    else:
        # ``PyJWK`` only accepts known key types, but keep the fingerprint
        # deterministic for future or unusual members rather than failing an
        # otherwise accepted key set.
        thumbprint_input = {
            name: value
            for name, value in data.items()
            if name not in {"kid", "use", "alg", "key_ops"}
        }
    return _fingerprint(_canonical_json(thumbprint_input))


def normalize_kid(kid: Any) -> str | None:
    """Return *kid* as a string, or ``None`` when it is absent.

    RFC 7517 defines ``kid`` as a string, but the field is attacker-controlled
    and a malformed JWK Set can carry any JSON type. Non-string values are
    reported by their JSON representation so that snapshots stay orderable
    and log output stays predictable.
    """
    if kid is None:
        return None
    if isinstance(kid, str):
        return kid
    try:
        return json.dumps(kid, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(kid)


def snapshot_jwk_set(jwk_set: PyJWKSet) -> dict[str | None, frozenset[str]]:
    """Build a fingerprint snapshot of *jwk_set* keyed by normalized ``kid``."""
    mutable: dict[str | None, set[str]] = {}
    for key in jwk_set.keys:
        mutable.setdefault(normalize_kid(key.key_id), set()).add(jwk_thumbprint(key))
    return {key_id: frozenset(thumbprints) for key_id, thumbprints in mutable.items()}


def observer_identifier(observer: Callable[..., Any]) -> str:
    """Return a log-safe identifier for *observer*.

    Repr strings of arbitrary callables are not guaranteed to be stable or
    free of key material, so prefer well-known metadata and fall back to a
    type name.
    """
    for attribute in ("__qualname__", "__name__"):
        name = getattr(observer, attribute, None)
        if isinstance(name, str) and name:
            module = getattr(observer, "__module__", None)
            if isinstance(module, str) and module:
                return f"{module}.{name}"
            return name
    return type(observer).__qualname__


def set_fingerprint(fingerprints: dict[str | None, frozenset[str]]) -> str:
    """Return a stable fingerprint for the collection of key fingerprints."""
    payload = [
        [kid, fingerprint]
        for kid in sorted(
            fingerprints, key=lambda value: (value is not None, value or "")
        )
        for fingerprint in sorted(fingerprints[kid])
    ]
    return _fingerprint(_canonical_json(payload))


def diff_jwk_sets(
    previous: dict[str | None, frozenset[str]],
    current: dict[str | None, frozenset[str]],
) -> tuple[
    tuple[JWKSetKeyChange, ...],
    tuple[JWKSetKeyChange, ...],
    tuple[JWKSetKeyChange, ...],
]:
    """Compute added, removed, and replaced keys between two snapshots.

    A replacement is reported when a ``kid`` has material in both snapshots
    that is not present in the other snapshot. Extra material under the same
    ``kid`` is reported as an addition or removal.
    """
    added: list[JWKSetKeyChange] = []
    removed: list[JWKSetKeyChange] = []
    replaced: list[JWKSetKeyChange] = []

    all_kids = set(previous) | set(current)
    for kid in sorted(all_kids, key=lambda value: (value is not None, value or "")):
        before = previous.get(kid, frozenset())
        after = current.get(kid, frozenset())

        removed_material = sorted(before - after)
        added_material = sorted(after - before)

        paired = min(len(removed_material), len(added_material))
        for old, new in zip(removed_material[:paired], added_material[:paired]):
            replaced.append(
                JWKSetKeyChange(
                    change_type=JWKSetChangeType.REPLACED,
                    key_id=kid,
                    fingerprint=new,
                    previous_fingerprint=old,
                )
            )

        for fingerprint in removed_material[paired:]:
            removed.append(
                JWKSetKeyChange(
                    change_type=JWKSetChangeType.REMOVED,
                    key_id=kid,
                    fingerprint=fingerprint,
                )
            )

        for fingerprint in added_material[paired:]:
            added.append(
                JWKSetKeyChange(
                    change_type=JWKSetChangeType.ADDED,
                    key_id=kid,
                    fingerprint=fingerprint,
                )
            )

    return tuple(added), tuple(removed), tuple(replaced)
