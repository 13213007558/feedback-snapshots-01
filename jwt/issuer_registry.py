from __future__ import annotations

import math
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

from .api_jwk import PyJWK
from .api_jwt import PyJWT
from .exceptions import (
    InvalidAlgorithmError,
    InvalidIssuerError,
    IssuerConfigurationError,
    MissingRequiredClaimError,
    PyJWKClientError,
    UnregisteredIssuerError,
)
from .jwks_client import PyJWKClient
from .types import Options

if TYPE_CHECKING:
    from .algorithms import AllowedPublicKeys

_SYMMETRIC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_FORBIDDEN_ALGORITHMS = frozenset({"none"})


def _normalise_algorithms(algorithms: Sequence[str]) -> tuple[str, ...]:
    if isinstance(algorithms, (str, bytes, bytearray)) or not isinstance(
        algorithms, Iterable
    ):
        raise IssuerConfigurationError(
            "algorithms must be a non-empty sequence of algorithm names"
        )

    names = tuple(algorithms)
    if not names:
        raise IssuerConfigurationError(
            "algorithms must be a non-empty sequence of algorithm names"
        )

    seen: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not name:
            raise IssuerConfigurationError("algorithm names must be non-empty strings")
        if name.lower() in _FORBIDDEN_ALGORITHMS:
            raise IssuerConfigurationError(
                "the 'none' algorithm cannot be registered for an issuer"
            )
        if name in seen:
            raise IssuerConfigurationError(f"duplicate algorithm {name!r}")
        seen.add(name)

    symmetric = seen & _SYMMETRIC_ALGORITHMS
    if symmetric and symmetric != seen:
        raise IssuerConfigurationError(
            "an issuer configuration cannot mix symmetric and asymmetric algorithms"
        )

    return names


def _normalise_audience(
    audience: str | Iterable[str] | None,
) -> str | tuple[str, ...] | None:
    if audience is None:
        return None

    if isinstance(audience, str):
        if not audience:
            raise IssuerConfigurationError("audience must not be empty")
        return audience

    if isinstance(audience, (bytes, bytearray)) or not isinstance(audience, Iterable):
        raise IssuerConfigurationError(
            "audience must be a string, an iterable of strings or None"
        )

    values = tuple(audience)
    if not values:
        raise IssuerConfigurationError("audience must not be empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise IssuerConfigurationError("audience values must be non-empty strings")
    return values


def _normalise_options(
    options: Mapping[str, Any] | None,
    audience: str | tuple[str, ...] | None,
) -> dict[str, Any]:
    if options is None:
        merged: dict[str, Any] = {}
    elif not isinstance(options, Mapping):
        raise IssuerConfigurationError("options must be a mapping or None")
    else:
        merged = dict(options)

    if not merged.get("verify_signature", True):
        raise IssuerConfigurationError(
            "signature verification cannot be disabled for an issuer"
        )
    if not merged.get("verify_iss", True):
        raise IssuerConfigurationError(
            "issuer verification cannot be disabled for an issuer"
        )
    if audience is not None and not merged.get("verify_aud", True):
        raise IssuerConfigurationError(
            "audience verification cannot be disabled when an audience is configured"
        )

    merged["verify_signature"] = True
    merged["verify_iss"] = True
    if audience is not None:
        merged["verify_aud"] = True

    require = merged.get("require", [])
    if isinstance(require, (str, bytes, bytearray)) or not isinstance(
        require, Iterable
    ):
        raise IssuerConfigurationError(
            "options['require'] must be an iterable of claims"
        )
    required = list(require)
    if any(not isinstance(claim, str) or not claim for claim in required):
        raise IssuerConfigurationError(
            "options['require'] values must be non-empty strings"
        )
    if "iss" not in required:
        required.append("iss")
    merged["require"] = required

    if merged.get("strict_aud") and not isinstance(audience, str):
        raise IssuerConfigurationError("strict_aud requires a single string audience")

    return merged


def _normalise_leeway(leeway: float | timedelta) -> float | timedelta:
    if isinstance(leeway, timedelta):
        seconds = leeway.total_seconds()
    elif isinstance(leeway, (int, float)) and not isinstance(leeway, bool):
        seconds = float(leeway)
    else:
        raise IssuerConfigurationError(
            "leeway must be a number of seconds or a datetime.timedelta"
        )

    if not math.isfinite(seconds) or seconds < 0:
        raise IssuerConfigurationError("leeway must be a finite, non-negative value")

    return leeway


@dataclass(frozen=True)
class IssuerConfig:
    """Verification parameters for a single trusted issuer.

    Instances are normally created through :meth:`IssuerRegistry.register`,
    but can also be constructed directly and passed to the registry.

    Every configuration owns one key source: either ``key`` or a JWKS client
    (created from ``jwks_uri`` or supplied as ``jwks_client``).  The
    ``audience`` and ``algorithms`` values apply only to tokens routed to
    this issuer; they are never inherited from another registration.
    """

    issuer: str
    algorithms: Sequence[str]
    audience: str | Iterable[str] | None = None
    key: Any = field(default=None, repr=False)
    jwks_uri: str | None = None
    jwks_client: PyJWKClient | None = field(default=None, repr=False)
    options: Options | Mapping[str, Any] | None = None
    leeway: float | timedelta = 0
    subject: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer:
            raise IssuerConfigurationError("issuer must be a non-empty string")

        object.__setattr__(self, "algorithms", _normalise_algorithms(self.algorithms))
        audience = _normalise_audience(self.audience)
        object.__setattr__(self, "audience", audience)
        object.__setattr__(self, "options", _normalise_options(self.options, audience))
        object.__setattr__(self, "leeway", _normalise_leeway(self.leeway))

        if self.subject is not None and not isinstance(self.subject, str):
            raise IssuerConfigurationError("subject must be a string or None")

        provided = [
            self.key is not None,
            self.jwks_uri is not None,
            self.jwks_client is not None,
        ]
        if sum(provided) != 1:
            raise IssuerConfigurationError(
                "an issuer configuration requires exactly one key source: "
                "key, jwks_uri or jwks_client"
            )

        if self.jwks_uri is not None:
            if not isinstance(self.jwks_uri, str) or not self.jwks_uri:
                raise IssuerConfigurationError("jwks_uri must be a non-empty string")
            try:
                client = PyJWKClient(self.jwks_uri)
            except PyJWKClientError as exc:
                raise IssuerConfigurationError(f"invalid jwks_uri: {exc}") from exc
            object.__setattr__(self, "jwks_client", client)

        if isinstance(self.key, PyJWK) and self.key.algorithm_name not in cast(
            tuple[str, ...], self.algorithms
        ):
            raise IssuerConfigurationError(
                "the configured PyJWK algorithm is not in this issuer's algorithms"
            )


@dataclass(frozen=True)
class VerifiedToken:
    """A token that was routed to an issuer and accepted by its configuration.

    ``issuer`` is the configured issuer value, not the unverified ``iss``
    claim.  It is only produced after the signature and claim checks passed.
    """

    issuer: str
    payload: dict[str, Any]
    header: dict[str, Any]


class IssuerRegistry:
    """A closed set of trusted issuers and their verification parameters.

    Tokens are routed by their ``iss`` claim to the matching registration,
    then verified with that registration's audience, algorithms and key
    source.  An issuer that is not registered is rejected before any key
    lookup, including a JWKS fetch.
    """

    def __init__(self, configs: Iterable[IssuerConfig] = ()) -> None:
        self._configs: dict[str, IssuerConfig] = {}
        self._lock = threading.RLock()
        self._jwt = PyJWT()
        for config in configs:
            self.register(config)

    def register(
        self,
        config: IssuerConfig | None = None,
        *,
        issuer: str | None = None,
        algorithms: Sequence[str] | None = None,
        audience: str | Iterable[str] | None = None,
        key: AllowedPublicKeys | PyJWK | str | bytes | None = None,
        jwks_uri: str | None = None,
        jwks_client: PyJWKClient | None = None,
        options: Options | Mapping[str, Any] | None = None,
        leeway: float | timedelta | None = None,
        subject: str | None = None,
    ) -> IssuerConfig:
        """Register an issuer configuration.

        Pass either a prepared :class:`IssuerConfig` or the individual
        arguments.  Registering the same issuer twice raises
        :class:`~jwt.exceptions.IssuerConfigurationError`.
        """
        if config is not None:
            if any(
                value is not None
                for value in (
                    issuer,
                    algorithms,
                    audience,
                    key,
                    jwks_uri,
                    jwks_client,
                    options,
                    leeway,
                    subject,
                )
            ):
                raise TypeError(
                    "pass either an IssuerConfig or individual registration "
                    "arguments, not both"
                )
            if not isinstance(config, IssuerConfig):
                raise TypeError("config must be an IssuerConfig")
        else:
            if issuer is None:
                raise TypeError("issuer is required")
            if algorithms is None:
                raise TypeError("algorithms is required")
            config = IssuerConfig(
                issuer=issuer,
                algorithms=algorithms,
                audience=audience,
                key=key,
                jwks_uri=jwks_uri,
                jwks_client=jwks_client,
                options=options,
                leeway=0 if leeway is None else leeway,
                subject=subject,
            )

        with self._lock:
            if config.issuer in self._configs:
                raise IssuerConfigurationError(
                    "an issuer with this name is already registered"
                )
            self._configs[config.issuer] = config

        return config

    def unregister(self, issuer: str) -> bool:
        """Remove *issuer* from the registry.

        :returns: ``True`` if the issuer was registered and has been removed.
        """
        with self._lock:
            return self._configs.pop(issuer, None) is not None

    def clear(self) -> None:
        """Remove all issuer registrations."""
        with self._lock:
            self._configs.clear()

    @property
    def issuers(self) -> tuple[str, ...]:
        """The registered issuer names, in registration order."""
        with self._lock:
            return tuple(self._configs)

    def __contains__(self, issuer: object) -> bool:
        with self._lock:
            return issuer in self._configs

    def __len__(self) -> int:
        with self._lock:
            return len(self._configs)

    def decode(self, token: str | bytes) -> VerifiedToken:
        """Route *token* to its issuer and verify it.

        The unverified ``iss`` claim is used only to select a registration.
        The signature, issuer, audience and other claims are then verified
        with that registration before a :class:`VerifiedToken` is returned.

        :raises UnregisteredIssuerError: If ``iss`` is not registered.  No
            key source is contacted in that case.
        :raises MissingRequiredClaimError: If the token has no ``iss`` claim.
        :raises InvalidIssuerError: If the ``iss`` claim is not a string.
        :raises InvalidAlgorithmError: If the token's ``alg`` header is not
            in the selected issuer's algorithm allowlist.  Raised before the
            issuer's key source is contacted.
        :raises InvalidTokenError: If the token fails verification under the
            selected issuer configuration.
        """
        config = self._route(token)
        key = self._resolve_key(config, token)
        decoded = self._jwt.decode_complete(
            token,
            key=key,
            algorithms=cast(tuple[str, ...], config.algorithms),
            options=cast(Options, config.options),
            audience=cast(str | tuple[str, ...] | None, config.audience),
            issuer=config.issuer,
            subject=config.subject,
            leeway=config.leeway,
        )
        return VerifiedToken(
            issuer=config.issuer,
            payload=cast(dict[str, Any], decoded["payload"]),
            header=cast(dict[str, Any], decoded["header"]),
        )

    def _route(self, token: str | bytes) -> IssuerConfig:
        unverified = self._jwt.decode_complete(
            token, options={"verify_signature": False}
        )
        header = cast(dict[str, Any], unverified["header"])
        payload = cast(dict[str, Any], unverified["payload"])

        if payload.get("iss") is None:
            raise MissingRequiredClaimError("iss")
        issuer = payload["iss"]
        if not isinstance(issuer, str):
            raise InvalidIssuerError("Payload Issuer (iss) must be a string")

        with self._lock:
            config = self._configs.get(issuer)
        if config is None:
            raise UnregisteredIssuerError("Issuer is not registered")

        # Reject a token whose advertised algorithm is not usable with this
        # issuer before selecting a key.  This keeps an unaccepted algorithm
        # from reaching the issuer's key source at all.
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in config.algorithms:
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        return config

    @staticmethod
    def _resolve_key(config: IssuerConfig, token: str | bytes) -> Any:
        if config.jwks_client is not None:
            return config.jwks_client.get_signing_key_from_jwt(token)
        return config.key


__all__ = ["IssuerConfig", "IssuerRegistry", "VerifiedToken"]
