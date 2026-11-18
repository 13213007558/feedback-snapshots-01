"""Server identity policy for endpoints returned by OPC UA discovery.

Discovery responses are declarations, not trust anchors.  This module keeps
the deployment-owned identity (application URI, pinned certificate or trust
store, allowed network origins) separate from the endpoint list proposed by a
server, and only selects an endpoint that satisfies every configured check.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509

from asyncua import ua
from asyncua.crypto import uacrypto
from asyncua.crypto.security_policies import (
    SECURITY_POLICY_TYPE_MAP,
    SecurityPolicy,
    SecurityPolicyAes128Sha256RsaOaep,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyBasic256Sha256,
    SecurityPolicyNone,
)
from asyncua.crypto.truststore import TrustStore

_logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_SECURITY_POLICIES = frozenset(
    {
        SecurityPolicyBasic256Sha256.URI,
        SecurityPolicyAes128Sha256RsaOaep.URI,
        SecurityPolicyAes256Sha256RsaPss.URI,
    }
)

_POLICY_BY_URI: dict[str, type[SecurityPolicy]] = {
    policy.URI: policy
    for policy, _mode, _level in SECURITY_POLICY_TYPE_MAP.values()
    if policy is not SecurityPolicyNone
}

_STRENGTH_BY_POLICY_AND_MODE: dict[tuple[str, ua.MessageSecurityMode], int] = {
    (policy.URI, mode): level for policy, mode, level in SECURITY_POLICY_TYPE_MAP.values()
}


class EndpointSecurityError(ua.UaError):
    """Base error for endpoint identity and credential-release decisions."""


class MissingServerTrustError(EndpointSecurityError):
    """Raised when no deployment-owned trust anchor is available."""


class EndpointSelectionError(EndpointSecurityError):
    """Raised when discovery does not contain an endpoint that may be used."""


class EndpointRejected(EndpointSelectionError):
    """Raised when an endpoint does not satisfy one or more identity checks."""


class ServerEndpointChanged(EndpointSelectionError):
    """Raised when CreateSession returns an endpoint that differs from the selected one."""


class CredentialReleaseDenied(EndpointSecurityError):
    """Raised when user credentials would be sent without complete channel evidence."""


@dataclass(frozen=True, order=True)
class EndpointOrigin:
    """Normalized OPC UA TCP origin used for address allow-list checks."""

    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, url: str | None) -> EndpointOrigin:
        if not url:
            raise EndpointRejected("endpoint URL is missing")
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme != ua.OPC_TCP_SCHEME:
            raise EndpointRejected(f"unsupported endpoint scheme: {scheme!r}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise EndpointRejected(f"endpoint URL has no host: {url!r}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise EndpointRejected(f"endpoint URL has an invalid port: {url!r}") from exc
        if port is None:
            raise EndpointRejected(f"endpoint URL has no explicit port: {url!r}")
        return cls(scheme=scheme, host=host, port=port)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True)
class ServerIdentity:
    """Deployment-owned identity of the server that may receive credentials.

    ``allowed_origins`` may list several addresses on purpose: HA setups can
    reach the same server identity through multiple nodes, and the endpoint
    URL returned by discovery must still be one of them.  If it is empty, only
    the configured connection target is accepted.

    ``certificate`` pins one exact application instance certificate.  If it is
    omitted, ``trust_store`` must validate the certificate proposed by the
    server.  At least one of the two is required.  ``application_uri`` is
    always required and is checked independently of certificate trust.
    """

    application_uri: str
    certificate: x509.Certificate | None = None
    trust_store: TrustStore | None = None
    allowed_origins: frozenset[EndpointOrigin] = frozenset()
    require_certificate_application_uri: bool = True

    def __post_init__(self) -> None:
        if not self.application_uri:
            raise MissingServerTrustError("server application URI is not configured")
        if self.certificate is None and self.trust_store is None:
            raise MissingServerTrustError(
                "server identity has no trust anchor: configure a pinned certificate or a trust store"
            )
        if self.certificate is not None and not isinstance(self.certificate, x509.Certificate):
            raise TypeError("certificate must be an x509.Certificate")
        if self.allowed_origins and any(not isinstance(origin, EndpointOrigin) for origin in self.allowed_origins):
            raise TypeError("allowed_origins must contain EndpointOrigin values")
        if self.trust_store is not None and not self._trust_store_loaded:
            _logger.warning("trust_store was supplied without calling load(); an unloaded store trusts nothing")

    @property
    def _trust_store_loaded(self) -> bool:
        return self.trust_store is None or self.trust_store.is_loaded

    @classmethod
    async def create(
        cls,
        application_uri: str,
        certificate: x509.Certificate | bytes | str | Path | None = None,
        trust_store: TrustStore | None = None,
        allowed_origins: frozenset[EndpointOrigin] | None = None,
        require_certificate_application_uri: bool = True,
    ) -> ServerIdentity:
        loaded_certificate = certificate
        if certificate is not None and not isinstance(certificate, x509.Certificate):
            loaded_certificate = await uacrypto.load_certificate(certificate)
        return cls(
            application_uri=application_uri,
            certificate=loaded_certificate,
            trust_store=trust_store,
            allowed_origins=allowed_origins or frozenset(),
            require_certificate_application_uri=require_certificate_application_uri,
        )

    def permitted_origins(self, actual_origin: EndpointOrigin) -> frozenset[EndpointOrigin]:
        return self.allowed_origins or frozenset({actual_origin})


@dataclass(frozen=True)
class EndpointSecurityPolicy:
    """Rules applied to every endpoint before it can be selected or used."""

    identity: ServerIdentity
    allowed_security_policy_uris: frozenset[str] = DEFAULT_ALLOWED_SECURITY_POLICIES
    minimum_security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt
    require_username_token: bool = True
    require_username_token_encryption: bool = True

    def __post_init__(self) -> None:
        if not self.allowed_security_policy_uris:
            raise EndpointSelectionError("allowed_security_policy_uris must not be empty")
        if self.minimum_security_mode in (ua.MessageSecurityMode.None_, ua.MessageSecurityMode.Invalid):
            raise EndpointSelectionError(
                "minimum_security_mode None_/Invalid is not allowed on the strict endpoint path"
            )


@dataclass(frozen=True)
class EndpointSelection:
    """An endpoint accepted by the local policy, with the evidence used."""

    endpoint: ua.EndpointDescription
    origin: EndpointOrigin
    certificate: x509.Certificate
    effective_security_level: int
    declared_security_level: int
    declared_security_level_matches_policy: bool
    application_uri: str
    security_policy_uri: str
    security_mode: ua.MessageSecurityMode

    @property
    def endpoint_url(self) -> str | None:
        return self.endpoint.EndpointUrl

    @property
    def certificate_sha256(self) -> str:
        return hashlib.sha256(uacrypto.der_from_x509(self.certificate)).hexdigest()

    @property
    def username_token_policy(self) -> ua.UserTokenPolicy | None:
        for token in self.endpoint.UserIdentityTokens or []:
            if token.TokenType == ua.UserTokenType.UserName:
                return token
        return None

    def describe(self) -> str:
        return (
            f"url={self.endpoint_url} origin={self.origin} app_uri={self.application_uri} "
            f"policy={self.security_policy_uri} mode={self.security_mode.name} "
            f"cert_sha256={self.certificate_sha256} declared_level={self.declared_security_level} "
            f"effective_level={self.effective_security_level}"
        )


def security_policy_class(policy_uri: str) -> type[SecurityPolicy]:
    policy = _POLICY_BY_URI.get(policy_uri)
    if policy is None:
        raise EndpointSelectionError(f"unsupported security policy URI: {policy_uri!r}")
    return policy


def effective_security_level(policy_uri: str, mode: ua.MessageSecurityMode) -> int | None:
    return _STRENGTH_BY_POLICY_AND_MODE.get((policy_uri, mode))


def _certificate_time_valid(certificate: x509.Certificate) -> bool:
    now = datetime.now(UTC)
    return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc


def _certificate_application_uris(certificate: x509.Certificate) -> list[str]:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.UniformResourceIdentifier)


def verify_server_certificate(certificate: x509.Certificate, identity: ServerIdentity) -> None:
    """Raise EndpointRejected unless ``certificate`` satisfies ``identity``."""
    error = _certificate_trust_error(certificate, identity)
    if error:
        raise EndpointRejected(error)


def _certificate_trust_error(certificate: x509.Certificate, identity: ServerIdentity) -> str | None:
    if not _certificate_time_valid(certificate):
        return "server certificate is outside its validity period"
    if identity.certificate is not None:
        expected = uacrypto.der_from_x509(identity.certificate)
        actual = uacrypto.der_from_x509(certificate)
        if actual != expected:
            return "server certificate does not match the pinned certificate"
    elif identity.trust_store is None or not identity.trust_store.validate(certificate):
        return "server certificate is not trusted by the configured trust store"
    if identity.require_certificate_application_uri:
        uris = _certificate_application_uris(certificate)
        if identity.application_uri not in uris:
            return "certificate SubjectAltName does not contain the expected application URI"
    return None


def _token_effective_policy_uri(endpoint: ua.EndpointDescription, token: ua.UserTokenPolicy) -> str | None:
    if token.SecurityPolicyUri:
        return token.SecurityPolicyUri
    return endpoint.SecurityPolicyUri


def _username_token_error(selection: EndpointSelection, policy: EndpointSecurityPolicy) -> str | None:
    token = selection.username_token_policy
    if token is None:
        if policy.require_username_token:
            return "endpoint does not advertise a UserName identity token"
        return None
    if not policy.require_username_token_encryption:
        return None
    token_policy_uri = _token_effective_policy_uri(selection.endpoint, token)
    if not token_policy_uri or token_policy_uri == SecurityPolicyNone.URI:
        return "UserName token would be sent without an encryption policy"
    if token_policy_uri not in policy.allowed_security_policy_uris:
        return f"UserName token policy {token_policy_uri!r} is not in the allowed set"
    return None


def assess_endpoint(
    endpoint: ua.EndpointDescription,
    policy: EndpointSecurityPolicy,
    actual_origin: EndpointOrigin,
) -> EndpointSelection:
    identity = policy.identity
    if endpoint is None:
        raise EndpointRejected("discovery returned a null endpoint")
    origin = EndpointOrigin.parse(endpoint.EndpointUrl)
    permitted = identity.permitted_origins(actual_origin)
    if actual_origin not in permitted:
        raise EndpointRejected(f"connection target {actual_origin} is not in the configured address allow-list")
    if origin != actual_origin:
        raise EndpointRejected(
            f"discovered endpoint address {origin} does not match the configured connection target {actual_origin}"
        )

    if endpoint.Server is None:
        raise EndpointRejected("endpoint has no Server application description")
    application_uri = endpoint.Server.ApplicationUri
    if application_uri != identity.application_uri:
        raise EndpointRejected(
            f"server application URI {application_uri!r} does not match the configured {identity.application_uri!r}"
        )

    try:
        certificate = uacrypto.x509_from_der(endpoint.ServerCertificate)
    except ValueError as exc:
        raise EndpointRejected(f"endpoint server certificate cannot be parsed: {exc}") from exc
    if certificate is None:
        raise EndpointRejected("endpoint has no server certificate")
    trust_error = _certificate_trust_error(certificate, identity)
    if trust_error:
        raise EndpointRejected(trust_error)

    policy_uri = endpoint.SecurityPolicyUri
    if policy_uri not in policy.allowed_security_policy_uris:
        raise EndpointRejected(f"security policy {policy_uri!r} is not in the allowed set")
    if endpoint.SecurityMode < policy.minimum_security_mode:
        raise EndpointRejected(
            f"security mode {endpoint.SecurityMode.name} is below the required {policy.minimum_security_mode.name}"
        )
    level = effective_security_level(policy_uri, endpoint.SecurityMode)
    if level is None:
        raise EndpointRejected(f"no local strength classification for {policy_uri!r}/{endpoint.SecurityMode.name}")

    selection = EndpointSelection(
        endpoint=endpoint,
        origin=origin,
        certificate=certificate,
        effective_security_level=level,
        declared_security_level=endpoint.SecurityLevel,
        declared_security_level_matches_policy=endpoint.SecurityLevel == level,
        application_uri=application_uri,
        security_policy_uri=policy_uri,
        security_mode=endpoint.SecurityMode,
    )
    token_error = _username_token_error(selection, policy)
    if token_error:
        raise EndpointRejected(token_error)
    if not selection.declared_security_level_matches_policy:
        _logger.warning(
            "endpoint %s declares SecurityLevel %s but its policy/mode evaluates to %s; "
            "the declared value is diagnostic only and is not used for trust",
            endpoint.EndpointUrl,
            endpoint.SecurityLevel,
            level,
        )
    return selection


def select_endpoint(
    endpoints: list[ua.EndpointDescription],
    policy: EndpointSecurityPolicy,
    actual_origin: EndpointOrigin,
    required_policy_uri: str | None = None,
    required_mode: ua.MessageSecurityMode | None = None,
) -> EndpointSelection:
    accepted: list[EndpointSelection] = []
    rejected: list[str] = []
    for endpoint in endpoints:
        try:
            if required_policy_uri is not None and endpoint.SecurityPolicyUri != required_policy_uri:
                raise EndpointRejected(f"security policy {endpoint.SecurityPolicyUri!r} is not the required policy")
            if required_mode is not None and endpoint.SecurityMode != required_mode:
                raise EndpointRejected(f"security mode {endpoint.SecurityMode.name} is not the required mode")
            accepted.append(assess_endpoint(endpoint, policy, actual_origin))
        except EndpointRejected as exc:
            rejected.append(f"{endpoint.EndpointUrl}: {exc}")
    if not accepted:
        detail = "; ".join(rejected) if rejected else "server returned no endpoints"
        raise EndpointSelectionError(f"no endpoint satisfies the server identity policy: {detail}")
    accepted.sort(key=lambda item: (item.effective_security_level, item.security_policy_uri, item.endpoint_url or ""))
    return accepted[-1]


def validate_session_endpoint(
    selection: EndpointSelection,
    policy: EndpointSecurityPolicy,
    server_endpoints: list[ua.EndpointDescription],
    actual_origin: EndpointOrigin,
    server_certificate_der: bytes | None,
) -> EndpointSelection:
    if not server_certificate_der:
        raise ServerEndpointChanged("CreateSession response has no server certificate")
    response_certificate = uacrypto.x509_from_der(server_certificate_der)
    if response_certificate is None or uacrypto.der_from_x509(response_certificate) != uacrypto.der_from_x509(
        selection.certificate
    ):
        raise ServerEndpointChanged("CreateSession server certificate differs from the selected server certificate")
    if not server_endpoints:
        raise ServerEndpointChanged("CreateSession response has no ServerEndpoints")

    for endpoint in server_endpoints:
        try:
            candidate = assess_endpoint(endpoint, policy, actual_origin)
        except EndpointRejected:
            continue
        if (
            candidate.security_policy_uri == selection.security_policy_uri
            and candidate.security_mode == selection.security_mode
            and candidate.origin == selection.origin
            and candidate.application_uri == selection.application_uri
            and candidate.certificate_sha256 == selection.certificate_sha256
        ):
            return candidate
    raise ServerEndpointChanged(
        "CreateSession ServerEndpoints no longer contain the selected policy, mode, "
        "origin, application URI and certificate"
    )


def require_credentials_allowed(
    selection: EndpointSelection,
    policy: EndpointSecurityPolicy,
    active_policy_uri: str,
    active_mode: ua.MessageSecurityMode,
) -> None:
    if selection.security_mode != ua.MessageSecurityMode.SignAndEncrypt:
        raise CredentialReleaseDenied("credentials require a SignAndEncrypt secure channel")
    if active_mode != selection.security_mode or active_policy_uri != selection.security_policy_uri:
        raise CredentialReleaseDenied("active secure channel does not match the validated endpoint")
    token = selection.username_token_policy
    if token is None:
        raise CredentialReleaseDenied("validated endpoint does not advertise a UserName identity token")
    token_policy_uri = _token_effective_policy_uri(selection.endpoint, token)
    if not token_policy_uri or token_policy_uri == SecurityPolicyNone.URI:
        raise CredentialReleaseDenied("UserName token policy does not encrypt the password")
    if token_policy_uri not in policy.allowed_security_policy_uris:
        raise CredentialReleaseDenied(f"UserName token policy {token_policy_uri!r} is not in the allowed set")
